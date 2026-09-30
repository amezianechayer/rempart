// Package anthropic is the Anthropic direct adapter of ports.ModelProvider
// (ADR 0002): no environment, no redirect, no log; the key only in X-Api-Key.
package anthropic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"time"

	sdk "github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/anthropics/anthropic-sdk-go/packages/param"

	"github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/llm/ports"
	"github.com/amezianechayer/rempart/internal/secrets/secret"
)

var (
	ErrInvalidConfig     = errors.New("anthropic: invalid configuration")
	ErrWrongPlatform     = fmt.Errorf("%w: not anthropic direct", domain.ErrInvalidRoute)
	ErrAPI               = errors.New("anthropic: api error")
	ErrTransport         = errors.New("anthropic: transport failure")
	ErrRedirectRefused   = errors.New("anthropic: redirect refused")
	ErrEmptyResponse     = errors.New("anthropic: empty response")
	ErrUnexpectedContent = errors.New("anthropic: unexpected content")
	ErrRefusal           = errors.New("anthropic: refusal")
	ErrMaxTokens         = errors.New("anthropic: max tokens reached")
	ErrUnexpectedStop    = errors.New("anthropic: unexpected stop reason")
	ErrInvalidUsage      = errors.New("anthropic: invalid usage")
	ErrTimeout           = errors.New("anthropic: timeout")
	ErrResponseTooLarge  = errors.New("anthropic: response too large")
	ErrInvalidMetadata   = errors.New("anthropic: invalid response metadata")
	ErrReencoded         = errors.New("anthropic: schema reencoded")
)

var _ ports.ModelProvider = (*Provider)(nil)

const MaxResponseBytes = 1 << 20

// sdkModels: the models of the SDK that CheckPolicy pins (T51, T80).
var sdkModels = []string{
	sdk.ModelClaudeFable5_1, sdk.ModelClaudeOpus5_5, sdk.ModelClaudeMythos5_1, sdk.ModelClaudeSonnet5,
	sdk.ModelClaudeFable5, sdk.ModelClaudeMythos5, sdk.ModelClaudeOpus5, sdk.ModelClaudeOpus4_8,
	sdk.ModelClaudeOpus4_7, sdk.ModelClaudeOpus4_6, sdk.ModelClaudeSonnet4_6,
	sdk.ModelClaudeHaiku4_5_20251001, sdk.ModelClaudeOpus4_5_20251101, sdk.ModelClaudeSonnet4_5_20250929,
}

var metaPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

type Config struct {
	APIKey    secret.Value
	BaseURL   string
	Timeout   time.Duration
	Transport http.RoundTripper
}

// APIError keeps no body, no request, no key.
type APIError struct {
	StatusCode int
	RequestID  string
}

func (e *APIError) Error() string { return fmt.Sprintf("anthropic: api error %d", e.StatusCode) }

func (e *APIError) Unwrap() error { return ErrAPI }

func (e *APIError) Retryable() bool {
	c := e.StatusCode
	return c == http.StatusRequestTimeout || c == http.StatusConflict || c == http.StatusTooManyRequests || c >= http.StatusInternalServerError
}

type Provider struct{ msgs sdk.MessageService }

func New(cfg Config) (*Provider, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || cfg.APIKey.IsZero() || cfg.Timeout <= 0 || cfg.Timeout > 10*time.Minute {
		return nil, ErrInvalidConfig
	}
	ip := net.ParseIP(u.Hostname())
	local := u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && (u.Scheme != "http" || !local)) {
		return nil, ErrInvalidConfig
	}
	rt, ok := transport(cfg.Transport)
	if !ok {
		return nil, ErrInvalidConfig
	}
	c := sdk.NewClient(
		option.WithoutEnvironmentDefaults(),
		option.WithBaseURL(u.String()),
		option.WithHTTPClient(&http.Client{Transport: capped{rt}, CheckRedirect: refuse, Timeout: cfg.Timeout}),
		option.WithAPIKey(cfg.APIKey.Reveal()),
		option.WithMaxRetries(0),
		option.WithRequestTimeout(cfg.Timeout),
	)
	return &Provider{msgs: c.Messages}, nil
}

func transport(rt http.RoundTripper) (http.RoundTripper, bool) { // T47
	if rt == nil {
		return noProxy(), true
	}
	t, ok := rt.(*http.Transport)
	if !ok || t == nil || t.Proxy != nil {
		return nil, false
	}
	return t.Clone(), true
}

type capped struct{ rt http.RoundTripper } // T49

func (c capped) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := c.rt.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	if resp.ContentLength > MaxResponseBytes {
		_ = resp.Body.Close()
		return nil, ErrResponseTooLarge
	}
	resp.Body = &cappedBody{rc: resp.Body, left: MaxResponseBytes}
	return resp, nil
}

type cappedBody struct {
	rc   io.ReadCloser
	left int64
}

func (b *cappedBody) Read(p []byte) (int, error) {
	if b.left <= 0 {
		var one [1]byte
		n, err := b.rc.Read(one[:])
		if n > 0 {
			return 0, ErrResponseTooLarge
		}
		return 0, err
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.rc.Read(p)
	b.left -= int64(n)
	return n, err
}

func (b *cappedBody) Close() error { return b.rc.Close() }

func noProxy() http.RoundTripper {
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		c := t.Clone()
		c.Proxy = nil
		return c
	}
	return &http.Transport{}
}

func refuse(*http.Request, []*http.Request) error { return ErrRedirectRefused }

func (p *Provider) Structured(ctx context.Context, route domain.Route, req domain.Request) (domain.Response, error) {
	return p.call(ctx, route, req, nil, false)
}

func (p *Provider) WithTools(ctx context.Context, route domain.Route, req domain.Request, tools []domain.ToolSpec) (domain.Response, error) {
	return p.call(ctx, route, req, tools, true)
}

func (p *Provider) call(ctx context.Context, route domain.Route, req domain.Request, tools []domain.ToolSpec, withTools bool) (domain.Response, error) {
	if err := ctx.Err(); err != nil {
		return domain.Response{}, err
	}
	if route.Platform != domain.PlatformAnthropic || route.Region != "" || route.Model == "" {
		return domain.Response{}, ErrWrongPlatform
	}
	if withTools && req.HasUntrusted() {
		return domain.Response{}, domain.ErrUntrustedWithTools
	}
	params, want, err := buildParams(route, req, tools, withTools)
	if err != nil {
		return domain.Response{}, err
	}
	msg, err := p.msgs.New(ctx, params, option.WithMiddleware(verifiedBytes(want)))
	var aerr *sdk.Error
	switch {
	case err == nil:
		return convertMessage(msg, req.MaxTokens, tools, withTools)
	case ctx.Err() != nil:
		return domain.Response{}, ctx.Err()
	case errors.Is(err, ErrRedirectRefused):
		return domain.Response{}, ErrRedirectRefused
	case errors.Is(err, ErrResponseTooLarge):
		return domain.Response{}, ErrResponseTooLarge
	case errors.Is(err, ErrReencoded):
		return domain.Response{}, ErrReencoded
	case isTimeout(err):
		return domain.Response{}, ErrTimeout
	case errors.As(err, &aerr):
		return domain.Response{}, &APIError{StatusCode: aerr.StatusCode, RequestID: meta(aerr.RequestID)}
	default:
		return domain.Response{}, ErrTransport
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout()
}

func meta(s string) string {
	if metaPattern.MatchString(s) {
		return s
	}
	return ""
}

type sent struct {
	schema json.RawMessage
	tools  [][]byte
}

func buildParams(route domain.Route, req domain.Request, tools []domain.ToolSpec, withTools bool) (sdk.MessageNewParams, sent, error) {
	var out sdk.MessageNewParams
	var want sent
	if err := req.Validate(); err != nil {
		return out, sent{}, err
	}
	if req.MaxTokens < 1 || req.MaxTokens > 1<<16 || (!withTools && len(req.Schema) == 0) || (withTools && len(tools) == 0) {
		return out, sent{}, domain.ErrInvalidRequest
	}
	out.Model, out.MaxTokens = route.Model, int64(req.MaxTokens)
	if req.System != "" {
		out.System = []sdk.TextBlockParam{{Text: req.System}}
	}
	for _, m := range req.Messages {
		blocks := make([]sdk.ContentBlockParamUnion, 0, len(m.Parts))
		for _, pt := range m.Parts {
			text := pt.Text
			if pt.Untrusted != nil {
				text = domain.RenderUntrusted(*pt.Untrusted)
			}
			blocks = append(blocks, sdk.NewTextBlock(text))
		}
		out.Messages = append(out.Messages, sdk.MessageParam{Role: sdk.MessageParamRole(m.Role), Content: blocks})
	}
	if len(req.Schema) > 0 {
		c, ok := compactObject(req.Schema)
		if !ok {
			return out, sent{}, domain.ErrInvalidRequest
		}
		want.schema = c
		out.OutputConfig = sdk.OutputConfigParam{Format: param.Override[sdk.JSONOutputFormatParam](
			json.RawMessage(`{"type":"json_schema","schema":` + string(c) + `}`))}
	}
	for _, t := range tools {
		c, ok := compactObject(t.InputSchema)
		if !ok || t.Name == "" {
			return out, sent{}, domain.ErrInvalidRequest
		}
		want.tools = append(want.tools, c)
		tp := sdk.ToolUnionParamOfTool(param.Override[sdk.ToolInputSchemaParam](json.RawMessage(bytes.Clone(c))), t.Name)
		tp.OfTool.Strict = sdk.Bool(true)
		if t.Description != "" {
			tp.OfTool.Description = sdk.String(t.Description)
		}
		out.Tools = append(out.Tools, tp)
	}
	return out, want, nil
}

func compactObject(raw json.RawMessage) (json.RawMessage, bool) {
	if _, ok := decodeObject(raw); !ok {
		return nil, false
	}
	var b bytes.Buffer
	if json.Compact(&b, raw) != nil {
		return nil, false
	}
	return b.Bytes(), true
}

type sentBody struct {
	OutputConfig struct {
		Format struct {
			Schema json.RawMessage `json:"schema"`
		} `json:"format"`
	} `json:"output_config"`
	Tools []struct {
		InputSchema json.RawMessage `json:"input_schema"`
	} `json:"tools"`
}

// verifiedBytes refuses, before any I/O, a body whose schemas are not the
// compacted verified bytes (T70).
func verifiedBytes(want sent) option.Middleware {
	return func(r *http.Request, next option.MiddlewareNext) (*http.Response, error) {
		if r.GetBody == nil {
			return nil, ErrReencoded
		}
		rc, err := r.GetBody()
		if err != nil {
			return nil, ErrReencoded
		}
		body, err := io.ReadAll(rc)
		_ = rc.Close()
		var got sentBody
		if err != nil || json.Unmarshal(body, &got) != nil ||
			!bytes.Equal(got.OutputConfig.Format.Schema, want.schema) || len(got.Tools) != len(want.tools) {
			return nil, ErrReencoded
		}
		for i, t := range want.tools {
			if !bytes.Equal(got.Tools[i].InputSchema, t) {
				return nil, ErrReencoded
			}
		}
		return next(r)
	}
}

func decodeObject(raw json.RawMessage) (map[string]any, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil {
		return nil, false
	}
	_, err := dec.Token()
	return m, errors.Is(err, io.EOF)
}

func convertMessage(msg *sdk.Message, maxTokens int, tools []domain.ToolSpec, withTools bool) (domain.Response, error) {
	if msg == nil {
		return domain.Response{}, ErrEmptyResponse
	}
	if !metaPattern.MatchString(msg.ID) || !metaPattern.MatchString(msg.Model) {
		return domain.Response{}, ErrInvalidMetadata
	}
	switch msg.StopReason {
	case sdk.StopReasonEndTurn:
	case sdk.StopReasonToolUse:
		if !withTools {
			return domain.Response{}, ErrUnexpectedContent
		}
	case sdk.StopReasonRefusal:
		return domain.Response{}, ErrRefusal
	case sdk.StopReasonMaxTokens:
		return domain.Response{}, ErrMaxTokens
	default:
		return domain.Response{}, ErrUnexpectedStop
	}
	u := msg.Usage
	if u.InputTokens < 0 || u.OutputTokens < 0 || u.InputTokens > 1<<21 || u.OutputTokens > int64(maxTokens) {
		return domain.Response{}, ErrInvalidUsage
	}
	resp := domain.Response{Model: msg.Model, RequestID: msg.ID}
	resp.Usage = domain.Usage{InputTokens: int(u.InputTokens), OutputTokens: int(u.OutputTokens)}
	for _, b := range msg.Content {
		switch {
		case b.Type == "text":
			resp.Output = append(resp.Output, b.Text...)
		case b.Type == "tool_use" && withTools && slices.ContainsFunc(tools, func(t domain.ToolSpec) bool { return t.Name == b.Name }):
			resp.ToolCalls = append(resp.ToolCalls, domain.ToolCall{Name: b.Name, Input: bytes.Clone(b.Input)})
		default:
			return domain.Response{}, ErrUnexpectedContent
		}
	}
	if len(resp.Output) == 0 && len(resp.ToolCalls) == 0 {
		return domain.Response{}, ErrEmptyResponse
	}
	return resp, nil
}

func (p *Provider) Capabilities(route domain.Route) domain.Capabilities {
	known := route.Platform == domain.PlatformAnthropic && route.Region == "" && slices.Contains(sdkModels, route.Model)
	return domain.Capabilities{NativeStructuredOutput: known, StrictTools: known, RequiresRetention: true}
}
