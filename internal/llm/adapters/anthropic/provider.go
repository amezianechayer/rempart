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
	"slices"
	"strings"
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
)

var _ ports.ModelProvider = (*Provider)(nil)

// models: constants of anthropic-sdk-go v1.75.0 (message.go), 2026-09-24.
const models = "claude-opus-5-5 claude-opus-5 claude-sonnet-5 claude-haiku-4-5 claude-sonnet-4-5 claude-sonnet-4-5-20250929"

type Config struct {
	APIKey     secret.Value
	BaseURL    string
	Timeout    time.Duration
	MaxRetries int
	Transport  http.RoundTripper
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
	if err != nil || cfg.APIKey.IsZero() || cfg.Timeout <= 0 || cfg.Timeout > 10*time.Minute || cfg.MaxRetries < 0 || cfg.MaxRetries > 3 {
		return nil, ErrInvalidConfig
	}
	ip := net.ParseIP(u.Hostname())
	local := u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && (u.Scheme != "http" || !local)) {
		return nil, ErrInvalidConfig
	}
	rt := cfg.Transport
	if rt == nil {
		rt = noProxy()
	}
	c := sdk.NewClient(
		option.WithoutEnvironmentDefaults(),
		option.WithBaseURL(u.String()),
		option.WithHTTPClient(&http.Client{Transport: rt, CheckRedirect: refuse, Timeout: cfg.Timeout}),
		option.WithAPIKey(cfg.APIKey.Reveal()),
		option.WithMaxRetries(cfg.MaxRetries),
		option.WithRequestTimeout(cfg.Timeout),
	)
	return &Provider{msgs: c.Messages}, nil
}

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
	params, err := buildParams(route, req, tools, withTools)
	if err != nil {
		return domain.Response{}, err
	}
	msg, err := p.msgs.New(ctx, params)
	var aerr *sdk.Error
	switch {
	case err == nil:
		return convertMessage(msg, req.MaxTokens, withTools)
	case ctx.Err() != nil:
		return domain.Response{}, ctx.Err()
	case errors.Is(err, ErrRedirectRefused):
		return domain.Response{}, ErrRedirectRefused
	case errors.As(err, &aerr):
		return domain.Response{}, &APIError{StatusCode: aerr.StatusCode, RequestID: aerr.RequestID}
	default:
		return domain.Response{}, ErrTransport
	}
}

func buildParams(route domain.Route, req domain.Request, tools []domain.ToolSpec, withTools bool) (sdk.MessageNewParams, error) {
	var out sdk.MessageNewParams
	if err := req.Validate(); err != nil {
		return out, err
	}
	if req.MaxTokens < 1 || req.MaxTokens > 1<<16 || (!withTools && len(req.Schema) == 0) || (withTools && len(tools) == 0) {
		return out, domain.ErrInvalidRequest
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
		schema, ok := decodeObject(req.Schema)
		if !ok {
			return out, domain.ErrInvalidRequest
		}
		out.OutputConfig = sdk.OutputConfigParam{Format: sdk.JSONOutputFormatParam{Schema: schema}}
	}
	for _, t := range tools {
		if _, ok := decodeObject(t.InputSchema); !ok || t.Name == "" {
			return out, domain.ErrInvalidRequest
		}
		tp := sdk.ToolUnionParamOfTool(param.Override[sdk.ToolInputSchemaParam](json.RawMessage(bytes.Clone(t.InputSchema))), t.Name)
		tp.OfTool.Strict = sdk.Bool(true)
		if t.Description != "" {
			tp.OfTool.Description = sdk.String(t.Description)
		}
		out.Tools = append(out.Tools, tp)
	}
	return out, nil
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

func convertMessage(msg *sdk.Message, maxTokens int, withTools bool) (domain.Response, error) {
	if msg == nil {
		return domain.Response{}, ErrEmptyResponse
	}
	switch msg.StopReason {
	case sdk.StopReasonEndTurn, sdk.StopReasonToolUse:
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
		case b.Type == "tool_use" && withTools:
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
	known := route.Platform == domain.PlatformAnthropic && route.Region == "" && slices.Contains(strings.Fields(models), route.Model)
	return domain.Capabilities{NativeStructuredOutput: known, StrictTools: known, RequiresRetention: true}
}
