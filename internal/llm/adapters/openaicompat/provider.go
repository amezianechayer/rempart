// Package openaicompat is the model adapter for OpenAI-compatible chat APIs
// (ADR 0008), built on net/http and encoding/json only. M1 wires OpenRouter
// only, for synthetic evals (residency none): every request pins one final
// provider without fallback, refuses data collection, disables prompt
// transforms and asks for a strict JSON schema.
package openaicompat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/amezianechayer/rempart/internal/llm/adapters/transport"
	"github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/llm/ports"
	"github.com/amezianechayer/rempart/internal/secrets/secret"
)

// openRouterBase: the coded host (ADR 0008 D3, T22); BaseURL replaces it in
// tests only, on loopback.
const openRouterBase = "https://openrouter.ai/api/v1"

const (
	maxMaxTokens   = 1 << 16
	maxInputTokens = 1 << 21
)

var (
	ErrPlatformNotWired   = errors.New("openaicompat: platform not wired in M1 (ADR 0008 D1)")
	ErrConfig             = errors.New("openaicompat: invalid configuration")
	ErrWrongRoute         = errors.New("openaicompat: route of another platform, with a region, or of an unlisted model")
	ErrToolsNotSupported  = errors.New("openaicompat: calls with tools are not supported")
	ErrProviderMismatch   = errors.New("openaicompat: final provider differs from the closed list")
	ErrUnexpectedResponse = errors.New("openaicompat: unexpected response")
	ErrRefusal            = errors.New("openaicompat: the model refused")
	ErrMaxTokens          = errors.New("openaicompat: output truncated at max_tokens")
	ErrInvalidUsage       = errors.New("openaicompat: invalid usage")
	ErrAPI                = errors.New("openaicompat: api error")
	ErrTimeout            = errors.New("openaicompat: timeout")
	ErrTransport          = errors.New("openaicompat: transport failure")
)

// APIError carries the HTTP status of a refused call, never its body.
type APIError struct{ StatusCode int }

func (e *APIError) Error() string { return fmt.Sprintf("openaicompat: api error %d", e.StatusCode) }
func (e *APIError) Unwrap() error { return ErrAPI }

// Config configures a Provider. APIKey and Timeout are required.
type Config struct {
	APIKey    secret.Value
	BaseURL   string            // empty: the coded host; tests: http on 127.0.0.1 or [::1] only
	Transport http.RoundTripper // nil: a new transport without proxy; else hardened
	Timeout   time.Duration     // 1 ns to transport.MaxTimeout
}

// Provider calls one platform. It holds the key, printed as [REDACTED].
type Provider struct {
	platform domain.Platform
	base     string
	key      secret.Value
	http     *http.Client
}

var _ ports.ModelProvider = (*Provider)(nil)

var (
	idPattern       = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	modelPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
	providerPattern = regexp.MustCompile(`^[A-Za-z0-9 ._-]{1,64}$`)
)

// New returns a Provider for platform: ErrPlatformNotWired for any platform
// but openrouter, ErrConfig for an invalid configuration.
func New(platform domain.Platform, cfg Config) (*Provider, error) {
	if platform != domain.PlatformOpenRouter {
		return nil, ErrPlatformNotWired
	}
	if cfg.APIKey.IsZero() || cfg.Timeout <= 0 || cfg.Timeout > transport.MaxTimeout {
		return nil, ErrConfig
	}
	base := openRouterBase
	if cfg.BaseURL != "" {
		if !loopbackBase(cfg.BaseURL) {
			return nil, ErrConfig
		}
		base = strings.TrimSuffix(cfg.BaseURL, "/")
	}
	rt, err := transport.Harden(cfg.Transport)
	if err != nil {
		return nil, ErrConfig
	}
	c, err := transport.Client(rt, cfg.Timeout)
	if err != nil {
		return nil, ErrConfig
	}
	return &Provider{platform: platform, base: base, key: cfg.APIKey, http: c}, nil
}

// loopbackBase admits http://127.0.0.1:<port>[/path] or http://[::1]:<port>[/path].
func loopbackBase(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.Port() == "" {
		return false
	}
	ip, err := netip.ParseAddr(u.Hostname())
	return err == nil && (ip == netip.MustParseAddr("127.0.0.1") || ip == netip.IPv6Loopback())
}

// Capabilities: structured output for a listed OpenRouter model; retention
// is always required (data_collection deny is not zero retention, F3).
func (p *Provider) Capabilities(route domain.Route) domain.Capabilities {
	_, listed := domain.OpenRouterProvider(route.Model)
	ok := route.Platform == domain.PlatformOpenRouter && route.Region == "" && listed
	return domain.Capabilities{NativeStructuredOutput: ok, RequiresRetention: true}
}

// WithTools is refused: no tool call goes through a gateway in M1.
func (p *Provider) WithTools(_ context.Context, _ domain.Route, req domain.Request, _ []domain.ToolSpec) (domain.Response, error) {
	if req.HasUntrusted() {
		return domain.Response{}, domain.ErrUntrustedWithTools
	}
	return domain.Response{}, ErrToolsNotSupported
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type jsonSchema struct {
	Name   string          `json:"name"`
	Strict bool            `json:"strict"`
	Schema json.RawMessage `json:"schema"`
}

type responseFormat struct {
	Type       string     `json:"type"`
	JSONSchema jsonSchema `json:"json_schema"`
}

// providerPrefs: ADR 0008 D3; zdr is sent only once confirmed at the source.
type providerPrefs struct {
	Order             []string `json:"order"`
	AllowFallbacks    bool     `json:"allow_fallbacks"`
	RequireParameters bool     `json:"require_parameters"`
	DataCollection    string   `json:"data_collection"`
}

type chatRequest struct {
	Model          string         `json:"model"`
	Messages       []chatMessage  `json:"messages"`
	MaxTokens      int            `json:"max_tokens"`
	Stream         bool           `json:"stream"`
	Transforms     []string       `json:"transforms"`
	ResponseFormat responseFormat `json:"response_format"`
	Provider       providerPrefs  `json:"provider"`
}

type chatResponse struct {
	ID       string `json:"id"`
	Model    string `json:"model"`
	Provider string `json:"provider"`
	Choices  []struct {
		FinishReason string `json:"finish_reason"`
		Message      struct {
			Content   *string         `json:"content"`
			Refusal   *string         `json:"refusal"`
			ToolCalls json.RawMessage `json:"tool_calls"`
		} `json:"message"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

// Structured sends one chat completion with a strict JSON schema.
func (p *Provider) Structured(ctx context.Context, route domain.Route, req domain.Request) (domain.Response, error) {
	if err := ctx.Err(); err != nil {
		return domain.Response{}, err
	}
	slug, listed := domain.OpenRouterProvider(route.Model)
	if route.Platform != p.platform || route.Region != "" || !listed {
		return domain.Response{}, ErrWrongRoute
	}
	body, err := buildBody(route, slug, req)
	if err != nil {
		return domain.Response{}, err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, p.base+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return domain.Response{}, ErrTransport
	}
	hr.Header.Set("Authorization", "Bearer "+p.key.Reveal())
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Accept", "application/json")
	resp, err := p.http.Do(hr)
	if err != nil {
		return domain.Response{}, transportError(ctx, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return domain.Response{}, &APIError{StatusCode: resp.StatusCode}
	}
	if err != nil {
		if errors.Is(err, transport.ErrResponseTooLarge) {
			return domain.Response{}, fmt.Errorf("%w: body too large", ErrUnexpectedResponse)
		}
		return domain.Response{}, transportError(ctx, err)
	}
	return convert(raw, slug, req.MaxTokens)
}

func transportError(ctx context.Context, err error) error {
	var ne net.Error
	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return ErrTimeout
	default:
		return ErrTransport
	}
}

// buildBody renders the request: system prompt, then each message, its
// untrusted parts by domain.RenderUntrusted only.
func buildBody(route domain.Route, slug string, req domain.Request) ([]byte, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if req.MaxTokens < 1 || req.MaxTokens > maxMaxTokens || len(req.Schema) == 0 {
		return nil, domain.ErrInvalidRequest
	}
	var schema bytes.Buffer
	if json.Compact(&schema, req.Schema) != nil || schema.Len() == 0 || schema.Bytes()[0] != '{' {
		return nil, domain.ErrInvalidRequest
	}
	var msgs []chatMessage
	if req.System != "" {
		msgs = append(msgs, chatMessage{Role: "system", Content: req.System})
	}
	for _, m := range req.Messages {
		texts := make([]string, 0, len(m.Parts))
		for _, pt := range m.Parts {
			if pt.Untrusted != nil {
				texts = append(texts, domain.RenderUntrusted(*pt.Untrusted))
			} else {
				texts = append(texts, pt.Text)
			}
		}
		msgs = append(msgs, chatMessage{Role: string(m.Role), Content: strings.Join(texts, "\n\n")})
	}
	body := chatRequest{
		Model: route.Model, Messages: msgs, MaxTokens: req.MaxTokens, Transforms: []string{},
		ResponseFormat: responseFormat{Type: "json_schema", JSONSchema: jsonSchema{Name: "output", Strict: true, Schema: schema.Bytes()}},
		Provider:       providerPrefs{Order: []string{slug}, RequireParameters: true, DataCollection: "deny"},
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		return nil, domain.ErrInvalidRequest
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

// convert checks a 200 response: one document, one choice that stopped
// normally with text and no tool call, a valid id and model, the final
// provider of the closed list, a bounded usage.
func convert(raw []byte, slug string, maxTokens int) (domain.Response, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var r chatResponse
	if dec.Decode(&r) != nil {
		return domain.Response{}, ErrUnexpectedResponse
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return domain.Response{}, ErrUnexpectedResponse
	}
	if !idPattern.MatchString(r.ID) || !modelPattern.MatchString(r.Model) || len(r.Choices) != 1 {
		return domain.Response{}, ErrUnexpectedResponse
	}
	if !sameProvider(r.Provider, slug) {
		if providerPattern.MatchString(r.Provider) {
			return domain.Response{}, fmt.Errorf("%w: served by %q", ErrProviderMismatch, r.Provider)
		}
		return domain.Response{}, ErrProviderMismatch
	}
	c := r.Choices[0]
	switch {
	case c.Message.Refusal != nil && *c.Message.Refusal != "":
		return domain.Response{}, ErrRefusal
	case c.FinishReason == "length":
		return domain.Response{}, ErrMaxTokens
	case c.FinishReason != "stop", len(c.Message.ToolCalls) > 0 && string(c.Message.ToolCalls) != "null",
		c.Message.Content == nil, c.Message.Content != nil && *c.Message.Content == "":
		return domain.Response{}, ErrUnexpectedResponse
	}
	u := r.Usage
	if u == nil || u.PromptTokens < 0 || u.CompletionTokens < 0 || u.PromptTokens > maxInputTokens || u.CompletionTokens > maxTokens {
		return domain.Response{}, ErrInvalidUsage
	}
	return domain.Response{
		Output:    json.RawMessage(*c.Message.Content),
		Model:     r.Model,
		RequestID: r.ID,
		Usage:     domain.Usage{InputTokens: u.PromptTokens, OutputTokens: u.CompletionTokens},
	}, nil
}

// sameProvider compares the declared final provider ("DeepSeek") with the
// slug of the closed list ("deepseek"): case and separators ignored.
func sameProvider(declared, slug string) bool {
	norm := func(s string) string {
		var b strings.Builder
		for _, r := range strings.ToLower(s) {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
				b.WriteRune(r)
			}
		}
		return b.String()
	}
	return declared != "" && norm(declared) == norm(slug)
}
