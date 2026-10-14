package openaicompat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/secrets/secret"
)

// Tests of ADR 0008 (M1-T09): the OpenRouter adapter against httptest servers
// on 127.0.0.1; no request leaves the process.

const (
	testKey   = "sk-or-v1-TEST-canary-0f3c"
	testModel = "deepseek/deepseek-chat"
	okReply   = `{"id":"gen-123","model":"deepseek/deepseek-chat","provider":"DeepSeek",` +
		`"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"{\"greeting\":\"bonjour\"}"}}],` +
		`"usage":{"prompt_tokens":12,"completion_tokens":5}}`
)

var testSchema = json.RawMessage(`{"type":"object","properties":{"greeting":{"type":"string"}},"required":["greeting"],"additionalProperties":false}`)

type captured struct {
	mu      sync.Mutex
	method  string
	path    string
	headers http.Header
	body    []byte
	n       int
}

func (c *captured) get() captured {
	c.mu.Lock()
	defer c.mu.Unlock()
	return captured{method: c.method, path: c.path, headers: c.headers.Clone(), body: bytes.Clone(c.body), n: c.n}
}

// server answers every request with status and reply, and records it.
func server(t *testing.T, status int, reply string) (*httptest.Server, *captured) {
	t.Helper()
	c := &captured{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.method, c.path, c.headers, c.body, c.n = r.Method, r.URL.Path, r.Header.Clone(), body, c.n+1
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(ts.Close)
	return ts, c
}

func newProvider(t *testing.T, ts *httptest.Server) *Provider {
	t.Helper()
	p, err := New(domain.PlatformOpenRouter, Config{APIKey: secret.New(testKey), BaseURL: ts.URL + "/api/v1", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func route() domain.Route {
	return domain.Route{Platform: domain.PlatformOpenRouter, Model: testModel}
}

func request() domain.Request {
	return domain.Request{
		PromptID: "demo", System: "Answer with JSON.", Schema: testSchema, MaxTokens: 64,
		Messages: []domain.Message{{Role: domain.RoleUser, Parts: []domain.Part{
			{Text: "Greet the target."},
			{Untrusted: &domain.UntrustedBlock{SourceID: "target", Content: "bonjour"}},
		}}},
	}
}

// TestOpenRouterRequestBody (ADR 0008 D3, D5): exactly the routing
// preferences, no compression, a strict JSON schema, no forbidden key; the key
// only in the Authorization header.
func TestOpenRouterRequestBody(t *testing.T) {
	ts, c := server(t, http.StatusOK, okReply)
	if _, err := newProvider(t, ts).Structured(context.Background(), route(), request()); err != nil {
		t.Fatalf("Structured: %v", err)
	}
	got := c.get()
	if got.n != 1 || got.method != http.MethodPost || got.path != "/api/v1/chat/completions" {
		t.Fatalf("%d requests, last %s %s; want one POST /api/v1/chat/completions", got.n, got.method, got.path)
	}
	if a := got.headers.Get("Authorization"); a != "Bearer "+testKey {
		t.Errorf("Authorization %q, want the bearer key", a)
	}
	for _, h := range []string{"HTTP-Referer", "X-Title"} {
		if got.headers.Get(h) != "" {
			t.Errorf("header %s sent", h)
		}
	}
	if bytes.Contains(got.body, []byte(testKey)) {
		t.Error("the key is in the body")
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(got.body, &body); err != nil {
		t.Fatalf("body is not a JSON object: %v", err)
	}
	for _, k := range []string{"tools", "tool_choice", "functions", "plugins", "models", "route", "n"} {
		if _, ok := body[k]; ok {
			t.Errorf("forbidden key %q sent", k)
		}
	}
	want := map[string]string{
		"model":      `"deepseek/deepseek-chat"`,
		"stream":     `false`,
		"transforms": `[]`,
		"max_tokens": `64`,
		"provider":   `{"order":["deepseek"],"allow_fallbacks":false,"require_parameters":true,"data_collection":"deny"}`,
		"response_format": `{"type":"json_schema","json_schema":{"name":"output","strict":true,"schema":` +
			string(testSchema) + `}}`,
	}
	for k, v := range want {
		if string(body[k]) != v {
			t.Errorf("%s = %s, want %s", k, body[k], v)
		}
	}
	var msgs []struct{ Role, Content string }
	if err := json.Unmarshal(body["messages"], &msgs); err != nil || len(msgs) != 2 {
		t.Fatalf("messages %s: %v", body["messages"], err)
	}
	if msgs[0].Role != "system" || msgs[0].Content != "Answer with JSON." || msgs[1].Role != "user" {
		t.Errorf("messages %+v", msgs)
	}
	if !strings.Contains(msgs[1].Content, "Greet the target.") ||
		!strings.Contains(msgs[1].Content, domain.RenderUntrusted(domain.UntrustedBlock{SourceID: "target", Content: "bonjour"})) {
		t.Errorf("user content %q: the untrusted block is not rendered by RenderUntrusted", msgs[1].Content)
	}
}

// TestOpenRouterResponse: output, model, usage and request id come from the
// response, never from the route.
func TestOpenRouterResponse(t *testing.T) {
	ts, _ := server(t, http.StatusOK, okReply)
	resp, err := newProvider(t, ts).Structured(context.Background(), route(), request())
	if err != nil {
		t.Fatalf("Structured: %v", err)
	}
	if string(resp.Output) != `{"greeting":"bonjour"}` || resp.Model != testModel || resp.RequestID != "gen-123" ||
		resp.Usage != (domain.Usage{InputTokens: 12, OutputTokens: 5}) {
		t.Errorf("response %+v", resp)
	}
}

// TestOpenRouterProviderMismatchRejected (ADR 0008 D4, T21, T92): a final
// provider other than the one of the closed list is refused.
func TestOpenRouterProviderMismatchRejected(t *testing.T) {
	ts, _ := server(t, http.StatusOK, strings.Replace(okReply, `"provider":"DeepSeek"`, `"provider":"Fireworks"`, 1))
	_, err := newProvider(t, ts).Structured(context.Background(), route(), request())
	if !errors.Is(err, ErrProviderMismatch) {
		t.Fatalf("Structured = %v, want ErrProviderMismatch", err)
	}
	if strings.Contains(fmt.Sprint(err), testKey) {
		t.Error("the error quotes the key")
	}
	ts2, _ := server(t, http.StatusOK, strings.Replace(okReply, `"provider":"DeepSeek",`, ``, 1))
	if _, err := newProvider(t, ts2).Structured(context.Background(), route(), request()); !errors.Is(err, ErrProviderMismatch) {
		t.Errorf("no provider: %v, want ErrProviderMismatch", err)
	}
}

// TestOpenRouterResponseRefused: every malformed or partial answer is an
// error, never an output.
func TestOpenRouterResponseRefused(t *testing.T) {
	for name, c := range map[string]struct {
		status int
		reply  string
		want   error
	}{
		"two_choices": {200, strings.Replace(okReply, `}}],`, `}},{"index":1,"finish_reason":"stop","message":{"role":"assistant","content":"{}"}}],`, 1), ErrUnexpectedResponse},
		"no_choice":   {200, `{"id":"gen-1","model":"deepseek/deepseek-chat","provider":"DeepSeek","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}`, ErrUnexpectedResponse},
		"length":      {200, strings.Replace(okReply, `"finish_reason":"stop"`, `"finish_reason":"length"`, 1), ErrMaxTokens},
		"tool_calls":  {200, strings.Replace(okReply, `"finish_reason":"stop"`, `"finish_reason":"tool_calls"`, 1), ErrUnexpectedResponse},
		"refusal":     {200, strings.Replace(okReply, `"role":"assistant",`, `"role":"assistant","refusal":"no",`, 1), ErrRefusal},
		"empty":       {200, strings.Replace(okReply, `"content":"{\"greeting\":\"bonjour\"}"`, `"content":""`, 1), ErrUnexpectedResponse},
		"usage_neg":   {200, strings.Replace(okReply, `"prompt_tokens":12`, `"prompt_tokens":-1`, 1), ErrInvalidUsage},
		"usage_over":  {200, strings.Replace(okReply, `"completion_tokens":5`, `"completion_tokens":65`, 1), ErrInvalidUsage},
		"bad_id":      {200, strings.Replace(okReply, `"gen-123"`, `"gen 123\n"`, 1), ErrUnexpectedResponse},
		"not_json":    {200, `<html>`, ErrUnexpectedResponse},
		"trailing":    {200, okReply + `{}`, ErrUnexpectedResponse},
		"api_401":     {401, `{"error":{"message":"bad key ` + testKey + `"}}`, ErrAPI},
		"api_429":     {429, `{}`, ErrAPI},
	} {
		t.Run(name, func(t *testing.T) {
			ts, _ := server(t, c.status, c.reply)
			resp, err := newProvider(t, ts).Structured(context.Background(), route(), request())
			if !errors.Is(err, c.want) || resp.Output != nil {
				t.Fatalf("Structured = %+v, %v; want %v", resp, err, c.want)
			}
			if strings.Contains(fmt.Sprintf("%v %+v", err, err), testKey) {
				t.Error("the error quotes the key")
			}
		})
	}
	var ae *APIError
	ts, _ := server(t, http.StatusUnauthorized, `{}`)
	if _, err := newProvider(t, ts).Structured(context.Background(), route(), request()); !errors.As(err, &ae) || ae.StatusCode != http.StatusUnauthorized {
		t.Errorf("401: %v, want an *APIError with status 401", err)
	}
}

// TestOpenRouterCallRefusedBeforeIO: a wrong platform or region, an unlisted
// model, tools, a missing schema or a cancelled context fail before any
// request.
func TestOpenRouterCallRefusedBeforeIO(t *testing.T) {
	ts, c := server(t, http.StatusOK, okReply)
	p := newProvider(t, ts)
	ctx := context.Background()
	for name, call := range map[string]func() error{
		"anthropic_route": func() error {
			_, err := p.Structured(ctx, domain.Route{Platform: domain.PlatformAnthropic, Model: testModel}, request())
			return err
		},
		"region": func() error {
			_, err := p.Structured(ctx, domain.Route{Platform: domain.PlatformOpenRouter, Region: "eu", Model: testModel}, request())
			return err
		},
		"unlisted": func() error {
			_, err := p.Structured(ctx, domain.Route{Platform: domain.PlatformOpenRouter, Model: "openrouter/auto"}, request())
			return err
		},
		"no_schema": func() error {
			r := request()
			r.Schema = nil
			_, err := p.Structured(ctx, route(), r)
			return err
		},
		"tools_untrusted": func() error {
			_, err := p.WithTools(ctx, route(), request(), []domain.ToolSpec{{Name: "t", InputSchema: testSchema}})
			if !errors.Is(err, domain.ErrUntrustedWithTools) {
				return errors.New("not ErrUntrustedWithTools")
			}
			return err
		},
		"tools": func() error {
			r := request()
			r.Messages[0].Parts = r.Messages[0].Parts[:1]
			_, err := p.WithTools(ctx, route(), r, []domain.ToolSpec{{Name: "t", InputSchema: testSchema}})
			return err
		},
		"cancelled": func() error {
			cctx, cancel := context.WithCancel(ctx)
			cancel()
			_, err := p.Structured(cctx, route(), request())
			return err
		},
	} {
		if err := call(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if n := c.get().n; n != 0 {
		t.Errorf("%d requests sent, want 0", n)
	}
}

// TestPlatformNotWired (ADR 0008 D1): only openrouter is wired in M1.
func TestPlatformNotWired(t *testing.T) {
	for _, pl := range []domain.Platform{domain.PlatformOpenAI, domain.PlatformDeepSeek, domain.PlatformQwen, domain.PlatformAnthropic, domain.PlatformSelfHosted, "x"} {
		if p, err := New(pl, Config{APIKey: secret.New(testKey), Timeout: time.Second}); !errors.Is(err, ErrPlatformNotWired) || p != nil {
			t.Errorf("New(%s) = %v, %v; want nil, ErrPlatformNotWired", pl, p, err)
		}
	}
}

// TestConfigRefused (T20, T22): a key is required; a base URL is loopback
// http only (tests); a timeout is required and bounded; an injected
// transport is hardened.
func TestConfigRefused(t *testing.T) {
	for name, cfg := range map[string]Config{
		"no_key":       {Timeout: time.Second},
		"no_timeout":   {APIKey: secret.New(testKey)},
		"long_timeout": {APIKey: secret.New(testKey), Timeout: time.Hour},
		"remote_base":  {APIKey: secret.New(testKey), Timeout: time.Second, BaseURL: "https://example.com/api/v1"},
		"https_base":   {APIKey: secret.New(testKey), Timeout: time.Second, BaseURL: "https://127.0.0.1:8443/api/v1"},
		"user_base":    {APIKey: secret.New(testKey), Timeout: time.Second, BaseURL: "http://u@127.0.0.1:8080/api/v1"},
		"proxy":        {APIKey: secret.New(testKey), Timeout: time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}},
	} {
		if p, err := New(domain.PlatformOpenRouter, cfg); !errors.Is(err, ErrConfig) || p != nil {
			t.Errorf("%s: New = %v, %v; want nil, ErrConfig", name, p, err)
		}
	}
	p, err := New(domain.PlatformOpenRouter, Config{APIKey: secret.New(testKey), Timeout: time.Second})
	if err != nil || p.base != "https://openrouter.ai/api/v1" {
		t.Errorf("default base %v, %v; want the coded host", p, err)
	}
	if s := fmt.Sprintf("%v %+v %#v", p, p, p); strings.Contains(s, testKey) {
		t.Error("printing the provider reveals the key")
	}
}

// TestCapabilities: structured output for a listed model; retention is
// always required (data_collection deny is not zero retention).
func TestCapabilities(t *testing.T) {
	p, err := New(domain.PlatformOpenRouter, Config{APIKey: secret.New(testKey), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if c := p.Capabilities(route()); !c.NativeStructuredOutput || c.StrictTools || !c.RequiresRetention {
		t.Errorf("listed model: %+v", c)
	}
	if c := p.Capabilities(domain.Route{Platform: domain.PlatformOpenRouter, Model: "openrouter/auto"}); c.NativeStructuredOutput || !c.RequiresRetention {
		t.Errorf("unlisted model: %+v", c)
	}
}
