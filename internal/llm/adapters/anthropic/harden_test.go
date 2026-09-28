package anthropic_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/anthropics/anthropic-sdk-go"

	"github.com/amezianechayer/rempart/internal/llm/adapters/anthropic"
	"github.com/amezianechayer/rempart/internal/llm/domain"
)

// okMessage is a valid Structured answer, as raw JSON.
const okMessage = `{"id":"msg_EXAMPLE1","type":"message","role":"assistant","model":"` + modelA +
	`","stop_reason":"end_turn","content":[{"type":"text","text":"{\"greeting\":\"bonjour\"}"}],` +
	`"usage":{"input_tokens":12,"output_tokens":5}}`

// padded is body completed with spaces up to n bytes (valid JSON either way).
func padded(body string, n int) []byte {
	return append([]byte(body), bytes.Repeat([]byte(" "), n-len(body))...)
}

// raw answers with code and body; length, when not negative, is announced in
// Content-Length (otherwise the body goes chunked).
func raw(code int, body []byte, length int) reply {
	return func(_ *testing.T, w http.ResponseWriter, _ map[string]any) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("request-id", "req_EXAMPLE1")
		if length >= 0 {
			w.Header().Set("Content-Length", strconv.Itoa(length))
		}
		w.WriteHeader(code)
		_, _ = w.Write(body)
	}
}

// direct serves h and counts its requests; h sees the request context, so a
// stalled answer ends when the client goes away.
func direct(t *testing.T, h http.HandlerFunc) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

// stall sends nothing for d, or until the client goes away.
func stall(d time.Duration) http.HandlerFunc {
	return func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(d):
		case <-r.Context().Done():
		}
	}
}

func isZero(resp domain.Response) bool { return reflect.DeepEqual(resp, domain.Response{}) }

// TestResponseBodyBounded: no body above MaxResponseBytes is read, whatever
// its status or framing, and none is truncated (D5, T49).
func TestResponseBodyBounded(t *testing.T) {
	over := anthropic.MaxResponseBytes + 1
	errBody := `{"type":"error","error":{"type":"x","message":"m"}}`
	for name, fn := range map[string]reply{
		"200 chunked":        raw(http.StatusOK, padded(okMessage, over), -1),
		"200 content length": raw(http.StatusOK, padded(okMessage, over), over),
		"400 chunked":        raw(http.StatusBadRequest, padded(errBody, over), -1),
		"400 content length": raw(http.StatusBadRequest, padded(errBody, over), over),
	} {
		t.Run(name, func(t *testing.T) {
			srv, rec := serve(t, fn)
			resp, err := newProvider(t, srv.URL).Structured(bg, routeA, reqQ())
			if !errors.Is(err, anthropic.ErrResponseTooLarge) || errors.Is(err, anthropic.ErrAPI) || !isZero(resp) {
				t.Errorf("%+v, %v; want ErrResponseTooLarge, not ErrAPI, empty response", resp, err)
			}
			if n := len(rec.all()); n != 1 {
				t.Errorf("%d requests, want 1", n)
			}
		})
	}
	t.Run("announced then stalled", func(t *testing.T) {
		srv, _ := direct(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", strconv.Itoa(over))
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, okMessage[:10])
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			stall(3*time.Second)(w, r)
		})
		start := time.Now()
		resp, err := newProvider(t, srv.URL).Structured(bg, routeA, reqQ())
		if d := time.Since(start); !errors.Is(err, anthropic.ErrResponseTooLarge) || !isZero(resp) || d >= time.Second {
			t.Errorf("%+v, %v after %v; want ErrResponseTooLarge before reading, in less than 1 s", resp, err, d)
		}
	})
	for name, length := range map[string]int{"witness chunked": -1, "witness content length": anthropic.MaxResponseBytes} {
		t.Run(name, func(t *testing.T) {
			srv, _ := serve(t, raw(http.StatusOK, padded(okMessage, anthropic.MaxResponseBytes), length))
			resp, err := newProvider(t, srv.URL).Structured(bg, routeA, reqQ())
			if err != nil || string(resp.Output) != valueV {
				t.Errorf("body of exactly MaxResponseBytes: %+v, %v; want accepted", resp, err)
			}
		})
	}
}

// TestSingleAttemptAndDeadline: one attempt, no wait on Retry-After, the
// whole call bounded by Timeout (D2, T50).
func TestSingleAttemptAndDeadline(t *testing.T) {
	t.Run("529 retry after one hour", func(t *testing.T) {
		srv, rec := serve(t, func(_ *testing.T, w http.ResponseWriter, _ map[string]any) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("request-id", "req_EXAMPLE1")
			w.Header().Set("Retry-After-Ms", "3600000")
			w.Header().Set("Retry-After", "3600")
			w.WriteHeader(529)
			_, _ = io.WriteString(w, `{"type":"error","error":{"type":"overloaded_error","message":"m"}}`)
		})
		start := time.Now()
		_, err := newProvider(t, srv.URL).Structured(bg, routeA, reqQ())
		var e *anthropic.APIError
		if d := time.Since(start); !errors.As(err, &e) || e.StatusCode != 529 || d >= 2*time.Second {
			t.Errorf("%v after %v; want APIError 529 in less than 2 s", err, d)
		}
		if n := len(rec.all()); n != 1 {
			t.Errorf("%d requests, want 1", n)
		}
	})
	t.Run("silent server", func(t *testing.T) {
		srv, n := direct(t, stall(3*time.Second))
		cfg := config(srv.URL)
		cfg.Timeout = 300 * time.Millisecond
		p, err := anthropic.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		resp, err := p.Structured(bg, routeA, reqQ())
		if d := time.Since(start); !errors.Is(err, anthropic.ErrTimeout) || !isZero(resp) || d >= 2*time.Second {
			t.Errorf("%+v, %v after %v; want ErrTimeout in less than 2 s", resp, err, d)
		}
		if got := n.Load(); got != 1 {
			t.Errorf("%d requests, want 1", got)
		}
	})
	t.Run("caller canceled", func(t *testing.T) {
		srv, _ := direct(t, stall(3*time.Second))
		ctx, cancel := context.WithCancel(bg)
		defer cancel()
		time.AfterFunc(100*time.Millisecond, cancel)
		start := time.Now()
		_, err := newProvider(t, srv.URL).Structured(ctx, routeA, reqQ())
		if d := time.Since(start); !errors.Is(err, context.Canceled) || d >= 2*time.Second {
			t.Errorf("%v after %v; want context.Canceled in less than 2 s", err, d)
		}
	})
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestTransportProxyRefused: an injected transport is a *http.Transport
// without proxy, cloned by New; anything else is refused (D3, T47).
func TestTransportProxyRefused(t *testing.T) {
	trap, trapRec := serve(t, auto)
	trapURL, err := url.Parse(trap.URL)
	if err != nil {
		t.Fatal(err)
	}
	srv, rec := serve(t, auto)
	for name, rt := range map[string]http.RoundTripper{
		"default transport": http.DefaultTransport,
		"proxy":             &http.Transport{Proxy: http.ProxyURL(trapURL)},
		"nil transport":     (*http.Transport)(nil),
		"custom":            roundTripper(http.DefaultTransport.RoundTrip),
	} {
		cfg := config(srv.URL)
		cfg.Transport = rt
		if p, err := anthropic.New(cfg); p != nil || !errors.Is(err, anthropic.ErrInvalidConfig) {
			t.Errorf("%s: %v, %v; want ErrInvalidConfig", name, p, err)
		}
	}
	tr := &http.Transport{}
	cfg := config(srv.URL)
	cfg.Transport = tr
	p, err := anthropic.New(cfg)
	if err != nil {
		t.Fatalf("transport without proxy refused: %v", err)
	}
	tr.Proxy = http.ProxyURL(trapURL)
	if _, err := p.Structured(bg, routeA, reqQ()); err != nil {
		t.Fatalf("call after the injected transport changed: %v", err)
	}
	if n, m := len(rec.all()), len(trapRec.all()); n != 1 || m != 0 {
		t.Fatalf("server got %d requests (want 1), proxy trap got %d (want 0)", n, m)
	}
}

// TestResponseMetadataValidated: id and model of the answer and the request-id
// of an API error are copied only when they match ^[A-Za-z0-9_-]{1,128}$
// (D4, T52).
func TestResponseMetadataValidated(t *testing.T) {
	v := text(valueV)
	for name, fn := range map[string]reply{
		"id empty":       messageID("", "", "end_turn", v),
		"id blank":       messageID("msg bad", "", "end_turn", v),
		"id markup":      messageID("msg<x>", "", "end_turn", v),
		"id too long":    messageID(strings.Repeat("a", 129), "", "end_turn", v),
		"id non ascii":   messageID("msg_é", "", "end_turn", v),
		"model with dot": messageID("msg_EXAMPLE1", "claude.opus", "end_turn", v),
		"model newline":  messageID("msg_EXAMPLE1", "claude\nopus", "end_turn", v),
	} {
		t.Run(name, func(t *testing.T) {
			srv, _ := serve(t, fn)
			resp, err := newProvider(t, srv.URL).Structured(bg, routeA, reqQ())
			if !errors.Is(err, anthropic.ErrInvalidMetadata) || !isZero(resp) {
				t.Errorf("%+v, %v; want ErrInvalidMetadata", resp, err)
			}
		})
	}
	long := strings.Repeat("a", 128)
	srv, _ := serve(t, messageID(long, "", "end_turn", v))
	resp, err := newProvider(t, srv.URL).Structured(bg, routeA, reqQ())
	if err != nil || resp.RequestID != long || resp.Model != modelA {
		t.Errorf("id of 128 characters: %+v, %v; want accepted", resp, err)
	}
	for name, id := range map[string]string{"blank": "req bad", "too long": "r" + strings.Repeat("a", 128), "witness": "req_EXAMPLE1"} {
		srv, _ := serve(t, func(_ *testing.T, w http.ResponseWriter, _ map[string]any) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("request-id", id)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"type":"error","error":{"type":"x","message":"m"}}`)
		})
		_, err := newProvider(t, srv.URL).Structured(bg, routeA, reqQ())
		want := ""
		if name == "witness" {
			want = id
		}
		var e *anthropic.APIError
		if !errors.As(err, &e) || e.RequestID != want {
			t.Errorf("request-id %s: %v; want APIError with RequestID %q", name, err, want)
		}
	}
}

// TestToolUseOnlyWithTools: a tool_use stop without tools, or a call to a tool
// that was not declared, is unexpected content (D9).
func TestToolUseOnlyWithTools(t *testing.T) {
	other := map[string]any{"type": "tool_use", "id": "toolu_EXAMPLE", "name": "other", "input": map[string]any{"greeting": "x"}}
	srv, _ := serve(t, message("", "tool_use", 12, 5, text(valueV)))
	if resp, err := newProvider(t, srv.URL).Structured(bg, routeA, reqQ()); !errors.Is(err, anthropic.ErrUnexpectedContent) || !isZero(resp) {
		t.Errorf("Structured, stop tool_use with text: %+v, %v; want ErrUnexpectedContent", resp, err)
	}
	srv, _ = serve(t, message("", "tool_use", 12, 5, other))
	if resp, err := newProvider(t, srv.URL).WithTools(bg, routeA, reqQ(), []domain.ToolSpec{toolT}); !errors.Is(err, anthropic.ErrUnexpectedContent) || !isZero(resp) {
		t.Errorf("WithTools, undeclared tool: %+v, %v; want ErrUnexpectedContent", resp, err)
	}
	srv, _ = serve(t, message("", "tool_use", 12, 5, toolUse))
	resp, err := newProvider(t, srv.URL).WithTools(bg, routeA, reqQ(), []domain.ToolSpec{toolT})
	if err != nil || len(resp.ToolCalls) != 1 || resp.ToolCalls[0].Name != "greet" {
		t.Errorf("WithTools, declared tool: %+v, %v; want accepted", resp, err)
	}
}

// sentSchemas are the raw bytes of the schemas in a request body.
type sentSchemas struct {
	OutputConfig struct {
		Format struct {
			Schema json.RawMessage `json:"schema"`
		} `json:"format"`
	} `json:"output_config"`
	Tools []struct {
		InputSchema json.RawMessage `json:"input_schema"`
	} `json:"tools"`
}

// TestSentSchemaIsVerifiedBytes: the schema bytes on the wire are the checked
// bytes, compacted, never reencoded (keys kept in order); a schema that the
// SDK would rewrite (<, >, &) is refused before any I/O (D6, T70).
func TestSentSchemaIsVerifiedBytes(t *testing.T) {
	unsorted := "{\"type\": \"object\", \"required\": [\"greeting\"],\n  \"properties\": {\"greeting\": {\"type\": \"string\", \"description\": \"z then a\"}},\n  \"additionalProperties\": false}\n"
	var compact bytes.Buffer
	if err := json.Compact(&compact, []byte(unsorted)); err != nil {
		t.Fatal(err)
	}
	srv, rec := serve(t, auto)
	p := newProvider(t, srv.URL)
	req := reqQ()
	req.Schema = json.RawMessage(unsorted)
	if _, err := p.Structured(bg, routeA, req); err != nil {
		t.Fatalf("Structured: %v", err)
	}
	tool := domain.ToolSpec{Name: "greet", Description: "Greet", InputSchema: json.RawMessage(unsorted)}
	if _, err := p.WithTools(bg, routeA, req, []domain.ToolSpec{tool}); err != nil {
		t.Fatalf("WithTools: %v", err)
	}
	all := rec.all()
	if len(all) != 2 {
		t.Fatalf("%d requests, want 2", len(all))
	}
	for i, s := range all {
		var got sentSchemas
		if err := json.Unmarshal(s.body, &got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.OutputConfig.Format.Schema, compact.Bytes()) {
			t.Errorf("request %d: output schema sent %s, want %s", i, got.OutputConfig.Format.Schema, compact.Bytes())
		}
		if i == 1 && (len(got.Tools) != 1 || !bytes.Equal(got.Tools[0].InputSchema, compact.Bytes())) {
			t.Errorf("request %d: tool schemas sent %+v, want %s", i, got.Tools, compact.Bytes())
		}
	}
	for _, d := range []string{"a<b", "a&b", "a>b"} {
		bad := json.RawMessage(`{"type":"object","description":"` + d + `","properties":{},"additionalProperties":false}`)
		srv, rec := serve(t, auto)
		p := newProvider(t, srv.URL)
		asPrompt := reqQ()
		asPrompt.Schema = bad
		asTool := domain.ToolSpec{Name: "greet", Description: "Greet", InputSchema: bad}
		for name, err := range map[string]error{
			"prompt": errOf(p.Structured(bg, routeA, asPrompt)),
			"tool":   errOf(p.WithTools(bg, routeA, reqQ(), []domain.ToolSpec{asTool})),
		} {
			if !errors.Is(err, anthropic.ErrReencoded) || strings.Contains(err.Error(), d) {
				t.Errorf("%s %q: %v; want ErrReencoded, schema not quoted", name, d, err)
			}
		}
		if n := len(rec.all()); n != 0 {
			t.Errorf("%q: %d requests, want 0", d, n)
		}
	}
}

// TestSDKModelsClassified: every model of the SDK that CheckPolicy pins has
// the capabilities of the adapter, and the undated aliases have none (T51, T80).
func TestSDKModelsClassified(t *testing.T) {
	p := newProvider(t, "http://127.0.0.1:1")
	pinned := []sdk.Model{
		sdk.ModelClaudeFable5_1, sdk.ModelClaudeOpus5_5, sdk.ModelClaudeMythos5_1, sdk.ModelClaudeSonnet5,
		sdk.ModelClaudeFable5, sdk.ModelClaudeMythos5, sdk.ModelClaudeOpus5, sdk.ModelClaudeOpus4_8,
		sdk.ModelClaudeOpus4_7, sdk.ModelClaudeOpus4_6, sdk.ModelClaudeSonnet4_6,
		sdk.ModelClaudeHaiku4_5_20251001, sdk.ModelClaudeOpus4_5_20251101, sdk.ModelClaudeSonnet4_5_20250929,
	}
	refused := []sdk.Model{
		sdk.ModelClaudeHaiku4_5, sdk.ModelClaudeOpus4_5, sdk.ModelClaudeSonnet4_5,
		sdk.ModelClaudeMythosPreview, //nolint:staticcheck // SA1019: a deprecated preview alias, cited to prove it stays refused (T80).
	}
	policy := func(m string) domain.TenantPolicy {
		return domain.TenantPolicy{
			Route:     domain.Route{Platform: domain.PlatformAnthropic, Model: m},
			Residency: domain.ResidencyNone, Retention: domain.RetentionStandard,
		}
	}
	for _, m := range pinned {
		caps := p.Capabilities(policy(m).Route)
		if err := domain.CheckPolicy(policy(m), caps); err != nil || !caps.NativeStructuredOutput || !caps.StrictTools {
			t.Errorf("%s: CheckPolicy %v, capabilities %+v; want pinned and native", m, err, caps)
		}
	}
	for _, m := range refused {
		caps := p.Capabilities(policy(m).Route)
		if err := domain.CheckPolicy(policy(m), caps); !errors.Is(err, domain.ErrModelNotPinned) || caps.NativeStructuredOutput || caps.StrictTools {
			t.Errorf("%s: CheckPolicy %v, capabilities %+v; want ErrModelNotPinned, no capability", m, err, caps)
		}
	}
}
