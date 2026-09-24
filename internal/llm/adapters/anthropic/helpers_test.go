package anthropic_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/amezianechayer/rempart/internal/llm"
	"github.com/amezianechayer/rempart/internal/llm/adapters/anthropic"
	"github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/llm/fake"
	"github.com/amezianechayer/rempart/internal/llm/prompts"
	"github.com/amezianechayer/rempart/internal/secrets/secret"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

const (
	modelA  = "claude-sonnet-4-5-20250929"
	promptA = "test.greeting.v1"
	schemaG = `{"type":"object","properties":{"greeting":{"type":"string"}},"required":["greeting"],"additionalProperties":false}`
	valueV  = `{"greeting":"bonjour"}`
)

// FAKE and EXAMPLE forms of M0-T07 only.
func fakeKey() string { return "sk-ant-api03-FAKEEXAMPLE0000000000000000" }

func fakeAWSKey() string { return "AKIAIOSFODNN7EXAMPLE" }

func fakeAWSSecret() string { return "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" }

func fakeGitHubToken() string { return "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000" }

var (
	bg      = context.Background()
	routeA  = domain.Route{Platform: domain.PlatformAnthropic, Model: modelA}
	toolT   = domain.ToolSpec{Name: "greet", Description: "Greet", InputSchema: json.RawMessage(schemaG)}
	toolUse = map[string]any{"type": "tool_use", "id": "toolu_EXAMPLE", "name": "greet", "input": map[string]any{"greeting": "x"}}
)

type seen struct {
	header http.Header
	url    string
	body   []byte
}

type recorder struct {
	sync.Mutex
	reqs []seen
}

func (r *recorder) all() []seen {
	r.Lock()
	defer r.Unlock()
	return slices.Clone(r.reqs)
}

type reply func(t *testing.T, w http.ResponseWriter, body map[string]any)

func serve(t *testing.T, fn reply) (*httptest.Server, *recorder) {
	t.Helper()
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		rec.Lock()
		rec.reqs = append(rec.reqs, seen{r.Header.Clone(), r.URL.String(), raw})
		rec.Unlock()
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		fn(t, w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

func text(s string) map[string]any { return map[string]any{"type": "text", "text": s} }

func message(model, stop string, in, out int, content ...map[string]any) reply {
	return func(t *testing.T, w http.ResponseWriter, body map[string]any) {
		m := model
		if m == "" {
			m, _ = body["model"].(string)
		}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(map[string]any{
			"id": "msg_EXAMPLE1", "type": "message", "role": "assistant",
			"model": m, "stop_reason": stop, "content": content, "usage": map[string]any{"input_tokens": in, "output_tokens": out},
		})
		if err != nil {
			t.Error(err)
		}
	}
}

func auto(t *testing.T, w http.ResponseWriter, body map[string]any) {
	if _, ok := body["tools"]; ok {
		message("", "tool_use", 12, 5, toolUse)(t, w, body)
		return
	}
	message("", "end_turn", 12, 5, text(valueV))(t, w, body)
}

func status(code int, body string) reply {
	return func(_ *testing.T, w http.ResponseWriter, _ map[string]any) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("request-id", "req_EXAMPLE1")
		w.Header().Set("Retry-After-Ms", "1")
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	}
}

func config(url string, retries int) anthropic.Config {
	return anthropic.Config{APIKey: secret.New(fakeKey()), BaseURL: url, Timeout: 5 * time.Second, MaxRetries: retries}
}

func newProvider(t *testing.T, url string, retries int) *anthropic.Provider {
	t.Helper()
	p, err := anthropic.New(config(url, retries))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func user(parts ...domain.Part) []domain.Message {
	return []domain.Message{{Role: domain.RoleUser, Parts: parts}}
}

func reqQ(parts ...domain.Part) domain.Request {
	if len(parts) == 0 {
		parts = []domain.Part{{Text: "hello"}}
	}
	return domain.Request{PromptID: promptA, System: "Greet.", Messages: user(parts...), Schema: json.RawMessage(schemaG), MaxTokens: 256}
}

func errOf(_ domain.Response, err error) error { return err }

// at decodes bytes, then walks keys and indexes; nil when absent.
func at(t *testing.T, v any, path ...any) any {
	t.Helper()
	if raw, ok := v.([]byte); ok && json.Unmarshal(raw, &v) != nil {
		t.Fatalf("not JSON: %s", raw)
	}
	for _, k := range path {
		m, _ := v.(map[string]any)
		s, _ := v.([]any)
		if i, ok := k.(int); ok && i < len(s) {
			v = s[i]
		} else if key, ok := k.(string); ok {
			v = m[key]
		} else {
			return nil
		}
	}
	return v
}

func viaService(t *testing.T, p *anthropic.Provider, res domain.Residency, withTools bool, parts ...domain.Part) error {
	t.Helper()
	fsys := fstest.MapFS{promptA + "/system.txt": {Data: []byte("Greet.\n")}, promptA + "/schema.json": {Data: []byte(schemaG)}}
	pr, err := prompts.LoadFS(fsys, promptA)
	if err != nil {
		t.Fatal(err)
	}
	tenant := tenancy.ID("0f8fad5b-d9cb-469f-a165-70867728950e")
	rr, err := fake.NewStaticResolver(map[tenancy.ID]domain.TenantPolicy{tenant: {Route: routeA, Residency: res, Retention: domain.RetentionStandard}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := llm.NewClient(p, rr, fsys, llm.Config{MaxTokensPerCall: 256})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := tenancy.WithTenant(bg, tenant)
	if err != nil {
		t.Fatal(err)
	}
	call := llm.Call{PromptID: promptA, PromptHash: pr.Hash, Messages: user(parts...), MaxTokens: 256}
	if withTools {
		_, _, err = c.WithTools(ctx, call, []domain.ToolSpec{toolT})
		return err
	}
	_, err = c.Structured(ctx, call)
	return err
}
