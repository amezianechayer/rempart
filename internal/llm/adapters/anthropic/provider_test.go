package anthropic_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/amezianechayer/rempart/internal/llm/adapters/anthropic"
	"github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/llm/fake"
	"github.com/amezianechayer/rempart/internal/llm/ports"
	"github.com/amezianechayer/rempart/internal/llm/redact"
)

func TestProviderContract(t *testing.T) {
	fr := domain.Route{Platform: domain.PlatformFake, Model: "fake-model-v1"}
	out := domain.Response{Output: json.RawMessage(valueV), Model: fr.Model, RequestID: "msg_EXAMPLE1"}
	f, err := fake.New(fake.Options{Scripts: map[string][]fake.Step{promptA: {{Response: out}}}})
	if err != nil {
		t.Fatal(err)
	}
	srv, rec := serve(t, auto)
	p := newProvider(t, srv.URL, 0)
	canceled, cancel := context.WithCancel(bg)
	cancel()
	bad := domain.Part{Untrusted: &domain.UntrustedBlock{SourceID: "r", Content: "CANARY"}}
	empty := reqQ()
	empty.Messages = nil
	for i, s := range []struct {
		p     ports.ModelProvider
		route domain.Route
		sent  func() int
	}{{f, fr, func() int { return len(f.Calls()) }}, {p, routeA, func() int { return len(rec.all()) }}} {
		resp, err := s.p.Structured(bg, s.route, reqQ())
		if err != nil || string(resp.Output) != valueV || resp.Model != s.route.Model || resp.RequestID != "msg_EXAMPLE1" {
			t.Fatalf("subject %d: %+v, %v", i, resp, err)
		}
		for j, c := range []struct{ err, want error }{
			{errOf(s.p.WithTools(bg, s.route, reqQ(bad), []domain.ToolSpec{toolT})), domain.ErrUntrustedWithTools},
			{errOf(s.p.WithTools(bg, s.route, reqQ(bad), nil)), domain.ErrUntrustedWithTools},
			{errOf(s.p.Structured(bg, domain.Route{Platform: domain.PlatformSelfHosted, Model: "m"}, reqQ())), domain.ErrInvalidRoute},
			{errOf(s.p.Structured(bg, domain.Route{Platform: domain.PlatformAnthropic, Region: "eu", Model: modelA}, reqQ())), domain.ErrInvalidRoute},
			{errOf(s.p.Structured(bg, s.route, empty)), domain.ErrInvalidRequest},
			{errOf(s.p.Structured(canceled, s.route, reqQ())), context.Canceled},
		} {
			if !errors.Is(c.err, c.want) {
				t.Errorf("subject %d, refusal %d: %v", i, j, c.err)
			}
		}
		if n := s.sent(); n != 1 {
			t.Errorf("subject %d: %d requests sent, want 1", i, n)
		}
	}
	tools := []domain.ToolSpec{toolT, {Name: "other", InputSchema: json.RawMessage(schemaG)}}
	resp, err := p.WithTools(bg, routeA, reqQ(), tools)
	if err != nil || len(resp.ToolCalls) != 1 || at(t, []byte(resp.ToolCalls[0].Input), "greeting") != "x" {
		t.Fatalf("WithTools: %+v, %v", resp, err)
	}
	ub := domain.UntrustedBlock{SourceID: "r-7f3a", Content: "<b>CANARY</b>"}
	if _, err := p.Structured(bg, routeA, reqQ(domain.Part{Untrusted: &ub})); err != nil {
		t.Fatal(err)
	}
	all, schema := rec.all(), at(t, []byte(schemaG))
	b1, b2 := at(t, all[1].body), at(t, all[2].body)
	for _, b := range []any{b1, b2} {
		if at(t, b, "output_config", "format", "type") != "json_schema" || !reflect.DeepEqual(at(t, b, "output_config", "format", "schema"), schema) ||
			at(t, b, "model") != modelA || at(t, b, "inference_geo") != nil {
			t.Errorf("body: %v", b)
		}
	}
	for i := range tools {
		if at(t, b1, "tools", i, "strict") != true || !reflect.DeepEqual(at(t, b1, "tools", i, "input_schema"), schema) {
			t.Errorf("tools[%d] = %v", i, at(t, b1, "tools", i))
		}
	}
	if at(t, b2, "tools") != nil || at(t, b2, "messages", 0, "content", 0, "text") != domain.RenderUntrusted(ub) {
		t.Errorf("Structured body: %v", b2)
	}
}

func TestResidencyEUBlocksAnthropicDirect(t *testing.T) {
	srv, rec := serve(t, auto)
	p := newProvider(t, srv.URL, 0)
	for _, withTools := range []bool{false, true} {
		if err := viaService(t, p, domain.ResidencyEU, withTools, domain.Part{Text: "hi"}); !errors.Is(err, domain.ErrResidency) {
			t.Errorf("withTools=%v: %v", withTools, err)
		}
	}
	if err := viaService(t, p, domain.ResidencyNone, false, domain.Part{Text: "hi"}); err != nil || len(rec.all()) != 1 {
		t.Fatalf("%v; %d requests, want 1 (control only)", err, len(rec.all()))
	}
}

func TestNoSecretInOutgoingRequest(t *testing.T) {
	srv, rec := serve(t, auto)
	p := newProvider(t, srv.URL, 0)
	txt := domain.Part{Text: "key " + fakeAWSKey() + " and " + fakeGitHubToken()}
	ub := domain.Part{Untrusted: &domain.UntrustedBlock{
		SourceID: fakeAWSKey(),
		Content:  "AWS_SECRET_ACCESS_KEY=" + fakeAWSSecret() + "\n" + fakeKey(),
	}}
	if err := viaService(t, p, domain.ResidencyNone, false, txt, ub); err != nil {
		t.Fatal(err)
	}
	if err := viaService(t, p, domain.ResidencyNone, true, txt); err != nil {
		t.Fatal(err)
	}
	for i, s := range rec.all() {
		if b := string(s.body); redact.New().ContainsSecret(b) || strings.Contains(b, "EXAMPLE") || strings.Contains(b, "FAKE") {
			t.Errorf("body %d holds a secret", i)
		}
	}
	if n := len(rec.all()); n != 2 {
		t.Fatalf("%d requests, want 2", n)
	}
}

// Also covers the ANTHROPIC_* environment and redirects.
func TestAPIKeyOnlyInHeader(t *testing.T) {
	trap, trapRec := serve(t, auto)
	for _, k := range []string{"ANTHROPIC_API_KEY", "ANTHROPIC_PROFILE", "ANTHROPIC_CUSTOM_HEADERS"} {
		t.Setenv(k, "")
		_ = os.Unsetenv(k)
	}
	t.Setenv("ANTHROPIC_CONFIG_DIR", t.TempDir())
	t.Setenv("ANTHROPIC_BASE_URL", trap.URL)
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "FAKE-token-EXAMPLE")
	okSrv, okRec := serve(t, auto)
	badSrv, badRec := serve(t, status(http.StatusUnauthorized, `{"type":"error","error":{"type":"x","message":"`+fakeKey()+`"}}`))
	redir, redirRec := serve(t, func(_ *testing.T, w http.ResponseWriter, _ map[string]any) {
		w.Header().Set("Location", trap.URL+"/v1/messages")
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	good := newProvider(t, okSrv.URL, 0)
	if _, err := good.WithTools(bg, routeA, reqQ(), []domain.ToolSpec{toolT}); err != nil {
		t.Fatal(err)
	}
	err := errOf(newProvider(t, badSrv.URL, 0).Structured(bg, routeA, reqQ()))
	if s := fmt.Sprintf("%v %+v %#v %+v %#v", err, err, err, good, good); err == nil || strings.Contains(s, "FAKEEXAMPLE") {
		t.Errorf("no error, or key in an error or a dump")
	}
	if err := errOf(newProvider(t, redir.URL, 2).Structured(bg, routeA, reqQ())); !errors.Is(err, anthropic.ErrRedirectRefused) {
		t.Errorf("redirect: %v", err)
	}
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")
	_ = os.Unsetenv("ANTHROPIC_AUTH_TOKEN")
	t.Setenv("ANTHROPIC_CUSTOM_HEADERS", "X-Evil: 1")
	if _, err := newProvider(t, okSrv.URL, 0).Structured(bg, routeA, reqQ()); err != nil {
		t.Fatal(err)
	}
	all := slices.Concat(okRec.all(), badRec.all(), redirRec.all())
	for i, s := range all {
		v := s.header.Values("X-Api-Key")
		h := s.header.Clone()
		h.Del("X-Api-Key")
		if len(v) != 1 || v[0] != fakeKey() || h.Get("Authorization") != "" || h.Get("X-Evil") != "" ||
			strings.Contains(fmt.Sprint(h)+s.url+string(s.body), "FAKE") {
			t.Errorf("request %d: key not only in X-Api-Key, or environment used", i)
		}
	}
	if len(all) != 4 || len(trapRec.all()) != 0 {
		t.Fatalf("%d requests, want 4; trap got %d, want 0", len(all), len(trapRec.all()))
	}
}

func TestResponseMapping(t *testing.T) {
	v, apiBody := text(valueV), `{"type":"error","error":{"type":"x","message":"CANARY `+fakeKey()+`"}}`
	for name, c := range map[string]struct {
		fn            reply
		retries, sent int
		want          error
	}{
		"echo":          {message("claude-opus-5", "end_turn", 12, 256, text("not json")), 0, 1, nil},
		"max_tokens":    {message("", "max_tokens", 12, 256, v), 0, 1, anthropic.ErrMaxTokens},
		"refusal":       {message("", "refusal", 12, 5, v), 0, 1, anthropic.ErrRefusal},
		"pause_turn":    {message("", "pause_turn", 12, 5, v), 0, 1, anthropic.ErrUnexpectedStop},
		"tool_no_tools": {message("", "tool_use", 12, 5, toolUse), 0, 1, anthropic.ErrUnexpectedContent},
		"empty":         {message("", "end_turn", 12, 5), 0, 1, anthropic.ErrEmptyResponse},
		"negative":      {message("", "end_turn", -1, 5, v), 0, 1, anthropic.ErrInvalidUsage},
		"above_max":     {message("", "end_turn", 12, 257, v), 0, 1, anthropic.ErrInvalidUsage},
		"malformed":     {status(http.StatusOK, `{"content": CANARY`), 0, 1, anthropic.ErrTransport},
		"400":           {status(http.StatusBadRequest, apiBody), 2, 1, anthropic.ErrAPI},
		"429":           {status(http.StatusTooManyRequests, apiBody), 0, 1, anthropic.ErrAPI},
		"529_retried":   {status(529, apiBody), 2, 3, anthropic.ErrAPI},
	} {
		srv, rec := serve(t, c.fn)
		resp, err := newProvider(t, srv.URL, c.retries).Structured(bg, routeA, reqQ())
		var e *anthropic.APIError
		if !errors.Is(err, c.want) || len(rec.all()) != c.sent || (err != nil && (!reflect.DeepEqual(resp, domain.Response{}) ||
			strings.Contains(err.Error(), "CANARY") || strings.Contains(err.Error(), "FAKE"))) ||
			(errors.As(err, &e) && (e.RequestID != "req_EXAMPLE1" || e.Retryable() == (e.StatusCode == http.StatusBadRequest))) {
			t.Errorf("%s: %+v, %v, %d requests", name, resp, err, len(rec.all()))
		}
		if name == "echo" && (string(resp.Output) != "not json" || resp.Model != "claude-opus-5" || resp.RequestID != "msg_EXAMPLE1") {
			t.Errorf("echo: %+v", resp)
		}
	}
}

func TestNewValidatesConfig(t *testing.T) {
	noKey, zero := config("https://api.anthropic.com", 0), config("https://api.anthropic.com", 0)
	noKey.APIKey, zero.Timeout = anthropic.Config{}.APIKey, 0
	bad := []anthropic.Config{noKey, zero, config("https://api.anthropic.com", -1), config("https://api.anthropic.com", 4)}
	for _, u := range []string{"", "http://api.anthropic.com", "https://u:p@h.example", "https://h.example?k=1", "ftp://h.example"} {
		bad = append(bad, config(u, 0))
	}
	for i, c := range bad {
		if p, err := anthropic.New(c); p != nil || !errors.Is(err, anthropic.ErrInvalidConfig) {
			t.Errorf("config %d: %v, %v", i, p, err)
		}
	}
	if _, err := anthropic.New(config("http://[::1]:1", 3)); err != nil {
		t.Errorf("loopback refused: %v", err)
	}
	want := domain.Capabilities{NativeStructuredOutput: true, StrictTools: true, RequiresRetention: true}
	if got := newProvider(t, "https://api.anthropic.com", 0).Capabilities(routeA); got != want {
		t.Errorf("Capabilities: %+v", got)
	}
}
