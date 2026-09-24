# M0-T12 `llm-anthropic` : adaptateur Anthropic direct testé contre `httptest`

2026-09-24, `architect`, proposé. Fiche `docs/plans/M0-overview.md` §7, critères 8 et 9 de `prompts/M0.md`. Sans ADR. Revue sécurité : oui.

## 0. Amendements

- V1 (2026-09-24, `test-author`, étape A2) : `policy.go` sans l'ajout du jeton `"preview"` (redondant pour Anthropic, Bedrock et Vertex, car la regex exige une version ; hors périmètre et non testé pour selfhosted et fake ; mutation survivante). `anthropic_preview` reste refusé, 41 cas. Tests : `gofumpt -w` et valeurs EXAMPLE déplacées dans `fakeAWSKey()`, `fakeAWSSecret()`, `fakeGitHubToken()` (gosec G101). `provider.go` inchangé. 15 mutations sur 15 détectées. La mutation M21 du plan M0-T08 n'a plus de cible.

## 1. Objet et décisions
Fichiers : `internal/llm/adapters/anthropic/{provider,helpers_test,provider_test}.go`, `internal/llm/domain/policy{,_test}.go`, `go.mod`, `go.sum`, `docs/STATUS.md`. Hors : `cmd/` (T20), Bedrock, Vertex, T42.
- SDK v1.75.0 (MIT), `option.WithoutEnvironmentDefaults()` (client.go:52) ; HTTP sans redirection ni proxy d'environnement, `Timeout` explicite.
- Écart : `Config` exige l'URL (`https`, ou `http` en boucle locale) et porte `MaxRetries` (0 à 3 ; 0 en T20).
- `*sdk.Error` (requête, clé, corps) jamais enveloppée ; `RequiresRetention` toujours vrai (pas d'accord ZDR modélisé).
- Politique : famille, une ou deux versions de 1 ou 2 chiffres, date optionnelle ; `preview` refusé.

Étape 0 (`phase free`) : `GOFLAGS=-mod=mod GOPROXY=off go get github.com/anthropics/anthropic-sdk-go@v1.75.0`, `make verify-quick`, commit `build(deps): pin anthropic-sdk-go v1.75.0`. Puis protocole de `docs/plans/M0-llm-client.md` §4, §7.

## 2. Implémentation de référence

`internal/llm/adapters/anthropic/provider.go` :
```go
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
```

`internal/llm/domain/policy.go` : `const modelVersion` avant le bloc `var`, lignes 33 à 35 remplacées, `"preview"` ajouté ligne 93.
```go
const modelVersion = `claude-[a-z]+(-[0-9]{1,2}){1,2}`

	anthropicModel = regexp.MustCompile(`^` + modelVersion + `(-[0-9]{8})?$`)
	bedrockModel   = regexp.MustCompile(`^((eu|us|apac|global)\.)?anthropic\.` + modelVersion + `(-[0-9]{8}-v[0-9]+:[0-9]+|-v[0-9]+(:[0-9]+)?)?$`)
	vertexModel    = regexp.MustCompile(`^` + modelVersion + `(@[0-9]{8})?$`)
```

## 3. Tests de référence (`test-author`)

`policy_test.go`, table de `TestCheckPolicyModelPinned` : les trois `*_no_date` deviennent `*_undated`, attendus `true` ; ajout :
```go
		{"anthropic_preview", PlatformAnthropic, "claude-mythos-preview", false},
		{"anthropic_three_digits", PlatformAnthropic, "claude-opus-5-100", false},
		{"bedrock_eu_undated", PlatformBedrock, "eu.anthropic.claude-opus-5", true},
		{"bedrock_undated_revision", PlatformBedrock, "anthropic.claude-opus-4-6-v1", true},
```

`helpers_test.go` :
```go
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
		err := json.NewEncoder(w).Encode(map[string]any{"id": "msg_EXAMPLE1", "type": "message", "role": "assistant",
			"model": m, "stop_reason": stop, "content": content, "usage": map[string]any{"input_tokens": in, "output_tokens": out}})
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

func user(parts ...domain.Part) []domain.Message { return []domain.Message{{Role: domain.RoleUser, Parts: parts}} }

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
```

`provider_test.go` :
```go
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
	txt := domain.Part{Text: "key AKIAIOSFODNN7EXAMPLE and ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000"}
	ub := domain.Part{Untrusted: &domain.UntrustedBlock{SourceID: "AKIAIOSFODNN7EXAMPLE",
		Content: "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n" + fakeKey()}}
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
```

## 4. Critères d'acceptation (racine)
`F=internal/llm/adapters/anthropic/provider.go`.

| # | Commande | Attendu |
|---|---|---|
| 1 | `go test ./internal/llm/adapters/anthropic/ -count=1 -v 2>&1 \| grep -cE '^--- PASS: Test'` | `6` (critère 8) |
| 2 | `go test ./internal/llm/domain/ -count=1 -v -run 'TestCheckPolicyModelPinned$' 2>&1 \| grep -cE '^ +--- PASS'` | `41` |
| 3 | `go test ./internal/llm/... ./internal/archtest/ -count=1 -race; echo rc=$?` | `rc=0` (critère 9) |
| 4 | `go list -m github.com/anthropics/anthropic-sdk-go` ; `go list -deps ./internal/llm/... \| grep -c 'sdk-go/[bva]'` | `v1.75.0` ; `0` |
| 5 | `grep -cE 'os\.\|"log\|fmt\.Print\|panic\(' $F` ; `grep -cE 'WithoutEnvironmentDefaults\(\)\|Proxy = nil\|Reveal\(\)' $F` | `0` ; `3` |
| 6 | `go tool govulncheck ./...` ; `make verify-quick` ; `wc -c < docs/plans/M0-llm-anthropic.md` | `rc=0` ; `rc=0` ; au plus `30720` |

## 5. Mutations sur copie
Script de `docs/plans/M0-tenancy.md` 8.3, `OLD` unique dans `$F` (P1 : `policy.go`), test indiqué en `--- FAIL`.

| # | `OLD` | `NEW` | Test |
|---|---|---|---|
| M1 | `option.WithoutEnvironmentDefaults(),` | (vide) | APIKeyOnlyInHeader |
| M2 | `CheckRedirect: refuse, ` | (vide) | APIKeyOnlyInHeader |
| M3 | `option.WithMaxRetries(cfg.MaxRetries),` | (vide) | ResponseMapping |
| M4 | `if withTools && req.HasUntrusted() {` | `if false {` | ProviderContract |
| M5 | `text = domain.RenderUntrusted(*pt.Untrusted)` | `text = pt.Untrusted.Content` | ProviderContract |
| M6 | `route.Platform != domain.PlatformAnthropic \|\| ` | (vide) | ProviderContract |
| M7 | `tp.OfTool.Strict = sdk.Bool(true)` | (vide) | ProviderContract |
| M8 | `out.OutputConfig = ` | `_ = ` | ProviderContract |
| M9 | `&APIError{StatusCode: aerr.StatusCode, RequestID: aerr.RequestID}` | `fmt.Errorf("%w: %w", ErrAPI, err)` | ResponseMapping |
| M10 | `u.OutputTokens > int64(maxTokens)` | `u.OutputTokens > int64(maxTokens)+1` | ResponseMapping |
| M11 | `&& withTools:` | `:` | ResponseMapping |
| M12 | `RequiresRetention: true}` | `RequiresRetention: !known}` | NewValidatesConfig |
| M13 | `option.WithAPIKey(` | `option.WithAuthToken(` | APIKeyOnlyInHeader |
| M14 | `cfg.APIKey.IsZero() \|\| ` | (vide) | NewValidatesConfig |
| P1 | `(-[0-9]{1,2}){1,2}` | `(-[0-9]+){1,2}` | CheckPolicyModelPinned |

## 6. Sécurité et tâches
Revue : T7, T36 (M1, M2, M9, M13, M14 ; un seul `Reveal`), T2 (M4, M5), T10 (M3), T45 soldée (M10). À proposer : T46 environnement du SDK, T47 redirection ou proxy, T48 erreur du SDK portant la clé, T49 corps de réponse sans borne (avant T20).

Tâches : A0 étape 0 ; A1 `phase tests`, section 3 ; A2 copie, section 2, `gofmt -l`, `golangci-lint`, `go test -race`, mutations (écart : amendement V1) ; A3 `phase impl` ; I1 section 2, `go mod tidy` ; F1 mutations ; F2 `security-reviewer`, `acceptance-verifier` ; F3 `docs/STATUS.md` (T42, T49, `MaxRetries` 0 pour T20), commit `feat(llm): hardened anthropic adapter (M0-T12)`.

## 7. Points non vérifiés
- Rien n'a été compilé : A2 vérifie gofumpt, linters et la taille du plan.
- `JSONOutputFormatParam` n'a pas de champ `Strict` en v1.75.0 (message.go:5072), contrairement à la consigne.
- `param.Override` hors du SDK, `auth.EnvCredentials`, formes Bedrock et Vertex non datées, `go get` hors ligne : non exécutés.
