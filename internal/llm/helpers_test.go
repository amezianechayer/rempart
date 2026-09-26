package llm

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"

	"github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/llm/fake"
	"github.com/amezianechayer/rempart/internal/llm/ports"
	"github.com/amezianechayer/rempart/internal/llm/prompts"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

// Fixtures of plan M0-llm-client, section 6.
const (
	greetingID = "test.greeting.v1"
	leakyID    = "test.leaky.v1"

	greetingSchema = `{"type":"object","properties":{"greeting":{"type":"string"}},"required":["greeting"],"additionalProperties":false}`
	lookupSchema   = `{"type":"object","properties":{"name":{"type":"string"}},"required":["name"],"additionalProperties":false}`

	modelV1     = "fake-model-v1"
	modelRetain = "fake-model-retain"
	modelB3     = "eu.anthropic.claude-sonnet-4-20250514-v1:0"

	// Tenants A, B, C of internal/llm/fake/resolver_test.go.
	tenantA tenancy.ID = "0f8fad5b-d9cb-469f-a165-70867728950e"
	tenantB tenancy.ID = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
	tenantC tenancy.ID = "1b4e28ba-2fa1-41d2-883f-0016d3cca427"
)

// Test secrets: the documented EXAMPLE and FAKE forms of M0-T07 only.
func fakeAWSKey() string { return "AKIAIOSFODNN7EXAMPLE" }

func fakeAWSSecret() string { return "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" }

func fakeGitHub() string { return "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000" }

// valueV is the valid output V.
var valueV = json.RawMessage(`{"greeting":"bonjour"}`)

// promptFS is F: built fresh on every call.
func promptFS() fstest.MapFS {
	return fstest.MapFS{
		greetingID + "/system.txt":  {Data: []byte("Reply with a JSON greeting.\n")},
		greetingID + "/schema.json": {Data: []byte(greetingSchema)},
		leakyID + "/system.txt":     {Data: []byte("Use key " + fakeAWSKey() + ".\n")},
		leakyID + "/schema.json":    {Data: []byte(greetingSchema)},
	}
}

func promptHash(t *testing.T, id string) string {
	t.Helper()
	p, err := prompts.LoadFS(promptFS(), id)
	if err != nil {
		t.Fatalf("prompts.LoadFS(%q): %v", id, err)
	}
	return p.Hash
}

// hashH is H, the hash of test.greeting.v1.
func hashH(t *testing.T) string {
	t.Helper()
	return promptHash(t, greetingID)
}

func userText(s string) domain.Message {
	return domain.Message{Role: domain.RoleUser, Parts: []domain.Part{{Text: s}}}
}

// call0 is C0: built fresh on every call.
func call0(t *testing.T) Call {
	t.Helper()
	return Call{PromptID: greetingID, PromptHash: hashH(t), Messages: []domain.Message{userText("hello")}, MaxTokens: 256}
}

// configK is K.
func configK() Config {
	return Config{MaxCorrections: 0, MaxTokensPerCall: 256, AllowFakeRoute: true}
}

func routePA() domain.Route {
	return domain.Route{Platform: domain.PlatformFake, Region: "", Model: modelV1}
}

// policyPA is PA.
func policyPA() domain.TenantPolicy {
	return domain.TenantPolicy{Route: routePA(), Residency: domain.ResidencyEU, Retention: domain.RetentionZero}
}

func fakePolicy(model string, ret domain.Retention) domain.TenantPolicy {
	return domain.TenantPolicy{
		Route:     domain.Route{Platform: domain.PlatformFake, Model: model},
		Residency: domain.ResidencyEU,
		Retention: ret,
	}
}

func routeB3() domain.Route {
	return domain.Route{Platform: domain.PlatformBedrock, Region: "eu-west-3", Model: modelB3}
}

// policyB3 is B3.
func policyB3() domain.TenantPolicy {
	return domain.TenantPolicy{Route: routeB3(), Residency: domain.ResidencyEU, Retention: domain.RetentionZero}
}

// toolT is T.
func toolT() domain.ToolSpec {
	return domain.ToolSpec{Name: "lookup", Description: "Look up a record by name", InputSchema: json.RawMessage(lookupSchema)}
}

func ctxFor(t *testing.T, id tenancy.ID) context.Context {
	t.Helper()
	ctx, err := tenancy.WithTenant(context.Background(), id)
	if err != nil {
		t.Fatalf("tenancy.WithTenant: %v", err)
	}
	return ctx
}

// step answers with output under model.
func step(output, model string) fake.Step {
	r := domain.Response{Model: model, RequestID: "fake-req"}
	if output != "" {
		r.Output = json.RawMessage(output)
	}
	return fake.Step{Response: r}
}

func stepV() fake.Step { return step(string(valueV), modelV1) }

func repeatStep(s fake.Step, n int) []fake.Step {
	out := make([]fake.Step, n)
	for i := range out {
		out[i] = s
	}
	return out
}

// newFake builds the fake with the models of the plan and a script for test.greeting.v1.
func newFake(t *testing.T, steps ...fake.Step) *fake.Provider {
	t.Helper()
	opt := fake.Options{Models: map[string]domain.Capabilities{
		modelV1:     {},
		modelRetain: {RequiresRetention: true},
	}}
	if len(steps) > 0 {
		opt.Scripts = map[string][]fake.Step{greetingID: steps}
	}
	p, err := fake.New(opt)
	if err != nil || p == nil {
		t.Fatalf("fake.New: %v", err)
	}
	return p
}

// funcResolver adapts a function to ports.RouteResolver.
type funcResolver func(ctx context.Context, tenant tenancy.ID) (domain.TenantPolicy, error)

func (f funcResolver) Resolve(ctx context.Context, tenant tenancy.ID) (domain.TenantPolicy, error) {
	return f(ctx, tenant)
}

// countingResolver counts every Resolve.
type countingResolver struct {
	inner ports.RouteResolver
	n     atomic.Int64
}

func (r *countingResolver) Resolve(ctx context.Context, tenant tenancy.ID) (domain.TenantPolicy, error) {
	r.n.Add(1)
	return r.inner.Resolve(ctx, tenant)
}

func (r *countingResolver) Count() int { return int(r.n.Load()) }

func countingStatic(t *testing.T, policies map[tenancy.ID]domain.TenantPolicy) *countingResolver {
	t.Helper()
	sr, err := fake.NewStaticResolver(policies)
	if err != nil || sr == nil {
		t.Fatalf("fake.NewStaticResolver: %v", err)
	}
	return &countingResolver{inner: sr}
}

func countingFunc(f funcResolver) *countingResolver { return &countingResolver{inner: f} }

// seqResolver returns pols[i] on its i-th Resolve, then the last one.
type seqResolver struct {
	mu   sync.Mutex
	pols []domain.TenantPolicy
	i    int
}

func (r *seqResolver) Resolve(context.Context, tenancy.ID) (domain.TenantPolicy, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := min(r.i, len(r.pols)-1)
	r.i++
	return r.pols[i], nil
}

func mustClient(t *testing.T, p ports.ModelProvider, rr ports.RouteResolver, cfg Config) *Client {
	t.Helper()
	c, err := NewClient(p, rr, promptFS(), cfg)
	if err != nil || c == nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// env is the usual set-up: fake provider, counting resolver with tenant A.
type env struct {
	fake *fake.Provider
	rr   *countingResolver
	c    *Client
}

func newEnv(t *testing.T, cfg Config, pol domain.TenantPolicy, steps ...fake.Step) env {
	t.Helper()
	f := newFake(t, steps...)
	rr := countingStatic(t, map[tenancy.ID]domain.TenantPolicy{tenantA: pol})
	return env{fake: f, rr: rr, c: mustClient(t, f, rr, cfg)}
}

// outcome is what one service call returned.
type outcome struct {
	res   Result
	calls []domain.ToolCall
	err   error
}

type method struct {
	name string
	run  func(c *Client, ctx context.Context, call Call) outcome
}

func structuredM() method {
	return method{"Structured", func(c *Client, ctx context.Context, call Call) outcome {
		res, err := c.Structured(ctx, call)
		return outcome{res: res, err: err}
	}}
}

func withToolsM(tools []domain.ToolSpec) method {
	return method{"WithTools", func(c *Client, ctx context.Context, call Call) outcome {
		res, calls, err := c.WithTools(ctx, call, tools)
		return outcome{res, calls, err}
	}}
}

// bothMethods: Structured and WithTools with [T].
func bothMethods() []method {
	return []method{structuredM(), withToolsM([]domain.ToolSpec{toolT()})}
}

// assertFailed: every wanted error (errors.Is), Result{}, no tool call.
func assertFailed(t *testing.T, o outcome, wants ...error) {
	t.Helper()
	if o.err == nil {
		t.Fatalf("call succeeded with %+v, want an error", o.res)
	}
	for _, w := range wants {
		if !errors.Is(o.err, w) {
			t.Errorf("error %q does not match %q", o.err, w)
		}
	}
	if !reflect.DeepEqual(o.res, Result{}) {
		t.Errorf("result = %+v with an error, want Result{}", o.res)
	}
	if o.calls != nil {
		t.Errorf("tool calls = %+v with an error, want nil", o.calls)
	}
}

// assertNoIO is the plan's "sans I/O": failure, no provider call, no Resolve.
func assertNoIO(t *testing.T, e env, o outcome, wants ...error) {
	t.Helper()
	assertFailed(t, o, wants...)
	if n := e.fake.Invocations(); n != 0 {
		t.Errorf("provider invocations = %d, want 0", n)
	}
	if n := e.rr.Count(); n != 0 {
		t.Errorf("Resolve count = %d, want 0 (no I/O before the check)", n)
	}
}

// assertNoCall is the plan's "sans appel": failure, one Resolve, no provider call.
func assertNoCall(t *testing.T, e env, o outcome, wants ...error) {
	t.Helper()
	assertFailed(t, o, wants...)
	if n := e.fake.Invocations(); n != 0 {
		t.Errorf("provider invocations = %d, want 0", n)
	}
	if n := e.rr.Count(); n != 1 {
		t.Errorf("Resolve count = %d, want 1", n)
	}
}

func assertOK(t *testing.T, o outcome) {
	t.Helper()
	if o.err != nil {
		t.Fatalf("unexpected error %v", o.err)
	}
}

// cloneMessages is a deep copy written independently of the code under test.
func cloneMessages(msgs []domain.Message) []domain.Message {
	if msgs == nil {
		return nil
	}
	out := make([]domain.Message, len(msgs))
	for i, m := range msgs {
		out[i].Role = m.Role
		if m.Parts == nil {
			continue
		}
		out[i].Parts = make([]domain.Part, len(m.Parts))
		for j, p := range m.Parts {
			out[i].Parts[j].Text = p.Text
			if p.Untrusted != nil {
				b := *p.Untrusted
				out[i].Parts[j].Untrusted = &b
			}
		}
	}
	return out
}

func cloneRequest(r domain.Request) domain.Request {
	r.Messages = cloneMessages(r.Messages)
	r.Schema = append(json.RawMessage(nil), r.Schema...)
	return r
}

// spyCall is what an honest provider saw.
type spyCall struct {
	tenant    tenancy.ID
	withTools bool
	route     domain.Route
	req       domain.Request
}

// spy is an honest provider of any platform: it records the tenant of its
// context, the route and the request, and answers V under the route model,
// or the configured error. Unknown model: retention required.
type spy struct {
	err   error
	mu    sync.Mutex
	calls []spyCall
}

var spyKnownModels = map[string]bool{
	modelV1: true, "fake-model-a": true, "fake-model-b": true, modelB3: true,
}

func (s *spy) Structured(ctx context.Context, route domain.Route, req domain.Request) (domain.Response, error) {
	return s.call(ctx, false, route, req)
}

func (s *spy) WithTools(ctx context.Context, route domain.Route, req domain.Request, _ []domain.ToolSpec) (domain.Response, error) {
	if req.HasUntrusted() {
		return domain.Response{}, domain.ErrUntrustedWithTools
	}
	return s.call(ctx, true, route, req)
}

func (s *spy) call(ctx context.Context, withTools bool, route domain.Route, req domain.Request) (domain.Response, error) {
	tenant, _ := tenancy.FromContext(ctx)
	s.mu.Lock()
	s.calls = append(s.calls, spyCall{tenant: tenant, withTools: withTools, route: route, req: cloneRequest(req)})
	s.mu.Unlock()
	if s.err != nil {
		return domain.Response{}, s.err
	}
	return domain.Response{
		Output:    append(json.RawMessage(nil), valueV...),
		Model:     route.Model,
		RequestID: "spy-req-1",
		Usage:     domain.Usage{InputTokens: 12, OutputTokens: 5},
	}, nil
}

func (s *spy) Capabilities(route domain.Route) domain.Capabilities {
	if spyKnownModels[route.Model] {
		return domain.Capabilities{}
	}
	return domain.Capabilities{RequiresRetention: true}
}

func (s *spy) Calls() []spyCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]spyCall(nil), s.calls...)
}

// cancelling delegates to the fake, then cancels the caller's context.
type cancelling struct {
	inner  *fake.Provider
	cancel context.CancelFunc
}

func (p *cancelling) Structured(ctx context.Context, route domain.Route, req domain.Request) (domain.Response, error) {
	resp, err := p.inner.Structured(ctx, route, req)
	p.cancel()
	return resp, err
}

func (p *cancelling) WithTools(ctx context.Context, route domain.Route, req domain.Request, tools []domain.ToolSpec) (domain.Response, error) {
	resp, err := p.inner.WithTools(ctx, route, req, tools)
	p.cancel()
	return resp, err
}

func (p *cancelling) Capabilities(route domain.Route) domain.Capabilities {
	return p.inner.Capabilities(route)
}
