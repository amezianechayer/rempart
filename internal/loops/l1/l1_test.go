package l1_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/workflow"

	"github.com/amezianechayer/rempart/internal/intent/domain"
	"github.com/amezianechayer/rempart/internal/llm"
	lldomain "github.com/amezianechayer/rempart/internal/llm/domain"
	llmfake "github.com/amezianechayer/rempart/internal/llm/fake"
	"github.com/amezianechayer/rempart/internal/loops"
	"github.com/amezianechayer/rempart/internal/loops/codec"
	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
	"github.com/amezianechayer/rempart/internal/loops/l1"
	"github.com/amezianechayer/rempart/internal/loops/l1/activities"
	"github.com/amezianechayer/rempart/internal/secrets/envelope"
	secretsfake "github.com/amezianechayer/rempart/internal/secrets/fake"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

// M1-T05 (lean mode, docs/loops/L1.md): the loop L1 on the in-process test
// environment, fake model scripted with the drafts of internal/intent.

const (
	tenantA tenancy.ID = "0f8fad5b-d9cb-469f-a165-70867728950e"
	tenantB tenancy.ID = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
	model              = "fake-model-v1"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := fs.ReadFile(os.DirFS(filepath.Join("..", "..", "intent", "testdata")), name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// draft returns a fixture draft, compact, with the replacements old, new, ...
func draft(t *testing.T, name string, repl ...string) json.RawMessage {
	t.Helper()
	s := string(fixture(t, name))
	for i := 0; i+1 < len(repl); i += 2 {
		if !strings.Contains(s, repl[i]) {
			t.Fatalf("%s: %q not found", name, repl[i])
		}
		s = strings.Replace(s, repl[i], repl[i+1], 1)
	}
	var b bytes.Buffer
	if err := json.Compact(&b, []byte(s)); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func answer(out json.RawMessage) llmfake.Step {
	return llmfake.Step{Response: lldomain.Response{Output: out, Model: model, Usage: lldomain.Usage{InputTokens: 100, OutputTokens: 50}}}
}

func times(s llmfake.Step, n int) []llmfake.Step {
	out := make([]llmfake.Step, n)
	for i := range out {
		out[i] = s
	}
	return out
}

func referenceContext() domain.TenantContext {
	return domain.TenantContext{AllowedRegions: []string{"eu-west-3", "francecentral"}}
}

func referenceInput(t *testing.T) l1.Input {
	return l1.Input{RequestText: string(fixture(t, "reference-request.txt")), Context: referenceContext(), Round: 1}
}

type harness struct {
	env     *testsuite.TestWorkflowEnvironment
	prov    *llmfake.Provider
	mu      sync.Mutex
	started map[string]int
}

func newHarness(t *testing.T, tenant tenancy.ID, steps []llmfake.Step) *harness {
	t.Helper()
	opt := llmfake.Options{Models: map[string]lldomain.Capabilities{model: {NativeStructuredOutput: true}}}
	if len(steps) > 0 {
		opt.Scripts = map[string][]llmfake.Step{activities.PromptID: steps}
	}
	prov, err := llmfake.New(opt)
	if err != nil {
		t.Fatal(err)
	}
	res, err := llmfake.NewStaticResolver(map[tenancy.ID]lldomain.TenantPolicy{tenant: {
		Route: lldomain.Route{Platform: lldomain.PlatformFake, Model: model}, Residency: lldomain.ResidencyEU, Retention: lldomain.RetentionZero,
	}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := llm.NewClient(prov, res, nil, llm.Config{MaxTokensPerCall: activities.MaxTokensPerCall, AllowFakeRoute: true})
	if err != nil {
		t.Fatal(err)
	}
	var suite testsuite.WorkflowTestSuite
	h := &harness{env: suite.NewTestWorkflowEnvironment(), prov: prov, started: map[string]int{}}
	if err := l1.Register(h.env, &activities.Activities{LLM: c, Tenant: tenant}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	h.env.SetOnActivityStartedListener(func(info *activity.Info, _ context.Context, _ converter.EncodedValues) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.started[info.ActivityType.Name]++
	})
	return h
}

// sealed puts the converters of Rempart for tenant on the environment of h.
func (h *harness) sealed(t *testing.T, tenant tenancy.ID) *harness {
	t.Helper()
	s, err := envelope.NewSealer(secretsfake.NewKeyWrapper([32]byte{0x4c, 0x31}), envelope.Options{})
	if err != nil {
		t.Fatal(err)
	}
	dc, err := codec.NewDataConverter(s, tenant)
	if err != nil {
		t.Fatal(err)
	}
	fc, err := codec.NewFailureConverter(dc)
	if err != nil {
		t.Fatal(err)
	}
	h.env.SetDataConverter(dc)
	h.env.SetFailureConverter(fc)
	h.env.SetContextPropagators([]workflow.ContextPropagator{codec.NewTenantPropagator()})
	h.env.SetHeader(&commonpb.Header{Fields: map[string]*commonpb.Payload{codec.TenantHeader: {
		Metadata: map[string][]byte{converter.MetadataEncoding: []byte(codec.EncodingTenant)},
		Data:     []byte(tenant),
	}}})
	return h
}

func (h *harness) count(name string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.started[name]
}

func (h *harness) run(t *testing.T, in l1.Input) (l1.Output, error) {
	t.Helper()
	h.env.ExecuteWorkflow(l1.WorkflowName, in)
	if !h.env.IsWorkflowCompleted() {
		t.Fatal("workflow did not complete")
	}
	if err := h.env.GetWorkflowError(); err != nil {
		return l1.Output{}, err
	}
	var out l1.Output
	if err := h.env.GetWorkflowResult(&out); err != nil {
		t.Fatalf("GetWorkflowResult: %v", err)
	}
	return out, nil
}

func mustRun(t *testing.T, h *harness, in l1.Input) l1.Output {
	t.Helper()
	out, err := h.run(t, in)
	if err != nil {
		t.Fatalf("workflow error: %v", err)
	}
	return out
}

// tree decodes v once encoded as JSON.
func tree(t *testing.T, v any) any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// referenceIR is reference-ir.json with the tenant of the worker.
func referenceIR(t *testing.T, tenant tenancy.ID) any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(fixture(t, "reference-ir.json"), &m); err != nil {
		t.Fatal(err)
	}
	m["tenant_id"] = string(tenant)
	return m
}

func assertEscalatedWithoutIR(t *testing.T, h *harness, out l1.Output) {
	t.Helper()
	if out.Status != l1.StatusEscalated || out.IR != nil {
		t.Errorf("status %s, IR %v; want escalated without IR", out.Status, out.IR != nil)
	}
	if out.Contradictions == nil {
		t.Error("contradictions is nil, want a list")
	}
	if n := h.count(l1.FinalizeActivity); n != 0 && out.Reason != l1.ReasonClarificationExhausted {
		t.Errorf("%d finalizations after an escalation of the loop", n)
	}
	assertNoDraft(t, out)
}

// assertNoDraft (review of M1-T05, T98): the output never carries a draft of
// the model, the rejected best candidate least of all: the IR is the only
// deliverable.
func assertNoDraft(t *testing.T, out l1.Output) {
	t.Helper()
	if out.Loop.Best != nil {
		t.Errorf("output carries the best candidate of the loop: %s", out.Loop.Best)
	}
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if loop, ok := m["loop"].(map[string]any); !ok || loop["best"] != nil {
		t.Errorf("serialized output has a loop without object or with a best key: %s", raw)
	}
}

// TestL1ConvergesOnReferenceScenario (C3 at the loop level): the reference
// draft converges in one proposal into reference-ir.json with the tenant of
// the worker, with and without the codec of Rempart.
func TestL1ConvergesOnReferenceScenario(t *testing.T) {
	for name, seal := range map[string]bool{"plain": false, "sealed": true} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, tenantA, []llmfake.Step{answer(draft(t, "reference-draft.json"))})
			if seal {
				h.sealed(t, tenantA)
			}
			out := mustRun(t, h, referenceInput(t))
			if out.Status != l1.StatusConverged || out.IR == nil || out.Loop.Status != loops.StatusConverged {
				t.Fatalf("status %s, loop %s, reason %s/%s, remaining %+v; want converged with an IR", out.Status, out.Loop.Status, out.Reason, out.Loop.Reason, out.Loop.Remaining)
			}
			if got, want := tree(t, out.IR), referenceIR(t, tenantA); !reflect.DeepEqual(got, want) {
				t.Errorf("IR differs from reference-ir.json\n got: %v\nwant: %v", got, want)
			}
			if len(out.Contradictions) != 0 || out.Contradictions == nil {
				t.Errorf("contradictions %+v, want an empty list", out.Contradictions)
			}
			for _, a := range []string{l1.PrepareActivity, l1.ProposeActivity, l1.VerifyActivity, l1.FinalizeActivity} {
				if n := h.count(a); n != 1 {
					t.Errorf("%s started %d times, want 1", a, n)
				}
			}
			if n := h.prov.Invocations(); n != 1 {
				t.Errorf("%d provider calls, want 1", n)
			}
			assertNoDraft(t, out)
		})
	}
}

// TestL1CorrectionThenConverge: an invented budget is a finding; the second
// proposal receives the previous draft and the findings, in untrusted blocks
// only, and converges.
func TestL1CorrectionThenConverge(t *testing.T) {
	bad := draft(t, "reference-draft.json", `"monthly_budget_eur": 1500`, `"monthly_budget_eur": 9999`)
	h := newHarness(t, tenantA, []llmfake.Step{answer(bad), answer(draft(t, "reference-draft.json"))})
	out := mustRun(t, h, referenceInput(t))
	if out.Status != l1.StatusConverged || out.IR == nil {
		t.Fatalf("status %s, reason %s, remaining %+v; want converged", out.Status, out.Loop.Reason, out.Loop.Remaining)
	}
	calls := h.prov.Calls()
	if len(calls) != 2 {
		t.Fatalf("%d provider calls, want 2", len(calls))
	}
	if b := untrusted(calls[0].Request, activities.SourcePreviousDraft); len(b) != 0 {
		t.Errorf("first proposal carries a previous draft: %q", b)
	}
	prev, finds := untrusted(calls[1].Request, activities.SourcePreviousDraft), untrusted(calls[1].Request, activities.SourceFindings)
	if len(prev) != 1 || !strings.Contains(prev[0], "9999") {
		t.Errorf("correction previous draft blocks %q, want the first draft", prev)
	}
	if len(finds) != 1 || !strings.Contains(finds[0], "INTENT-") {
		t.Errorf("correction findings blocks %q, want the INTENT findings", finds)
	}
	for _, p := range textParts(calls[1].Request) {
		if strings.Contains(p, "9999") || strings.Contains(p, "INTENT-") {
			t.Errorf("trusted text part quotes the draft or a finding: %q", p)
		}
	}
}

// TestL1EscalatesAfterCorrectionBudget: a draft that never passes escalates
// within the budget of the fiche, without IR and without finalization.
func TestL1EscalatesAfterCorrectionBudget(t *testing.T) {
	bad := draft(t, "reference-draft.json", `"monthly_budget_eur": 1500`, `"monthly_budget_eur": 9999`)
	h := newHarness(t, tenantA, times(answer(bad), 8))
	out := mustRun(t, h, referenceInput(t))
	assertEscalatedWithoutIR(t, h, out)
	if n := h.prov.Invocations(); n < 3 || n > l1.Spec().Budget.MaxIterations {
		t.Errorf("%d provider calls, want 3 to %d", n, l1.Spec().Budget.MaxIterations)
	}
	if out.Reason == "" || out.Reason != string(out.Loop.Reason) {
		t.Errorf("reason %q, loop reason %q; want the reason of the loop", out.Reason, out.Loop.Reason)
	}
	if len(out.Loop.Remaining) == 0 {
		t.Error("escalation without the remaining findings")
	}
}

// TestL1InjectionNoExposure (C4 at the loop level): a model that obeys the
// injection never yields an IR exposing the database; a model that captures
// the request in explicit_overrides yields an IR without exposure.
func TestL1InjectionNoExposure(t *testing.T) {
	in := l1.Input{RequestText: string(fixture(t, "c4-request.txt")), Round: 1}
	t.Run("obeys", func(t *testing.T) {
		h := newHarness(t, tenantA, times(answer(draft(t, "drafts/c4-obey-managed-db.json")), 8))
		out := mustRun(t, h, in)
		assertEscalatedWithoutIR(t, h, out)
		if !slices.ContainsFunc(out.Loop.Remaining, func(f loopsFinding) bool { return f.Code == "INTENT-EXPOSURE-SENSITIVE" }) {
			t.Errorf("remaining findings %+v, want INTENT-EXPOSURE-SENSITIVE", out.Loop.Remaining)
		}
		raw, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(`"exposure"`)) || bytes.Contains(raw, []byte("demande d'exposition")) {
			t.Errorf("escalated output carries the exposure of the injected draft: %s", raw)
		}
	})
	t.Run("obeys_then_override", func(t *testing.T) {
		h := newHarness(t, tenantA, []llmfake.Step{answer(draft(t, "drafts/c4-obey-managed-db.json")), answer(draft(t, "drafts/c4-override.json"))})
		out := mustRun(t, h, in)
		if out.IR == nil || out.Status == l1.StatusEscalated {
			t.Fatalf("status %s, reason %s, remaining %+v; want an IR", out.Status, out.Reason, out.Loop.Remaining)
		}
		if len(out.IR.Exposure) != 0 || len(out.IR.ExplicitOverrides) != 1 {
			t.Errorf("exposure %+v, overrides %+v; want none and one", out.IR.Exposure, out.IR.ExplicitOverrides)
		}
	})
}

// TestL1TenantFromContextOnly (rule 9, T3): no tenant in the input; the IR
// carries the tenant of the worker; a draft that names a tenant never becomes
// an IR.
func TestL1TenantFromContextOnly(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeFor[l1.Input](), reflect.TypeFor[domain.TenantContext](), reflect.TypeFor[activities.Answer]()} {
		for f := range typ.Fields() {
			if strings.Contains(strings.ToLower(f.Name+f.Tag.Get("json")), "tenant") && f.Type != reflect.TypeFor[domain.TenantContext]() {
				t.Errorf("%s.%s names a tenant", typ.Name(), f.Name)
			}
		}
	}
	t.Run("worker_tenant", func(t *testing.T) {
		h := newHarness(t, tenantB, []llmfake.Step{answer(draft(t, "reference-draft.json"))})
		out := mustRun(t, h, referenceInput(t))
		if out.IR == nil || out.IR.TenantID != string(tenantB) {
			t.Fatalf("IR %+v, want the tenant of the worker", out.IR)
		}
	})
	for _, name := range []string{"tenant-top-level.json", "tenant-nested-in-workload.json", "tenant-camel-case.json"} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, tenantA, times(answer(draft(t, "drafts/"+name)), 8))
			out := mustRun(t, h, referenceInput(t))
			// The strict output schema of the prompt refuses the tenant key in
			// llm.Client already; Verify reports it too (activities tests).
			assertEscalatedWithoutIR(t, h, out)
			if h.count(l1.FinalizeActivity) != 0 {
				t.Error("a draft naming a tenant reached Finalize")
			}
		})
	}
}

// TestL1ContradictionsBecomeQuestions (rule 5, D4): a region outside the
// tenant context is a contradiction asked first, with a safe default; at the
// last round the loop escalates instead of asking again.
func TestL1ContradictionsBecomeQuestions(t *testing.T) {
	in := referenceInput(t)
	in.Context = domain.TenantContext{AllowedRegions: []string{"francecentral"}}
	h := newHarness(t, tenantA, []llmfake.Step{answer(draft(t, "reference-draft.json"))})
	out := mustRun(t, h, in)
	if out.Status != l1.StatusNeedsClarification || out.IR == nil {
		t.Fatalf("status %s, reason %s, remaining %+v; want needs_clarification with an IR", out.Status, out.Reason, out.Loop.Remaining)
	}
	if len(out.Contradictions) == 0 || out.Contradictions[0].Code != domain.ContraRegionNotAllowed {
		t.Fatalf("contradictions %+v, want %s first", out.Contradictions, domain.ContraRegionNotAllowed)
	}
	qs := out.IR.OpenQuestions
	if len(qs) == 0 || len(qs) > 3 || qs[0].Field != out.Contradictions[0].Field || qs[0].Default == "" || qs[0].Question == "" {
		t.Errorf("open questions %+v, want the contradiction first, with a default, 3 at most", qs)
	}
	t.Run("last_round", func(t *testing.T) {
		h := newHarness(t, tenantA, []llmfake.Step{answer(draft(t, "reference-draft.json"))})
		in.Round = l1.MaxRounds
		out := mustRun(t, h, in)
		assertEscalatedWithoutIR(t, h, out)
		if out.Reason != l1.ReasonClarificationExhausted || len(out.Contradictions) == 0 {
			t.Errorf("reason %q, contradictions %+v; want %s with the contradictions", out.Reason, out.Contradictions, l1.ReasonClarificationExhausted)
		}
	})
}

// TestL1UserTextIsUntrustedNoTools (D9, T85): the request and the answers
// reach the model only in untrusted blocks, in a call without tools, with the
// prompt intent.extract.v1.
func TestL1UserTextIsUntrustedNoTools(t *testing.T) {
	const marker, answerText = "Budget de 1500 euros", "retention de 90 jours"
	in := referenceInput(t)
	in.Round = 2
	in.PriorAnswers = []activities.Answer{{Field: "observability.retention_days", Answer: answerText}}
	h := newHarness(t, tenantA, []llmfake.Step{answer(draft(t, "reference-draft.json"))})
	if _, err := h.run(t, in); err != nil {
		t.Fatalf("workflow error: %v", err)
	}
	calls := h.prov.Calls()
	if len(calls) == 0 {
		t.Fatal("no provider call")
	}
	for i, c := range calls {
		if c.WithTools || len(c.Tools) != 0 || c.Request.PromptID != activities.PromptID {
			t.Errorf("call %d: tools %v %d, prompt %s; want Structured without tools, %s", i, c.WithTools, len(c.Tools), c.Request.PromptID, activities.PromptID)
		}
		for _, p := range append(textParts(c.Request), c.Request.System) {
			if strings.Contains(p, marker) || strings.Contains(p, answerText) {
				t.Errorf("call %d: user text in a trusted part: %q", i, p)
			}
		}
		if req := untrusted(c.Request, activities.SourceRequest); len(req) != 1 || !strings.Contains(req[0], marker) {
			t.Errorf("call %d: request blocks %q, want one with the request", i, req)
		}
		if ans := untrusted(c.Request, activities.SourceAnswer); len(ans) != 1 || !strings.Contains(ans[0], answerText) {
			t.Errorf("call %d: answer blocks %q, want one with the answer", i, ans)
		}
	}
}

// TestL1LanguageUnsupportedEscalates (obligation (dh)): a request in an
// uncovered language escalates without any proposer call.
func TestL1LanguageUnsupportedEscalates(t *testing.T) {
	in := l1.Input{RequestText: "Ich möchte einen Kubernetes-Cluster auf AWS in eu-west-3 mit drei Knoten für eine öffentliche Webanwendung.", Round: 1}
	h := newHarness(t, tenantA, []llmfake.Step{answer(draft(t, "reference-draft.json"))})
	out := mustRun(t, h, in)
	assertEscalatedWithoutIR(t, h, out)
	if out.Reason != l1.ReasonLanguageUnsupported {
		t.Errorf("reason %q, want %s", out.Reason, l1.ReasonLanguageUnsupported)
	}
	if n := h.prov.Invocations(); n != 0 || h.count(l1.ProposeActivity) != 0 {
		t.Errorf("%d provider calls, %d proposals; want 0, 0", n, h.count(l1.ProposeActivity))
	}
}

// TestL1InputBounds: an input out of bounds fails the workflow before any
// provider call.
func TestL1InputBounds(t *testing.T) {
	ok := referenceInput(t)
	cases := map[string]func(*l1.Input){
		"empty_text":     func(in *l1.Input) { in.RequestText = " \n" },
		"text_too_long":  func(in *l1.Input) { in.RequestText = strings.Repeat("données ", activities.MaxRequestBytes/8+1) },
		"nul_byte":       func(in *l1.Input) { in.RequestText = "Je veux \x00 un cluster." },
		"round_zero":     func(in *l1.Input) { in.Round = 0 },
		"round_four":     func(in *l1.Input) { in.Round = l1.MaxRounds + 1 },
		"answers_round1": func(in *l1.Input) { in.PriorAnswers = []activities.Answer{{Field: "environment", Answer: "prod"}} },
		"too_many_answers": func(in *l1.Input) {
			in.Round = 2
			in.PriorAnswers = slices.Repeat([]activities.Answer{{Field: "environment", Answer: "prod"}}, activities.MaxAnswers+1)
		},
		"answer_too_long": func(in *l1.Input) {
			in.Round = 2
			in.PriorAnswers = []activities.Answer{{Field: "environment", Answer: strings.Repeat("a", activities.MaxAnswerBytes+1)}}
		},
		"too_many_regions": func(in *l1.Input) {
			in.Context.AllowedRegions = slices.Repeat([]string{"eu-west-3"}, activities.MaxContextItems+1)
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			in := ok
			in.Context.AllowedRegions = slices.Clone(ok.Context.AllowedRegions)
			edit(&in)
			h := newHarness(t, tenantA, []llmfake.Step{answer(draft(t, "reference-draft.json"))})
			if _, err := h.run(t, in); err == nil {
				t.Fatal("workflow succeeded, want an input error")
			}
			if n := h.prov.Invocations(); n != 0 {
				t.Errorf("%d provider calls, want 0", n)
			}
		})
	}
}

// TestL1Register: nil arguments and the system tenant are refused; the spec
// is valid and carries the budget of the fiche.
func TestL1Register(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	c, err := llm.NewClient(&llmfake.Provider{}, &llmfake.StaticResolver{}, nil, llm.Config{MaxTokensPerCall: 1})
	if err != nil {
		t.Fatal(err)
	}
	for name, a := range map[string]*activities.Activities{
		"nil":           nil,
		"nil_llm":       {Tenant: tenantA},
		"system_tenant": {LLM: c, Tenant: tenancy.System},
		"bad_tenant":    {LLM: c, Tenant: "x"},
	} {
		if err := l1.Register(env, a); !errors.Is(err, l1.ErrInvalidRegistration) {
			t.Errorf("%s: Register = %v, want ErrInvalidRegistration", name, err)
		}
	}
	if err := l1.Register(nil, &activities.Activities{LLM: c, Tenant: tenantA}); !errors.Is(err, l1.ErrInvalidRegistration) {
		t.Errorf("nil registry: Register = %v", err)
	}
	s := l1.Spec()
	if err := s.Validate(); err != nil {
		t.Fatalf("Spec: %v", err)
	}
	if b := s.Budget; b.MaxIterations != 4 || b.MaxTokens != 40000 || b.MaxWallTime.Minutes() != 3 || s.SwitchAfter != 2 || s.EscalateAfter != 3 {
		t.Errorf("spec %+v, want the budget of docs/loops/L1.md", s)
	}
	if !slices.Equal(s.Strategies, []string{activities.StrategyDirect, activities.StrategyFocusedCorrection}) {
		t.Errorf("strategies %q", s.Strategies)
	}
}

type loopsFinding = loopsdomain.Finding

func untrusted(r lldomain.Request, source string) []string {
	var out []string
	for _, m := range r.Messages {
		for _, p := range m.Parts {
			if p.Untrusted != nil && p.Untrusted.SourceID == source {
				out = append(out, p.Untrusted.Content)
			}
		}
	}
	return out
}

func textParts(r lldomain.Request) []string {
	var out []string
	for _, m := range r.Messages {
		for _, p := range m.Parts {
			if p.Untrusted == nil {
				out = append(out, p.Text)
			}
		}
	}
	return out
}

// TestL1OutputCarriesRoute (obligation (eg), T101): a delivered IR comes with
// the effective route (platform, region, model) and the pinned prompt; an
// escalation without proposer call carries none.
func TestL1OutputCarriesRoute(t *testing.T) {
	h := newHarness(t, tenantA, []llmfake.Step{answer(draft(t, "reference-draft.json"))})
	out := mustRun(t, h, referenceInput(t))
	want := l1.Route{Platform: "fake", Region: "", Model: model, PromptID: activities.PromptID, PromptHash: activities.PromptHash}
	if out.Route == nil || *out.Route != want {
		t.Errorf("route %+v, want %+v", out.Route, want)
	}
	raw, err := json.Marshal(out)
	if err != nil || !bytes.Contains(raw, []byte(`"route":{"platform":"fake","region":"","model":"fake-model-v1"`)) {
		t.Errorf("serialized output %s, %v; want the route", raw, err)
	}
	h = newHarness(t, tenantA, []llmfake.Step{answer(draft(t, "reference-draft.json"))})
	esc := mustRun(t, h, l1.Input{RequestText: "Ich möchte einen Kubernetes-Cluster auf AWS in eu-west-3 mit drei Knoten.", Round: 1})
	if esc.Route != nil {
		t.Errorf("escalation without model call carries a route %+v", esc.Route)
	}
}
