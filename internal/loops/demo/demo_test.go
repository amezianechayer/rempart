package demo_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/workflow"

	"github.com/amezianechayer/rempart/internal/llm"
	lldomain "github.com/amezianechayer/rempart/internal/llm/domain"
	llmfake "github.com/amezianechayer/rempart/internal/llm/fake"
	"github.com/amezianechayer/rempart/internal/llm/prompts"
	"github.com/amezianechayer/rempart/internal/llm/schema"
	"github.com/amezianechayer/rempart/internal/loops"
	"github.com/amezianechayer/rempart/internal/loops/demo"
	"github.com/amezianechayer/rempart/internal/loops/demo/activities"
	"github.com/amezianechayer/rempart/internal/loops/domain"
	loopsfake "github.com/amezianechayer/rempart/internal/loops/fake"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

// Fixtures of plan M0-demo-workflow, section 6.2.
const (
	tenantA        tenancy.ID = "0f8fad5b-d9cb-469f-a165-70867728950e"
	tenantB        tenancy.ID = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
	model                     = "fake-model-v1"
	target                    = "bonjour"
	commitName                = "demo.Commit"
	verifyApproval            = "demo.VerifyApproval"
	loopsImport               = "github.com/amezianechayer/rempart/internal/loops"
	workflowImport            = "go.temporal.io/sdk/workflow"
)

var (
	greetBonjour = json.RawMessage(`{"greeting":"bonjour"}`)
	greetSalut   = json.RawMessage(`{"greeting":"salut"}`)
	targetLoad   = json.RawMessage(`{"target":"bonjour"}`)
)

func input() demo.Input {
	return demo.Input{Target: target, Author: "alice", ApprovalTimeout: 5 * time.Second}
}

func answer(out json.RawMessage) llmfake.Step {
	return llmfake.Step{Response: lldomain.Response{Output: out, Model: model, Usage: lldomain.Usage{InputTokens: 10, OutputTokens: 5}}}
}

func times(s llmfake.Step, n int) []llmfake.Step {
	out := make([]llmfake.Step, n)
	for i := range out {
		out[i] = s
	}
	return out
}

// expectedHash recomputes D8: SHA-256 of the domain line then the candidate.
func expectedHash(best json.RawMessage) string {
	sum := sha256.Sum256(append([]byte("rempart-demo-plan-v1\n"), best...))
	return hex.EncodeToString(sum[:])
}

func signedBy(approver, planHash string) loops.Approval {
	a := loops.Approval{Approved: true, PlanHash: planHash, Approver: approver}
	a.Signature = loopsfake.ExpectedSignature(a)
	return a
}

// newClient: fake provider and resolver, tenant A only, EU residency, zero retention.
func newClient(t *testing.T, steps []llmfake.Step) (*llm.Client, *llmfake.Provider) {
	t.Helper()
	opt := llmfake.Options{Models: map[string]lldomain.Capabilities{model: {NativeStructuredOutput: true}}}
	if len(steps) > 0 {
		opt.Scripts = map[string][]llmfake.Step{activities.PromptID: steps}
	}
	prov, err := llmfake.New(opt)
	if err != nil {
		t.Fatalf("fake.New: %v", err)
	}
	res, err := llmfake.NewStaticResolver(map[tenancy.ID]lldomain.TenantPolicy{tenantA: {
		Route:     lldomain.Route{Platform: lldomain.PlatformFake, Model: model},
		Residency: lldomain.ResidencyEU, Retention: lldomain.RetentionZero,
	}})
	if err != nil {
		t.Fatalf("NewStaticResolver: %v", err)
	}
	c, err := llm.NewClient(prov, res, nil, llm.Config{MaxCorrections: 0, MaxTokensPerCall: 256, AllowFakeRoute: true})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c, prov
}

// harness runs the registered demo in the in-process test suite: no socket.
type harness struct {
	env     *testsuite.TestWorkflowEnvironment
	prov    *llmfake.Provider
	mu      sync.Mutex
	started map[string]int
	commits []string
	start   time.Time
}

func newHarness(t *testing.T, tenant tenancy.ID, steps []llmfake.Step) *harness {
	t.Helper()
	return newHarnessWith(t, tenant, steps, &loopsfake.ApprovalVerifier{})
}

// newHarnessWith registers the demo with the verifier v.
func newHarnessWith(t *testing.T, tenant tenancy.ID, steps []llmfake.Step, v demo.ApprovalVerifier) *harness {
	t.Helper()
	c, prov := newClient(t, steps)
	var suite testsuite.WorkflowTestSuite
	h := &harness{env: suite.NewTestWorkflowEnvironment(), prov: prov, started: map[string]int{}}
	if err := demo.Register(h.env, &activities.Activities{LLM: c, Tenant: tenant}, v); err != nil {
		t.Fatalf("Register: %v", err)
	}
	h.env.SetOnActivityStartedListener(func(info *activity.Info, _ context.Context, args converter.EncodedValues) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.started[info.ActivityType.Name]++
		if info.ActivityType.Name == commitName {
			var s string
			if err := args.Get(&s); err != nil {
				s = "undecodable"
			}
			h.commits = append(h.commits, s)
		}
	})
	return h
}

func (h *harness) signalAt(d time.Duration, a loops.Approval) {
	h.env.RegisterDelayedCallback(func() { h.env.SignalWorkflow(loops.ApprovalSignal, a) }, d)
}

// run executes the workflow by its registered name and returns its output or
// error; in is a demo.Input or, to test the decoding, a json.RawMessage.
func (h *harness) run(t *testing.T, in any) (demo.Output, error) {
	t.Helper()
	h.start = h.env.Now()
	h.env.ExecuteWorkflow(demo.WorkflowName, in)
	if !h.env.IsWorkflowCompleted() {
		t.Fatal("workflow not completed")
	}
	var out demo.Output
	if err := h.env.GetWorkflowError(); err != nil {
		return out, err
	}
	if err := h.env.GetWorkflowResult(&out); err != nil {
		t.Fatalf("GetWorkflowResult: %v", err)
	}
	return out, nil
}

func (h *harness) count(name string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.started[name]
}

func (h *harness) total() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, c := range h.started {
		n += c
	}
	return n
}

func (h *harness) elapsed() time.Duration { return h.env.Now().Sub(h.start) }

func mustRun(t *testing.T, h *harness, in any) demo.Output {
	t.Helper()
	out, err := h.run(t, in)
	if err != nil {
		t.Fatalf("workflow failed: %v", err)
	}
	return out
}

func wantIgnored(t *testing.T, got []loops.IgnoredSignal, want ...loops.IgnoredSignal) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("ignored = %+v, want %+v", got, want)
	}
}

func appError(t *testing.T, err error) *temporal.ApplicationError {
	t.Helper()
	var ae *temporal.ApplicationError
	if !errors.As(err, &ae) {
		t.Fatalf("error %v (%T) holds no ApplicationError", err, err)
	}
	return ae
}

func wantValidation(t *testing.T, err error) {
	t.Helper()
	ae := appError(t, err)
	if ae.Type() != loops.ErrTypeValidation || !ae.NonRetryable() {
		t.Errorf("error type %q non-retryable %v, want %q non-retryable", ae.Type(), ae.NonRetryable(), loops.ErrTypeValidation)
	}
}

// TestDemoConverges: the second proposal converges; the target reaches the
// model only as an untrusted block; nobody approves, nothing is committed.
func TestDemoConverges(t *testing.T) {
	h := newHarness(t, tenantA, []llmfake.Step{answer(greetSalut), answer(greetBonjour)})
	out := mustRun(t, h, input())
	l := out.Loop
	if l.Status != loops.StatusConverged || l.Iterations != 2 || l.Tokens != 30 {
		t.Fatalf("loop = %s, %d iterations, %d tokens; want converged, 2, 30", l.Status, l.Iterations, l.Tokens)
	}
	if string(l.Best) != string(greetBonjour) {
		t.Errorf("best = %s, want %s", l.Best, greetBonjour)
	}
	if out.PlanHash != expectedHash(greetBonjour) {
		t.Errorf("plan hash = %q, want %q", out.PlanHash, expectedHash(greetBonjour))
	}
	if out.Approval.Outcome != loops.OutcomeTimedOut || out.Committed || h.count(commitName) != 0 {
		t.Errorf("approval %q, committed %v, %d commits; want timed_out, false, 0", out.Approval.Outcome, out.Committed, h.count(commitName))
	}
	calls := h.prov.Calls()
	if len(calls) != 2 {
		t.Fatalf("%d provider calls, want 2", len(calls))
	}
	for i, c := range calls {
		r := c.Request
		if r.PromptID != activities.PromptID || r.PromptHash != activities.PromptHash {
			t.Errorf("call %d: prompt %q %q, want %q %q", i, r.PromptID, r.PromptHash, activities.PromptID, activities.PromptHash)
		}
		if c.WithTools || len(c.Tools) != 0 {
			t.Errorf("call %d carries tools", i)
		}
		var blocks []string
		for _, m := range r.Messages {
			for _, p := range m.Parts {
				if p.Untrusted != nil {
					blocks = append(blocks, p.Untrusted.Content)
				}
				if strings.Contains(p.Text, target) || strings.Contains(p.Text, "salut") {
					t.Errorf("call %d: text part %q quotes the target or a candidate (D4)", i, p.Text)
				}
			}
		}
		if !slices.Equal(blocks, []string{target}) {
			t.Errorf("call %d: untrusted blocks %q, want exactly [%q]", i, blocks, target)
		}
	}
}

// TestDemoStagnationEscalatesWithoutApprovalWait: an escalation never waits for an approval.
func TestDemoStagnationEscalatesWithoutApprovalWait(t *testing.T) {
	h := newHarness(t, tenantA, times(answer(greetSalut), 3))
	in := input()
	in.ApprovalTimeout = time.Hour
	out := mustRun(t, h, in)
	l := out.Loop
	if l.Status != loops.StatusEscalated || l.Reason != loops.ReasonStagnation {
		t.Fatalf("loop = %s %s, want escalated stagnation", l.Status, l.Reason)
	}
	var strategies []string
	for _, tr := range l.Trace {
		strategies = append(strategies, tr.Strategy)
	}
	want := []string{activities.StrategyDirect, activities.StrategyDirect, activities.StrategyReformulate}
	if !slices.Equal(strategies, want) {
		t.Errorf("strategies = %v, want %v", strategies, want)
	}
	if !reflect.DeepEqual(out.Approval, loops.ApprovalResult{}) || out.PlanHash != "" || out.Committed {
		t.Errorf("approval %+v, plan hash %q, committed %v; want zero, empty, false", out.Approval, out.PlanHash, out.Committed)
	}
	if h.count(verifyApproval) != 0 || h.count(commitName) != 0 {
		t.Errorf("VerifyApproval %d, Commit %d; want 0, 0", h.count(verifyApproval), h.count(commitName))
	}
	if h.elapsed() >= time.Hour {
		t.Errorf("simulated duration %v: the workflow waited for an approval", h.elapsed())
	}
}

// TestDemoApprovalTimeoutNoCommit: an unsigned signal does not count; the timeout commits nothing.
func TestDemoApprovalTimeoutNoCommit(t *testing.T) {
	h := newHarness(t, tenantA, []llmfake.Step{answer(greetBonjour)})
	h.signalAt(time.Second, loops.Approval{Approved: true, PlanHash: expectedHash(greetBonjour), Approver: "bob", Signature: "unsigned"})
	out := mustRun(t, h, input())
	wantIgnored(t, out.Approval.Ignored, loops.IgnoredSignal{DeclaredApprover: "bob", Reason: loops.IgnoredInvalidSignature})
	if out.Approval.Outcome != loops.OutcomeTimedOut || len(out.Approval.Approvals) != 0 {
		t.Errorf("approval = %+v, want timed_out without approval", out.Approval)
	}
	if h.elapsed() < 5*time.Second {
		t.Errorf("simulated duration %v, want at least 5s", h.elapsed())
	}
	if out.Committed || h.count(commitName) != 0 {
		t.Errorf("committed %v, %d commits; want false, 0", out.Committed, h.count(commitName))
	}
}

// TestDemoApprovedCommitsOnce: the author's own approval is ignored; one other
// signed approval commits exactly once, with the plan hash.
func TestDemoApprovedCommitsOnce(t *testing.T) {
	h := newHarness(t, tenantA, []llmfake.Step{answer(greetBonjour)})
	hash := expectedHash(greetBonjour)
	h.signalAt(time.Second, signedBy("alice", hash))
	h.signalAt(2*time.Second, signedBy("bob", hash))
	out := mustRun(t, h, input())
	wantIgnored(t, out.Approval.Ignored, loops.IgnoredSignal{DeclaredApprover: "alice", Reason: loops.IgnoredSelfApproval})
	if out.Approval.Outcome != loops.OutcomeApproved || len(out.Approval.Approvals) != 1 || out.Approval.Approvals[0].Approver != "bob" {
		t.Fatalf("approval = %+v, want approved by bob", out.Approval)
	}
	h.mu.Lock()
	commits := slices.Clone(h.commits)
	h.mu.Unlock()
	if !slices.Equal(commits, []string{hash}) || !out.Committed || out.PlanHash != hash {
		t.Errorf("commits %q, committed %v, plan hash %q; want [%q], true", commits, out.Committed, out.PlanHash, hash)
	}
}

// TestDemoApprovalOnOtherHashIgnored: a valid signature on another plan does not count.
func TestDemoApprovalOnOtherHashIgnored(t *testing.T) {
	h := newHarness(t, tenantA, []llmfake.Step{answer(greetBonjour)})
	h.signalAt(time.Second, signedBy("bob", strings.Repeat("ab", 32)))
	out := mustRun(t, h, input())
	wantIgnored(t, out.Approval.Ignored, loops.IgnoredSignal{DeclaredApprover: "bob", Reason: loops.IgnoredWrongHash})
	if out.Approval.Outcome != loops.OutcomeTimedOut || out.Committed || h.count(commitName) != 0 {
		t.Errorf("approval %q, committed %v, %d commits; want timed_out, false, 0", out.Approval.Outcome, out.Committed, h.count(commitName))
	}
}

// TestDemoVerifyDeterministic: Verify never needs the model and gives the same result twice.
func TestDemoVerifyDeterministic(t *testing.T) {
	a := &activities.Activities{} // no client: a model call would fail
	verify := func(payload, candidate json.RawMessage) (loops.VerifyResult, error) {
		return a.Verify(t.Context(), loops.VerifyRequest{Payload: payload, Candidate: candidate, Iteration: 1})
	}
	cases := []struct {
		name      string
		candidate json.RawMessage
		code      string // empty: accepted
	}{
		{"equal", greetBonjour, ""},
		{"mismatch", greetSalut, activities.CodeMismatch},
		{"extra_property", json.RawMessage(`{"greeting":"bonjour","x":1}`), activities.CodeSchema},
		{"upper_case", json.RawMessage(`{"greeting":"Bonjour"}`), activities.CodeSchema},
		{"empty", json.RawMessage(`{"greeting":""}`), activities.CodeSchema},
		{"array", json.RawMessage(`[]`), activities.CodeSchema},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first, err1 := verify(targetLoad, tc.candidate)
			second, err2 := verify(targetLoad, tc.candidate)
			if err1 != nil || err2 != nil {
				t.Fatalf("Verify errors %v, %v", err1, err2)
			}
			if !reflect.DeepEqual(first, second) {
				t.Errorf("results differ: %+v then %+v", first, second)
			}
			if tc.code == "" {
				if !first.OK || len(first.Findings) != 0 {
					t.Errorf("result %+v, want OK without finding", first)
				}
				return
			}
			if first.OK || len(first.Findings) != 1 {
				t.Fatalf("result %+v, want one finding %s", first, tc.code)
			}
			f := first.Findings[0]
			if f.Code != tc.code || f.Severity != domain.SeverityHigh || f.Resource != "candidate" {
				t.Errorf("finding %+v, want %s, high, candidate", f, tc.code)
			}
		})
	}
	for _, p := range []string{`{"target":"Bonjour"}`, `{"target":"bonjour","x":"y"}`, `{}`} {
		t.Run("payload_"+p, func(t *testing.T) {
			for range 2 {
				_, err := verify(json.RawMessage(p), greetBonjour)
				wantValidation(t, err)
			}
		})
	}
}

// TestDemoPromptStrict: the embedded prompt is the pinned one and its schema closed.
func TestDemoPromptStrict(t *testing.T) {
	p, err := prompts.Load(activities.PromptID)
	if err != nil {
		t.Fatalf("Load(%q): %v", activities.PromptID, err)
	}
	onDisk, err := prompts.LoadFS(os.DirFS(filepath.Join("..", "..", "llm", "prompts")), activities.PromptID)
	if err != nil {
		t.Fatalf("LoadFS from the source files: %v", err)
	}
	if p.Hash != activities.PromptHash || onDisk.Hash != activities.PromptHash {
		t.Errorf("embedded hash %q, file hash %q, want PromptHash %q", p.Hash, onDisk.Hash, activities.PromptHash)
	}
	if !schema.AdmittedText(p.System) || strings.ContainsRune(p.System, '\r') {
		t.Error("system prompt outside the admission list or with a carriage return")
	}
	for i := range len(p.System) {
		if p.System[i] >= 0x80 {
			t.Fatalf("system prompt byte %d is not ASCII", i)
		}
	}
	if err := p.Schema.Validate(greetBonjour); err != nil {
		t.Errorf("schema refuses %s: %v", greetBonjour, err)
	}
	for _, c := range []string{
		`{"greeting":"bonjour","x":1}`, `{"greeting":"Bonjour"}`, `{"greeting":""}`,
		`{"greeting":"` + strings.Repeat("a", 65) + `"}`, `{"greeting":"a\"b"}`, `{}`,
	} {
		if p.Schema.Validate(json.RawMessage(c)) == nil {
			t.Errorf("schema admits %s", c)
		}
	}
	if p.Schema.Validate(json.RawMessage(`{"greeting":"`+strings.Repeat("a", 64)+`"}`)) != nil {
		t.Error("schema refuses a 64-byte greeting")
	}
}

// TestDemoInputRejected: an invalid input fails before any activity, without quoting the value.
func TestDemoInputRejected(t *testing.T) {
	long := strings.Repeat("a", 65)
	cases := []struct {
		name, quoted string
		mutate       func(*demo.Input)
	}{
		{"target_empty", "", func(in *demo.Input) { in.Target = "" }},
		{"target_upper", "Bonjour", func(in *demo.Input) { in.Target = "Bonjour" }},
		{"target_quote", `a"b`, func(in *demo.Input) { in.Target = `a"b` }},
		{"target_65", long, func(in *demo.Input) { in.Target = long }},
		{"author_empty", "", func(in *demo.Input) { in.Author = "" }},
		{"author_upper", "Alice", func(in *demo.Input) { in.Author = "Alice" }},
		{"timeout_zero", "0s", func(in *demo.Input) { in.ApprovalTimeout = 0 }},
		{"timeout_999ms", "999", func(in *demo.Input) { in.ApprovalTimeout = 999 * time.Millisecond }},
		{"timeout_61m", "1h1m", func(in *demo.Input) { in.ApprovalTimeout = 61 * time.Minute }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tenantA, times(answer(greetBonjour), 4))
			in := input()
			tc.mutate(&in)
			_, err := h.run(t, in)
			if err == nil {
				t.Fatal("workflow succeeded, want InvalidDemoInput")
			}
			ae := appError(t, err)
			if ae.Type() != demo.ErrTypeInvalidDemoInput || !ae.NonRetryable() {
				t.Errorf("error type %q non-retryable %v, want %q non-retryable", ae.Type(), ae.NonRetryable(), demo.ErrTypeInvalidDemoInput)
			}
			if tc.quoted != "" && (strings.Contains(ae.Error(), tc.quoted) || strings.Contains(err.Error(), tc.quoted)) {
				t.Errorf("error %q quotes the value %q", err.Error(), tc.quoted)
			}
			if n := h.prov.Invocations(); n != 0 {
				t.Errorf("%d provider calls, want 0", n)
			}
			if n := h.total(); n != 0 {
				t.Errorf("%d activities started, want 0", n)
			}
		})
	}
}

// TestDemoProposeErrors (D10, D11, obligations (av), (af)): a failure after a
// provider call counts the UsageError bound, declared usage plus MaxTokens and
// the request bytes of a call failed without usage; only an output out of
// schema is retried. A refusal without I/O costs nothing and is not retried.
func TestDemoProposeErrors(t *testing.T) {
	failure := llmfake.Step{Err: "provider_unavailable"}
	mismatch := llmfake.Step{Response: lldomain.Response{
		Output: greetBonjour, Model: "other-model", Usage: lldomain.Usage{InputTokens: 10, OutputTokens: 5},
	}}
	upper := answer(json.RawMessage(`{"greeting":"Bonjour"}`))
	// failedCall is MaxTokensPerCall plus the bytes of the first request the fake saw.
	failedCall := func(t *testing.T, prov *llmfake.Provider) int {
		t.Helper()
		calls := prov.Calls()
		if len(calls) == 0 {
			t.Fatal("no provider call recorded")
		}
		n := llm.RequestBytes(calls[0].Request)
		if n <= 0 {
			t.Fatalf("RequestBytes = %d, want a positive size", n)
		}
		return 256 + n
	}
	fixed := func(n int) func(*testing.T, *llmfake.Provider) int {
		return func(*testing.T, *llmfake.Provider) int { return n }
	}
	cases := []struct {
		name       string
		tenant     tenancy.ID
		steps      []llmfake.Step
		iterations int
		tokens     func(*testing.T, *llmfake.Provider) int
		calls      int
	}{
		{"provider_failure", tenantA, times(failure, 3), 1, failedCall, 1},
		{"model_mismatch", tenantA, times(mismatch, 3), 1, fixed(15), 1},
		{"out_of_schema", tenantA, times(upper, 3), 3, fixed(45), 3},
		{"no_route", tenantB, times(answer(greetBonjour), 3), 1, fixed(0), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.tenant, tc.steps)
			out := mustRun(t, h, input())
			l := out.Loop
			if l.Status != loops.StatusEscalated || l.Reason != loops.ReasonActivityFailed {
				t.Fatalf("loop = %s %s, want escalated activity_failed", l.Status, l.Reason)
			}
			if n := h.prov.Invocations(); n != tc.calls {
				t.Errorf("%d provider calls, want %d", n, tc.calls)
			}
			if want := tc.tokens(t, h.prov); l.Iterations != tc.iterations || l.Tokens != want {
				t.Errorf("%d iterations, %d tokens; want %d, %d", l.Iterations, l.Tokens, tc.iterations, want)
			}
			if out.PlanHash != "" || h.count(verifyApproval) != 0 || h.count(commitName) != 0 {
				t.Error("an escalation computed a plan hash, verified an approval or committed")
			}
		})
	}
	propose := func(t *testing.T, a *activities.Activities) (*temporal.ApplicationError, error) {
		t.Helper()
		_, err := a.Propose(t.Context(), loops.ProposeRequest{Payload: targetLoad, Strategy: activities.StrategyDirect, Iteration: 1})
		if reflect.TypeOf(err) != reflect.TypeFor[*temporal.ApplicationError]() {
			t.Fatalf("error %v of type %T, want *temporal.ApplicationError, never wrapped", err, err)
		}
		return appError(t, err), err
	}
	wantDetail := func(t *testing.T, ae *temporal.ApplicationError, tokens int) {
		t.Helper()
		if ae.Type() != activities.ErrTypeProposeFailed {
			t.Errorf("type %q, want %q", ae.Type(), activities.ErrTypeProposeFailed)
		}
		var pf loops.ProposeFailure
		if !ae.HasDetails() || ae.Details(&pf) != nil || pf != (loops.ProposeFailure{Tokens: tokens}) {
			t.Errorf("details %+v, want ProposeFailure{%d}", pf, tokens)
		}
		p, perr := converter.GetDefaultDataConverter().ToPayload(pf)
		if want := `{"tokens":` + strconv.Itoa(tokens) + `}`; perr != nil || string(p.GetData()) != want {
			t.Errorf("detail encodes to %q, want %q", p.GetData(), want)
		}
	}
	t.Run("direct_billed", func(t *testing.T) {
		c, prov := newClient(t, []llmfake.Step{failure})
		ae, _ := propose(t, &activities.Activities{LLM: c, Tenant: tenantA})
		if !ae.NonRetryable() {
			t.Error("a provider failure is retryable, want non-retryable (D11)")
		}
		wantDetail(t, ae, failedCall(t, prov))
	})
	t.Run("direct_out_of_schema", func(t *testing.T) {
		c, _ := newClient(t, []llmfake.Step{upper})
		ae, _ := propose(t, &activities.Activities{LLM: c, Tenant: tenantA})
		if ae.NonRetryable() {
			t.Error("an output out of schema is non-retryable, want retryable (D11)")
		}
		wantDetail(t, ae, 15)
	})
	t.Run("direct_invalid_tenant", func(t *testing.T) {
		c, prov := newClient(t, []llmfake.Step{answer(greetBonjour)})
		ae, _ := propose(t, &activities.Activities{LLM: c, Tenant: tenancy.ID("not-a-tenant")})
		if !ae.NonRetryable() || ae.HasDetails() {
			t.Errorf("non-retryable %v, details %v; want a non-retryable refusal without detail", ae.NonRetryable(), ae.HasDetails())
		}
		if prov.Invocations() != 0 {
			t.Errorf("%d provider calls, want 0", prov.Invocations())
		}
	})
	t.Run("direct_canceled", func(t *testing.T) {
		c, prov := newClient(t, []llmfake.Step{answer(greetBonjour)})
		a := &activities.Activities{LLM: c, Tenant: tenantA}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := a.Propose(ctx, loops.ProposeRequest{Payload: targetLoad, Strategy: activities.StrategyDirect, Iteration: 1})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error %v, want context.Canceled", err)
		}
		if prov.Invocations() != 0 {
			t.Errorf("%d provider calls, want 0", prov.Invocations())
		}
	})
}

// TestDemoCommitNoEffect: Commit accepts exactly 64 lower-case hex digits and is idempotent.
func TestDemoCommitNoEffect(t *testing.T) {
	a := &activities.Activities{}
	valid := expectedHash(greetBonjour)
	for range 2 {
		if err := a.Commit(t.Context(), valid); err != nil {
			t.Fatalf("Commit(valid) = %v", err)
		}
	}
	for name, h := range map[string]string{
		"empty": "", "upper_case": strings.ToUpper(valid), "63_bytes": valid[:63], "non_hex": strings.Repeat("g", 64),
	} {
		t.Run(name, func(t *testing.T) { wantValidation(t, a.Commit(t.Context(), h)) })
	}
}

// parseDir parses the non-test Go files of dir.
func parseDir(t *testing.T, dir string) []*ast.File {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatalf("no Go source in %s", dir)
	}
	return files
}

func importName(f *ast.File, path string) (string, bool) {
	for _, is := range f.Imports {
		p, err := strconv.Unquote(is.Path.Value)
		if err != nil || p != path {
			continue
		}
		if is.Name != nil {
			return is.Name.Name, true
		}
		return path[strings.LastIndex(path, "/")+1:], true
	}
	return "", false
}

// TestDemoSingleApprovalWait: obligation (o), one approval wait per workflow,
// outside any loop or closure; no raw signal channel nor ContinueAsNew.
func TestDemoSingleApprovalWait(t *testing.T) {
	forbidden := func(name string) bool {
		return name == "GetSignalChannel" || name == "NewContinueAsNewError" || strings.HasPrefix(name, "SetUpdateHandler")
	}
	waits := 0
	for _, f := range parseDir(t, ".") {
		loopsName, hasLoops := importName(f, loopsImport)
		var stack []ast.Node
		ast.Inspect(f, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			stack = append(stack, n)
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if forbidden(sel.Sel.Name) {
				t.Errorf("demo uses %s", sel.Sel.Name)
			}
			x, isIdent := sel.X.(*ast.Ident)
			if !hasLoops || !isIdent || x.Name != loopsName || sel.Sel.Name != "AwaitApprovals" {
				return true
			}
			waits++
			inWorkflow := false
			for _, anc := range stack[:len(stack)-1] {
				switch a := anc.(type) {
				case *ast.ForStmt, *ast.RangeStmt, *ast.GoStmt, *ast.FuncLit:
					t.Errorf("AwaitApprovals under a %T", a)
				case *ast.FuncDecl:
					inWorkflow = a.Recv == nil && a.Name.Name == "Workflow"
				}
			}
			if len(stack) < 2 {
				t.Error("AwaitApprovals at the root")
			} else if call, isCall := stack[len(stack)-2].(*ast.CallExpr); !isCall || call.Fun != sel {
				t.Error("AwaitApprovals used as a value, not called")
			}
			if !inWorkflow {
				t.Error("AwaitApprovals outside func Workflow")
			}
			return true
		})
	}
	if waits != 1 {
		t.Errorf("%d references to loops.AwaitApprovals, want exactly 1", waits)
	}
	for _, f := range parseDir(t, "activities") {
		if _, ok := importName(f, workflowImport); ok {
			t.Errorf("activities imports %s (rule l)", workflowImport)
		}
	}
}

// TestDemoCanceledNoCommit: obligation (m), a cancellation never commits, even
// with a valid approval delivered at the same instant.
func TestDemoCanceledNoCommit(t *testing.T) {
	for _, withApproval := range []bool{true, false} {
		name := "cancel_during_wait"
		if withApproval {
			name = "cancel_with_approval"
		}
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, tenantA, []llmfake.Step{answer(greetBonjour)})
			h.env.RegisterDelayedCallback(func() {
				if withApproval {
					h.env.SignalWorkflow(loops.ApprovalSignal, signedBy("bob", expectedHash(greetBonjour)))
				}
				h.env.CancelWorkflow()
			}, time.Second)
			_, err := h.run(t, input())
			if !temporal.IsCanceledError(err) {
				t.Errorf("error %v, want a cancellation", err)
			}
			if h.count(commitName) != 0 {
				t.Errorf("%d commits after a cancellation, want 0", h.count(commitName))
			}
		})
	}
}

// registry records what Register registers.
type registry struct {
	workflows  map[string]string
	activities map[string]string
}

func funcName(f any) string {
	v := reflect.ValueOf(f)
	if v.Kind() != reflect.Func {
		return "not a function"
	}
	return runtime.FuncForPC(v.Pointer()).Name()
}

func (r *registry) RegisterWorkflowWithOptions(w any, o workflow.RegisterOptions) {
	r.workflows[o.Name] = funcName(w)
}

func (r *registry) RegisterActivityWithOptions(a any, o activity.RegisterOptions) {
	r.activities[o.Name] = funcName(a)
}

// TestDemoRegister: exactly one workflow and four activities, each under its
// name; D9: a nil registry, activities, client or verifier, an invalid tenant
// or the System tenant (T34, T75) refuse the registration, registering nothing.
func TestDemoRegister(t *testing.T) {
	newReg := func() *registry { return &registry{workflows: map[string]string{}, activities: map[string]string{}} }
	c, _ := newClient(t, nil)
	valid := func() *activities.Activities { return &activities.Activities{LLM: c, Tenant: tenantA} }
	r := newReg()
	if err := demo.Register(r, valid(), &loopsfake.ApprovalVerifier{}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if len(r.workflows) != 1 || !strings.HasSuffix(r.workflows[demo.WorkflowName], "/internal/loops/demo.Workflow") {
		t.Errorf("workflows = %v, want only %s -> demo.Workflow", r.workflows, demo.WorkflowName)
	}
	want := map[string]string{
		demo.ProposeActivity: ".Propose-fm", demo.VerifyActivity: ".Verify-fm",
		demo.CommitActivity: ".Commit-fm", demo.VerifyApprovalActivity: ".VerifyApproval-fm",
	}
	if len(r.activities) != len(want) {
		t.Errorf("activities = %v, want exactly %d", r.activities, len(want))
	}
	for name, suffix := range want {
		if fn, ok := r.activities[name]; !ok || !strings.HasSuffix(fn, suffix) {
			t.Errorf("activity %q -> %q, want a function ending in %q", name, fn, suffix)
		}
	}
	if !strings.HasPrefix(r.activities[demo.ProposeActivity], "github.com/amezianechayer/rempart/internal/loops/demo/activities.") {
		t.Errorf("activities bound to unexpected receivers: %v", r.activities)
	}
	if demo.ProposeActivity != "demo.Propose" || demo.VerifyActivity != "demo.Verify" || demo.CommitActivity != commitName || demo.VerifyApprovalActivity != verifyApproval {
		t.Error("activity names differ from the loop card")
	}
	refused := []struct {
		name string
		reg  func(*registry) error
	}{
		{"nil_registry", func(*registry) error { return demo.Register(nil, valid(), &loopsfake.ApprovalVerifier{}) }},
		{"nil_activities", func(r *registry) error { return demo.Register(r, nil, &loopsfake.ApprovalVerifier{}) }},
		{"nil_verifier", func(r *registry) error { return demo.Register(r, valid(), nil) }},
		{"nil_llm", func(r *registry) error {
			return demo.Register(r, &activities.Activities{Tenant: tenantA}, &loopsfake.ApprovalVerifier{})
		}},
		{"invalid_tenant", func(r *registry) error {
			return demo.Register(r, &activities.Activities{LLM: c, Tenant: tenancy.ID("not-a-tenant")}, &loopsfake.ApprovalVerifier{})
		}},
		{"system_tenant", func(r *registry) error {
			return demo.Register(r, &activities.Activities{LLM: c, Tenant: tenancy.System}, &loopsfake.ApprovalVerifier{})
		}},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			r := newReg()
			if err := tc.reg(r); !errors.Is(err, demo.ErrInvalidRegistration) {
				t.Errorf("Register = %v, want ErrInvalidRegistration", err)
			}
			if len(r.workflows)+len(r.activities) != 0 {
				t.Errorf("registered %v %v despite the error", r.workflows, r.activities)
			}
		})
	}
}

// TestDemoRegisterTypedNilVerifierFailsClosed (D9): a typed nil verifier is not
// detectable without reflect. Either Register refuses it, or the verification
// fails and a valid signed approval is ignored (verify_error): the approval
// times out and nothing is committed.
func TestDemoRegisterTypedNilVerifierFailsClosed(t *testing.T) {
	var v *loopsfake.ApprovalVerifier
	c, _ := newClient(t, nil)
	var suite testsuite.WorkflowTestSuite
	if err := demo.Register(suite.NewTestWorkflowEnvironment(), &activities.Activities{LLM: c, Tenant: tenantA}, v); err != nil {
		if !errors.Is(err, demo.ErrInvalidRegistration) {
			t.Fatalf("Register = %v, want nil or ErrInvalidRegistration", err)
		}
		return
	}
	h := newHarnessWith(t, tenantA, []llmfake.Step{answer(greetBonjour)}, v)
	h.signalAt(time.Second, signedBy("bob", expectedHash(greetBonjour)))
	out := mustRun(t, h, input())
	wantIgnored(t, out.Approval.Ignored, loops.IgnoredSignal{DeclaredApprover: "bob", Reason: loops.IgnoredVerifyError})
	if out.Approval.Outcome != loops.OutcomeTimedOut || len(out.Approval.Approvals) != 0 {
		t.Errorf("approval = %+v, want timed_out without approval", out.Approval)
	}
	if out.Committed || h.count(commitName) != 0 {
		t.Errorf("committed %v, %d commits; want false, 0", out.Committed, h.count(commitName))
	}
}

// TestDemoInputDecodingFrozen (T78): the workflow input is decoded by the
// default data converter, as encoding/json does: an unknown field is ignored,
// a key matches its field case-insensitively and the last duplicate wins. This
// test freezes that behaviour for M0; M1 inverts it (closed input decoding).
// The tenant stays the worker's (tenant B has no route: honouring the input
// field would escalate).
func TestDemoInputDecodingFrozen(t *testing.T) {
	const rest = `"author":"alice","approval_timeout":5000000000`
	cases := []struct{ name, raw string }{
		{"extra_tenant", `{"target":"bonjour",` + rest + `,"tenant":"` + string(tenantB) + `"}`},
		{"upper_case_key", `{"TARGET":"bonjour",` + rest + `}`},
		{"duplicate_key", `{"target":"salut","target":"bonjour",` + rest + `}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tenantA, []llmfake.Step{answer(greetBonjour)})
			out := mustRun(t, h, json.RawMessage(tc.raw))
			if out.Loop.Status != loops.StatusConverged || out.Loop.Iterations != 1 {
				t.Fatalf("loop = %s, %d iterations; want converged, 1", out.Loop.Status, out.Loop.Iterations)
			}
			if out.Approval.Outcome != loops.OutcomeTimedOut || out.Committed {
				t.Errorf("approval %q, committed %v; want timed_out, false", out.Approval.Outcome, out.Committed)
			}
			calls := h.prov.Calls()
			if len(calls) != 1 {
				t.Fatalf("%d provider calls, want 1", len(calls))
			}
			var blocks []string
			for _, m := range calls[0].Request.Messages {
				for _, p := range m.Parts {
					if p.Untrusted != nil {
						blocks = append(blocks, p.Untrusted.Content)
					}
				}
			}
			if !slices.Equal(blocks, []string{target}) {
				t.Errorf("untrusted blocks %q, want exactly [%q]", blocks, target)
			}
		})
	}
}

// TestDemoExecutionTimeout (c, D16): the execution timeout of one demo run is
// the bound of RunLoop, the approval wait, one late verification, the commit
// and a fixed margin: 228 s for the 5 s wait of make demo.
func TestDemoExecutionTimeout(t *testing.T) {
	if demo.IDPrefix != "l0-demo" || demo.ExecutionMargin != 30*time.Second {
		t.Errorf("IDPrefix %q, ExecutionMargin %v; want l0-demo, 30s", demo.IDPrefix, demo.ExecutionMargin)
	}
	if got := demo.Spec().MaxRunDuration(); got != 153*time.Second {
		t.Errorf("Spec().MaxRunDuration() = %v, want 153s", got)
	}
	cases := []struct{ approval, want time.Duration }{
		{5 * time.Second, 228 * time.Second},
		{time.Hour, 3823 * time.Second},
		{demo.MinApprovalTimeout, 224 * time.Second},
	}
	for _, tc := range cases {
		if got := demo.ExecutionTimeout(tc.approval); got != tc.want {
			t.Errorf("ExecutionTimeout(%v) = %v, want %v", tc.approval, got, tc.want)
		}
	}
}
