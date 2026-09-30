package loops

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"

	"github.com/amezianechayer/rempart/internal/loops/domain"
)

const (
	proposeName = "Propose"
	verifyName  = "Verify"
)

func payload() json.RawMessage { return json.RawMessage(`{"goal":"demo"}`) }

func candidate(it int) json.RawMessage { return json.RawMessage(`{"n":` + strconv.Itoa(it) + `}`) }

func fnd(sev domain.Severity, code string) domain.Finding {
	return domain.Finding{Code: code, Source: "fake", Severity: sev, Resource: "aws_s3_bucket.logs", File: "main.tf", Line: 1, Message: "m"}
}

func high(code string) domain.Finding { return fnd(domain.SeverityHigh, code) }

type step struct {
	tokens                int
	ok                    bool
	cand                  json.RawMessage
	findings              []domain.Finding
	proposeErr, verifyErr error
}

func fail(f ...domain.Finding) step { return step{tokens: 10, findings: f} }

func pass(f ...domain.Finding) step { return step{tokens: 10, ok: true, findings: f} }

// script answers by iteration; every attempt is recorded.
type script struct {
	mu        sync.Mutex
	steps     []step
	proposals []ProposeRequest
	verifies  []VerifyRequest
}

func newScript(steps ...step) *script { return &script{steps: steps} }

func (s *script) at(it int) (step, error) {
	if it < 1 || it > len(s.steps) {
		return step{}, temporal.NewNonRetryableApplicationError("script exhausted", "ScriptExhausted", nil)
	}
	return s.steps[it-1], nil
}

func (s *script) propose(_ context.Context, req ProposeRequest) (ProposeResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.proposals = append(s.proposals, req)
	st, err := s.at(req.Iteration)
	if err != nil {
		return ProposeResponse{}, err
	}
	if st.proposeErr != nil {
		return ProposeResponse{}, st.proposeErr
	}
	c := candidate(req.Iteration)
	if st.cand != nil {
		c = st.cand
	}
	return ProposeResponse{Candidate: c, Tokens: st.tokens}, nil
}

func (s *script) verify(_ context.Context, req VerifyRequest) (VerifyResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifies = append(s.verifies, req)
	st, err := s.at(req.Iteration)
	if err != nil {
		return VerifyResult{}, err
	}
	if st.verifyErr != nil {
		return VerifyResult{}, st.verifyErr
	}
	return VerifyResult{OK: st.ok, Findings: st.findings}, nil
}

func (s *script) calls() (proposals, verifies int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.proposals), len(s.verifies)
}

func (s *script) sent() []ProposeRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.proposals)
}

func (s *script) verified() []VerifyRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.verifies)
}

func testSpec(strategies ...string) LoopSpec {
	if len(strategies) == 0 {
		strategies = []string{"s1", "s2", "s3"}
	}
	return LoopSpec{
		ID: "test-loop", ProposeActivity: proposeName, VerifyActivity: verifyName, Strategies: strategies,
		Budget: Budget{MaxIterations: 8, MaxTokens: 1_000_000, MaxWallTime: time.Hour},
	}
}

func execute(t *testing.T, spec LoopSpec, s *script, setup func(*testsuite.TestWorkflowEnvironment)) (LoopResult, error) {
	t.Helper()
	return executeWith(t, spec, payload(), s, setup)
}

func executeWith(t *testing.T, spec LoopSpec, in any, s *script, setup func(*testsuite.TestWorkflowEnvironment)) (LoopResult, error) {
	t.Helper()
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	env.RegisterActivityWithOptions(s.propose, activity.RegisterOptions{Name: proposeName})
	env.RegisterActivityWithOptions(s.verify, activity.RegisterOptions{Name: verifyName})
	if setup != nil {
		setup(env)
	}
	env.RegisterWorkflow(RunLoop)
	env.ExecuteWorkflow("RunLoop", spec, in) // by name: no reflective check, a RawValue input passes as is
	if !env.IsWorkflowCompleted() {
		t.Fatal("workflow not completed")
	}
	if err := env.GetWorkflowError(); err != nil {
		return LoopResult{}, err
	}
	var res LoopResult
	if err := env.GetWorkflowResult(&res); err != nil {
		t.Fatalf("GetWorkflowResult: %v", err)
	}
	return res, nil
}

// rawValue is a json/plain payload holding exactly data.
func rawValue(t *testing.T, data string) converter.RawValue {
	t.Helper()
	p, err := converter.GetDefaultDataConverter().ToPayload("")
	if err != nil {
		t.Fatal(err)
	}
	p.Data = []byte(data)
	return converter.NewRawValue(p)
}

// obj is {"k":"<fill x n>"}: 12 bytes of weight around the fill.
func obj(fill string, n int) string { return `{"k":"` + strings.Repeat(fill, n) + `"}` }

// rawActivity answers every call to the activity name with data.
func rawActivity(name string, data converter.RawValue) func(*testsuite.TestWorkflowEnvironment) {
	return func(env *testsuite.TestWorkflowEnvironment) {
		env.RegisterActivityWithOptions(func(context.Context, json.RawMessage) (converter.RawValue, error) {
			return data, nil
		}, activity.RegisterOptions{Name: name})
	}
}

func isInvalidSpecErr(err error) bool {
	var ae *temporal.ApplicationError
	return errors.As(err, &ae) && ae.Type() == ErrTypeInvalidLoopSpec && ae.NonRetryable()
}

func traced(failed bool) IterationTrace {
	return IterationTrace{Iteration: 1, Strategy: "s1", Failed: failed}
}

func run(t *testing.T, spec LoopSpec, s *script, setup func(*testsuite.TestWorkflowEnvironment)) LoopResult {
	t.Helper()
	res, err := execute(t, spec, s, setup)
	if err != nil {
		t.Fatalf("RunLoop failed: %v", err)
	}
	return res
}

func want(t *testing.T, res LoopResult, st Status, r Reason, iterations int) {
	t.Helper()
	if res.Status != st || res.Reason != r || res.Iterations != iterations || len(res.Trace) != iterations {
		t.Fatalf("got %q %q after %d iterations (%d traced), want %q %q after %d",
			res.Status, res.Reason, res.Iterations, len(res.Trace), st, r, iterations)
	}
}

func strategiesOf(reqs []ProposeRequest) []string {
	out := make([]string, len(reqs))
	for i, r := range reqs {
		out[i] = r.Strategy
	}
	return out
}

func TestRunLoopConverges(t *testing.T) {
	low := fnd(domain.SeverityLow, "L")
	s := newScript(fail(high("A")), pass(low))
	res := run(t, testSpec(), s, nil)
	want(t, res, StatusConverged, "", 2)
	if string(res.Best) != `{"n":2}` || res.Tokens != 20 || !slices.Equal(res.Remaining, []domain.Finding{low}) {
		t.Fatalf("best %s, tokens %d, remaining %v", res.Best, res.Tokens, res.Remaining)
	}
	if tr := res.Trace[1]; !tr.Verified || tr.Fingerprint != domain.Fingerprint(nil) || tr.Score != 1 || tr.Findings != 1 || tr.Strategy != "s1" {
		t.Errorf("trace %+v", tr)
	}
	v := s.verified()
	if len(v) != 2 || string(v[1].Candidate) != `{"n":2}` || string(v[1].Payload) != string(payload()) || v[1].Iteration != 2 {
		t.Errorf("verify requests %+v", v)
	}
	t.Run("ok with a blocking finding is incoherent", func(t *testing.T) {
		res := run(t, testSpec(), newScript(pass(fnd(domain.SeverityMedium, "M"))), nil)
		want(t, res, StatusEscalated, ReasonInvalidResponse, 1)
		if res.Best != nil {
			t.Errorf("best %s, want none", res.Best)
		}
	})
}

func TestRunLoopStagnationSwitchesStrategy(t *testing.T) {
	s := newScript(fail(high("A")), fail(high("A")), pass())
	res := run(t, testSpec(), s, nil)
	want(t, res, StatusConverged, "", 3)
	if got := strategiesOf(s.sent()); !slices.Equal(got, []string{"s1", "s1", "s2"}) || res.Trace[2].Strategy != "s2" {
		t.Errorf("strategies %v", got)
	}
}

func TestRunLoopStagnationEscalates(t *testing.T) {
	cases := []struct {
		name  string
		steps []step
	}{
		{"same findings", []step{fail(high("A")), fail(high("A")), fail(high("A")), pass()}},
		{"no blocking finding", []step{fail(fnd(domain.SeverityInfo, "I0")), fail(fnd(domain.SeverityLow, "L")), fail(fnd(domain.SeverityInfo, "I")), pass()}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newScript(c.steps...)
			res := run(t, testSpec(), s, nil)
			want(t, res, StatusEscalated, ReasonStagnation, 3)
			if got := strategiesOf(s.sent()); !slices.Equal(got, []string{"s1", "s1", "s2"}) {
				t.Errorf("strategies %v", got)
			}
			if string(res.Best) != `{"n":1}` {
				t.Errorf("best %s, want the first of equal scores", res.Best)
			}
		})
	}
}

func TestRunLoopStrategiesExhausted(t *testing.T) {
	one := newScript(fail(high("A")), fail(high("A")), pass())
	want(t, run(t, testSpec("s1"), one, nil), StatusEscalated, ReasonStrategiesExhausted, 2)
	two := newScript(fail(high("A")), fail(high("A")), fail(high("B")), fail(high("B")), pass())
	want(t, run(t, testSpec("s1", "s2"), two, nil), StatusEscalated, ReasonStrategiesExhausted, 4)
	if got := strategiesOf(two.sent()); !slices.Equal(got, []string{"s1", "s1", "s2", "s2"}) {
		t.Errorf("strategies %v", got)
	}
}

func TestRunLoopFingerprintChangeResetsCount(t *testing.T) {
	s := newScript(fail(high("A")), fail(high("A")), fail(high("B")), fail(high("B")), pass())
	want(t, run(t, testSpec(), s, nil), StatusConverged, "", 5)
	if got := strategiesOf(s.sent()); !slices.Equal(got, []string{"s1", "s1", "s2", "s2", "s3"}) {
		t.Errorf("strategies %v", got)
	}
}

func TestRunLoopBudgetIterations(t *testing.T) {
	spec := testSpec()
	spec.Budget.MaxIterations = 3
	s := newScript(fail(high("A")), fail(high("B")), fail(high("C")), pass())
	res := run(t, spec, s, nil)
	want(t, res, StatusEscalated, ReasonBudgetIterations, 3)
	if p, v := s.calls(); p != 3 || v != 3 || res.Tokens != 30 || string(res.Best) != `{"n":1}` {
		t.Errorf("calls %d %d, tokens %d, best %s", p, v, res.Tokens, res.Best)
	}
}

func TestRunLoopBudgetTokens(t *testing.T) {
	distinct := func() *script {
		var steps []step
		for i := range 6 {
			steps = append(steps, step{tokens: 100, findings: []domain.Finding{high("C" + strconv.Itoa(i))}})
		}
		return newScript(steps...)
	}
	for _, c := range []struct{ max, iterations, tokens, verifies int }{{250, 3, 300, 2}, {300, 4, 400, 3}} {
		spec := testSpec()
		spec.Budget.MaxTokens = c.max
		s := distinct()
		res := run(t, spec, s, nil)
		want(t, res, StatusEscalated, ReasonBudgetTokens, c.iterations)
		if _, v := s.calls(); v != c.verifies || res.Tokens != c.tokens || res.Trace[c.iterations-1].Verified {
			t.Errorf("max %d: verifies %d, tokens %d", c.max, v, res.Tokens)
		}
	}
	for _, n := range []int{-1, MaxTokensLimit + 1} {
		s := newScript(step{tokens: n})
		res := run(t, testSpec(), s, nil)
		want(t, res, StatusEscalated, ReasonInvalidResponse, 1) // traced first (obligation i)
		if _, v := s.calls(); v != 0 || res.Tokens != 0 || res.Trace[0] != traced(false) {
			t.Errorf("tokens %d accepted", n)
		}
	}
}

func TestRunLoopBudgetWallTime(t *testing.T) {
	distinct := func() *script { return newScript(fail(high("A")), fail(high("B")), fail(high("C"))) }
	t.Run("no verification past the budget", func(t *testing.T) {
		s := distinct()
		res := run(t, testSpec(), s, func(env *testsuite.TestWorkflowEnvironment) {
			env.OnActivity(proposeName, mock.Anything, mock.Anything).Return(s.propose).After(30 * time.Minute)
		})
		want(t, res, StatusEscalated, ReasonBudgetTime, 2)
		if p, v := s.calls(); p != 2 || v != 1 || res.Trace[1].Verified || string(res.Best) != `{"n":1}` {
			t.Errorf("calls %d %d, best %s", p, v, res.Best)
		}
	})
	t.Run("no proposal past the budget", func(t *testing.T) {
		s := distinct()
		res := run(t, testSpec(), s, func(env *testsuite.TestWorkflowEnvironment) {
			env.OnActivity(verifyName, mock.Anything, mock.Anything).Return(s.verify).After(time.Hour)
		})
		want(t, res, StatusEscalated, ReasonBudgetTime, 1)
		if p, v := s.calls(); p != 1 || v != 1 {
			t.Errorf("calls %d %d", p, v)
		}
	})
}

func TestRunLoopKeepsBestCandidate(t *testing.T) {
	spec := testSpec()
	spec.Budget.MaxIterations = 4
	b := high("B")
	crit := func(c string) domain.Finding { return fnd(domain.SeverityCritical, c) }
	s := newScript(fail(crit("A")), fail(b), fail(high("C")), fail(crit("D"), crit("E")))
	res := run(t, spec, s, nil)
	want(t, res, StatusEscalated, ReasonBudgetIterations, 4)
	if string(res.Best) != `{"n":2}` || !slices.Equal(res.Remaining, []domain.Finding{b}) {
		t.Fatalf("best %s, remaining %v", res.Best, res.Remaining)
	}
	sent := s.sent()
	for i, w := range []string{"", `{"n":1}`, `{"n":2}`, `{"n":2}`} {
		if i >= len(sent) || string(sent[i].Best) != w {
			t.Fatalf("proposal %d: best sent %v, want %q", i+1, sent, w)
		}
	}
}

func TestRunLoopSendsTop20Findings(t *testing.T) {
	sevs := []domain.Severity{domain.SeverityInfo, domain.SeverityLow, domain.SeverityMedium, domain.SeverityHigh, domain.SeverityCritical}
	var many []domain.Finding
	for i := range 25 {
		f := fnd(sevs[i%5], "C"+strconv.Itoa(i))
		f.Line = 25 - i
		many = append(many, f)
	}
	s := newScript(fail(many...), pass())
	want(t, run(t, testSpec(), s, nil), StatusConverged, "", 2)
	sent := s.sent()
	if len(sent) != 2 || len(sent[0].Findings) != 0 {
		t.Fatalf("proposals %d, first with %d findings", len(sent), len(sent[0].Findings))
	}
	got := sent[1]
	if len(got.Findings) != 20 || !slices.Equal(got.Findings, domain.Top(many, 20)) {
		t.Errorf("findings sent %v", got.Findings)
	}
	if string(got.Payload) != string(payload()) || got.Iteration != 2 || got.Strategy != "s1" || string(got.Best) != `{"n":1}` {
		t.Errorf("request %+v", got)
	}
}

func TestRunLoopRecomputesFingerprint(t *testing.T) {
	a, b := high("A"), fnd(domain.SeverityMedium, "B")
	a2, b2 := a, b
	a2.Message, a2.Line, a2.Source = "other wording", 9, "trivy"
	b2.File = "other.tf"
	rounds := [][]domain.Finding{{a, b}, {b2, a2, fnd(domain.SeverityLow, "N")}, {a, b, a, fnd(domain.SeverityInfo, "I")}}
	s := newScript(fail(rounds[0]...), fail(rounds[1]...), fail(rounds[2]...), pass())
	res := run(t, testSpec(), s, nil)
	want(t, res, StatusEscalated, ReasonStagnation, 3)
	for i, tr := range res.Trace {
		r := rounds[i]
		if !tr.Verified || tr.Fingerprint != domain.Fingerprint(r) || tr.Score != domain.Score(r) || tr.Findings != len(r) {
			t.Errorf("trace %d: %+v", i+1, tr)
		}
	}
	if res.Trace[0].Fingerprint == domain.Fingerprint(nil) {
		t.Error("blocking findings ignored")
	}
}

func TestRunLoopInvalidSpecRejected(t *testing.T) {
	valid := testSpec()
	valid.ID = "canary-loop"
	with := func(f func(*LoopSpec)) LoopSpec {
		s := valid
		s.Strategies = slices.Clone(valid.Strategies)
		f(&s)
		return s
	}
	invalid := []LoopSpec{
		with(func(s *LoopSpec) { s.Budget.MaxIterations = 0 }),
		with(func(s *LoopSpec) { s.Budget.MaxIterations = MaxIterationsLimit + 1 }),
		with(func(s *LoopSpec) { s.Budget.MaxTokens = 0 }),
		with(func(s *LoopSpec) { s.Budget.MaxTokens = MaxTokensLimit + 1 }),
		with(func(s *LoopSpec) { s.Budget.MaxWallTime = 0 }),
		with(func(s *LoopSpec) { s.Budget.MaxWallTime = -time.Second }),
		with(func(s *LoopSpec) { s.Budget.MaxWallTime = MaxWallTimeLimit + time.Second }),
		with(func(s *LoopSpec) { s.Strategies = nil }),
		with(func(s *LoopSpec) { s.Strategies = []string{"s1", ""} }),
		with(func(s *LoopSpec) { s.Strategies = slices.Repeat([]string{"s"}, MaxStrategies+1) }),
		with(func(s *LoopSpec) { s.ID = "" }),
		with(func(s *LoopSpec) { s.ProposeActivity = "" }),
		with(func(s *LoopSpec) { s.VerifyActivity = "" }),
		with(func(s *LoopSpec) { s.VerifyActivity = proposeName }),
		with(func(s *LoopSpec) { s.SwitchAfter = 3 }),
		with(func(s *LoopSpec) { s.EscalateAfter = 2 }),
		with(func(s *LoopSpec) { s.SwitchAfter = -1 }),
		with(func(s *LoopSpec) { s.EscalateAfter = -1 }),
		with(func(s *LoopSpec) { s.ActivityTimeout = -time.Second }),
		with(func(s *LoopSpec) { s.ActivityTimeout = MinActivityTimeout - time.Millisecond }),
		with(func(s *LoopSpec) { s.ActivityTimeout = MaxActivityTimeout + time.Second }),
		with(func(s *LoopSpec) { s.EscalateAfter = MaxEscalateAfter + 1 }),
	}
	isInvalidSpec := func(err error) bool {
		var ae *temporal.ApplicationError
		return errors.As(err, &ae) && ae.Type() == ErrTypeInvalidLoopSpec && ae.NonRetryable() &&
			!strings.Contains(strings.ToLower(err.Error()), "canary")
	}
	for i, s := range invalid {
		if err := s.Validate(); !isInvalidSpec(err) {
			t.Errorf("case %d: Validate() = %v", i, err)
		}
	}
	for i, s := range []LoopSpec{
		valid,
		with(func(s *LoopSpec) {
			s.Budget = Budget{MaxIterations: MaxIterationsLimit, MaxTokens: MaxTokensLimit, MaxWallTime: MaxWallTimeLimit}
			s.ActivityTimeout = MaxActivityTimeout
			s.SwitchAfter, s.EscalateAfter = MaxEscalateAfter-1, MaxEscalateAfter
		}),
		with(func(s *LoopSpec) {
			s.Budget = Budget{MaxIterations: 1, MaxTokens: 1, MaxWallTime: time.Second}
			s.Strategies = slices.Repeat([]string{"s"}, MaxStrategies)
			s.SwitchAfter, s.EscalateAfter, s.ActivityTimeout = 1, 2, MinActivityTimeout
		}),
	} {
		if err := s.Validate(); err != nil {
			t.Errorf("valid case %d refused: %v", i, err)
		}
	}
	for _, i := range []int{0, 13} {
		s := newScript(pass())
		if _, err := execute(t, invalid[i], s, nil); !isInvalidSpec(err) {
			t.Errorf("case %d: workflow error %v", i, err)
		}
		if p, v := s.calls(); p+v != 0 {
			t.Errorf("case %d: %d activities ran", i, p+v)
		}
	}
}

func TestRunLoopValidationErrorNotRetried(t *testing.T) {
	for _, typ := range NonRetryableErrorTypes() {
		s := newScript(step{proposeErr: temporal.NewApplicationError("rejected", typ, ProposeFailure{Tokens: 40})}, pass())
		res := run(t, testSpec(), s, nil)
		want(t, res, StatusEscalated, ReasonActivityFailed, 1)
		if p, _ := s.calls(); p != 1 || res.Tokens != 40 || !res.Trace[0].Failed {
			t.Errorf("%s: %d attempts, tokens %d, trace %+v", typ, p, res.Tokens, res.Trace)
		}
	}
	s := newScript(step{tokens: 10, verifyErr: temporal.NewApplicationError("rejected", ErrTypeValidation)})
	res := run(t, testSpec(), s, nil)
	want(t, res, StatusEscalated, ReasonActivityFailed, 1)
	if _, v := s.calls(); v != 1 || res.Trace[0].Verified || res.Tokens != 10 {
		t.Errorf("verifier: %d attempts, trace %+v", v, res.Trace)
	}
	if !slices.Equal(NonRetryableErrorTypes(), []string{ErrTypeValidation, ErrTypePolicyViolation, ErrTypeBudgetExceeded}) {
		t.Error("non retryable error types changed")
	}
}

func TestRunLoopActivityFailureEscalates(t *testing.T) {
	transient := errors.New("transient")
	e := step{proposeErr: temporal.NewApplicationError("transient", "Transient", ProposeFailure{})} // declared (obligation h)
	s := newScript(fail(high("A")), e, e, e, pass())
	res := run(t, testSpec(), s, nil)
	want(t, res, StatusEscalated, ReasonActivityFailed, 1+MaxActivityAttempts)
	if p, _ := s.calls(); p != 1+MaxActivityAttempts {
		t.Errorf("proposer attempts %d", p)
	}
	if string(res.Best) != `{"n":1}` || !slices.Equal(res.Remaining, []domain.Finding{high("A")}) {
		t.Errorf("best %s, remaining %v", res.Best, res.Remaining)
	}
	s = newScript(step{tokens: 10, verifyErr: transient}, pass())
	res = run(t, testSpec(), s, nil)
	want(t, res, StatusEscalated, ReasonActivityFailed, 1)
	if p, v := s.calls(); p != 1 || v != MaxActivityAttempts || res.Best != nil {
		t.Errorf("verifier: calls %d %d, best %s", p, v, res.Best)
	}
}

func TestRunLoopProposerFailuresCounted(t *testing.T) {
	failed := func(detail any) step {
		return step{proposeErr: temporal.NewApplicationError("llm call failed", "Transient", detail)}
	}
	s := newScript(fail(high("A")), failed(ProposeFailure{Tokens: 7}), failed(ProposeFailure{Tokens: 5}), pass())
	res := run(t, testSpec(), s, nil)
	want(t, res, StatusConverged, "", 4)
	tr := res.Trace
	if p, v := s.calls(); p != 4 || v != 2 || res.Tokens != 32 || tr[1].Tokens != 7 || !tr[2].Failed || tr[2].Verified || tr[3].Failed {
		t.Errorf("calls %d %d, tokens %d, trace %+v", p, v, res.Tokens, tr)
	}
	other := step{proposeErr: temporal.NewNonRetryableApplicationError("llm", "Other", nil)}
	want(t, run(t, testSpec(), newScript(other, pass()), nil), StatusEscalated, ReasonActivityFailed, 1)
	for _, d := range []any{ProposeFailure{Tokens: -1}, ProposeFailure{Tokens: MaxTokensLimit + 1}, "tokens"} {
		s := newScript(failed(d), pass())
		res := run(t, testSpec(), s, nil)
		want(t, res, StatusEscalated, ReasonInvalidResponse, 1)
		if p, _ := s.calls(); p != 1 || res.Tokens != 0 || res.Trace[0] != traced(true) {
			t.Errorf("detail %v: calls %d, tokens %d", d, p, res.Tokens)
		}
	}
	t.Run("consecutive failures only, request and stagnation kept", func(t *testing.T) {
		f := failed(ProposeFailure{Tokens: 1})
		s := newScript(fail(high("A")), f, fail(high("A")), f, f, pass())
		res := run(t, testSpec(), s, nil)
		want(t, res, StatusConverged, "", 6)
		sent := s.sent()
		if got := strategiesOf(sent); !slices.Equal(got, []string{"s1", "s1", "s1", "s2", "s2", "s2"}) || res.Tokens != 33 {
			t.Errorf("strategies %v, tokens %d", got, res.Tokens)
		}
		for i, r := range sent[1:] {
			if string(r.Best) != `{"n":1}` || !slices.Equal(r.Findings, []domain.Finding{high("A")}) {
				t.Errorf("proposal %d: best %s, findings %v", i+2, r.Best, r.Findings)
			}
		}
	})
	t.Run("failed calls spend the token budget", func(t *testing.T) {
		spec := testSpec()
		spec.Budget.MaxTokens = 15
		s := newScript(fail(high("A")), failed(ProposeFailure{Tokens: 6}), pass())
		res := run(t, spec, s, nil)
		want(t, res, StatusEscalated, ReasonBudgetTokens, 2)
		if p, v := s.calls(); p != 2 || v != 1 || res.Tokens != 16 || !res.Trace[1].Failed {
			t.Errorf("calls %d %d, tokens %d, trace %+v", p, v, res.Tokens, res.Trace)
		}
	})
}

func TestRunLoopEmptyCandidateRejected(t *testing.T) {
	for _, c := range []string{"null", `""`, "{}", " [ ] "} {
		s := newScript(step{tokens: 10, ok: true, cand: json.RawMessage(c)}, pass())
		res := run(t, testSpec(), s, nil)
		want(t, res, StatusEscalated, ReasonInvalidResponse, 1)
		if _, v := s.calls(); v != 0 || res.Tokens != 10 || res.Best != nil {
			t.Errorf("candidate %q: %d verifies, tokens %d, best %s", c, v, res.Tokens, res.Best)
		}
	}
	s := newScript(pass(), pass())
	res := run(t, testSpec(), s, func(env *testsuite.TestWorkflowEnvironment) {
		env.RegisterActivityWithOptions(func(ctx context.Context, req ProposeRequest) (map[string]int, error) {
			r, err := s.propose(ctx, req)
			return map[string]int{"tokens": r.Tokens}, err // no candidate key
		}, activity.RegisterOptions{Name: proposeName})
	})
	want(t, res, StatusEscalated, ReasonInvalidResponse, 1)
	if p, v := s.calls(); p != 1 || v != 0 || res.Tokens != 10 || res.Best != nil {
		t.Errorf("absent candidate: calls %d %d, tokens %d, best %s", p, v, res.Tokens, res.Best)
	}
}

func TestRunLoopFailureWithoutFindingRejected(t *testing.T) {
	res := run(t, testSpec(), newScript(fail(high("A")), fail(), pass()), nil)
	want(t, res, StatusEscalated, ReasonInvalidResponse, 2)
	if !res.Trace[1].Verified || string(res.Best) != `{"n":1}` || !slices.Equal(res.Remaining, []domain.Finding{high("A")}) {
		t.Errorf("best %s, remaining %v", res.Best, res.Remaining)
	}
}

func TestRunLoopLimitsFrozen(t *testing.T) {
	got := []any{
		DefaultSwitchAfter, DefaultEscalateAfter, DefaultActivityTimeout, MaxIterationsLimit, MaxTokensLimit, MaxWallTimeLimit,
		MinActivityTimeout, MaxActivityTimeout, MaxStrategies, MaxFindingsToPropose, MaxActivityAttempts, MaxEscalateAfter,
	}
	frozen := []any{2, 3, 5 * time.Minute, 100, 10_000_000, 24 * time.Hour, time.Second, 30 * time.Minute, 10, 20, 3, 10}
	if !slices.Equal(got, frozen) {
		t.Errorf("limits %v, want %v", got, frozen)
	}
}

func TestRunLoopCanceled(t *testing.T) {
	for _, name := range []string{proposeName, verifyName} {
		t.Run(name, func(t *testing.T) {
			s := newScript(fail(high("A")), pass())
			var fn any = s.propose
			if name == verifyName {
				fn = s.verify
			}
			_, err := execute(t, testSpec(), s, func(env *testsuite.TestWorkflowEnvironment) {
				env.OnActivity(name, mock.Anything, mock.Anything).Return(fn).After(30 * time.Minute)
				env.RegisterDelayedCallback(env.CancelWorkflow, 10*time.Minute)
			})
			if !temporal.IsCanceledError(err) {
				t.Fatalf("error %v: a cancellation is neither an escalation nor a failure", err)
			}
		})
	}
}

func TestRunLoopPayloadBounded(t *testing.T) {
	for _, c := range []struct {
		name, data string
		ok         bool
	}{
		{"at the bound", obj("a", MaxPayloadBytes-12), true},
		{"one byte over", obj("a", MaxPayloadBytes-11), false},
		{"raw < weighs 6", obj("<", (MaxPayloadBytes-12)/6+1), false},
		{"rune bytes weigh 2", obj("\u00e9", (MaxPayloadBytes-12)/4+1), false},
		{"invalid UTF-8", obj("\xff", 1), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newScript(pass())
			res, err := executeWith(t, testSpec(), rawValue(t, c.data), s, nil)
			p, v := s.calls()
			if c.ok && (err != nil || res.Status != StatusConverged) || !c.ok && (!isInvalidSpecErr(err) || p+v != 0) {
				t.Errorf("error %v, status %q, %d activities", err, res.Status, p+v)
			}
		})
	}
}

func TestRunLoopCandidateBounded(t *testing.T) {
	for _, c := range []struct {
		name, cand string
		ok         bool
	}{
		{"at the bound", obj("a", MaxCandidateBytes-12), true},
		{"one byte over", obj("a", MaxCandidateBytes-11), false},
		{"raw < weighs 6", obj("<", (MaxCandidateBytes-12)/6+1), false},
		{"invalid UTF-8", obj("\xff", 1), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newScript(pass(), pass())
			res := run(t, testSpec(), s, rawActivity(proposeName, rawValue(t, `{"candidate":`+c.cand+`,"tokens":10}`)))
			if c.ok {
				want(t, res, StatusConverged, "", 1)
				return
			}
			want(t, res, StatusEscalated, ReasonInvalidResponse, 1)
			if _, v := s.calls(); v != 0 || res.Tokens != 10 || res.Best != nil {
				t.Errorf("verifies %d, tokens %d, best %d bytes", v, res.Tokens, len(res.Best))
			}
		})
	}
}

func TestRunLoopBlankCandidateRejected(t *testing.T) {
	for _, c := range []string{"[ \n ]", "{\t}", "[\r\n]", `"  "`} {
		s := newScript(pass(), pass())
		res := run(t, testSpec(), s, rawActivity(proposeName, rawValue(t, `{"candidate":`+c+`,"tokens":10}`)))
		want(t, res, StatusEscalated, ReasonInvalidResponse, 1)
		if _, v := s.calls(); v != 0 || res.Tokens != 10 {
			t.Errorf("candidate %q: %d verifies, tokens %d", c, v, res.Tokens)
		}
	}
}

func TestRunLoopFindingsBounded(t *testing.T) {
	many := func(n int) []domain.Finding {
		f := make([]domain.Finding, n)
		for i := range f {
			f[i] = fnd(domain.SeverityLow, "L"+strconv.Itoa(i))
		}
		return f
	}
	refused := func(t *testing.T, st step) {
		t.Helper()
		s := newScript(st, pass())
		res := run(t, testSpec(), s, nil)
		want(t, res, StatusEscalated, ReasonInvalidResponse, 1)
		if _, v := s.calls(); v != 1 || res.Trace[0].Verified || res.Best != nil || res.Remaining != nil {
			t.Errorf("verifies %d, trace %+v, best %s", v, res.Trace[0], res.Best)
		}
	}
	want(t, run(t, testSpec(), newScript(fail(many(MaxFindings)...), pass()), nil), StatusConverged, "", 2)
	refused(t, fail(many(MaxFindings+1)...))
	refused(t, pass(many(MaxFindings+1)...))
	base := domain.Finding{Code: "c", Source: "s", Severity: domain.SeverityLow, Resource: "r", File: "f", Message: "m"} // weight 8
	for i := range 6 {
		at, over := base, base
		for _, c := range []struct {
			f *domain.Finding
			n int
		}{{&at, MaxFindingBytes - 8}, {&over, MaxFindingBytes - 7}} {
			fields := []*string{&c.f.Code, &c.f.Source, (*string)(&c.f.Severity), &c.f.Resource, &c.f.File, &c.f.Message}
			*fields[i] += strings.Repeat("x", c.n)
		}
		if res := run(t, testSpec(), newScript(fail(at), pass()), nil); res.Status != StatusConverged {
			t.Errorf("field %d at the bound: %q %q", i, res.Status, res.Reason)
		}
		refused(t, fail(over))
	}
	lt := base
	lt.Message = strings.Repeat("<", 170) // 170 raw bytes, weight 7 + 1020
	refused(t, fail(lt))
	type class struct {
		fill   string
		weight int
	}
	classes := []class{{"\u00e9", 4}, {"\u2028", 6}, {"\U0001f600", 8}}
	for b := range 0x80 { // D1 for every ASCII byte
		c := class{string(rune(b)), 1}
		switch {
		case b < 0x20 || strings.ContainsRune("<>&", rune(b)):
			c.weight = 6
		case b == '"' || b == '\\':
			c.weight = 2
		}
		classes = append(classes, c)
	}
	for _, c := range classes {
		at, over := base, base // other fields weigh 7
		at.Message = strings.Repeat(c.fill, (MaxFindingBytes-7)/c.weight)
		over.Message = at.Message + c.fill
		if enc, err := json.Marshal(at.Message); err != nil || len(enc)-2 > len(at.Message)/len(c.fill)*c.weight {
			t.Errorf("fill %q: weight %d below its encoding %d, %v", c.fill, c.weight, len(enc)-2, err)
		}
		if res := run(t, testSpec(), newScript(fail(at), pass()), nil); res.Status != StatusConverged {
			t.Errorf("fill %q at the bound: %q %q", c.fill, res.Status, res.Reason)
		}
		s := newScript(fail(over), pass())
		if res := run(t, testSpec(), s, nil); res.Reason != ReasonInvalidResponse || res.Trace[0].Verified {
			t.Errorf("fill %q over the bound: %q %q", c.fill, res.Status, res.Reason)
		}
	}
}

func TestRunLoopSizeLimits(t *testing.T) {
	if got := []int{MaxPayloadBytes, MaxCandidateBytes, MaxFindings, MaxFindingBytes, MaxNameBytes}; !slices.Equal(got, []int{64 << 10, 64 << 10, 100, 1 << 10, 64}) {
		t.Fatalf("size limits %v", got)
	}
	for _, c := range []struct { // D1: every bound reached with the bytes JSON expands most
		fill   string
		weight int
	}{{"<", 6}, {"&", 6}, {"\u2028", 6}, {"\u00e9", 4}} {
		f := domain.Finding{Message: strings.Repeat(c.fill, MaxFindingBytes/c.weight), Line: math.MinInt}
		tr := IterationTrace{
			Iteration: MaxIterationsLimit, Strategy: strings.Repeat("s", MaxNameBytes), Fingerprint: domain.Fingerprint(nil),
			Score: MaxFindings * 100, Findings: MaxFindings, Tokens: MaxTokensLimit,
		}
		res := LoopResult{
			Status: StatusEscalated, Reason: ReasonStrategiesExhausted,
			Best:      json.RawMessage(`"` + strings.Repeat(c.fill, (MaxCandidateBytes-4)/c.weight) + `"`),
			Remaining: slices.Repeat([]domain.Finding{f}, MaxFindings), Iterations: MaxIterationsLimit,
			Tokens: MaxTokensLimit, Trace: slices.Repeat([]IterationTrace{tr}, MaxIterationsLimit),
		}
		p, err := converter.GetDefaultDataConverter().ToPayload(res)
		if err != nil || len(p.GetData()) >= 256<<10 {
			t.Errorf("fill %q: %d bytes, %v", c.fill, len(p.GetData()), err)
		}
	}
}

func TestRunLoopProposerErrorKinds(t *testing.T) {
	declared := temporal.NewApplicationError("llm call failed", "Transient", ProposeFailure{Tokens: 5})
	check := func(t *testing.T, s *script, res LoopResult) {
		t.Helper()
		want(t, res, StatusEscalated, ReasonActivityFailed, 1)
		if p, _ := s.calls(); p != 1 || res.Tokens != 0 || res.Trace[0] != traced(true) {
			t.Errorf("calls %d, tokens %d, trace %+v", p, res.Tokens, res.Trace)
		}
	}
	for _, c := range []struct {
		name string
		err  error
	}{
		{"undeclared", errors.New("transient")},
		{"declared cause of an undeclared application error", temporal.NewApplicationErrorWithCause("llm", "Transient", declared)},
		{"declared cause of a timeout", temporal.NewTimeoutError(1, declared)}, // 1: START_TO_CLOSE, no import of go.temporal.io/api
		{"cancellation by the activity", temporal.NewCanceledError(ProposeFailure{Tokens: 5})},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newScript(step{proposeErr: c.err}, pass())
			check(t, s, run(t, testSpec(), s, nil))
		})
	}
	t.Run("declared but non retryable", func(t *testing.T) {
		err := temporal.NewNonRetryableApplicationError("llm call failed", "Transient", nil, ProposeFailure{Tokens: 5})
		s := newScript(step{proposeErr: err}, pass())
		res := run(t, testSpec(), s, nil)
		want(t, res, StatusEscalated, ReasonActivityFailed, 1)
		if p, _ := s.calls(); p != 1 || res.Tokens != 5 || !res.Trace[0].Failed || res.Trace[0].Tokens != 5 {
			t.Errorf("calls %d, tokens %d, trace %+v", p, res.Tokens, res.Trace)
		}
	})
	t.Run("panic", func(t *testing.T) {
		s := newScript(pass(), pass())
		check(t, s, run(t, testSpec(), s, func(env *testsuite.TestWorkflowEnvironment) {
			env.RegisterActivityWithOptions(func(ctx context.Context, req ProposeRequest) (ProposeResponse, error) {
				r, err := s.propose(ctx, req)
				r.Tokens /= len(req.Findings) // runtime panic: no finding at iteration 1 (criterion 7 bans the builtin)
				return r, err
			}, activity.RegisterOptions{Name: proposeName})
		}))
	})
}

func TestRunLoopProposeFailureCanonical(t *testing.T) {
	failed := func(details ...any) step {
		return step{proposeErr: temporal.NewApplicationError("llm call failed", "Transient", details...)}
	}
	s := newScript(failed(rawValue(t, `{"tokens":7}`)), failed(ProposeFailure{}), pass())
	res := run(t, testSpec(), s, nil)
	want(t, res, StatusConverged, "", 3)
	if res.Tokens != 17 {
		t.Errorf("tokens %d", res.Tokens)
	}
	bad := [][]any{{ProposeFailure{Tokens: 7}, ProposeFailure{Tokens: 7}}, {[]byte(`{"tokens":7}`)}}
	for _, d := range []string{
		`{"tokens":07}`, `{"tokens":+7}`, `{"tokens":-0}`, `{"tokens":7.0}`, `{"tokens":1e1}`, `{"tokens":"7"}`,
		`{"tokens": 7}`, ` {"tokens":7}`, `{"tokens":7} `, `{"Tokens":7}`, `{"tokens":7,"tokens":7}`,
		`{"tokens":7,"cost":1}`, `null`, `{}`, `7}`, `{"tokens":7`,
	} {
		bad = append(bad, []any{rawValue(t, d)})
	}
	for i, d := range bad {
		s := newScript(failed(d...), pass())
		res := run(t, testSpec(), s, nil)
		want(t, res, StatusEscalated, ReasonInvalidResponse, 1)
		if p, _ := s.calls(); p != 1 || res.Tokens != 0 || res.Trace[0] != traced(true) {
			t.Errorf("detail %d: calls %d, tokens %d, trace %+v", i, p, res.Tokens, res.Trace)
		}
	}
}

func TestRunLoopFailureWithoutFindingAtFirstIteration(t *testing.T) {
	res := run(t, testSpec(), newScript(fail(), pass()), nil)
	want(t, res, StatusEscalated, ReasonInvalidResponse, 1)
	if !res.Trace[0].Verified || res.Best != nil || res.Remaining != nil {
		t.Errorf("trace %+v, best %s, remaining %v", res.Trace[0], res.Best, res.Remaining)
	}
}

func TestRunLoopSpecNamesBounded(t *testing.T) {
	long := strings.Repeat("n", MaxNameBytes)
	for i, f := range []func(*LoopSpec){
		func(s *LoopSpec) { s.ID = long + "n" },
		func(s *LoopSpec) { s.ID = "loop\n" },
		func(s *LoopSpec) { s.ProposeActivity = "Propose " },
		func(s *LoopSpec) { s.VerifyActivity = "V\u00e9rifier" },
		func(s *LoopSpec) { s.Strategies = []string{"s1", long + "s"} },
		func(s *LoopSpec) { s.Strategies = []string{`s"1`} },
	} {
		s := testSpec()
		f(&s)
		if err := s.Validate(); !isInvalidSpecErr(err) {
			t.Errorf("case %d: %v", i, err)
		}
	}
	s := testSpec()
	s.ID, s.ProposeActivity, s.Strategies = long, "A-Z.a_z0-9", []string{long}
	if err := s.Validate(); err != nil {
		t.Errorf("valid names refused: %v", err)
	}
}
