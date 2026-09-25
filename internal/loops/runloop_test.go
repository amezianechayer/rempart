package loops

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"go.temporal.io/sdk/activity"
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
	return ProposeResponse{Candidate: candidate(req.Iteration), Tokens: st.tokens}, nil
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
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	env.RegisterActivityWithOptions(s.propose, activity.RegisterOptions{Name: proposeName})
	env.RegisterActivityWithOptions(s.verify, activity.RegisterOptions{Name: verifyName})
	if setup != nil {
		setup(env)
	}
	env.ExecuteWorkflow(RunLoop, spec, payload())
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
		{"no blocking finding", []step{fail(), fail(fnd(domain.SeverityLow, "L")), fail(fnd(domain.SeverityInfo, "I")), pass()}},
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
		want(t, res, StatusEscalated, ReasonInvalidResponse, 0)
		if _, v := s.calls(); v != 0 || res.Tokens != 0 {
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
		s := newScript(step{proposeErr: temporal.NewApplicationError("rejected", typ)})
		want(t, run(t, testSpec(), s, nil), StatusEscalated, ReasonActivityFailed, 0)
		if p, _ := s.calls(); p != 1 {
			t.Errorf("%s: %d attempts, want 1", typ, p)
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
	s := newScript(fail(high("A")), step{proposeErr: transient})
	res := run(t, testSpec(), s, nil)
	want(t, res, StatusEscalated, ReasonActivityFailed, 1)
	if p, _ := s.calls(); p != 1+MaxActivityAttempts {
		t.Errorf("proposer attempts %d", p)
	}
	if string(res.Best) != `{"n":1}` || !slices.Equal(res.Remaining, []domain.Finding{high("A")}) {
		t.Errorf("best %s, remaining %v", res.Best, res.Remaining)
	}
	s = newScript(step{tokens: 10, verifyErr: transient})
	res = run(t, testSpec(), s, nil)
	want(t, res, StatusEscalated, ReasonActivityFailed, 1)
	if _, v := s.calls(); v != MaxActivityAttempts || res.Best != nil {
		t.Errorf("verifier attempts %d, best %s", v, res.Best)
	}
}
