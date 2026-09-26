package loops_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"

	"github.com/amezianechayer/rempart/internal/loops"
	"github.com/amezianechayer/rempart/internal/loops/fake"
)

const verifyApprovalName = "VerifyApproval"

func plan() string { return strings.Repeat("ab", 32) }

func request(required int, security bool) loops.ApprovalRequest {
	return loops.ApprovalRequest{
		PlanHash: plan(), Author: "alice", Required: required,
		NeedsSecurityRole: security, VerifyActivity: verifyApprovalName,
	}
}

func sign(a loops.Approval) loops.Approval {
	a.Signature = fake.ExpectedSignature(a)
	return a
}

// signed passes the fake verifier; forged carries the signature of another approver.
func signed(approver string, approved bool) loops.Approval {
	return sign(loops.Approval{Approved: approved, PlanHash: plan(), Approver: approver})
}

func forged(approver string, approved bool) loops.Approval {
	a := signed(approver, approved)
	a.Signature = signed("mallory", approved).Signature
	return a
}

func onHash(h string, approved bool) loops.Approval {
	return sign(loops.Approval{Approved: approved, PlanHash: h, Approver: "bob"})
}

func ign(approver string, r loops.IgnoredReason) loops.IgnoredSignal {
	return loops.IgnoredSignal{Approver: approver, Reason: r}
}

// rawJSON is a json/plain payload holding exactly data.
func rawJSON(t *testing.T, data string) converter.RawValue {
	t.Helper()
	p, err := converter.GetDefaultDataConverter().ToPayload("")
	if err != nil {
		t.Fatal(err)
	}
	p.Data = []byte(data)
	return converter.NewRawValue(p)
}

// verifier wraps the fake: it records every call and fails the first failFirst.
type verifier struct {
	mu        sync.Mutex
	fake      fake.ApprovalVerifier
	failFirst int
	seen      []string
}

func newVerifier(security ...string) *verifier {
	roles := map[string]bool{}
	for _, s := range security {
		roles[s] = true
	}
	return &verifier{fake: fake.ApprovalVerifier{SecurityRoles: roles}}
}

func (v *verifier) verify(ctx context.Context, a loops.Approval) (loops.ApprovalCheck, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.seen = append(v.seen, a.Approver)
	if len(v.seen) <= v.failFirst {
		return loops.ApprovalCheck{}, temporal.NewApplicationError("verifier unavailable", "Transient")
	}
	return v.fake.VerifyApproval(ctx, a)
}

func wantVerified(t *testing.T, v *verifier, approvers ...string) {
	t.Helper()
	v.mu.Lock()
	defer v.mu.Unlock()
	if !slices.Equal(v.seen, approvers) {
		t.Errorf("verified %v, want %v", v.seen, approvers)
	}
}

type outcome struct {
	res    loops.ApprovalResult
	err    error
	timers []time.Duration
}

func await(t *testing.T, req loops.ApprovalRequest, timeout time.Duration, v *verifier, setup func(*testsuite.TestWorkflowEnvironment), signals ...any) outcome {
	t.Helper()
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	env.RegisterActivityWithOptions(v.verify, activity.RegisterOptions{Name: verifyApprovalName})
	var out outcome
	env.SetOnTimerScheduledListener(func(_ string, d time.Duration) { out.timers = append(out.timers, d) })
	for i, s := range signals {
		env.RegisterDelayedCallback(func() { env.SignalWorkflow(loops.ApprovalSignal, s) }, time.Duration(i+1)*time.Minute)
	}
	if setup != nil {
		setup(env)
	}
	env.ExecuteWorkflow(loops.AwaitApprovals, req, timeout)
	if !env.IsWorkflowCompleted() {
		t.Fatal("workflow not completed")
	}
	if out.err = env.GetWorkflowError(); out.err == nil {
		if err := env.GetWorkflowResult(&out.res); err != nil {
			t.Fatalf("GetWorkflowResult: %v", err)
		}
	}
	return out
}

func wantOutcome(t *testing.T, out outcome, o loops.ApprovalOutcome, approvers []string, ignored ...loops.IgnoredSignal) {
	t.Helper()
	if out.err != nil {
		t.Fatalf("AwaitApprovals failed: %v", out.err)
	}
	var got []string
	for _, a := range out.res.Approvals {
		got = append(got, a.Approver)
	}
	if out.res.Outcome != o || !slices.Equal(got, approvers) || !slices.Equal(out.res.Ignored, ignored) {
		t.Fatalf("got %q %v, ignored %v; want %q %v, ignored %v", out.res.Outcome, got, out.res.Ignored, o, approvers, ignored)
	}
}

func TestAwaitApprovalsTimeoutDoesNothing(t *testing.T) {
	v := newVerifier()
	out := await(t, request(1, false), time.Hour, v, nil)
	wantOutcome(t, out, loops.OutcomeTimedOut, nil)
	wantVerified(t, v)
	if !slices.Equal(out.timers, []time.Duration{time.Hour}) {
		t.Errorf("timers %v, want the timeout only", out.timers)
	}
	t.Run("partial quorum not retained", func(t *testing.T) {
		v := newVerifier()
		wantOutcome(t, await(t, request(2, false), time.Hour, v, nil, signed("bob", true)), loops.OutcomeTimedOut, nil)
		wantVerified(t, v, "bob")
	})
	t.Run("signal after the deadline", func(t *testing.T) {
		v := newVerifier()
		wantOutcome(t, await(t, request(1, false), 30*time.Second, v, nil, signed("bob", true)), loops.OutcomeTimedOut, nil)
		wantVerified(t, v)
	})
}

func TestAwaitApprovalsWrongHashIgnored(t *testing.T) {
	v, other := newVerifier(), strings.Repeat("cd", 32)
	out := await(t, request(1, false), time.Hour, v, nil, onHash(other, true), onHash(strings.ToUpper(plan()), true),
		onHash(plan()[:63], true), onHash(other, false), signed("bob", true))
	w := ign("bob", loops.IgnoredWrongHash)
	wantOutcome(t, out, loops.OutcomeApproved, []string{"bob"}, w, w, w, w)
	wantVerified(t, v, "bob")
	if out.res.Approvals[0] != signed("bob", true) {
		t.Errorf("approval %+v", out.res.Approvals[0])
	}
	t.Run("the hash is checked before the author", func(t *testing.T) {
		byAuthor := sign(loops.Approval{Approved: true, PlanHash: other, Approver: "alice"})
		out := await(t, request(1, false), time.Hour, newVerifier(), nil, byAuthor, signed("bob", true))
		wantOutcome(t, out, loops.OutcomeApproved, []string{"bob"}, ign("alice", loops.IgnoredWrongHash))
	})
}

func TestAwaitApprovalsInvalidSignatureIgnored(t *testing.T) {
	v, upper := newVerifier(), signed("bob", true)
	upper.Signature = strings.ToUpper(upper.Signature)
	out := await(t, request(1, false), time.Hour, v, nil, forged("bob", true), upper, signed("bob", true))
	w := ign("bob", loops.IgnoredInvalidSignature)
	wantOutcome(t, out, loops.OutcomeApproved, []string{"bob"}, w, w)
	wantVerified(t, v, "bob", "bob", "bob")
}

func TestAwaitApprovalsSelfApprovalIgnored(t *testing.T) {
	v := newVerifier()
	out := await(t, request(1, false), time.Hour, v, nil, signed("alice", true), signed("alice", false), signed("bob", true))
	w := ign("alice", loops.IgnoredSelfApproval)
	wantOutcome(t, out, loops.OutcomeApproved, []string{"bob"}, w, w)
	wantVerified(t, v, "bob")
}

func TestAwaitApprovalsDuplicateApproverIgnored(t *testing.T) {
	v := newVerifier()
	out := await(t, request(2, false), time.Hour, v, nil, signed("bob", true), signed("bob", true), forged("bob", true),
		onHash(strings.Repeat("cd", 32), true), signed("carol", true))
	w := ign("bob", loops.IgnoredDuplicate)
	wantOutcome(t, out, loops.OutcomeApproved, []string{"bob", "carol"}, w, w, ign("bob", loops.IgnoredWrongHash))
	wantVerified(t, v, "bob", "carol")
}

func TestAwaitApprovalsQuorumWithSecurityRole(t *testing.T) {
	v := newVerifier("carol")
	out := await(t, request(2, true), time.Hour, v, nil, signed("bob", true), signed("carol", true), signed("dave", true))
	wantOutcome(t, out, loops.OutcomeApproved, []string{"bob", "carol"})
	wantVerified(t, v, "bob", "carol")
	t.Run("one approver with the role", func(t *testing.T) {
		out := await(t, request(1, true), time.Hour, newVerifier("carol"), nil, signed("bob", true), signed("carol", true))
		wantOutcome(t, out, loops.OutcomeApproved, []string{"carol"}, ign("bob", loops.IgnoredNeedsSecurityRole))
	})
	t.Run("the role first frees the last place", func(t *testing.T) {
		out := await(t, request(3, true), time.Hour, newVerifier("carol"), nil, signed("carol", true), signed("bob", true), signed("dave", true))
		wantOutcome(t, out, loops.OutcomeApproved, []string{"carol", "bob", "dave"})
	})
}

func TestAwaitApprovalsQuorumWithoutSecurityRoleKeepsWaiting(t *testing.T) {
	w := ign("carol", loops.IgnoredNeedsSecurityRole)
	out := await(t, request(2, true), time.Hour, newVerifier("dave"), nil, signed("bob", true), signed("carol", true))
	wantOutcome(t, out, loops.OutcomeTimedOut, nil, w)
	out = await(t, request(2, true), time.Hour, newVerifier("dave"), nil, signed("bob", true), signed("carol", true), signed("dave", true))
	wantOutcome(t, out, loops.OutcomeApproved, []string{"bob", "dave"}, w)
}

func TestAwaitApprovalsAuthenticatedRefusalStops(t *testing.T) {
	v := newVerifier()
	out := await(t, request(2, false), time.Hour, v, nil, signed("bob", true), signed("carol", false), signed("dave", true))
	wantOutcome(t, out, loops.OutcomeRejected, nil)
	wantVerified(t, v, "bob", "carol")
	t.Run("an approver withdraws", func(t *testing.T) {
		out := await(t, request(2, false), time.Hour, newVerifier(), nil, signed("bob", true), signed("bob", false), signed("carol", true))
		wantOutcome(t, out, loops.OutcomeRejected, nil)
	})
	t.Run("a refusal needs no security role", func(t *testing.T) {
		v := newVerifier("carol")
		out := await(t, request(1, true), time.Hour, v, nil, signed("bob", false), signed("carol", true))
		wantOutcome(t, out, loops.OutcomeRejected, nil)
		wantVerified(t, v, "bob")
	})
}

func TestAwaitApprovalsUnauthenticatedRefusalIgnored(t *testing.T) {
	out := await(t, request(1, false), time.Hour, newVerifier(), nil, forged("bob", false), forged("carol", false), signed("dave", true))
	wantOutcome(t, out, loops.OutcomeApproved, []string{"dave"},
		ign("bob", loops.IgnoredInvalidSignature), ign("carol", loops.IgnoredInvalidSignature))
}

func TestAwaitApprovalsMalformedSignalIgnored(t *testing.T) {
	valid := signed("bob", true)
	body, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	j := string(body)
	noApproved, err := json.Marshal(map[string]string{"plan_hash": plan(), "approver": "bob", "signature": valid.Signature})
	if err != nil {
		t.Fatal(err)
	}
	huge, unsigned := valid, valid
	huge.Signature, unsigned.Signature = strings.Repeat("a", loops.MaxApprovalSignalBytes), ""
	malformed := []any{
		rawJSON(t, j[:len(j)-1]), rawJSON(t, j+" {}"), rawJSON(t, strings.Replace(j, "{", `{"scope":"all",`, 1)),
		rawJSON(t, string(noApproved)), rawJSON(t, strings.Replace(j, "true", `"true"`, 1)),
		rawJSON(t, strings.Replace(j, `"`+valid.Signature+`"`, "null", 1)),
		rawJSON(t, "null"), rawJSON(t, "[]"), rawJSON(t, `"approved"`), body, nil, huge, unsigned,
		signed("Bob", true), signed(" bob", true), signed("", true), signed(strings.Repeat("b", loops.MaxIdentityBytes+1), true),
	}
	for _, key := range []string{"approved", "plan_hash", "approver", "signature"} {
		for _, absent := range []bool{true, false} {
			fields := map[string]any{}
			if err := json.Unmarshal(body, &fields); err != nil {
				t.Fatal(err)
			}
			if absent {
				delete(fields, key)
			} else {
				fields[key] = nil
			}
			b, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			malformed = append(malformed, rawJSON(t, string(b)))
		}
	}
	protoJSON := rawJSON(t, j)
	protoJSON.Payload().Metadata[converter.MetadataEncoding] = []byte(converter.MetadataEncodingProtoJSON)
	malformed = append(malformed, protoJSON)
	req, v := request(1, false), newVerifier()
	req.MaxIgnored = len(malformed)
	out := await(t, req, time.Hour, v, nil, append(malformed, valid)...)
	wantOutcome(t, out, loops.OutcomeApproved, []string{"bob"}, slices.Repeat([]loops.IgnoredSignal{ign("", loops.IgnoredMalformed)}, len(malformed))...)
	wantVerified(t, v, "bob")
	t.Run("size bound", func(t *testing.T) {
		pad := func(n int) converter.RawValue { return rawJSON(t, j+strings.Repeat(" ", n-len(j))) }
		out := await(t, request(1, false), time.Hour, newVerifier(), nil, pad(loops.MaxApprovalSignalBytes+1), pad(loops.MaxApprovalSignalBytes))
		wantOutcome(t, out, loops.OutcomeApproved, []string{"bob"}, ign("", loops.IgnoredMalformed))
	})
}

func TestAwaitApprovalsVerifierErrorIgnored(t *testing.T) {
	v := newVerifier()
	v.failFirst = 1
	out := await(t, request(1, false), time.Hour, v, nil, signed("bob", true), signed("bob", true))
	wantOutcome(t, out, loops.OutcomeApproved, []string{"bob"}, ign("bob", loops.IgnoredVerifyError))
	wantVerified(t, v, "bob", "bob") // one attempt per signal
}

func TestAwaitApprovalsSignalFlood(t *testing.T) {
	wrong, w := onHash(strings.Repeat("cd", 32), true), ign("bob", loops.IgnoredWrongHash)
	req, v := request(1, false), newVerifier()
	req.MaxIgnored = 3
	out := await(t, req, time.Hour, v, nil, wrong, wrong, rawJSON(t, "{}"), wrong, signed("bob", true))
	wantOutcome(t, out, loops.OutcomeSignalFlood, nil, w, w, ign("", loops.IgnoredMalformed), w)
	wantVerified(t, v)
	t.Run("at the bound the wait goes on", func(t *testing.T) {
		out := await(t, req, time.Hour, newVerifier(), nil, wrong, wrong, wrong, signed("bob", true))
		wantOutcome(t, out, loops.OutcomeApproved, []string{"bob"}, w, w, w)
	})
	t.Run("default bound", func(t *testing.T) {
		flood := slices.Repeat([]any{wrong}, loops.DefaultMaxIgnored)
		out := await(t, request(1, false), 3*time.Hour, newVerifier(), nil, append(flood, signed("bob", true))...)
		wantOutcome(t, out, loops.OutcomeApproved, []string{"bob"}, slices.Repeat([]loops.IgnoredSignal{w}, loops.DefaultMaxIgnored)...)
	})
	t.Run("default bound exceeded", func(t *testing.T) {
		v := newVerifier()
		flood := slices.Repeat([]any{wrong}, loops.DefaultMaxIgnored+1)
		out := await(t, request(1, false), 3*time.Hour, v, nil, append(flood, signed("bob", true))...)
		wantOutcome(t, out, loops.OutcomeSignalFlood, nil, slices.Repeat([]loops.IgnoredSignal{w}, loops.DefaultMaxIgnored+1)...)
		wantVerified(t, v)
	})
}

func TestAwaitApprovalsInvalidRequest(t *testing.T) {
	valid := request(1, false)
	valid.Author = "canary-author"
	with := func(f func(*loops.ApprovalRequest)) loops.ApprovalRequest {
		r := valid
		f(&r)
		return r
	}
	invalid := []loops.ApprovalRequest{
		with(func(r *loops.ApprovalRequest) { r.PlanHash = "" }),
		with(func(r *loops.ApprovalRequest) { r.PlanHash = strings.ToUpper(plan()) }),
		with(func(r *loops.ApprovalRequest) { r.PlanHash = plan()[:63] }),
		with(func(r *loops.ApprovalRequest) { r.PlanHash = plan() + "a" }),
		with(func(r *loops.ApprovalRequest) { r.PlanHash = strings.Repeat("g", 64) }),
		with(func(r *loops.ApprovalRequest) { r.Author = "" }),
		with(func(r *loops.ApprovalRequest) { r.Author = "Canary-author" }),
		with(func(r *loops.ApprovalRequest) { r.Author = "canary author" }),
		with(func(r *loops.ApprovalRequest) { r.Author = strings.Repeat("c", loops.MaxIdentityBytes+1) }),
		with(func(r *loops.ApprovalRequest) { r.Required = 0 }),
		with(func(r *loops.ApprovalRequest) { r.Required = loops.MaxRequiredApprovals + 1 }),
		with(func(r *loops.ApprovalRequest) { r.VerifyActivity = "" }),
		with(func(r *loops.ApprovalRequest) { r.MaxIgnored = -1 }),
		with(func(r *loops.ApprovalRequest) { r.MaxIgnored = loops.MaxIgnoredLimit + 1 }),
	}
	isInvalid := func(err error) bool {
		var ae *temporal.ApplicationError
		return errors.As(err, &ae) && ae.Type() == loops.ErrTypeInvalidApprovalRequest && ae.NonRetryable() &&
			!strings.Contains(strings.ToLower(err.Error()), "canary")
	}
	for i, r := range invalid {
		if err := r.Validate(); !isInvalid(err) {
			t.Errorf("case %d: Validate() = %v", i, err)
		}
	}
	for i, r := range []loops.ApprovalRequest{
		valid,
		with(func(r *loops.ApprovalRequest) { r.Author = "0.9_-@z" }),
		with(func(r *loops.ApprovalRequest) {
			r.Author, r.Required, r.MaxIgnored = strings.Repeat("c", loops.MaxIdentityBytes), loops.MaxRequiredApprovals, loops.MaxIgnoredLimit
		}),
	} {
		if err := r.Validate(); err != nil {
			t.Errorf("valid case %d refused: %v", i, err)
		}
	}
	for i, c := range []struct {
		req     loops.ApprovalRequest
		timeout time.Duration
	}{{invalid[0], time.Hour}, {invalid[9], time.Hour}, {valid, 0}, {valid, -time.Second}, {valid, loops.MaxApprovalTimeout + time.Second}} {
		v := newVerifier()
		out := await(t, c.req, c.timeout, v, nil, signed("bob", true))
		if !isInvalid(out.err) || len(out.timers) != 0 {
			t.Errorf("case %d: error %v, timers %v", i, out.err, out.timers)
		}
		wantVerified(t, v)
	}
	wantOutcome(t, await(t, valid, loops.MaxApprovalTimeout, newVerifier(), nil, signed("bob", true)), loops.OutcomeApproved, []string{"bob"})
}

func TestAwaitApprovalsCanceled(t *testing.T) {
	canceled := func(t *testing.T, out outcome) {
		t.Helper()
		if !temporal.IsCanceledError(out.err) {
			t.Fatalf("error %v, outcome %q: want the cancellation, never an outcome", out.err, out.res.Outcome)
		}
	}
	t.Run("while waiting", func(t *testing.T) {
		v := newVerifier()
		canceled(t, await(t, request(1, false), time.Hour, v, func(env *testsuite.TestWorkflowEnvironment) {
			env.RegisterDelayedCallback(env.CancelWorkflow, 30*time.Minute)
		}, forged("bob", true)))
		wantVerified(t, v, "bob")
	})
	t.Run("during a verification", func(t *testing.T) {
		v := newVerifier()
		canceled(t, await(t, request(1, false), time.Hour, v, func(env *testsuite.TestWorkflowEnvironment) {
			env.OnActivity(verifyApprovalName, mock.Anything, mock.Anything).Return(v.verify).After(20 * time.Minute)
			env.RegisterDelayedCallback(env.CancelWorkflow, 10*time.Minute)
		}, signed("bob", true)))
	})
	t.Run("then the signal that floods", func(t *testing.T) {
		req, wrong := request(1, false), onHash(strings.Repeat("cd", 32), true)
		req.MaxIgnored = 1
		canceled(t, await(t, req, time.Hour, newVerifier(), func(env *testsuite.TestWorkflowEnvironment) {
			env.RegisterDelayedCallback(func() {
				env.CancelWorkflow()
				env.SignalWorkflow(loops.ApprovalSignal, wrong)
			}, 30*time.Minute)
		}, wrong))
	})
}

func TestAwaitApprovalsDeadlineDuringVerification(t *testing.T) {
	v := newVerifier()
	out := await(t, request(1, false), time.Hour, v, func(env *testsuite.TestWorkflowEnvironment) {
		env.OnActivity(verifyApprovalName, mock.Anything, mock.Anything).Return(v.verify).After(time.Hour)
	}, signed("bob", true))
	wantOutcome(t, out, loops.OutcomeTimedOut, nil)
	wantVerified(t, v, "bob")
}

func TestAwaitApprovalsLimitsFrozen(t *testing.T) {
	got := []any{
		loops.ApprovalSignal, loops.ErrTypeInvalidApprovalRequest, loops.DefaultMaxIgnored, loops.MaxIgnoredLimit, loops.MaxRequiredApprovals,
		loops.MaxApprovalTimeout, loops.VerifyApprovalTimeout, loops.MaxApprovalSignalBytes, loops.MaxIdentityBytes,
	}
	frozen := []any{"approval", "InvalidApprovalRequest", 100, 1000, 5, 7 * 24 * time.Hour, 30 * time.Second, 8192, 128}
	if !slices.Equal(got, frozen) {
		t.Errorf("limits %v, want %v", got, frozen)
	}
	codes := []string{
		string(loops.OutcomeApproved), string(loops.OutcomeRejected), string(loops.OutcomeTimedOut), string(loops.OutcomeSignalFlood),
		string(loops.IgnoredMalformed), string(loops.IgnoredWrongHash), string(loops.IgnoredSelfApproval), string(loops.IgnoredDuplicate),
		string(loops.IgnoredVerifyError), string(loops.IgnoredInvalidSignature), string(loops.IgnoredNeedsSecurityRole),
	}
	want := []string{
		"approved", "rejected", "timed_out", "signal_flood", "malformed", "wrong_hash",
		"self_approval", "duplicate", "verify_error", "invalid_signature", "needs_security_role",
	}
	if !slices.Equal(codes, want) {
		t.Errorf("codes %v, want %v", codes, want)
	}
}
