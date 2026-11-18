package demo_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/workflow"

	llmfake "github.com/amezianechayer/rempart/internal/llm/fake"
	"github.com/amezianechayer/rempart/internal/loops"
	"github.com/amezianechayer/rempart/internal/loops/demo"
)

// TestDemoApprovalPhaseRequiresContinuation (ADR 0001, guard of
// prompts/M1.md, D7 of M1-codec-replay, T18): run 1 runs the loop and
// continues as new right before the approval wait; the approval phase is
// admitted only in a continuation, for a converged loop with a candidate,
// and the plan hash is computed again from the candidate, never read.
func TestDemoApprovalPhaseRequiresContinuation(t *testing.T) {
	converged := loops.LoopResult{Status: loops.StatusConverged, Best: greetBonjour, Iterations: 1, Tokens: 15}
	phaseInput := func(l loops.LoopResult) demo.Input {
		in := input()
		in.Phase = &demo.ApprovalPhase{Loop: l}
		return in
	}

	t.Run("first_run_continues_before_wait", func(t *testing.T) {
		h := newHarness(t, tenantA, []llmfake.Step{answer(greetBonjour)})
		h.signalAt(0, signedBy("bob", expectedHash(greetBonjour)))
		h.env.ExecuteWorkflow(demo.WorkflowName, input())
		var can *workflow.ContinueAsNewError
		if !h.env.IsWorkflowCompleted() || !errors.As(h.env.GetWorkflowError(), &can) {
			t.Fatalf("run 1 ended with %v, want a continuation", h.env.GetWorkflowError())
		}
		if can.WorkflowType == nil || can.WorkflowType.Name != demo.WorkflowName {
			t.Fatalf("continuation to %+v, want %s", can.WorkflowType, demo.WorkflowName)
		}
		var next demo.Input
		if err := converter.GetDefaultDataConverter().FromPayloads(can.Input, &next); err != nil {
			t.Fatal(err)
		}
		if next.Phase == nil || next.Phase.Loop.Status != loops.StatusConverged || string(next.Phase.Loop.Best) != string(greetBonjour) {
			t.Errorf("input of run 2 %+v, want the converged loop in the approval phase", next)
		}
		if next.Target != target || next.Author != "alice" || next.ApprovalTimeout != 5*time.Second {
			t.Errorf("input of run 2 %+v, want the input of run 1", next)
		}
		if n := h.count(verifyApproval) + h.count(commitName); n != 0 {
			t.Errorf("%d approval verifications or commits in run 1, want 0", n)
		}
	})

	t.Run("phase_without_continuation_refused", func(t *testing.T) {
		h := newHarness(t, tenantA, []llmfake.Step{answer(greetBonjour)})
		h.signalAt(time.Second, signedBy("bob", expectedHash(greetBonjour)))
		h.env.ExecuteWorkflow(demo.WorkflowName, phaseInput(converged))
		ae := appError(t, h.env.GetWorkflowError())
		if ae.Type() != demo.ErrTypeInvalidDemoInput || !ae.NonRetryable() {
			t.Errorf("error type %q non-retryable %v, want %q non-retryable", ae.Type(), ae.NonRetryable(), demo.ErrTypeInvalidDemoInput)
		}
		if h.total() != 0 || len(h.prov.Calls()) != 0 {
			t.Errorf("%d activities, %d provider calls; want 0, 0", h.total(), len(h.prov.Calls()))
		}
	})

	for name, l := range map[string]loops.LoopResult{
		"escalated_loop":  {Status: loops.StatusEscalated, Best: greetBonjour},
		"empty_candidate": {Status: loops.StatusConverged},
	} {
		t.Run("continuation_"+name+"_refused", func(t *testing.T) {
			h := newHarness(t, tenantA, []llmfake.Step{answer(greetBonjour)})
			h.env.SetContinuedExecutionRunID("run-1")
			h.env.ExecuteWorkflow(demo.WorkflowName, phaseInput(l))
			ae := appError(t, h.env.GetWorkflowError())
			if ae.Type() != demo.ErrTypeInvalidDemoInput || !ae.NonRetryable() || h.total() != 0 {
				t.Errorf("error type %q non-retryable %v, %d activities; want %q non-retryable, 0", ae.Type(), ae.NonRetryable(), h.total(), demo.ErrTypeInvalidDemoInput)
			}
		})
	}

	t.Run("phase_in_continuation_waits", func(t *testing.T) {
		h := newHarness(t, tenantA, nil)
		h.env.SetContinuedExecutionRunID("run-1")
		h.env.ExecuteWorkflow(demo.WorkflowName, phaseInput(converged))
		var out demo.Output
		if err := h.env.GetWorkflowError(); err != nil {
			t.Fatalf("run 2: %v", err)
		}
		if err := h.env.GetWorkflowResult(&out); err != nil {
			t.Fatal(err)
		}
		if out.Approval.Outcome != loops.OutcomeTimedOut || out.Committed || out.PlanHash != expectedHash(greetBonjour) {
			t.Errorf("approval %s, committed %v, plan hash %q; want timed_out, false, the hash of the candidate", out.Approval.Outcome, out.Committed, out.PlanHash)
		}
		if out.Loop.Status != loops.StatusConverged || string(out.Loop.Best) != string(greetBonjour) {
			t.Errorf("loop %+v, want the loop of run 1", out.Loop)
		}
		if len(h.prov.Calls()) != 0 || h.count(demo.ProposeActivity) != 0 {
			t.Errorf("run 2 called the model: %d calls, %d proposals", len(h.prov.Calls()), h.count(demo.ProposeActivity))
		}
	})

	t.Run("approval_after_continuation_commits", func(t *testing.T) {
		h := newHarness(t, tenantA, []llmfake.Step{answer(greetBonjour)})
		h.signalAt(time.Second, signedBy("bob", expectedHash(greetBonjour)))
		out := mustRun(t, h, input())
		if h.continued == nil || out.Approval.Outcome != loops.OutcomeApproved || !out.Committed || h.count(commitName) != 1 {
			t.Errorf("continued %v, approval %s, committed %v, %d commits; want a continuation, approved, true, 1",
				h.continued != nil, out.Approval.Outcome, out.Committed, h.count(commitName))
		}
	})

	t.Run("input_carries_no_plan_hash", func(t *testing.T) {
		raw, err := json.Marshal(phaseInput(converged))
		if err != nil {
			t.Fatal(err)
		}
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(raw, &keys); err != nil {
			t.Fatal(err)
		}
		if _, ok := keys["plan_hash"]; ok {
			t.Errorf("input %s carries a plan hash: it must be computed again in run 2 (T54)", raw)
		}
	})
}
