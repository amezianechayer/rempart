// Package l1 is the loop L1-intent (docs/loops/L1.md): from a request in
// natural language to a verified Intent IR v1.
package l1

import (
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	"github.com/amezianechayer/rempart/internal/intent/domain"
	"github.com/amezianechayer/rempart/internal/loops"
	"github.com/amezianechayer/rempart/internal/loops/l1/activities"
)

const (
	WorkflowName     = "rempart.l1.v1"
	TaskQueue        = "rempart-l1"
	IDPrefix         = "l1-intent"
	PrepareActivity  = "l1.Prepare"
	ProposeActivity  = "l1.Propose"
	VerifyActivity   = "l1.Verify"
	FinalizeActivity = "l1.Finalize"
	MaxRounds        = activities.MaxRounds
	// StepTimeout bounds Prepare and Finalize, deterministic and local.
	StepTimeout     = 30 * time.Second
	ExecutionMargin = 30 * time.Second
)

// Status of an L1 run.
const (
	StatusConverged          = activities.StatusConverged
	StatusNeedsClarification = activities.StatusNeedsClarification
	StatusEscalated          = "escalated"
)

// Reasons of an escalation decided by L1 itself; the other reasons are those
// of loops.RunLoop.
const (
	ReasonLanguageUnsupported    = "language_unsupported"    // obligation (dh)
	ReasonClarificationExhausted = "clarification_exhausted" // questions left at the last round
)

// Input carries no tenant: the tenant is the one of the worker (rule 9).
type Input = activities.Input

// Route is the effective route of a delivered IR (obligation (eg)).
type Route = activities.Route

// Output: IR only when converged or needs_clarification (D5).
type Output struct {
	Status         string                 `json:"status"`
	Reason         string                 `json:"reason,omitempty"`
	IR             *domain.IR             `json:"ir,omitempty"`
	Contradictions []domain.Contradiction `json:"contradictions"`
	Route          *Route                 `json:"route,omitempty"` // set once Finalize ran
	Loop           loops.LoopResult       `json:"loop"`
}

// Spec is the loop of docs/loops/L1.md: 1 proposal and 3 corrections.
func Spec() loops.LoopSpec {
	return loops.LoopSpec{
		ID: "L1-intent", ProposeActivity: ProposeActivity, VerifyActivity: VerifyActivity,
		Strategies:  []string{activities.StrategyDirect, activities.StrategyFocusedCorrection},
		Budget:      loops.Budget{MaxIterations: 4, MaxTokens: 40000, MaxWallTime: 3 * time.Minute},
		SwitchAfter: 2, EscalateAfter: 3, ActivityTimeout: 2 * time.Minute,
	}
}

// ExecutionTimeout bounds one execution: Prepare, RunLoop, Finalize, a margin.
func ExecutionTimeout() time.Duration {
	return Spec().MaxRunDuration() + 2*loops.MaxActivityAttempts*StepTimeout + ExecutionMargin
}

func Workflow(ctx workflow.Context, in Input) (Output, error) {
	sctx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: StepTimeout,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval: time.Second, BackoffCoefficient: 2, MaximumAttempts: loops.MaxActivityAttempts,
			NonRetryableErrorTypes: loops.NonRetryableErrorTypes(),
		},
	})
	var prep activities.Prepared
	if err := workflow.ExecuteActivity(sctx, PrepareActivity, in).Get(ctx, &prep); err != nil {
		return Output{}, err
	}
	out := Output{Contradictions: []domain.Contradiction{}}
	if prep.Unsupported { // (dh): no proposer call
		out.Status, out.Reason = StatusEscalated, ReasonLanguageUnsupported
		return out, nil
	}
	loop, err := loops.RunLoop(ctx, Spec(), prep.Payload)
	if err != nil {
		return Output{}, err
	}
	best := loop.Best
	loop.Best = nil // T98: a draft never leaves L1, the rejected one least of all; the IR is the only deliverable
	out.Loop = loop
	if loop.Status != loops.StatusConverged {
		out.Status, out.Reason = StatusEscalated, string(loop.Reason)
		return out, nil
	}
	var fin activities.Finalized
	req := activities.FinalizeRequest{Payload: prep.Payload, Candidate: best}
	if err := workflow.ExecuteActivity(sctx, FinalizeActivity, req).Get(ctx, &fin); err != nil {
		return Output{}, err
	}
	out.Contradictions, out.Route = fin.Contradictions, &fin.Route
	if fin.Status == StatusNeedsClarification && in.Round >= MaxRounds {
		out.Status, out.Reason = StatusEscalated, ReasonClarificationExhausted
		return out, nil
	}
	out.Status, out.IR = fin.Status, &fin.IR
	return out, nil
}
