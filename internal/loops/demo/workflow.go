// Package demo is the synthetic loop L0-demo (docs/loops/L0-demo.md).
package demo

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	"github.com/amezianechayer/rempart/internal/loops"
	"github.com/amezianechayer/rempart/internal/loops/demo/activities"
)

const (
	WorkflowName            = "rempart.demo.v1"
	TaskQueue               = "rempart-demo"
	ProposeActivity         = "demo.Propose"
	VerifyActivity          = "demo.Verify"
	VerifyApprovalActivity  = "demo.VerifyApproval"
	CommitActivity          = "demo.Commit"
	RequiredApprovals       = 1
	MaxIgnoredSignals       = 20
	MinApprovalTimeout      = time.Second
	MaxApprovalTimeout      = time.Hour
	CommitTimeout           = 10 * time.Second
	ErrTypeInvalidDemoInput = "InvalidDemoInput"
	identityBytes           = "abcdefghijklmnopqrstuvwxyz0123456789._-@"
	planDomain              = "rempart-demo-plan-v1\n"
	IDPrefix                = "l0-demo"
	ExecutionMargin         = 30 * time.Second
)

// ExecutionTimeout bounds one execution (c, D16): RunLoop, the approval wait,
// one late verification, the commit and a margin.
func ExecutionTimeout(approvalTimeout time.Duration) time.Duration {
	return Spec().MaxRunDuration() + approvalTimeout + loops.VerifyApprovalTimeout + CommitTimeout + ExecutionMargin
}

// Input of the demo. Phase is set by the workflow only, for the continuation
// of D7 (M1-codec-replay): it is admitted only in a continued execution.
type Input struct {
	Target          string         `json:"target"`
	Author          string         `json:"author"` // declared, not authenticated until M4
	ApprovalTimeout time.Duration  `json:"approval_timeout"`
	Phase           *ApprovalPhase `json:"approval_phase,omitempty"`
}

// ApprovalPhase carries the converged loop of run 1 to run 2; the plan hash
// is computed again from Loop.Best, never carried (T54).
type ApprovalPhase struct {
	Loop loops.LoopResult `json:"loop"`
}

type Output struct {
	Loop      loops.LoopResult     `json:"loop"`
	Approval  loops.ApprovalResult `json:"approval"`
	PlanHash  string               `json:"plan_hash,omitempty"`
	Committed bool                 `json:"committed"`
}

func Spec() loops.LoopSpec {
	return loops.LoopSpec{
		ID: "L0-demo", ProposeActivity: ProposeActivity, VerifyActivity: VerifyActivity,
		Strategies:  []string{activities.StrategyDirect, activities.StrategyReformulate},
		Budget:      loops.Budget{MaxIterations: 4, MaxTokens: 4000, MaxWallTime: time.Minute},
		SwitchAfter: 2, EscalateAfter: 3, ActivityTimeout: 30 * time.Second,
	}
}

// Workflow: run 1 runs the loop and, converged, continues as new right before
// the approval wait (ADR 0001, D7): the history of the wait starts small and
// in-flight runs survive a change of the loop. Run 2 waits for the approval;
// signals sent to run 1 are lost by design (R8).
func Workflow(ctx workflow.Context, in Input) (Output, error) {
	if err := in.validate(); err != nil {
		return Output{}, err
	}
	if in.Phase == nil {
		loop, err := loops.RunLoop(ctx, Spec(), payload(in.Target))
		if err != nil {
			return Output{}, err
		}
		if loop.Status != loops.StatusConverged { // escalation: no approval wait
			return Output{Loop: loop}, nil
		}
		next := in
		next.Phase = &ApprovalPhase{Loop: loop}
		return Output{}, workflow.NewContinueAsNewError(ctx, WorkflowName, next)
	}
	// Run 2: admitted only in a continued execution, for a converged loop
	// with a candidate (T18), before any activity.
	loop := in.Phase.Loop
	if workflow.GetInfo(ctx).ContinuedExecutionRunID == "" || loop.Status != loops.StatusConverged || len(loop.Best) == 0 {
		return Output{}, invalidInput("approval phase")
	}
	out := Output{Loop: loop}
	out.PlanHash = planHash(loop.Best)
	approval, err := loops.AwaitApprovals(ctx, loops.ApprovalRequest{
		PlanHash: out.PlanHash, Author: in.Author, Required: RequiredApprovals,
		NeedsSecurityRole: false, VerifyActivity: VerifyApprovalActivity, MaxIgnored: MaxIgnoredSignals,
	}, in.ApprovalTimeout)
	if err != nil {
		return out, err
	}
	out.Approval = approval
	if approval.Outcome != loops.OutcomeApproved { // principle 7
		return out, nil
	}
	if err := ctx.Err(); err != nil { // obligation (m)
		return out, err
	}
	cctx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: CommitTimeout, RetryPolicy: &temporal.RetryPolicy{MaximumAttempts: 1},
	})
	if err := workflow.ExecuteActivity(cctx, CommitActivity, out.PlanHash).Get(ctx, nil); err != nil {
		return out, err
	}
	out.Committed = true
	return out, nil
}

func (in Input) validate() error {
	switch {
	case !activities.ValidTarget(in.Target):
		return invalidInput("target")
	case in.Author == "" || len(in.Author) > loops.MaxIdentityBytes || strings.Trim(in.Author, identityBytes) != "":
		return invalidInput("author")
	case in.ApprovalTimeout < MinApprovalTimeout || in.ApprovalTimeout > MaxApprovalTimeout:
		return invalidInput("approval timeout")
	}
	return nil
}

func payload(target string) json.RawMessage {
	return json.RawMessage("{\"target\":\"" + target + "\"}")
}

func planHash(best json.RawMessage) string {
	sum := sha256.Sum256(append([]byte(planDomain), best...))
	return hex.EncodeToString(sum[:])
}

func invalidInput(what string) error {
	return temporal.NewNonRetryableApplicationError("invalid demo input: "+what, ErrTypeInvalidDemoInput, nil)
}
