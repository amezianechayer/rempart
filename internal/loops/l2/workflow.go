// Package l2 is the loop L2-design (docs/loops/L2.md, ADR 0012): from a
// confirmed IR or candidate graph to a graph that the design policies and the
// invariants of the core accept, or an escalation explained by codes. No
// model: the proposer is the deterministic reviser.
package l2

import (
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	"github.com/amezianechayer/rempart/internal/design/revise"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	"github.com/amezianechayer/rempart/internal/loops"
	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
	"github.com/amezianechayer/rempart/internal/loops/l2/activities"
	"github.com/amezianechayer/rempart/internal/threat"
)

const (
	WorkflowName     = "rempart.l2.v1"
	TaskQueue        = "rempart-l2"
	IDPrefix         = "l2-design"
	PrepareActivity  = "l2.Prepare"
	ProposeActivity  = "l2.Propose"
	VerifyActivity   = "l2.Verify"
	FinalizeActivity = "l2.Finalize"
	// StepTimeout bounds Prepare and Finalize, deterministic and local.
	StepTimeout     = 30 * time.Second
	ExecutionMargin = 30 * time.Second
	// ErrTypeInvalidL2Input: refusal before the loop, never retried.
	ErrTypeInvalidL2Input = activities.ErrTypeInvalidL2Input
)

// Status of an L2 run.
const (
	StatusConverged = "converged"
	StatusEscalated = "escalated"
)

// Input carries no tenant: the tenant is the one of the worker (rule 9).
type Input = activities.Input

// Explanation is one coded cause of an escalation.
type Explanation = activities.Explanation

// Applied is one revision that changed the graph.
type Applied = revise.Applied

// Output: graph, threat model and delta only when converged, explanation
// only when escalated; no list written null; the best of the loop never
// leaves L2 (analogue of T98).
type Output struct {
	Status          string                `json:"status"`
	Reason          string                `json:"reason,omitempty"`
	Subject         string                `json:"subject"`
	Graph           *graphdomain.Graph    `json:"graph,omitempty"`
	Applied         []Applied             `json:"applied"`
	InitialFindings []loopsdomain.Finding `json:"initial_findings"`
	Advisories      []loopsdomain.Finding `json:"advisories"`
	Threats         *threat.Model         `json:"threats,omitempty"`
	ThreatDelta     *threat.Delta         `json:"threat_delta,omitempty"`
	Explanation     []Explanation         `json:"explanation,omitempty"`
	Loop            loops.LoopResult      `json:"loop"`
}

// Spec is the loop of docs/loops/L2.md: one deterministic strategy, no model.
func Spec() loops.LoopSpec {
	return loops.LoopSpec{
		ID: "L2-design", ProposeActivity: ProposeActivity, VerifyActivity: VerifyActivity,
		Strategies:  []string{activities.StrategyCatalog},
		Budget:      loops.Budget{MaxIterations: 5, MaxTokens: 1, MaxWallTime: 2 * time.Minute},
		SwitchAfter: 2, EscalateAfter: 3, ActivityTimeout: 30 * time.Second,
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
			NonRetryableErrorTypes: append(loops.NonRetryableErrorTypes(), ErrTypeInvalidL2Input),
		},
	})
	var prep activities.Prepared
	if err := workflow.ExecuteActivity(sctx, PrepareActivity, in).Get(ctx, &prep); err != nil {
		return Output{}, err
	}
	out := Output{
		Subject: prep.Subject, Applied: []Applied{}, InitialFindings: []loopsdomain.Finding{}, Advisories: []loopsdomain.Finding{},
		Loop: loops.LoopResult{Trace: []loops.IterationTrace{}},
	}
	if len(prep.Escalation) > 0 { // escalated before the loop: no activity of the loop
		out.Status, out.Reason, out.Explanation = StatusEscalated, prep.Escalation[0].Code, prep.Escalation
		return out, nil
	}
	loop, err := loops.RunLoop(ctx, Spec(), prep.Payload)
	if err != nil {
		return Output{}, err
	}
	best := loop.Best
	loop.Best = nil // the best candidate never leaves L2; the verified graph is the only deliverable
	out.Loop = loop
	req := activities.FinalizeRequest{Payload: prep.Payload, Best: best, Converged: loop.Status == loops.StatusConverged, Remaining: loop.Remaining}
	var fin activities.Finalized
	if err := workflow.ExecuteActivity(sctx, FinalizeActivity, req).Get(ctx, &fin); err != nil {
		return Output{}, err
	}
	out.Applied, out.InitialFindings, out.Advisories = fin.Applied, fin.InitialFindings, fin.Advisories
	if !req.Converged {
		out.Status, out.Reason, out.Explanation = StatusEscalated, string(loop.Reason), fin.Explanation
		return out, nil
	}
	out.Status, out.Graph, out.Threats, out.ThreatDelta = StatusConverged, fin.Graph, fin.Threats, fin.ThreatDelta
	return out, nil
}
