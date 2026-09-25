package loops

import (
	"encoding/json"
	"slices"
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	"github.com/amezianechayer/rempart/internal/loops/domain"
)

// ProposeRequest is the input of the proposer activity.
type ProposeRequest struct {
	Payload   json.RawMessage  `json:"payload"`
	Strategy  string           `json:"strategy"`
	Best      json.RawMessage  `json:"best,omitempty"`
	Findings  []domain.Finding `json:"findings,omitempty"`
	Iteration int              `json:"iteration"`
}

// ProposeResponse is untrusted: RunLoop bounds Tokens (threats T10, T45).
type ProposeResponse struct {
	Candidate json.RawMessage `json:"candidate"`
	Tokens    int             `json:"tokens"`
}

// VerifyRequest is the input of the verifier activity.
type VerifyRequest struct {
	Payload   json.RawMessage `json:"payload"`
	Candidate json.RawMessage `json:"candidate"`
	Iteration int             `json:"iteration"`
}

// VerifyResult carries no fingerprint nor score: RunLoop computes them.
type VerifyResult struct {
	OK       bool             `json:"ok"`
	Findings []domain.Finding `json:"findings"`
}

// Status is the outcome of a run.
type Status string

const (
	StatusConverged Status = "converged"
	StatusEscalated Status = "escalated"
)

// Reason codes an escalation.
type Reason string

const (
	ReasonBudgetIterations    Reason = "budget_iterations"
	ReasonBudgetTokens        Reason = "budget_tokens"
	ReasonBudgetTime          Reason = "budget_time"
	ReasonStagnation          Reason = "stagnation"
	ReasonStrategiesExhausted Reason = "strategies_exhausted"
	ReasonActivityFailed      Reason = "activity_failed"
	ReasonInvalidResponse     Reason = "invalid_response"
)

// IterationTrace records one proposal; Verified is false when the run
// stopped before its verification.
type IterationTrace struct {
	Iteration   int    `json:"iteration"`
	Strategy    string `json:"strategy"`
	Verified    bool   `json:"verified"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Score       int    `json:"score"`
	Findings    int    `json:"findings"`
	Tokens      int    `json:"tokens"`
}

// LoopResult is the outcome of a run. Remaining holds the sorted findings of
// Best.
type LoopResult struct {
	Status     Status           `json:"status"`
	Reason     Reason           `json:"reason,omitempty"`
	Best       json.RawMessage  `json:"best,omitempty"`
	Remaining  []domain.Finding `json:"remaining,omitempty"`
	Iterations int              `json:"iterations"`
	Tokens     int              `json:"tokens"`
	Trace      []IterationTrace `json:"trace"`
}

// RunLoop proposes and verifies until the verifier accepts a candidate, or a
// budget, a stagnation or a failed activity escalates. An escalation is a
// result, not an error: only an invalid spec fails the workflow.
func RunLoop(ctx workflow.Context, spec LoopSpec, payload json.RawMessage) (LoopResult, error) {
	if err := spec.Validate(); err != nil {
		return LoopResult{}, err
	}
	spec = spec.withDefaults()
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: spec.ActivityTimeout,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:        time.Second,
			BackoffCoefficient:     2,
			MaximumInterval:        time.Minute,
			MaximumAttempts:        MaxActivityAttempts,
			NonRetryableErrorTypes: NonRetryableErrorTypes(),
		},
	})
	start := workflow.Now(ctx)
	timeUp := func() bool { return workflow.Now(ctx).Sub(start) >= spec.Budget.MaxWallTime }

	var (
		res             LoopResult
		best            json.RawMessage
		remaining, last []domain.Finding
		bestScore       int
		haveBest        bool
		lastFP          string
		same, strat     int
	)
	escalate := func(r Reason) (LoopResult, error) {
		res.Status, res.Reason, res.Best, res.Remaining = StatusEscalated, r, best, remaining
		return res, nil
	}

	for it := 1; it <= spec.Budget.MaxIterations; it++ {
		if timeUp() { // T10: no proposal past the wall time budget
			return escalate(ReasonBudgetTime)
		}
		req := ProposeRequest{
			Payload: payload, Strategy: spec.Strategies[strat], Best: best,
			Findings: domain.Top(last, MaxFindingsToPropose), Iteration: it,
		}
		var prop ProposeResponse
		if err := workflow.ExecuteActivity(ctx, spec.ProposeActivity, req).Get(ctx, &prop); err != nil {
			return escalate(ReasonActivityFailed)
		}
		if prop.Tokens < 0 || prop.Tokens > MaxTokensLimit {
			return escalate(ReasonInvalidResponse)
		}
		res.Iterations, res.Tokens = it, res.Tokens+prop.Tokens
		res.Trace = append(res.Trace, IterationTrace{Iteration: it, Strategy: req.Strategy, Tokens: prop.Tokens})
		if res.Tokens > spec.Budget.MaxTokens {
			return escalate(ReasonBudgetTokens)
		}
		if timeUp() { // T10: no verification past the wall time budget
			return escalate(ReasonBudgetTime)
		}
		var vr VerifyResult
		vreq := VerifyRequest{Payload: payload, Candidate: prop.Candidate, Iteration: it}
		if err := workflow.ExecuteActivity(ctx, spec.VerifyActivity, vreq).Get(ctx, &vr); err != nil {
			return escalate(ReasonActivityFailed)
		}
		fp, score := domain.Fingerprint(vr.Findings), domain.Score(vr.Findings)
		tr := &res.Trace[len(res.Trace)-1]
		tr.Verified, tr.Fingerprint, tr.Score, tr.Findings = true, fp, score, len(vr.Findings)
		if vr.OK {
			if blocking(vr.Findings) {
				return escalate(ReasonInvalidResponse)
			}
			res.Status, res.Best, res.Remaining = StatusConverged, prop.Candidate, domain.Sort(vr.Findings)
			return res, nil
		}
		if !haveBest || score < bestScore {
			best, bestScore, remaining, haveBest = prop.Candidate, score, domain.Sort(vr.Findings), true
		}
		last = vr.Findings
		if fp == lastFP {
			same++
		} else {
			lastFP, same = fp, 1
		}
		switch {
		case same >= spec.EscalateAfter:
			return escalate(ReasonStagnation)
		case same >= spec.SwitchAfter:
			if strat+1 >= len(spec.Strategies) {
				return escalate(ReasonStrategiesExhausted)
			}
			strat++
		}
	}
	return escalate(ReasonBudgetIterations)
}

// blocking reports a finding at the fingerprint threshold (medium or more,
// unknown severities included): such a result cannot converge.
func blocking(f []domain.Finding) bool {
	return slices.ContainsFunc(f, func(x domain.Finding) bool {
		return x.Severity.Weight() >= domain.SeverityMedium.Weight()
	})
}
