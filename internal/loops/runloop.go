package loops

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"go.temporal.io/sdk/converter"
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

// ProposeFailure is the only detail of a proposer ApplicationError that spent
// tokens. RunLoop admits it only as the exact bytes {"tokens":N} and retries
// only such a declared failure (threats T10, T45, obligation h).
type ProposeFailure struct {
	Tokens int `json:"tokens"`
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
	Failed      bool   `json:"failed"`
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
// budget, a stagnation, a failed activity or an invalid response escalates. An
// escalation is a result, not an error: only an invalid spec or payload or a
// cancellation ends in error.
func RunLoop(ctx workflow.Context, spec LoopSpec, payload json.RawMessage) (LoopResult, error) {
	if err := spec.Validate(); err != nil {
		return LoopResult{}, err
	}
	if !admittedJSON(payload, MaxPayloadBytes) { // obligation a: bounded payload
		return LoopResult{}, invalidSpec("payload")
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
	// T10: one attempt per paid call; RunLoop retries within the budgets.
	pctx := workflow.WithRetryPolicy(ctx, temporal.RetryPolicy{MaximumAttempts: 1})
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
		failures        int
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
		perr := workflow.ExecuteActivity(pctx, spec.ProposeActivity, req).Get(ctx, &prop)
		if ctx.Err() != nil { // cancellation is no proposer failure (obligation b)
			return LoopResult{}, ctx.Err()
		}
		retry := false
		if perr != nil {
			prop.Tokens, retry = failedCall(perr)
		}
		res.Iterations = it
		res.Trace = append(res.Trace, IterationTrace{Iteration: it, Strategy: req.Strategy, Failed: perr != nil})
		tr := &res.Trace[len(res.Trace)-1]
		if prop.Tokens < 0 || prop.Tokens > MaxTokensLimit {
			return escalate(ReasonInvalidResponse) // traced, tokens not counted (obligation i)
		}
		tr.Tokens, res.Tokens = prop.Tokens, res.Tokens+prop.Tokens
		if res.Tokens > spec.Budget.MaxTokens {
			return escalate(ReasonBudgetTokens)
		}
		if perr != nil {
			failures++
			if !retry || failures >= MaxActivityAttempts {
				return escalate(ReasonActivityFailed)
			}
			continue // same request; time checked first
		}
		failures = 0
		if !admittedJSON(prop.Candidate, MaxCandidateBytes) { // obligation a: bounded candidate
			return escalate(ReasonInvalidResponse)
		}
		if emptyCandidate(prop.Candidate) { // T53: empty desired state
			return escalate(ReasonInvalidResponse)
		}
		if timeUp() { // T10: no verification past the wall time budget
			return escalate(ReasonBudgetTime)
		}
		var vr VerifyResult
		vreq := VerifyRequest{Payload: payload, Candidate: prop.Candidate, Iteration: it}
		verr := workflow.ExecuteActivity(ctx, spec.VerifyActivity, vreq).Get(ctx, &vr)
		if ctx.Err() != nil { // cancellation wins over any verifier result (obligations b, m)
			return LoopResult{}, ctx.Err()
		}
		if verr != nil {
			return escalate(ReasonActivityFailed) // Temporal retries only
		}
		if !findingsInBounds(vr.Findings) { // obligation a: bounded findings
			return escalate(ReasonInvalidResponse)
		}
		fp, score := domain.Fingerprint(vr.Findings), domain.Score(vr.Findings)
		tr.Verified, tr.Fingerprint, tr.Score, tr.Findings = true, fp, score, len(vr.Findings)
		if vr.OK {
			if blocking(vr.Findings) {
				return escalate(ReasonInvalidResponse)
			}
			res.Status, res.Best, res.Remaining = StatusConverged, prop.Candidate, domain.Sort(vr.Findings)
			return res, nil
		}
		if len(vr.Findings) == 0 { // T53: failure without finding
			return escalate(ReasonInvalidResponse)
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

const jsonBlanks = " \t\n\r"

// failedCall reads a failed proposer call from the direct cause of the
// ActivityError only (obligation h): no ProposeFailure, 0 tokens and no retry.
func failedCall(err error) (tokens int, retry bool) {
	ae := directApplicationError(err)
	if ae == nil || !ae.HasDetails() {
		return 0, false
	}
	tokens, ok := failureTokens(ae)
	if !ok {
		return -1, false
	}
	return tokens, !ae.NonRetryable() && !slices.Contains(NonRetryableErrorTypes(), ae.Type())
}

// directApplicationError returns the cause of err if err is exactly an
// ActivityError and the cause exactly an ApplicationError (errors.As stops there).
func directApplicationError(err error) *temporal.ApplicationError {
	if reflect.TypeOf(err) != reflect.TypeFor[*temporal.ActivityError]() {
		return nil
	}
	cause := errors.Unwrap(err)
	var ae *temporal.ApplicationError
	if reflect.TypeOf(cause) != reflect.TypeFor[*temporal.ApplicationError]() || !errors.As(cause, &ae) {
		return nil
	}
	return ae
}

// failureTokens admits exactly one json/plain detail whose bytes are
// {"tokens":N}, N in canonical decimal form; RunLoop bounds N.
func failureTokens(ae *temporal.ApplicationError) (int, bool) {
	var first, second converter.RawValue
	if ae.Details(&first, &second) != nil || second.Payload() != nil {
		return 0, false
	}
	p := first.Payload()
	if string(p.GetMetadata()[converter.MetadataEncoding]) != converter.MetadataEncodingJSON {
		return 0, false
	}
	digits, ok1 := strings.CutPrefix(string(p.GetData()), `{"tokens":`)
	digits, ok2 := strings.CutSuffix(digits, "}")
	n, err := strconv.Atoi(digits)
	if !ok1 || !ok2 || err != nil || strconv.Itoa(n) != digits {
		return 0, false
	}
	return n, true
}

// admittedJSON reports raw JSON of valid UTF-8 whose encoding stays within limit.
func admittedJSON(raw json.RawMessage, limit int) bool {
	return utf8.Valid(raw) && wireLen(raw) <= limit
}

// findingsInBounds admits at most MaxFindings findings whose string fields
// encode to at most MaxFindingBytes each (obligation a).
func findingsInBounds(f []domain.Finding) bool {
	return len(f) <= MaxFindings && !slices.ContainsFunc(f, func(x domain.Finding) bool {
		n := wireLen(x.Code) + wireLen(x.Source) + wireLen(x.Severity) + wireLen(x.Resource) + wireLen(x.File) + wireLen(x.Message)
		return n > MaxFindingBytes
	})
}

// wireLen bounds the encoding/json length of s, valid UTF-8, HTML escaped: 6
// for a control byte, <, > and &; 2 for ", \ and multi-byte rune bytes; else 1.
func wireLen[T ~string | ~[]byte](s T) int {
	n := 0
	for i := range len(s) {
		switch b := s[i]; {
		case b < 0x20 || b == '<' || b == '>' || b == '&':
			n += 6
		case b == '"' || b == '\\' || b >= utf8.RuneSelf:
			n += 2
		default:
			n++
		}
	}
	return n
}

// emptyCandidate reports a candidate without content once every JSON blank
// is removed; a string of blanks is empty too (fail safe, obligation i).
func emptyCandidate(c json.RawMessage) bool {
	compact := strings.Map(func(r rune) rune {
		if strings.ContainsRune(jsonBlanks, r) {
			return -1
		}
		return r
	}, string(c))
	return slices.Contains([]string{"", "null", `""`, "{}", "[]"}, compact)
}
