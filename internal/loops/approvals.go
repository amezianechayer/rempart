package loops

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// ApprovalSignal is the name of the signal that carries one Approval.
const ApprovalSignal = "approval"

// ErrTypeInvalidApprovalRequest types the refusal of a request or a timeout.
const ErrTypeInvalidApprovalRequest = "InvalidApprovalRequest"

// Defaults and bounds of an approval wait (threats T10, T12, T18).
const (
	DefaultMaxIgnored      = 100
	MaxIgnoredLimit        = 1000
	MaxRequiredApprovals   = 5
	MaxApprovalTimeout     = 7 * 24 * time.Hour
	VerifyApprovalTimeout  = 30 * time.Second
	MaxApprovalSignalBytes = 8 << 10
	MaxIdentityBytes       = 128
)

const (
	hexDigits     = "0123456789abcdef"
	identityBytes = "abcdefghijklmnopqrstuvwxyz0123456789._-@"
)

// ApprovalRequest says what to gather before applying one plan. The calling
// workflow builds it from constants and the deterministic risk
// classification, never from an input (threat T54).
type ApprovalRequest struct {
	PlanHash          string // SHA-256 of the plan, 64 lower-case hex digits
	Author            string // canonical identity; none of its signals counts
	Required          int    // distinct approvers, 1 to MaxRequiredApprovals
	NeedsSecurityRole bool   // one of them at least has the security role
	VerifyActivity    string // registered verification activity
	MaxIgnored        int    // 0 means DefaultMaxIgnored
}

// Approval is one decision on a plan hash. A signal is not authenticated:
// only the signature, checked by the verification activity, counts.
type Approval struct {
	Approved  bool   `json:"approved"`
	PlanHash  string `json:"plan_hash"`
	Approver  string `json:"approver"`
	Signature string `json:"signature"`
}

// ApprovalCheck is the result of the verification activity. SignatureValid
// means a valid signature of an approver allowed to decide on this plan.
type ApprovalCheck struct {
	SignatureValid bool `json:"signature_valid"`
	SecurityRole   bool `json:"security_role"`
}

// ApprovalOutcome ends a wait.
type ApprovalOutcome string

const (
	OutcomeApproved    ApprovalOutcome = "approved"
	OutcomeRejected    ApprovalOutcome = "rejected"
	OutcomeTimedOut    ApprovalOutcome = "timed_out"
	OutcomeSignalFlood ApprovalOutcome = "signal_flood"
)

// IgnoredReason says why a signal did not count.
type IgnoredReason string

const (
	IgnoredMalformed         IgnoredReason = "malformed"
	IgnoredWrongHash         IgnoredReason = "wrong_hash"
	IgnoredSelfApproval      IgnoredReason = "self_approval"
	IgnoredDuplicate         IgnoredReason = "duplicate"
	IgnoredVerifyError       IgnoredReason = "verify_error"
	IgnoredInvalidSignature  IgnoredReason = "invalid_signature"
	IgnoredNeedsSecurityRole IgnoredReason = "needs_security_role"
)

// IgnoredSignal records one ignored signal; Approver is empty if malformed.
type IgnoredSignal struct {
	Approver string        `json:"approver"`
	Reason   IgnoredReason `json:"reason"`
}

// ApprovalResult holds Approvals only for OutcomeApproved: exactly Required
// distinct approvals, in arrival order.
type ApprovalResult struct {
	Outcome   ApprovalOutcome `json:"outcome"`
	Approvals []Approval      `json:"approvals,omitempty"`
	Ignored   []IgnoredSignal `json:"ignored,omitempty"`
}

// Validate checks r once defaults are applied. The error is a non-retryable
// application error of type ErrTypeInvalidApprovalRequest that never quotes r.
func (r ApprovalRequest) Validate() error {
	r = r.withDefaults()
	switch {
	case !validPlanHash(r.PlanHash):
		return invalidApproval("plan hash")
	case !validIdentity(r.Author):
		return invalidApproval("author")
	case r.Required < 1 || r.Required > MaxRequiredApprovals:
		return invalidApproval("required approvals")
	case r.VerifyActivity == "":
		return invalidApproval("verify activity")
	case r.MaxIgnored < 1 || r.MaxIgnored > MaxIgnoredLimit:
		return invalidApproval("ignored signals bound")
	}
	return nil
}

func (r ApprovalRequest) withDefaults() ApprovalRequest {
	if r.MaxIgnored == 0 {
		r.MaxIgnored = DefaultMaxIgnored
	}
	return r
}

// AwaitApprovals waits until req.Required distinct approvers approve
// req.PlanHash, one of them with the security role if required, or until one
// authenticated refusal. An invalid signal is recorded and ignored without
// ending the wait, unless more than req.MaxIgnored were. Timeout: nothing is
// approved. The error is an invalid request or the cancellation of ctx,
// never an outcome.
func AwaitApprovals(ctx workflow.Context, req ApprovalRequest, timeout time.Duration) (ApprovalResult, error) {
	if err := req.Validate(); err != nil {
		return ApprovalResult{}, err
	}
	if timeout <= 0 || timeout > MaxApprovalTimeout {
		return ApprovalResult{}, invalidApproval("timeout")
	}
	req = req.withDefaults()
	actx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		ScheduleToCloseTimeout: VerifyApprovalTimeout,
		StartToCloseTimeout:    VerifyApprovalTimeout,
		RetryPolicy:            &temporal.RetryPolicy{MaximumAttempts: 1},
	})
	tctx, cancelTimer := workflow.WithCancel(ctx)
	defer cancelTimer()
	deadline := workflow.NewTimer(tctx, timeout)
	signals := workflow.GetSignalChannel(ctx, ApprovalSignal)

	var (
		res      ApprovalResult
		security bool
	)
	end := func(o ApprovalOutcome) (ApprovalResult, error) {
		if err := ctx.Err(); err != nil { // a cancellation is never an outcome
			return ApprovalResult{}, err
		}
		if o != OutcomeApproved {
			res.Approvals = nil // nothing retained unless approved
		}
		res.Outcome = o
		return res, nil
	}
	for {
		var (
			raw converter.RawValue
			got bool
		)
		workflow.NewSelector(ctx).
			AddFuture(deadline, func(workflow.Future) {}).
			AddReceive(signals, func(c workflow.ReceiveChannel, _ bool) { got = c.ReceiveAsync(&raw) }).
			Select(ctx)
		if deadline.IsReady() {
			return end(OutcomeTimedOut)
		}
		if !got {
			continue // dropped by the SDK: not decodable by the data converter
		}
		a, reason := screen(raw, req, res.Approvals)
		if reason == "" {
			var check ApprovalCheck
			err := workflow.ExecuteActivity(actx, req.VerifyActivity, a).Get(ctx, &check)
			if ctx.Err() != nil || deadline.IsReady() { // late verification: nothing retained
				return end(OutcomeTimedOut)
			}
			switch {
			case err != nil:
				reason = IgnoredVerifyError
			case !check.SignatureValid:
				reason = IgnoredInvalidSignature
			case !a.Approved:
				return end(OutcomeRejected)
			case req.NeedsSecurityRole && !security && !check.SecurityRole && len(res.Approvals) == req.Required-1:
				reason = IgnoredNeedsSecurityRole
			default:
				res.Approvals = append(res.Approvals, a)
				security = security || check.SecurityRole
				if len(res.Approvals) == req.Required {
					return end(OutcomeApproved)
				}
				continue
			}
		}
		res.Ignored = append(res.Ignored, IgnoredSignal{Approver: a.Approver, Reason: reason})
		if len(res.Ignored) > req.MaxIgnored {
			return end(OutcomeSignalFlood)
		}
	}
}

// screen decodes raw and applies, in order, the checks that need no activity.
func screen(raw converter.RawValue, req ApprovalRequest, kept []Approval) (Approval, IgnoredReason) {
	a, ok := decodeApproval(raw)
	dup := slices.ContainsFunc(kept, func(k Approval) bool { return k.Approver == a.Approver })
	switch {
	case !ok:
		return a, IgnoredMalformed
	case a.PlanHash != req.PlanHash: // exact bytes: the hash is public, nothing to time
		return a, IgnoredWrongHash
	case a.Approver == req.Author:
		return a, IgnoredSelfApproval
	case a.Approved && dup:
		return a, IgnoredDuplicate
	}
	return a, ""
}

// approvalWire tells absent and null fields apart from zero values.
type approvalWire struct {
	Approved  *bool   `json:"approved"`
	PlanHash  *string `json:"plan_hash"`
	Approver  *string `json:"approver"`
	Signature *string `json:"signature"`
}

// decodeApproval accepts one bounded json/plain object with exactly the four
// fields, none null, a canonical approver and a non-empty signature.
func decodeApproval(raw converter.RawValue) (Approval, bool) {
	p := raw.Payload()
	if string(p.GetMetadata()[converter.MetadataEncoding]) != converter.MetadataEncodingJSON {
		return Approval{}, false
	}
	data := p.GetData()
	var w approvalWire
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if len(data) > MaxApprovalSignalBytes || dec.Decode(&w) != nil || !errors.Is(dec.Decode(new(json.RawMessage)), io.EOF) {
		return Approval{}, false
	}
	if w.Approved == nil || w.PlanHash == nil || w.Approver == nil || w.Signature == nil ||
		!validIdentity(*w.Approver) || *w.Signature == "" {
		return Approval{}, false
	}
	return Approval{Approved: *w.Approved, PlanHash: *w.PlanHash, Approver: *w.Approver, Signature: *w.Signature}, true
}

// validPlanHash: 64 lower-case hex digits (Trim leaves any other byte).
func validPlanHash(s string) bool {
	return len(s) == 64 && strings.Trim(s, hexDigits) == ""
}

// validIdentity: 1 to MaxIdentityBytes bytes of identityBytes; identities are
// compared byte for byte, never normalized.
func validIdentity(s string) bool {
	return s != "" && len(s) <= MaxIdentityBytes && strings.Trim(s, identityBytes) == ""
}

func invalidApproval(what string) error {
	return temporal.NewNonRetryableApplicationError("invalid approval request: "+what, ErrTypeInvalidApprovalRequest, nil)
}
