package loops

import (
	"slices"
	"strings"
	"time"

	"go.temporal.io/sdk/temporal"
)

// Error types. Activities report a non-transient failure with one of the last
// three: RunLoop never retries them.
const (
	ErrTypeInvalidLoopSpec = "InvalidLoopSpec"
	ErrTypeValidation      = "ValidationError"
	ErrTypePolicyViolation = "PolicyViolation"
	ErrTypeBudgetExceeded  = "BudgetExceeded"
)

// Defaults and bounds of a LoopSpec (threat T10).
const (
	DefaultSwitchAfter     = 2
	DefaultEscalateAfter   = 3
	DefaultActivityTimeout = 5 * time.Minute

	MaxIterationsLimit   = 100
	MaxTokensLimit       = 10_000_000
	MaxWallTimeLimit     = 24 * time.Hour
	MinActivityTimeout   = time.Second
	MaxActivityTimeout   = 30 * time.Minute
	MaxStrategies        = 10
	MaxFindingsToPropose = 20
	MaxActivityAttempts  = 3
	MaxEscalateAfter     = 10
)

// Size bounds (obligation a), upper bounds of the JSON encoding (wireLen): a
// LoopResult then encodes to less than 256 KiB, the M1 codec limit.
const (
	MaxPayloadBytes   = 64 << 10
	MaxCandidateBytes = 64 << 10
	MaxFindings       = 100
	MaxFindingBytes   = 1 << 10
	MaxNameBytes      = 64
)

// nameBytes admits the names of a LoopSpec; JSON never escapes them.
const nameBytes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"

// Budget bounds one run; every field is required.
type Budget struct {
	MaxIterations int
	MaxTokens     int
	MaxWallTime   time.Duration
}

// LoopSpec describes one loop. Zero SwitchAfter, EscalateAfter and
// ActivityTimeout take their defaults; a zero budget is refused.
type LoopSpec struct {
	ID              string
	ProposeActivity string
	VerifyActivity  string
	Strategies      []string
	Budget          Budget
	SwitchAfter     int
	EscalateAfter   int
	ActivityTimeout time.Duration
}

// NonRetryableErrorTypes returns the activity error types never retried.
func NonRetryableErrorTypes() []string {
	return []string{ErrTypeValidation, ErrTypePolicyViolation, ErrTypeBudgetExceeded}
}

// Validate checks s once defaults are applied. The error is a non-retryable
// application error of type ErrTypeInvalidLoopSpec that never quotes s.
func (s LoopSpec) Validate() error {
	s = s.withDefaults()
	b := s.Budget
	switch {
	case !validName(s.ID) || !validName(s.ProposeActivity) || !validName(s.VerifyActivity):
		return invalidSpec("names")
	case s.ProposeActivity == s.VerifyActivity:
		return invalidSpec("the verifier must not be the proposer")
	case len(s.Strategies) == 0 || len(s.Strategies) > MaxStrategies || slices.ContainsFunc(s.Strategies, invalidName):
		return invalidSpec("strategies")
	case b.MaxIterations < 1 || b.MaxIterations > MaxIterationsLimit:
		return invalidSpec("iteration budget")
	case b.MaxTokens < 1 || b.MaxTokens > MaxTokensLimit:
		return invalidSpec("token budget")
	case b.MaxWallTime <= 0 || b.MaxWallTime > MaxWallTimeLimit:
		return invalidSpec("wall time budget")
	case s.SwitchAfter < 1 || s.SwitchAfter >= s.EscalateAfter || s.EscalateAfter > MaxEscalateAfter:
		return invalidSpec("stagnation thresholds")
	case s.ActivityTimeout < MinActivityTimeout || s.ActivityTimeout > MaxActivityTimeout:
		return invalidSpec("activity timeout")
	}
	return nil
}

// validName: 1 to MaxNameBytes bytes of nameBytes.
func validName(s string) bool {
	return s != "" && len(s) <= MaxNameBytes && strings.Trim(s, nameBytes) == ""
}

func invalidName(s string) bool { return !validName(s) }

// MaxRunDuration bounds RunLoop (c): wall time, then a verification started
// just before it: MaxActivityAttempts attempts, backoff 1 s then 2 s.
func (s LoopSpec) MaxRunDuration() time.Duration {
	s = s.withDefaults()
	return s.Budget.MaxWallTime + MaxActivityAttempts*s.ActivityTimeout + 3*time.Second
}

func (s LoopSpec) withDefaults() LoopSpec {
	if s.SwitchAfter == 0 {
		s.SwitchAfter = DefaultSwitchAfter
	}
	if s.EscalateAfter == 0 {
		s.EscalateAfter = DefaultEscalateAfter
	}
	if s.ActivityTimeout == 0 {
		s.ActivityTimeout = DefaultActivityTimeout
	}
	return s
}

func invalidSpec(what string) error {
	return temporal.NewNonRetryableApplicationError("invalid loop spec: "+what, ErrTypeInvalidLoopSpec, nil)
}
