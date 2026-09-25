package loops

import (
	"slices"
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
)

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
	case s.ID == "" || s.ProposeActivity == "" || s.VerifyActivity == "":
		return invalidSpec("missing name")
	case s.ProposeActivity == s.VerifyActivity:
		return invalidSpec("the verifier must not be the proposer")
	case len(s.Strategies) == 0 || len(s.Strategies) > MaxStrategies || slices.Contains(s.Strategies, ""):
		return invalidSpec("strategies")
	case b.MaxIterations < 1 || b.MaxIterations > MaxIterationsLimit:
		return invalidSpec("iteration budget")
	case b.MaxTokens < 1 || b.MaxTokens > MaxTokensLimit:
		return invalidSpec("token budget")
	case b.MaxWallTime <= 0 || b.MaxWallTime > MaxWallTimeLimit:
		return invalidSpec("wall time budget")
	case s.SwitchAfter < 1 || s.SwitchAfter >= s.EscalateAfter:
		return invalidSpec("stagnation thresholds")
	case s.ActivityTimeout < MinActivityTimeout || s.ActivityTimeout > MaxActivityTimeout:
		return invalidSpec("activity timeout")
	}
	return nil
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
