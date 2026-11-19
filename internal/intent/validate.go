package intent

import (
	"github.com/amezianechayer/rempart/internal/intent/domain"
	"github.com/amezianechayer/rempart/internal/intent/irvalid"
)

// ErrIRInvalid: the IR does not match schemas/intent/v1.json or its tenant is
// not a customer tenant. Fixed message. The same error as irvalid.
var ErrIRInvalid = irvalid.ErrIRInvalid

// ValidateIR checks ir against schemas/intent/v1.json (plan P1), then its
// tenant; see irvalid.ValidateIR.
func ValidateIR(ir domain.IR) error { return irvalid.ValidateIR(ir) }
