package intent

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/amezianechayer/rempart/internal/intent/domain"
	"github.com/amezianechayer/rempart/internal/tenancy"
	"github.com/amezianechayer/rempart/schemas"
)

// ErrIRInvalid: the IR does not match schemas/intent/v1.json or its tenant is
// not a customer tenant. Fixed message.
var ErrIRInvalid = errors.New("intent: invalid IR")

// ValidateIR checks ir against schemas/intent/v1.json (plan P1), then its
// tenant with tenancy.ParseID; the system tenant is refused.
func ValidateIR(ir domain.IR) error {
	s, err := schemas.Compile(schemas.IntentIR)
	if err != nil {
		return ErrIRInvalid
	}
	raw, err := json.Marshal(ir)
	if err != nil {
		return ErrIRInvalid
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return ErrIRInvalid
	}
	if err := s.Validate(v); err != nil {
		return ErrIRInvalid
	}
	id, err := tenancy.ParseID(ir.TenantID)
	if err != nil || id == tenancy.System {
		return ErrIRInvalid
	}
	return nil
}
