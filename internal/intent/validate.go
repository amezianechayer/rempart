package intent

import (
	"bytes"
	"encoding/json"
	"errors"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/amezianechayer/rempart/internal/intent/domain"
	"github.com/amezianechayer/rempart/internal/tenancy"
	"github.com/amezianechayer/rempart/schemas"
)

// ErrIRInvalid: the IR does not match schemas/intent/v1.json or its tenant is
// not a customer tenant. Fixed message.
var ErrIRInvalid = errors.New("intent: invalid IR")

const irResource = "https://rempart.invalid/schemas/intent/v1.json"

type denyLoader struct{}

func (denyLoader) Load(string) (any, error) {
	return nil, errors.New("intent: resource loading is denied")
}

var irSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	raw, err := schemas.FS.ReadFile(schemas.IntentIR)
	if err != nil {
		return nil, err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(denyLoader{})
	if err := c.AddResource(irResource, doc); err != nil {
		return nil, err
	}
	return c.Compile(irResource)
})

// ValidateIR checks ir against schemas/intent/v1.json (plan P1), then its
// tenant with tenancy.ParseID; the system tenant is refused.
func ValidateIR(ir domain.IR) error {
	s, err := irSchema()
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
