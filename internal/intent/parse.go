package intent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/amezianechayer/rempart/internal/intent/domain"
	"github.com/amezianechayer/rempart/internal/llm/schema"
	"github.com/amezianechayer/rempart/schemas"
)

// ErrDraftInvalid: the model output is not a valid draft. Fixed message.
var ErrDraftInvalid = errors.New("intent: invalid draft")

var draftSchema = sync.OnceValues(func() (*schema.Schema, error) {
	raw, err := schemas.FS.ReadFile(schemas.IntentDraft)
	if err != nil {
		return nil, err
	}
	return schema.CompileSchema(raw)
})

// ParseDraft decodes the model output strictly (plan P2): strict JSON, no
// tenant key at any depth, strict draft schema, unknown fields refused.
func ParseDraft(raw []byte) (domain.Draft, error) {
	tree, err := schema.DecodeStrict(raw)
	if err != nil {
		return domain.Draft{}, ErrDraftInvalid
	}
	if _, found := domain.TenantKeyPath(tree); found {
		return domain.Draft{}, fmt.Errorf("%w", domain.ErrTenantFromModel)
	}
	s, err := draftSchema()
	if err != nil {
		return domain.Draft{}, fmt.Errorf("%w: schema unavailable", ErrDraftInvalid)
	}
	if err := s.Validate(raw); err != nil {
		return domain.Draft{}, ErrDraftInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var d domain.Draft
	if err := dec.Decode(&d); err != nil {
		return domain.Draft{}, ErrDraftInvalid
	}
	return d, nil
}

// MaxIRBytes bounds the size of a serialized IR read by ParseIR (threat T10).
const MaxIRBytes = 1 << 20

// ParseIR decodes a serialized IR strictly (at most MaxIRBytes, duplicate keys
// and excessive depth refused, unknown fields refused), then validates it with
// ValidateIR. Every failure returns ErrIRInvalid, whose message quotes nothing.
func ParseIR(raw []byte) (domain.IR, error) {
	if len(raw) > MaxIRBytes {
		return domain.IR{}, ErrIRInvalid
	}
	if _, err := schema.DecodeStrict(raw); err != nil {
		return domain.IR{}, ErrIRInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var ir domain.IR
	if err := dec.Decode(&ir); err != nil {
		return domain.IR{}, ErrIRInvalid
	}
	if err := ValidateIR(ir); err != nil {
		return domain.IR{}, ErrIRInvalid
	}
	return ir, nil
}
