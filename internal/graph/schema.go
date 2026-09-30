package graph

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/amezianechayer/rempart/internal/graph/domain"
	"github.com/amezianechayer/rempart/schemas"
)

// ErrGraphInvalid: the graph does not match schemas/graph/v1.json or breaks a
// structural invariant. Fixed message.
var ErrGraphInvalid = errors.New("graph: invalid graph")

// ValidateSchema checks g against schemas/graph/v1.json, then domain.Validate.
func ValidateSchema(g domain.Graph) error {
	s, err := schemas.Compile(schemas.Graph)
	if err != nil {
		return fmt.Errorf("%w: schema unavailable", ErrGraphInvalid)
	}
	raw, err := json.Marshal(g)
	if err != nil {
		return fmt.Errorf("%w: encoding", ErrGraphInvalid)
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("%w: encoding", ErrGraphInvalid)
	}
	if err := s.Validate(v); err != nil {
		return fmt.Errorf("%w: schema", ErrGraphInvalid)
	}
	if err := domain.Validate(g); err != nil {
		return fmt.Errorf("%w: %w", ErrGraphInvalid, err)
	}
	return nil
}
