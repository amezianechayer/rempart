package threat

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/amezianechayer/rempart/schemas"
)

// MaxDecodeBytes bounds a document read by DecodeModel or DecodeDelta.
const MaxDecodeBytes = 16 << 20

// ErrDecode: a document outside schemas/threat/v1.json or not strictly JSON.
// Fixed messages: the document is never quoted.
var ErrDecode = errors.New("threat: invalid model or delta document")

// maxDepth bounds the nesting of a document (a model or a delta nests 5 deep).
const maxDepth = 16

// DecodeModel reads a model strictly (ADR 0010 D11).
func DecodeModel(raw []byte) (Model, error) {
	var m Model
	if err := decode(raw, schemas.ThreatModel, &m); err != nil {
		return Model{}, err
	}
	return m, nil
}

// DecodeDelta reads a delta strictly (ADR 0010 D11).
func DecodeDelta(raw []byte) (Delta, error) {
	var d Delta
	if err := decode(raw, schemas.ThreatDelta, &d); err != nil {
		return Delta{}, err
	}
	return d, nil
}

// decode: bounded size, valid UTF-8, one JSON value without duplicate key,
// the schema (which also refuses a key of inexact case), then the structure
// with unknown fields refused.
func decode(raw []byte, schemaPath string, out any) error {
	if len(raw) == 0 || len(raw) > MaxDecodeBytes || !utf8.Valid(raw) {
		return fmt.Errorf("%w: size or encoding", ErrDecode)
	}
	if !singleValueWithoutDuplicates(raw) {
		return fmt.Errorf("%w: duplicate key or not a single value", ErrDecode)
	}
	s, err := schemas.Compile(schemaPath)
	if err != nil {
		return fmt.Errorf("%w: schema unavailable", ErrDecode)
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil || s.Validate(v) != nil {
		return fmt.Errorf("%w: schema", ErrDecode)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("%w: structure", ErrDecode)
	}
	return nil
}

// singleValueWithoutDuplicates walks the tokens of raw: a local copy of the
// check of internal/llm/schema/decode.go (internal/threat does not import
// internal/llm, criterion 3 of M2-T05).
func singleValueWithoutDuplicates(raw []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if !walkValue(dec, 0) {
		return false
	}
	_, err := dec.Token()
	return errors.Is(err, io.EOF)
}

func walkValue(dec *json.Decoder, depth int) bool {
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return true
	}
	if depth >= maxDepth {
		return false
	}
	keys := map[string]bool{}
	for dec.More() {
		if delim == '{' {
			k, err := dec.Token()
			key, isKey := k.(string)
			if err != nil || !isKey || keys[key] {
				return false
			}
			keys[key] = true
		}
		if !walkValue(dec, depth+1) {
			return false
		}
	}
	_, err = dec.Token()
	return err == nil
}
