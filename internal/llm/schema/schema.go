// Package schema validates LLM outputs against strict JSON Schemas.
package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

var (
	ErrOutOfSchema     = errors.New("llm: output does not match schema")
	ErrSchemaNotStrict = errors.New("llm: schema is not strict")
	ErrInvalidSchema   = errors.New("llm: invalid schema")
	errLoadDenied      = errors.New("schema: resource loading is denied")
)

const (
	MaxOutputBytes = 256 << 10
	MaxSchemaBytes = 64 << 10
	MaxDepth       = 32
	MaxNumberLen   = 40
	maxSegments    = 16
	resourceURL    = "https://rempart.invalid/llm/output.schema.json"
)

var keywordPattern = regexp.MustCompile(`^[A-Za-z$]{1,32}$`)

type Schema struct {
	raw      []byte
	names    map[string]bool
	compiled *jsonschema.Schema
}

type denyLoader struct{}

func (denyLoader) Load(string) (any, error) { return nil, errLoadDenied }

func CompileSchema(raw json.RawMessage) (*Schema, error) {
	if len(raw) > MaxSchemaBytes {
		return nil, fmt.Errorf("%w: too large", ErrInvalidSchema)
	}
	doc, reason := decodeStrict(raw)
	if reason != "" {
		return nil, fmt.Errorf("%w: %s", ErrInvalidSchema, reason)
	}
	names, err := checkStrict(doc)
	if err != nil {
		return nil, err
	}
	compiled, err := compileDoc(doc)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSchema, err)
	}
	return &Schema{raw: bytes.Clone(raw), names: names, compiled: compiled}, nil
}

func compileDoc(doc any) (*jsonschema.Schema, error) {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(denyLoader{})
	if err := c.AddResource(resourceURL, doc); err != nil {
		return nil, err
	}
	return c.Compile(resourceURL)
}

func (s *Schema) Validate(output json.RawMessage) error {
	if s == nil || s.compiled == nil {
		return fmt.Errorf("%w: no schema", ErrOutOfSchema)
	}
	if len(output) > MaxOutputBytes {
		return fmt.Errorf("%w: output too large", ErrOutOfSchema)
	}
	v, reason := decodeStrict(output)
	if reason != "" {
		return fmt.Errorf("%w: %s", ErrOutOfSchema, reason)
	}
	err := s.compiled.Validate(v)
	if err == nil {
		return nil
	}
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return fmt.Errorf("%w: validation failed", ErrOutOfSchema)
	}
	return fmt.Errorf("%w: %s", ErrOutOfSchema, describe(ve, s.names))
}

func (s *Schema) Raw() json.RawMessage {
	if s == nil {
		return nil
	}
	return bytes.Clone(s.raw)
}

func describe(ve *jsonschema.ValidationError, names map[string]bool) string {
	var leaves []string
	var walk func(e *jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		for _, c := range e.Causes {
			walk(c)
		}
		if len(e.Causes) > 0 {
			return
		}
		kw := "?"
		if e.ErrorKind != nil {
			if p := e.ErrorKind.KeywordPath(); len(p) > 0 && keywordPattern.MatchString(p[len(p)-1]) {
				kw = p[len(p)-1]
			}
		}
		leaves = append(leaves, "keyword "+kw+" at "+pointer(e.InstanceLocation, names))
	}
	walk(ve)
	slices.Sort(leaves)
	return leaves[0]
}

func pointer(location []string, names map[string]bool) string {
	segs := make([]string, 0, maxSegments+1)
	for i, s := range location {
		if i == maxSegments {
			segs = append(segs, "*")
			break
		}
		if !isIndex(s) && !names[s] {
			s = "*"
		}
		segs = append(segs, s)
	}
	return "/" + strings.Join(segs, "/")
}

func isIndex(s string) bool {
	return s != "" && len(s) <= 10 && strings.Trim(s, "0123456789") == ""
}
