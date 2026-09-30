// Package schemas embeds the versioned JSON Schemas of Rempart.
package schemas

import (
	"bytes"
	"embed"
	"errors"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// FS holds the schemas, read-only, compiled into the binary.
//
//go:embed intent/v1.json intent/draft-v1.json graph/v1.json
var FS embed.FS

// Paths of the schemas inside FS.
const (
	IntentIR    = "intent/v1.json"
	IntentDraft = "intent/draft-v1.json"
	Graph       = "graph/v1.json"
)

// ErrUnknownSchema: the path is not one of the embedded schemas.
var ErrUnknownSchema = errors.New("schemas: unknown schema")

const resourceBase = "https://rempart.invalid/schemas/"

type denyLoader struct{}

func (denyLoader) Load(string) (any, error) {
	return nil, errors.New("schemas: resource loading is denied")
}

// compiled holds one lazy compilation per embedded schema. The map is never
// written after package initialization.
var compiled = map[string]func() (*jsonschema.Schema, error){
	IntentIR:    sync.OnceValues(func() (*jsonschema.Schema, error) { return compile(IntentIR) }),
	IntentDraft: sync.OnceValues(func() (*jsonschema.Schema, error) { return compile(IntentDraft) }),
	Graph:       sync.OnceValues(func() (*jsonschema.Schema, error) { return compile(Graph) }),
}

// Compile compiles an embedded schema (Draft 2020-12, loader that denies any
// access), once per path. Used by intent.ValidateIR and graph.ValidateSchema.
func Compile(path string) (*jsonschema.Schema, error) {
	f, ok := compiled[path]
	if !ok {
		return nil, ErrUnknownSchema
	}
	return f()
}

func compile(path string) (*jsonschema.Schema, error) {
	raw, err := FS.ReadFile(path)
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
	if err := c.AddResource(resourceBase+path, doc); err != nil {
		return nil, err
	}
	return c.Compile(resourceBase + path)
}
