package opa

import (
	"encoding/json"
	"slices"

	"github.com/open-policy-agent/opa/v1/ast"
)

// allowedBuiltins is the closed list of pure, deterministic builtins of ADR
// 0011 D3 (and object.union, for the fixtures of the Rego tests checked by
// opa check). A builtin is added by review of this list and of
// capabilities.json (CODEOWNERS, D9).
var allowedBuiltins = []string{
	"abs", "and", "array.concat", "array.slice", "assign", "concat", "contains", "count", "div", "endswith",
	"eq", "equal", "gt", "gte", "internal.member_2", "internal.member_3", "intersection", "is_array",
	"is_boolean", "is_null", "is_number", "is_object", "is_set", "is_string", "lt", "lte", "max", "min",
	"minus", "mul", "neq", "object.get", "object.keys", "object.union", "or", "plus", "rego.metadata.rule",
	"rem", "sort", "startswith", "sum", "type_name", "union",
}

// capabilities returns the capabilities of this OPA version restricted to
// allowedBuiltins, with no network host.
func capabilities() *ast.Capabilities {
	c := ast.CapabilitiesForThisVersion()
	kept := make([]*ast.Builtin, 0, len(allowedBuiltins))
	for _, b := range c.Builtins {
		if slices.Contains(allowedBuiltins, b.Name) {
			kept = append(kept, b)
		}
	}
	c.Builtins = kept
	c.AllowNet = []string{}
	return c
}

// capabilitiesJSON is capabilities.json, read by opa check in make opa-test.
func capabilitiesJSON() ([]byte, error) {
	raw, err := json.MarshalIndent(capabilities(), "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}
