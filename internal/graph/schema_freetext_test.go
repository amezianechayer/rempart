package graph_test

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/amezianechayer/rempart/schemas"
)

// knownKeywords are the JSON Schema keywords the walk understands. Any other
// keyword fails the test: a subschema hidden under an unwalked keyword (for
// example patternProperties or $dynamicRef) never escapes the check.
var knownKeywords = map[string]bool{
	"$schema": true, "$id": true, "$ref": true, "$defs": true, "$comment": true,
	"title": true, "description": true, "default": true,
	"type": true, "const": true, "enum": true, "pattern": true,
	"minLength": true, "maxLength": true, "minimum": true, "maximum": true,
	"minItems": true, "maxItems": true, "uniqueItems": true,
	"properties": true, "required": true, "additionalProperties": true, "items": true,
	"allOf": true, "anyOf": true, "oneOf": true, "not": true, "if": true, "then": true, "else": true,
}

const freeTextRef = "#/$defs/free_text"

// p9Fields are the four free text values of plan P9.
var p9Fields = []string{"justification", "notes", "purpose", "summary"}

type walker struct {
	t           *testing.T
	strings     int      // string subschemas seen
	freeTextAt  []string // fields referencing $defs/free_text
	rootSummary bool
}

func (w *walker) schema(v any, path []string, conditional bool) {
	w.t.Helper()
	at := "/" + strings.Join(path, "/")
	n, ok := v.(map[string]any)
	if !ok {
		if _, isBool := v.(bool); isBool {
			w.t.Errorf("%s: boolean schema (accepts anything)", at)
			return
		}
		w.t.Errorf("%s: schema is %T, not an object", at, v)
		return
	}
	for k := range n {
		if !knownKeywords[k] {
			w.t.Errorf("%s: keyword %q unknown to the walk", at, k)
		}
	}
	isFreeTextDef := at == "/$defs/free_text"
	if isString(n["type"]) {
		w.strings++
		_, hasEnum := n["enum"]
		_, hasConst := n["const"]
		_, hasPattern := n["pattern"]
		if !hasEnum && !hasConst && !hasPattern && !isFreeTextDef {
			w.t.Errorf("%s: string without enum, const or pattern (free text must use %s)", at, freeTextRef)
		}
	}
	if isFreeTextDef {
		ml, ok := n["maxLength"].(float64)
		if n["type"] != "string" || !ok || ml <= 0 || ml > 500 {
			w.t.Errorf("%s: want type string and 0 < maxLength <= 500, got %v", at, n)
		}
	}
	if ref, ok := n["$ref"]; ok {
		if ref == freeTextRef {
			l := len(path)
			if l < 4 || path[l-2] != "properties" || path[l-3] != "untrusted_text" || path[l-4] != "properties" {
				w.t.Errorf("%s: %s outside a property of an untrusted_text object", at, freeTextRef)
			} else {
				w.freeTextAt = append(w.freeTextAt, path[l-1])
				if l == 4 && path[l-1] == "summary" {
					w.rootSummary = true
				}
			}
		} else if s, isStr := ref.(string); !isStr || !strings.HasPrefix(s, "#/$defs/") {
			w.t.Errorf("%s: $ref %v is not a local definition", at, ref)
		}
	}
	_, hasProps := n["properties"]
	if n["type"] == "object" || (hasProps && !conditional) {
		if n["type"] != "object" {
			w.t.Errorf("%s: object schema without type object", at)
		}
		if ap, present := n["additionalProperties"]; !present || ap != false {
			w.t.Errorf("%s: additionalProperties must be false, got %v", at, ap)
		}
	}
	for _, k := range []string{"properties", "$defs"} {
		if m, ok := n[k].(map[string]any); ok {
			for name, sub := range m {
				w.schema(sub, append(slices.Clone(path), k, name), conditional)
			}
		}
	}
	for _, k := range []string{"items", "not"} {
		if sub, ok := n[k]; ok {
			w.schema(sub, append(slices.Clone(path), k), conditional)
		}
	}
	for _, k := range []string{"if", "then", "else"} {
		if sub, ok := n[k]; ok {
			w.schema(sub, append(slices.Clone(path), k), true)
		}
	}
	for _, k := range []string{"allOf", "anyOf", "oneOf"} {
		if list, ok := n[k].([]any); ok {
			for i, sub := range list {
				w.schema(sub, append(slices.Clone(path), k, strconv.Itoa(i)), true)
			}
		}
	}
	if sub, ok := n["additionalProperties"].(map[string]any); ok {
		w.schema(sub, append(slices.Clone(path), "additionalProperties"), conditional)
	}
}

func isString(typ any) bool {
	switch x := typ.(type) {
	case string:
		return x == "string"
	case []any:
		return slices.Contains(x, any("string"))
	}
	return false
}

// TestGraphSchemaMarksFreeText proves the guard of prompts/M1.md and plan P9:
// in schemas/graph/v1.json, every string is closed (enum, const, pattern)
// except $defs/free_text, bounded, and referenced only from untrusted_text.
func TestGraphSchemaMarksFreeText(t *testing.T) {
	raw, err := schemas.FS.ReadFile(schemas.Graph)
	if err != nil {
		t.Fatalf("read %s: %v", schemas.Graph, err)
	}
	if _, err := schemas.Compile(schemas.Graph); err != nil {
		t.Fatalf("Compile(%s): %v", schemas.Graph, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc["additionalProperties"] != false {
		t.Errorf("root additionalProperties = %v, want false", doc["additionalProperties"])
	}
	w := &walker{t: t}
	w.schema(doc, nil, false)

	if w.strings < 5 {
		t.Errorf("only %d string subschemas walked: the walk did not reach the schema", w.strings)
	}
	if !w.rootSummary {
		t.Errorf("root untrusted_text.summary does not reference %s", freeTextRef)
	}
	seen := slices.Compact(slices.Sorted(slices.Values(w.freeTextAt)))
	if !slices.Equal(seen, p9Fields) {
		t.Errorf("fields referencing %s: %v, want exactly %v (plan P9)", freeTextRef, seen, p9Fields)
	}
}
