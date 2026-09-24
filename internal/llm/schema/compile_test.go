package schema

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// fixtureSchema is F of docs/plans/M0-llm-schema-prompts.md section 5.6, copied
// as is from internal/llm/prompts/testdata/fixture.v1/schema.json.
const fixtureSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object", "additionalProperties": false, "required": ["count", "greeting", "tags"],
  "properties": {
    "greeting": {"type": "string", "minLength": 1, "maxLength": 200},
    "count": {"anyOf": [{"type": "integer", "minimum": 0}, {"type": "null"}]},
    "tags": {"type": "array", "maxItems": 5, "items": {
      "type": "object", "additionalProperties": false, "required": ["key", "level"],
      "properties": {"key": {"type": "string", "pattern": "^[a-z]+$"}, "level": {"$ref": "#/$defs/level"}}}}
  },
  "$defs": {"level": {"enum": ["low", "medium", "high"]}}
}
`

// strictRoot is the smallest strict schema.
const strictRoot = `{"type":"object","additionalProperties":false}`

// wrap is R(p): a strict root object whose single required property x has
// the subschema p.
func wrap(p string) string {
	return `{"type":"object","additionalProperties":false,"required":["x"],"properties":{"x":` + p + `}}`
}

// withDefs is a strict root whose single property x has the subschema p, with
// the given $defs object.
func withDefs(p, defs string) string {
	return `{"type":"object","additionalProperties":false,"required":["x"],"properties":{"x":` + p + `},"$defs":` + defs + `}`
}

// nested is E_k: k nested JSON arrays.
func nested(k int) string {
	return strings.Repeat("[", k) + strings.Repeat("]", k)
}

// pad completes x with spaces up to n bytes.
func pad(x string, n int) string {
	if len(x) > n {
		panic("pad: input longer than target")
	}
	return x + strings.Repeat(" ", n-len(x))
}

func requireUniqueNames(t *testing.T, names []string) {
	t.Helper()
	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] {
			t.Fatalf("duplicate case name %q", n)
		}
		seen[n] = true
	}
}

type compileCase struct {
	name, schema string
}

// strictAccepted are schemas CompileSchema must accept.
func strictAccepted() []compileCase {
	return []compileCase{
		{"fixture", fixtureSchema},
		{"no_schema_keyword", `{"type":"object","additionalProperties":false,"required":["a"],"properties":{"a":{"type":"string"}}}`},
		{"object_without_properties", strictRoot},
		{"nullable_string", wrap(`{"anyOf":[{"type":"string"},{"type":"null"}]}`)},
		{"anyof_strict_objects", wrap(`{"anyOf":[` +
			`{"type":"object","additionalProperties":false,"required":["a"],"properties":{"a":{"type":"string"}}},` +
			`{"type":"object","additionalProperties":false,"required":["b"],"properties":{"b":{"type":"integer"}}}]}`)},
		{"depth_32", wrap(`{"enum":` + nested(29) + `}`)},
		{"max_size", pad(fixtureSchema, MaxSchemaBytes)},
	}
}

// strictRejected are schemas that are valid JSON but not strict.
func strictRejected() []compileCase {
	const levelDefs = `{"level":{"enum":["low","high"]}}`
	return []compileCase{
		{"not_an_object", `[]`},
		{"root_type_array", `{"type":"array","items":{"type":"string"}}`},
		{"root_type_missing", `{"additionalProperties":false,"required":["a"],"properties":{"a":{"type":"string"}}}`},
		{"root_ap_missing", `{"type":"object","required":["a"],"properties":{"a":{"type":"string"}}}`},
		{"root_ap_true", `{"type":"object","additionalProperties":true,"required":["a"],"properties":{"a":{"type":"string"}}}`},
		{"root_ap_schema", `{"type":"object","additionalProperties":{"type":"string"},"required":["a"],"properties":{"a":{"type":"string"}}}`},
		{"nested_ap_missing", wrap(`{"type":"object","required":["a"],"properties":{"a":{"type":"string"}}}`)},
		{"items_ap_missing", wrap(`{"type":"array","items":{"type":"object","required":["a"],"properties":{"a":{"type":"string"}}}}`)},
		{"defs_ap_missing", withDefs(`{"$ref":"#/$defs/o"}`, `{"o":{"type":"object","required":["a"],"properties":{"a":{"type":"string"}}}}`)},
		{"anyof_ap_missing", wrap(`{"anyOf":[{"type":"object","required":["a"],"properties":{"a":{"type":"string"}}},{"type":"null"}]}`)},
		{"oneof_ap_missing", wrap(`{"oneOf":[{"type":"null"},{"type":"object","required":["a"],"properties":{"a":{"type":"string"}}}]}`)},
		{"required_incomplete", `{"type":"object","additionalProperties":false,"required":["a"],"properties":{"a":{"type":"string"},"b":{"type":"string"}}}`},
		{"required_unknown", `{"type":"object","additionalProperties":false,"required":["a","c"],"properties":{"a":{"type":"string"}}}`},
		{"required_duplicate", `{"type":"object","additionalProperties":false,"required":["a","a"],"properties":{"a":{"type":"string"}}}`},
		{"type_list", wrap(`{"type":["string","null"]}`)},
		{"type_list_with_object", wrap(`{"type":["object","null"],"additionalProperties":false,"required":[],"properties":{}}`)},
		{"unknown_type", wrap(`{"type":"text"}`)},
		{"boolean_true", wrap(`true`)},
		{"boolean_items", wrap(`{"type":"array","items":true}`)},
		{"empty_subschema", wrap(`{}`)},
		{"array_without_items", wrap(`{"type":"array"}`)},
		{"draft_07", `{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","additionalProperties":false}`},
		{"schema_uri_fragment", `{"$schema":"https://json-schema.org/draft/2020-12/schema#","type":"object","additionalProperties":false}`},
		{"external_ref_https", wrap(`{"$ref":"https://example.invalid/other.schema.json"}`)},
		{"external_ref_file", wrap(`{"$ref":"file:///tmp/other.schema.json"}`)},
		{"external_ref_local_fragment", withDefs(`{"$ref":"https://rempart.invalid/o.json#/$defs/level"}`, levelDefs)},
		{"relative_ref", withDefs(`{"$ref":"other.json#/$defs/level"}`, levelDefs)},
		{"ref_to_properties", `{"type":"object","additionalProperties":false,"required":["x","y"],` +
			`"properties":{"x":{"$ref":"#/properties/y"},"y":{"type":"string"}}}`},
		{"ref_missing_def", withDefs(`{"$ref":"#/$defs/absent"}`, levelDefs)},
		{"ref_inside_defs", withDefs(`{"$ref":"#/$defs/a"}`, `{"a":{"$ref":"#/$defs/b"},"b":{"type":"string"}}`)},
		{"ref_with_sibling_type", withDefs(`{"$ref":"#/$defs/level","type":"string"}`, levelDefs)},
		{"defs_below_root", wrap(`{"type":"object","additionalProperties":false,"$defs":{"a":{"type":"string"}}}`)},
		{"keyword_id", `{"$id":"https://rempart.invalid/s.json","type":"object","additionalProperties":false}`},
		{"keyword_anchor", wrap(`{"type":"string","$anchor":"a"}`)},
		{"keyword_dynamic_ref", wrap(`{"type":"string","$dynamicRef":"#a"}`)},
		{"allof", wrap(`{"type":"string","allOf":[{"minLength":1}]}`)},
		{"not", wrap(`{"type":"string","not":{"const":"a"}}`)},
		{"if_then", wrap(`{"type":"string","if":{"const":"a"},"then":{"minLength":2}}`)},
		{"pattern_properties", wrap(`{"type":"object","additionalProperties":false,"patternProperties":{"^a":{"type":"string"}}}`)},
		{"unevaluated_properties", wrap(`{"type":"object","additionalProperties":false,"unevaluatedProperties":false}`)},
		{"format", wrap(`{"type":"string","format":"email"}`)},
	}
}

// Test 1 (task sheet): only strict schemas compile; every permissive or
// externally referencing schema is refused with ErrSchemaNotStrict.
func TestCompileSchemaRequiresStrict(t *testing.T) {
	accepted, rejected := strictAccepted(), strictRejected()
	if len(accepted) != 7 || len(rejected) != 41 {
		t.Fatalf("case table: %d accepted, %d rejected, want 7 and 41", len(accepted), len(rejected))
	}
	var names []string
	for _, tc := range append(accepted, rejected...) {
		names = append(names, tc.name)
	}
	requireUniqueNames(t, names)

	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			s, err := CompileSchema([]byte(tc.schema))
			if err != nil {
				t.Fatalf("CompileSchema(%s) = %v, want nil", tc.name, err)
			}
			if s == nil {
				t.Fatalf("CompileSchema(%s) returned a nil schema without error", tc.name)
			}
		})
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			s, err := CompileSchema([]byte(tc.schema))
			if !errors.Is(err, ErrSchemaNotStrict) {
				t.Fatalf("CompileSchema(%s) error = %v, want ErrSchemaNotStrict", tc.name, err)
			}
			if s != nil {
				t.Errorf("CompileSchema(%s) returned a schema with an error", tc.name)
			}
		})
	}
}

// Test 2: malformed, oversized or meta-invalid schemas are refused with
// ErrInvalidSchema.
func TestCompileSchemaRejectsInvalid(t *testing.T) {
	cases := []compileCase{
		{"not_json", `{"type":`},
		{"empty", ``},
		{"trailing_data", strictRoot + ` trailing`},
		{"two_values", strictRoot + strictRoot},
		{"duplicate_key", `{"type":"object","type":"object","additionalProperties":false}`},
		{"invalid_utf8", `{"type":"object","additionalProperties":false,"title":"a` + "\xff" + `"}`},
		{"too_large", pad(fixtureSchema, MaxSchemaBytes+1)},
		{"exponent", wrap(`{"type":"string","maxLength":1e2}`)},
		{"too_deep", wrap(`{"enum":` + nested(30) + `}`)},
		{"meta_invalid", wrap(`{"type":"string","minLength":-1}`)},
		{"invalid_pattern", wrap(`{"type":"string","pattern":"("}`)},
	}
	if len(cases) != 11 {
		t.Fatalf("case table: %d cases, want 11", len(cases))
	}
	var names []string
	for _, tc := range cases {
		names = append(names, tc.name)
	}
	requireUniqueNames(t, names)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := CompileSchema([]byte(tc.schema))
			if !errors.Is(err, ErrInvalidSchema) {
				t.Fatalf("CompileSchema(%s) error = %v, want ErrInvalidSchema", tc.name, err)
			}
			if s != nil {
				t.Errorf("CompileSchema(%s) returned a schema with an error", tc.name)
			}
		})
	}
}

func mustDecode(t *testing.T, src string) any {
	t.Helper()
	v, reason := decodeStrict([]byte(src))
	if reason != "" {
		t.Fatalf("decodeStrict(%q) failed: %s", src, reason)
	}
	return v
}

// Test 3: the compiler never loads a resource. A witness compiler with the
// library's default loader resolves a file:// reference to a readable local
// schema; compileDoc refuses the same document, and a remote reference.
func TestCompilerNeverLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "local.schema.json")
	if err := os.WriteFile(path, []byte(`{"type":"string"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	fileRef := wrap(`{"$ref":"file://` + filepath.ToSlash(path) + `"}`)

	witness := jsonschema.NewCompiler()
	witness.DefaultDraft(jsonschema.Draft2020)
	const witnessURL = "https://rempart.invalid/witness.schema.json"
	if err := witness.AddResource(witnessURL, mustDecode(t, fileRef)); err != nil {
		t.Fatalf("witness AddResource: %v", err)
	}
	if _, err := witness.Compile(witnessURL); err != nil {
		t.Fatalf("witness compiler with the default loader must resolve the local file, got %v", err)
	}

	if _, err := compileDoc(mustDecode(t, fileRef)); err == nil {
		t.Error("compileDoc loaded a local file:// reference, want an error")
	}
	if _, err := compileDoc(mustDecode(t, wrap(`{"$ref":"https://rempart.invalid/x.json"}`))); err == nil {
		t.Error("compileDoc accepted a remote https reference, want an error")
	}
	if _, err := compileDoc(mustDecode(t, fixtureSchema)); err != nil {
		t.Errorf("compileDoc(F) = %v, want nil", err)
	}
}

// Test 9: the three exported sentinels are distinct and prefixed "llm: ".
func TestSchemaSentinels(t *testing.T) {
	sentinels := []error{ErrOutOfSchema, ErrSchemaNotStrict, ErrInvalidSchema}
	for i, a := range sentinels {
		if a == nil {
			t.Fatalf("sentinel %d is nil", i)
		}
		if !strings.HasPrefix(a.Error(), "llm: ") {
			t.Errorf("sentinel %q lacks the prefix %q", a.Error(), "llm: ")
		}
		for j, b := range sentinels {
			if i != j && (errors.Is(a, b) || a.Error() == b.Error()) {
				t.Errorf("sentinels %q and %q are not distinct", a.Error(), b.Error())
			}
		}
	}
}
