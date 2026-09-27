package schema

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func wantNotStrict(t *testing.T, s string) {
	t.Helper()
	got, err := CompileSchema([]byte(s))
	if !errors.Is(err, ErrSchemaNotStrict) || got != nil {
		t.Fatalf("CompileSchema = %v, %v; want ErrSchemaNotStrict", got, err)
	}
	if strings.ContainsAny(err.Error(), "\t\r\u00a0\u00d7\u200b\u2028\u202e\ufeff") {
		t.Errorf("error %q quotes a refused character", err)
	}
}

// TestStrictClosedForms: each form admits only its keywords, at any depth (D1, D4).
func TestStrictClosedForms(t *testing.T) {
	obj := func(name string) string {
		return `{"type":"object","additionalProperties":false,"required":["` + name + `"],"properties":{"` + name + `":{"type":"string"}}}`
	}
	rejected := map[string]string{
		"string with properties":    wrap(`{"type":"string","properties":{"a":{"foo":1}}}`),
		"enum with properties":      wrap(`{"enum":["a"],"properties":{"a":{"type":"string"}}}`),
		"object with items":         wrap(`{"type":"object","additionalProperties":false,"items":{"type":"string"}}`),
		"type and anyOf":            wrap(`{"type":"string","anyOf":[{"type":"string"}]}`),
		"anyOf and oneOf":           wrap(`{"anyOf":[{"type":"null"}],"oneOf":[{"type":"null"}]}`),
		"enum and const":            wrap(`{"enum":["a"],"const":"a"}`),
		"sibling inside anyOf":      wrap(`{"anyOf":[{"type":"string","items":{"type":"string"}}]}`),
		"sibling inside defs":       withDefs(`{"$ref":"#/$defs/l"}`, `{"l":{"enum":["a"],"minimum":0}}`),
		"root with items":           `{"type":"object","additionalProperties":false,"items":{"type":"string"}}`,
		"property name with dash":   obj("a-b"),
		"property name non ascii":   obj(`\u00e9`),
		"definition name with dash": withDefs(`{"$ref":"#/$defs/l"}`, `{"l":{"enum":["a"]},"a-b":{"type":"string"}}`),
	}
	accepted := map[string]string{
		"string enum annotated": wrap(`{"type":"string","enum":["a","b"],"title":"t","description":"d"}`),
		"integer bounds const":  wrap(`{"type":"integer","minimum":0,"maximum":3,"const":1}`),
		"ref annotated":         withDefs(`{"$ref":"#/$defs/l","description":"x"}`, `{"l":{"enum":["a"]}}`),
		"property name a_B9":    obj("a_B9"),
	}
	if len(rejected) != 12 || len(accepted) != 4 {
		t.Fatalf("case table: %d rejected, %d accepted; want 12 and 4", len(rejected), len(accepted))
	}
	for name, s := range rejected {
		t.Run(name, func(t *testing.T) { wantNotStrict(t, s) })
	}
	for name, s := range accepted {
		t.Run(name, func(t *testing.T) {
			if _, err := CompileSchema([]byte(s)); err != nil {
				t.Fatalf("CompileSchema = %v, want nil", err)
			}
		})
	}
}

// TestSchemaAdmissionList: every key and string, escapes decoded, is admitted (D3).
func TestSchemaAdmissionList(t *testing.T) {
	for _, s := range []string{
		wrap(`{"type":"string","description":"a\u202eb"}`),
		wrap(`{"type":"string","title":"a\u200bb"}`),
		wrap(`{"type":"string","description":"a\tb"}`),
		wrap(`{"type":"string","description":"a\rb"}`),
		wrap(`{"type":"string","description":"a\u0000b"}`),
		wrap(`{"type":"string","pattern":"a\u00a0b"}`),
		wrap(`{"type":"string","enum":["a\u00d7b"]}`),
		wrap(`{"const":"a\u2028b"}`),
		wrap(`{"enum":[{"a\u202e":1}]}`),
		wrap(`{"type":"string","title":"\ufeffa"}`),
		wrap("{\"type\":\"string\",\"description\":\"a\u202eb\"}"), // interpreted: raw rune at run time
	} {
		wantNotStrict(t, s)
	}
	french := wrap(`{"type":"string","description":"Réponds en français.\nœ Œ Ÿ ÿ À","enum":["é"]}`)
	if _, err := CompileSchema([]byte(french)); err != nil {
		t.Errorf("French text refused: %v", err)
	}
}

// TestAdmittedText: the closed list of D3, rune by rune.
func TestAdmittedText(t *testing.T) {
	admitted := []rune{' ', '~', 'a', 'Z', '0', '\n', 0xC0, 0xD6, 0xD8, 0xF6, 0xF8, 0xFF, 0x152, 0x153, 0x178}
	refused := []rune{
		'\t', '\r', 0x00, 0x1F, 0x7F, 0x80, 0x9F, 0xA0, 0xAD, 0xBF, 0xD7, 0xF7, 0x100, 0x151,
		0x154, 0x177, 0x179, 0x200B, 0x202E, 0x2028, 0xFEFF, 0xFFFD, 0x1F600,
	}
	for _, r := range admitted {
		if !AdmittedText("a" + string(r) + "b") {
			t.Errorf("U+%04X refused", r)
		}
	}
	for _, r := range refused {
		if AdmittedText("a" + string(r) + "b") {
			t.Errorf("U+%04X admitted", r)
		}
	}
	if !AdmittedText("") || AdmittedText("a\xffb") {
		t.Error("empty text refused or invalid UTF-8 admitted")
	}
}

// closedForms is the table of D1 as written in the plan: the keywords of a
// subschema of each form, besides title and description.
var closedForms = map[string][]string{
	"object":  {"type", "properties", "required", "additionalProperties"},
	"array":   {"type", "items", "minItems", "maxItems"},
	"string":  {"type", "minLength", "maxLength", "pattern", "enum", "const"},
	"integer": {"type", "minimum", "maximum", "enum", "const"},
	"number":  {"type", "minimum", "maximum", "enum", "const"},
	"boolean": {"type", "enum", "const"},
	"null":    {"type", "enum", "const"},
	"$ref":    {"$ref"},
	"anyOf":   {"anyOf"},
	"oneOf":   {"oneOf"},
	"enum":    {"enum"},
	"const":   {"const"},
}

// formBase is the smallest strict subschema of each form, as JSON members.
var formBase = map[string]string{
	"object":  `"type":"object","additionalProperties":false`,
	"array":   `"type":"array","items":{"type":"string"}`,
	"string":  `"type":"string"`,
	"integer": `"type":"integer"`,
	"number":  `"type":"number"`,
	"boolean": `"type":"boolean"`,
	"null":    `"type":"null"`,
	"$ref":    `"$ref":"#/$defs/l"`,
	"anyOf":   `"anyOf":[{"type":"string"}]`,
	"oneOf":   `"oneOf":[{"type":"string"}]`,
	"enum":    `"enum":["a"]`,
	"const":   `"const":"a"`,
}

// formScalar is a value of the type of each form, for enum and const.
var formScalar = map[string]string{"integer": `1`, "number": `0.5`, "boolean": `true`, "null": `null`}

// keywordValues gives each keyword of the universe a well-formed value, so
// that a refusal comes from the closed list and not from the meta-schema.
// The form keywords (type, $ref, anyOf, oneOf) are absent: adding one changes
// the form.
var keywordValues = map[string]string{
	"properties": `{}`, "required": `[]`, "additionalProperties": `false`,
	"items": `{"type":"string"}`, "minItems": `0`, "maxItems": `1`,
	"minLength": `0`, "maxLength": `1`, "pattern": `"a"`, "minimum": `0`, "maximum": `1`,
	"enum": ``, "const": ``, "title": `"t"`, "description": `"d"`,
	"$schema": `"https://json-schema.org/draft/2020-12/schema"`, "$defs": `{}`, "definitions": `{}`,
	"allOf": `[{"type":"string"}]`, "not": `{"type":"string"}`, "if": `{"type":"string"}`,
	"then": `{"type":"string"}`, "else": `{"type":"string"}`, "format": `"email"`, "default": `"a"`,
	"examples": `["a"]`, "$id": `"https://rempart.invalid/x"`, "$anchor": `"a"`, "$comment": `"c"`,
	"$dynamicRef": `"#a"`, "$dynamicAnchor": `"a"`, "$vocabulary": `{}`, "prefixItems": `[{"type":"string"}]`,
	"contains": `{"type":"string"}`, "minContains": `0`, "maxContains": `1`, "uniqueItems": `true`,
	"patternProperties": `{}`, "propertyNames": `{"type":"string"}`, "unevaluatedProperties": `false`,
	"unevaluatedItems": `false`, "dependentRequired": `{}`, "dependentSchemas": `{}`, "multipleOf": `1`,
	"exclusiveMinimum": `0`, "exclusiveMaximum": `1`, "minProperties": `0`, "maxProperties": `1`,
	"contentEncoding": `"base64"`, "contentMediaType": `"text/plain"`, "deprecated": `true`,
	"readOnly": `true`, "writeOnly": `true`, "foo": `1`,
}

func keywordValue(form, k string) string {
	scalar, ok := formScalar[form]
	if !ok {
		scalar = `"a"`
	}
	switch k {
	case "enum":
		return "[" + scalar + "]"
	case "const":
		return scalar
	}
	return keywordValues[k]
}

// atProperty places the members of a subschema at property x; a $ref form
// gets its definition.
func atProperty(form, members string) string {
	if form == "$ref" {
		return withDefs("{"+members+"}", `{"l":{"enum":["a"]}}`)
	}
	return wrap("{" + members + "}")
}

// TestStrictFormsExhaustive: for every form, every keyword of its list is
// admitted together, and every other keyword of the universe is refused (D1).
func TestStrictFormsExhaustive(t *testing.T) {
	if len(closedForms) != len(formBase) {
		t.Fatal("form tables differ")
	}
	for form, list := range closedForms {
		members := formBase[form]
		for _, k := range append(slices.Clone(list), "title", "description") {
			if !strings.Contains(members, `"`+k+`":`) {
				members += `,"` + k + `":` + keywordValue(form, k)
			}
		}
		if _, err := CompileSchema([]byte(atProperty(form, members))); err != nil {
			t.Errorf("form %s with all its keywords: %v, want nil", form, err)
		}
		for k := range keywordValues {
			if slices.Contains(list, k) || k == "title" || k == "description" {
				continue
			}
			s := atProperty(form, formBase[form]+`,"`+k+`":`+keywordValue(form, k))
			if got, err := CompileSchema([]byte(s)); !errors.Is(err, ErrSchemaNotStrict) || got != nil {
				t.Errorf("form %s with %s: %v, want ErrSchemaNotStrict", form, k, err)
			}
		}
	}
	root := `{"$schema":"https://json-schema.org/draft/2020-12/schema","$defs":{},"type":"object",` +
		`"properties":{},"required":[],"additionalProperties":false,"title":"t","description":"d"}`
	if _, err := CompileSchema([]byte(root)); err != nil {
		t.Errorf("root with all its keywords: %v, want nil", err)
	}
}

// TestStrictKeywordsAtDepth: $schema and $defs belong to the root only, and a
// sibling is refused at every position where a subschema applies (D1, D2).
func TestStrictKeywordsAtDepth(t *testing.T) {
	positions := map[string]func(sub string) string{
		"property":        func(s string) string { return wrap(s) },
		"array items":     func(s string) string { return wrap(`{"type":"array","items":` + s + `}`) },
		"anyOf item":      func(s string) string { return wrap(`{"anyOf":[{"type":"null"},` + s + `]}`) },
		"oneOf item":      func(s string) string { return wrap(`{"oneOf":[{"type":"null"},` + s + `]}`) },
		"definition":      func(s string) string { return withDefs(`{"$ref":"#/$defs/l"}`, `{"l":`+s+`}`) },
		"nested property": func(s string) string { return wrap(wrap(s)) },
	}
	for name, at := range positions {
		if _, err := CompileSchema([]byte(at(`{"type":"string","minLength":0}`))); err != nil {
			t.Errorf("%s: witness refused: %v", name, err)
		}
		for _, sub := range []string{
			`{"type":"string","minItems":0}`,
			`{"type":"string","$defs":{}}`,
			`{"type":"string","$schema":"https://json-schema.org/draft/2020-12/schema"}`,
			`{"enum":["a"],"type":"string","pattern":"a","items":{"type":"string"}}`,
		} {
			if got, err := CompileSchema([]byte(at(sub))); !errors.Is(err, ErrSchemaNotStrict) || got != nil {
				t.Errorf("%s %s: %v, want ErrSchemaNotStrict", name, sub, err)
			}
		}
	}
}

// admittedOracle is D3 written from the plan, independently of AdmittedText.
func admittedOracle(r rune) bool {
	switch {
	case r == '\n', r >= 0x20 && r <= 0x7E:
		return true
	case r == 0xD7 || r == 0xF7:
		return false
	case r >= 0xC0 && r <= 0xFF:
		return true
	}
	return r == 0x152 || r == 0x153 || r == 0x178
}

// TestEveryCodePointAdmission: every code point, surrogates included, follows D3.
func TestEveryCodePointAdmission(t *testing.T) {
	bad := 0
	for r := rune(0); r <= unicode.MaxRune && bad < 10; r++ {
		want := admittedOracle(r) && utf8.ValidRune(r)
		if got := AdmittedText(string(r)); got != want {
			t.Errorf("AdmittedText(U+%04X) = %v, want %v", r, got, want)
			bad++
		}
	}
}

// TestSchemaRawAdmission: the reviewed bytes are the bytes the model reads.
// A JSON escape other than \", \\ and \n, or a decoded backslash that reads
// as an escape (\\u0041, \\x41), would let a reviewer or a secret
// scanner read another text than the model (a secret hidden behind
// \u0041), and a carriage return or a tab between tokens can hide text on a
// terminal: both are refused, the escape or the byte never quoted (D3, T64).
func TestSchemaRawAdmission(t *testing.T) {
	for _, s := range []string{
		wrap(`{"type":"string","description":"\u0041KIA"}`),
		wrap(`{"type":"string","description":"a\u00e9"}`),
		wrap(`{"type":"string","description":"a/b\/c"}`),
		wrap(`{"type":"string","description":"a\bc"}`),
		wrap(`{"type":"string","description":"a\fc"}`),
		`{"type":"object","additionalProperties":false,"required":["\u0070w"],"properties":{"pw":{"type":"string"}}}`,
		`{"type":"object","additionalProperties":false,"required":["pw"],"properties":{"\u0070w":{"type":"string"}}}`,
		wrap(`{"enum":["\u0041"]}`),
		wrap(`{"type":"string","description":"a\\u0041b"}`),
		wrap(`{"type":"string","description":"a\\x41b"}`),
		wrap(`{"type":"string","description":"a\\U0001F600b"}`),
		wrap(`{"type":"string","description":"a\\x{41}b"}`),
		wrap(`{"type":"string","pattern":"^\\u00e9$"}`),
		wrap(`{"const":"\\\\\\u0041"}`),
		"{\"type\":\"object\",\r\"additionalProperties\":false}",
		"{\"type\":\"object\",\t\"additionalProperties\":false}",
	} {
		wantNotStrict(t, s)
		if _, err := CompileSchema([]byte(s)); err != nil && strings.Contains(err.Error(), "u00") {
			t.Errorf("error %q quotes an escape", err)
		}
	}
	for _, s := range []string{
		wrap(`{"type":"string","description":"say \"hi\", a\\b, line 1\nline 2","pattern":"^a\\.b$"}`),
		"{\"type\":\"object\",\n\"additionalProperties\":false}\n",
		wrap(`{"type":"string","description":"a\\uz, \\xyz, \\d, \\n, \\\\, end \\","pattern":"^\\d+\\.\\w$"}`),
	} {
		if _, err := CompileSchema([]byte(s)); err != nil {
			t.Errorf("CompileSchema(%s) = %v, want nil", s, err)
		}
	}
}

// TestStrictNameLengths: the name patterns of D4 at their length bounds.
func TestStrictNameLengths(t *testing.T) {
	prop := func(name string) string {
		return `{"type":"object","additionalProperties":false,"required":["` + name + `"],"properties":{"` + name + `":{"type":"string"}}}`
	}
	def := func(name string) string {
		return withDefs(`{"$ref":"#/$defs/l"}`, `{"l":{"enum":["a"]},"`+name+`":{"type":"string"}}`)
	}
	for _, s := range []string{prop("a" + strings.Repeat("9", 63)), def(strings.Repeat("_", 64)), prop("A"), def("9")} {
		if _, err := CompileSchema([]byte(s)); err != nil {
			t.Errorf("CompileSchema(%s) = %v, want nil", s, err)
		}
	}
	for _, s := range []string{prop("a" + strings.Repeat("9", 64)), def(strings.Repeat("_", 65)), prop("9a"), prop("_a"), def("")} {
		wantNotStrict(t, s)
	}
}
