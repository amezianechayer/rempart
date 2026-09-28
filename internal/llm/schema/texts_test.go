package schema

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// namedRoot is a strict root whose single required property name has the
// subschema sub, with the given $defs object when defs is not empty.
func namedRoot(name, sub, defs string) string {
	s := `{"type":"object","additionalProperties":false,"required":["` + name + `"],"properties":{"` + name + `":` + sub + `}`
	if defs != "" {
		s += `,"$defs":` + defs
	}
	return s + `}`
}

func mustTexts(t *testing.T, raw string) []string {
	t.Helper()
	texts, err := Texts([]byte(raw))
	if err != nil {
		t.Fatalf("Texts(%s) = %v, want nil", raw, err)
	}
	return texts
}

// TestTextsNamedValues: a value under a named property (const, enum, pattern,
// through items, anyOf, oneOf, $ref) is read with its name, "name: value", and
// a value starting with blanks is also read without them (D8, obligation (aa)).
func TestTextsNamedValues(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"const", namedRoot("api_key", `{"const":"v1"}`, ""), []string{"api_key: v1"}},
		{"enum", namedRoot("api_key", `{"type":"string","enum":["a","b"]}`, ""), []string{"api_key: a", "api_key: b"}},
		{"pattern", namedRoot("api_key", `{"type":"string","pattern":"^abc$"}`, ""), []string{"api_key: ^abc$", "api_key: abc"}},
		{"ref", namedRoot("api_key", `{"$ref":"#/$defs/l"}`, `{"l":{"enum":["x"]}}`), []string{"api_key: x", "l: x"}},
		{"items", namedRoot("api_key", `{"type":"array","items":{"type":"string","enum":["i1"]}}`, ""), []string{"api_key: i1"}},
		{"anyOf", namedRoot("api_key", `{"anyOf":[{"type":"null"},{"const":"o1"}]}`, ""), []string{"api_key: o1"}},
		{"oneOf", namedRoot("api_key", `{"oneOf":[{"type":"null"},{"type":"string","enum":["o2"]}]}`, ""), []string{"api_key: o2"}},
		{"items ref", namedRoot("api_key", `{"type":"array","items":{"$ref":"#/$defs/l"}}`, `{"l":{"const":"r1"}}`), []string{"api_key: r1", "l: r1"}},
		{
			"nested property",
			namedRoot("outer", `{"type":"object","additionalProperties":false,"required":["token"],"properties":{"token":{"const":"t1"}}}`, ""),
			[]string{"token: t1"},
		},
		{"const leading blanks", namedRoot("api_key", `{"const":"\n  v"}`, ""), []string{"api_key: v", "api_key: \n  v"}},
		{
			"description leading newline",
			`{"type":"object","additionalProperties":false,"description":"\nw","properties":{}}`,
			[]string{"description: w", "description: \nw"},
		},
		{
			"const object leading newline",
			namedRoot("x", `{"const":{"api_key":"\nv"}}`, ""),
			[]string{"api_key: v", "api_key: \nv"},
		},
		// witnesses of M0-T19a: every key, every string, "key: value"
		{
			"witnesses",
			namedRoot("api_key", `{"type":"string","description":"d1","enum":["e1"]}`, ""),
			[]string{"api_key", "properties", "type", "string", "type: string", "description: d1", "d1", "e1", "required"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			texts := mustTexts(t, c.raw)
			for _, w := range c.want {
				if !slices.Contains(texts, w) {
					t.Errorf("Texts misses %q; got %q", w, texts)
				}
			}
		})
	}
	t.Run("numeric const", func(t *testing.T) {
		for _, s := range mustTexts(t, namedRoot("api_key", `{"type":"integer","const":1,"enum":[1,2]}`, "")) {
			if strings.HasPrefix(s, "api_key: ") {
				t.Errorf("numeric value read as a named text: %q", s)
			}
		}
	})
	t.Run("root not an object", func(t *testing.T) {
		for _, raw := range []string{`["a",{"$ref":"#/$defs/l"}]`, `"a"`, `1`} {
			if _, err := Texts([]byte(raw)); err != nil && !errors.Is(err, ErrInvalidSchema) {
				t.Errorf("Texts(%s) = %v, want nil or ErrInvalidSchema", raw, err)
			}
		}
	})
	t.Run("ref cycle", func(t *testing.T) {
		defs := `{"a":{"anyOf":[{"$ref":"#/$defs/a"},{"$ref":"#/$defs/a"}]},"b":{"enum":["c1"]}}`
		raw := namedRoot("api_key", `{"anyOf":[{"$ref":"#/$defs/a"},{"$ref":"#/$defs/b"}]}`, defs)
		texts := mustTexts(t, raw)
		if !slices.Contains(texts, "api_key: c1") {
			t.Errorf("Texts misses %q after a cycle; got %q", "api_key: c1", texts)
		}
	})
}

// TestTextsBounded: the number of texts is bounded (at most 65 536), so that a
// schema under MaxSchemaBytes does not fan out without end through $ref (D8).
// Each of fan properties refers to one definition holding an enum of size
// one-character strings: size named pairs per property. The walk stops at the
// bound: a schema of 60 KB that fans out to 8 million pairs is refused without
// building them (allocations bounded).
func TestTextsBounded(t *testing.T) {
	build := func(fan, size int) string {
		enum := strings.TrimSuffix(strings.Repeat(`"a",`, size), ",")
		var props []string
		for i := range fan {
			props = append(props, `"p`+strconv.Itoa(i)+`":{"$ref":"#/$defs/l"}`)
		}
		return `{"type":"object","additionalProperties":false,"properties":{` + strings.Join(props, ",") +
			`},"$defs":{"l":{"enum":[` + enum + `]}}}`
	}
	for _, c := range []struct{ fan, size int }{{8, 10000}, {1100, 7500}} {
		raw := build(c.fan, c.size)
		if len(raw) > MaxSchemaBytes {
			t.Fatalf("test schema is %d bytes, above MaxSchemaBytes: the refusal would not come from the count", len(raw))
		}
		if texts, err := Texts([]byte(raw)); !errors.Is(err, ErrInvalidSchema) || texts != nil {
			t.Errorf("Texts with %d x %d named pairs = %d texts, %v; want ErrInvalidSchema", c.fan, c.size, len(texts), err)
		}
	}
	fanout := []byte(build(1100, 7500))
	if n := testing.AllocsPerRun(1, func() { _, _ = Texts(fanout) }); n > 1<<20 {
		t.Errorf("Texts with 1100 x 7500 named pairs made %.0f allocations, want at most %d: the walk does not stop at the bound", n, 1<<20)
	}
	if texts, err := Texts([]byte(build(1, 10000))); err != nil || len(texts) < 30000 {
		t.Errorf("witness with 1 x 10 000 named pairs = %d texts, %v; want nil and at least 30 000 texts", len(texts), err)
	}
}
