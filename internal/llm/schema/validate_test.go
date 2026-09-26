package schema

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const (
	outPrefix = "llm: output does not match schema: "
	minOutput = `{"greeting":"a","count":null,"tags":[]}`
	fullOut   = `{"greeting":"Bonjour","count":3,"tags":[{"key":"env","level":"low"}]}`
)

func compileFixture(t *testing.T) *Schema {
	t.Helper()
	s, err := CompileSchema([]byte(fixtureSchema))
	if err != nil {
		t.Fatalf("CompileSchema(F) = %v", err)
	}
	return s
}

// withGreeting is MIN with the raw JSON value v as greeting.
func withGreeting(v string) string {
	return `{"greeting":` + v + `,"count":null,"tags":[]}`
}

// withCount is MIN with the raw JSON value v as count.
func withCount(v string) string {
	return `{"greeting":"a","count":` + v + `,"tags":[]}`
}

// withTags is MIN with the raw JSON array v as tags.
func withTags(v string) string {
	return `{"greeting":"a","count":null,"tags":` + v + `}`
}

// Test 4 (task sheet): conforming outputs of F are accepted.
func TestValidateAcceptsConforming(t *testing.T) {
	s := compileFixture(t)
	cases := []struct{ name, out string }{
		{"minimal", minOutput},
		{"full", fullOut},
		{"whitespace_around", "\n\t " + fullOut + " \r\n"},
		{"key_order", `{"tags":[{"level":"high","key":"db"}],"count":7,"greeting":"x"}`},
		{"unicode", withGreeting(`"Grüße, 你好, café"`)},
		{"escapes", withGreeting(`"line\nnext \"quoted\" é \\ \/"`)},
		{"number_40_digits", withCount(`1234567890123456789012345678901234567890`)},
		{"zero_count", withCount(`0`)},
		{"exactly_max_bytes", pad(minOutput, MaxOutputBytes)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.Validate([]byte(tc.out)); err != nil {
				t.Fatalf("Validate(%s) = %v, want nil", tc.name, err)
			}
		})
	}
}

type target int

const (
	fixtureTarget target = iota
	nilTarget
	zeroTarget
)

type rejectCase struct {
	name   string
	target target
	out    string
	want   string // suffix after outPrefix
}

func rejectCases() []rejectCase {
	sixTags := `[` + strings.Repeat(`{"key":"a","level":"low"},`, 5) + `{"key":"a","level":"low"}]`
	return []rejectCase{
		{"missing_required", fixtureTarget, `{"greeting":"a","count":null}`, "keyword required at /"},
		{"extra_field", fixtureTarget, `{"greeting":"a","count":null,"tags":[],"extra":1}`, "keyword additionalProperties at /"},
		{"nested_extra_field", fixtureTarget, withTags(`[{"key":"a","level":"low","extra":1}]`), "keyword additionalProperties at /tags/0"},
		{"wrong_type", fixtureTarget, withGreeting(`5`), "keyword type at /greeting"},
		{"null_for_string", fixtureTarget, withGreeting(`null`), "keyword type at /greeting"},
		{"depth_32", fixtureTarget, withGreeting(nested(31)), "keyword type at /greeting"},
		{"enum_mismatch", fixtureTarget, withTags(`[{"key":"a","level":"extreme"}]`), "keyword enum at /tags/0/level"},
		{"pattern_mismatch", fixtureTarget, withTags(`[{"key":"Upper","level":"low"}]`), "keyword pattern at /tags/0/key"},
		{"too_many_items", fixtureTarget, withTags(sixTags), "keyword maxItems at /tags"},
		{"empty_greeting", fixtureTarget, withGreeting(`""`), "keyword minLength at /greeting"},
		{"negative_count", fixtureTarget, withCount(`-1`), "keyword minimum at /count"},
		{"float_count", fixtureTarget, withCount(`1.5`), "keyword type at /count"},
		{"top_level_array", fixtureTarget, `[]`, "keyword type at /"},
		{"top_level_string", fixtureTarget, `"a"`, "keyword type at /"},
		{"top_level_null", fixtureTarget, `null`, "keyword type at /"},
		{"not_json", fixtureTarget, `{"greeting":`, "not a single JSON value"},
		{"empty", fixtureTarget, ``, "not a single JSON value"},
		{"whitespace_only", fixtureTarget, " \n\t ", "not a single JSON value"},
		{"json_then_text", fixtureTarget, minOutput + ` done`, "not a single JSON value"},
		{"two_values", fixtureTarget, minOutput + minOutput, "not a single JSON value"},
		{"markdown_fence", fixtureTarget, "```json\n" + minOutput + "\n```", "not a single JSON value"},
		{"trailing_comma", fixtureTarget, `{"greeting":"a","count":null,"tags":[],}`, "not a single JSON value"},
		{"single_quotes", fixtureTarget, `{'greeting':'a','count':null,'tags':[]}`, "not a single JSON value"},
		{"nan", fixtureTarget, withCount(`NaN`), "not a single JSON value"},
		{"duplicate_key", fixtureTarget, `{"greeting":"a","greeting":"b","count":null,"tags":[]}`, "duplicate object key"},
		{"duplicate_key_escaped", fixtureTarget, `{"greeting":"a","greeting":"b","count":null,"tags":[]}`, "duplicate object key"},
		{"invalid_utf8", fixtureTarget, withGreeting(`"a` + "\xff" + `"`), "invalid UTF-8"},
		{"too_large", fixtureTarget, pad(minOutput, MaxOutputBytes+1), "output too large"},
		{"too_deep", fixtureTarget, withGreeting(nested(32)), "nesting too deep"},
		{"exponent", fixtureTarget, withCount(`1e2`), "number too long or in exponent form"},
		{"long_number", fixtureTarget, withCount(`12345678901234567890123456789012345678901`), "number too long or in exponent form"},
		{"nil_schema", nilTarget, minOutput, "no schema"},
		{"zero_schema", zeroTarget, minOutput, "no schema"},
	}
}

// Test 5 (task sheet): out-of-schema or malformed outputs are refused with
// ErrOutOfSchema and an exact, fixed message.
func TestValidateRejectsOutOfSchema(t *testing.T) {
	cases := rejectCases()
	if len(cases) != 33 {
		t.Fatalf("case table: %d cases, want 33", len(cases))
	}
	var names []string
	for _, tc := range cases {
		names = append(names, tc.name)
	}
	requireUniqueNames(t, names)

	fixture := compileFixture(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var s *Schema
			switch tc.target {
			case fixtureTarget:
				s = fixture
			case zeroTarget:
				s = &Schema{}
			case nilTarget:
			}
			err := s.Validate([]byte(tc.out))
			if !errors.Is(err, ErrOutOfSchema) {
				t.Fatalf("Validate(%s) error = %v, want ErrOutOfSchema", tc.name, err)
			}
			if got, want := err.Error(), outPrefix+tc.want; got != want {
				t.Errorf("Validate(%s) message\n got: %q\nwant: %q", tc.name, got, want)
			}
		})
	}
}

// fixedReasons are the fixed reasons of schema.go and decode.go.
var fixedReasons = []string{
	"no schema", "output too large", "validation failed",
	"invalid UTF-8", "not a single JSON value", "duplicate object key",
	"nesting too deep", "number too long or in exponent form",
}

var keywordMessage = regexp.MustCompile(`^keyword [A-Za-z$?]+ at /[A-Za-z0-9_*/-]*$`)

// Test 6 (task sheet): a validation error never echoes any byte of the output.
func TestValidationErrorDoesNotEchoOutput(t *testing.T) {
	var fiftyKeys strings.Builder
	fiftyKeys.WriteString(`{"greeting":"a","count":null,"tags":[]`)
	for i := range 50 {
		fmt.Fprintf(&fiftyKeys, `,"CANARY_%d":"CANARY"`, i)
	}
	fiftyKeys.WriteString(`}`)

	cases := []struct{ name, out string }{
		{"extra_root_key", `{"greeting":"a","count":null,"tags":[],"CANARY":"CANARY"}`},
		{"extra_nested_key", withTags(`[{"key":"a","level":"low","CANARY":"CANARY"}]`)},
		{"fifty_extra_keys", fiftyKeys.String()},
		{"extra_key_path_like", `{"greeting":"a","count":null,"tags":[],"CANARY/../x":"CANARY"}`},
		{"wrong_type", withCount(`"CANARY"`)},
		{"enum_mismatch", withTags(`[{"key":"a","level":"CANARY"}]`)},
		{"pattern_mismatch", withTags(`[{"key":"CANARY","level":"low"}]`)},
		{"too_long", withGreeting(`"` + strings.Repeat("CANARY", 40) + `"`)},
		{"text_before", `CANARY ` + minOutput},
		{"text_after", minOutput + ` CANARY`},
		{"duplicate_key", `{"greeting":"CANARY","greeting":"CANARY","count":null,"tags":[]}`},
		{"root_string", `"CANARY"`},
	}
	s := compileFixture(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := s.Validate([]byte(tc.out))
			if !errors.Is(err, ErrOutOfSchema) {
				t.Fatalf("Validate(%s) error = %v, want ErrOutOfSchema", tc.name, err)
			}
			msg := err.Error()
			if strings.Contains(strings.ToLower(msg), "canary") {
				t.Errorf("message echoes the output: %q", msg)
			}
			if len(msg) > 200 {
				t.Errorf("message is %d bytes long, want at most 200: %q", len(msg), msg)
			}
			reason, ok := strings.CutPrefix(msg, outPrefix)
			if !ok {
				t.Fatalf("message %q lacks the prefix %q", msg, outPrefix)
			}
			if !slices.Contains(fixedReasons, reason) && !keywordMessage.MatchString(reason) {
				t.Errorf("reason %q is neither a fixed reason nor \"keyword K at /P\"", reason)
			}
		})
	}
}

// Test 7: pointer keeps array indexes and declared property names only.
func TestPointerFiltersSegments(t *testing.T) {
	names := map[string]bool{"tags": true, "level": true}
	twenty := slices.Repeat([]string{"0"}, 20)
	cases := []struct {
		name     string
		location []string
		want     string
	}{
		{"empty", []string{}, "/"},
		{"declared_and_index", []string{"tags", "0", "level"}, "/tags/0/level"},
		{"undeclared", []string{"CANARY"}, "/*"},
		{"hex_like", []string{"0x1"}, "/*"},
		{"empty_segment", []string{""}, "/*"},
		{"index_too_long", []string{"12345678901"}, "/*"},
		{"too_many_segments", twenty, "/" + strings.Repeat("0/", 16) + "*"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pointer(tc.location, names); got != tc.want {
				t.Errorf("pointer(%q) = %q, want %q", tc.location, got, tc.want)
			}
		})
	}
}

// Test 8: Raw returns a copy; the schema never aliases its input nor its
// returned bytes.
func TestSchemaRawIsCopy(t *testing.T) {
	in := []byte(fixtureSchema)
	s, err := CompileSchema(in)
	if err != nil {
		t.Fatalf("CompileSchema(F) = %v", err)
	}
	in[0] = 'X'
	if got := s.Raw(); !bytes.Equal(got, []byte(fixtureSchema)) {
		t.Fatalf("Raw changed after the input was modified: %q", got)
	}
	r := s.Raw()
	r[0] = 'X'
	if got := s.Raw(); !bytes.Equal(got, []byte(fixtureSchema)) {
		t.Fatalf("Raw changed after a returned slice was modified: %q", got)
	}
	if got := (*Schema)(nil).Raw(); got != nil {
		t.Errorf("(*Schema)(nil).Raw() = %q, want nil", got)
	}
}
