package secret

import (
	"bytes"
	"encoding"
	"encoding/gob"
	"encoding/json"
	"encoding/xml"
	"errors"
	htmltemplate "html/template"
	"strings"
	"testing"
	texttemplate "text/template"
)

// secretType is the set of secret types, for tests that need a static type.
type secretType interface {
	Value | Bytes
	IsZero() bool
}

// revealString returns the content of a secret as a string, for comparisons.
func revealString(t *testing.T, x any) string {
	t.Helper()
	switch s := x.(type) {
	case Value:
		return s.Reveal()
	case Bytes:
		return string(s.Reveal())
	default:
		t.Fatalf("unexpected secret type %T", x)
		return ""
	}
}

type jsonCase struct {
	name string
	in   func() ([]byte, error)
	// want is the exact output, or a substring when contains is set.
	want     string
	contains bool
}

func commonJSONCases(x, px any) []jsonCase {
	return []jsonCase{
		{name: "direct", in: func() ([]byte, error) { return json.Marshal(x) }, want: `"[REDACTED]"`},
		{name: "pointer", in: func() ([]byte, error) { return json.Marshal(px) }, want: `"[REDACTED]"`},
		{
			name: "tagged_field",
			in: func() ([]byte, error) {
				return json.Marshal(struct {
					K any `json:"api_key"`
				}{x})
			},
			want: `{"api_key":"[REDACTED]"}`,
		},
		{
			name: "slice", in: func() ([]byte, error) { return json.Marshal([]any{x, x}) },
			want: `["[REDACTED]","[REDACTED]"]`,
		},
		{
			name: "map_value", in: func() ([]byte, error) { return json.Marshal(map[string]any{"k": x}) },
			want: `{"k":"[REDACTED]"}`,
		},
		{
			name: "indent",
			in: func() ([]byte, error) {
				return json.MarshalIndent(struct{ K any }{x}, "", "  ")
			},
			want: `"K": "[REDACTED]"`, contains: true,
		},
		{
			name: "encoder",
			in: func() ([]byte, error) {
				var buf bytes.Buffer
				enc := json.NewEncoder(&buf)
				enc.SetEscapeHTML(false)
				err := enc.Encode(x)
				return buf.Bytes(), err
			},
			want: "\"[REDACTED]\"\n",
		},
	}
}

func typedJSONCases[T secretType](s T, embedded any) []jsonCase {
	return []jsonCase{
		{
			name: "unexported_field",
			in:   func() ([]byte, error) { return marshalJSON(struct{ k T }{s}) },
			want: `{}`,
		},
		{
			name: "omitzero_zero",
			in: func() ([]byte, error) {
				return json.Marshal(struct {
					K T `json:"k,omitzero"`
				}{})
			},
			want: `{}`,
		},
		{
			name: "omitzero_set",
			in: func() ([]byte, error) {
				return json.Marshal(struct {
					K T `json:"k,omitzero"`
				}{s})
			},
			want: `{"k":"[REDACTED]"}`,
		},
		{
			name: "embedded",
			in:   func() ([]byte, error) { return json.Marshal(embedded) },
			want: `"[REDACTED]"`,
		},
	}
}

func TestJSONRedacts(t *testing.T) {
	for _, sub := range subjects() {
		t.Run(sub.name, func(t *testing.T) {
			cases := commonJSONCases(sub.x, sub.px)
			switch s := sub.x.(type) {
			case Value:
				cases = append(cases, typedJSONCases(s, struct {
					Value
					Name string
				}{s, "n"})...)
			case Bytes:
				cases = append(cases, typedJSONCases(s, struct {
					Bytes
					Name string
				}{s, "n"})...)
			default:
				t.Fatalf("unexpected subject type %T", sub.x)
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					got, err := tc.in()
					if err != nil {
						t.Fatalf("case %s: unexpected error: %v", tc.name, err)
					}
					out := string(got)
					if tc.contains {
						if !strings.Contains(out, tc.want) {
							t.Errorf("case %s: got %s, want it to contain %s", tc.name, out, tc.want)
						}
					} else if out != tc.want {
						t.Errorf("case %s: got %s, want %s", tc.name, out, tc.want)
					}
					assertNoLeak(t, out)
				})
			}
		})
	}
}

type decodeCase struct {
	name string
	// run decodes and reports whether the target is still in the expected
	// state (zero, or unchanged for text), with the decoding error.
	run func(t *testing.T) (bool, error)
	// sentinel requires errors.Is(err, ErrDecodeRefused).
	sentinel bool
}

func decodeCases[T secretType](s T) []decodeCase {
	type field struct {
		K T `json:"k"`
	}
	jsonField := func(input string) func(*testing.T) (bool, error) {
		return func(*testing.T) (bool, error) {
			var target field
			err := json.Unmarshal([]byte(input), &target)
			return target.K.IsZero(), err
		}
	}
	return []decodeCase{
		{name: "json_string_field", run: jsonField(`{"k":"` + canary + `"}`), sentinel: true},
		{name: "json_redacted_literal", run: jsonField(`{"k":"[REDACTED]"}`), sentinel: true},
		{name: "json_null_field", run: jsonField(`{"k":null}`), sentinel: true},
		{name: "json_object_field", run: jsonField(`{"k":{}}`), sentinel: true},
		{
			name: "json_direct",
			run: func(*testing.T) (bool, error) {
				var target T
				err := json.Unmarshal([]byte(`"x"`), &target)
				return target.IsZero(), err
			},
			sentinel: true,
		},
		{
			name: "json_roundtrip",
			run: func(t *testing.T) (bool, error) {
				t.Helper()
				data, err := json.Marshal(field{K: s})
				if err != nil {
					t.Fatalf("json.Marshal before round trip: %v", err)
				}
				var target field
				err = json.Unmarshal(data, &target)
				return target.K.IsZero(), err
			},
			sentinel: true,
		},
		{
			name: "text",
			run: func(t *testing.T) (bool, error) {
				t.Helper()
				target := s
				u, ok := any(&target).(encoding.TextUnmarshaler)
				if !ok {
					t.Fatalf("*%T does not implement encoding.TextUnmarshaler", target)
				}
				err := u.UnmarshalText([]byte("FAKE-other-secret"))
				return revealString(t, target) == canary, err
			},
			sentinel: true,
		},
		{
			name: "xml",
			run: func(*testing.T) (bool, error) {
				var target struct {
					XMLName xml.Name `xml:"h"`
					K       T        `xml:"k"`
				}
				err := xml.Unmarshal([]byte("<h><k>"+canary+"</k></h>"), &target)
				return target.K.IsZero(), err
			},
		},
	}
}

func TestDecodeRefused(t *testing.T) {
	for _, sub := range subjects() {
		t.Run(sub.name, func(t *testing.T) {
			var cases []decodeCase
			switch s := sub.x.(type) {
			case Value:
				cases = decodeCases(s)
			case Bytes:
				cases = decodeCases(s)
			default:
				t.Fatalf("unexpected subject type %T", sub.x)
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					unchanged, err := tc.run(t)
					if err == nil {
						t.Fatalf("case %s: decoding succeeded, want an error", tc.name)
					}
					if tc.sentinel && !errors.Is(err, ErrDecodeRefused) {
						t.Errorf("case %s: error %v is not ErrDecodeRefused", tc.name, err)
					}
					if !unchanged {
						t.Errorf("case %s: decoding modified the target", tc.name)
					}
					assertNoLeak(t, err.Error())
				})
			}
		})
	}
}

type encoderCase struct {
	name string
	run  func(t *testing.T) string
}

func typedEncoderCases[T secretType](s T) []encoderCase {
	return []encoderCase{
		{
			name: "xml_attr",
			run: func(t *testing.T) string {
				t.Helper()
				out, err := xml.Marshal(struct {
					XMLName xml.Name `xml:"h"`
					A       T        `xml:"a,attr"`
				}{A: s})
				if err != nil {
					t.Fatalf("xml.Marshal with attribute: %v", err)
				}
				if !strings.Contains(string(out), `a="[REDACTED]"`) {
					t.Errorf("xml attribute output %s does not contain %s", out, `a="[REDACTED]"`)
				}
				return string(out)
			},
		},
		{
			name: "gob",
			run: func(t *testing.T) string {
				t.Helper()
				var buf bytes.Buffer
				err := gob.NewEncoder(&buf).Encode(struct{ K T }{s})
				if err == nil {
					t.Fatal("gob encoding of a secret succeeded, want an error")
				}
				return err.Error() + "\n" + buf.String()
			},
		},
	}
}

func commonEncoderCases(x any) []encoderCase {
	return []encoderCase{
		{
			name: "marshal_text",
			run: func(t *testing.T) string {
				t.Helper()
				m, ok := x.(encoding.TextMarshaler)
				if !ok {
					t.Fatalf("%T does not implement encoding.TextMarshaler", x)
				}
				out, err := m.MarshalText()
				if err != nil {
					t.Fatalf("MarshalText: %v", err)
				}
				if string(out) != wantRedacted {
					t.Errorf("MarshalText() = %q, want %q", out, wantRedacted)
				}
				return string(out)
			},
		},
		{
			name: "xml_element",
			run: func(t *testing.T) string {
				t.Helper()
				out, err := xml.Marshal(struct {
					XMLName xml.Name `xml:"h"`
					K       any      `xml:"k"`
				}{K: x})
				if err != nil {
					t.Fatalf("xml.Marshal: %v", err)
				}
				if !strings.Contains(string(out), "<k>[REDACTED]</k>") {
					t.Errorf("xml output %s does not contain <k>[REDACTED]</k>", out)
				}
				return string(out)
			},
		},
		{
			name: "text_template",
			run: func(t *testing.T) string {
				t.Helper()
				tmpl := texttemplate.Must(texttemplate.New("t").Parse(`{{.K}} {{printf "%s" .K}} {{printf "%x" .K}}`))
				var buf bytes.Buffer
				if err := tmpl.Execute(&buf, struct{ K any }{x}); err != nil {
					t.Fatalf("text/template Execute: %v", err)
				}
				want := wantRedacted + " " + wantRedacted + " " + wantRedacted
				if buf.String() != want {
					t.Errorf("text/template output = %q, want %q", buf.String(), want)
				}
				return buf.String()
			},
		},
		{
			name: "html_template",
			run: func(t *testing.T) string {
				t.Helper()
				tmpl := htmltemplate.Must(htmltemplate.New("t").Parse(`{{.K}}`))
				var buf bytes.Buffer
				if err := tmpl.Execute(&buf, struct{ K any }{x}); err != nil {
					t.Fatalf("html/template Execute: %v", err)
				}
				if buf.String() != wantRedacted {
					t.Errorf("html/template output = %q, want %q", buf.String(), wantRedacted)
				}
				return buf.String()
			},
		},
	}
}

func TestOtherEncodersRedact(t *testing.T) {
	for _, sub := range subjects() {
		t.Run(sub.name, func(t *testing.T) {
			cases := commonEncoderCases(sub.x)
			switch s := sub.x.(type) {
			case Value:
				cases = append(cases, typedEncoderCases(s)...)
			case Bytes:
				cases = append(cases, typedEncoderCases(s)...)
			default:
				t.Fatalf("unexpected subject type %T", sub.x)
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					assertNoLeak(t, tc.run(t))
				})
			}
		})
	}
}
