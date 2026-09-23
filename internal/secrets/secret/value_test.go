package secret

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// canary is a fake secret: any of its encodings in an output is a leak.
const canary = "FAKE-canary-7d41e9b2"

// wantRedacted is written literally so that a change of Redacted is caught.
const wantRedacted = "[REDACTED]"

// leakForms returns the encodings of s that must never appear in an output.
func leakForms(s string) []string {
	b := []byte(s)
	return []string{
		s,
		hex.EncodeToString(b),
		strings.ToUpper(hex.EncodeToString(b)),
		base64.StdEncoding.EncodeToString(b),
		base64.RawStdEncoding.EncodeToString(b),
		base64.URLEncoding.EncodeToString(b),
		base64.RawURLEncoding.EncodeToString(b),
		decimalForm(b),
	}
}

// decimalForm returns the bytes of b in decimal separated by spaces, the way
// fmt prints a byte slice with %v, without the brackets.
func decimalForm(b []byte) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = strconv.Itoa(int(c))
	}
	return strings.Join(parts, " ")
}

// marshalJSON hides the static type of v, so that encoding a struct without
// exported fields, which is the point of some cases, is not reported by lint.
func marshalJSON(v any) ([]byte, error) { return json.Marshal(v) }

// assertNoLeak fails if out contains any form of the canary.
func assertNoLeak(t *testing.T, out string) {
	t.Helper()
	for _, form := range leakForms(canary) {
		if strings.Contains(out, form) {
			t.Errorf("output leaks the secret in form %q: %q", form, out)
		}
	}
}

// subject is one secret type under test, holding the canary.
type subject struct {
	name     string
	x        any
	px       any
	typeName string
}

func subjects() []subject {
	v := New(canary)
	b := NewBytes([]byte(canary))
	return []subject{
		{name: "value", x: v, px: &v, typeName: "secret.Value"},
		{name: "bytes", x: b, px: &b, typeName: "secret.Bytes"},
	}
}

type matchMode int

const (
	exact matchMode = iota
	prefix
	contains
)

type printCase struct {
	name string
	// format and args are used when out is nil; format is a field so that
	// vet does not check it, which allows %w and an extra argument.
	format string
	args   func(x, px any) []any
	out    func(x, px any) string
	mode   matchMode
	want   func(typeName string) string
}

func constant(s string) func(string) string {
	return func(string) string { return s }
}

func printCases() []printCase {
	one := func(x, _ any) []any { return []any{x} }
	r := wantRedacted
	return []printCase{
		{name: "v", format: "%v", args: one, want: constant(r)},
		{name: "plus_v", format: "%+v", args: one, want: constant(r)},
		{name: "sharp_v", format: "%#v", args: one, want: constant(r)},
		{name: "s", format: "%s", args: one, want: constant(r)},
		{name: "q", format: "%q", args: one, want: constant(r)},
		{name: "x", format: "%x", args: one, want: constant(r)},
		{name: "upper_x", format: "%X", args: one, want: constant(r)},
		{name: "d", format: "%d", args: one, want: constant(r)},
		{name: "sharp_x", format: "%#x", args: one, want: constant(r)},
		{name: "space_x", format: "% x", args: one, want: constant(r)},
		{name: "width", format: "%20v", args: one, want: constant(r)},
		{name: "left_width", format: "%-20s|", args: one, want: constant(r + "|")},
		{name: "precision", format: "%.3s", args: one, want: constant(r)},
		{name: "zero_pad", format: "%020d", args: one, want: constant(r)},
		{
			name: "star_width", format: "%*v",
			args: func(x, _ any) []any { return []any{12, x} }, want: constant(r),
		},
		{name: "indexed", format: "%[1]v %[1]s %[1]q", args: one, want: constant(r + " " + r + " " + r)},
		{
			name: "pointer", format: "%v|%+v|%#v|%s",
			args: func(_, px any) []any { return []any{px, px, px, px} },
			want: constant(r + "|" + r + "|" + r + "|" + r),
		},
		{
			name: "in_slice", format: "%v",
			args: func(x, _ any) []any { return []any{[]any{x, x}} }, want: constant("[" + r + " " + r + "]"),
		},
		{
			name: "in_map", format: "%v",
			args: func(x, _ any) []any { return []any{map[string]any{"k": x}} }, want: constant("map[k:" + r + "]"),
		},
		{
			name: "exported_field", format: "%+v",
			args: func(x, _ any) []any { return []any{struct{ Key any }{x}} }, want: constant("{Key:" + r + "}"),
		},
		{
			name: "exported_field_sharp", format: "%#v",
			args: func(x, _ any) []any { return []any{struct{ Key any }{x}} },
			mode: contains, want: constant("Key:" + r),
		},
		{
			name: "reflect_value", format: "%v",
			args: func(x, _ any) []any { return []any{reflect.ValueOf(x)} }, want: constant(r),
		},
		{name: "type", format: "%T", args: one, want: func(typ string) string { return typ }},
		{
			name: "bad_verb_p", format: "%p", args: one,
			mode: prefix, want: func(typ string) string { return "%!p(" + typ + "=" },
		},
		{
			name: "bad_verb_w", format: "%w", args: one,
			mode: prefix, want: func(typ string) string { return "%!w(" + typ + "=" },
		},
		{
			name: "extra_arg", format: "k", args: one,
			want: func(typ string) string { return "k%!(EXTRA " + typ + "=" + r + ")" },
		},
		{name: "sprint", out: func(x, _ any) string { return fmt.Sprint(x) }, want: constant(r)},
		{name: "sprint_mixed", out: func(x, _ any) string { return fmt.Sprint("k=", x) }, want: constant("k=" + r)},
		{name: "sprintln", out: func(x, _ any) string { return fmt.Sprintln(x) }, want: constant(r + "\n")},
		{
			name: "fprintln",
			out: func(x, _ any) string {
				var buf bytes.Buffer
				if _, err := fmt.Fprintln(&buf, "k", x); err != nil {
					return "Fprintln error: " + err.Error()
				}
				return buf.String()
			},
			want: constant("k " + r + "\n"),
		},
		{
			name: "errorf",
			out:  func(x, _ any) string { return fmt.Errorf("connect: %v", x).Error() },
			want: constant("connect: " + r),
		},
		{
			name: "string_method",
			out: func(x, _ any) string {
				s, ok := x.(fmt.Stringer)
				if !ok {
					return "<not a fmt.Stringer>"
				}
				return s.String()
			},
			want: constant(r),
		},
		{
			name: "gostring_method",
			out: func(x, _ any) string {
				s, ok := x.(fmt.GoStringer)
				if !ok {
					return "<not a fmt.GoStringer>"
				}
				return s.GoString()
			},
			want: constant(r),
		},
		{
			name: "log_value",
			out: func(x, _ any) string {
				lv, ok := x.(slog.LogValuer)
				if !ok {
					return "<not a slog.LogValuer>"
				}
				return lv.LogValue().String()
			},
			want: constant(r),
		},
	}
}

func TestValueNeverPrinted(t *testing.T) {
	cases := printCases()
	if len(cases) != 34 {
		t.Fatalf("expected 34 print cases, got %d", len(cases))
	}
	seen := make(map[string]bool, len(cases))
	for _, tc := range cases {
		if seen[tc.name] {
			t.Fatalf("duplicate print case name %q", tc.name)
		}
		seen[tc.name] = true
	}
	for _, s := range subjects() {
		t.Run(s.name, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					var out string
					if tc.out != nil {
						out = tc.out(s.x, s.px)
					} else {
						out = fmt.Sprintf(tc.format, tc.args(s.x, s.px)...)
					}
					want := tc.want(s.typeName)
					switch tc.mode {
					case exact:
						if out != want {
							t.Errorf("case %s: got %q, want %q", tc.name, out, want)
						}
					case prefix:
						if !strings.HasPrefix(out, want) {
							t.Errorf("case %s: got %q, want prefix %q", tc.name, out, want)
						}
					case contains:
						if !strings.Contains(out, want) {
							t.Errorf("case %s: got %q, want it to contain %q", tc.name, out, want)
						}
					}
					assertNoLeak(t, out)
				})
			}
		})
	}
}

// holder keeps secrets in unexported fields: fmt and slog cannot call their
// methods and fall back to reflection.
type holder struct {
	name string
	key  Value
	raw  Bytes
	keyp *Value
	rawp *Bytes
}

func TestNoLeakThroughUnexportedField(t *testing.T) {
	k := New(canary)
	b := NewBytes([]byte(canary))
	h := holder{
		name: "visible",
		key:  New(canary),
		raw:  NewBytes([]byte(canary)),
		keyp: &k,
		rawp: &b,
	}
	address := regexp.MustCompile("0x[0-9a-f]+")
	// sprintf takes the format as a variable: vet rejects %s, %x, %q and %d
	// on a struct at compile time, but fmt must still be proven safe on them.
	sprintf := func(format string, arg any) func(*testing.T) string {
		return func(*testing.T) string { return fmt.Sprintf(format, arg) }
	}
	slogOut := func(t *testing.T, jsonHandler bool) string {
		t.Helper()
		var buf bytes.Buffer
		var handler slog.Handler
		if jsonHandler {
			handler = slog.NewJSONHandler(&buf, nil)
		} else {
			handler = slog.NewTextHandler(&buf, nil)
		}
		slog.New(handler).Info("m", slog.Any("h", h))
		return buf.String()
	}
	cases := []struct {
		name string
		out  func(t *testing.T) string
		// witness requires the output to show the visible field and an
		// address, proving that reflection reached the secret fields.
		witness bool
	}{
		{name: "v", out: sprintf("%v", h)},
		{name: "plus_v", out: sprintf("%+v", h), witness: true},
		{name: "sharp_v", out: sprintf("%#v", h)},
		{name: "s", out: sprintf("%s", h)},
		{name: "x", out: sprintf("%x", h)},
		{name: "q", out: sprintf("%q", h)},
		{name: "d", out: sprintf("%d", h)},
		{name: "pointer_plus_v", out: sprintf("%+v", &h)},
		{name: "sprint", out: func(*testing.T) string { return fmt.Sprint(h) }},
		{name: "nested_plus_v", out: sprintf("%+v", struct{ H holder }{h})},
		{name: "slog_text", out: func(t *testing.T) string { return slogOut(t, false) }, witness: true},
		{name: "slog_json", out: func(t *testing.T) string { return slogOut(t, true) }},
		{
			name: "json",
			out: func(t *testing.T) string {
				t.Helper()
				got, err := marshalJSON(h)
				if err != nil {
					t.Fatalf("json.Marshal(holder): %v", err)
				}
				if string(got) != "{}" {
					t.Errorf("json.Marshal(holder) = %s, want {}", got)
				}
				return string(got)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := tc.out(t)
			assertNoLeak(t, out)
			if tc.witness {
				if !strings.Contains(out, "visible") {
					t.Errorf("case %s: output %q does not show the visible field", tc.name, out)
				}
				if !address.MatchString(out) {
					t.Errorf("case %s: output %q shows no address for the secret fields", tc.name, out)
				}
			}
		})
	}
}

func TestRevealReturnsValue(t *testing.T) {
	t.Run("value", func(t *testing.T) {
		v := New(canary)
		if got := v.Reveal(); got != canary {
			t.Errorf("New(canary).Reveal() = %q, want %q", got, canary)
		}
		if v.IsZero() {
			t.Error("New(canary).IsZero() = true, want false")
		}
	})
	t.Run("value_copy", func(t *testing.T) {
		v := New(canary)
		w := v
		if got := w.Reveal(); got != canary {
			t.Errorf("copy of New(canary).Reveal() = %q, want %q", got, canary)
		}
	})
	t.Run("value_binary", func(t *testing.T) {
		in := "é\x00\n\t[REDACTED]"
		v := New(in)
		if got := v.Reveal(); got != in {
			t.Errorf("New(binary).Reveal() = %q, want %q", got, in)
		}
		if v.IsZero() {
			t.Error("New(binary).IsZero() = true, want false")
		}
	})
	t.Run("bytes", func(t *testing.T) {
		b := NewBytes([]byte(canary))
		if got := b.Reveal(); !bytes.Equal(got, []byte(canary)) {
			t.Errorf("NewBytes(canary).Reveal() = %q, want %q", got, canary)
		}
		if got := b.Len(); got != len(canary) {
			t.Errorf("NewBytes(canary).Len() = %d, want %d", got, len(canary))
		}
		if b.IsZero() {
			t.Error("NewBytes(canary).IsZero() = true, want false")
		}
	})
	t.Run("bytes_binary", func(t *testing.T) {
		in := make([]byte, 256)
		for i := range in {
			in[i] = byte(i)
		}
		want := bytes.Clone(in)
		b := NewBytes(in)
		if got := b.Reveal(); !bytes.Equal(got, want) {
			t.Errorf("NewBytes(all byte values).Reveal() = %v, want %v", got, want)
		}
		if got := b.Len(); got != 256 {
			t.Errorf("NewBytes(all byte values).Len() = %d, want 256", got)
		}
	})
	t.Run("bytes_copy", func(t *testing.T) {
		b := NewBytes([]byte(canary))
		c := b
		if got := c.Reveal(); !bytes.Equal(got, []byte(canary)) {
			t.Errorf("copy of NewBytes(canary).Reveal() = %q, want %q", got, canary)
		}
		if got := c.Len(); got != len(canary) {
			t.Errorf("copy of NewBytes(canary).Len() = %d, want %d", got, len(canary))
		}
	})
}

func TestZeroValues(t *testing.T) {
	t.Run("value_zero", func(t *testing.T) {
		var v Value
		if !v.IsZero() {
			t.Error("Value{}.IsZero() = false, want true")
		}
		if got := v.Reveal(); got != "" {
			t.Errorf("Value{}.Reveal() = %q, want empty", got)
		}
		if got := fmt.Sprint(v); got != wantRedacted {
			t.Errorf("fmt.Sprint(Value{}) = %q, want %q", got, wantRedacted)
		}
		got, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("json.Marshal(Value{}): %v", err)
		}
		if string(got) != `"[REDACTED]"` {
			t.Errorf("json.Marshal(Value{}) = %s, want %q", got, `"[REDACTED]"`)
		}
		if got := v.LogValue().String(); got != wantRedacted {
			t.Errorf("Value{}.LogValue() = %q, want %q", got, wantRedacted)
		}
	})
	t.Run("value_new_empty", func(t *testing.T) {
		if !New("").IsZero() {
			t.Error(`New("").IsZero() = false, want true`)
		}
	})
	t.Run("value_new_space", func(t *testing.T) {
		v := New(" ")
		if v.IsZero() {
			t.Error(`New(" ").IsZero() = true, want false`)
		}
		if got := v.Reveal(); got != " " {
			t.Errorf(`New(" ").Reveal() = %q, want " "`, got)
		}
	})
	t.Run("bytes_zero", func(t *testing.T) {
		var b Bytes
		if !b.IsZero() {
			t.Error("Bytes{}.IsZero() = false, want true")
		}
		if got := b.Len(); got != 0 {
			t.Errorf("Bytes{}.Len() = %d, want 0", got)
		}
		if got := b.Reveal(); got != nil {
			t.Errorf("Bytes{}.Reveal() = %v, want nil", got)
		}
		b.Wipe()
		if got := fmt.Sprint(b); got != wantRedacted {
			t.Errorf("fmt.Sprint(Bytes{}) = %q, want %q", got, wantRedacted)
		}
	})
	t.Run("bytes_new_nil", func(t *testing.T) {
		b := NewBytes(nil)
		if !b.IsZero() {
			t.Error("NewBytes(nil).IsZero() = false, want true")
		}
		if got := b.Reveal(); got != nil {
			t.Errorf("NewBytes(nil).Reveal() = %v, want nil", got)
		}
	})
	t.Run("bytes_new_empty", func(t *testing.T) {
		b := NewBytes([]byte{})
		if !b.IsZero() {
			t.Error("NewBytes([]byte{}).IsZero() = false, want true")
		}
		if got := b.Reveal(); got != nil {
			t.Errorf("NewBytes([]byte{}).Reveal() = %#v, want nil (not an empty non-nil slice)", got)
		}
	})
	t.Run("nil_pointers", func(t *testing.T) {
		if got := fmt.Sprint((*Value)(nil)); got != "<nil>" {
			t.Errorf("fmt.Sprint((*Value)(nil)) = %q, want <nil>", got)
		}
		if got := fmt.Sprint((*Bytes)(nil)); got != "<nil>" {
			t.Errorf("fmt.Sprint((*Bytes)(nil)) = %q, want <nil>", got)
		}
		got, err := json.Marshal((*Value)(nil))
		if err != nil {
			t.Fatalf("json.Marshal((*Value)(nil)): %v", err)
		}
		if string(got) != "null" {
			t.Errorf("json.Marshal((*Value)(nil)) = %s, want null", got)
		}
	})
}

func TestNotComparable(t *testing.T) {
	t.Run("value", func(t *testing.T) {
		if reflect.TypeFor[Value]().Comparable() {
			t.Error("Value is comparable, want not comparable (== would compare pointers)")
		}
	})
	t.Run("bytes", func(t *testing.T) {
		if reflect.TypeFor[Bytes]().Comparable() {
			t.Error("Bytes is comparable, want not comparable (== would compare pointers)")
		}
	})
}

func TestSentinelAndConstant(t *testing.T) {
	if Redacted != wantRedacted {
		t.Errorf("Redacted = %q, want %q", Redacted, wantRedacted)
	}
	if ErrDecodeRefused == nil {
		t.Fatal("ErrDecodeRefused is nil")
	}
	msg := ErrDecodeRefused.Error()
	if !strings.HasPrefix(msg, "secret: ") {
		t.Errorf("ErrDecodeRefused message %q does not start with %q", msg, "secret: ")
	}
	if strings.Contains(msg, "%") {
		t.Errorf("ErrDecodeRefused message %q contains a %% sign", msg)
	}
}
