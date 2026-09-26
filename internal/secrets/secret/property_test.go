package secret

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// TestPropertyOutputIndependentOfContent proves that the printed and encoded
// form of a secret does not depend on its content, for any verb, flags, width
// and precision.
func TestPropertyOutputIndependentOfContent(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		s := rapid.String().Draw(rt, "secret")
		verb := rapid.SampledFrom([]string{"v", "s", "q", "x", "X", "d"}).Draw(rt, "verb")

		var flags []string
		for _, f := range []string{"+", "-", "#", " ", "0"} {
			if rapid.Bool().Draw(rt, "flag "+strconv.Quote(f)) {
				flags = append(flags, f)
			}
		}
		flags = rapid.Permutation(flags).Draw(rt, "flag order")

		var format strings.Builder
		format.WriteString("%")
		format.WriteString(strings.Join(flags, ""))
		if rapid.Bool().Draw(rt, "has width") {
			format.WriteString(strconv.Itoa(rapid.IntRange(1, 40).Draw(rt, "width")))
		}
		if rapid.Bool().Draw(rt, "has precision") {
			format.WriteString("." + strconv.Itoa(rapid.IntRange(0, 40).Draw(rt, "precision")))
		}
		format.WriteString(verb)
		f := format.String()

		v := New(s)
		b := NewBytes([]byte(s))
		outputs := map[string]string{
			"value":         fmt.Sprintf(f, v),
			"value pointer": fmt.Sprintf(f, &v),
			"bytes":         fmt.Sprintf(f, b),
		}
		for name, got := range outputs {
			if got != wantRedacted {
				rt.Fatalf("format %q on %s = %q, want %q", f, name, got, wantRedacted)
			}
		}

		for name, x := range map[string]any{"value": v, "bytes": b} {
			got, err := json.Marshal(x)
			if err != nil {
				rt.Fatalf("json.Marshal(%s): %v", name, err)
			}
			if string(got) != `"[REDACTED]"` {
				rt.Fatalf("json.Marshal(%s) = %s, want %q", name, got, `"[REDACTED]"`)
			}
		}
	})
}
