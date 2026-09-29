package loops

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// uuidV4Suffix is the oracle of the random part of an identifier: a canonical
// RFC 9562 version 4 UUID (criterion 8 of docs/plans/M0-worker-demo.md).
const uuidV4Suffix = `-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`

// demoIDRe is the pattern of criterion 8, written out independently of the code.
var demoIDRe = regexp.MustCompile(`^l0-demo` + uuidV4Suffix)

// TestNewWorkflowIDOpaque (c, D7, threat T14): a workflow or task queue
// identifier is the loop identifier followed by a random version 4 UUID; it
// never carries a tenant nor any customer content. An invalid loop identifier
// is refused with ErrInvalidLoopID, without quoting it.
func TestNewWorkflowIDOpaque(t *testing.T) {
	t.Run("distinct_and_canonical", func(t *testing.T) {
		seen := make(map[string]bool, 1000)
		for range 1000 {
			id, err := NewWorkflowID("l0-demo")
			if err != nil {
				t.Fatalf("NewWorkflowID(l0-demo): %v", err)
			}
			if !demoIDRe.MatchString(id) {
				t.Fatalf("id %q does not match %s", id, demoIDRe)
			}
			if seen[id] {
				t.Fatalf("id %q drawn twice in 1000 draws", id)
			}
			seen[id] = true
		}
	})

	t.Run("bound", func(t *testing.T) {
		if MaxLoopIDBytes != 32 {
			t.Errorf("MaxLoopIDBytes = %d, want 32 (a 36-byte tenant id never fits, T14)", MaxLoopIDBytes)
		}
		longest := strings.Repeat("a", 32)
		id, err := NewWorkflowID(longest)
		if err != nil || !regexp.MustCompile(`^`+longest+uuidV4Suffix).MatchString(id) {
			t.Errorf("NewWorkflowID(32 bytes) = %q, %v; want an identifier", id, err)
		}
		for _, ok := range []string{"a", "rempart-demo", "rempart-demo-it", "l0-demo", "0"} {
			if _, err := NewWorkflowID(ok); err != nil {
				t.Errorf("NewWorkflowID(%q) = %v, want an identifier", ok, err)
			}
		}
	})

	t.Run("refused", func(t *testing.T) {
		cases := []struct{ name, loopID string }{
			{"empty", ""},
			{"upper_case", "L0-demo"},
			{"underscore", "l0_demo"},
			{"space", "l0 demo"},
			{"leading_hyphen", "-l0"},
			{"trailing_hyphen", "l0-"},
			{"33_bytes", strings.Repeat("a", 33)},
			{"tenant_id", "0f8fad5b-d9cb-469f-a165-70867728950e"},
			{"slash", "l0/demo"},
			{"newline", "l0\ndemo"},
			{"non_ascii", "l0-démo"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				id, err := NewWorkflowID(tc.loopID)
				if !errors.Is(err, ErrInvalidLoopID) {
					t.Fatalf("NewWorkflowID(%q) = %q, %v; want ErrInvalidLoopID", tc.loopID, id, err)
				}
				if id != "" {
					t.Errorf("identifier %q returned with the error, want empty", id)
				}
				if tc.loopID != "" && strings.Contains(err.Error(), tc.loopID) {
					t.Errorf("error %q quotes the refused loop id", err)
				}
			})
		}
	})

	// Property: every valid loop identifier yields itself plus a v4 UUID, and
	// nothing else; every identifier with a byte outside [a-z0-9-] is refused.
	t.Run("property", func(t *testing.T) {
		rapid.Check(t, func(rt *rapid.T) {
			loopID := rapid.StringMatching(`[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?`).Draw(rt, "loopID")
			id, err := NewWorkflowID(loopID)
			if err != nil {
				rt.Fatalf("NewWorkflowID(%q): %v", loopID, err)
			}
			if !regexp.MustCompile(`^` + regexp.QuoteMeta(loopID) + uuidV4Suffix).MatchString(id) {
				rt.Fatalf("NewWorkflowID(%q) = %q, want the loop id then a v4 UUID", loopID, id)
			}
		})
		rapid.Check(t, func(rt *rapid.T) {
			base := []byte(rapid.StringMatching(`[a-z0-9]{1,30}`).Draw(rt, "base"))
			pos := rapid.IntRange(0, len(base)-1).Draw(rt, "pos")
			b := rapid.Byte().Filter(func(b byte) bool {
				return !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz0123456789-", rune(b))
			}).Draw(rt, "byte")
			base[pos] = b
			if id, err := NewWorkflowID(string(base)); !errors.Is(err, ErrInvalidLoopID) {
				rt.Fatalf("NewWorkflowID(%q) = %q, %v; want ErrInvalidLoopID", base, id, err)
			}
		})
	})
}
