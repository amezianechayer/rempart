package redact

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

// patternsFile is the reference list of the llm-safety skill, read only.
const patternsFile = "../../../.claude/skills/llm-safety/references/redaction-patterns.md"

// Test 2 (task sheet): every bullet of redaction-patterns.md maps to kinds,
// and every kind of a bullet has a positive case on that line. A bullet added
// to the skill makes this test fail until referenceLines and a positive case
// are written: traceability from the skill to the tests.
func TestEveryPatternLineMapped(t *testing.T) {
	data, err := os.ReadFile(patternsFile)
	if err != nil {
		t.Fatalf("read %s: %v", patternsFile, err)
	}
	var bullets []string
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if text, ok := strings.CutPrefix(line, "- "); ok {
			bullets = append(bullets, text)
		}
	}
	if len(bullets) == 0 {
		t.Fatalf("%s has no bullet line", patternsFile)
	}

	t.Run("bullets_match_entries", func(t *testing.T) {
		if len(bullets) != len(referenceLines) {
			t.Errorf("%s has %d bullets, referenceLines has %d entries", patternsFile, len(bullets), len(referenceLines))
		}
		hits := make([]int, len(referenceLines))
		for i, b := range bullets {
			var matched []int
			for j, e := range referenceLines {
				if strings.HasPrefix(b, e.prefix) {
					matched = append(matched, j)
					hits[j]++
				}
			}
			switch {
			case len(matched) != 1:
				t.Errorf("bullet %d %q starts with %d prefixes of referenceLines, want exactly 1", i+1, b, len(matched))
			case matched[0] != i:
				t.Errorf("bullet %d %q matches entry %d, want entry %d (same order as the file)", i+1, b, matched[0]+1, i+1)
			}
		}
		for j, n := range hits {
			if n != 1 {
				t.Errorf("entry %d %q matches %d bullets, want exactly 1", j+1, referenceLines[j].prefix, n)
			}
		}
	})

	t.Run("kinds_cover_all", func(t *testing.T) {
		union := make(map[Kind]bool)
		for _, e := range referenceLines {
			if len(e.kinds) == 0 {
				t.Errorf("entry %q requires no kind", e.prefix)
			}
			for _, k := range e.kinds {
				union[k] = true
			}
		}
		all := New().Kinds()
		for _, k := range all {
			if !union[k] {
				t.Errorf("kind %q is required by no line of %s", k, patternsFile)
			}
		}
		for k := range union {
			if !slices.Contains(all, k) {
				t.Errorf("kind %q required by a line is not listed by Kinds()", k)
			}
		}
		for _, k := range declaredKinds {
			if !union[k] {
				t.Errorf("declared kind %q is required by no line", k)
			}
		}
	})

	t.Run("every_kind_has_positive_case", func(t *testing.T) {
		for i, e := range referenceLines {
			line := i + 1
			for _, k := range e.kinds {
				found := false
				for _, c := range positiveCases {
					if c.line == line && slices.Contains(c.kinds, k) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("line %d %q: no positive case with kind %q", line, e.prefix, k)
				}
			}
		}
	})

	t.Run("case_lines_valid", func(t *testing.T) {
		for _, c := range positiveCases {
			if c.line < 1 || c.line > len(referenceLines) {
				t.Errorf("%s: line %d outside [1, %d]", c.name, c.line, len(referenceLines))
				continue
			}
			if prefix := fmt.Sprintf("l%02d_", c.line); !strings.HasPrefix(c.name, prefix) {
				t.Errorf("%s: name does not start with %q", c.name, prefix)
			}
			if len(c.kinds) == 0 {
				t.Errorf("%s: no expected kind", c.name)
			}
		}
	})
}
