package archtest

import (
	"slices"
	"testing"
)

// TestCalibrationConfinedToEvalsCLI (M1-T05, D10): the calibration client,
// the only way to run a route without baseline, is imported by
// cmd/rempart-evals only.
func TestCalibrationConfinedToEvalsCLI(t *testing.T) {
	const (
		m    = modulePath
		rule = "llm-calibration-evals-cli-only"
		cal  = m + "/internal/llm/calibration"
	)
	rules := DefaultRules(m)
	i := slices.IndexFunc(rules, func(r Rule) bool { return r.Name == rule })
	if i < 0 {
		t.Fatalf("DefaultRules has no rule %s", rule)
	}
	if r := rules[i]; r.Kind != Confine || !slices.Equal(r.Targets, []string{cal + "/..."}) ||
		!slices.Equal(r.AllowedFrom, []string{m + "/cmd/rempart-evals"}) {
		t.Fatalf("%s: kind %d, Targets %q, AllowedFrom %q", rule, r.Kind, r.Targets, r.AllowedFrom)
	}
	only := func(vs []Violation) []Violation {
		var out []Violation
		for _, v := range vs {
			if v.Rule == rule {
				out = append(out, v)
			}
		}
		return out
	}
	for _, from := range []string{m + "/cmd/rempart-worker", m + "/internal/loops/l1/activities", m + "/internal/llm"} {
		t.Run("from_"+from[len(m)+1:], func(t *testing.T) {
			got := Check(m, []Package{{ImportPath: from, Imports: []string{cal}}}, rules)
			expectViolations(t, only(got), []Violation{{Rule: rule, Importer: from, Imported: cal}})
		})
	}
	t.Run("from_evals", func(t *testing.T) {
		got := Check(m, []Package{{ImportPath: m + "/cmd/rempart-evals", Imports: []string{cal, m + "/internal/llm"}}}, rules)
		expectViolations(t, only(got), nil)
	})
}
