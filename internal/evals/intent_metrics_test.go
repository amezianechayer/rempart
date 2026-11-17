package evals

import (
	"errors"
	"slices"
	"testing"
)

// M1-T06 (lean mode): invented_values (criterion 1 of prompts/M1.md) and the
// closed vocabulary of case tags (obligations (u), (bz), T66).

// TestInventedValuesRegressive: the report sums the invented values of the
// runs; any rise over the baseline is a regression, a negative count is an
// incomplete run, a negative baseline count is an invalid baseline.
func TestInventedValuesRegressive(t *testing.T) {
	c := mk(Expect{Escalation: ptr(false)})
	c.Runs = 2
	s := Suite{Loop: "L1", Cases: []Case{c}}
	grades := []Grade{{CaseID: c.ID, Pass: true}, {CaseID: c.ID, Run: 1, Pass: true}}
	r, err := Aggregate(s, grades, []Outcome{{Invented: 2}, {Invented: 1}})
	if err != nil || r.InventedValues != 3 {
		t.Fatalf("report %+v, %v; want 3 invented values", r, err)
	}
	if _, err := Aggregate(s, grades, []Outcome{{Invented: -1}, {}}); !errors.Is(err, ErrIncompleteRuns) {
		t.Errorf("negative invented count: %v", err)
	}
	if got := diff(base(), func(r *Report) { r.InventedValues = 1 }); !slices.Contains(got, "invented_values 0 1") {
		t.Errorf("rise from 0 to 1: %q, want an invented_values regression", got)
	}
	if got := diff(base(), func(*Report) {}); len(got) != 0 {
		t.Errorf("equal report: %q", got)
	}
	b := base()
	b.Report.InventedValues = -1
	if b.Validate() == nil {
		t.Error("baseline with a negative invented count is valid")
	}
}

// TestCaseTagsClosed: a case tag outside the closed vocabulary is refused.
func TestCaseTagsClosed(t *testing.T) {
	for _, tag := range CaseTags() {
		c := mk(Expect{Escalation: ptr(false)})
		c.Tags = []string{tag}
		if _, _, err := compileCase(c); err != nil {
			t.Errorf("tag %q refused: %v", tag, err)
		}
	}
	for _, tag := range []string{"foo", "injections", "nominal2", "Injection"} {
		c := mk(Expect{Escalation: ptr(false)})
		c.Tags = []string{tag}
		if _, _, err := compileCase(c); !errors.Is(err, ErrInvalidCase) {
			t.Errorf("tag %q accepted", tag)
		}
	}
	if !slices.Contains(CaseTags(), InjectionTag) || len(CaseTags()) > 16 {
		t.Errorf("vocabulary %q", CaseTags())
	}
}
