package main

import (
	"context"
	"io"
	"os"
	"slices"
	"testing"

	"github.com/amezianechayer/rempart/internal/evals"
)

// TestIntentSuiteComposition (M1-T06): evals/intent holds at least 22 cases
// of the categories of the card, 3 runs each, and every case passes on the
// fake model with no invented value (per-case diagnostic of make evals).
func TestIntentSuiteComposition(t *testing.T) {
	root, err := os.OpenRoot("../../evals")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	s, err := evals.LoadSuite(root.FS(), "intent")
	if err != nil {
		t.Fatalf("LoadSuite: %v", err)
	}
	if s.Target != "intent" || s.Loop != "L1-intent" || len(s.Cases) < 22 {
		t.Errorf("suite %s, loop %s, target %s, %d cases; want L1-intent, intent, at least 22", s.Name, s.Loop, s.Target, len(s.Cases))
	}
	want := map[string]int{"nominal": 4, "multicloud": 3, "ambiguous": 5, "contradictory": 4, "incomplete": 4, evals.InjectionTag: 5, "tenant": 1, "technical-value": 1, "language": 1}
	got := map[string]int{}
	for _, c := range s.Cases {
		if c.Runs != 3 {
			t.Errorf("%s: %d runs, want 3", c.ID, c.Runs)
		}
		for _, tag := range c.Tags {
			got[tag]++
		}
	}
	for tag, n := range want {
		if got[tag] < n {
			t.Errorf("%d cases tagged %s, want at least %d", got[tag], tag, n)
		}
	}
	tg := intentTarget{log: io.Discard}
	for _, c := range s.Cases {
		if err := tg.Check(c); err != nil {
			t.Errorf("%s: input refused: %v", c.ID, err)
			continue
		}
		o, err := tg.Run(context.Background(), c, 0)
		if err != nil {
			t.Errorf("%s: %v", c.ID, err)
			continue
		}
		g, err := evals.GradeOutcome(c, 0, o)
		if err != nil || !g.Pass || o.Invented != 0 {
			t.Errorf("%s: failures %q, invented %d, %v\noutput: %s", c.ID, g.Failures, o.Invented, err, o.Output)
		}
		if slices.Contains(c.Tags, evals.InjectionTag) && !g.Pass {
			t.Errorf("%s: injection not resisted", c.ID)
		}
	}
}
