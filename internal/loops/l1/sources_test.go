package l1_test

import (
	"slices"
	"testing"

	llmfake "github.com/amezianechayer/rempart/internal/llm/fake"
	"github.com/amezianechayer/rempart/internal/loops/l1"
)

// Review of the M1 milestone (T102): the reference request restricted to one
// address. The faithful draft (A/32) converges with the restriction; a draft
// that drops it never converges, so the loop yields the IR with the
// restriction or escalates without IR, never an exposure to all of Internet.
func TestL1SourceRestrictionKept(t *testing.T) {
	in := referenceInput(t)
	in.RequestText += " L'application n'est accessible que depuis 203.0.113.10."
	kept := answer(draft(t, "reference-draft.json", `"allowed_sources": []`, `"allowed_sources": ["203.0.113.10/32"]`))
	dropped := answer(draft(t, "reference-draft.json"))

	for name, steps := range map[string][]llmfake.Step{
		"faithful":          {kept},
		"dropped_then_kept": {dropped, kept},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, tenantA, steps)
			out := mustRun(t, h, in)
			if out.Status != l1.StatusConverged || out.IR == nil {
				t.Fatalf("status %s, reason %s, remaining %+v; want converged", out.Status, out.Loop.Reason, out.Loop.Remaining)
			}
			if len(out.IR.Exposure) != 1 || !slices.Equal(out.IR.Exposure[0].AllowedSources, []string{"203.0.113.10/32"}) {
				t.Errorf("exposure %+v, want the restriction 203.0.113.10/32", out.IR.Exposure)
			}
			assertNoDraft(t, out)
		})
	}

	t.Run("always_dropped", func(t *testing.T) {
		h := newHarness(t, tenantA, times(dropped, 8))
		out := mustRun(t, h, in)
		assertEscalatedWithoutIR(t, h, out)
		if !slices.ContainsFunc(out.Loop.Remaining, func(f loopsFinding) bool { return f.Code == "INTENT-EXPOSURE-SOURCES-OMITTED" }) {
			t.Errorf("remaining %+v, want INTENT-EXPOSURE-SOURCES-OMITTED", out.Loop.Remaining)
		}
	})
}
