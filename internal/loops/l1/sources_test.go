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

// TestL1SourceRestrictionGluedForms (second review pass, T102): an address
// glued to a key by ':' or followed by a port is kept or escalates, never
// dropped into an IR open to all of Internet.
func TestL1SourceRestrictionGluedForms(t *testing.T) {
	kept := answer(draft(t, "reference-draft.json", `"allowed_sources": []`, `"allowed_sources": ["203.0.113.10/32"]`))
	dropped := answer(draft(t, "reference-draft.json"))
	for name, extra := range map[string]string{
		"colon_key":    " L'accès à l'application est réservé à source:203.0.113.10.",
		"word_key":     " Accès depuis:203.0.113.10 seulement.",
		"with_port":    " Accès depuis 203.0.113.10:443 seulement.",
		"key_and_port": " L'accès à l'application est réservé à ip:203.0.113.10:443.",
	} {
		t.Run(name, func(t *testing.T) {
			in := referenceInput(t)
			in.RequestText += extra
			h := newHarness(t, tenantA, []llmfake.Step{kept, dropped})
			out := mustRun(t, h, in)
			if out.Status != l1.StatusConverged || out.IR == nil || len(out.IR.Exposure) != 1 ||
				!slices.Equal(out.IR.Exposure[0].AllowedSources, []string{"203.0.113.10/32"}) {
				t.Fatalf("status %s, remaining %+v, IR %v; want converged on the faithful draft", out.Status, out.Loop.Remaining, out.IR != nil)
			}
			h = newHarness(t, tenantA, times(dropped, 8))
			out = mustRun(t, h, in)
			assertEscalatedWithoutIR(t, h, out)
		})
	}
}
