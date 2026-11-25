package domain

import (
	"testing"

	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
)

// TestRegulatedInternalExposureRejected (closing review of M2, high, T139):
// data the model classifies internal but declares regulated is sensitive for
// the exposure rule of L1, as in L2; the classification chosen by the model
// never opens an exposure of regulated data.
func TestRegulatedInternalExposureRejected(t *testing.T) {
	text := readText(t, "reference-request.txt")
	store := func(classification string, regulation []any) Draft {
		return draftFrom(t, "reference-draft.json", func(t *testing.T, m map[string]any) {
			data, ok := m["data"].([]any)
			if !ok || len(data) == 0 {
				t.Fatal("reference draft without data")
			}
			d, ok := data[0].(map[string]any)
			if !ok {
				t.Fatal("reference draft data is not an object")
			}
			d["classification"], d["regulation"], d["stored_in"] = classification, regulation, []any{"app-cluster"}
		})
	}
	got := Check(text, store("internal", []any{"health"}), TenantContext{})
	if !hasFinding(got, "INTENT-EXPOSURE-SENSITIVE", loopsdomain.SeverityHigh, "exposure[0].workload") {
		t.Errorf("internal data regulated health stored on the exposed workload: no INTENT-EXPOSURE-SENSITIVE, got %+v", got)
	}
	got = Check(text, store("internal", []any{}), TenantContext{})
	if hasFinding(got, "INTENT-EXPOSURE-SENSITIVE", loopsdomain.SeverityHigh, "exposure[0].workload") {
		t.Errorf("internal data without regulation: INTENT-EXPOSURE-SENSITIVE, want none (control)")
	}
}
