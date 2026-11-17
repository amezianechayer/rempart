package domain

import (
	"reflect"
	"testing"
)

// M1-T06: invented_values is measured on the delivered IR, apart from the
// loop: the IR is read back as a draft and the provenance checks are run on it.

// TestDraftOfIRRoundTrip: DraftOf inverts ToIR on the reference scenario.
func TestDraftOfIRRoundTrip(t *testing.T) {
	d := draftFrom(t, "reference-draft.json", nil)
	ir := d.ToIR("0f8fad5b-d9cb-469f-a165-70867728950e")
	if back := DraftOf(ir).ToIR(ir.TenantID); !reflect.DeepEqual(back, ir) {
		t.Errorf("DraftOf(ir).ToIR differs\n got: %+v\nwant: %+v", back, ir)
	}
}

// TestInventedValuesOfIR: the reference IR has no invented value; a budget,
// a region or a count that the user never wrote is counted.
func TestInventedValuesOfIR(t *testing.T) {
	text := readText(t, "reference-request.txt")
	ctx := TenantContext{AllowedRegions: []string{"eu-west-3", "francecentral"}}
	ir := draftFrom(t, "reference-draft.json", nil).ToIR("0f8fad5b-d9cb-469f-a165-70867728950e")
	if n := InventedValues(text, ir, ctx); n != 0 {
		t.Fatalf("reference IR: %d invented values, want 0", n)
	}
	budget := ir
	b := 9999.0
	budget.Constraints.MonthlyBudgetEUR = &b
	if n := InventedValues(text, budget, ctx); n < 1 {
		t.Errorf("invented budget: %d, want at least 1", n)
	}
	count := DraftOf(ir).ToIR(ir.TenantID)
	seven := 7
	count.Workloads[wAppCluster].Size.Count = &seven
	if n := InventedValues(text, count, ctx); n < 1 {
		t.Errorf("invented node count: %d, want at least 1", n)
	}
}
