package intent_test

import (
	"reflect"
	"testing"

	"github.com/amezianechayer/rempart/internal/intent"
	"github.com/amezianechayer/rempart/internal/intent/domain"
	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
)

// TestReferenceScenarioValid: criterion 3 of prompts/M1.md (first half). The
// draft of the reference scenario parses, passes every L1 check, converts to
// the expected IR with the tenant of the context, validates, and raises no
// contradiction.
func TestReferenceScenarioValid(t *testing.T) {
	text := string(readFixture(t, "reference-request.txt"))
	ctx := domain.TenantContext{AllowedRegions: []string{"eu-west-3", "francecentral"}}
	d := referenceDraft(t)

	for _, f := range domain.Check(text, d, ctx) {
		if f.Severity.Weight() >= loopsdomain.SeverityMedium.Weight() {
			t.Errorf("unexpected finding %+v", f)
		}
	}

	ir := d.ToIR(referenceTenant)
	want := decodeTree(t, readFixture(t, "reference-ir.json"))
	if got := asTree(t, ir); !reflect.DeepEqual(got, want) {
		t.Errorf("ToIR differs from reference-ir.json\n got: %v\nwant: %v", got, want)
	}

	if err := intent.ValidateIR(ir); err != nil {
		t.Errorf("ValidateIR: %v", err)
	}
	if cs := domain.Contradictions(ir, ctx); len(cs) != 0 {
		t.Errorf("want no contradiction, got %+v", cs)
	}
}
