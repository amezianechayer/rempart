package intent_test

import (
	"errors"
	"testing"

	"github.com/amezianechayer/rempart/internal/intent"
	"github.com/amezianechayer/rempart/internal/intent/domain"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

// TestDraftWithTenantIDRejected: rule 9 of the intent-to-spec skill, threat T3.
// The model never produces the tenant: a tenant key at any depth, under any
// spelling, or an assumption aimed at it, is refused; the tenant of the IR is
// the one injected by the caller, and only a customer tenant validates.
func TestDraftWithTenantIDRejected(t *testing.T) {
	for _, tc := range []struct{ name, fixture string }{
		{"top_level", "drafts/tenant-top-level.json"},
		{"nested_in_workload", "drafts/tenant-nested-in-workload.json"},
		{"camel_case", "drafts/tenant-camel-case.json"},
		{"assumption_field", "drafts/tenant-assumption-field.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := intent.ParseDraft(readFixture(t, tc.fixture))
			if !errors.Is(err, domain.ErrTenantFromModel) {
				t.Errorf("want ErrTenantFromModel, got %v", err)
			}
		})
	}

	t.Run("tenant_injected", func(t *testing.T) {
		const x = "7d9e1c2b-3a4f-4b5c-8d6e-0f1a2b3c4d5e"
		ir := referenceDraft(t).ToIR(x)
		if ir.TenantID != x {
			t.Errorf("ToIR: TenantID = %q, want %q", ir.TenantID, x)
		}
		if err := intent.ValidateIR(ir); err != nil {
			t.Errorf("ValidateIR with a customer tenant: %v", err)
		}
	})

	for _, tc := range []struct{ name, tenant string }{
		{"system", string(tenancy.System)},
		{"uuid_v7", "01890a5d-ac96-774b-bcce-b302099a8057"},
		{"upper_case", "3F6C2A9E-8B1D-4C7A-9E2F-5D4B3A2C1E0F"},
	} {
		t.Run("validate_refuses_"+tc.name, func(t *testing.T) {
			err := intent.ValidateIR(referenceDraft(t).ToIR(tc.tenant))
			if !errors.Is(err, intent.ErrIRInvalid) {
				t.Errorf("want ErrIRInvalid, got %v", err)
			}
		})
	}
}
