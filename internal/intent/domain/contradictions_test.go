package domain

import (
	"testing"
)

// TestContradictionsDetected: rule 5 of the intent-to-spec skill, ADR 0006
// decision 3. Contradictions are computed in code on the IR and the tenant
// context; each names a path and proposes a non-empty safe default. The EU
// zone comes from a closed table (London and Zurich are outside), never from
// the "eu-" prefix.
func TestContradictionsDetected(t *testing.T) {
	allowed := TenantContext{AllowedRegions: []string{"eu-west-3", "francecentral"}}
	for name, c := range map[string]TenantContext{"empty_context": {}, "allowed_regions": allowed} {
		t.Run("reference_"+name, func(t *testing.T) {
			if got := Contradictions(irFrom(t, "reference-ir.json", nil), c); len(got) != 0 {
				t.Errorf("reference IR: want no contradiction, got %+v", got)
			}
		})
	}

	legacyRegion := func(r string) func(t *testing.T, m map[string]any) {
		return func(t *testing.T, m map[string]any) { item(t, m, "workloads", wLegacyVMs)["region"] = r }
	}
	cases := []struct {
		name  string
		ctx   TenantContext
		edit  func(t *testing.T, m map[string]any)
		code  string
		field string
	}{
		{
			name:  "residency_eu_in_us_east_1",
			edit:  legacyRegion("us-east-1"),
			code:  "CONTRA-RESIDENCY",
			field: "workloads[legacy-vms].region",
		},
		{
			name:  "residency_eu_in_london",
			edit:  legacyRegion("eu-west-2"),
			code:  "CONTRA-RESIDENCY",
			field: "workloads[legacy-vms].region",
		},
		{
			name:  "residency_eu_in_zurich",
			edit:  legacyRegion("eu-central-2"),
			code:  "CONTRA-RESIDENCY",
			field: "workloads[legacy-vms].region",
		},
		{
			name: "residency_fr_in_frankfurt",
			edit: func(t *testing.T, m map[string]any) {
				item(t, m, "data", 0)["residency"] = "fr"
				item(t, m, "workloads", wLegacyVMs)["region"] = "eu-central-1"
			},
			code:  "CONTRA-RESIDENCY",
			field: "workloads[legacy-vms].region",
		},
		{
			name:  "region_not_allowed_by_tenant",
			ctx:   TenantContext{AllowedRegions: []string{"eu-west-3"}},
			code:  "CONTRA-REGION-NOT-ALLOWED",
			field: "workloads[legacy-vms].region",
		},
		{
			name:  "forbidden_cloud_in_context",
			ctx:   TenantContext{ForbiddenClouds: []string{"azure"}},
			code:  "CONTRA-FORBIDDEN-CLOUD",
			field: "workloads[legacy-vms].cloud",
		},
		{
			name: "forbidden_cloud_in_constraints",
			edit: func(t *testing.T, m map[string]any) {
				obj(t, m, "constraints")["forbidden_clouds"] = []any{"azure"}
			},
			code:  "CONTRA-FORBIDDEN-CLOUD",
			field: "workloads[legacy-vms].cloud",
		},
		{
			name:  "runs_on_vm_group",
			edit:  func(t *testing.T, m map[string]any) { item(t, m, "workloads", wObs)["runs_on"] = "legacy-vms" },
			code:  "CONTRA-RUNS-ON-NOT-CLUSTER",
			field: "workloads[obs].runs_on",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Contradictions(irFrom(t, "reference-ir.json", tc.edit), tc.ctx)
			found := false
			for _, c := range got {
				if c.Default == "" {
					t.Errorf("contradiction without a safe default: %+v", c)
				}
				if c.Code == tc.code && c.Field == tc.field {
					found = true
				}
			}
			if !found {
				t.Errorf("want %s on %q, got %+v", tc.code, tc.field, got)
			}
		})
	}
}
