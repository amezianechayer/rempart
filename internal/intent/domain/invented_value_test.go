package domain

import (
	"testing"

	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
)

// TestInventedValueDetected: rules 2 and 3 of the intent-to-spec skill, ADR 0006
// decision 2. The value of a controlled path is anchored in the text, assumed
// with exactly that value, or a safe default; otherwise INTENT-INVENTED-VALUE.
// An assumption on a blocking field (cloud, region outside the allowed ones,
// classification weaker than confidential) is INTENT-BLOCKING-ASSUMED.
func TestInventedValueDetected(t *testing.T) {
	text := readText(t, "reference-request.txt")
	ctx := TenantContext{}

	if got := atLeastMedium(Check(text, draftFrom(t, "reference-draft.json", nil), ctx)); len(got) != 0 {
		t.Fatalf("reference draft: want no finding medium or above, got %+v", got)
	}

	invented := []struct {
		name string
		path string
		edit func(m map[string]any)
	}{
		{
			name: "region_not_in_text",
			path: "workloads[app-cluster].region",
			edit: func(m map[string]any) { item(m, "workloads", wAppCluster)["region"] = "eu-central-1" },
		},
		{
			name: "size_count",
			path: "workloads[app-cluster].size.count",
			edit: func(m map[string]any) {
				item(m, "workloads", wAppCluster)["size"].(map[string]any)["count"] = 5
			},
		},
		{
			name: "port",
			path: "connectivity[0].ports",
			edit: func(m map[string]any) {
				c := item(m, "connectivity", 0)
				c["ports"] = append(c["ports"].([]any), "tcp/6379")
			},
		},
		{
			name: "classification_public",
			path: "data[customer-db].classification",
			edit: func(m map[string]any) { item(m, "data", 0)["classification"] = "public" },
		},
		{
			name: "compliance_dora",
			path: "compliance",
			edit: func(m map[string]any) { m["compliance"] = []any{"nis2", "dora"} },
		},
		{
			name: "budget",
			path: "constraints.monthly_budget_eur",
			edit: func(m map[string]any) { m["constraints"].(map[string]any)["monthly_budget_eur"] = 3000 },
		},
		{
			name: "environment_without_assumption",
			path: "environment",
			edit: func(m map[string]any) {
				m["environment"] = "prod"
				dropAssumption(m, "environment")
			},
		},
		{
			name: "retention_without_assumption",
			path: "observability.retention_days",
			edit: func(m map[string]any) {
				m["observability"].(map[string]any)["retention_days"] = 30
				dropAssumption(m, "observability.retention_days")
			},
		},
		{
			name: "criticality_low",
			path: "workloads[gitops].criticality",
			edit: func(m map[string]any) { item(m, "workloads", wGitops)["criticality"] = "low" },
		},
		{
			name: "assumption_same_path_other_value_environment",
			path: "environment",
			edit: func(m map[string]any) { m["environment"] = "prod" }, // assumption says staging
		},
		{
			name: "assumption_same_path_other_value_retention",
			path: "observability.retention_days",
			edit: func(m map[string]any) {
				m["observability"].(map[string]any)["retention_days"] = 30 // assumption says 90
			},
		},
	}
	for _, tc := range invented {
		t.Run(tc.name, func(t *testing.T) {
			got := Check(text, draftFrom(t, "reference-draft.json", tc.edit), ctx)
			if !hasFinding(got, "INTENT-INVENTED-VALUE", loopsdomain.SeverityHigh, tc.path) {
				t.Errorf("want INTENT-INVENTED-VALUE high on %q, got %+v", tc.path, got)
			}
		})
	}

	accepted := []struct {
		name string
		edit func(m map[string]any)
	}{
		{
			name: "exact_assumption",
			edit: func(m map[string]any) {
				m["environment"] = "prod"
				setAssumption(m, "environment", "prod")
			},
		},
		{
			name: "criticality_high_safe_default",
			edit: func(m map[string]any) {
				item(m, "workloads", wLegacyVMs)["criticality"] = "high"
				dropAssumption(m, "workloads[legacy-vms].criticality")
			},
		},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			got := atLeastMedium(Check(text, draftFrom(t, "reference-draft.json", tc.edit), ctx))
			if len(got) != 0 {
				t.Errorf("want no finding medium or above, got %+v", got)
			}
		})
	}

	blocking := []struct {
		name string
		path string
		edit func(m map[string]any)
	}{
		{
			name: "assumed_cloud",
			path: "workloads[legacy-vms].cloud",
			edit: func(m map[string]any) { setAssumption(m, "workloads[legacy-vms].cloud", "azure") },
		},
		{
			name: "assumed_region_not_allowed",
			path: "workloads[legacy-vms].region",
			edit: func(m map[string]any) {
				item(m, "workloads", wLegacyVMs)["region"] = "westeurope"
				setAssumption(m, "workloads[legacy-vms].region", "westeurope")
			},
		},
		{
			name: "assumed_classification_internal",
			path: "data[customer-db].classification",
			edit: func(m map[string]any) {
				item(m, "data", 0)["classification"] = "internal"
				setAssumption(m, "data[customer-db].classification", "internal")
			},
		},
	}
	for _, tc := range blocking {
		t.Run(tc.name, func(t *testing.T) {
			got := Check(text, draftFrom(t, "reference-draft.json", tc.edit), ctx)
			if !hasFinding(got, "INTENT-BLOCKING-ASSUMED", loopsdomain.SeverityMedium, tc.path) {
				t.Errorf("want INTENT-BLOCKING-ASSUMED medium on %q, got %+v", tc.path, got)
			}
		})
	}
}
