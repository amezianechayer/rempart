package domain

import (
	"testing"

	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
)

// TestReferencesMustExist: rule 10 of the intent-to-spec skill. Every reference
// to a workload names an existing workload, and workload ids are unique.
func TestReferencesMustExist(t *testing.T) {
	text := readText(t, "reference-request.txt")
	ctx := TenantContext{}

	base := Check(text, draftFrom(t, "reference-draft.json", nil), ctx)
	for _, f := range base {
		if f.Code == "INTENT-REF-UNKNOWN" || f.Code == "INTENT-REF-DUPLICATE" {
			t.Fatalf("reference draft: unexpected finding %+v", f)
		}
	}

	cases := []struct {
		name     string
		edit     func(t *testing.T, m map[string]any)
		code     string
		resource string
	}{
		{
			name:     "stored_in",
			edit:     func(t *testing.T, m map[string]any) { item(t, m, "data", 0)["stored_in"] = []any{"ghost"} },
			code:     "INTENT-REF-UNKNOWN",
			resource: "data[customer-db].stored_in",
		},
		{
			name:     "runs_on",
			edit:     func(t *testing.T, m map[string]any) { item(t, m, "workloads", wObs)["runs_on"] = "ghost" },
			code:     "INTENT-REF-UNKNOWN",
			resource: "workloads[obs].runs_on",
		},
		{
			name:     "connectivity_from",
			edit:     func(t *testing.T, m map[string]any) { item(t, m, "connectivity", 0)["from"] = "ghost" },
			code:     "INTENT-REF-UNKNOWN",
			resource: "connectivity[0].from",
		},
		{
			name:     "connectivity_to",
			edit:     func(t *testing.T, m map[string]any) { item(t, m, "connectivity", 0)["to"] = "ghost" },
			code:     "INTENT-REF-UNKNOWN",
			resource: "connectivity[0].to",
		},
		{
			name:     "exposure_workload",
			edit:     func(t *testing.T, m map[string]any) { item(t, m, "exposure", 0)["workload"] = "ghost" },
			code:     "INTENT-REF-UNKNOWN",
			resource: "exposure[0].workload",
		},
		{
			name: "duplicate_workload",
			edit: func(t *testing.T, m map[string]any) { item(t, m, "workloads", wGitops)["id"] = "obs" },
			code: "INTENT-REF-DUPLICATE",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Check(text, draftFrom(t, "reference-draft.json", tc.edit), ctx)
			if !hasFinding(got, tc.code, loopsdomain.SeverityHigh, tc.resource) {
				t.Errorf("want %s high on %q, got %+v", tc.code, tc.resource, got)
			}
		})
	}
}
