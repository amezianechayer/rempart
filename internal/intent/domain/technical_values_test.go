package domain

import (
	"strings"
	"testing"

	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
)

// TestTechnicalValuesRejected: rule 7 of the intent-to-spec skill. The model
// describes needs; a CIDR, an IP address, an ASN or an IAM role in any string of
// the draft is refused, except in exposure[].allowed_sources (canonical prefix)
// and explicit_overrides[].statement, and there only if the value is written
// in the user's text. Findings never quote the value (plan P6).
func TestTechnicalValuesRejected(t *testing.T) {
	text := readText(t, "reference-request.txt")
	ctx := TenantContext{}

	cases := []struct {
		name  string
		text  string
		value string
		edit  func(t *testing.T, m map[string]any)
	}{
		{
			name:  "ipv4_cidr_in_notes",
			value: "10.0.0.0/16",
			edit: func(t *testing.T, m map[string]any) {
				item(t, m, "workloads", wAppCluster)["notes"] = "réseau 10.0.0.0/16 pour le cluster"
			},
		},
		{
			name:  "ipv6_cidr_in_purpose",
			value: "fd00::/8",
			edit: func(t *testing.T, m map[string]any) {
				item(t, m, "connectivity", 0)["purpose"] = "plage fd00::/8 côté Azure"
			},
		},
		{
			name:  "asn_in_summary",
			value: "AS64512",
			edit: func(t *testing.T, m map[string]any) {
				m["summary"] = str(t, m, "summary") + " Annonce BGP depuis AS64512."
			},
		},
		{
			name:  "iam_role_in_justification",
			value: "arn:aws:iam::123456789012:role/admin",
			edit: func(t *testing.T, m map[string]any) {
				item(t, m, "exposure", 0)["justification"] = "accès par arn:aws:iam::123456789012:role/admin"
			},
		},
		{
			name:  "allowed_sources_not_in_text",
			value: "198.51.100.0/24",
			edit: func(t *testing.T, m map[string]any) {
				item(t, m, "exposure", 0)["allowed_sources"] = []any{"198.51.100.0/24"}
			},
		},
		{
			name:  "allowed_sources_not_canonical",
			text:  text + " Seules les adresses 203.0.113.1/24 peuvent joindre l'application.",
			value: "203.0.113.1/24",
			edit: func(t *testing.T, m map[string]any) {
				item(t, m, "exposure", 0)["allowed_sources"] = []any{"203.0.113.1/24"}
			},
		},
		{
			name:  "override_not_in_text",
			value: "198.51.100.0/24",
			edit: func(t *testing.T, m map[string]any) {
				m["explicit_overrides"] = []any{map[string]any{
					"statement": "ouvrir l'application à 198.51.100.0/24",
					"affects":   "exposure",
				}}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			txt := tc.text
			if txt == "" {
				txt = text
			}
			got := Check(txt, draftFrom(t, "reference-draft.json", tc.edit), ctx)
			if !hasFinding(got, "INTENT-TECHNICAL-VALUE", loopsdomain.SeverityHigh, "") {
				t.Errorf("want INTENT-TECHNICAL-VALUE high, got %+v", got)
			}
			for _, f := range got {
				if strings.Contains(f.Message, tc.value) || strings.Contains(f.Resource, tc.value) {
					t.Errorf("finding quotes the technical value: %+v", f)
				}
			}
		})
	}

	t.Run("witness_anchored_in_both_places", func(t *testing.T) {
		txt := text + " Seules les adresses 203.0.113.0/24 peuvent joindre l'application."
		d := draftFrom(t, "reference-draft.json", func(t *testing.T, m map[string]any) {
			item(t, m, "exposure", 0)["allowed_sources"] = []any{"203.0.113.0/24"}
			m["explicit_overrides"] = []any{map[string]any{
				"statement": "restreindre l'accès à 203.0.113.0/24",
				"affects":   "exposure",
			}}
		})
		if got := Check(txt, d, ctx); len(got) != 0 {
			t.Errorf("want no finding, got %+v", got)
		}
	})
}
