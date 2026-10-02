package domain

import (
	"testing"

	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
)

// TestClassificationAnchoredToStrictest: ADR 0006 amendment A1.4, obligation
// (ci) (plan M1-intent-multilingual, P9, test 4). A declared classification is
// never less strict than the strictest one written in the text (public <
// internal < confidential < regulated): a weaker form written next to a
// stricter one does not anchor the weaker value, and the safe default
// confidential does not hold under regulated. Witnesses show that the rule
// does not reject a classification as strict as the text, nor a weak one when
// nothing stricter is written.
func TestClassificationAnchoredToStrictest(t *testing.T) {
	const (
		textInternalConfidentialEN = "A managed PostgreSQL database on Scaleway in fr-par, in production, with internal data for the logs and confidential customer data."
		textInternalConfidentialFR = "Une base PostgreSQL managée sur Scaleway en fr-par, en production, avec des journaux internes et des données clients confidentielles."
		textRegulatedConfidential  = "A managed PostgreSQL database on Scaleway in fr-par, in production, with regulated health data and confidential logs."
		textInternalOnly           = "A managed PostgreSQL database on Scaleway in fr-par, in production, with internal data for the logs."
		logsPath                   = "data[logs].classification"
	)
	ctx := TenantContext{}

	// withLogs adds a data set "logs" stored in the database of the C4 draft;
	// customer, when not empty, sets the classification of customer-data.
	withLogs := func(logs, customer string, regulation ...string) func(t *testing.T, m map[string]any) {
		return func(t *testing.T, m map[string]any) {
			if customer != "" {
				cd := item(t, m, "data", 0)
				cd["classification"] = customer
				regs := []any{}
				for _, r := range regulation {
					regs = append(regs, r)
				}
				cd["regulation"] = regs
			}
			m["data"] = append(list(t, m, "data"), map[string]any{
				"id": "logs", "classification": logs, "regulation": []any{}, "stored_in": []any{"db"}, "residency": nil,
			})
		}
	}

	rejected := []struct {
		name, text string
		edit       func(t *testing.T, m map[string]any)
	}{
		{"internal_below_confidential_en", textInternalConfidentialEN, withLogs("internal", "")},
		{"internal_below_confidential_fr", textInternalConfidentialFR, withLogs("internal", "")},
		{"confidential_below_regulated", textRegulatedConfidential, withLogs("confidential", "regulated", "health")},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			got := Check(tc.text, draftFrom(t, "drafts/c4-override.json", tc.edit), ctx)
			if !hasFinding(got, "INTENT-INVENTED-VALUE", loopsdomain.SeverityHigh, logsPath) {
				t.Errorf("want INTENT-INVENTED-VALUE high on %s, got %+v", logsPath, got)
			}
		})
	}

	witnesses := []struct {
		name, text string
		edit       func(t *testing.T, m map[string]any)
	}{
		{"witness_confidential_logs", textInternalConfidentialEN, withLogs("confidential", "")},
		{
			name: "witness_internal_only",
			text: textInternalOnly,
			edit: func(t *testing.T, m map[string]any) {
				m["data"] = []any{map[string]any{
					"id": "logs", "classification": "internal", "regulation": []any{}, "stored_in": []any{"db"}, "residency": nil,
				}}
			},
		},
	}
	for _, tc := range witnesses {
		t.Run(tc.name, func(t *testing.T) {
			if got := atLeastMedium(Check(tc.text, draftFrom(t, "drafts/c4-override.json", tc.edit), ctx)); len(got) != 0 {
				t.Errorf("want no finding medium or above, got %+v", got)
			}
		})
	}
}
