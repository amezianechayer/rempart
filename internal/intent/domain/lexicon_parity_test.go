package domain

import (
	"slices"
	"testing"
)

// TestEnglishLexiconParity: ADR 0006 amendment A1.1 (plan M1-intent-multilingual,
// P1, P2, P11, section 6.1, test 2). The closed lexicon covers English as it
// covers French: (a) every value with a French form has an English or common
// form, the database and exposure markers exist in both languages, and no form
// is listed as both French and English; (b) the English reference request with
// the reference draft passes every check; (c) the English forms anchor their
// value, and the conservative ones ("public data", "internal data") do not
// anchor on a single ambiguous word.
func TestEnglishLexiconParity(t *testing.T) {
	t.Run("structure", func(t *testing.T) {
		parity := map[string]lexDomain{
			"environment": lexEnvironment, "criticality": lexCriticality, "tier": lexTier,
			"classification": lexClass, "regulation": lexRegulation, "residency": lexResidency,
		}
		for name, d := range parity {
			for v, f := range d {
				if len(f.fr) > 0 && len(f.en)+len(f.any) == 0 {
					t.Errorf("%s[%s]: French forms %v without an English or common form", name, v, f.fr)
				}
			}
		}
		for name, f := range map[string]forms{"databaseMarkers": databaseMarkers, "exposureMarkers": exposureMarkers} {
			if len(f.fr) == 0 || len(f.en) == 0 {
				t.Errorf("%s: want French and English forms, got fr=%v en=%v", name, f.fr, f.en)
			}
		}

		all := map[string]lexDomain{
			"cloud": lexCloud, "environment": lexEnvironment, "criticality": lexCriticality, "tier": lexTier,
			"os": lexOS, "protocol": lexProtocol, "classification": lexClass, "regulation": lexRegulation,
			"residency": lexResidency, "compliance": lexCompliance, "observability": lexObservability,
		}
		disjoint := func(name string, f forms) {
			for _, x := range f.fr {
				if slices.Contains(f.en, x) {
					t.Errorf("%s: form %q is both French and English", name, x)
				}
			}
		}
		for name, d := range all {
			for v, f := range d {
				disjoint(name+"["+v+"]", f)
			}
		}
		disjoint("databaseMarkers", databaseMarkers)
		disjoint("exposureMarkers", exposureMarkers)
	})

	t.Run("english_reference_passes", func(t *testing.T) {
		text := readText(t, "en/reference-request.txt")
		if got := atLeastMedium(Check(text, draftFrom(t, "reference-draft.json", nil), TenantContext{})); len(got) != 0 {
			t.Errorf("want no finding medium or above, got %+v", got)
		}
	})

	t.Run("anchoring", func(t *testing.T) {
		cases := []struct {
			name, text, value string
			dom               lexDomain
			want              bool
		}{
			{"critical", "a critical workload", "high", lexCriticality, true},
			{"large", "three large nodes", "large", lexTier, true},
			{"development", "a development environment", "dev", lexEnvironment, true},
			{"pre-production", "a pre-production environment", "staging", lexEnvironment, true},
			{"healthcare", "healthcare records", "health", lexRegulation, true},
			{"banking", "banking records", "financial", lexRegulation, true},
			{"regulated", "regulated records", "regulated", lexClass, true},
			{"internal_data", "internal data for the logs", "internal", lexClass, true},
			{"public_data", "public data for the site", "public", lexClass, true},
			{"european", "a european residency", "eu", lexResidency, true},
			{"cloudwatch", "logs in cloudwatch", "cloud_native", lexObservability, true},
			{"public_alone", "a public web application", "public", lexClass, false},
			{"internal_network", "an internal network", "internal", lexClass, false},
		}
		for _, tc := range cases {
			if got := newIndex(tc.text).anchoredIn(tc.dom, tc.value); got != tc.want {
				t.Errorf("%s: anchoredIn(%q, %q) = %v, want %v", tc.name, tc.text, tc.value, got, tc.want)
			}
		}
	})
}
