package domain

import (
	"strings"
	"testing"

	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
)

// Review of the M1 milestone (T102): a source restriction written by the user
// (an address or a prefix) may not disappear from the draft. Every address or
// prefix of the text must be an allowed source of an exposure, in canonical
// form (an address A as A/32 or A/128), or be captured in explicit_overrides;
// otherwise INTENT-EXPOSURE-SOURCES-OMITTED (high). The rule reads the whole
// text, never a sentence (T85c). The faithful form A/32 of an address A of the
// text is anchored (neither INTENT-TECHNICAL-VALUE nor INTENT-INVENTED-VALUE).

const codeSourcesOmitted = "INTENT-EXPOSURE-SOURCES-OMITTED"

func withSources(sources ...string) func(t *testing.T, m map[string]any) {
	return func(t *testing.T, m map[string]any) {
		list := make([]any, len(sources))
		for i, s := range sources {
			list[i] = s
		}
		item(t, m, "exposure", 0)["allowed_sources"] = list
	}
}

func withOverride(statement string) func(t *testing.T, m map[string]any) {
	return func(t *testing.T, m map[string]any) {
		m["explicit_overrides"] = []any{map[string]any{"statement": statement, "affects": "exposure"}}
	}
}

func TestExposureSourcesOmitted(t *testing.T) {
	fr := readText(t, "reference-request.txt")
	en := readText(t, "en/reference-request.txt")
	cases := map[string]struct {
		text, value string
		edit        func(t *testing.T, m map[string]any)
	}{
		"fr_address":           {fr + " L'application n'est accessible que depuis 203.0.113.10.", "203.0.113.10", nil},
		"fr_prefix":            {fr + " Seules les adresses 203.0.113.0/24 peuvent joindre l'application.", "203.0.113.0/24", nil},
		"fr_no_accents":        {fr + " Application accessible uniquement depuis 203.0.113.10, pas depuis le reste d'Internet.", "203.0.113.10", nil},
		"en_address":           {en + " The application is reachable only from 203.0.113.10.", "203.0.113.10", nil},
		"en_prefix":            {en + " Only 198.51.100.0/24 may reach the application.", "198.51.100.0/24", nil},
		"ipv6_prefix":          {fr + " Accès limité à 2001:db8:42::/48.", "2001:db8:42::/48", nil},
		"glued_to_a_key":       {fr + " Restriction source=203.0.113.10 sur l'application.", "203.0.113.10", nil},
		"other_sentence":       {fr + " Une seule adresse : 203.0.113.10. Elle seule joindra l'application.", "203.0.113.10", nil},
		"one_of_two_kept":      {fr + " Accès depuis 203.0.113.10 et 198.51.100.7 seulement.", "198.51.100.7", withSources("203.0.113.10/32")},
		"other_address_listed": {fr + " Accès depuis 203.0.113.10 seulement.", "203.0.113.10", withSources("203.0.113.11/32")},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := Check(tc.text, draftFrom(t, "reference-draft.json", tc.edit), TenantContext{})
			if !hasFinding(got, codeSourcesOmitted, loopsdomain.SeverityHigh, "exposure") {
				t.Errorf("want %s high on exposure, got %+v", codeSourcesOmitted, got)
			}
			for _, f := range got {
				if strings.Contains(f.Message, tc.value) || strings.Contains(f.Resource, tc.value) {
					t.Errorf("finding quotes the value: %+v", f)
				}
			}
		})
	}
}

func TestExposureSourcesKept(t *testing.T) {
	fr := readText(t, "reference-request.txt")
	cases := map[string]struct {
		text string
		edit func(t *testing.T, m map[string]any)
	}{
		"address_as_32":        {fr + " L'application n'est accessible que depuis 203.0.113.10.", withSources("203.0.113.10/32")},
		"ipv6_address_as_128":  {fr + " Accès limité à 2001:db8::10.", withSources("2001:db8::10/128")},
		"prefix":               {fr + " Seules les adresses 203.0.113.0/24 peuvent joindre l'application.", withSources("203.0.113.0/24")},
		"two_addresses":        {fr + " Accès depuis 203.0.113.10 et 198.51.100.7 seulement.", withSources("203.0.113.10/32", "198.51.100.7/32")},
		"captured_in_override": {fr + " L'application n'est accessible que depuis 203.0.113.10.", withOverride("restreindre l'accès à 203.0.113.10")},
		"glued_kept":           {fr + " Restriction source=203.0.113.10 sur l'application.", withSources("203.0.113.10/32")},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := Check(tc.text, draftFrom(t, "reference-draft.json", tc.edit), TenantContext{}); len(got) != 0 {
				t.Errorf("want no finding, got %+v", got)
			}
		})
	}
}

// TestExposureSourcesNoFalsePositive: text without an address or a prefix
// (versions, hours, ports, a double colon) needs no source.
func TestExposureSourcesNoFalsePositive(t *testing.T) {
	fr := readText(t, "reference-request.txt")
	for name, extra := range map[string]string{
		"version":      " Version 1.27 de Go, puis 2.3.4.",
		"hour":         " Maintenance à 12:30 ou 10:00:00.",
		"double_colon": " Note :: rien de plus.",
		"ratio":        " Disponibilité 99.9 et ratio 3/4.",
	} {
		t.Run(name, func(t *testing.T) {
			if got := Check(fr+extra, draftFrom(t, "reference-draft.json", nil), TenantContext{}); hasFinding(got, codeSourcesOmitted, loopsdomain.SeverityHigh, "") {
				t.Errorf("unexpected %s: %+v", codeSourcesOmitted, got)
			}
		})
	}
}
