package domain

import (
	"fmt"
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
		// Second review pass: forms glued to a key by ':', with a port,
		// unreadable (leading zeros) fail closed unless captured verbatim.
		"colon_key_ip":              {fr + " Accès réservé à ip:203.0.113.10.", "203.0.113.10", nil},
		"colon_key_source":          {fr + " Restriction source:203.0.113.10 sur l'application.", "203.0.113.10", nil},
		"colon_key_cidr":            {fr + " Accès réservé à cidr:203.0.113.0/24.", "203.0.113.0/24", nil},
		"colon_key_word":            {fr + " Accès depuis:203.0.113.10 seulement.", "203.0.113.10", nil},
		"with_port":                 {fr + " Accès depuis 203.0.113.10:443 seulement.", "203.0.113.10", nil},
		"key_and_port":              {fr + " Accès réservé à source:203.0.113.10:443.", "203.0.113.10", nil},
		"ipv6_colon_key":            {fr + " Accès réservé à ip:2001:db8::10.", "2001:db8::10", nil},
		"leading_zeros":             {fr + " Accès depuis 203.000.113.010 seulement.", "203.000.113.010", nil},
		"five_parts":                {fr + " Accès depuis 203.0.113.10.5 seulement.", "203.0.113.10.5", nil},
		"leading_zeros_with_source": {fr + " Accès depuis 203.000.113.010 seulement.", "203.000.113.010", withSources("203.0.113.10/32")},
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
		"colon_key_kept":       {fr + " Restriction source:203.0.113.10 sur l'application.", withSources("203.0.113.10/32")},
		"colon_key_cidr_kept":  {fr + " L'accès à l'application est réservé à cidr:203.0.113.0/24.", withSources("203.0.113.0/24")},
		"port_kept":            {fr + " Accès depuis 203.0.113.10:443 seulement.", withSources("203.0.113.10/32")},
		"ipv6_colon_key_kept":  {fr + " Accès réservé à ip:2001:db8::10.", withSources("2001:db8::10/128")},
		"unreadable_override":  {fr + " Accès depuis 203.000.113.010 seulement.", withOverride("restreindre l'accès à 203.000.113.010")},
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
		"date":         " Mise en service le 18.11.2026 à 10:30:15.",
		"amount":       " Plafond de 1.500.000 euros.",
		"port_alone":   " Service sur le port :8443.",
		"uuid":         " Référence 7c9e6679-7425-40de-944b-e07fc1f90ae7.",
	} {
		t.Run(name, func(t *testing.T) {
			if got := Check(fr+extra, draftFrom(t, "reference-draft.json", nil), TenantContext{}); hasFinding(got, codeSourcesOmitted, loopsdomain.SeverityHigh, "") {
				t.Errorf("unexpected %s: %+v", codeSourcesOmitted, got)
			}
		})
	}
}

// TestExposureSourcesNonASCIISeparators (obligation (ez)): an address written
// with a dot look-alike (U+2024, U+FF0E, U+00B7, U+3002, U+FE52) is read as
// the address: dropped, it fails (or the language escalates); kept as /32,
// it is anchored.
func TestExposureSourcesNonASCIISeparators(t *testing.T) {
	fr := readText(t, "reference-request.txt")
	for _, sep := range []string{"․", "．", "·", "。", "﹒"} {
		addr := strings.Join([]string{"203", "0", "113", "10"}, sep)
		text := fr + " L'application n'est accessible que depuis " + addr + " et rien d'autre."
		t.Run(fmt.Sprintf("U+%04X", []rune(sep)[0]), func(t *testing.T) {
			got := Check(text, draftFrom(t, "reference-draft.json", nil), TenantContext{})
			if !hasFinding(got, codeSourcesOmitted, loopsdomain.SeverityHigh, "exposure") && !hasFinding(got, CodeLanguageUnsupported, loopsdomain.SeverityHigh, "") {
				t.Errorf("dropped restriction: want %s or the language refused, got %+v", codeSourcesOmitted, got)
			}
			kept := Check(text, draftFrom(t, "reference-draft.json", withSources("203.0.113.10/32")), TenantContext{})
			for _, f := range kept {
				if f.Code == codeSourcesOmitted || f.Code == "INTENT-TECHNICAL-VALUE" || f.Code == "INTENT-INVENTED-VALUE" {
					t.Errorf("kept restriction refused: %+v", kept)
				}
			}
		})
	}
}

// TestExposureSourcesDefanged (obligation (ez)): a defanged address
// ([.], (.), [:]), with spaced dots or commas, is read as the address.
func TestExposureSourcesDefanged(t *testing.T) {
	fr := readText(t, "reference-request.txt")
	for name, tc := range map[string]struct{ written, source string }{
		"brackets":      {"203[.]0[.]113[.]10", "203.0.113.10/32"},
		"parentheses":   {"203(.)0(.)113(.)10", "203.0.113.10/32"},
		"spaced_dots":   {"203 . 0 . 113 . 10", "203.0.113.10/32"},
		"commas":        {"203,0,113,10", "203.0.113.10/32"},
		"ipv6_brackets": {"2001[:]db8[:][:]10", "2001:db8::10/128"},
		"prefix":        {"198[.]51[.]100[.]0/24", "198.51.100.0/24"},
	} {
		text := fr + " L'application n'est accessible que depuis " + tc.written + " et rien d'autre."
		t.Run(name, func(t *testing.T) {
			got := Check(text, draftFrom(t, "reference-draft.json", nil), TenantContext{})
			if !hasFinding(got, codeSourcesOmitted, loopsdomain.SeverityHigh, "exposure") {
				t.Errorf("dropped restriction: want %s, got %+v", codeSourcesOmitted, got)
			}
			if kept := Check(text, draftFrom(t, "reference-draft.json", withSources(tc.source)), TenantContext{}); len(kept) != 0 {
				t.Errorf("kept restriction: want no finding, got %+v", kept)
			}
		})
	}
	t.Run("amounts_and_versions_untouched", func(t *testing.T) {
		text := fr + " Version 2.4 du service, quota de 1,5 To et 99,9 de disponibilité."
		if got := Check(text, draftFrom(t, "reference-draft.json", nil), TenantContext{}); hasFinding(got, codeSourcesOmitted, loopsdomain.SeverityHigh, "") {
			t.Errorf("unexpected %s: %+v", codeSourcesOmitted, got)
		}
	})
}

// TestExposureSourcesRearmNeverRemoves (review of M2-T01): the rereading of
// the separators never removes a reading of the original text: two addresses
// at a sentence end, or an address followed by a list of numbers, stay
// readable, and their faithful form is anchored.
func TestExposureSourcesRearmNeverRemoves(t *testing.T) {
	fr := readText(t, "reference-request.txt")
	for name, tc := range map[string]struct {
		written string
		sources []string
	}{
		"sentence_end":   {"203.0.113.10. 198.51.100.7 doit aussi y accéder", []string{"203.0.113.10/32", "198.51.100.7/32"}},
		"list_after":     {"192.168.1.1,2,3,4 et rien d'autre", []string{"192.168.1.1/32"}},
		"spaced_one_end": {"203.0.113.10 .5 de marge", []string{"203.0.113.10/32"}},
	} {
		text := fr + " L'application n'est accessible que depuis " + tc.written + "."
		t.Run(name, func(t *testing.T) {
			if got := Check(text, draftFrom(t, "reference-draft.json", withSources(tc.sources...)), TenantContext{}); len(got) != 0 {
				t.Errorf("faithful draft refused: %+v", got)
			}
			if got := Check(text, draftFrom(t, "reference-draft.json", nil), TenantContext{}); !hasFinding(got, codeSourcesOmitted, loopsdomain.SeverityHigh, "exposure") {
				t.Errorf("dropped restriction: want %s, got %+v", codeSourcesOmitted, got)
			}
		})
	}
}

// TestCitesAddress proves ADR 0012 D4 and obligation (ey): the reader of L1,
// exported, says whether a text cites an address or a prefix, rearmed forms
// and unreadable address-like tokens included (fail closed); a text without
// one, ports and versions included, does not.
func TestCitesAddress(t *testing.T) {
	for _, s := range []string{
		"autoriser seulement 203.0.113.10",
		"restreindre au bureau 198.51.100.0/24",
		"source 203[.]0[.]113[.]10",
		"allow 2001:db8::1 only",
		"bureau 203 . 0 . 113 . 10",
		"accès depuis 203,0,113,10",
		"source 999.1.2.3.4",
	} {
		if !CitesAddress(s) {
			t.Errorf("CitesAddress(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "exposer en https sur le port 443", "version 1.2 du schéma", "à 10:30 le matin", "ouvert à tous"} {
		if CitesAddress(s) {
			t.Errorf("CitesAddress(%q) = true, want false", s)
		}
	}
}
