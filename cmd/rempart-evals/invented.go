package main

import (
	"net/netip"
	"strconv"
	"strings"
	"unicode"

	intentdomain "github.com/amezianechayer/rempart/internal/intent/domain"
)

// Oracle of invented_values (criterion 1 of prompts/M1.md, review of M1-T06):
// the controlled values of a delivered IR that the request does not state and
// that no assumption nor open question declares. It is written for the
// evaluation (CODEOWNERS) and independent of the checks of internal/intent:
// its own folding, its own synonyms, its own list of controlled values, so
// that a weakened check of L1 shows in the metric instead of hiding in it.

var oracleFold = strings.NewReplacer(
	"à", "a", "â", "a", "ä", "a", "ç", "c", "é", "e", "è", "e", "ê", "e", "ë", "e",
	"î", "i", "ï", "i", "ô", "o", "ö", "o", "ù", "u", "û", "u", "ü", "u", "ÿ", "y", "œ", "oe", "æ", "ae",
)

// oracleSynonyms are the words that state an enumerated value, folded.
var oracleSynonyms = map[string][]string{
	"aws": words("aws amazon"), "azure": words("azure"), "scaleway": words("scaleway"), "ovhcloud": words("ovhcloud ovh"),
	"prod": words("prod production"), "staging": words("staging preprod pre-production recette"),
	"dev":   words("dev developpement development"),
	"small": words("small petite petites petit petits"), "medium": words("medium moyenne moyennes moyen moyens"),
	"large": words("large grande grandes grand grands"), "xlarge": words("xlarge"),
	"low": words("low faible basse"), "high": words("high haute critique critical"),
	"linux": words("linux"), "windows": words("windows"),
	"public": words("public publique publiques publics"), "internal": words("internal interne internes"),
	"confidential": words("confidential confidentiel confidentielle confidentielles confidentiels"),
	"regulated":    words("regulated reglemente reglementee reglementees reglementes"),
	"gdpr":         words("gdpr rgpd"), "eu": words("eu ue europe european europeen europeenne europeens europeennes"),
	"fr": words("france fr"),
}

var oracleNumbers = map[int][]string{
	1: words("un une one"), 2: words("deux two"), 3: words("trois three"), 4: words("quatre four"), 5: words("cinq five"),
	6: words("six"), 7: words("sept seven"), 8: words("huit eight"), 9: words("neuf nine"), 10: words("dix ten"),
}

// words splits a list of synonyms (no composite literal with an elided type,
// read as unkeyed by the rule loops-keyed-literals).
func words(s string) []string { return strings.Fields(s) }

var oracleStandardPorts = map[string]int{"https": 443, "http": 80}

type oracleText map[string]bool

func newOracleText(request string) oracleText {
	words := oracleText{}
	t := oracleFold.Replace(strings.ToLower(request))
	for _, w := range strings.FieldsFunc(t, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '.' }) {
		if w = strings.Trim(w, ".-"); w != "" {
			words[w] = true
		}
	}
	return words
}

// states reports whether the request states the value v.
func (t oracleText) states(v string) bool {
	v = oracleFold.Replace(strings.ToLower(v))
	if t[v] {
		return true
	}
	for _, s := range oracleSynonyms[v] {
		if t[s] {
			return true
		}
	}
	return false
}

func (t oracleText) statesNumber(n int) bool {
	if t[strconv.Itoa(n)] {
		return true
	}
	for _, s := range oracleNumbers[n] {
		if t[s] {
			return true
		}
	}
	return false
}

// inventedValues counts the invented values of ir for request.
func inventedValues(request string, ir intentdomain.IR) int {
	t := newOracleText(request)
	sources := oracleSources(request)
	declared := func(field, value string) bool {
		for _, a := range ir.Assumptions {
			if a.Field == field && a.Value == value {
				return true
			}
		}
		for _, q := range ir.OpenQuestions {
			if q.Field == field {
				return true
			}
		}
		return false
	}
	n := 0
	check := func(field, value string, ok bool) {
		if !ok && !declared(field, value) {
			n++
		}
	}
	str := func(field, v string) { check(field, v, t.states(v)) }
	num := func(field string, v int) { check(field, strconv.Itoa(v), t.statesNumber(v)) }

	if ir.Environment != "" {
		str("environment", ir.Environment)
	}
	for _, w := range ir.Workloads {
		p := "workloads[" + w.ID + "]."
		str(p+"cloud", w.Cloud)
		str(p+"region", w.Region)
		check(p+"criticality", w.Criticality, w.Criticality == "high" || t.states(w.Criticality)) // high: safe default
		if s := w.Size; s != nil {
			if s.Count != nil {
				num(p+"size.count", *s.Count)
			}
			if s.Tier != nil {
				str(p+"size.tier", *s.Tier)
			}
			if s.OS != nil {
				str(p+"size.os", *s.OS)
			}
		}
	}
	for i, l := range ir.Connectivity {
		for _, port := range l.Ports {
			_, nums, _ := strings.Cut(port, "/")
			ok := true
			for _, part := range strings.Split(nums, "-") {
				v, err := strconv.Atoi(part)
				ok = ok && err == nil && t.statesNumber(v)
			}
			check("connectivity["+strconv.Itoa(i)+"].ports", port, ok)
		}
	}
	for i, e := range ir.Exposure {
		p := "exposure[" + strconv.Itoa(i) + "]."
		str(p+"protocol", e.Protocol)
		if e.Port != nil {
			std, has := oracleStandardPorts[e.Protocol]
			check(p+"port", strconv.Itoa(*e.Port), t.statesNumber(*e.Port) || has && std == *e.Port && t.states(e.Protocol))
		}
		for _, s := range e.AllowedSources {
			src, err := netip.ParsePrefix(s)
			check(p+"allowed_sources", s, err == nil && src == src.Masked() && sources[src.String()])
		}
	}
	for _, d := range ir.Data {
		p := "data[" + d.ID + "]."
		check(p+"classification", d.Classification, d.Classification == "confidential" || t.states(d.Classification)) // confidential: safe default
		for _, r := range d.Regulation {
			str(p+"regulation", r)
		}
		if d.Residency != nil {
			str(p+"residency", *d.Residency)
		}
	}
	if o := ir.Observability; o != nil {
		for name, v := range map[string]*string{"metrics": o.Metrics, "logs": o.Logs, "dashboards": o.Dashboards} {
			if v != nil {
				str("observability."+name, *v)
			}
		}
		if o.RetentionDays != nil {
			num("observability.retention_days", *o.RetentionDays)
		}
	}
	for _, c := range ir.Compliance {
		str("compliance", c)
	}
	if b := ir.Constraints.MonthlyBudgetEUR; b != nil {
		v := strconv.FormatFloat(*b, 'f', -1, 64)
		check("constraints.monthly_budget_eur", v, t[v])
	}
	for _, r := range ir.Constraints.AllowedRegions {
		str("constraints.allowed_regions", r)
	}
	for _, c := range ir.Constraints.ForbiddenClouds {
		str("constraints.forbidden_clouds", c)
	}
	return n
}

// oracleSources returns the allowed sources a request states, in the form of
// a canonical prefix: each prefix written, masked, and each address written,
// as a /32 or /128. Its own cut of the text: whitespace and punctuation, a
// key glued by "=".
func oracleSources(request string) map[string]bool {
	out := map[string]bool{}
	cut := func(r rune) bool { return unicode.IsSpace(r) || strings.ContainsRune(",;()[]{}\"'«»=", r) }
	for _, f := range strings.FieldsFunc(request, cut) {
		f = strings.TrimRight(f, ".:")
		if p, err := netip.ParsePrefix(f); err == nil {
			out[p.Masked().String()] = true
		} else if a, err := netip.ParseAddr(f); err == nil && a.Zone() == "" {
			out[netip.PrefixFrom(a, a.BitLen()).String()] = true
		}
	}
	return out
}
