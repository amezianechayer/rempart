package domain

import (
	"strings"
	"unicode"
)

// Closed lexicon of plan section 6.2. Any entry added weakens provenance and
// needs a plan amendment and a security review.
type lexDomain map[string][]string

var (
	lexCloud = lexDomain{
		"aws": {"aws", "amazon"}, "azure": {"azure"}, "scaleway": {"scaleway"}, "ovhcloud": {"ovh", "ovhcloud"},
	}
	lexEnvironment = lexDomain{
		"dev": {"dev", "développement"}, "staging": {"staging", "préproduction", "recette"}, "prod": {"prod", "production"},
	}
	lexCriticality = lexDomain{"high": {"critique", "critiques"}}
	lexTier        = lexDomain{
		"small":  {"petit", "petite", "petits", "petites"},
		"medium": {"moyen", "moyenne", "moyens", "moyennes"},
		"large":  {"grand", "grande", "grands", "grandes"},
	}
	lexOS       = lexDomain{"linux": {"linux"}, "windows": {"windows"}}
	lexProtocol = lexDomain{"https": {"https", "web"}, "http": {"http"}, "tcp": {"tcp"}, "udp": {"udp"}}
	lexClass    = lexDomain{
		"public":       {"données publiques"},
		"internal":     {"interne", "internes"},
		"confidential": {"confidentiel", "confidentielle", "confidentiels", "confidentielles"},
		"regulated":    {"réglementé", "réglementée", "réglementés", "réglementées"},
	}
	lexRegulation = lexDomain{
		"gdpr": {"rgpd", "gdpr"}, "health": {"santé", "hds"},
		"financial": {"bancaire", "bancaires", "financier", "financières"},
	}
	lexResidency  = lexDomain{"eu": {"ue", "europe", "européenne", "européen"}, "fr": {"france"}}
	lexCompliance = lexDomain{
		"nis2": {"nis2"}, "dora": {"dora"}, "secnumcloud": {"secnumcloud"},
		"iso27001": {"iso27001", "iso 27001"}, "cis": {"cis"},
	}
	lexObservability = lexDomain{
		"prometheus": {"prometheus"}, "loki": {"loki"}, "grafana": {"grafana"},
		"cloud_native": {"cloudwatch", "monitor"},
	}
	exposureMarkers = []string{
		"public", "publique", "publics", "publiques", "internet", "expose", "exposé", "exposée",
		"exposer", "exposition", "extérieur",
	}
)

// tokenIndex is the token index of the user's text (plan P5), built once per Check.
type tokenIndex struct {
	tokens []string
	set    map[string]bool
	raw    string
}

func tokenize(s string) []string {
	fields := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-'
	})
	out := fields[:0]
	for _, f := range fields {
		if f = strings.Trim(f, "-"); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func newIndex(text string) tokenIndex {
	ix := tokenIndex{tokens: tokenize(text), set: map[string]bool{}, raw: text}
	for _, t := range ix.tokens {
		ix.set[t] = true
	}
	return ix
}

// has reports whether form (one or more words) is in the text.
func (ix tokenIndex) has(form string) bool {
	words := tokenize(form)
	switch len(words) {
	case 0:
		return false
	case 1:
		return ix.set[words[0]]
	}
	if !ix.set[words[0]] {
		return false
	}
	for i := 0; i+len(words) <= len(ix.tokens); i++ {
		match := true
		for j, w := range words {
			if ix.tokens[i+j] != w {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// literal reports whether value equals a token of the text.
func (ix tokenIndex) literal(value string) bool { return ix.set[strings.ToLower(value)] }

// anchoredIn reports whether a form of value in the lexicon domain is in the text.
func (ix tokenIndex) anchoredIn(d lexDomain, value string) bool {
	for _, f := range d[value] {
		if ix.has(f) {
			return true
		}
	}
	return false
}

func (ix tokenIndex) exposureRequested() bool {
	for _, m := range exposureMarkers {
		if ix.set[m] {
			return true
		}
	}
	return false
}
