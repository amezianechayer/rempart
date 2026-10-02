package domain

import (
	"slices"
	"strings"
	"unicode"
)

// forms are the forms of one lexicon value, per covered language (plan
// M1-intent-multilingual, P2). any: forms common to the covered languages.
// A form is never both in fr and en.
type forms struct{ any, fr, en []string }

// all returns the union of the forms (A1.1: applied to any text).
func (f forms) all() []string { return slices.Concat(f.any, f.fr, f.en) }

// Closed lexicon of plan section 6.1. Any entry added weakens provenance and
// needs a plan amendment and a security review.
type lexDomain map[string]forms

var (
	lexCloud = lexDomain{
		"aws": {any: []string{"aws", "amazon"}}, "azure": {any: []string{"azure"}},
		"scaleway": {any: []string{"scaleway"}}, "ovhcloud": {any: []string{"ovh", "ovhcloud"}},
	}
	lexEnvironment = lexDomain{
		"dev":     {any: []string{"dev"}, fr: []string{"développement"}, en: []string{"development"}},
		"staging": {any: []string{"staging"}, fr: []string{"préproduction", "recette"}, en: []string{"preproduction", "pre-production"}},
		"prod":    {any: []string{"prod", "production"}},
	}
	lexCriticality = lexDomain{"high": {fr: []string{"critique", "critiques"}, en: []string{"critical"}}}
	lexTier        = lexDomain{
		"small":  {fr: []string{"petit", "petite", "petits", "petites"}, en: []string{"small"}},
		"medium": {fr: []string{"moyen", "moyenne", "moyens", "moyennes"}, en: []string{"medium"}},
		"large":  {fr: []string{"grand", "grande", "grands", "grandes"}, en: []string{"large"}},
	}
	lexOS       = lexDomain{"linux": {any: []string{"linux"}}, "windows": {any: []string{"windows"}}}
	lexProtocol = lexDomain{
		"https": {any: []string{"https", "web"}}, "http": {any: []string{"http"}},
		"tcp": {any: []string{"tcp"}}, "udp": {any: []string{"udp"}},
	}
	lexClass = lexDomain{
		"public":       {fr: []string{"données publiques"}, en: []string{"public data"}},
		"internal":     {fr: []string{"interne", "internes"}, en: []string{"internal data"}},
		"confidential": {fr: []string{"confidentiel", "confidentielle", "confidentiels", "confidentielles"}, en: []string{"confidential"}},
		"regulated":    {fr: []string{"réglementé", "réglementée", "réglementés", "réglementées"}, en: []string{"regulated"}},
	}
	lexRegulation = lexDomain{
		"gdpr":   {any: []string{"gdpr"}, fr: []string{"rgpd"}},
		"health": {fr: []string{"santé", "hds"}, en: []string{"health", "healthcare"}},
		"financial": {
			fr: []string{"bancaire", "bancaires", "financier", "financière", "financiers", "financières"},
			en: []string{"banking", "financial"},
		},
	}
	lexResidency = lexDomain{
		"eu": {any: []string{"europe"}, fr: []string{"ue", "européen", "européenne"}, en: []string{"eu", "european"}},
		"fr": {any: []string{"france"}},
	}
	lexCompliance = lexDomain{
		"nis2": {any: []string{"nis2"}}, "dora": {any: []string{"dora"}}, "secnumcloud": {any: []string{"secnumcloud"}},
		"iso27001": {any: []string{"iso27001", "iso 27001"}}, "cis": {any: []string{"cis"}},
	}
	lexObservability = lexDomain{
		"prometheus": {any: []string{"prometheus"}}, "loki": {any: []string{"loki"}}, "grafana": {any: []string{"grafana"}},
		"cloud_native": {any: []string{"cloudwatch", "monitor"}},
	}
	// databaseMarkers: T85b, the user's text names a database.
	databaseMarkers = forms{
		any: []string{"postgresql", "postgres", "mysql", "mariadb", "mongodb", "sql"},
		fr:  []string{"base de données", "bases de données", "base", "bases", "bdd"},
		en:  []string{"database", "databases", "db", "dbs"},
	}
	exposureMarkers = forms{
		any: []string{"public", "internet", "expose"},
		fr: []string{
			"publique", "publics", "publiques", "exposé", "exposée", "exposés", "exposées", "exposer", "exposez",
			"exposons", "exposition", "extérieur", "ouvert au monde", "ouverte au monde",
		},
		en: []string{"publicly", "exposed", "exposes", "exposing", "exposure", "internet-facing", "open to the world"},
	}
	// exposureLiterals are searched in the raw text (plan P10).
	exposureLiterals = []string{"0.0.0.0/0", "::/0"}
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

// hasAny reports whether one of the forms is in the text.
func (ix tokenIndex) hasAny(f forms) bool {
	return slices.ContainsFunc(f.all(), ix.has)
}

// literal reports whether value equals a token of the text.
func (ix tokenIndex) literal(value string) bool { return ix.set[strings.ToLower(value)] }

// anchoredIn reports whether a form of value in the lexicon domain, in any
// covered language, is in the text.
func (ix tokenIndex) anchoredIn(d lexDomain, value string) bool {
	f, ok := d[value]
	return ok && ix.hasAny(f)
}

func (ix tokenIndex) exposureRequested() bool {
	if ix.hasAny(exposureMarkers) {
		return true
	}
	for _, l := range exposureLiterals {
		if strings.Contains(ix.raw, l) {
			return true
		}
	}
	return false
}

// sensitiveRequested reports whether the text names sensitive data or a
// database (T85b): forms of confidential or regulated, of any regulation, or a
// database marker. It rests on the user's text, never on the model's draft.
func (ix tokenIndex) sensitiveRequested() bool {
	for _, v := range []string{"confidential", "regulated"} {
		if ix.anchoredIn(lexClass, v) {
			return true
		}
	}
	for v := range lexRegulation {
		if ix.anchoredIn(lexRegulation, v) {
			return true
		}
	}
	return ix.hasAny(databaseMarkers)
}

// sentences splits text on ! ? ; and newline, and on a dot followed by a
// blank or the end of the text (plan P4).
func sentences(text string) []string {
	var out []string
	start := 0
	cut := func(end, next int) {
		if s := text[start:end]; strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
		start = next
	}
	for i, r := range text {
		switch r {
		case '!', '?', ';', '\n':
			cut(i, i+1)
		case '.':
			if rest := text[i+1:]; rest == "" || unicode.IsSpace(firstRune(rest)) {
				cut(i, i+1)
			}
		}
	}
	cut(len(text), len(text))
	return out
}

func firstRune(s string) rune {
	for _, r := range s {
		return r
	}
	return 0
}

// sensitiveExposureRequested (variant D): one sentence of the text holds both
// an exposure marker and a sensitivity or database marker.
func sensitiveExposureRequested(text string) bool {
	for _, sentence := range sentences(text) {
		ix := newIndex(sentence)
		if ix.exposureRequested() && ix.sensitiveRequested() {
			return true
		}
	}
	return false
}
