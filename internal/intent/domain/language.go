package domain

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Lang is a covered language of the request (ADR 0006, amendment A1.1).
type Lang string

// Covered languages.
const (
	LangFR Lang = "fr"
	LangEN Lang = "en"
)

// Reasons of an unsupported language (closed list, plan P6).
const (
	ReasonAlphabet   = "alphabet"
	ReasonNoEvidence = "no_evidence"
	ReasonSentence   = "sentence"
)

// LanguageReport is the result of DetectLanguage.
type LanguageReport struct {
	Languages   []Lang // covered languages with non-zero evidence, sorted, no duplicate
	Primary     Lang   // language of the questions; "" if Unsupported
	Unsupported bool
	Reason      string // "" if covered, else one of the reasons above
}

// frenchLetters are the non-ASCII letters admitted (plan P3).
const frenchLetters = "àâæçéèêëîïôœùûüÿÀÂÆÇÉÈÊËÎÏÔŒÙÛÜŸ"

// Closed lists of plan sections 6.2 and 6.3.
var (
	functionWords = map[Lang]map[string]bool{
		LangFR: set("le", "les", "des", "du", "une", "et", "est", "sont", "ont", "pour", "sur", "dans", "avec", "sans",
			"je", "nous", "vous", "qui", "pas", "au", "aux", "ce", "cette", "ces", "mais", "par", "leur", "leurs",
			"notre", "veux", "voulons", "souhaite", "faut", "doit", "doivent", "être", "depuis", "vers", "chez",
			"très", "aussi"),
		LangEN: set("the", "and", "of", "to", "for", "with", "is", "are", "be", "we", "our", "want", "need", "needs",
			"must", "should", "this", "that", "these", "those", "from", "by", "at", "it", "its", "not", "or", "as",
			"into", "will", "can", "which", "on", "in", "per", "has", "have", "using", "without", "behind", "over"),
	}
	foreignSentinels = set(
		"el", "los", "las", "del", "una", "con", "para", "por", "quiero", "necesito", "datos",
		"der", "die", "und", "mit", "ich", "nicht", "ist", "ein", "eine", "einen", "zu", "von", "auf", "wir", "soll", "daten",
		"gli", "della", "delle", "dello", "che", "sono", "voglio", "dati", "nel", "nella",
		"uma", "em", "quero", "dados", "preciso",
		"het", "een", "ik", "wil", "voor", "niet", "wij", "gegevens", "naar",
	)
	// evidence: function words and one-word lexicon forms, per language;
	// common: one-word forms of the any lists.
	evidence = map[Lang]map[string]bool{}
	common   = map[string]bool{}
)

func set(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

func init() {
	for _, l := range []Lang{LangFR, LangEN} {
		evidence[l] = map[string]bool{}
		for w := range functionWords[l] {
			evidence[l][w] = true
		}
	}
	add := func(f forms) {
		for _, x := range [...]struct {
			dst  map[string]bool
			list []string
		}{{evidence[LangFR], f.fr}, {evidence[LangEN], f.en}, {common, f.any}} {
			for _, form := range x.list {
				if ws := tokenize(form); len(ws) == 1 {
					x.dst[ws[0]] = true
				}
			}
		}
	}
	for _, d := range []lexDomain{
		lexCloud, lexEnvironment, lexCriticality, lexTier, lexOS, lexProtocol, lexClass,
		lexRegulation, lexResidency, lexCompliance, lexObservability,
	} {
		for _, f := range d {
			add(f)
		}
	}
	add(databaseMarkers)
	add(exposureMarkers)
}

// admittedRune: plan P3.
func admittedRune(r rune) bool {
	switch {
	case r == '\t' || r == '\n' || r == '\r':
		return true
	case unicode.In(r, unicode.Cc, unicode.Mn, unicode.Me, unicode.Cf, unicode.Co, unicode.Cs):
		return false
	case !unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z):
		return false // unassigned
	case unicode.IsLetter(r):
		return 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || strings.ContainsRune(frenchLetters, r)
	case unicode.IsNumber(r):
		return r >= '0' && r <= '9'
	}
	return true
}

func isWord(tok string) bool {
	for _, r := range tok {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return tok != ""
}

type langCounts struct{ fr, en, foreign, n int }

func count(text string) langCounts {
	var c langCounts
	for _, tok := range tokenize(text) {
		if evidence[LangFR][tok] {
			c.fr++
		}
		if evidence[LangEN][tok] {
			c.en++
		}
		if foreignSentinels[tok] {
			c.foreign++
		}
		if isWord(tok) && !common[tok] {
			c.n++
		}
	}
	return c
}

// DetectLanguage: plan P3 to P6. Deterministic, linear in the size of the text.
// It reads only the user's text.
func DetectLanguage(text string) LanguageReport {
	unsupported := func(reason string) LanguageReport { return LanguageReport{Unsupported: true, Reason: reason} }
	if !utf8.ValidString(text) {
		return unsupported(ReasonAlphabet)
	}
	for _, r := range text {
		if !admittedRune(r) {
			return unsupported(ReasonAlphabet)
		}
	}
	total := count(text)
	if total.fr+total.en == 0 {
		return unsupported(ReasonNoEvidence)
	}
	for _, s := range sentences(text) {
		c := count(s)
		if c.foreign > c.fr+c.en || c.n >= 3 && c.fr+c.en == 0 {
			return unsupported(ReasonSentence)
		}
	}
	var rep LanguageReport
	if total.en > 0 {
		rep.Languages = append(rep.Languages, LangEN)
	}
	if total.fr > 0 {
		rep.Languages = append(rep.Languages, LangFR)
	}
	rep.Primary = LangFR
	if total.en > total.fr {
		rep.Primary = LangEN
	}
	return rep
}
