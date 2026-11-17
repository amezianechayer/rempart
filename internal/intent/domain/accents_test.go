package domain

import "testing"

// TestLexiconWithoutAccents (obligation (dc), before M1-T05): French written
// without diacritics is read like French with them, on both sides.
func TestLexiconWithoutAccents(t *testing.T) {
	for text, check := range map[string]func(tokenIndex) bool{
		"donnees de sante des patients":     func(ix tokenIndex) bool { return ix.anchoredIn(lexRegulation, "health") },
		"donnees reglementees":              func(ix tokenIndex) bool { return ix.anchoredIn(lexClass, "regulated") },
		"une base de donnees":               func(ix tokenIndex) bool { return ix.hasAny(databaseMarkers) },
		"environnement de preproduction":    func(ix tokenIndex) bool { return ix.anchoredIn(lexEnvironment, "staging") },
		"region europeenne":                 func(ix tokenIndex) bool { return ix.anchoredIn(lexResidency, "eu") },
		"service expose a l'exterieur":      func(ix tokenIndex) bool { return ix.exposureRequested() },
		"DONNÉES DE SANTÉ":                  func(ix tokenIndex) bool { return ix.anchoredIn(lexRegulation, "health") },
		"données réglementées, comme avant": func(ix tokenIndex) bool { return ix.anchoredIn(lexClass, "regulated") },
	} {
		if !check(newIndex(text)) {
			t.Errorf("%q: lexicon form not read", text)
		}
	}
	if !sensitiveExposureRequested("Exposez la base de donnees au public.") {
		t.Error("variant D not triggered without accents")
	}
}
