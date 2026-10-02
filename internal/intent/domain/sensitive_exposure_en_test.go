package domain

import (
	"testing"

	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
)

// TestSensitiveExposureRejectedEnglish: ADR 0006 decision 4 and amendment A1.1
// (plan M1-intent-multilingual, test 3). The same cases as in French hold on
// the English texts with the same drafts: an English request is never a way to
// blind the completeness rule (T85c) or variant D. A request that mixes the two
// languages, the injection written in French after an English request, is
// caught as well.
func TestSensitiveExposureRejectedEnglish(t *testing.T) {
	runSensitiveExposureCases(t, exposureTexts{
		c4:                  readText(t, "en/c4-request.txt"),
		split:               readText(t, "en/c4-split-sentence.txt"),
		storedIn:            readText(t, "en/stored-in-only.txt"),
		reference:           readText(t, "en/reference-request.txt"),
		referenceNoExposure: readText(t, "en/reference-request-no-exposure.txt"),
	})

	t.Run("mixed_split_sentence", func(t *testing.T) {
		text := readText(t, "mixed-split-sentence.txt")
		got := Check(text, draftFrom(t, "drafts/c4-split-sentence.json", nil), TenantContext{})
		if !hasFinding(got, "INTENT-DATA-OMITTED", loopsdomain.SeverityHigh, "data") &&
			!hasFinding(got, "INTENT-EXPOSURE-SENSITIVE", loopsdomain.SeverityHigh, "exposure[0].workload") {
			t.Errorf("want INTENT-DATA-OMITTED high on data or INTENT-EXPOSURE-SENSITIVE high on exposure[0].workload, got %+v", got)
		}
	})
}
