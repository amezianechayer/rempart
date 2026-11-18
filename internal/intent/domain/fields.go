package domain

import (
	"regexp"

	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
)

// Obligations (es) and (ck), T104: the field of an assumption or of an open
// question is a path of the draft, from a closed grammar, never free text of
// the model; a finding names assumptions[i].field or open_questions[i].field.

const maxFieldBytes = 64

var fieldPattern = regexp.MustCompile(`^[a-z_]+(\[([0-9]{1,3}|[a-z][a-z0-9-]{0,40})\])?(\.[a-z_]+(\[([0-9]{1,3}|[a-z][a-z0-9-]{0,40})\])?)*$`)

func validField(f string) bool { return len(f) <= maxFieldBytes && fieldPattern.MatchString(f) }

func checkFields(d Draft) []loopsdomain.Finding {
	var out []loopsdomain.Finding
	for i, a := range d.Assumptions {
		if !validField(a.Field) {
			out = append(out, finding(codeFieldInvalid, iPath("assumptions", i, "field")))
		}
	}
	for i, q := range d.OpenQuestions {
		if !validField(q.Field) {
			out = append(out, finding(codeFieldInvalid, iPath("open_questions", i, "field")))
		}
	}
	return out
}
