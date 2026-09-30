package domain

import (
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
)

const (
	codeRefUnknown        = "INTENT-REF-UNKNOWN"
	codeRefDuplicate      = "INTENT-REF-DUPLICATE"
	codeTechnicalValue    = "INTENT-TECHNICAL-VALUE"
	codeInventedValue     = "INTENT-INVENTED-VALUE"
	codeBlockingAssumed   = "INTENT-BLOCKING-ASSUMED"
	codeExposureSensitive = "INTENT-EXPOSURE-SENSITIVE"
	codeExposureUnrequest = "INTENT-EXPOSURE-UNREQUESTED"
	codeDataOmitted       = "INTENT-DATA-OMITTED"
)

// Fixed messages, per code, never quoting a value (plan P6).
var messages = map[string]string{
	codeRefUnknown:        "reference to a workload that does not exist",
	codeRefDuplicate:      "identifier used twice",
	codeTechnicalValue:    "technical value (CIDR, IP address, ASN, IAM role) not allowed here; describe the need instead",
	codeInventedValue:     "value not written by the user; declare it in assumptions or ask a question",
	codeBlockingAssumed:   "blocking field cannot be assumed; ask a question",
	codeExposureSensitive: "sensitive workload exposed; remove the entry and capture the request in explicit_overrides",
	codeExposureUnrequest: "exposure not requested by the user; remove the entry",
	codeDataOmitted:       "sensitive data written by the user is not declared in data",
}

var severities = map[string]loopsdomain.Severity{
	codeBlockingAssumed: loopsdomain.SeverityMedium,
}

func finding(code, resource string) loopsdomain.Finding {
	sev, ok := severities[code]
	if !ok {
		sev = loopsdomain.SeverityHigh
	}
	return loopsdomain.Finding{Code: code, Source: "intent", Severity: sev, Resource: resource, Message: messages[code]}
}

// Check runs the references (rule 10), technical values (rule 7), provenance
// and blocking fields (rules 2 and 3) and sensitive exposure (decision 4).
func Check(text string, d Draft, c TenantContext) []loopsdomain.Finding {
	ix := newIndex(text)
	var out []loopsdomain.Finding
	out = append(out, checkReferences(d)...)
	out = append(out, checkTechnical(text, d)...)
	out = append(out, checkProvenance(ix, d, c)...)
	out = append(out, checkExposure(ix, d)...)
	out = append(out, checkCompleteness(ix, d)...)
	return loopsdomain.Sort(out)
}

func wPath(id, field string) string { return "workloads[" + id + "]." + field }
func dPath(id, field string) string { return "data[" + id + "]." + field }
func iPath(list string, i int, field string) string {
	return list + "[" + strconv.Itoa(i) + "]." + field
}

func checkReferences(d Draft) []loopsdomain.Finding {
	var out []loopsdomain.Finding
	ids := map[string]bool{}
	for _, w := range d.Workloads {
		if ids[w.ID] {
			out = append(out, finding(codeRefDuplicate, wPath(w.ID, "id")))
		}
		ids[w.ID] = true
	}
	dataIDs := map[string]bool{}
	for _, x := range d.Data {
		if dataIDs[x.ID] {
			out = append(out, finding(codeRefDuplicate, dPath(x.ID, "id")))
		}
		dataIDs[x.ID] = true
		for _, s := range x.StoredIn {
			if !ids[s] {
				out = append(out, finding(codeRefUnknown, dPath(x.ID, "stored_in")))
			}
		}
	}
	for _, w := range d.Workloads {
		if w.RunsOn != nil && !ids[*w.RunsOn] {
			out = append(out, finding(codeRefUnknown, wPath(w.ID, "runs_on")))
		}
	}
	for i, l := range d.Connectivity {
		if !ids[l.From] {
			out = append(out, finding(codeRefUnknown, iPath("connectivity", i, "from")))
		}
		if !ids[l.To] {
			out = append(out, finding(codeRefUnknown, iPath("connectivity", i, "to")))
		}
	}
	for i, e := range d.Exposure {
		if !ids[e.Workload] {
			out = append(out, finding(codeRefUnknown, iPath("exposure", i, "workload")))
		}
	}
	return out
}

var (
	asnPattern = regexp.MustCompile(`(?i)\bas[0-9]+\b`)
	iamPattern = regexp.MustCompile(`(?i)(\barn:|\brole/)`)
)

// technicalValues returns the technical values found in s.
func technicalValues(s string) []string {
	var out []string
	for _, f := range strings.Fields(s) {
		f = strings.Trim(f, ".,;()[]{}\"'«»")
		if _, err := netip.ParsePrefix(f); err == nil {
			out = append(out, f)
		} else if _, err := netip.ParseAddr(f); err == nil {
			out = append(out, f)
		}
	}
	out = append(out, asnPattern.FindAllString(s, -1)...)
	for _, f := range strings.Fields(s) {
		if iamPattern.MatchString(f) {
			out = append(out, f)
		}
	}
	return out
}

type located struct{ path, value string }

// freeStrings lists every string of the draft outside the two admitted places.
func freeStrings(d Draft) []located {
	out := []located{{"summary", d.Summary}}
	opt := func(p string, s *string) {
		if s != nil {
			out = append(out, located{p, *s})
		}
	}
	for _, w := range d.Workloads {
		out = append(out, located{wPath(w.ID, "region"), w.Region})
		opt(wPath(w.ID, "notes"), w.Notes)
	}
	for i, l := range d.Connectivity {
		opt(iPath("connectivity", i, "purpose"), l.Purpose)
	}
	for i, e := range d.Exposure {
		out = append(out, located{iPath("exposure", i, "justification"), e.Justification})
	}
	for _, r := range d.Constraints.AllowedRegions {
		out = append(out, located{"constraints.allowed_regions", r})
	}
	for i, o := range d.ExplicitOverrides {
		out = append(out, located{iPath("explicit_overrides", i, "affects"), o.Affects})
	}
	for i, a := range d.Assumptions {
		p := iPath("assumptions", i, "")
		out = append(out, located{p + "field", a.Field}, located{p + "value", a.Value}, located{p + "rationale", a.Rationale})
	}
	for i, q := range d.OpenQuestions {
		p := iPath("open_questions", i, "")
		out = append(out, located{p + "field", q.Field}, located{p + "question", q.Question}, located{p + "default", q.Default})
	}
	return out
}

func checkTechnical(text string, d Draft) []loopsdomain.Finding {
	var out []loopsdomain.Finding
	for _, l := range freeStrings(d) {
		if len(technicalValues(l.value)) > 0 {
			out = append(out, finding(codeTechnicalValue, l.path))
		}
	}
	for i, e := range d.Exposure {
		for _, s := range e.AllowedSources {
			p, err := netip.ParsePrefix(s)
			if err != nil || p.Masked() != p || !strings.Contains(text, s) {
				out = append(out, finding(codeTechnicalValue, iPath("exposure", i, "allowed_sources")))
			}
		}
	}
	for i, o := range d.ExplicitOverrides {
		for _, v := range technicalValues(o.Statement) {
			if !strings.Contains(text, v) {
				out = append(out, finding(codeTechnicalValue, iPath("explicit_overrides", i, "statement")))
			}
		}
	}
	return out
}

// checkCompleteness (T85c): a classification (confidential, regulated) or a
// regulation written in the text needs a data entry that declares it. It rests
// on the user's text, so omitting the data set does not escape decision 4.
func checkCompleteness(ix tokenIndex, d Draft) []loopsdomain.Finding {
	for _, c := range []string{"confidential", "regulated"} {
		if ix.anchoredIn(lexClass, c) && !slices.ContainsFunc(d.Data, func(x DraftData) bool { return x.Classification == c }) {
			return []loopsdomain.Finding{finding(codeDataOmitted, "data")}
		}
	}
	for _, r := range slices.Sorted(maps.Keys(lexRegulation)) {
		if ix.anchoredIn(lexRegulation, r) && !slices.ContainsFunc(d.Data, func(x DraftData) bool { return slices.Contains(x.Regulation, r) }) {
			return []loopsdomain.Finding{finding(codeDataOmitted, "data")}
		}
	}
	return nil
}
