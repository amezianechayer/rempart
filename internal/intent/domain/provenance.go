package domain

import (
	"slices"
	"strconv"
	"strings"

	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
)

// controlled is one value of a controlled path (plan section 6.1).
type controlled struct {
	path, value string
	anchored    bool
	safeDefault bool
}

var standardPorts = map[string]int{"https": 443, "http": 80}

// classRank orders the classifications, the strictest last (plan P9, A1.4).
var classRank = map[string]int{"public": 0, "internal": 1, "confidential": 2, "regulated": 3}

// strictestClass is the highest rank of the classifications anchored in the
// text, -1 if none.
func strictestClass(ix tokenIndex) int {
	r := -1
	for c, k := range classRank {
		if k > r && ix.anchoredIn(lexClass, c) {
			r = k
		}
	}
	return r
}

func controlledValues(ix tokenIndex, d Draft) []controlled {
	var out []controlled
	add := func(path, value string, anchored, safe bool) {
		out = append(out, controlled{path: path, value: value, anchored: anchored, safeDefault: safe})
	}
	lex := func(path string, dom lexDomain, v string) { add(path, v, ix.anchoredIn(dom, v), false) }
	lit := func(path, v string) { add(path, v, ix.literal(v), false) }

	if d.Environment != nil {
		lex("environment", lexEnvironment, *d.Environment)
	}
	for _, w := range d.Workloads {
		lex(wPath(w.ID, "cloud"), lexCloud, w.Cloud)
		lit(wPath(w.ID, "region"), w.Region)
		add(wPath(w.ID, "criticality"), w.Criticality, ix.anchoredIn(lexCriticality, w.Criticality), w.Criticality == "high")
		if s := w.Size; s != nil {
			if s.Count != nil {
				lit(wPath(w.ID, "size.count"), strconv.Itoa(*s.Count))
			}
			if s.Tier != nil {
				lex(wPath(w.ID, "size.tier"), lexTier, *s.Tier)
			}
			if s.OS != nil {
				lex(wPath(w.ID, "size.os"), lexOS, *s.OS)
			}
		}
	}
	for i, l := range d.Connectivity {
		for _, p := range l.Ports {
			proto, nums, _ := strings.Cut(p, "/")
			ok := proto == "tcp" || ix.literal(proto)
			for _, n := range strings.Split(nums, "-") {
				ok = ok && ix.literal(n)
			}
			add(iPath("connectivity", i, "ports"), p, ok, false)
		}
	}
	for i, e := range d.Exposure {
		protoAnchored := ix.anchoredIn(lexProtocol, e.Protocol)
		add(iPath("exposure", i, "protocol"), e.Protocol, protoAnchored, false)
		if e.Port != nil {
			std, has := standardPorts[e.Protocol]
			add(iPath("exposure", i, "port"), strconv.Itoa(*e.Port), ix.literal(strconv.Itoa(*e.Port)), has && protoAnchored && std == *e.Port)
		}
		for _, s := range e.AllowedSources {
			add(iPath("exposure", i, "allowed_sources"), s, strings.Contains(ix.raw, s), false)
		}
	}
	strictest := strictestClass(ix)
	for _, x := range d.Data {
		rank, known := classRank[x.Classification]
		atLeast := known && rank >= strictest
		add(dPath(x.ID, "classification"), x.Classification,
			atLeast && ix.anchoredIn(lexClass, x.Classification),
			atLeast && x.Classification == "confidential")
		for _, r := range x.Regulation {
			lex(dPath(x.ID, "regulation"), lexRegulation, r)
		}
		if x.Residency != nil {
			lex(dPath(x.ID, "residency"), lexResidency, *x.Residency)
		}
	}
	if o := d.Observability; o != nil {
		for _, f := range []struct {
			name string
			v    *string
		}{{"metrics", o.Metrics}, {"logs", o.Logs}, {"dashboards", o.Dashboards}} {
			if f.v != nil {
				lex("observability."+f.name, lexObservability, *f.v)
			}
		}
		if o.RetentionDays != nil {
			lit("observability.retention_days", strconv.Itoa(*o.RetentionDays))
		}
	}
	for _, c := range d.Compliance {
		lex("compliance", lexCompliance, c)
	}
	if b := d.Constraints.MonthlyBudgetEUR; b != nil {
		lit("constraints.monthly_budget_eur", strconv.FormatFloat(*b, 'f', -1, 64))
	}
	for _, r := range d.Constraints.AllowedRegions {
		lit("constraints.allowed_regions", r)
	}
	for _, c := range d.Constraints.ForbiddenClouds {
		lex("constraints.forbidden_clouds", lexCloud, c)
	}
	return out
}

func assumed(d Draft, path, value string) bool {
	for _, a := range d.Assumptions {
		if a.Field == path && a.Value == value {
			return true
		}
	}
	return false
}

func checkProvenance(ix tokenIndex, d Draft, c TenantContext) []loopsdomain.Finding {
	var out []loopsdomain.Finding
	for _, v := range controlledValues(ix, d) {
		if !v.anchored && !v.safeDefault && !assumed(d, v.path, v.value) {
			out = append(out, finding(codeInventedValue, v.path))
		}
	}
	allowed := append(slices.Clone(c.AllowedRegions), d.Constraints.AllowedRegions...)
	for _, a := range d.Assumptions {
		switch {
		case strings.HasPrefix(a.Field, "workloads[") && strings.HasSuffix(a.Field, "].cloud"):
			out = append(out, finding(codeBlockingAssumed, a.Field))
		case strings.HasPrefix(a.Field, "workloads[") && strings.HasSuffix(a.Field, "].region") && !slices.Contains(allowed, a.Value):
			out = append(out, finding(codeBlockingAssumed, a.Field))
		case strings.HasPrefix(a.Field, "data[") && strings.HasSuffix(a.Field, "].classification") &&
			a.Value != "confidential" && a.Value != "regulated":
			out = append(out, finding(codeBlockingAssumed, a.Field))
		}
	}
	return out
}
