// Package verify is the verifier of L2 on one candidate graph (ADR 0012 D4),
// independent of the proposer: schema and invariants of the graph, tenant,
// CIDR plan read back from the graph, reachability recomputed, the two
// invariants of the core (independent of the policy pack, T108), then the
// design pack on the facts. No model, no free text read.
package verify

import (
	"context"
	"errors"
	"slices"

	"github.com/amezianechayer/rempart/internal/design"
	"github.com/amezianechayer/rempart/internal/design/cidr"
	"github.com/amezianechayer/rempart/internal/design/confirm"
	"github.com/amezianechayer/rempart/internal/graph"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	"github.com/amezianechayer/rempart/internal/graph/reach"
	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
	"github.com/amezianechayer/rempart/internal/policy"
	policydomain "github.com/amezianechayer/rempart/internal/policy/domain"
)

// Codes of the invariants of the core and source of their findings.
const (
	CodeInternetToSensitive = "L2-INTERNET-TO-SENSITIVE"
	CodeExposureUnconfirmed = "L2-EXPOSURE-UNCONFIRMED"
	Source                  = "l2:core"
)

// ErrCandidate: a candidate outside the schema or the invariants of the graph,
// of another tenant, or a verifier without pack. Fixed message.
var ErrCandidate = errors.New("verify: invalid candidate")

var core = []policydomain.Control{
	{ID: CodeExposureUnconfirmed, Title: "Exposition depuis Internet non confirmée par un humain", Severity: loopsdomain.SeverityHigh, Remediation: policydomain.RemediationEscalate},
	{ID: CodeInternetToSensitive, Title: "Donnée sensible ou son hôte atteignable directement depuis Internet", Severity: loopsdomain.SeverityCritical, Remediation: policydomain.RemediationMakePrivate},
}

// CoreControls returns the controls of the core, sorted by identifier.
func CoreControls() []policydomain.Control { return slices.Clone(core) }

// Context is what the verifier takes from the subject: the exposure keys a
// human confirmed, whether an override cites an address (obligation (ey)),
// and the design context of the IR (ADR 0012 D7).
type Context struct {
	Confirmed            []confirm.ExposureKey
	OverridesCiteAddress bool
	Base                 policy.DesignContext
}

// Candidate verifies g for the tenant of the worker and returns every finding
// (all severities, sorted by loopsdomain.Sort, never nil); an error is never
// an empty list.
func Candidate(ctx context.Context, ev policy.Evaluator, g graphdomain.Graph, tenant string, c Context) ([]loopsdomain.Finding, error) {
	if ev == nil || g.TenantID != tenant || g.Source != "design" {
		return nil, ErrCandidate
	}
	if graph.ValidateSchema(g) != nil || graphdomain.Validate(g) != nil {
		return nil, ErrCandidate
	}
	f := graphdomain.FactsOf(g)
	plan, err := design.PlanOf(f)
	if err != nil {
		return nil, ErrCandidate
	}
	out := append([]loopsdomain.Finding{}, cidr.Check(plan)...)
	m, err := reach.FromGraph(f)
	if err != nil {
		return nil, ErrCandidate
	}
	r, err := reach.Compute(m, reach.DefaultLimits)
	if err != nil {
		return nil, err
	}
	out = append(out, internetToSensitive(f, r)...)
	uncovered := confirm.Uncovered(r.Hops, c.Confirmed)
	opened := map[string]bool{}
	for _, h := range uncovered {
		if !opened[h.Dst] {
			opened[h.Dst] = true
			out = append(out, finding(core[0], h.Dst))
		}
	}

	dc := c.Base
	dc.UnconfirmedExposures, dc.SourcesUnresolved = []string{}, []string{}
	for _, e := range f.Edges {
		if e.Type == graphdomain.EdgeExposes && opened[e.Src] {
			dc.UnconfirmedExposures = append(dc.UnconfirmedExposures, e.ID)
		}
	}
	in, err := policy.NewDesignInput(f, r, dc)
	if err != nil {
		return nil, ErrCandidate
	}
	if c.OverridesCiteAddress {
		for _, e := range f.Edges {
			if e.Type == graphdomain.EdgeExposes && slices.Contains(in.Derived.WorldSources, e.ID) {
				dc.SourcesUnresolved = append(dc.SourcesUnresolved, e.ID)
			}
		}
		if in, err = policy.NewDesignInput(f, r, dc); err != nil {
			return nil, ErrCandidate
		}
	}
	pack, err := ev.Evaluate(ctx, in)
	if err != nil {
		return nil, err
	}
	out = append(out, pack...)
	if sorted := loopsdomain.Sort(out); sorted != nil {
		return sorted, nil
	}
	return []loopsdomain.Finding{}, nil
}

// internetToSensitive: a hop from the Internet to sensitive data (confidential,
// regulated, unclassified, or under any regulation: FactNode.SensitiveData,
// T139), or to a host (STORES) of it (T108).
func internetToSensitive(f graphdomain.FactsGraph, r reach.Result) []loopsdomain.Finding {
	sensitive := map[string]bool{}
	for _, n := range f.Nodes {
		if n.SensitiveData() {
			sensitive[n.ID] = true
		}
	}
	hosts := map[string]bool{}
	for _, e := range f.Edges {
		if e.Type == graphdomain.EdgeStores && sensitive[e.Dst] {
			hosts[e.Src] = true
		}
	}
	out := []loopsdomain.Finding{}
	seen := map[string]bool{}
	for _, h := range r.Hops {
		if h.Src == reach.Internet && (sensitive[h.Dst] || hosts[h.Dst]) && !seen[h.Dst] {
			seen[h.Dst] = true
			out = append(out, finding(core[1], h.Dst))
		}
	}
	return out
}

func finding(c policydomain.Control, resource string) loopsdomain.Finding {
	return loopsdomain.Finding{Code: c.ID, Source: Source, Severity: c.Severity, Resource: resource, Message: c.Title}
}
