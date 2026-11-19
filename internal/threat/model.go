package threat

import (
	"errors"
	"regexp"
	"slices"
	"strings"

	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	"github.com/amezianechayer/rempart/internal/graph/reach"
	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
)

// MaxThreats bounds a model (ADR 0010 D11): beyond, reach.ErrGraphTooLarge.
const MaxThreats = 20000

// Statuses of a threat; accepted arrives with human exceptions (M4).
const (
	StatusOpen      = "open"
	StatusMitigated = "mitigated"
)

// ErrInvalidInput: a graph without tenant or a pack digest outside the
// grammar. Fixed message.
var ErrInvalidInput = errors.New("threat: invalid analysis input")

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Pack is the evaluated policy pack: its digest and the controls it evaluated
// (the Go invariants and CIDR codes of L2 included by the caller).
type Pack struct {
	Digest   string
	Controls []string
}

// Threat is one threat of a model: no free text.
type Threat struct {
	ID         string   `json:"id"`
	Rule       string   `json:"rule"`
	Category   string   `json:"category"`
	Target     string   `json:"target"`
	TargetType string   `json:"target_type"`
	Severity   string   `json:"severity"`
	Status     string   `json:"status"`
	Controls   []string `json:"controls"`
}

// Model is the threat model of one graph revision.
type Model struct {
	SchemaVersion string   `json:"schema_version"`
	Catalog       string   `json:"catalog"`
	TenantID      string   `json:"tenant_id"`
	GraphRevision string   `json:"graph_revision"`
	PackDigest    string   `json:"pack_digest"`
	Threats       []Threat `json:"threats"`
}

// Analyze applies stride-v1 to the facts of g (never its free text): one
// threat per entry and matching element, status mitigated if and only if the
// entry cites a control, every cited control was evaluated by p, and no finding
// of these controls lands on the resources of the target (ADR 0010 D9). The
// graph is bounded by reach.DefaultLimits, the model by MaxThreats.
func Analyze(g graphdomain.FactsGraph, findings []loopsdomain.Finding, p Pack) (Model, error) {
	if g.TenantID == "" || !hex64.MatchString(p.Digest) {
		return Model{}, ErrInvalidInput
	}
	rev, err := Revision(g)
	if err != nil {
		return Model{}, err
	}
	rm, err := reach.FromGraph(g)
	if err != nil {
		return Model{}, err
	}
	r, err := reach.Compute(rm, reach.DefaultLimits)
	if err != nil {
		return Model{}, err
	}

	kinds := make(map[string]graphdomain.NodeKind, len(g.Nodes))
	for _, n := range g.Nodes {
		kinds[n.ID] = n.Kind
	}
	// Extra resources of a node target: the permissions that leave or reach
	// it (an identity, an account), and the load balancers that forward to it
	// (an exposure of the front is an exposure of the process behind).
	resources := map[string][]string{}
	sensitiveHosts := map[string]bool{}
	for _, e := range g.Edges {
		switch e.Type {
		case graphdomain.EdgeHasPermission:
			resources[e.Src] = append(resources[e.Src], e.ID)
			resources[e.Dst] = append(resources[e.Dst], e.ID)
		case graphdomain.EdgeCanReach:
			if kinds[e.Src] == graphdomain.KindLoadBalancer && e.Src != e.Dst {
				resources[e.Dst] = append(resources[e.Dst], e.Src)
			}
		case graphdomain.EdgeStores:
			sensitiveHosts[e.Src] = sensitiveHosts[e.Src] || sensitiveData(g, e.Dst)
		}
	}
	transitive := map[string]bool{}
	for _, path := range r.FromInternet {
		if len(path.Nodes) > 2 {
			transitive[path.Target] = true
		}
	}
	evaluated := map[string]bool{}
	for _, c := range p.Controls {
		evaluated[c] = true
	}
	found := map[[2]string]bool{}
	for _, f := range findings {
		found[[2]string{f.Code, f.Resource}] = true
	}
	status := func(e Entry, res []string) string {
		if len(e.Controls) == 0 {
			return StatusOpen
		}
		for _, c := range e.Controls {
			if !evaluated[c] {
				return StatusOpen
			}
			for _, r := range res {
				if found[[2]string{c, r}] {
					return StatusOpen
				}
			}
		}
		return StatusMitigated
	}

	threats := []Threat{}
	add := func(e Entry, target string, res []string) {
		threats = append(threats, Threat{
			ID: e.Rule + "@" + target, Rule: e.Rule, Category: e.Category, Target: target, TargetType: e.TargetType,
			Severity: string(e.Severity), Status: status(e, res), Controls: append([]string{}, e.Controls...),
		})
	}
	for _, e := range catalog {
		if e.TargetType == TargetFlow {
			for _, x := range g.Edges {
				if slices.Contains(e.Targets, string(x.Type)) {
					add(e, x.ID, []string{x.ID, x.Src, x.Dst})
				}
			}
			continue
		}
		for _, n := range g.Nodes {
			if !slices.Contains(e.Targets, string(n.Kind)) {
				continue
			}
			pivot := transitive[n.ID] && (sensitiveHosts[n.ID] || sensitiveData(g, n.ID))
			if e.Hypothesis && !pivot {
				continue
			}
			add(e, n.ID, append([]string{n.ID}, resources[n.ID]...))
		}
		if len(threats) > MaxThreats {
			return Model{}, reach.ErrGraphTooLarge
		}
	}
	if len(threats) > MaxThreats {
		return Model{}, reach.ErrGraphTooLarge
	}
	slices.SortFunc(threats, func(a, b Threat) int { return strings.Compare(a.ID, b.ID) })
	return Model{
		SchemaVersion: SchemaVersion, Catalog: CatalogVersion, TenantID: g.TenantID,
		GraphRevision: rev, PackDigest: p.Digest, Threats: threats,
	}, nil
}

// sensitiveData: a data store classified confidential or regulated, or with no
// classification (read on the safe side, as the policies do).
func sensitiveData(g graphdomain.FactsGraph, id string) bool {
	for _, n := range g.Nodes {
		if n.ID == id && n.Kind == graphdomain.KindDataStore {
			c := n.Attrs.Classification
			return c == nil || (*c != "public" && *c != "internal")
		}
	}
	return false
}
