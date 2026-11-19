package policy

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"regexp"
	"slices"

	"github.com/santhosh-tekuri/jsonschema/v6"

	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	"github.com/amezianechayer/rempart/internal/graph/reach"
	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
	policydomain "github.com/amezianechayer/rempart/internal/policy/domain"
	"github.com/amezianechayer/rempart/schemas"
)

// ErrDesignInput: a context NewDesignInput cannot check. Fixed message: it
// never quotes the context.
var ErrDesignInput = errors.New("policy: invalid design input")

// DesignContext are the facts of the IR and of L2 that the graph does not carry
// (ADR 0011 D5): identifiers of EXPOSES edges, constraints, environment,
// observability, roles of workloads. Never an override or any free text.
type DesignContext struct {
	UnconfirmedExposures []string
	SourcesUnresolved    []string
	Constraints          policydomain.Constraints
	Environment          string // "" for none: the networks decide, then prod
	Observability        policydomain.Observability
	WorkloadRoles        map[string]string
}

// DesignInput is the whole input of the design policies, serialized to
// schemas/policy/design-input-v1.json. No type reachable from it holds a FreeText.
type DesignInput struct {
	Graph   graphdomain.FactsGraph `json:"graph"`
	Reach   reach.Result           `json:"reach"`
	Derived policydomain.Derived   `json:"derived"`
}

// Evaluator evaluates the design pack on the facts of one graph.
type Evaluator interface {
	// Evaluate returns the findings (Code = control_id, Source =
	// "policy:design"), sorted; an error is never an empty list.
	Evaluate(ctx context.Context, in DesignInput) ([]loopsdomain.Finding, error)
	// Controls returns the controls of the pack, sorted by control_id.
	Controls() []policydomain.Control
	// Digest returns the SHA-256 of the compiled pack (ADR 0011 D4).
	Digest() string
}

var (
	regionRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}[a-z0-9]$`)
	clouds   = []string{"aws", "azure", "scaleway", "ovhcloud"}
	envRank  = map[string]int{"dev": 1, "staging": 2, "prod": 3}
	roles    = []string{policydomain.RoleGitOpsController, policydomain.RoleObservabilityStack}
	// workloads are the kinds a role can name.
	workloads = []graphdomain.NodeKind{graphdomain.KindCompute, graphdomain.KindK8sCluster, graphdomain.KindK8sWorkload}
)

// NewDesignInput checks c against g, computes the jurisdiction of every node
// that carries a cloud and a region (a K8sWorkload takes that of its cluster)
// and the environment (the most demanding of c and of the networks, prod when
// none), sorts and deduplicates every list and writes no list or map as null.
func NewDesignInput(g graphdomain.FactsGraph, r reach.Result, c DesignContext) (DesignInput, error) {
	kinds := make(map[string]graphdomain.NodeKind, len(g.Nodes))
	attrs := make(map[string]graphdomain.NodeAttrs, len(g.Nodes))
	env := 0
	if c.Environment != "" {
		if env = envRank[c.Environment]; env == 0 {
			return DesignInput{}, ErrDesignInput
		}
	}
	for _, n := range g.Nodes {
		kinds[n.ID], attrs[n.ID] = n.Kind, n.Attrs
		if n.Kind == graphdomain.KindNetwork && n.Attrs.Env != nil {
			env = max(env, envRank[*n.Attrs.Env])
		}
	}
	if !reachWithin(r, kinds) {
		return DesignInput{}, ErrDesignInput
	}
	exposes := map[string]bool{}
	cluster := map[string]string{}
	for _, e := range g.Edges {
		switch {
		case e.Type == graphdomain.EdgeExposes:
			exposes[e.ID] = true
		case e.Type == graphdomain.EdgeMemberOf && kinds[e.Src] == graphdomain.KindK8sWorkload && kinds[e.Dst] == graphdomain.KindK8sCluster:
			cluster[e.Src] = e.Dst
		}
	}

	d := policydomain.Derived{Jurisdiction: map[string]policydomain.Zone{}, WorkloadRoles: map[string]string{}, WorldSources: []string{}}
	for _, e := range g.Edges {
		fromInternet := e.Type == graphdomain.EdgeCanReach && kinds[e.Src] == graphdomain.KindInternet
		if (e.Type == graphdomain.EdgeExposes || fromInternet) && coversInternet(e.Attrs.AllowedSources) {
			d.WorldSources = append(d.WorldSources, e.ID)
		}
	}
	for _, n := range g.Nodes {
		if n.Kind == graphdomain.KindK8sCluster && coversInternet(n.Attrs.APIAllowedSources) {
			d.WorldSources = append(d.WorldSources, n.ID)
		}
	}
	d.WorldSources = sortedSet(d.WorldSources)
	var err error
	if d.UnconfirmedExposures, err = exposureIDs(c.UnconfirmedExposures, exposes); err != nil {
		return DesignInput{}, err
	}
	if d.SourcesUnresolved, err = exposureIDs(c.SourcesUnresolved, exposes); err != nil {
		return DesignInput{}, err
	}
	for _, rg := range c.Constraints.AllowedRegions {
		if !regionRe.MatchString(rg) {
			return DesignInput{}, ErrDesignInput
		}
	}
	for _, cl := range c.Constraints.ForbiddenClouds {
		if !slices.Contains(clouds, cl) {
			return DesignInput{}, ErrDesignInput
		}
	}
	d.Constraints = policydomain.Constraints{
		AllowedRegions:  sortedSet(c.Constraints.AllowedRegions),
		ForbiddenClouds: sortedSet(c.Constraints.ForbiddenClouds),
	}
	for id, role := range c.WorkloadRoles {
		if !slices.Contains(roles, role) || !slices.Contains(workloads, kinds[id]) {
			return DesignInput{}, ErrDesignInput
		}
		d.WorkloadRoles[id] = role
	}
	for id, a := range attrs {
		if c, ok := cluster[id]; ok {
			a = attrs[c]
		}
		if a.Cloud != nil && a.Region != nil {
			d.Jurisdiction[id] = policydomain.Jurisdiction(*a.Cloud, *a.Region)
		}
	}
	d.Environment = "prod"
	for name, rank := range envRank {
		if rank == env {
			d.Environment = name
		}
	}
	d.Observability = c.Observability

	g.Nodes, g.Edges = orEmpty(g.Nodes), orEmpty(g.Edges)
	r.Hops, r.FromInternet = orEmpty(r.Hops), orEmpty(r.FromInternet)
	return DesignInput{Graph: g, Reach: r, Derived: d}, nil
}

// Check revalidates in before an evaluation (obligation (ff), T3, T119): the
// input must be the one NewDesignInput produces from its graph, its
// reachability and the context it carries (the identifiers of the
// reachability in the graph, the jurisdiction, the environment, the world
// sources and every list recomputed, no list written null), whatever the
// order of its nodes, edges and hops. Fixed error.
func (in DesignInput) Check() error {
	d := in.Derived
	if d.Environment == "" || in.Graph.Nodes == nil || in.Graph.Edges == nil || in.Reach.Hops == nil || in.Reach.FromInternet == nil {
		return ErrDesignInput
	}
	want, err := NewDesignInput(in.Graph, in.Reach, DesignContext{
		UnconfirmedExposures: d.UnconfirmedExposures, SourcesUnresolved: d.SourcesUnresolved,
		Constraints: d.Constraints, Environment: d.Environment, Observability: d.Observability, WorkloadRoles: d.WorkloadRoles,
	})
	if err != nil || !reflect.DeepEqual(want.Derived, d) {
		return ErrDesignInput
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return ErrDesignInput
	}
	sch, err := schemas.Compile(schemas.PolicyDesignInput)
	if err != nil {
		return ErrDesignInput
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil || sch.Validate(doc) != nil {
		return ErrDesignInput
	}
	return nil
}

// reachWithin: every node named by r (hops, paths) is a node of the graph, the
// Internet included (obligation (ff)).
func reachWithin(r reach.Result, kinds map[string]graphdomain.NodeKind) bool {
	in := func(id string) bool { _, ok := kinds[id]; return ok }
	for _, h := range r.Hops {
		if !in(h.Src) || !in(h.Dst) {
			return false
		}
	}
	for _, p := range r.FromInternet {
		if !in(p.Target) || len(p.Nodes) == 0 || p.Nodes[len(p.Nodes)-1] != p.Target {
			return false
		}
		for _, id := range p.Nodes {
			if !in(id) {
				return false
			}
		}
	}
	return true
}

// coversInternet: sources absent or empty, or whose IPv4 prefixes, merged,
// cover 0.0.0.0/0 (obligation (fg)). An unparsable source is read as the
// world (fail closed; the graph schema refuses it before).
func coversInternet(sources []string) bool {
	type span struct{ lo, hi uint64 }
	spans := make([]span, 0, len(sources))
	for _, s := range sources {
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is4() {
			return true
		}
		p = p.Masked()
		a := p.Addr().As4()
		lo := uint64(a[0])<<24 | uint64(a[1])<<16 | uint64(a[2])<<8 | uint64(a[3])
		spans = append(spans, span{lo, lo + 1<<(32-p.Bits()) - 1})
	}
	if len(spans) == 0 {
		return true
	}
	slices.SortFunc(spans, func(x, y span) int { return cmp.Compare(x.lo, y.lo) })
	next := uint64(0) // first address not yet covered
	for _, sp := range spans {
		if sp.lo > next {
			return false
		}
		next = max(next, sp.hi+1)
	}
	return next > 0xFFFFFFFF
}

// exposureIDs requires identifiers of EXPOSES edges of the graph.
func exposureIDs(ids []string, exposes map[string]bool) ([]string, error) {
	for _, id := range ids {
		if !exposes[id] {
			return nil, ErrDesignInput
		}
	}
	return sortedSet(ids), nil
}

// sortedSet returns the sorted list without duplicates, never nil.
func sortedSet(xs []string) []string {
	out := append([]string{}, xs...)
	slices.Sort(out)
	return slices.Compact(out)
}

// orEmpty writes an absent list as [], never null: count(null) is an error in
// strict Rego.
func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
