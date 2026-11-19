package reach_test

import (
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/amezianechayer/rempart/internal/design"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	"github.com/amezianechayer/rempart/internal/graph/reach"
	"github.com/amezianechayer/rempart/internal/intent"
)

func ptr[T any](v T) *T { return &v }

// referenceFacts is the FactsGraph of the reference scenario (Build of
// internal/intent/testdata/reference-ir.json).
func referenceFacts(t *testing.T) graphdomain.FactsGraph {
	t.Helper()
	raw, err := os.ReadFile("../../intent/testdata/reference-ir.json")
	if err != nil {
		t.Fatal(err)
	}
	ir, err := intent.ParseIR(raw)
	if err != nil {
		t.Fatal(err)
	}
	g, _, err := design.Build(ir, design.Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return graphdomain.FactsOf(g)
}

func node(t *testing.T, f *graphdomain.FactsGraph, id string) *graphdomain.FactNode {
	t.Helper()
	i := slices.IndexFunc(f.Nodes, func(n graphdomain.FactNode) bool { return n.ID == id })
	if i < 0 {
		t.Fatalf("node %s missing from the reference graph", id)
	}
	return &f.Nodes[i]
}

func fromFacts(t *testing.T, f graphdomain.FactsGraph) reach.Result {
	t.Helper()
	m, err := reach.FromGraph(f)
	if err != nil {
		t.Fatalf("FromGraph: %v", err)
	}
	for _, r := range m.Rules {
		if r.Action != reach.Allow {
			t.Fatalf("FromGraph produced %+v: no deny in M2 (ADR 0010, D2)", r)
		}
	}
	r, err := reach.Compute(m, reach.DefaultLimits)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	checkCanonical(t, r)
	return r
}

func withSources(h reach.Hop, world bool, sources ...string) reach.Hop {
	h.World = world
	for _, s := range sources {
		h.Sources = append(h.Sources, mustPrefix(s))
	}
	return h
}

func hasHop(r reach.Result, want reach.Hop) bool {
	return slices.ContainsFunc(r.Hops, func(h reach.Hop) bool {
		return h.Src == want.Src && h.Dst == want.Dst && h.Proto == want.Proto && h.World == want.World &&
			slices.Equal(h.Ports, want.Ports) && slices.Equal(h.Sources, want.Sources)
	})
}

func pathTo(r reach.Result, target string) []string {
	for _, p := range r.FromInternet {
		if p.Target == target {
			return p.Nodes
		}
	}
	return nil
}

// TestReachFromGraphReference proves the closed table of ADR 0010, D2 on the
// reference scenario: Internet reaches the load balancer only, never the
// database directly, no implicit deny; then each row R1 to R6, the widest
// reading of an absent attribute, and the refusal of an unreadable fact.
func TestReachFromGraphReference(t *testing.T) {
	const (
		lb    = "lb:app-cluster-443"
		app   = "wl:app-cluster"
		vms   = "wl:legacy-vms"
		db    = "data:customer-db"
		obs   = "wl:obs"
		gitop = "wl:gitops"
	)
	f := referenceFacts(t)
	m, err := reach.FromGraph(f)
	if err != nil {
		t.Fatalf("FromGraph: %v", err)
	}
	if want := []string{db, lb, app, gitop, vms, obs}; !slices.Equal(m.Nodes, want) {
		t.Fatalf("model nodes %v, want %v (no Internet, Network, Identity or Account)", m.Nodes, want)
	}
	r := fromFacts(t, f)
	want := []reach.Hop{
		withSources(hop(reach.Internet, lb, reach.TCP, 443, 443), true),
		hop(lb, app, reach.TCP, 443, 443),
		hop(app, vms, reach.TCP, 5432, 5432, 9100, 9100),
	}
	if got := mustJSON(t, r.Hops); got != mustJSON(t, want) {
		t.Fatalf("hops %s\nwant %s", got, mustJSON(t, want))
	}
	paths := map[string][]string{
		lb:  {reach.Internet, lb},
		app: {reach.Internet, lb, app},
		vms: {reach.Internet, lb, app, vms},
	}
	if len(r.FromInternet) != len(paths) {
		t.Fatalf("paths %v, want %v", r.FromInternet, paths)
	}
	for target, nodes := range paths {
		if got := pathTo(r, target); !slices.Equal(got, nodes) {
			t.Fatalf("path to %s %v, want %v", target, got, nodes)
		}
	}
	if pathTo(r, db) != nil {
		t.Fatalf("the database is the target of a path: STORES is no flow")
	}

	type variant struct {
		name  string
		edit  func(t *testing.T, f *graphdomain.FactsGraph)
		hops  []reach.Hop // each must be present
		paths map[string][]string
	}
	edge := func(typ graphdomain.EdgeType, id, src, dst string, a graphdomain.EdgeAttrs) graphdomain.FactEdge {
		return graphdomain.FactEdge{ID: id, Type: typ, Src: src, Dst: dst, Attrs: a}
	}
	all := func(dst string, protos ...reach.Proto) []reach.Hop {
		var out []reach.Hop
		for _, p := range protos {
			out = append(out, withSources(hop(reach.Internet, dst, p, 1, 65535), true))
		}
		return out
	}
	variants := []variant{
		{
			"r3_public_dataset_in_data_tier", func(t *testing.T, f *graphdomain.FactsGraph) { node(t, f, db).Attrs.PublicAccess = ptr(true) },
			[]reach.Hop{withSources(hop(reach.Internet, db, reach.TCP, 443, 443), true)},
			map[string][]string{db: {reach.Internet, db}},
		},
		{"r3_public_managed_db", func(t *testing.T, f *graphdomain.FactsGraph) {
			f.Nodes = append(f.Nodes, graphdomain.FactNode{
				ID: "wl:orders-db", Kind: graphdomain.KindDataStore,
				Attrs: graphdomain.NodeAttrs{Subtype: ptr("managed_db"), PublicAccess: ptr(true)},
			})
		}, all("wl:orders-db", reach.TCP), map[string][]string{"wl:orders-db": {reach.Internet, "wl:orders-db"}}},
		{
			"r3_absent_public_access_is_widest", func(t *testing.T, f *graphdomain.FactsGraph) { node(t, f, db).Attrs.PublicAccess = nil },
			[]reach.Hop{withSources(hop(reach.Internet, db, reach.TCP, 443, 443), true)},
			nil,
		},
		{"r4_public_api_with_sources", func(t *testing.T, f *graphdomain.FactsGraph) {
			a := &node(t, f, app).Attrs
			a.APIPublic, a.APIAllowedSources = ptr(true), []string{"203.0.113.0/24"}
		}, []reach.Hop{withSources(hop(reach.Internet, app, reach.TCP, 443, 443), false, "203.0.113.0/24")}, map[string][]string{app: {reach.Internet, app}}},
		{
			"r4_public_api_world", func(t *testing.T, f *graphdomain.FactsGraph) { node(t, f, app).Attrs.APIPublic = ptr(true) },
			[]reach.Hop{withSources(hop(reach.Internet, app, reach.TCP, 443, 443), true)},
			nil,
		},
		{
			"r5_public_ip", func(t *testing.T, f *graphdomain.FactsGraph) { node(t, f, vms).Attrs.PublicIP = ptr(true) },
			all(vms, reach.TCP, reach.UDP),
			map[string][]string{vms: {reach.Internet, vms}},
		},
		{
			"r5_absent_public_ip_is_widest", func(t *testing.T, f *graphdomain.FactsGraph) { node(t, f, vms).Attrs.PublicIP = nil },
			all(vms, reach.TCP, reach.UDP), nil,
		},
		{
			"r6_pods_see_each_other", func(t *testing.T, f *graphdomain.FactsGraph) {
				node(t, f, app).Attrs.NetworkPolicyDefaultDeny = ptr(false)
			},
			[]reach.Hop{hop(app, obs, reach.TCP, 1, 65535), hop(obs, app, reach.UDP, 1, 65535), hop(app, gitop, reach.UDP, 1, 65535), hop(gitop, app, reach.TCP, 1, 65535)},
			map[string][]string{obs: {reach.Internet, lb, app, obs}},
		},
		{
			"r6_absent_default_deny_is_widest", func(t *testing.T, f *graphdomain.FactsGraph) { node(t, f, app).Attrs.NetworkPolicyDefaultDeny = nil },
			[]reach.Hop{hop(app, gitop, reach.TCP, 1, 65535)},
			nil,
		},
		{"r1_exposes_sources", func(t *testing.T, f *graphdomain.FactsGraph) {
			for i := range f.Edges {
				if f.Edges[i].Type == graphdomain.EdgeExposes {
					f.Edges[i].Attrs.AllowedSources = []string{"198.51.100.0/24", "192.0.2.0/24"}
				}
			}
		}, []reach.Hop{withSources(hop(reach.Internet, lb, reach.TCP, 443, 443), false, "192.0.2.0/24", "198.51.100.0/24")}, nil},
		{"r2_absent_protocol_and_ports_are_widest", func(t *testing.T, f *graphdomain.FactsGraph) {
			f.Edges = append(f.Edges, edge(graphdomain.EdgeCanReach, "can_reach|wl:obs|wl:legacy-vms", obs, vms, graphdomain.EdgeAttrs{}))
		}, []reach.Hop{hop(obs, vms, reach.TCP, 1, 65535), hop(obs, vms, reach.UDP, 1, 65535)}, nil},
		{"r2_http_read_as_tcp", func(t *testing.T, f *graphdomain.FactsGraph) {
			f.Edges = append(f.Edges, edge(graphdomain.EdgeCanReach, "can_reach|wl:obs|wl:legacy-vms|http/8080", obs, vms,
				graphdomain.EdgeAttrs{Protocol: ptr("http"), PortFrom: ptr(8080), PortTo: ptr(8080)}))
		}, []reach.Hop{hop(obs, vms, reach.TCP, 8080, 8080)}, nil},
		{"r2_from_internet_with_sources", func(t *testing.T, f *graphdomain.FactsGraph) {
			f.Edges = append(f.Edges, edge(graphdomain.EdgeCanReach, "can_reach|internet|wl:obs|tcp/9090", reach.Internet, obs,
				graphdomain.EdgeAttrs{Protocol: ptr("tcp"), PortFrom: ptr(9090), PortTo: ptr(9090), AllowedSources: []string{"192.0.2.0/24"}}))
		}, []reach.Hop{withSources(hop(reach.Internet, obs, reach.TCP, 9090, 9090), false, "192.0.2.0/24")}, map[string][]string{obs: {reach.Internet, obs}}},
		{"egress_ignored", func(t *testing.T, f *graphdomain.FactsGraph) {
			f.Edges = append(f.Edges, edge(graphdomain.EdgeCanReach, "can_reach|wl:obs|internet|tcp/443", obs, reach.Internet,
				graphdomain.EdgeAttrs{Protocol: ptr("tcp"), PortFrom: ptr(443), PortTo: ptr(443)}))
		}, nil, nil},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			f := referenceFacts(t)
			v.edit(t, &f)
			r := fromFacts(t, f)
			for _, h := range v.hops {
				if !hasHop(r, h) {
					t.Fatalf("missing hop %s in %s", mustJSON(t, h), mustJSON(t, r.Hops))
				}
			}
			for target, nodes := range v.paths {
				if got := pathTo(r, target); !slices.Equal(got, nodes) {
					t.Fatalf("path to %s %v, want %v", target, got, nodes)
				}
			}
			for _, h := range r.Hops {
				if h.Dst == reach.Internet {
					t.Fatalf("hop %v towards internet", h)
				}
			}
			// The reference hops never disappear: every variant only adds facts.
			for _, h := range want {
				if v.name == "r1_exposes_sources" && h.Src == reach.Internet {
					continue
				}
				if !hasHop(r, h) {
					t.Fatalf("variant lost the reference hop %s", mustJSON(t, h))
				}
			}
		})
	}

	invalid := []struct {
		name string
		edit func(t *testing.T, f *graphdomain.FactsGraph)
	}{
		{"can_reach_from_network", func(t *testing.T, f *graphdomain.FactsGraph) {
			f.Edges = append(f.Edges, edge(graphdomain.EdgeCanReach, "can_reach|net:aws-eu-west-3-staging|wl:obs", "net:aws-eu-west-3-staging", obs, graphdomain.EdgeAttrs{}))
		}},
		{"can_reach_unknown_node", func(t *testing.T, f *graphdomain.FactsGraph) {
			f.Edges = append(f.Edges, edge(graphdomain.EdgeCanReach, "can_reach|wl:ghost|wl:obs", "wl:ghost", obs, graphdomain.EdgeAttrs{}))
		}},
		{"ports_reversed", func(t *testing.T, f *graphdomain.FactsGraph) {
			f.Edges = append(f.Edges, edge(graphdomain.EdgeCanReach, "can_reach|wl:obs|wl:legacy-vms", obs, vms,
				graphdomain.EdgeAttrs{Protocol: ptr("tcp"), PortFrom: ptr(9000), PortTo: ptr(80)}))
		}},
		{"unknown_protocol", func(t *testing.T, f *graphdomain.FactsGraph) {
			f.Edges = append(f.Edges, edge(graphdomain.EdgeCanReach, "can_reach|wl:obs|wl:legacy-vms", obs, vms,
				graphdomain.EdgeAttrs{Protocol: ptr("icmp")}))
		}},
		{"source_not_canonical", func(t *testing.T, f *graphdomain.FactsGraph) {
			for i := range f.Edges {
				if f.Edges[i].Type == graphdomain.EdgeExposes {
					f.Edges[i].Attrs.AllowedSources = []string{"192.0.2.7/24"}
				}
			}
		}},
		{"api_source_unreadable", func(t *testing.T, f *graphdomain.FactsGraph) {
			a := &node(t, f, app).Attrs
			a.APIPublic, a.APIAllowedSources = ptr(true), []string{"not-a-prefix"}
		}},
	}
	for _, c := range invalid {
		t.Run("invalid_"+c.name, func(t *testing.T) {
			f := referenceFacts(t)
			c.edit(t, &f)
			if _, err := reach.FromGraph(f); !errors.Is(err, reach.ErrInvalidModel) {
				t.Fatalf("FromGraph = %v, want ErrInvalidModel", err)
			}
		})
	}
}
