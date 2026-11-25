package verify_test

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/amezianechayer/rempart/internal/design/verify"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
)

// Obligation (fp) (T110, T122): the verifier checks that a candidate derives
// from the subject by the closed table of revisions of ADR 0012 D1.

func enriched(t *testing.T) graphdomain.Graph {
	t.Helper()
	raw, err := os.ReadFile("../revise/testdata/enriched.graph.json")
	if err != nil {
		t.Fatal(err)
	}
	var g graphdomain.Graph
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	return g
}

// copyOf is a deep copy through JSON: no slice or pointer shared with g.
func copyOf(t *testing.T, g graphdomain.Graph) graphdomain.Graph {
	t.Helper()
	raw, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	var out graphdomain.Graph
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func nodeOf(t *testing.T, g *graphdomain.Graph, id string) *graphdomain.Node {
	t.Helper()
	for i := range g.Nodes {
		if g.Nodes[i].ID == id {
			return &g.Nodes[i]
		}
	}
	t.Fatalf("node %s absent", id)
	return nil
}

func edgeOf(t *testing.T, g *graphdomain.Graph, id string) *graphdomain.Edge {
	t.Helper()
	for i := range g.Edges {
		if g.Edges[i].ID == id {
			return &g.Edges[i]
		}
	}
	t.Fatalf("edge %s absent", id)
	return nil
}

func without(g *graphdomain.Graph, id string) {
	g.Edges = slices.DeleteFunc(g.Edges, func(e graphdomain.Edge) bool { return e.ID == id })
}

func bptr(b bool) *bool     { return &b }
func sptr(s string) *string { return &s }
func iptr(i int) *int       { return &i }

func ftext(s string) *graphdomain.FreeText {
	v := graphdomain.NewFreeText(s)
	return &v
}

const (
	exposes443  = "exposes|lb:app-cluster-443|internet|https/443"
	exposes80   = "exposes|lb:web-80|internet|http/80"
	reachNet80  = "can_reach|internet|wl:billing|http/8080"
	vpn5432     = "can_reach|wl:app-cluster|wl:legacy-vms|tcp/5432"
	permLegacy  = "has_permission|id:legacy-vms|data:customer-db"
	billingApp  = "member_of|wl:billing|net:aws-eu-west-3-staging-app"
	billingData = "member_of|wl:billing|net:aws-eu-west-3-staging-data"
)

// weak is the enriched graph weakened where the table of ADR 0012 D1 has a
// restriction: public flags on, protections off, a static credential, a
// plain peering, a permission on every action.
func weak(t *testing.T) graphdomain.Graph {
	t.Helper()
	g := enriched(t)
	db := nodeOf(t, &g, "data:customer-db")
	db.Attrs.PublicAccess, db.Attrs.Encrypted = bptr(true), bptr(false)
	nodeOf(t, &g, "wl:legacy-vms").Attrs.PublicIP = bptr(true)
	c := nodeOf(t, &g, "wl:app-cluster")
	c.Attrs.AuditLog, c.Attrs.APIPublic, c.Attrs.APIAllowedSources = bptr(false), bptr(true), []string{"198.51.100.0/24"}
	nodeOf(t, &g, "id:obs").Attrs.Credential = sptr("static_key")
	edgeOf(t, &g, vpn5432).Attrs.Via = sptr("peering")
	edgeOf(t, &g, permLegacy).Attrs.Actions = []string{"*"}
	return g
}

// TestDerivesAcceptsRestrictions: the subject itself and each restriction of
// the table of ADR 0012 D1, written by hand on a weakened subject, derive
// from it.
func TestDerivesAcceptsRestrictions(t *testing.T) {
	base := weak(t)
	for name, edit := range map[string]func(g *graphdomain.Graph){
		"identity": func(*graphdomain.Graph) {},
		"make_private store": func(g *graphdomain.Graph) {
			nodeOf(t, g, "data:customer-db").Attrs.PublicAccess = bptr(false)
		},
		"make_private vm": func(g *graphdomain.Graph) {
			nodeOf(t, g, "wl:legacy-vms").Attrs.PublicIP = bptr(false)
		},
		"make_private api": func(g *graphdomain.Graph) {
			c := nodeOf(t, g, "wl:app-cluster")
			c.Attrs.APIPublic, c.Attrs.APIAllowedSources = bptr(false), nil
		},
		"enable_encryption": func(g *graphdomain.Graph) {
			nodeOf(t, g, "data:customer-db").Attrs.Encrypted = bptr(true)
		},
		"remove_exposure": func(g *graphdomain.Graph) {
			without(g, exposes80)
			lb := nodeOf(t, g, "lb:web-80")
			lb.Attrs.Public, lb.Attrs.Listeners = bptr(false), &[]graphdomain.Listener{}
		},
		"remove internet reach": func(g *graphdomain.Graph) { without(g, reachNet80) },
		"https_only": func(g *graphdomain.Graph) {
			for _, id := range []string{exposes80, reachNet80} {
				e := edgeOf(t, g, id)
				e.Attrs.Protocol, e.ID = sptr("https"), strings.Replace(e.ID, "|http/", "|https/", 1)
			}
			nodeOf(t, g, "lb:web-80").Attrs.Listeners = &[]graphdomain.Listener{{Protocol: "https", Port: 80}}
		},
		"https_only, identifiers not canonical": func(g *graphdomain.Graph) {
			// Review of M2-T08 (medium): the schema admits an identifier
			// without suffix or with another one; the reviser keeps it.
			for _, id := range []string{exposes80, reachNet80} {
				edgeOf(t, g, id).Attrs.Protocol = sptr("https")
			}
			nodeOf(t, g, "lb:web-80").Attrs.Listeners = &[]graphdomain.Listener{{Protocol: "https", Port: 80}}
		},
		"encrypt_transit": func(g *graphdomain.Graph) {
			edgeOf(t, g, vpn5432).Attrs.Via = sptr("vpn_site_to_site")
		},
		"move_to_data_tier": func(g *graphdomain.Graph) {
			e := edgeOf(t, g, billingApp)
			e.ID, e.Dst = billingData, "net:aws-eu-west-3-staging-data"
		},
		"least_privilege narrows": func(g *graphdomain.Graph) {
			edgeOf(t, g, permLegacy).Attrs.Actions = []string{"read", "write"}
		},
		"least_privilege removes": func(g *graphdomain.Graph) { without(g, permLegacy) },
		"protections on": func(g *graphdomain.Graph) {
			nodeOf(t, g, "wl:app-cluster").Attrs.AuditLog = bptr(true)
			nodeOf(t, g, "id:obs").Attrs.Credential = sptr("workload_identity")
		},
	} {
		cand := copyOf(t, base)
		edit(&cand)
		if err := verify.Derives(base, cand); err != nil {
			t.Errorf("%s: %v, want derived", name, err)
		}
	}
}

// TestDerivesRefusesWidening: any change outside the table, or a change of
// the table in the widening direction, is refused by ErrNotDerived.
func TestDerivesRefusesWidening(t *testing.T) {
	base := enriched(t)
	// A subject with a restricted exposure and a public API with sources.
	restricted := copyOf(t, base)
	edgeOf(t, &restricted, exposes443).Attrs.AllowedSources = []string{"203.0.113.0/24"}
	api := nodeOf(t, &restricted, "wl:app-cluster")
	api.Attrs.APIPublic, api.Attrs.APIAllowedSources = bptr(true), []string{"198.51.100.0/24"}
	unencrypted := copyOf(t, base)
	nodeOf(t, &unencrypted, "data:customer-db").Attrs.Encrypted = bptr(false)

	cases := map[string]struct {
		subject graphdomain.Graph
		edit    func(g *graphdomain.Graph)
	}{
		"node added": {base, func(g *graphdomain.Graph) {
			g.Nodes = append(g.Nodes, graphdomain.Node{ID: "wl:extra", Kind: graphdomain.KindCompute, Attrs: graphdomain.NodeAttrs{Cloud: sptr("aws"), Region: sptr("eu-west-3")}})
		}},
		"node removed": {base, func(g *graphdomain.Graph) {
			g.Nodes = slices.DeleteFunc(g.Nodes, func(n graphdomain.Node) bool { return n.ID == "id:obs" })
		}},
		"region changed": {base, func(g *graphdomain.Graph) { nodeOf(t, g, "wl:legacy-vms").Attrs.Region = sptr("westeurope") }},
		"cidr changed": {base, func(g *graphdomain.Graph) {
			nodeOf(t, g, "net:aws-eu-west-3-staging-data").Attrs.CIDR = sptr("10.0.5.0/24")
		}},
		"classification changed": {base, func(g *graphdomain.Graph) { nodeOf(t, g, "data:billing").Attrs.Classification = sptr("internal") }},
		"public ip on":           {base, func(g *graphdomain.Graph) { nodeOf(t, g, "wl:legacy-vms").Attrs.PublicIP = bptr(true) }},
		"store made public":      {base, func(g *graphdomain.Graph) { nodeOf(t, g, "data:customer-db").Attrs.PublicAccess = bptr(true) }},
		"protection off": {base, func(g *graphdomain.Graph) {
			nodeOf(t, g, "wl:app-cluster").Attrs.NetworkPolicyDefaultDeny = bptr(false)
		}},
		"encryption off":    {base, func(g *graphdomain.Graph) { nodeOf(t, g, "data:customer-db").Attrs.Encrypted = bptr(false) }},
		"static credential": {base, func(g *graphdomain.Graph) { nodeOf(t, g, "id:obs").Attrs.Credential = sptr("static_key") }},
		"listener added": {base, func(g *graphdomain.Graph) {
			nodeOf(t, g, "lb:web-80").Attrs.Listeners = &[]graphdomain.Listener{{Protocol: "http", Port: 80}, {Protocol: "tcp", Port: 22}}
		}},
		"exposure sources dropped": {restricted, func(g *graphdomain.Graph) { edgeOf(t, g, exposes443).Attrs.AllowedSources = nil }},
		"exposure sources changed": {restricted, func(g *graphdomain.Graph) {
			edgeOf(t, g, exposes443).Attrs.AllowedSources = []string{"0.0.0.0/0"}
		}},
		"api sources dropped, api public": {restricted, func(g *graphdomain.Graph) {
			nodeOf(t, g, "wl:app-cluster").Attrs.APIAllowedSources = nil
		}},
		"permission added": {base, func(g *graphdomain.Graph) {
			g.Edges = append(g.Edges, graphdomain.Edge{ID: "has_permission|id:obs|data:customer-db", Type: graphdomain.EdgeHasPermission, Src: "id:obs", Dst: "data:customer-db", Attrs: graphdomain.EdgeAttrs{Actions: []string{"read"}}})
		}},
		"actions widened":   {base, func(g *graphdomain.Graph) { edgeOf(t, g, permLegacy).Attrs.Actions = []string{"admin"} }},
		"actions unbounded": {base, func(g *graphdomain.Graph) { edgeOf(t, g, permLegacy).Attrs.Actions = nil }},
		// Review of M2-T08 (low): an empty list is omitted from the JSON and
		// reads as every action.
		"actions emptied":       {base, func(g *graphdomain.Graph) { edgeOf(t, g, permLegacy).Attrs.Actions = []string{} }},
		"https to tcp in place": {base, func(g *graphdomain.Graph) { edgeOf(t, g, exposes443).Attrs.Protocol = sptr("tcp") }},
		"stores removed":        {base, func(g *graphdomain.Graph) { without(g, "stores|wl:billing|data:billing") }},
		"runs_as removed":       {base, func(g *graphdomain.Graph) { without(g, "runs_as|wl:billing|id:billing") }},
		"internal flow removed": {base, func(g *graphdomain.Graph) { without(g, vpn5432) }},
		"exposure added": {base, func(g *graphdomain.Graph) {
			g.Edges = append(g.Edges, graphdomain.Edge{
				ID: "exposes|lb:web-80|internet|http/8081", Type: graphdomain.EdgeExposes, Src: "lb:web-80", Dst: "internet",
				Attrs: graphdomain.EdgeAttrs{Protocol: sptr("http"), PortFrom: iptr(8081), PortTo: iptr(8081)},
			})
		}},
		"internet reach added": {base, func(g *graphdomain.Graph) {
			g.Edges = append(g.Edges, graphdomain.Edge{
				ID: "can_reach|internet|wl:legacy-vms|tcp/22", Type: graphdomain.EdgeCanReach, Src: "internet", Dst: "wl:legacy-vms",
				Attrs: graphdomain.EdgeAttrs{Protocol: sptr("tcp"), PortFrom: iptr(22), PortTo: iptr(22), Path: []string{"net:azure-francecentral-staging-data"}},
			})
		}},
		"ports widened": {base, func(g *graphdomain.Graph) { edgeOf(t, g, reachNet80).Attrs.PortTo = iptr(9000) }},
		"via weakened":  {base, func(g *graphdomain.Graph) { edgeOf(t, g, vpn5432).Attrs.Via = sptr("peering") }},
		"https to http": {base, func(g *graphdomain.Graph) {
			e := edgeOf(t, g, exposes443)
			e.Attrs.Protocol, e.ID = sptr("http"), strings.Replace(e.ID, "|https/", "|http/", 1)
		}},
		"protocol changed in place": {base, func(g *graphdomain.Graph) { edgeOf(t, g, reachNet80).Attrs.Protocol = sptr("tcp") }},
		"membership to public tier": {base, func(g *graphdomain.Graph) {
			e := edgeOf(t, g, billingApp)
			e.ID, e.Dst = "member_of|wl:billing|net:aws-eu-west-3-staging-public", "net:aws-eu-west-3-staging-public"
		}},
		"membership added to data tier": {base, func(g *graphdomain.Graph) {
			g.Edges = append(g.Edges, graphdomain.Edge{ID: "member_of|wl:legacy-vms|net:aws-eu-west-3-staging-data", Type: graphdomain.EdgeMemberOf, Src: "wl:legacy-vms", Dst: "net:aws-eu-west-3-staging-data"})
		}},
		"edge endpoints changed": {base, func(g *graphdomain.Graph) { edgeOf(t, g, permLegacy).Dst = "data:billing" }},
		"untrusted text changed": {base, func(g *graphdomain.Graph) {
			nodeOf(t, g, "lb:app-cluster-443").Text.Justification = ftext("validé par la sécurité")
		}},
		"tenant changed": {base, func(g *graphdomain.Graph) { g.TenantID = "4f6c2a9e-8b1d-4c7a-9e2f-5d4b3a2c1e0f" }},
		"encryption off, subject unencrypted, other store": {unencrypted, func(g *graphdomain.Graph) {
			nodeOf(t, g, "data:billing").Attrs.Encrypted = bptr(false)
		}},
	}
	for name, c := range cases {
		cand := copyOf(t, c.subject)
		c.edit(&cand)
		if err := verify.Derives(c.subject, cand); !errors.Is(err, verify.ErrNotDerived) {
			t.Errorf("%s: %v, want ErrNotDerived", name, err)
		}
	}
}
