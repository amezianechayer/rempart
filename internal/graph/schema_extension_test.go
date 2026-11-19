package graph_test

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/amezianechayer/rempart/internal/graph"
	"github.com/amezianechayer/rempart/internal/graph/domain"
	"github.com/amezianechayer/rempart/internal/graph/reach"
	"github.com/amezianechayer/rempart/schemas"
)

func ptr[T any](v T) *T { return &v }

// extendedGraph is a valid graph using every element of ADR 0010, D6: Identity
// and Account nodes, RUNS_AS and HAS_PERMISSION edges (with "*", representable
// to describe a trap), cluster security attributes, public_ip, credential,
// api_allowed_sources and a restricted exposure.
func extendedGraph() domain.Graph {
	str, yes, no := ptr[string], ptr(true), ptr(false)
	n := func(id string, k domain.NodeKind, a domain.NodeAttrs) domain.Node {
		return domain.Node{ID: id, Kind: k, Attrs: a}
	}
	e := func(t domain.EdgeType, src, dst string, a domain.EdgeAttrs) domain.Edge {
		return domain.Edge{ID: string(t) + "|" + src + "|" + dst, Type: t, Src: src, Dst: dst, Attrs: a}
	}
	lowerID := func(ed domain.Edge) domain.Edge {
		b := []byte(ed.ID)
		for i, c := range b {
			if c >= 'A' && c <= 'Z' {
				b[i] = c + 'a' - 'A'
			}
		}
		ed.ID = string(b)
		return ed
	}
	g := domain.Graph{
		Version: domain.GraphVersion, TenantID: "3f6c2a9e-8b1d-4c7a-9e2f-5d4b3a2c1e0f", Source: domain.SourceDesign,
		Nodes: []domain.Node{
			n("internet", domain.KindInternet, domain.NodeAttrs{}),
			n("net:vpc", domain.KindNetwork, domain.NodeAttrs{Subtype: str("vpc"), CIDR: str("10.0.0.0/16"), Cloud: str("aws"), Region: str("eu-west-3"), Env: str("dev")}),
			n("net:vpc-app", domain.KindNetwork, domain.NodeAttrs{Subtype: str("subnet"), Tier: str("app"), CIDR: str("10.0.0.0/24"), Cloud: str("aws"), Region: str("eu-west-3"), Env: str("dev")}),
			n("net:vpc-public", domain.KindNetwork, domain.NodeAttrs{Subtype: str("subnet"), Tier: str("public"), CIDR: str("10.0.1.0/26"), Cloud: str("aws"), Region: str("eu-west-3"), Env: str("dev")}),
			n("wl:k8s", domain.KindK8sCluster, domain.NodeAttrs{
				Cloud: str("aws"), Region: str("eu-west-3"), Count: ptr(3),
				APIPublic: yes, APIAllowedSources: []string{"203.0.113.0/24"},
				AuditLog: yes, SecretsEncryption: yes, NetworkPolicyDefaultDeny: yes, AdmissionPolicy: yes, WorkloadIdentity: no,
			}),
			n("wl:vm", domain.KindCompute, domain.NodeAttrs{Subtype: str("vm"), Cloud: str("aws"), Region: str("eu-west-3"), Count: ptr(1), PublicIP: no}),
			n("id:vm", domain.KindIdentity, domain.NodeAttrs{Subtype: str("role"), Cloud: str("aws"), Credential: str("workload_identity")}),
			n("id:k8s-ci", domain.KindIdentity, domain.NodeAttrs{Subtype: str("k8s_service_account"), Cloud: str("aws"), Credential: str("static_key")}),
			n("acct:main", domain.KindAccount, domain.NodeAttrs{Cloud: str("aws")}),
			n("data:d", domain.KindDataStore, domain.NodeAttrs{Subtype: str("dataset"), Classification: str("internal"), Encrypted: yes, PublicAccess: no}),
			n("lb:vm-443", domain.KindLoadBalancer, domain.NodeAttrs{
				Cloud: str("aws"), Region: str("eu-west-3"), Public: yes,
				Listeners: &[]domain.Listener{{Protocol: "https", Port: 443}},
			}),
		},
		Edges: []domain.Edge{
			lowerID(e(domain.EdgeMemberOf, "net:vpc-app", "net:vpc", domain.EdgeAttrs{})),
			lowerID(e(domain.EdgeMemberOf, "net:vpc-public", "net:vpc", domain.EdgeAttrs{})),
			lowerID(e(domain.EdgeMemberOf, "wl:vm", "net:vpc-app", domain.EdgeAttrs{})),
			lowerID(e(domain.EdgeMemberOf, "wl:k8s", "net:vpc-app", domain.EdgeAttrs{})),
			lowerID(e(domain.EdgeMemberOf, "lb:vm-443", "net:vpc-public", domain.EdgeAttrs{})),
			lowerID(e(domain.EdgeExposes, "lb:vm-443", "internet", domain.EdgeAttrs{Protocol: str("https"), PortFrom: ptr(443), PortTo: ptr(443), AllowedSources: []string{"192.0.2.0/24"}})),
			lowerID(e(domain.EdgeCanReach, "lb:vm-443", "wl:vm", domain.EdgeAttrs{Protocol: str("https"), PortFrom: ptr(443), PortTo: ptr(443), Via: str("load_balancer"), Path: []string{"net:vpc-public", "net:vpc-app"}})),
			lowerID(e(domain.EdgeRunsAs, "wl:vm", "id:vm", domain.EdgeAttrs{})),
			lowerID(e(domain.EdgeRunsAs, "wl:k8s", "id:k8s-ci", domain.EdgeAttrs{})),
			lowerID(e(domain.EdgeHasPermission, "id:vm", "data:d", domain.EdgeAttrs{Actions: []string{"read", "write"}})),
			lowerID(e(domain.EdgeHasPermission, "id:k8s-ci", "acct:main", domain.EdgeAttrs{Actions: []string{"*"}})),
			lowerID(e(domain.EdgeHasPermission, "id:k8s-ci", "wl:k8s", domain.EdgeAttrs{Actions: []string{"admin"}})),
		},
	}
	g.Text.Summary = ptr(domain.NewFreeText("Graphe étendu : identités, comptes 🙂"))
	return g
}

func nodeOf(t *testing.T, g *domain.Graph, id string) *domain.Node {
	t.Helper()
	i := slices.IndexFunc(g.Nodes, func(n domain.Node) bool { return n.ID == id })
	if i < 0 {
		t.Fatalf("node %s missing", id)
	}
	return &g.Nodes[i]
}

func edgeOf(t *testing.T, g *domain.Graph, typ domain.EdgeType, src string) *domain.Edge {
	t.Helper()
	i := slices.IndexFunc(g.Edges, func(e domain.Edge) bool { return e.Type == typ && e.Src == src })
	if i < 0 {
		t.Fatalf("edge %s from %s missing", typ, src)
	}
	return &g.Edges[i]
}

// TestGraphSchemaExtension proves D5 and D6 of ADR 0010: schema v1 extended in
// place (Identity, Account, RUNS_AS, HAS_PERMISSION with "*" representable),
// required security attributes, closed values, the new rules of
// domain.Validate with fixed errors, free text without C0 or C1 control nor
// bidirectional character (obligation (cp)), and every edge type and boolean
// attribute of the schema classified by reach.FromGraph (T116).
func TestGraphSchemaExtension(t *testing.T) {
	if err := graph.ValidateSchema(extendedGraph()); err != nil {
		t.Fatalf("ValidateSchema(extended graph): %v", err)
	}

	type mutation struct {
		name string
		edit func(t *testing.T, g *domain.Graph)
		err  error // nil: graph.ErrGraphInvalid from the schema
	}
	text := func(s string) func(t *testing.T, g *domain.Graph) {
		return func(t *testing.T, g *domain.Graph) {
			edgeOf(t, g, domain.EdgeExposes, "lb:vm-443").Text.Justification = ptr(domain.NewFreeText("exposition publique" + s))
		}
	}
	refused := []mutation{
		// Closed values and required attributes (schema).
		{"actions_empty", func(t *testing.T, g *domain.Graph) {
			edgeOf(t, g, domain.EdgeHasPermission, "id:vm").Attrs.Actions = []string{}
		}, nil},
		{"actions_missing", func(t *testing.T, g *domain.Graph) {
			edgeOf(t, g, domain.EdgeHasPermission, "id:vm").Attrs.Actions = nil
		}, nil},
		{"actions_duplicate", func(t *testing.T, g *domain.Graph) {
			edgeOf(t, g, domain.EdgeHasPermission, "id:vm").Attrs.Actions = []string{"read", "read"}
		}, nil},
		{"actions_concrete", func(t *testing.T, g *domain.Graph) {
			edgeOf(t, g, domain.EdgeHasPermission, "id:vm").Attrs.Actions = []string{"s3:GetObject"}
		}, nil},
		{"credential_unknown", func(t *testing.T, g *domain.Graph) { nodeOf(t, g, "id:vm").Attrs.Credential = ptr("password") }, nil},
		{"identity_without_credential", func(t *testing.T, g *domain.Graph) { nodeOf(t, g, "id:vm").Attrs.Credential = nil }, nil},
		{"identity_subtype", func(t *testing.T, g *domain.Graph) { nodeOf(t, g, "id:vm").Attrs.Subtype = ptr("vm") }, nil},
		{"identity_without_cloud", func(t *testing.T, g *domain.Graph) { nodeOf(t, g, "id:vm").Attrs.Cloud = nil }, nil},
		{"account_without_cloud", func(t *testing.T, g *domain.Graph) { nodeOf(t, g, "acct:main").Attrs.Cloud = nil }, nil},
		{"compute_without_public_ip", func(t *testing.T, g *domain.Graph) { nodeOf(t, g, "wl:vm").Attrs.PublicIP = nil }, nil},
		{"cluster_without_audit_log", func(t *testing.T, g *domain.Graph) { nodeOf(t, g, "wl:k8s").Attrs.AuditLog = nil }, nil},
		{"cluster_without_secrets_encryption", func(t *testing.T, g *domain.Graph) { nodeOf(t, g, "wl:k8s").Attrs.SecretsEncryption = nil }, nil},
		{"cluster_without_default_deny", func(t *testing.T, g *domain.Graph) { nodeOf(t, g, "wl:k8s").Attrs.NetworkPolicyDefaultDeny = nil }, nil},
		{"cluster_without_admission", func(t *testing.T, g *domain.Graph) { nodeOf(t, g, "wl:k8s").Attrs.AdmissionPolicy = nil }, nil},
		{"cluster_without_workload_identity", func(t *testing.T, g *domain.Graph) { nodeOf(t, g, "wl:k8s").Attrs.WorkloadIdentity = nil }, nil},
		{"exposes_without_ports", func(t *testing.T, g *domain.Graph) {
			a := &edgeOf(t, g, domain.EdgeExposes, "lb:vm-443").Attrs
			a.PortFrom, a.PortTo = nil, nil
		}, nil},
		{"can_reach_without_protocol", func(t *testing.T, g *domain.Graph) {
			edgeOf(t, g, domain.EdgeCanReach, "lb:vm-443").Attrs.Protocol = nil
		}, nil},
		{"source_whole_ipv4", func(t *testing.T, g *domain.Graph) {
			edgeOf(t, g, domain.EdgeExposes, "lb:vm-443").Attrs.AllowedSources = []string{"0.0.0.0/0"}
		}, nil},
		{"api_sources_over_64", func(t *testing.T, g *domain.Graph) {
			s := make([]string, 65)
			for i := range s {
				s[i] = "192.0.2.0/24"
			}
			nodeOf(t, g, "wl:k8s").Attrs.APIAllowedSources = s
		}, nil},
		{"identity_prefix_on_other_kind", func(t *testing.T, g *domain.Graph) {
			g.Nodes = append(g.Nodes, domain.Node{ID: "id:x", Kind: domain.KindAccount, Attrs: domain.NodeAttrs{Cloud: ptr("aws")}})
		}, domain.ErrIDPrefix},
		// Free text: C0, C1 and bidirectional characters (obligation (cp)).
		{"text_newline", text("\n"), nil},
		{"text_tab", text("\t"), nil},
		{"text_escape", text("\x1b[31m"), nil},
		{"text_nul", text("\x00"), nil},
		{"text_c1", text("\u0085"), nil},
		{"text_rlo", text("\u202e"), nil},
		{"text_lri", text("\u2066"), nil},
		{"text_alm", text("\u061c"), nil},
		{"text_rlm", text("\u200f"), nil},
		// Rules of domain.Validate (fixed errors).
		{"identity_prefix_on_account", func(t *testing.T, g *domain.Graph) { nodeOf(t, g, "acct:main").ID = "id:main" }, domain.ErrIDPrefix},
		{"account_prefix_on_identity", func(t *testing.T, g *domain.Graph) {
			nodeOf(t, g, "id:k8s-ci").ID = "acct:k8s-ci"
			edgeOf(t, g, domain.EdgeRunsAs, "wl:k8s").Dst = "acct:k8s-ci"
			for i := range g.Edges {
				if g.Edges[i].Src == "id:k8s-ci" {
					g.Edges[i].Src = "acct:k8s-ci"
				}
			}
		}, domain.ErrIDPrefix},
		{"identity_without_prefix", func(t *testing.T, g *domain.Graph) {
			g.Nodes = append(g.Nodes, domain.Node{ID: "wl:role", Kind: domain.KindIdentity, Attrs: domain.NodeAttrs{Subtype: ptr("role"), Cloud: ptr("aws"), Credential: ptr("static_key")}})
		}, domain.ErrIDPrefix},
		{"internet_id_on_workload", func(t *testing.T, g *domain.Graph) { nodeOf(t, g, "internet").Kind = domain.KindK8sWorkload }, domain.ErrIDPrefix},
		{"runs_as_from_datastore", func(t *testing.T, g *domain.Graph) { edgeOf(t, g, domain.EdgeRunsAs, "wl:vm").Src = "data:d" }, domain.ErrEndpointKind},
		{"runs_as_to_account", func(t *testing.T, g *domain.Graph) { edgeOf(t, g, domain.EdgeRunsAs, "wl:vm").Dst = "acct:main" }, domain.ErrEndpointKind},
		{"permission_from_compute", func(t *testing.T, g *domain.Graph) { edgeOf(t, g, domain.EdgeHasPermission, "id:vm").Src = "wl:vm" }, domain.ErrEndpointKind},
		{"permission_to_network", func(t *testing.T, g *domain.Graph) { edgeOf(t, g, domain.EdgeHasPermission, "id:vm").Dst = "net:vpc" }, domain.ErrEndpointKind},
		{"exposes_from_datastore", func(t *testing.T, g *domain.Graph) {
			edgeOf(t, g, domain.EdgeExposes, "lb:vm-443").Src = "data:d"
			nodeOf(t, g, "lb:vm-443").Attrs.Public = ptr(false)
			nodeOf(t, g, "lb:vm-443").Attrs.Listeners = &[]domain.Listener{}
		}, domain.ErrEndpointKind},
		{"exposes_not_to_internet", func(t *testing.T, g *domain.Graph) { edgeOf(t, g, domain.EdgeExposes, "lb:vm-443").Dst = "wl:vm" }, domain.ErrEndpointKind},
		{"ports_reversed", func(t *testing.T, g *domain.Graph) {
			a := &edgeOf(t, g, domain.EdgeCanReach, "lb:vm-443").Attrs
			a.PortFrom, a.PortTo = ptr(8443), ptr(443)
		}, domain.ErrPortRange},
		{"public_lb_without_exposes", func(t *testing.T, g *domain.Graph) {
			g.Edges = slices.DeleteFunc(g.Edges, func(e domain.Edge) bool { return e.Type == domain.EdgeExposes })
		}, domain.ErrLoadBalancer},
		{"private_lb_with_exposes", func(t *testing.T, g *domain.Graph) { nodeOf(t, g, "lb:vm-443").Attrs.Public = ptr(false) }, domain.ErrLoadBalancer},
		{"listener_without_exposes", func(t *testing.T, g *domain.Graph) {
			nodeOf(t, g, "lb:vm-443").Attrs.Listeners = &[]domain.Listener{{Protocol: "https", Port: 443}, {Protocol: "tcp", Port: 22}}
		}, domain.ErrLoadBalancer},
		{"exposes_without_listener", func(t *testing.T, g *domain.Graph) {
			a := &edgeOf(t, g, domain.EdgeExposes, "lb:vm-443").Attrs
			a.PortFrom, a.PortTo = ptr(443), ptr(444)
		}, domain.ErrLoadBalancer},
		{"api_sources_with_private_api", func(t *testing.T, g *domain.Graph) { nodeOf(t, g, "wl:k8s").Attrs.APIPublic = ptr(false) }, domain.ErrAPISources},
		{"source_host_bits", func(t *testing.T, g *domain.Graph) {
			edgeOf(t, g, domain.EdgeExposes, "lb:vm-443").Attrs.AllowedSources = []string{"192.0.2.7/24"}
		}, domain.ErrSourceCIDR},
		{"api_source_host_bits", func(t *testing.T, g *domain.Graph) {
			nodeOf(t, g, "wl:k8s").Attrs.APIAllowedSources = []string{"203.0.113.9/24"}
		}, domain.ErrSourceCIDR},
		{"public_ip_on_datastore", func(t *testing.T, g *domain.Graph) { nodeOf(t, g, "data:d").Attrs.PublicIP = ptr(true) }, domain.ErrAttrKind},
		{"public_access_on_compute", func(t *testing.T, g *domain.Graph) { nodeOf(t, g, "wl:vm").Attrs.PublicAccess = ptr(true) }, domain.ErrAttrKind},
		{"api_public_on_compute", func(t *testing.T, g *domain.Graph) { nodeOf(t, g, "wl:vm").Attrs.APIPublic = ptr(true) }, domain.ErrAttrKind},
		{"credential_on_compute", func(t *testing.T, g *domain.Graph) { nodeOf(t, g, "wl:vm").Attrs.Credential = ptr("static_key") }, domain.ErrAttrKind},
		{"actions_on_can_reach", func(t *testing.T, g *domain.Graph) {
			edgeOf(t, g, domain.EdgeCanReach, "lb:vm-443").Attrs.Actions = []string{"read"}
		}, domain.ErrAttrKind},
		{"sources_on_internal_can_reach", func(t *testing.T, g *domain.Graph) {
			edgeOf(t, g, domain.EdgeCanReach, "lb:vm-443").Attrs.AllowedSources = []string{"192.0.2.0/24"}
		}, domain.ErrAttrKind},
	}
	for _, m := range refused {
		t.Run(m.name, func(t *testing.T) {
			g := extendedGraph()
			m.edit(t, &g)
			err := graph.ValidateSchema(g)
			if !errors.Is(err, graph.ErrGraphInvalid) {
				t.Fatalf("ValidateSchema = %v, want ErrGraphInvalid", err)
			}
			if m.err != nil && !errors.Is(err, m.err) {
				t.Fatalf("ValidateSchema = %v, want %v", err, m.err)
			}
		})
	}

	t.Run("free_text_accepted", func(t *testing.T) {
		g := extendedGraph()
		text(" : accès « HTTPS » 443, données réglementées ; 日本語 🙂")(t, &g)
		if err := graph.ValidateSchema(g); err != nil {
			t.Fatalf("ValidateSchema(printable text) = %v", err)
		}
	})

	t.Run("fromgraph_classifies_every_fact", func(t *testing.T) {
		raw, err := schemas.FS.ReadFile(schemas.Graph)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Defs map[string]struct {
				Properties map[string]struct {
					Type string   `json:"type"`
					Enum []string `json:"enum"`
				} `json:"properties"`
			} `json:"$defs"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		classes := []string{"R1", "R2", "R3", "R4", "R5", "R6", "non_network"}
		types := doc.Defs["edge"].Properties["type"].Enum
		if len(types) != 6 {
			t.Fatalf("edge types %v, want the 6 of ADR 0010", types)
		}
		for _, typ := range types {
			if c := reach.EdgeClass(domain.EdgeType(typ)); !slices.Contains(classes, c) {
				t.Errorf("edge type %s classified %q by FromGraph, want one of %v", typ, c, classes)
			}
		}
		bools := 0
		for _, def := range []string{"node_attrs", "edge_attrs"} {
			for name, p := range doc.Defs[def].Properties {
				if p.Type != "boolean" {
					continue
				}
				bools++
				if c := reach.BoolAttrClass(name); !slices.Contains(classes, c) {
					t.Errorf("boolean %s.%s classified %q by FromGraph, want one of %v", def, name, c, classes)
				}
			}
		}
		if bools != 10 {
			t.Errorf("%d boolean attributes in the schema, want 10", bools)
		}
		for fact, want := range map[string]string{
			"EXPOSES": "R1", "CAN_REACH": "R2", "MEMBER_OF": "R6", "STORES": "non_network", "RUNS_AS": "non_network", "HAS_PERMISSION": "non_network",
		} {
			if got := reach.EdgeClass(domain.EdgeType(fact)); got != want {
				t.Errorf("EdgeClass(%s) = %q, want %q", fact, got, want)
			}
		}
		for fact, want := range map[string]string{
			"public_access": "R3", "api_public": "R4", "public_ip": "R5", "network_policy_default_deny": "R6", "public": "R1",
		} {
			if got := reach.BoolAttrClass(fact); got != want {
				t.Errorf("BoolAttrClass(%s) = %q, want %q", fact, got, want)
			}
		}
		if reach.EdgeClass("CAN_ASSUME") != "" || reach.BoolAttrClass("ambiguous") != "" {
			t.Errorf("an unknown fact is classified: the guard would never fail")
		}
	})
}
