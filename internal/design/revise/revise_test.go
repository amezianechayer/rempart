package revise_test

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/amezianechayer/rempart/internal/design"
	"github.com/amezianechayer/rempart/internal/design/confirm"
	"github.com/amezianechayer/rempart/internal/design/revise"
	"github.com/amezianechayer/rempart/internal/design/verify"
	"github.com/amezianechayer/rempart/internal/graph"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	"github.com/amezianechayer/rempart/internal/graph/reach"
	"github.com/amezianechayer/rempart/internal/intent"
	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
	"github.com/amezianechayer/rempart/internal/policy/adapters/opa"
	policydomain "github.com/amezianechayer/rempart/internal/policy/domain"
)

const tenant = "3f6c2a9e-8b1d-4c7a-9e2f-5d4b3a2c1e0f"

func reference(t testing.TB) graphdomain.Graph {
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
		t.Fatal(err)
	}
	return g
}

func sshTrap(t testing.TB) graphdomain.Graph {
	t.Helper()
	raw, err := os.ReadFile("../../threat/testdata/reference-ssh.graph.json")
	if err != nil {
		t.Fatal(err)
	}
	var g graphdomain.Graph
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	if err := graph.ValidateSchema(g); err != nil {
		t.Fatal(err)
	}
	return g
}

// enriched is the reference graph with what it lacks for the table of ADR
// 0012 D1 (obligation (fq)): an http exposure and an http flow from the
// Internet (https_only), a data subnet in the AWS VPC and a host of
// regulated data in the app tier (move_to_data_tier).
func enriched(t testing.TB) graphdomain.Graph {
	t.Helper()
	raw, err := os.ReadFile("testdata/enriched.graph.json")
	if err != nil {
		t.Fatal(err)
	}
	var g graphdomain.Graph
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	if !valid(g) {
		t.Fatal("enriched graph invalid")
	}
	return g
}

// noncanonical is the enriched graph whose http edges carry identifiers the
// schema admits but the builder never writes: no suffix, or another protocol
// (review of M2-T08, medium: https_only refused by the verifier on them).
func noncanonical(t testing.TB) graphdomain.Graph {
	t.Helper()
	g := enriched(t)
	for i := range g.Edges {
		switch g.Edges[i].ID {
		case "exposes|lb:web-80|internet|http/80":
			g.Edges[i].ID = "exposes|lb:web-80|internet"
		case "can_reach|internet|wl:billing|http/8080":
			g.Edges[i].ID = "can_reach|internet|wl:billing|tcp/8080"
		}
	}
	slices.SortFunc(g.Edges, func(a, b graphdomain.Edge) int { return strings.Compare(a.ID, b.ID) })
	if !valid(g) {
		t.Fatal("noncanonical graph invalid")
	}
	return g
}

// targets of the enriched graphs for the remediations the reference graph
// cannot exercise.
var targets = map[policydomain.Remediation][]string{
	policydomain.RemediationHTTPSOnly: {
		"lb:web-80", "exposes|lb:web-80|internet|http/80", "can_reach|internet|wl:billing|http/8080",
		"exposes|lb:web-80|internet", "can_reach|internet|wl:billing|tcp/8080",
	},
	policydomain.RemediationMoveToDataTier: {"wl:billing"},
}

func clone(t testing.TB, g graphdomain.Graph) graphdomain.Graph {
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

func allControls(t testing.TB) []policydomain.Control {
	t.Helper()
	e, err := opa.NewDesign()
	if err != nil {
		t.Fatal(err)
	}
	return append(e.Controls(), verify.CoreControls()...)
}

// fataler is satisfied by *testing.T and *rapid.T.
type fataler interface {
	Helper()
	Fatal(args ...any)
}

func reachOf(t fataler, g graphdomain.Graph) reach.Result {
	t.Helper()
	m, err := reach.FromGraph(graphdomain.FactsOf(g))
	if err != nil {
		t.Fatal(err)
	}
	r, err := reach.Compute(m, reach.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func ptr[T any](v T) *T { return &v }

func valid(g graphdomain.Graph) bool {
	return graph.ValidateSchema(g) == nil && graphdomain.Validate(g) == nil
}

// mutate weakens g at random, keeping it valid: public flags, missing
// protections, static credentials, wide permissions, plain peering.
func mutate(t *rapid.T, g *graphdomain.Graph) {
	for i := range g.Nodes {
		n := &g.Nodes[i]
		a := &n.Attrs
		draw := func(label string) bool { return rapid.Bool().Draw(t, n.ID+"/"+label) }
		switch n.Kind {
		case graphdomain.KindDataStore:
			if draw("public_access") {
				a.PublicAccess = ptr(true)
			}
			if draw("unencrypted") {
				a.Encrypted = ptr(false)
			}
		case graphdomain.KindCompute:
			if draw("public_ip") {
				a.PublicIP = ptr(true)
			}
		case graphdomain.KindK8sCluster:
			if draw("api_public") {
				a.APIPublic = ptr(true)
				if draw("api_sources") {
					a.APIAllowedSources = []string{"203.0.113.0/24"}
				}
			}
			for label, p := range map[string]**bool{"audit": &a.AuditLog, "secrets": &a.SecretsEncryption, "netpol": &a.NetworkPolicyDefaultDeny, "admission": &a.AdmissionPolicy, "wi": &a.WorkloadIdentity} {
				if draw(label) {
					*p = ptr(false)
				}
			}
		case graphdomain.KindIdentity:
			if draw("static_key") {
				a.Credential = ptr("static_key")
			}
		}
	}
	for i := range g.Edges {
		e := &g.Edges[i]
		switch e.Type {
		case graphdomain.EdgeHasPermission:
			e.Attrs.Actions = []string{rapid.SampledFrom([]string{"read", "write", "admin", "*"}).Draw(t, e.ID+"/actions")}
		case graphdomain.EdgeCanReach:
			if rapid.Bool().Draw(t, e.ID+"/peering") && e.Attrs.Via != nil && *e.Attrs.Via == "vpn_site_to_site" {
				e.Attrs.Via = ptr("peering")
			}
		}
	}
}

// closure of a set of abstract actions (ADR 0010 D8).
func closure(actions []string) map[string]bool {
	out := map[string]bool{}
	if actions == nil {
		actions = []string{"*"}
	}
	for _, a := range actions {
		switch a {
		case "admin":
			out["read"], out["write"], out["admin"] = true, true, true
		case "*":
			out["read"], out["write"], out["admin"], out["*"] = true, true, true, true
		default:
			out[a] = true
		}
	}
	return out
}

func isTrue(p *bool) bool { return p != nil && *p }

// TestRevisionNeverWidens proves ADR 0012 D1 (T110): whatever the valid graph
// and the findings of any control on any resource, the revised graph is valid,
// its reachability is included in the initial one, no permission or identity
// binding is added nor any closure of actions enlarged, no public flag turns
// on, no source list changes on a kept edge or a public API, no protection
// turns off, no credential becomes static, no placement, prefix,
// classification, residency or regulation changes, no node is added or
// removed, and a revision is reported only for a change of the graph.
//
// Obligation (fq): the enriched base exercises https_only and
// move_to_data_tier, whose coverage is required; edges are paired across the
// renaming of https_only; every revision derives from its input for the
// verifier (verify.Derives, obligation (fp)).
func TestRevisionNeverWidens(t *testing.T) {
	bases := []graphdomain.Graph{reference(t), sshTrap(t), enriched(t), noncanonical(t)}
	controls := allControls(t)
	byRemediation := map[policydomain.Remediation][]policydomain.Control{}
	for _, c := range controls {
		byRemediation[c.Remediation] = append(byRemediation[c.Remediation], c)
	}
	rapid.Check(t, func(rt *rapid.T) {
		b := rapid.IntRange(0, len(bases)-1).Draw(rt, "base")
		g := clone(t, bases[b])
		weak := clone(t, g)
		mutate(rt, &weak)
		if valid(weak) {
			g = weak
		}
		var ids []string
		for _, n := range g.Nodes {
			ids = append(ids, n.ID)
		}
		for _, e := range g.Edges {
			ids = append(ids, e.ID)
		}
		var fs []loopsdomain.Finding
		for i, n := 0, rapid.IntRange(0, 12).Draw(rt, "findings"); i < n; i++ {
			c := rapid.SampledFrom(controls).Draw(rt, "control")
			fs = append(fs, loopsdomain.Finding{Code: c.ID, Severity: c.Severity, Resource: rapid.SampledFrom(ids).Draw(rt, "resource")})
		}
		if b >= 2 {
			for _, r := range []policydomain.Remediation{policydomain.RemediationHTTPSOnly, policydomain.RemediationMoveToDataTier} {
				if rapid.Bool().Draw(rt, "target "+string(r)) {
					c := rapid.SampledFrom(byRemediation[r]).Draw(rt, "targeted control")
					fs = append(fs, loopsdomain.Finding{Code: c.ID, Severity: c.Severity, Resource: rapid.SampledFrom(targets[r]).Draw(rt, "targeted resource")})
				}
			}
		}
		before := clone(t, g)
		got, applied, err := revise.Revise(g, fs, controls)
		if err != nil {
			rt.Fatalf("Revise: %v", err)
		}
		if !reflect.DeepEqual(g, before) {
			rt.Fatalf("Revise modified its input")
		}
		checkNeverWidens(rt, before, got, applied, fs)
		if err := verify.Derives(before, got); err != nil {
			rt.Fatalf("(fp) the verifier refuses a revision of the table: %v (applied %+v)", err, applied)
		}
	})
}

// TestRevisionCoversHTTPSAndDataTier (obligation (fq)): on the enriched bases,
// canonical or not, https_only and move_to_data_tier each apply on every
// target, never widen and derive from their input. Deterministic: under
// -short rapid draws only 20 graphs, too few to require their coverage in
// TestRevisionNeverWidens.
func TestRevisionCoversHTTPSAndDataTier(t *testing.T) {
	controls := allControls(t)
	for b, base := range []graphdomain.Graph{enriched(t), noncanonical(t)} {
		applications := map[policydomain.Remediation]int{}
		ids := map[string]bool{}
		for _, n := range base.Nodes {
			ids[n.ID] = true
		}
		for _, e := range base.Edges {
			ids[e.ID] = true
		}
		for _, r := range []policydomain.Remediation{policydomain.RemediationHTTPSOnly, policydomain.RemediationMoveToDataTier} {
			var code string
			for _, c := range controls {
				if c.Remediation == r {
					code = c.ID
				}
			}
			for _, res := range targets[r] {
				if !ids[res] {
					continue
				}
				fs := []loopsdomain.Finding{{Code: code, Severity: loopsdomain.SeverityHigh, Resource: res}}
				got, applied, err := revise.Revise(base, fs, controls)
				if err != nil || len(applied) != 1 || applied[0].Remediation != r {
					t.Errorf("%s on %s: applied %+v, %v; want it applied", r, res, applied, err)
					continue
				}
				rapid.Check(t, func(rt *rapid.T) { checkNeverWidens(rt, base, got, applied, fs) })
				if err := verify.Derives(base, got); err != nil {
					t.Errorf("%s on %s: Derives refused: %v", r, res, err)
				}
				applications[r]++
			}
		}
		// Obligation (gv): never green on empty targets.
		for _, r := range []policydomain.Remediation{policydomain.RemediationHTTPSOnly, policydomain.RemediationMoveToDataTier} {
			if applications[r] == 0 {
				t.Errorf("base %d: %s never applied", b, r)
			}
		}
	}
}

// edgeKey pairs an edge with its revision: https_only renames it, so the key
// is its type, ends, ports and protocol with https read as http.
func edgeKey(e graphdomain.Edge) string {
	k := string(e.Type) + "|" + e.Src + "|" + e.Dst
	for _, p := range []*int{e.Attrs.PortFrom, e.Attrs.PortTo} {
		if p == nil {
			k += "|-"
		} else {
			k += "|" + strconv.Itoa(*p)
		}
	}
	if p := e.Attrs.Protocol; p != nil && *p != "https" {
		k += "|" + *p
	} else if p != nil {
		k += "|http"
	}
	return k
}

func checkNeverWidens(t *rapid.T, g, h graphdomain.Graph, applied []revise.Applied, fs []loopsdomain.Finding) {
	if !valid(h) {
		t.Fatalf("(6) revised graph invalid")
	}
	if !reachOf(t, h).SubsetOf(reachOf(t, g)) {
		t.Fatalf("(1) reachability widened")
	}
	nodes := map[string]graphdomain.Node{}
	for _, n := range g.Nodes {
		nodes[n.ID] = n
	}
	if len(h.Nodes) != len(g.Nodes) {
		t.Fatalf("(5) %d nodes, want %d", len(h.Nodes), len(g.Nodes))
	}
	for _, n := range h.Nodes {
		o, ok := nodes[n.ID]
		if !ok {
			t.Fatalf("(5) node %s added", n.ID)
		}
		a, b := o.Attrs, n.Attrs
		if !reflect.DeepEqual([]any{a.Cloud, a.Region, a.CIDR, a.Classification, a.Residency, a.Regulation}, []any{b.Cloud, b.Region, b.CIDR, b.Classification, b.Residency, b.Regulation}) {
			t.Fatalf("(5) %s: placement, prefix, classification, residency or regulation changed", n.ID)
		}
		for label, pair := range map[string][2]*bool{"public_access": {a.PublicAccess, b.PublicAccess}, "public_ip": {a.PublicIP, b.PublicIP}, "api_public": {a.APIPublic, b.APIPublic}, "public": {a.Public, b.Public}} {
			if isTrue(pair[1]) && !isTrue(pair[0]) {
				t.Fatalf("(3) %s: %s turned on", n.ID, label)
			}
		}
		if isTrue(b.APIPublic) && !slices.Equal(a.APIAllowedSources, b.APIAllowedSources) {
			t.Fatalf("(3) %s: sources of a public API changed", n.ID)
		}
		for label, pair := range map[string][2]*bool{"encrypted": {a.Encrypted, b.Encrypted}, "audit_log": {a.AuditLog, b.AuditLog}, "secrets_encryption": {a.SecretsEncryption, b.SecretsEncryption}, "network_policy_default_deny": {a.NetworkPolicyDefaultDeny, b.NetworkPolicyDefaultDeny}, "admission_policy": {a.AdmissionPolicy, b.AdmissionPolicy}, "workload_identity": {a.WorkloadIdentity, b.WorkloadIdentity}} {
			if isTrue(pair[0]) && !isTrue(pair[1]) {
				t.Fatalf("(4) %s: %s turned off", n.ID, label)
			}
		}
		if b.Credential != nil && *b.Credential == "static_key" && (a.Credential == nil || *a.Credential != "static_key") {
			t.Fatalf("(4) %s: credential became static", n.ID)
		}
	}
	edges := map[string]graphdomain.Edge{}
	paired := map[string]graphdomain.Edge{}
	for _, e := range g.Edges {
		edges[e.ID] = e
		paired[edgeKey(e)] = e
	}
	for _, e := range h.Edges {
		if o, kept := paired[edgeKey(e)]; kept && !slices.Equal(o.Attrs.AllowedSources, e.Attrs.AllowedSources) {
			t.Fatalf("(3) %s: sources changed (paired with %s)", e.ID, o.ID)
		}
		o, kept := edges[e.ID]
		switch e.Type {
		case graphdomain.EdgeHasPermission, graphdomain.EdgeRunsAs:
			if !kept || o.Src != e.Src || o.Dst != e.Dst {
				t.Fatalf("(2) %s added", e.ID)
			}
			before := closure(o.Attrs.Actions)
			for a := range closure(e.Attrs.Actions) {
				if !before[a] {
					t.Fatalf("(2) %s: action %s added", e.ID, a)
				}
			}
		}
		if kept && !slices.Equal(o.Attrs.AllowedSources, e.Attrs.AllowedSources) {
			t.Fatalf("(3) %s: sources changed", e.ID)
		}
	}
	if len(applied) == 0 && !reflect.DeepEqual(g, h) {
		t.Fatalf("(6) graph changed without a reported revision")
	}
	seen := map[[2]string]bool{}
	for _, a := range applied {
		k := [2]string{a.ControlID, a.Resource}
		if seen[k] || !slices.ContainsFunc(fs, func(f loopsdomain.Finding) bool { return f.Code == a.ControlID && f.Resource == a.Resource }) {
			t.Fatalf("(6) applied %+v twice or without its finding", a)
		}
		seen[k] = true
		if a.Remediation == policydomain.RemediationDedicatedIdentity || a.Remediation == policydomain.RemediationEscalate || a.Remediation == policydomain.RemediationAdvisory {
			t.Fatalf("(6) %s applied in M2", a.Remediation)
		}
	}
}

// TestL2RevisesTrap proves ADR 0012 D1 at the level of the reviser (trap of
// the plan: SSH open): the design pack finds NET-003 on the load balancer
// that exposes port 22, the reviser removes the exposure (remove_exposure,
// NET-003 reported as applied) and encrypts the cross-cloud flow behind it,
// the revised graph has no hop from the Internet to that load balancer and
// no critical or high finding left.
func TestL2RevisesTrap(t *testing.T) {
	ctx := context.Background()
	e, err := opa.NewDesign()
	if err != nil {
		t.Fatal(err)
	}
	g := sshTrap(t)
	d, err := confirm.DigestOfGraph(g)
	if err != nil {
		t.Fatal(err)
	}
	vc := verify.Context{Confirmed: d.Exposures}
	fs, err := verify.Candidate(ctx, e, g, tenant, vc)
	if err != nil {
		t.Fatal(err)
	}
	var blocking []loopsdomain.Finding
	for _, f := range fs {
		if f.Severity == loopsdomain.SeverityCritical || f.Severity == loopsdomain.SeverityHigh {
			blocking = append(blocking, f)
		}
	}
	if !slices.ContainsFunc(blocking, func(f loopsdomain.Finding) bool { return f.Code == "NET-003" && f.Resource == "lb:legacy-vms-22" }) {
		t.Fatalf("trap: NET-003 on lb:legacy-vms-22 missing from %+v", blocking)
	}
	h, applied, err := revise.Revise(g, blocking, allControls(t))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(applied, revise.Applied{ControlID: "NET-003", Resource: "lb:legacy-vms-22", Remediation: policydomain.RemediationRemoveExposure}) {
		t.Errorf("applied %+v, want NET-003 remove_exposure on lb:legacy-vms-22", applied)
	}
	for _, hop := range reachOf(t, h).Hops {
		if hop.Src == reach.Internet && hop.Dst == "lb:legacy-vms-22" {
			t.Errorf("revised graph still exposes the SSH load balancer: %+v", hop)
		}
	}
	after, err := verify.Candidate(ctx, e, h, tenant, vc)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range after {
		if f.Severity == loopsdomain.SeverityCritical || f.Severity == loopsdomain.SeverityHigh {
			t.Errorf("finding left after the revision: %+v", f)
		}
	}
}

// TestMoveToDataTierDeterministic (review of M2-T08, low, pre-existing): with
// two data subnets in the VPC, the host always moves to the first by
// identifier, whatever the order of a map.
func TestMoveToDataTierDeterministic(t *testing.T) {
	g := enriched(t)
	second := "net:aws-eu-west-3-staging-data2"
	g.Nodes = append(g.Nodes, graphdomain.Node{ID: second, Kind: graphdomain.KindNetwork, Attrs: graphdomain.NodeAttrs{
		Cloud: ptr("aws"), Region: ptr("eu-west-3"), Env: ptr("staging"), Subtype: ptr("subnet"), CIDR: ptr("10.0.5.0/24"), Tier: ptr("data"),
	}})
	g.Edges = append(g.Edges, graphdomain.Edge{ID: "member_of|" + second + "|net:aws-eu-west-3-staging", Type: graphdomain.EdgeMemberOf, Src: second, Dst: "net:aws-eu-west-3-staging"})
	if !valid(g) {
		t.Fatal("graph with two data subnets invalid")
	}
	controls := allControls(t)
	var code string
	for _, c := range controls {
		if c.Remediation == policydomain.RemediationMoveToDataTier {
			code = c.ID
		}
	}
	fs := []loopsdomain.Finding{{Code: code, Severity: loopsdomain.SeverityHigh, Resource: "wl:billing"}}
	for i := range 40 {
		got, applied, err := revise.Revise(g, fs, controls)
		if err != nil || len(applied) != 1 {
			t.Fatalf("run %d: %v, %v", i, applied, err)
		}
		if !slices.ContainsFunc(got.Edges, func(e graphdomain.Edge) bool {
			return e.ID == "member_of|wl:billing|net:aws-eu-west-3-staging-data"
		}) {
			t.Fatalf("run %d: host moved elsewhere than the first data subnet", i)
		}
	}
}
