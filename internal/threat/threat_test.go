package threat_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/amezianechayer/rempart/internal/design"
	"github.com/amezianechayer/rempart/internal/graph"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	"github.com/amezianechayer/rempart/internal/intent"
	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
	"github.com/amezianechayer/rempart/internal/threat"
	"github.com/amezianechayer/rempart/schemas"
)

const tenant = "3f6c2a9e-8b1d-4c7a-9e2f-5d4b3a2c1e0f"

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// loadGraph reads a graph of testdata, strictly, and validates it.
func loadGraph(t *testing.T, name string) graphdomain.Graph {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name) //nolint:gosec // G304: constant test data
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var g graphdomain.Graph
	if err := dec.Decode(&g); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if err := graph.ValidateSchema(g); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return g
}

// allControls evaluates every control the catalog cites.
func allControls() threat.Pack {
	set := map[string]bool{}
	for _, e := range threat.Catalog() {
		for _, c := range e.Controls {
			set[c] = true
		}
	}
	p := threat.Pack{Digest: strings.Repeat("d", 64)}
	for c := range set {
		p.Controls = append(p.Controls, c)
	}
	slices.Sort(p.Controls)
	return p
}

func analyze(t *testing.T, g graphdomain.Graph, findings []loopsdomain.Finding, p threat.Pack) threat.Model {
	t.Helper()
	m, err := threat.Analyze(graphdomain.FactsOf(g), findings, p)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	return m
}

func byID(m threat.Model) map[string]threat.Threat {
	out := map[string]threat.Threat{}
	for _, th := range m.Threats {
		out[th.ID] = th
	}
	return out
}

var (
	letters  = map[string]string{"S": "spoofing", "T": "tampering", "R": "repudiation", "I": "information_disclosure", "D": "denial_of_service", "E": "elevation_of_privilege"}
	process  = []string{"S", "T", "R", "I", "D", "E"}
	coverage = map[string][]string{ // ADR 0010 D9: STRIDE per element
		"Compute": process, "K8sCluster": process, "K8sWorkload": process, "LoadBalancer": process,
		"DataStore": {"T", "R", "I", "D"}, "Identity": {"S", "R", "E"}, "Account": {"R", "E"},
		"EXPOSES": {"T", "I", "D"}, "CAN_REACH": {"T", "I", "D"},
	}
)

// extendedGraph is the reference graph with an Account, a permission on it
// and a managed database reached by the cluster.
func extendedGraph(t *testing.T) graphdomain.Graph {
	t.Helper()
	raw, err := os.ReadFile("../intent/testdata/reference-ir.json")
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
	str := func(s string) *string { return &s }
	g.Nodes = append(g.Nodes, graphdomain.Node{ID: "acct:main", Kind: graphdomain.KindAccount, Attrs: graphdomain.NodeAttrs{Cloud: str("aws")}})
	g.Edges = append(g.Edges, graphdomain.Edge{
		ID: "has_permission|id:gitops|acct:main", Type: graphdomain.EdgeHasPermission,
		Src: "id:gitops", Dst: "acct:main", Attrs: graphdomain.EdgeAttrs{Actions: []string{"read"}},
	})
	if err := graph.ValidateSchema(g); err != nil {
		t.Fatalf("extended graph: %v", err)
	}
	return g
}

// TestStrideCoversEveryNodeAndFlow proves ADR 0010 D9: STRIDE per element.
// Statically, every applicable (type, category) has a generic entry of
// stride-v1, and no entry targets Internet, Network or a non-flow edge;
// dynamically, every element of the reference and extended graphs receives
// at least one threat per applicable category, the others none, and the
// transitive path from Internet to sensitive data is a hypothesis threat.
func TestStrideCoversEveryNodeAndFlow(t *testing.T) {
	if threat.CatalogVersion != "stride-v1" {
		t.Fatalf("CatalogVersion = %q", threat.CatalogVersion)
	}
	ruleRe := regexp.MustCompile(`^STRIDE-([STRIDE])-[0-9]{3}$`)
	rules := map[string]bool{}
	hypothesis := ""
	for _, e := range threat.Catalog() {
		m := ruleRe.FindStringSubmatch(e.Rule)
		if m == nil || letters[m[1]] != e.Category || rules[e.Rule] {
			t.Errorf("entry %+v: rule outside the grammar, letter and category disagree, or duplicate", e)
			continue
		}
		rules[e.Rule] = true
		if !slices.IsSorted(e.Controls) || len(e.Targets) == 0 {
			t.Errorf("%s: controls not sorted or no target", e.Rule)
		}
		if !slices.Contains([]loopsdomain.Severity{"critical", "high", "medium", "low"}, e.Severity) {
			t.Errorf("%s: severity %q", e.Rule, e.Severity)
		}
		for _, typ := range e.Targets {
			if !slices.Contains(coverage[typ], m[1]) {
				t.Errorf("%s targets %s, outside the categories of D9", e.Rule, typ)
			}
			flow := typ == "EXPOSES" || typ == "CAN_REACH"
			if (e.TargetType == "flow") != flow {
				t.Errorf("%s: target type %q for %s", e.Rule, e.TargetType, typ)
			}
		}
		if e.Hypothesis {
			hypothesis = e.Rule
			if e.Category != "information_disclosure" {
				t.Errorf("%s: hypothesis outside information_disclosure", e.Rule)
			}
		}
	}
	for typ, cats := range coverage {
		for _, c := range cats {
			if !slices.ContainsFunc(threat.Catalog(), func(e threat.Entry) bool {
				return e.Category == letters[c] && slices.Contains(e.Targets, typ) && !e.Hypothesis
			}) {
				t.Errorf("no generic entry for (%s, %s)", typ, letters[c])
			}
		}
	}
	if hypothesis == "" {
		t.Fatalf("no hypothesis entry for transitive paths (Q3)")
	}

	for _, g := range []graphdomain.Graph{loadGraph(t, "reference.graph.json"), loadGraph(t, "reference-ssh.graph.json"), extendedGraph(t)} {
		m := analyze(t, g, nil, allControls())
		got := map[string]map[string]bool{} // target -> categories
		for _, th := range m.Threats {
			if got[th.Target] == nil {
				got[th.Target] = map[string]bool{}
			}
			got[th.Target][th.Category] = true
			if th.ID != th.Rule+"@"+th.Target {
				t.Errorf("threat id %q, want %s@%s", th.ID, th.Rule, th.Target)
			}
		}
		check := func(id, typ string) {
			for _, c := range coverage[typ] {
				if !got[id][letters[c]] {
					t.Errorf("%s (%s): no %s threat", id, typ, letters[c])
				}
			}
			if len(coverage[typ]) == 0 && len(got[id]) > 0 {
				t.Errorf("%s (%s): threats %v, want none", id, typ, got[id])
			}
		}
		for _, n := range g.Nodes {
			check(n.ID, string(n.Kind))
		}
		for _, e := range g.Edges {
			check(e.ID, string(e.Type))
		}
	}
	m := analyze(t, loadGraph(t, "reference.graph.json"), nil, allControls())
	if _, ok := byID(m)[hypothesis+"@wl:legacy-vms"]; !ok {
		t.Errorf("no %s threat on wl:legacy-vms (host of confidential data, three hops from Internet)", hypothesis)
	}
}

// ruleFor returns the rule of the first entry of category cat targeting typ
// and citing control.
func ruleFor(t *testing.T, cat, typ, control string) string {
	t.Helper()
	for _, e := range threat.Catalog() {
		if e.Category == cat && slices.Contains(e.Targets, typ) && slices.Contains(e.Controls, control) {
			return e.Rule
		}
	}
	t.Fatalf("no %s entry on %s citing %s", cat, typ, control)
	return ""
}

// TestThreatStatusFromControls proves ADR 0010 D9: a threat is mitigated if
// and only if its entry cites a control, every cited control was evaluated,
// and none of them has a finding on the resources of the target (the node;
// for a flow, the edge and both ends; for an identity, also its permissions;
// for an account, the permissions on it); otherwise open.
func TestThreatStatusFromControls(t *testing.T) {
	g := loadGraph(t, "reference.graph.json")
	p := allControls()
	clean := analyze(t, g, nil, p)
	for _, th := range clean.Threats {
		want := "mitigated"
		if len(th.Controls) == 0 {
			want = "open"
		}
		if th.Status != want {
			t.Errorf("%s: status %q without finding, want %q", th.ID, th.Status, want)
		}
	}

	s := ruleFor(t, "spoofing", "Compute", "IAM-006")
	m := byID(analyze(t, g, []loopsdomain.Finding{{Code: "IAM-006", Resource: "wl:legacy-vms", Severity: "medium"}}, p))
	if m[s+"@wl:legacy-vms"].Status != "open" {
		t.Errorf("%s@wl:legacy-vms not open with a finding of its control on the node", s)
	}
	if m[s+"@wl:app-cluster"].Status != "mitigated" {
		t.Errorf("%s@wl:app-cluster opened by a finding on another node", s)
	}

	var flowRule, flowControl string
	for _, e := range threat.Catalog() {
		if e.TargetType == "flow" && len(e.Controls) > 0 {
			flowRule, flowControl = e.Rule, e.Controls[0]
			break
		}
	}
	m = byID(analyze(t, g, []loopsdomain.Finding{{Code: flowControl, Resource: "wl:legacy-vms", Severity: "high"}}, p))
	end := m[flowRule+"@can_reach|wl:app-cluster|wl:legacy-vms|tcp/5432"]
	other := m[flowRule+"@can_reach|lb:app-cluster-443|wl:app-cluster|https/443"]
	if end.Status != "open" || other.Status != "mitigated" {
		t.Errorf("flow %s: status %q with a finding on its end, %q on an unrelated flow; want open, mitigated", flowRule, end.Status, other.Status)
	}

	e3 := ruleFor(t, "elevation_of_privilege", "Identity", "IAM-001")
	m = byID(analyze(t, g, []loopsdomain.Finding{{Code: "IAM-001", Resource: "has_permission|id:legacy-vms|data:customer-db", Severity: "critical"}}, p))
	if m[e3+"@id:legacy-vms"].Status != "open" {
		t.Errorf("%s@id:legacy-vms not open with IAM-001 on its permission", e3)
	}

	t.Run("control_not_evaluated", func(t *testing.T) {
		partial := p
		partial.Controls = slices.DeleteFunc(slices.Clone(p.Controls), func(c string) bool { return c == "IAM-006" })
		m := byID(analyze(t, g, nil, partial))
		if m[s+"@wl:legacy-vms"].Status != "open" {
			t.Errorf("%s mitigated although IAM-006 was not evaluated (T108)", s)
		}
	})
	t.Run("unrelated_control", func(t *testing.T) {
		m := byID(analyze(t, g, []loopsdomain.Finding{{Code: "ZZZ-999", Resource: "wl:legacy-vms", Severity: "critical"}}, p))
		if m[s+"@wl:legacy-vms"].Status != "mitigated" {
			t.Errorf("a finding of a control the entry does not cite opened %s", s)
		}
	})
}

// TestGraphRevisionStable proves ADR 0010 D10 (T5, T113): SHA-256 of the
// RFC 8785 form of the facts, nodes and edges sorted by id, attribute sets
// sorted without duplicates, path kept in order, free text excluded; a frozen
// vector protects the encoding.
func TestGraphRevisionStable(t *testing.T) {
	str := func(s string) *string { return &s }
	n := func(i int) *int { return &i }
	b := func(v bool) *bool { return &v }
	fg := graphdomain.FactsGraph{
		Version: "1", TenantID: tenant, Source: "design",
		Nodes: []graphdomain.FactNode{
			{ID: "wl:b", Kind: graphdomain.KindCompute, Attrs: graphdomain.NodeAttrs{Cloud: str("aws"), Count: n(2), PublicIP: b(false)}},
			{ID: "lb:a", Kind: graphdomain.KindLoadBalancer, Attrs: graphdomain.NodeAttrs{
				Public: b(true), Behind: []string{"waf", "cdn", "waf"},
				Listeners: &[]graphdomain.Listener{{Protocol: "https", Port: 443}, {Protocol: "http", Port: 80}},
			}},
		},
		Edges: []graphdomain.FactEdge{
			{ID: "exposes|lb:a|internet|https/443", Type: graphdomain.EdgeExposes, Src: "lb:a", Dst: "internet", Attrs: graphdomain.EdgeAttrs{
				Protocol: str("https"), PortFrom: n(443), PortTo: n(443), AllowedSources: []string{"198.51.100.0/24", "192.0.2.0/24"},
			}},
			{ID: "can_reach|lb:a|wl:b|https/443", Type: graphdomain.EdgeCanReach, Src: "lb:a", Dst: "wl:b", Attrs: graphdomain.EdgeAttrs{
				Protocol: str("https"), PortFrom: n(443), PortTo: n(443), Path: []string{"net:b", "net:a"},
			}},
		},
	}
	const canonical = `{"edges":[{"attrs":{"path":["net:b","net:a"],"port_from":443,"port_to":443,"protocol":"https"},"dst":"wl:b","id":"can_reach|lb:a|wl:b|https/443","src":"lb:a","type":"CAN_REACH"},` +
		`{"attrs":{"allowed_sources":["192.0.2.0/24","198.51.100.0/24"],"port_from":443,"port_to":443,"protocol":"https"},"dst":"internet","id":"exposes|lb:a|internet|https/443","src":"lb:a","type":"EXPOSES"}],` +
		`"nodes":[{"attrs":{"behind":["cdn","waf"],"listeners":[{"port":80,"protocol":"http"},{"port":443,"protocol":"https"}],"public":true},"id":"lb:a","kind":"LoadBalancer"},` +
		`{"attrs":{"cloud":"aws","count":2,"public_ip":false},"id":"wl:b","kind":"Compute"}],` +
		`"source":"design","tenant_id":"` + tenant + `","version":"1"}`
	sum := sha256.Sum256([]byte(canonical))
	want := hex.EncodeToString(sum[:])
	got, err := threat.Revision(fg)
	if err != nil || got != want {
		t.Fatalf("Revision = %q, %v; want %q (frozen vector)", got, err, want)
	}

	perm := fg
	perm.Nodes = []graphdomain.FactNode{fg.Nodes[1], fg.Nodes[0]}
	perm.Edges = []graphdomain.FactEdge{fg.Edges[1], fg.Edges[0]}
	if again, err := threat.Revision(perm); err != nil || again != want {
		t.Errorf("permuted nodes and edges give %q, %v", again, err)
	}
	empty, err := threat.Revision(graphdomain.FactsGraph{Version: "1", TenantID: tenant, Source: "design"})
	emptySum := sha256.Sum256([]byte(`{"edges":[],"nodes":[],"source":"design","tenant_id":"` + tenant + `","version":"1"}`))
	if err != nil || empty != hex.EncodeToString(emptySum[:]) {
		t.Errorf("empty graph revision %q, %v", empty, err)
	}

	ref := loadGraph(t, "reference.graph.json")
	r1, err := threat.Revision(graphdomain.FactsOf(ref))
	if err != nil || !hex64.MatchString(r1) {
		t.Fatalf("reference revision %q, %v", r1, err)
	}
	texted := loadGraph(t, "reference.graph.json")
	for i := range texted.Edges {
		if texted.Edges[i].Type == graphdomain.EdgeExposes {
			ft := graphdomain.NewFreeText("une autre justification")
			texted.Edges[i].Text.Justification = &ft
		}
	}
	if r2, _ := threat.Revision(graphdomain.FactsOf(texted)); r2 != r1 {
		t.Errorf("free text changed the revision (T111)")
	}
	other := graphdomain.FactsOf(ref)
	other.TenantID = "4f6c2a9e-8b1d-4c7a-9e2f-5d4b3a2c1e0f"
	if r3, _ := threat.Revision(other); r3 == r1 {
		t.Errorf("tenant not in the revision (T3)")
	}
	ssh, _ := threat.Revision(graphdomain.FactsOf(loadGraph(t, "reference-ssh.graph.json")))
	if ssh == r1 {
		t.Errorf("an added exposure kept the revision")
	}
}

// TestDeltaBetweenVersions proves criterion C4 of prompts/M2.md: between two
// versions of the graph, the delta names the threats added by the SSH
// exposure, the threats whose status changed, nothing for equal models.
func TestDeltaBetweenVersions(t *testing.T) {
	p := allControls()
	a := analyze(t, loadGraph(t, "reference.graph.json"), nil, p)
	b := analyze(t, loadGraph(t, "reference-ssh.graph.json"), []loopsdomain.Finding{{Code: "NET-003", Resource: "wl:legacy-vms", Severity: "critical"}}, p)
	d, err := threat.Diff(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if d.SchemaVersion != "1" || d.Catalog != "stride-v1" || d.TenantID != tenant || d.From != a.GraphRevision || d.To != b.GraphRevision || d.From == d.To {
		t.Fatalf("delta header %+v", d)
	}
	added := map[string]bool{}
	for _, th := range d.Added {
		added[th.Target] = true
	}
	for _, target := range []string{"lb:legacy-vms-22", "exposes|lb:legacy-vms-22|internet|tcp/22", "can_reach|lb:legacy-vms-22|wl:legacy-vms|tcp/22"} {
		if !added[target] {
			t.Errorf("no threat added on %s", target)
		}
	}
	if len(d.Removed) != 0 {
		t.Errorf("removed %v, want none", d.Removed)
	}
	changed := false
	for _, c := range d.Changed {
		if c.From.ID != c.ID || c.To.ID != c.ID || reflect.DeepEqual(c.From, c.To) {
			t.Errorf("change %+v not a change of one threat", c)
		}
		if c.From.Target == "wl:legacy-vms" && c.From.Status == "mitigated" && c.To.Status == "open" {
			changed = true
		}
	}
	if !changed {
		t.Errorf("no threat of wl:legacy-vms changed to open by NET-003: %+v", d.Changed)
	}
	for _, list := range [][]threat.Threat{d.Added, d.Removed} {
		if !slices.IsSortedFunc(list, func(x, y threat.Threat) int { return strings.Compare(x.ID, y.ID) }) {
			t.Errorf("list not sorted by id")
		}
	}
	same, err := threat.Diff(a, a)
	if err != nil || same.From != same.To || same.Added == nil || len(same.Added)+len(same.Removed)+len(same.Changed) != 0 || same.Removed == nil || same.Changed == nil {
		t.Errorf("Diff(a, a) = %+v, %v; want empty lists and from == to", same, err)
	}
}

func threatOf(rule, cat, target, typ, sev, status string, controls ...string) threat.Threat {
	return threat.Threat{ID: rule + "@" + target, Rule: rule, Category: cat, Target: target, TargetType: typ, Severity: sev, Status: status, Controls: controls}
}

func goldenModels() (threat.Model, threat.Model) {
	i002 := threatOf("STRIDE-I-002", "information_disclosure", "data:x", "node", "high", "mitigated", "DATA-001", "DATA-002")
	s003 := threatOf("STRIDE-S-003", "spoofing", "id:x", "node", "high", "open", "IAM-005")
	t006 := threatOf("STRIDE-T-006", "tampering", "exposes|lb:x-22|internet|tcp/22", "flow", "high", "open", "NET-007", "NET-011")
	i002open := i002
	i002open.Status = "open"
	a := threat.Model{SchemaVersion: "1", Catalog: "stride-v1", TenantID: tenant, GraphRevision: strings.Repeat("a", 64), PackDigest: strings.Repeat("d", 64), Threats: []threat.Threat{i002, s003}}
	b := threat.Model{SchemaVersion: "1", Catalog: "stride-v1", TenantID: tenant, GraphRevision: strings.Repeat("b", 64), PackDigest: strings.Repeat("d", 64), Threats: []threat.Threat{t006, i002open}}
	return a, b
}

func validateAgainst(t *testing.T, path string, raw []byte) error {
	t.Helper()
	s, err := schemas.Compile(path)
	if err != nil {
		t.Fatalf("Compile(%s): %v", path, err)
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return s.Validate(v)
}

// TestDeltaSerializationGolden proves ADR 0010 D11 (T113): the delta is
// serialized byte for byte as the golden file, matches $defs/delta of
// schemas/threat/v1.json, models match $defs/model, and the digest of the
// catalog stride-v1 is frozen next to its version.
func TestDeltaSerializationGolden(t *testing.T) {
	a, b := goldenModels()
	d, err := threat.Diff(a, b)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	golden, err := os.ReadFile("testdata/delta.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(append(raw, '\n'), golden) {
		t.Fatalf("delta\n%s\nwant\n%s", raw, golden)
	}
	if err := validateAgainst(t, schemas.ThreatDelta, golden); err != nil {
		t.Errorf("golden delta outside $defs/delta: %v", err)
	}
	for _, m := range []threat.Model{a, b} {
		mr, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateAgainst(t, schemas.ThreatModel, mr); err != nil {
			t.Errorf("model outside $defs/model: %v", err)
		}
	}
	if err := validateAgainst(t, schemas.ThreatDelta, []byte(strings.Replace(string(golden), `"status":"open"`, `"status":"accepted"`, 1))); err == nil {
		t.Errorf("status accepted admitted by the schema (outside stride-v1, D9)")
	}
	want, err := os.ReadFile("testdata/catalog.sha256")
	if err != nil || strings.TrimSpace(string(want)) != threat.CatalogDigest() {
		t.Errorf("catalog digest %s, frozen %q (%v): a change of stride-v1 needs a new CatalogVersion", threat.CatalogDigest(), want, err)
	}
}

// TestDeltaStrictDecode proves ADR 0010 D11: DecodeDelta and DecodeModel
// refuse an unknown key, a duplicate key, a key of inexact case, invalid UTF-8,
// an oversized input, trailing data and a value outside the schema, with a
// fixed error; a valid document round-trips.
func TestDeltaStrictDecode(t *testing.T) {
	golden, err := os.ReadFile("testdata/delta.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	d, err := threat.DecodeDelta(golden)
	a, b := goldenModels()
	want, _ := threat.Diff(a, b)
	if err != nil || !reflect.DeepEqual(d, want) {
		t.Fatalf("DecodeDelta(golden) = %+v, %v", d, err)
	}
	g := string(golden)
	cases := map[string]string{
		"unknown_key":    strings.Replace(g, `{"schema_version"`, `{"extra":1,"schema_version"`, 1),
		"duplicate_key":  strings.Replace(g, `"catalog":"stride-v1"`, `"catalog":"stride-v1","catalog":"stride-v1"`, 1),
		"inexact_case":   strings.Replace(g, `"catalog":`, `"Catalog":`, 1),
		"invalid_utf8":   strings.Replace(g, `"data:x"`, "\"data:\xff\"", 1),
		"trailing":       g + "{}",
		"null_list":      strings.Replace(g, `"removed":[`, `"removed":null,"x":[`, 1),
		"status_unknown": strings.Replace(g, `"status":"open"`, `"status":"accepted"`, 1),
		"bad_revision":   strings.Replace(g, strings.Repeat("a", 64), "not-a-revision", 1),
		"oversized":      g + strings.Repeat(" ", threat.MaxDecodeBytes),
		"empty":          "",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := threat.DecodeDelta([]byte(src)); !errors.Is(err, threat.ErrDecode) {
				t.Fatalf("DecodeDelta = %v, want ErrDecode", err)
			}
		})
	}
	mr, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	m, err := threat.DecodeModel(mr)
	if err != nil || !reflect.DeepEqual(m, a) {
		t.Fatalf("DecodeModel round trip: %+v, %v", m, err)
	}
	for name, src := range map[string]string{
		"unknown_key":   strings.Replace(string(mr), `{"schema_version"`, `{"extra":1,"schema_version"`, 1),
		"duplicate_key": strings.Replace(string(mr), `"catalog":"stride-v1"`, `"catalog":"stride-v1","catalog":"x"`, 1),
		"inexact_case":  strings.Replace(string(mr), `"threats":`, `"Threats":`, 1),
	} {
		if _, err := threat.DecodeModel([]byte(src)); !errors.Is(err, threat.ErrDecode) {
			t.Errorf("DecodeModel %s = %v, want ErrDecode", name, err)
		}
	}
	if _, err := threat.DecodeModel(golden); !errors.Is(err, threat.ErrDecode) {
		t.Errorf("DecodeModel accepted a delta")
	}
}

// TestDeltaRefusesCrossTenant proves ADR 0010 D11 (T3): a delta only compares
// two models of one tenant, one catalog and one pack.
func TestDeltaRefusesCrossTenant(t *testing.T) {
	a, b := goldenModels()
	other := b
	other.TenantID = "4f6c2a9e-8b1d-4c7a-9e2f-5d4b3a2c1e0f"
	if _, err := threat.Diff(a, other); !errors.Is(err, threat.ErrTenantMismatch) {
		t.Errorf("Diff across tenants = %v, want ErrTenantMismatch", err)
	}
	cat := b
	cat.Catalog = "stride-v2"
	if _, err := threat.Diff(a, cat); !errors.Is(err, threat.ErrCatalogMismatch) {
		t.Errorf("Diff across catalogs = %v, want ErrCatalogMismatch", err)
	}
	pack := b
	pack.PackDigest = strings.Repeat("e", 64)
	if _, err := threat.Diff(a, pack); !errors.Is(err, threat.ErrPackMismatch) {
		t.Errorf("Diff across packs = %v, want ErrPackMismatch", err)
	}
	if _, err := threat.Diff(a, other); err != nil && strings.Contains(err.Error(), other.TenantID) {
		t.Errorf("error quotes a tenant: %v", err)
	}
	if _, err := threat.Analyze(graphdomain.FactsGraph{Version: "1", Source: "design"}, nil, allControls()); err == nil {
		t.Errorf("Analyze accepted a graph without tenant")
	}
}

// TestThreatModelHasNoFreeText proves ADR 0010 D9 and D10 (T2, T111): no free
// text in the types of the model and of the delta, no canary of the IR in a
// model built from a graph that carries them.
func TestThreatModelHasNoFreeText(t *testing.T) {
	freeText := reflect.TypeFor[graphdomain.FreeText]()
	var walk func(reflect.Type, map[reflect.Type]bool) bool
	walk = func(typ reflect.Type, seen map[reflect.Type]bool) bool {
		switch typ.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
			return typ == freeText || walk(typ.Elem(), seen)
		case reflect.Struct:
			if typ == freeText {
				return true
			}
			if seen[typ] {
				return false
			}
			seen[typ] = true
			for i := range typ.NumField() {
				if walk(typ.Field(i).Type, seen) {
					return true
				}
			}
		case reflect.Interface:
			return true
		}
		return false
	}
	for _, typ := range []reflect.Type{reflect.TypeFor[threat.Model](), reflect.TypeFor[threat.Delta]()} {
		if walk(typ, map[reflect.Type]bool{}) {
			t.Errorf("%s can hold free text", typ)
		}
	}
	raw, err := os.ReadFile("../design/testdata/reference-canaries.json")
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
	full, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(full, []byte("CANARY-")) {
		t.Fatalf("control: the graph lost its canaries")
	}
	m := analyze(t, g, nil, allControls())
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"CANARY-", "pwned", "ignore previous", "untrusted_text"} {
		if bytes.Contains(out, []byte(c)) {
			t.Errorf("threat model contains %q", c)
		}
	}
}

// TestRegulationMakesDataSensitive (closing review of M2, high, T139): STRIDE
// reads regulated data as sensitive whatever its classification: the model of
// the reference graph is the same with its data confidential or internal
// when it stays regulated, and differs once the regulation is gone.
func TestRegulationMakesDataSensitive(t *testing.T) {
	p := allControls()
	model := func(classification string, regulation []string) map[string]string {
		g := loadGraph(t, "reference.graph.json")
		for i := range g.Nodes {
			if g.Nodes[i].ID == "data:customer-db" {
				g.Nodes[i].Attrs.Classification, g.Nodes[i].Attrs.Regulation = &classification, regulation
			}
		}
		out := map[string]string{}
		for _, th := range analyze(t, g, nil, p).Threats {
			out[th.ID] = th.Status
		}
		return out
	}
	confidential := model("confidential", []string{"gdpr"})
	if got := model("internal", []string{"gdpr"}); !maps.Equal(got, confidential) {
		t.Errorf("internal but regulated: STRIDE differs from confidential data")
	}
	if got := model("internal", nil); maps.Equal(got, confidential) {
		t.Errorf("control: internal unregulated data gives the same model as confidential data")
	}
}
