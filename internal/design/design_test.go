package design_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/amezianechayer/rempart/internal/design"
	"github.com/amezianechayer/rempart/internal/design/cidr"
	"github.com/amezianechayer/rempart/internal/graph"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	"github.com/amezianechayer/rempart/internal/intent"
	intentdomain "github.com/amezianechayer/rempart/internal/intent/domain"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

const referenceTenant = "3f6c2a9e-8b1d-4c7a-9e2f-5d4b3a2c1e0f"

// canaries are the four free text values of testdata/reference-canaries.json
// (plan P9: summary, notes, purpose, justification).
var canaries = []string{
	"CANARY-SUMMARY-7f3a",
	"CANARY-NOTES-7f3a",
	"CANARY-PURPOSE-7f3a",
	"CANARY-JUSTIFICATION-7f3a",
}

// parseIRFile parses path, relative to internal/, with the production parser.
func parseIRFile(t *testing.T, path string) intentdomain.IR {
	t.Helper()
	raw, err := fs.ReadFile(os.DirFS(".."), path)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := intent.ParseIR(raw)
	if err != nil {
		t.Fatalf("ParseIR(%s): %v", path, err)
	}
	return ir
}

func referenceIR(t *testing.T) intentdomain.IR {
	t.Helper()
	return parseIRFile(t, "intent/testdata/reference-ir.json")
}

// tree returns the generic JSON tree of v: node and edge attributes are read
// by their JSON names of schemas/graph/v1.json, not by Go field names.
func tree(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("encode %T: %v", v, err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

func objects(t *testing.T, v any) []map[string]any {
	t.Helper()
	list, ok := v.([]any)
	if !ok {
		t.Fatalf("%T is not a JSON array", v)
	}
	out := make([]map[string]any, 0, len(list))
	for _, x := range list {
		m, ok := x.(map[string]any)
		if !ok {
			t.Fatalf("%T is not a JSON object", x)
		}
		out = append(out, m)
	}
	return out
}

func attr(obj map[string]any, name string) any {
	a, _ := obj["attrs"].(map[string]any)
	return a[name]
}

// TestReferenceScenarioGraphValid proves criterion C3 (second half): the
// reference IR gives a valid graph with the nodes and edges of plan section 7,
// the legacy VMs in the data tier, nothing exposed from that tier, a clean CIDR
// plan and the tenant of the IR.
func TestReferenceScenarioGraphValid(t *testing.T) {
	ir := referenceIR(t)
	g, plan, err := design.Build(ir, design.Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := graph.ValidateSchema(g); err != nil {
		t.Fatalf("ValidateSchema: %v", err)
	}
	if g.TenantID != referenceTenant || g.TenantID != ir.TenantID {
		t.Fatalf("graph tenant %q, want %q", g.TenantID, ir.TenantID)
	}
	if g.Version != graphdomain.GraphVersion || g.Source != "design" {
		t.Fatalf("graph version %q source %q, want %q design", g.Version, g.Source, graphdomain.GraphVersion)
	}
	if f := cidr.Check(plan); len(f) != 0 {
		t.Fatalf("cidr.Check(plan) = %+v, want none", f)
	}

	doc := tree(t, g)
	nodes, edges := objects(t, doc["nodes"]), objects(t, doc["edges"])
	var ids []string
	kinds := map[string]int{}
	byID := map[string]map[string]any{}
	for _, n := range nodes {
		id, _ := n["id"].(string)
		ids = append(ids, id)
		kinds[fmt.Sprint(n["kind"])]++
		byID[id] = n
	}
	wantIDs := []string{
		"data:customer-db",
		"internet",
		"lb:app-cluster-443",
		"net:aws-eu-west-3-staging",
		"net:aws-eu-west-3-staging-app",
		"net:aws-eu-west-3-staging-public",
		"net:azure-francecentral-staging",
		"net:azure-francecentral-staging-data",
		"wl:app-cluster",
		"wl:gitops",
		"wl:legacy-vms",
		"wl:obs",
	}
	if got := slices.Sorted(slices.Values(ids)); !slices.Equal(got, wantIDs) {
		t.Fatalf("%d nodes %v, want 12 nodes %v", len(ids), got, wantIDs)
	}
	wantKinds := map[string]int{
		"Internet": 1, "Network": 5, "K8sCluster": 1, "Compute": 1,
		"K8sWorkload": 2, "LoadBalancer": 1, "DataStore": 1,
	}
	if !reflect.DeepEqual(kinds, wantKinds) {
		t.Fatalf("node kinds %v, want %v", kinds, wantKinds)
	}

	types := map[string]int{}
	for _, e := range edges {
		types[fmt.Sprint(e["type"])]++
	}
	wantTypes := map[string]int{"MEMBER_OF": 8, "EXPOSES": 1, "CAN_REACH": 3, "STORES": 1}
	if len(edges) != 13 || !reflect.DeepEqual(types, wantTypes) {
		t.Fatalf("%d edges by type %v, want 13 edges %v", len(edges), types, wantTypes)
	}

	has := func(typ, src, dst string) bool {
		return slices.ContainsFunc(edges, func(e map[string]any) bool {
			return e["type"] == typ && e["src"] == src && e["dst"] == dst
		})
	}
	const dataSubnet = "net:azure-francecentral-staging-data"
	if !has("MEMBER_OF", "wl:legacy-vms", dataSubnet) {
		t.Fatalf("wl:legacy-vms is not MEMBER_OF %s (host of confidential data, plan P8)", dataSubnet)
	}
	if tier := attr(byID[dataSubnet], "tier"); tier != "data" {
		t.Fatalf("%s tier %v, want data", dataSubnet, tier)
	}
	if !has("STORES", "wl:legacy-vms", "data:customer-db") || !has("EXPOSES", "lb:app-cluster-443", "internet") {
		t.Fatalf("missing STORES or EXPOSES edge: %v", edges)
	}
	for _, e := range edges {
		if e["type"] != "EXPOSES" {
			continue
		}
		for _, m := range edges {
			if m["type"] == "MEMBER_OF" && m["src"] == e["src"] && attr(byID[fmt.Sprint(m["dst"])], "tier") == "data" {
				t.Fatalf("EXPOSES edge %v from a member of the data tier", e["id"])
			}
		}
	}

	t.Run("exposed_data_tier_refused", func(t *testing.T) {
		exposed := parseIRFile(t, "design/testdata/exposed-data-tier.json")
		g, _, err := design.Build(exposed, design.Options{})
		if !errors.Is(err, design.ErrDesignRefused) {
			t.Fatalf("Build = %d nodes, %v; want ErrDesignRefused", len(g.Nodes), err)
		}
	})

	t.Run("system_tenant_refused", func(t *testing.T) {
		sys := referenceIR(t)
		sys.TenantID = string(tenancy.System)
		g, _, err := design.Build(sys, design.Options{})
		if !errors.Is(err, intent.ErrIRInvalid) {
			t.Fatalf("Build = %d nodes, %v; want ErrIRInvalid", len(g.Nodes), err)
		}
	})
}

// reachesFreeText reports the path to a graphdomain.FreeText field reachable
// from typ, or "" if none; seen lists the struct types visited.
func reachesFreeText(typ reflect.Type, path string, seen map[reflect.Type]bool) string {
	freeText := reflect.TypeFor[graphdomain.FreeText]()
	if typ == freeText {
		return path
	}
	switch typ.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return reachesFreeText(typ.Elem(), path+"[]", seen)
	case reflect.Map:
		if p := reachesFreeText(typ.Key(), path+"{key}", seen); p != "" {
			return p
		}
		return reachesFreeText(typ.Elem(), path+"{}", seen)
	case reflect.Struct:
		if seen[typ] {
			return ""
		}
		seen[typ] = true
		for i := range typ.NumField() {
			f := typ.Field(i)
			if p := reachesFreeText(f.Type, path+"."+f.Name, seen); p != "" {
				return p
			}
		}
	case reflect.Interface:
		return path + " (interface: may hold a FreeText)"
	}
	return ""
}

// TestFactsBlockHasNoFreeText proves the guard of prompts/M1.md (threat T2):
// the four free text values of the IR reach the graph under untrusted_text,
// never its Facts projection, and a FreeText never prints its content.
func TestFactsBlockHasNoFreeText(t *testing.T) {
	ir := parseIRFile(t, "design/testdata/reference-canaries.json")
	g, _, err := design.Build(ir, design.Options{})
	if err != nil {
		t.Fatalf("Build(reference-canaries): %v", err)
	}
	full, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range canaries {
		if !bytes.Contains(full, []byte(c)) {
			t.Fatalf("graph JSON lacks %s: the free text did not reach untrusted_text (control)", c)
		}
	}

	facts, err := graphdomain.Facts(g)
	if err != nil {
		t.Fatalf("Facts: %v", err)
	}
	for _, c := range canaries {
		if bytes.Contains(facts, []byte(c)) {
			t.Errorf("Facts contains %s", c)
		}
	}
	for _, forbidden := range []string{"untrusted_text", "CANARY", "\\u001b", "\x1b"} {
		if bytes.Contains(facts, []byte(forbidden)) {
			t.Errorf("Facts contains %q", forbidden)
		}
	}
	// Facts is the JSON of FactsGraph, and still carries the facts.
	dec := json.NewDecoder(bytes.NewReader(facts))
	dec.DisallowUnknownFields()
	var fg graphdomain.FactsGraph
	if err := dec.Decode(&fg); err != nil {
		t.Fatalf("Facts is not a FactsGraph: %v", err)
	}
	if !bytes.Contains(facts, []byte(`"wl:app-cluster"`)) || !bytes.Contains(facts, []byte(`"10.0.0.0/20"`)) {
		t.Fatalf("Facts lost the facts: %s", facts)
	}

	seen := map[reflect.Type]bool{}
	if p := reachesFreeText(reflect.TypeFor[graphdomain.FactsGraph](), "FactsGraph", seen); p != "" {
		t.Errorf("FreeText reachable from the facts types at %s", p)
	}
	for _, typ := range []reflect.Type{reflect.TypeFor[graphdomain.FactNode](), reflect.TypeFor[graphdomain.FactEdge]()} {
		if !seen[typ] {
			t.Errorf("walk of FactsGraph never reached %s", typ)
		}
	}
	// Control: the walk finds the FreeText of the full graph.
	if p := reachesFreeText(reflect.TypeFor[graphdomain.Graph](), "Graph", map[reflect.Type]bool{}); p == "" {
		t.Errorf("walk finds no FreeText in Graph: the walk is blind")
	}

	ft := graphdomain.NewFreeText(canaries[1])
	if ft.Untrusted() != canaries[1] {
		t.Fatalf("Untrusted() = %q, want %q", ft.Untrusted(), canaries[1])
	}
	pft := &ft
	for _, s := range []string{
		fmt.Sprintf("%v %+v %s", ft, ft, ft),
		fmt.Sprintf("%q %#v %x %v", ft, ft, ft, []graphdomain.FreeText{ft}),
		fmt.Sprint(ft, pft), fmt.Sprintf("%v %s", pft, pft),
		ft.String(),
	} {
		if strings.Contains(s, canaries[1]) || strings.Contains(s, fmt.Sprintf("%x", canaries[1])) {
			t.Errorf("formatting a FreeText prints its content: %q", s)
		}
	}
}
