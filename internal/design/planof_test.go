package design

import (
	"os"
	"slices"
	"testing"

	"github.com/amezianechayer/rempart/internal/design/cidr"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	"github.com/amezianechayer/rempart/internal/intent"
)

// TestPlanOfReadsBackThePlan proves ADR 0012 D4: the plan read back from the
// facts of a graph has the networks, parents, tiers and prefixes of the plan
// Build allocated, on the default superblock, and passes cidr.Check.
func TestPlanOfReadsBackThePlan(t *testing.T) {
	raw, err := os.ReadFile("../intent/testdata/reference-ir.json")
	if err != nil {
		t.Fatal(err)
	}
	ir, err := intent.ParseIR(raw)
	if err != nil {
		t.Fatal(err)
	}
	g, plan, err := Build(ir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := PlanOf(graphdomain.FactsOf(g))
	if err != nil {
		t.Fatal(err)
	}
	if got.Superblock != plan.Superblock || len(got.Networks) != len(plan.Networks) {
		t.Fatalf("PlanOf = %+v, want the networks of %+v", got, plan)
	}
	for i, n := range plan.Networks {
		w := got.Networks[i]
		if w.Name != n.Name || w.Parent != n.Parent || w.Tier != n.Tier || w.Prefix != n.Prefix {
			t.Errorf("network %d = %+v, want %+v", i, w, n)
		}
	}
	if fs := cidr.Check(got); len(fs) != 0 {
		t.Errorf("cidr.Check(PlanOf(reference)) = %+v", fs)
	}
	if !slices.IsSortedFunc(got.Networks, func(a, b cidr.Network) int { return a.Prefix.Addr().Compare(b.Prefix.Addr()) }) {
		t.Errorf("networks not sorted by address")
	}
}
