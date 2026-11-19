package activities_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/amezianechayer/rempart/internal/design/confirm"
	"github.com/amezianechayer/rempart/internal/design/revise"
	"github.com/amezianechayer/rempart/internal/design/verify"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	"github.com/amezianechayer/rempart/internal/loops"
	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
	"github.com/amezianechayer/rempart/internal/loops/l2/activities"
	"github.com/amezianechayer/rempart/internal/policy/adapters/opa"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

const tenant tenancy.ID = "3f6c2a9e-8b1d-4c7a-9e2f-5d4b3a2c1e0f"

// TestProposeReturnsBestExactly proves the high finding of the security
// review of M2-T05 (T122 proposed): Propose revises the best candidate as it
// was proposed, decoded into a zero value; a best with fewer edges than the
// initial candidate and no finding comes back byte for byte, no attribute of
// another edge of the initial graph carried over.
func TestProposeReturnsBestExactly(t *testing.T) {
	ctx := context.Background()
	raw, err := os.ReadFile("../../../threat/testdata/reference-ssh.graph.json")
	if err != nil {
		t.Fatal(err)
	}
	var g graphdomain.Graph
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	e, err := opa.NewDesign()
	if err != nil {
		t.Fatal(err)
	}
	a := &activities.Activities{Tenant: tenant, Policy: e}
	d, err := confirm.DigestOfGraph(g)
	if err != nil {
		t.Fatal(err)
	}
	prep, err := a.Prepare(ctx, activities.Input{Graph: &g, Confirmation: confirm.Confirmation{
		Subject: d.Subject, SubjectSHA256: d.SubjectSHA256, Exposures: d.Exposures, ConfirmedBy: "tester",
	}})
	if err != nil || len(prep.Payload) == 0 {
		t.Fatalf("Prepare = %+v, %v", prep, err)
	}
	x, applied, err := revise.Revise(g, []loopsdomain.Finding{{Code: "NET-003", Resource: "lb:legacy-vms-22", Severity: loopsdomain.SeverityCritical}},
		append(e.Controls(), verify.CoreControls()...))
	if err != nil || len(applied) != 1 || len(x.Edges) >= len(g.Edges) {
		t.Fatalf("control: the revision removes an edge: %d edges of %d, %v, %v", len(x.Edges), len(g.Edges), applied, err)
	}
	best, err := json.Marshal(activities.Candidate{Graph: x, Applied: applied})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.Propose(ctx, loops.ProposeRequest{Payload: prep.Payload, Strategy: activities.StrategyCatalog, Best: best, Iteration: 3})
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !bytes.Equal(resp.Candidate, best) {
		t.Fatalf("Propose changed the best candidate without finding:\n got %s\nwant %s", resp.Candidate, best)
	}
}
