package opa

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	"github.com/amezianechayer/rempart/internal/policy"
)

// BenchmarkEvaluate measures ADR 0011 D3 (recorded in docs/STATUS.md, no
// blocking threshold): the reference scenario, and a candidate graph of about
// 64 KiB (loops.MaxCandidateBytes) made of extra virtual machines with their
// identities, flows and exposures.
func BenchmarkEvaluate(b *testing.B) {
	e, err := NewDesign()
	if err != nil {
		b.Fatal(err)
	}
	reference := referenceInput(b, nil)
	large := referenceInput(b, func(f *graphdomain.FactsGraph) {
		str := func(s string) *string { return &s }
		no := false
		one := 1
		for i := 0; ; i++ {
			raw, _ := json.Marshal(f)
			if len(raw) >= 64<<10 {
				return
			}
			id := fmt.Sprintf("wl:vm-%03d", i)
			f.Nodes = append(f.Nodes,
				graphdomain.FactNode{ID: id, Kind: graphdomain.KindCompute, Attrs: graphdomain.NodeAttrs{
					Subtype: str("vm"), Cloud: str("aws"), Region: str("eu-west-3"), Count: &one, PublicIP: &no,
				}},
				graphdomain.FactNode{ID: "id:vm-" + fmt.Sprintf("%03d", i), Kind: graphdomain.KindIdentity, Attrs: graphdomain.NodeAttrs{
					Subtype: str("role"), Cloud: str("aws"), Credential: str("workload_identity"),
				}})
			port := 8000 + i
			f.Edges = append(f.Edges,
				graphdomain.FactEdge{ID: "member_of|" + id + "|net:aws-eu-west-3-staging-app", Type: graphdomain.EdgeMemberOf, Src: id, Dst: "net:aws-eu-west-3-staging-app"},
				graphdomain.FactEdge{ID: "runs_as|" + id + "|id:vm-" + fmt.Sprintf("%03d", i), Type: graphdomain.EdgeRunsAs, Src: id, Dst: "id:vm-" + fmt.Sprintf("%03d", i)},
				graphdomain.FactEdge{
					ID: fmt.Sprintf("can_reach|wl:app-cluster|%s|tcp/%d", id, port), Type: graphdomain.EdgeCanReach, Src: "wl:app-cluster", Dst: id,
					Attrs: graphdomain.EdgeAttrs{Protocol: str("tcp"), PortFrom: &port, PortTo: &port, Via: str("internal"), Path: []string{"net:aws-eu-west-3-staging-app"}},
				})
		}
	})
	for _, c := range []struct {
		name string
		in   policy.DesignInput
	}{{"reference", reference}, {"candidate_64KiB", large}} {
		raw, err := json.Marshal(c.in)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ReportMetric(float64(len(raw)), "input_bytes")
			for b.Loop() {
				if _, err := e.Evaluate(context.Background(), c.in); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
