package activities_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"go.temporal.io/sdk/temporal"
	"pgregory.net/rapid"

	"github.com/amezianechayer/rempart/internal/design/confirm"
	"github.com/amezianechayer/rempart/internal/design/revise"
	"github.com/amezianechayer/rempart/internal/design/verify"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	intentdomain "github.com/amezianechayer/rempart/internal/intent/domain"
	"github.com/amezianechayer/rempart/internal/loops"
	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
	"github.com/amezianechayer/rempart/internal/loops/l2/activities"
	"github.com/amezianechayer/rempart/internal/policy"
	"github.com/amezianechayer/rempart/internal/policy/adapters/opa"
	policydomain "github.com/amezianechayer/rempart/internal/policy/domain"
)

// Obligations (fp), (fq), (fs), (ft) of the security review of M2-T05.

const (
	enrichedPath  = "../../../design/revise/testdata/enriched.graph.json"
	referencePath = "../../../threat/testdata/reference.graph.json"
	sshPath       = "../../../threat/testdata/reference-ssh.graph.json"
)

func graphAt(t testing.TB, path string) graphdomain.Graph {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // fixed fixture paths of this file
	if err != nil {
		t.Fatal(err)
	}
	var g graphdomain.Graph
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	return g
}

func design(t testing.TB) *opa.Engine {
	t.Helper()
	e, err := opa.NewDesign()
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// prepared confirms every exposure of g and returns its payload.
func prepared(t testing.TB, a *activities.Activities, g graphdomain.Graph) json.RawMessage {
	t.Helper()
	d, err := confirm.DigestOfGraph(g)
	if err != nil {
		t.Fatal(err)
	}
	prep, err := a.Prepare(context.Background(), activities.Input{Graph: &g, Confirmation: confirm.Confirmation{
		Subject: d.Subject, SubjectSHA256: d.SubjectSHA256, Exposures: d.Exposures, ConfirmedBy: "tester",
	}})
	if err != nil || len(prep.Payload) == 0 {
		t.Fatalf("Prepare = %+v, %v", prep, err)
	}
	return prep.Payload
}

func nonRetryable(err error) bool {
	var ae *temporal.ApplicationError
	return errors.As(err, &ae) && ae.NonRetryable()
}

// TestProposeIterationsMatchRevise (obligation (fq)): over several iterations,
// with the findings of the verifier or drawn at random, Propose gives exactly
// the reviser composed in memory (the candidate crosses JSON and is decoded
// into a zero value every time), and every candidate derives from the
// subject for the verifier.
func TestProposeIterationsMatchRevise(t *testing.T) {
	ctx := context.Background()
	e := design(t)
	a := &activities.Activities{Tenant: tenant, Policy: e}
	controls := append(e.Controls(), verify.CoreControls()...)
	odd := graphAt(t, enrichedPath) // identifiers the schema admits, the builder never writes
	for i := range odd.Edges {
		switch odd.Edges[i].ID {
		case "exposes|lb:web-80|internet|http/80":
			odd.Edges[i].ID = "exposes|lb:web-80|internet"
		case "can_reach|internet|wl:billing|http/8080":
			odd.Edges[i].ID = "can_reach|internet|wl:billing|tcp/8080"
		}
	}
	slices.SortFunc(odd.Edges, func(p, q graphdomain.Edge) int { return strings.Compare(p.ID, q.ID) })
	bases := []graphdomain.Graph{graphAt(t, enrichedPath), graphAt(t, sshPath), odd}
	payloads := []json.RawMessage{prepared(t, a, bases[0]), prepared(t, a, bases[1]), prepared(t, a, bases[2])}
	rapid.Check(t, func(rt *rapid.T) {
		b := rapid.IntRange(0, len(bases)-1).Draw(rt, "base")
		g, payload := bases[b], payloads[b]
		var ids []string
		for _, n := range g.Nodes {
			ids = append(ids, n.ID)
		}
		for _, x := range g.Edges {
			ids = append(ids, x.ID)
		}
		resp, err := a.Propose(ctx, loops.ProposeRequest{Payload: payload, Strategy: activities.StrategyCatalog, Iteration: 1})
		if err != nil {
			rt.Fatalf("Propose 1: %v", err)
		}
		want, wantApplied := g, []revise.Applied{}
		best := resp.Candidate
		for it := 2; it <= rapid.IntRange(2, 5).Draw(rt, "iterations"); it++ {
			var fs []loopsdomain.Finding
			if rapid.Bool().Draw(rt, "verifier findings") {
				vr, err := a.Verify(ctx, loops.VerifyRequest{Payload: payload, Candidate: best, Iteration: it})
				if err != nil {
					rt.Fatalf("Verify %d: %v", it, err)
				}
				fs = loopsdomain.Top(vr.Findings, loops.MaxFindingsToPropose)
			}
			for i, n := 0, rapid.IntRange(0, 6).Draw(rt, "random findings"); i < n; i++ {
				c := rapid.SampledFrom(controls).Draw(rt, "control")
				fs = append(fs, loopsdomain.Finding{Code: c.ID, Severity: c.Severity, Resource: rapid.SampledFrom(ids).Draw(rt, "resource")})
			}
			resp, err := a.Propose(ctx, loops.ProposeRequest{Payload: payload, Strategy: activities.StrategyCatalog, Best: best, Findings: fs, Iteration: it})
			if err != nil {
				rt.Fatalf("Propose %d: %v", it, err)
			}
			next, applied, err := revise.Revise(want, fs, controls)
			if err != nil {
				rt.Fatalf("Revise %d: %v", it, err)
			}
			want = next
			for _, x := range applied {
				if !slices.Contains(wantApplied, x) {
					wantApplied = append(wantApplied, x)
				}
			}
			var got activities.Candidate
			if err := json.Unmarshal(resp.Candidate, &got); err != nil {
				rt.Fatalf("candidate %d: %v", it, err)
			}
			gotGraph, _ := json.Marshal(got.Graph)
			wantGraph, _ := json.Marshal(want)
			if !bytes.Equal(gotGraph, wantGraph) || !slices.Equal(got.Applied, wantApplied) {
				rt.Fatalf("iteration %d: Propose differs from the reviser composed in memory", it)
			}
			if err := verify.Derives(g, got.Graph); err != nil {
				rt.Fatalf("iteration %d: candidate refused by Derives: %v", it, err)
			}
			best = resp.Candidate
		}
	})
}

// TestVerifyRefusesUnderivedCandidate (obligation (fp), T110, T122): a
// candidate valid on its own but not derived from the subject (a node added,
// a flag turned on, a source dropped) is refused by Verify and by Finalize,
// non-retryable: never a finding to revise, never a graph delivered.
func TestVerifyRefusesUnderivedCandidate(t *testing.T) {
	ctx := context.Background()
	a := &activities.Activities{Tenant: tenant, Policy: design(t)}
	g := graphAt(t, referencePath)
	payload := prepared(t, a, g)
	yes := true
	for name, edit := range map[string]func(x *graphdomain.Graph){
		"node added": func(x *graphdomain.Graph) {
			x.Nodes = append(x.Nodes, graphdomain.Node{ID: "id:extra", Kind: graphdomain.KindIdentity})
			slices.SortFunc(x.Nodes, func(p, q graphdomain.Node) int { return strings.Compare(p.ID, q.ID) })
		},
		"vm made public": func(x *graphdomain.Graph) {
			for i := range x.Nodes {
				if x.Nodes[i].ID == "wl:legacy-vms" {
					x.Nodes[i].Attrs.PublicIP = &yes
				}
			}
		},
		"stores removed": func(x *graphdomain.Graph) {
			x.Edges = slices.DeleteFunc(x.Edges, func(e graphdomain.Edge) bool { return e.Type == graphdomain.EdgeStores })
		},
	} {
		raw, err := json.Marshal(g)
		if err != nil {
			t.Fatal(err)
		}
		var x graphdomain.Graph
		if err := json.Unmarshal(raw, &x); err != nil {
			t.Fatal(err)
		}
		edit(&x)
		cand, err := json.Marshal(activities.Candidate{Graph: x, Applied: []revise.Applied{}})
		if err != nil {
			t.Fatal(err)
		}
		if vr, err := a.Verify(ctx, loops.VerifyRequest{Payload: payload, Candidate: cand, Iteration: 2}); err == nil || !nonRetryable(err) {
			t.Errorf("%s: Verify = %+v, %v; want a non-retryable refusal", name, vr, err)
		}
		if fin, err := a.Finalize(ctx, activities.FinalizeRequest{Payload: payload, Best: cand, Converged: true, Remaining: []loopsdomain.Finding{}}); err == nil || fin.Graph != nil {
			t.Errorf("%s: Finalize delivered %v, %v; want a refusal", name, fin.Graph != nil, err)
		}
	}
	// The subject itself still passes.
	cand, err := json.Marshal(activities.Candidate{Graph: g, Applied: []revise.Applied{}})
	if err != nil {
		t.Fatal(err)
	}
	if vr, err := a.Verify(ctx, loops.VerifyRequest{Payload: payload, Candidate: cand, Iteration: 1}); err != nil || !vr.OK {
		t.Errorf("subject: Verify = %+v, %v; want OK", vr, err)
	}
}

// crowded is the reference graph with n virtual machines in the AWS app
// subnet, without identity (IAM-006, medium, each), and p public buckets of
// confidential data (DATA-001, critical, each).
func crowded(t testing.TB, n, p int) graphdomain.Graph {
	t.Helper()
	g := graphAt(t, referencePath)
	str := func(s string) *string { return &s }
	no, yes, one := false, true, 1
	for i := range n {
		id := fmt.Sprintf("wl:v%03d", i)
		g.Nodes = append(g.Nodes, graphdomain.Node{ID: id, Kind: graphdomain.KindCompute, Attrs: graphdomain.NodeAttrs{
			Cloud: str("aws"), Region: str("eu-west-3"), Subtype: str("vm"), Count: &one, OS: str("linux"), PublicIP: &no,
		}})
		g.Edges = append(g.Edges, graphdomain.Edge{ID: "member_of|" + id + "|net:aws-eu-west-3-staging-app", Type: graphdomain.EdgeMemberOf, Src: id, Dst: "net:aws-eu-west-3-staging-app"})
	}
	for i := range p {
		g.Nodes = append(g.Nodes, graphdomain.Node{ID: fmt.Sprintf("data:b%02d", i), Kind: graphdomain.KindDataStore, Attrs: graphdomain.NodeAttrs{
			Cloud: str("aws"), Region: str("eu-west-3"), Subtype: str("object_storage"), Classification: str("confidential"), Encrypted: &yes, PublicAccess: &yes,
		}})
	}
	slices.SortFunc(g.Nodes, func(a, b graphdomain.Node) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(g.Edges, func(a, b graphdomain.Edge) int { return strings.Compare(a.ID, b.ID) })
	return g
}

// allFindings runs the verifier as Finalize does on a graph subject.
func allFindings(t *testing.T, e policy.Evaluator, g graphdomain.Graph) []loopsdomain.Finding {
	t.Helper()
	d, err := confirm.DigestOfGraph(g)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := verify.Candidate(context.Background(), e, g, string(tenant), verify.Context{Confirmed: d.Exposures, Base: policy.DesignContext{
		Constraints: policydomain.Constraints{AllowedRegions: []string{}, ForbiddenClouds: []string{}}, WorkloadRoles: map[string]string{},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

// TestFinalizeBoundsFindings (obligation (fs), T112): Finalize reports at
// most MaxReportedFindings initial findings and advisories, the gravest, and
// counts the omitted ones.
func TestFinalizeBoundsFindings(t *testing.T) {
	ctx := context.Background()
	e := design(t)
	a := &activities.Activities{Tenant: tenant, Policy: e}
	bound := activities.MaxReportedFindings
	if bound < 1 || bound > loops.MaxFindings {
		t.Fatalf("MaxReportedFindings = %d", bound)
	}

	// Escalated: the initial findings are the gravest, criticals first.
	g := crowded(t, bound+10, 3)
	all := allFindings(t, e, g)
	if len(all) <= bound {
		t.Fatalf("control: %d findings, want more than %d", len(all), bound)
	}
	fin, err := a.Finalize(ctx, activities.FinalizeRequest{Payload: prepared(t, a, g), Converged: false, Reason: string(loops.ReasonStrategiesExhausted), Remaining: []loopsdomain.Finding{}})
	if err != nil {
		t.Fatal(err)
	}
	if want := loopsdomain.Top(all, bound); !slices.Equal(fin.InitialFindings, want) || fin.InitialFindingsOmitted != len(all)-bound {
		t.Errorf("initial findings: %d kept, %d omitted; want the %d gravest of %d, %d omitted",
			len(fin.InitialFindings), fin.InitialFindingsOmitted, bound, len(all), len(all)-bound)
	}

	// Converged: the advisories are bounded the same way.
	g = crowded(t, bound+10, 0)
	all = allFindings(t, e, g)
	payload := prepared(t, a, g)
	best, err := json.Marshal(activities.Candidate{Graph: g, Applied: []revise.Applied{}})
	if err != nil {
		t.Fatal(err)
	}
	fin, err = a.Finalize(ctx, activities.FinalizeRequest{Payload: payload, Best: best, Converged: true, Remaining: []loopsdomain.Finding{}})
	if err != nil {
		t.Fatalf("Finalize converged: %v", err)
	}
	if len(all) <= bound || len(fin.Advisories) != bound || fin.AdvisoriesOmitted != len(all)-bound || fin.InitialFindingsOmitted != len(all)-bound {
		t.Errorf("advisories: %d kept, %d omitted, initial omitted %d, of %d; want %d kept", len(fin.Advisories), fin.AdvisoriesOmitted, fin.InitialFindingsOmitted, len(all), bound)
	}

	// Small graphs omit nothing.
	g = graphAt(t, referencePath)
	fin, err = a.Finalize(ctx, activities.FinalizeRequest{Payload: prepared(t, a, g), Converged: false, Reason: string(loops.ReasonStrategiesExhausted), Remaining: []loopsdomain.Finding{}})
	if err != nil || fin.InitialFindingsOmitted != 0 || fin.AdvisoriesOmitted != 0 {
		t.Errorf("reference: omitted %d and %d, %v; want none", fin.InitialFindingsOmitted, fin.AdvisoriesOmitted, err)
	}
}

// TestPrepareBoundsSubjectFirst (obligation (ft), T24, T112): a subject
// larger than the bound of a candidate escalates payload_too_large before
// any schema, Build, reachability or confirmation work: even outside its
// schema and with no confirmation. A subject of another tenant is still
// refused first.
func TestPrepareBoundsSubjectFirst(t *testing.T) {
	ctx := context.Background()
	a := &activities.Activities{Tenant: tenant, Policy: design(t)}
	pad := strings.Repeat("a", loops.MaxCandidateBytes)

	g := graphAt(t, referencePath)
	g.Nodes = append(g.Nodes, graphdomain.Node{ID: "wl:" + pad, Kind: "Bogus"})
	ir := intentdomain.IR{Version: "1", TenantID: string(tenant), Summary: pad}
	for name, in := range map[string]activities.Input{
		"graph": {Graph: &g},
		"ir":    {IR: &ir},
	} {
		prep, err := a.Prepare(ctx, in)
		if err != nil || len(prep.Payload) != 0 || len(prep.Escalation) != 1 || prep.Escalation[0].Code != activities.CodePayloadTooLarge {
			t.Errorf("%s: Prepare = %+v, %v; want one escalation payload_too_large", name, prep.Escalation, err)
		}
	}

	other := g
	other.TenantID = "4f6c2a9e-8b1d-4c7a-9e2f-5d4b3a2c1e0f"
	if _, err := a.Prepare(ctx, activities.Input{Graph: &other}); err == nil {
		t.Error("oversized subject of another tenant: not refused")
	}
}

// TestFinalizeExplainsOversizeRevision (obligation (ft)): when the loop
// escalates because a revised candidate exceeds its bound (invalid_response,
// the only cause of that reason in L2), the explanation is payload_too_large,
// not manual_fix_required on the findings left.
func TestFinalizeExplainsOversizeRevision(t *testing.T) {
	ctx := context.Background()
	a := &activities.Activities{Tenant: tenant, Policy: design(t)}
	payload := prepared(t, a, graphAt(t, sshPath))
	left := []loopsdomain.Finding{{Code: "NET-003", Source: "policy:design", Severity: loopsdomain.SeverityCritical, Resource: "lb:legacy-vms-22"}}
	fin, err := a.Finalize(ctx, activities.FinalizeRequest{Payload: payload, Converged: false, Reason: string(loops.ReasonInvalidResponse), Remaining: left})
	if err != nil {
		t.Fatal(err)
	}
	if len(fin.Explanation) != 1 || fin.Explanation[0].Code != activities.CodePayloadTooLarge || fin.Graph != nil {
		t.Errorf("explanation %+v; want only payload_too_large", fin.Explanation)
	}
	fin, err = a.Finalize(ctx, activities.FinalizeRequest{Payload: payload, Converged: false, Reason: string(loops.ReasonStrategiesExhausted), Remaining: left})
	if err != nil || len(fin.Explanation) != 1 || fin.Explanation[0].Code != activities.CodeManualFixRequired {
		t.Errorf("strategies exhausted: %+v, %v; want manual_fix_required", fin.Explanation, err)
	}
}

// TestFinalizeExplainsActivityFailure (review of M2-T08, low, ADR 0012 D4):
// when the loop escalates on a failed activity (a candidate refused by
// Derives among others), the explanation starts with evaluation_failed,
// then the findings left.
func TestFinalizeExplainsActivityFailure(t *testing.T) {
	ctx := context.Background()
	a := &activities.Activities{Tenant: tenant, Policy: design(t)}
	payload := prepared(t, a, graphAt(t, sshPath))
	left := []loopsdomain.Finding{{Code: "NET-003", Source: "policy:design", Severity: loopsdomain.SeverityCritical, Resource: "lb:legacy-vms-22"}}
	for _, remaining := range [][]loopsdomain.Finding{left, {}} {
		fin, err := a.Finalize(ctx, activities.FinalizeRequest{Payload: payload, Converged: false, Reason: string(loops.ReasonActivityFailed), Remaining: remaining})
		if err != nil {
			t.Fatal(err)
		}
		if len(fin.Explanation) != 1+len(remaining) || fin.Explanation[0].Code != activities.CodeEvaluationFailed || fin.Graph != nil {
			t.Errorf("remaining %d: explanation %+v; want evaluation_failed first, then one per finding", len(remaining), fin.Explanation)
		}
	}
}

// wireBytes bounds the encoding/json length of s as loops counts it: 6 for a
// control byte, <, > and &; 2 for ", \ and each byte of a multi-byte rune.
func wireBytes(s string) int {
	n := 0
	for i := range len(s) {
		switch b := s[i]; {
		case b < 0x20 || b == '<' || b == '>' || b == '&':
			n += 6
		case b == '"' || b == '\\' || b >= 0x80:
			n += 2
		default:
			n++
		}
	}
	return n
}

// TestInvalidResponseOnlyFromSize (obligation (ge)): in L2, the loop reason
// invalid_response comes only from a candidate beyond its bound, so Finalize
// may explain it payload_too_large. Every finding Verify can return fits
// MaxFindingBytes (each title of the pack and of the core with the longest
// resource the graph schema admits, each CIDR code with the longest pair of
// networks), Propose declares no token and its refusals carry no details.
func TestInvalidResponseOnlyFromSize(t *testing.T) {
	e := design(t)
	node := "data:" + strings.Repeat("a", 81) // node_id: prefix and at most 81 characters
	edge := "can_reach|" + node + "|" + node + "|https/65535-65535"
	pair := strings.Repeat("a", 81) + "|" + strings.Repeat("b", 81)
	for _, c := range append(e.Controls(), verify.CoreControls()...) {
		n := wireBytes(c.ID) + wireBytes("policy:design") + wireBytes(string(c.Severity)) + wireBytes(edge) + wireBytes(c.Title)
		if n > loops.MaxFindingBytes {
			t.Errorf("%s: a finding of %d bytes, over MaxFindingBytes", c.ID, n)
		}
	}
	cidrMessages := []string{
		"invalid superblock", "invalid CIDR", "invalid external CIDR", "range is not RFC 1918 private",
		"range outside the superblock", "unknown parent", "range outside its parent", "sibling ranges overlap", "range overlaps an external range",
	}
	for _, m := range cidrMessages {
		if n := wireBytes("CIDR_OVERLAP_EXTERNAL") + wireBytes("cidr_check") + wireBytes("critical") + wireBytes(pair) + wireBytes(m); n > loops.MaxFindingBytes {
			t.Errorf("CIDR finding %q: %d bytes, over MaxFindingBytes", m, n)
		}
	}
	a := &activities.Activities{Tenant: tenant, Policy: e}
	payload := prepared(t, a, graphAt(t, sshPath))
	resp, err := a.Propose(context.Background(), loops.ProposeRequest{Payload: payload, Strategy: activities.StrategyCatalog, Iteration: 1})
	if err != nil || resp.Tokens != 0 {
		t.Errorf("Propose = %d tokens, %v; want 0, no error", resp.Tokens, err)
	}
	_, err = a.Propose(context.Background(), loops.ProposeRequest{Payload: payload, Strategy: "other", Iteration: 1})
	var ae *temporal.ApplicationError
	if !errors.As(err, &ae) || ae.HasDetails() {
		t.Errorf("Propose refusal %v: want an application error without details", err)
	}
}
