package verify_test

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/amezianechayer/rempart/internal/design"
	"github.com/amezianechayer/rempart/internal/design/confirm"
	"github.com/amezianechayer/rempart/internal/design/verify"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	"github.com/amezianechayer/rempart/internal/intent"
	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
	"github.com/amezianechayer/rempart/internal/policy"
	policydomain "github.com/amezianechayer/rempart/internal/policy/domain"
)

const (
	referenceIR = "../../intent/testdata/reference-ir.json"
	tenant      = "3f6c2a9e-8b1d-4c7a-9e2f-5d4b3a2c1e0f"
	exposure    = "exposes|lb:app-cluster-443|internet|https/443"
)

// recorder is an empty pack: no control, no finding; it keeps its input.
type recorder struct {
	in  policy.DesignInput
	out []loopsdomain.Finding
	err error
}

func (r *recorder) Evaluate(_ context.Context, in policy.DesignInput) ([]loopsdomain.Finding, error) {
	r.in = in
	if err := in.Check(); err != nil {
		return nil, err
	}
	return r.out, r.err
}

func (r *recorder) Controls() []policydomain.Control { return nil }

func (r *recorder) Digest() string { return strings.Repeat("0", 64) }

func reference(t *testing.T) graphdomain.Graph {
	t.Helper()
	raw, err := os.ReadFile(referenceIR)
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
	if g.TenantID != tenant {
		t.Fatalf("reference tenant %s", g.TenantID)
	}
	return g
}

func confirmedAll(t *testing.T, g graphdomain.Graph) verify.Context {
	t.Helper()
	d, err := confirm.DigestOfGraph(g)
	if err != nil {
		t.Fatal(err)
	}
	return verify.Context{Confirmed: d.Exposures}
}

func codes(fs []loopsdomain.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Code+"@"+f.Resource)
	}
	return out
}

func ptr[T any](v T) *T { return &v }

func setNode(g *graphdomain.Graph, id string, edit func(a *graphdomain.NodeAttrs)) {
	for i := range g.Nodes {
		if g.Nodes[i].ID == id {
			edit(&g.Nodes[i].Attrs)
		}
	}
}

// TestL2CoreInvariantWithoutPack proves ADR 0012 D4 (T108): with an empty
// pack, a sensitive data store or its host reached directly from the Internet
// is still a critical finding of the core, an exposure not covered by the
// confirmation a high one, and the facts given to the pack carry the
// unconfirmed exposures and, when an override cites an address, the
// exposures open to the world (obligation (ey)); the reference, confirmed,
// has no finding.
func TestL2CoreInvariantWithoutPack(t *testing.T) {
	ctx := context.Background()
	g := reference(t)
	ev := &recorder{out: []loopsdomain.Finding{}}
	fs, err := verify.Candidate(ctx, ev, g, tenant, confirmedAll(t, g))
	if err != nil || fs == nil || len(fs) != 0 {
		t.Fatalf("confirmed reference = %v, %v; want an empty, non-nil list", codes(fs), err)
	}
	if len(ev.in.Derived.UnconfirmedExposures) != 0 || len(ev.in.Derived.SourcesUnresolved) != 0 {
		t.Errorf("confirmed reference: derived %+v", ev.in.Derived)
	}

	exposed := reference(t)
	setNode(&exposed, "data:customer-db", func(a *graphdomain.NodeAttrs) { a.PublicAccess = ptr(true) })
	setNode(&exposed, "wl:legacy-vms", func(a *graphdomain.NodeAttrs) { a.PublicIP = ptr(true) })
	fs, err = verify.Candidate(ctx, &recorder{out: []loopsdomain.Finding{}}, exposed, tenant, confirmedAll(t, exposed))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{verify.CodeInternetToSensitive + "@data:customer-db", verify.CodeInternetToSensitive + "@wl:legacy-vms"} {
		if !slices.Contains(codes(fs), want) {
			t.Errorf("empty pack: %s missing from %v", want, codes(fs))
		}
	}
	for _, f := range fs {
		if f.Code == verify.CodeInternetToSensitive && (f.Severity != loopsdomain.SeverityCritical || f.Source != verify.Source) {
			t.Errorf("finding %+v: want critical, source %s", f, verify.Source)
		}
		if f.Resource == "lb:app-cluster-443" || f.Resource == "wl:app-cluster" {
			t.Errorf("a non-sensitive exposure is a finding of the core: %+v", f)
		}
	}

	ev = &recorder{out: []loopsdomain.Finding{}}
	fs, err = verify.Candidate(ctx, ev, g, tenant, verify.Context{Confirmed: []confirm.ExposureKey{}, OverridesCiteAddress: true})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(codes(fs), verify.CodeExposureUnconfirmed+"@lb:app-cluster-443") {
		t.Errorf("unconfirmed exposure: %v", codes(fs))
	}
	if !slices.Equal(ev.in.Derived.UnconfirmedExposures, []string{exposure}) || !slices.Equal(ev.in.Derived.SourcesUnresolved, []string{exposure}) {
		t.Errorf("derived facts %v, %v; want the exposure unconfirmed and its sources unresolved", ev.in.Derived.UnconfirmedExposures, ev.in.Derived.SourcesUnresolved)
	}

	controls := verify.CoreControls()
	if len(controls) != 2 || controls[0].ID != verify.CodeExposureUnconfirmed || controls[1].ID != verify.CodeInternetToSensitive ||
		controls[1].Severity != loopsdomain.SeverityCritical || controls[1].Remediation != policydomain.RemediationMakePrivate ||
		controls[0].Severity != loopsdomain.SeverityHigh || controls[0].Remediation != policydomain.RemediationEscalate {
		t.Errorf("core controls %+v", controls)
	}
}

// TestCandidateRefusesAndChecks proves ADR 0012 D4: a candidate of another
// tenant or outside the schema is refused with a fixed error, an error of the
// pack is never an empty list, the plan read back from the graph is checked
// (overlapping networks are a CIDR finding).
func TestCandidateRefusesAndChecks(t *testing.T) {
	ctx := context.Background()
	g := reference(t)
	c := confirmedAll(t, g)
	const other = "4f6c2a9e-8b1d-4c7a-9e2f-5d4b3a2c1e0f"
	if _, err := verify.Candidate(ctx, &recorder{}, g, other, c); !errors.Is(err, verify.ErrCandidate) || strings.Contains(err.Error(), other) {
		t.Errorf("other tenant: %v, want ErrCandidate without the tenant", err)
	}
	bad := reference(t)
	bad.Nodes = append(slices.Clone(bad.Nodes), graphdomain.Node{ID: "wl:x", Kind: "Mainframe"})
	if _, err := verify.Candidate(ctx, &recorder{}, bad, tenant, c); !errors.Is(err, verify.ErrCandidate) {
		t.Errorf("invalid graph: %v, want ErrCandidate", err)
	}
	boom := errors.New("pack failed")
	if fs, err := verify.Candidate(ctx, &recorder{err: boom}, g, tenant, c); err == nil || fs != nil {
		t.Errorf("pack error: %v, %v; want an error and no list", fs, err)
	}
	if _, err := verify.Candidate(ctx, nil, g, tenant, c); !errors.Is(err, verify.ErrCandidate) {
		t.Errorf("nil evaluator: %v", err)
	}

	overlap := reference(t)
	var first string
	for i := range overlap.Nodes {
		n := &overlap.Nodes[i]
		if n.Kind != graphdomain.KindNetwork || n.Attrs.Subtype == nil || *n.Attrs.Subtype != "vpc" {
			continue
		}
		if first == "" {
			first = *n.Attrs.CIDR
			continue
		}
		n.Attrs.CIDR = ptr(first)
	}
	fs, err := verify.Candidate(ctx, &recorder{out: []loopsdomain.Finding{}}, overlap, tenant, confirmedAll(t, overlap))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range fs {
		found = found || strings.HasPrefix(f.Code, "CIDR_")
	}
	if !found {
		t.Errorf("two VPCs on one prefix: no CIDR finding in %v", codes(fs))
	}
}
