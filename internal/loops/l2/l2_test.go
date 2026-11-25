package l2_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/mock"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"

	"github.com/amezianechayer/rempart/internal/design/confirm"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	"github.com/amezianechayer/rempart/internal/intent"
	intentdomain "github.com/amezianechayer/rempart/internal/intent/domain"
	"github.com/amezianechayer/rempart/internal/loops"
	"github.com/amezianechayer/rempart/internal/loops/l2"
	"github.com/amezianechayer/rempart/internal/loops/l2/activities"
	"github.com/amezianechayer/rempart/internal/policy/adapters/opa"
	policydomain "github.com/amezianechayer/rempart/internal/policy/domain"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

const (
	tenant      tenancy.ID = "3f6c2a9e-8b1d-4c7a-9e2f-5d4b3a2c1e0f"
	otherTenant tenancy.ID = "4f6c2a9e-8b1d-4c7a-9e2f-5d4b3a2c1e0f"
)

type harness struct {
	env     *testsuite.TestWorkflowEnvironment
	mu      sync.Mutex
	started map[string]int
}

func newHarness(t *testing.T, worker tenancy.ID) *harness {
	t.Helper()
	e, err := opa.NewDesign()
	if err != nil {
		t.Fatal(err)
	}
	var suite testsuite.WorkflowTestSuite
	h := &harness{env: suite.NewTestWorkflowEnvironment(), started: map[string]int{}}
	if err := l2.Register(h.env, &activities.Activities{Tenant: worker, Policy: e}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	h.env.SetOnActivityStartedListener(func(info *activity.Info, _ context.Context, _ converter.EncodedValues) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.started[info.ActivityType.Name]++
	})
	return h
}

func (h *harness) count(name string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.started[name]
}

func (h *harness) run(t *testing.T, in l2.Input) (l2.Output, error) {
	t.Helper()
	h.env.ExecuteWorkflow(l2.WorkflowName, in)
	if !h.env.IsWorkflowCompleted() {
		t.Fatal("workflow did not complete")
	}
	if err := h.env.GetWorkflowError(); err != nil {
		return l2.Output{}, err
	}
	var out l2.Output
	if err := h.env.GetWorkflowResult(&out); err != nil {
		t.Fatalf("GetWorkflowResult: %v", err)
	}
	return out, nil
}

func mustRun(t *testing.T, in l2.Input) l2.Output {
	t.Helper()
	out, err := newHarness(t, tenant).run(t, in)
	if err != nil {
		t.Fatalf("workflow error: %v", err)
	}
	return out
}

// irOf reads an IR fixture, edited as a JSON tree.
func irOf(t *testing.T, path string, edit func(m map[string]any)) intentdomain.IR {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // G304: constant paths of the repository test data
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		edit(m)
		if raw, err = json.Marshal(m); err != nil {
			t.Fatal(err)
		}
	}
	ir, err := intent.ParseIR(raw)
	if err != nil {
		t.Fatalf("ParseIR: %v", err)
	}
	return ir
}

const (
	referenceIR = "../../intent/testdata/reference-ir.json"
	canariesIR  = "../../design/testdata/reference-canaries.json"
	sshGraph    = "../../threat/testdata/reference-ssh.graph.json"
)

// confirmed is the input of ir with every exposure of its digest confirmed.
func confirmed(t *testing.T, ir intentdomain.IR) l2.Input {
	t.Helper()
	d, err := confirm.DigestOfIR(ir)
	if err != nil {
		t.Fatal(err)
	}
	return l2.Input{IR: &ir, Confirmation: confirm.Confirmation{Subject: d.Subject, SubjectSHA256: d.SubjectSHA256, Exposures: d.Exposures, ConfirmedBy: "tester@example.org"}}
}

func explained(out l2.Output, code string) bool {
	return slices.ContainsFunc(out.Explanation, func(e l2.Explanation) bool { return e.Code == code })
}

func invalidInput(err error) bool {
	var ae *temporal.ApplicationError
	return errors.As(err, &ae) && ae.Type() == l2.ErrTypeInvalidL2Input
}

// TestL2ReferenceConvergesUnchanged proves C2 of prompts/M2.md and ADR 0012 D5:
// the confirmed reference IR converges at the first verification, unchanged,
// with its STRIDE model and a delta from the initial graph to itself; no
// best, no explanation.
func TestL2ReferenceConvergesUnchanged(t *testing.T) {
	out := mustRun(t, confirmed(t, irOf(t, referenceIR, nil)))
	if out.Status != l2.StatusConverged || out.Subject != "ir" || out.Graph == nil || len(out.Applied) != 0 || out.Applied == nil {
		t.Fatalf("output %s %s, graph %v, applied %v", out.Status, out.Reason, out.Graph != nil, out.Applied)
	}
	if out.Threats == nil || len(out.Threats.Threats) == 0 || out.ThreatDelta == nil || out.ThreatDelta.From != out.ThreatDelta.To {
		t.Fatalf("threats %v, delta %+v", out.Threats != nil, out.ThreatDelta)
	}
	if len(out.Explanation) != 0 || out.Loop.Best != nil || out.Loop.Iterations != 1 {
		t.Errorf("explanation %v, best %s, iterations %d", out.Explanation, out.Loop.Best, out.Loop.Iterations)
	}
	if out.InitialFindings == nil || out.Advisories == nil {
		t.Errorf("lists written null: initial %v, advisories %v", out.InitialFindings, out.Advisories)
	}
	for _, f := range out.InitialFindings {
		if f.Severity == "critical" || f.Severity == "high" {
			t.Errorf("blocking finding on the reference: %+v", f)
		}
	}
}

// TestL2GraphFormRevisesTrap proves ADR 0012 D1 and D2 on the graph form:
// the SSH trap, confirmed, converges once the reviser removed the exposure
// found by NET-003; the delta differs from the initial model.
func TestL2GraphFormRevisesTrap(t *testing.T) {
	raw, err := os.ReadFile(sshGraph)
	if err != nil {
		t.Fatal(err)
	}
	var g graphdomain.Graph
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	d, err := confirm.DigestOfGraph(g)
	if err != nil {
		t.Fatal(err)
	}
	out := mustRun(t, l2.Input{Graph: &g, Confirmation: confirm.Confirmation{Subject: d.Subject, SubjectSHA256: d.SubjectSHA256, Exposures: d.Exposures, ConfirmedBy: "tester"}})
	if out.Status != l2.StatusConverged || out.Subject != "graph" || out.Graph == nil {
		t.Fatalf("output %s %s %+v", out.Status, out.Reason, out.Explanation)
	}
	if !slices.ContainsFunc(out.Applied, func(a l2.Applied) bool {
		return a.ControlID == "NET-003" && a.Resource == "lb:legacy-vms-22" && a.Remediation == policydomain.RemediationRemoveExposure
	}) {
		t.Errorf("applied %+v", out.Applied)
	}
	for _, e := range out.Graph.Edges {
		if e.Type == graphdomain.EdgeExposes && e.Src == "lb:legacy-vms-22" {
			t.Errorf("exposure left: %s", e.ID)
		}
	}
	if out.ThreatDelta == nil || out.ThreatDelta.From == out.ThreatDelta.To {
		t.Errorf("delta %+v, want two revisions", out.ThreatDelta)
	}
}

// TestL2RefusesUnconfirmed proves ADR 0012 D2 and D3 (T107): a confirmation
// of another document, a forged key, no form or two forms are refused by
// Prepare with InvalidL2Input, before any activity of the loop; a subject
// exposure left unconfirmed escalates with exposure_unconfirmed.
func TestL2RefusesUnconfirmed(t *testing.T) {
	ir := irOf(t, referenceIR, nil)
	base := confirmed(t, ir)
	var g graphdomain.Graph
	for name, in := range map[string]l2.Input{
		"other_document": func() l2.Input { x := base; x.Confirmation.SubjectSHA256 = strings.Repeat("0", 64); return x }(),
		"forged_key": func() l2.Input {
			x := base
			k := x.Confirmation.Exposures[0]
			k.Target = "data:customer-db"
			x.Confirmation.Exposures = []confirm.ExposureKey{k}
			return x
		}(),
		"no_form":    {Confirmation: base.Confirmation},
		"two_forms":  {IR: base.IR, Graph: &g, Confirmation: base.Confirmation},
		"no_author":  func() l2.Input { x := base; x.Confirmation.ConfirmedBy = ""; return x }(),
		"other_kind": func() l2.Input { x := base; x.Confirmation.Subject = "graph"; return x }(),
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, tenant)
			_, err := h.run(t, in)
			if !invalidInput(err) {
				t.Fatalf("workflow error %v, want %s", err, l2.ErrTypeInvalidL2Input)
			}
			for _, a := range []string{l2.ProposeActivity, l2.VerifyActivity, l2.FinalizeActivity} {
				if h.count(a) != 0 {
					t.Errorf("%s started %d times before the refusal", a, h.count(a))
				}
			}
		})
	}
	t.Run("exposure_unconfirmed", func(t *testing.T) {
		x := base
		x.Confirmation.Exposures = []confirm.ExposureKey{}
		out := mustRun(t, x)
		if out.Status != l2.StatusEscalated || !explained(out, "exposure_unconfirmed") || out.Graph != nil {
			t.Fatalf("output %s %s %+v", out.Status, out.Reason, out.Explanation)
		}
	})
}

// TestL2TenantMismatchRefused proves ADR 0012 D2 (T3, obligation of the plan
// M1-design-cidr applied to the worker): an IR or a graph of another tenant
// than the worker is refused before any activity of the loop.
func TestL2TenantMismatchRefused(t *testing.T) {
	in := confirmed(t, irOf(t, referenceIR, nil))
	h := newHarness(t, otherTenant)
	if _, err := h.run(t, in); !invalidInput(err) || h.count(l2.ProposeActivity) != 0 || h.count(l2.VerifyActivity) != 0 {
		t.Fatalf("IR of another tenant: %v, propose %d", err, h.count(l2.ProposeActivity))
	}
	_, quoted := newHarness(t, otherTenant).run(t, in)
	if quoted != nil && strings.Contains(quoted.Error(), string(otherTenant)) {
		t.Errorf("refusal quotes a tenant: %v", quoted)
	}
	raw, err := os.ReadFile(sshGraph)
	if err != nil {
		t.Fatal(err)
	}
	var g graphdomain.Graph
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	d, err := confirm.DigestOfGraph(g)
	if err != nil {
		t.Fatal(err)
	}
	gin := l2.Input{Graph: &g, Confirmation: confirm.Confirmation{Subject: d.Subject, SubjectSHA256: d.SubjectSHA256, Exposures: d.Exposures, ConfirmedBy: "tester"}}
	h = newHarness(t, otherTenant)
	if _, err := h.run(t, gin); !invalidInput(err) || h.count(l2.ProposeActivity) != 0 {
		t.Fatalf("graph of another tenant: %v", err)
	}
}

// TestL2UnresolvedSourceEscalates proves obligation (ey) (ADR 0012 D4): an
// override that cites an address while the exposure opens to the whole
// Internet escalates with sources_unresolved (NET-005), the override never
// applied.
func TestL2UnresolvedSourceEscalates(t *testing.T) {
	ir := irOf(t, referenceIR, func(m map[string]any) {
		m["explicit_overrides"] = []any{map[string]any{"statement": "n'ouvrir l'application qu'au bureau 203.0.113.10", "affects": "exposure"}}
	})
	out := mustRun(t, confirmed(t, ir))
	if out.Status != l2.StatusEscalated || !explained(out, "sources_unresolved") {
		t.Fatalf("output %s %s %+v", out.Status, out.Reason, out.Explanation)
	}
	for _, e := range out.Explanation {
		if e.Code == "sources_unresolved" && (e.ControlID != "NET-005" || e.Resource != "exposes|lb:app-cluster-443|internet|https/443") {
			t.Errorf("explanation %+v", e)
		}
	}
}

// inGermany moves every workload to aws eu-central-1, gives the data a
// French residency and allows only the regions listed.
func inGermany(t *testing.T, allowed ...any) intentdomain.IR {
	t.Helper()
	obj := func(v any) map[string]any {
		m, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("fixture: %T is not an object", v)
		}
		return m
	}
	list := func(v any) []any {
		l, ok := v.([]any)
		if !ok || len(l) == 0 {
			t.Fatalf("fixture: %T is not a list", v)
		}
		return l
	}
	return irOf(t, referenceIR, func(m map[string]any) {
		obj(list(m["data"])[0])["residency"] = "fr"
		for _, w := range list(m["workloads"]) {
			obj(w)["cloud"], obj(w)["region"] = "aws", "eu-central-1"
		}
		obj(m["constraints"])["allowed_regions"] = allowed
	})
}

// incompatibleIR keeps French data on hosts in Germany, the only region
// allowed: no allowed region satisfies the zone the data requires.
func incompatibleIR(t *testing.T) intentdomain.IR { return inGermany(t, "eu-central-1") }

// TestL2EscalatesIncompatibleConstraints proves ADR 0012 D5 (trap of the
// plan): French data on hosts of the only allowed region, in Germany, cannot
// be relocated by the reviser and no allowed region satisfies the zone;
// escalation coded incompatible_constraints on the host, a fixed template
// that names the control and the resource and no free text.
func TestL2EscalatesIncompatibleConstraints(t *testing.T) {
	out := mustRun(t, confirmed(t, incompatibleIR(t)))
	if out.Status != l2.StatusEscalated || !explained(out, "incompatible_constraints") {
		t.Fatalf("output %s %s %+v", out.Status, out.Reason, out.Explanation)
	}
	for _, e := range out.Explanation {
		if e.Code == "incompatible_constraints" && e.ControlID == "RES-002" {
			if e.Resource != "wl:legacy-vms" || !strings.Contains(e.Text, "RES-002") || !strings.Contains(e.Text, "wl:legacy-vms") {
				t.Errorf("explanation %+v", e)
			}
			return
		}
	}
	t.Errorf("no incompatible_constraints for RES-002 in %+v", out.Explanation)

	relocatable := inGermany(t, "eu-central-1", "eu-west-3")
	if out := mustRun(t, confirmed(t, relocatable)); out.Status != l2.StatusEscalated || !explained(out, "relocation_required") {
		t.Errorf("an allowed French region: %s %+v, want relocation_required", out.Status, out.Explanation)
	}
}

// TestL2EscalationHasNoGraph proves ADR 0012 D5 (analogue of T98): an
// escalated output, serialized, carries no graph, no best, no threat model
// and no delta, but its explanation.
func TestL2EscalationHasNoGraph(t *testing.T) {
	unconfirmed := confirmed(t, irOf(t, referenceIR, nil))
	unconfirmed.Confirmation.Exposures = []confirm.ExposureKey{}
	for name, in := range map[string]l2.Input{"incompatible": confirmed(t, incompatibleIR(t)), "unconfirmed": unconfirmed} {
		t.Run(name, func(t *testing.T) {
			out := mustRun(t, in)
			raw, err := json.Marshal(out)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			for _, k := range []string{"graph", "threats", "threat_delta"} {
				if _, ok := m[k]; ok {
					t.Errorf("escalated output carries %q", k)
				}
			}
			if loop, _ := m["loop"].(map[string]any); loop == nil || loop["best"] != nil {
				t.Errorf("loop %v carries a best", m["loop"])
			}
			if out.Status != l2.StatusEscalated || len(out.Explanation) == 0 || bytes.Contains(raw, []byte(`"nodes"`)) {
				t.Errorf("output %s, explanation %v", out.Status, out.Explanation)
			}
		})
	}
}

// stripUntrusted removes every untrusted_text object of a JSON tree.
func stripUntrusted(v any) any {
	switch x := v.(type) {
	case map[string]any:
		delete(x, "untrusted_text")
		for k, y := range x {
			x[k] = stripUntrusted(y)
		}
	case []any:
		for i, y := range x {
			x[i] = stripUntrusted(y)
		}
	}
	return v
}

// TestL2FreeTextHasNoEffect proves ADR 0012 D4 (T2, T111): the reference with
// injected untrusted text in every free field gives the same decision, the
// same revisions, findings, threat model and delta, the same facts; the
// canaries appear only inside untrusted_text.
func TestL2FreeTextHasNoEffect(t *testing.T) {
	ref := mustRun(t, confirmed(t, irOf(t, referenceIR, nil)))
	can := mustRun(t, confirmed(t, irOf(t, canariesIR, nil)))
	same := func(a, b any) bool {
		ra, errA := json.Marshal(a)
		rb, errB := json.Marshal(b)
		return errA == nil && errB == nil && bytes.Equal(ra, rb)
	}
	if ref.Status != can.Status || !same(ref.Applied, can.Applied) || !same(ref.InitialFindings, can.InitialFindings) ||
		!same(ref.Advisories, can.Advisories) || !same(ref.Threats, can.Threats) || !same(ref.ThreatDelta, can.ThreatDelta) {
		t.Fatalf("free text changed the decision: %s/%s", ref.Status, can.Status)
	}
	if ref.Graph == nil || can.Graph == nil || !same(graphdomain.FactsOf(*ref.Graph), graphdomain.FactsOf(*can.Graph)) {
		t.Fatalf("free text changed the facts of the graph")
	}
	raw, err := json.Marshal(can)
	if err != nil {
		t.Fatal(err)
	}
	var tree any
	if err := json.Unmarshal(raw, &tree); err != nil {
		t.Fatal(err)
	}
	clean, err := json.Marshal(stripUntrusted(tree))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("CANARY-")) || bytes.Contains(clean, []byte("CANARY-")) {
		t.Errorf("canaries outside untrusted_text, or absent from the graph: %v", bytes.Contains(raw, []byte("CANARY-")))
	}
}

// TestL2SpecIsTheSheet proves criterion 4 of the fiche and ADR 0012 D6: the
// loop of docs/loops/L2.md, valid, one strategy, no model.
func TestL2SpecIsTheSheet(t *testing.T) {
	s := l2.Spec()
	if err := s.Validate(); err != nil || s.ID != "L2-design" || !slices.Equal(s.Strategies, []string{"catalog"}) ||
		s.Budget.MaxIterations != 5 || s.Budget.MaxTokens != 1 || s.SwitchAfter != 2 || s.EscalateAfter != 3 {
		t.Fatalf("spec %+v, %v", s, err)
	}
	if l2.WorkflowName != "rempart.l2.v1" || l2.TaskQueue != "rempart-l2" {
		t.Errorf("names %s %s", l2.WorkflowName, l2.TaskQueue)
	}
	if err := l2.Register(newHarness(t, tenant).env, &activities.Activities{Tenant: tenancy.System, Policy: nil}); err == nil {
		t.Errorf("Register accepted the system tenant without a pack")
	}
}

// TestL2ThirdIterationKeepsOtherEdges proves the high finding of the security
// review of M2-T05 (T122 proposed), on its scenario: the SSH exposure, limited
// to one source, sits just before an exposure open to the whole Internet
// (NET-006, escalate); once the reviser removed the SSH exposure, the next
// iterations must not lend its source to the open one: the run escalates on
// NET-006, never converges.
// TestL2OversizeCandidateEscalatesPayloadTooLarge (obligation (ft), T24,
// T112): a proposal larger than the bound of a candidate makes the loop
// escalate (invalid_response); the workflow hands the reason to Finalize,
// which explains payload_too_large, without graph.
func TestL2OversizeCandidateEscalatesPayloadTooLarge(t *testing.T) {
	h := newHarness(t, tenant)
	big := json.RawMessage(`{"pad":"` + strings.Repeat("a", loops.MaxCandidateBytes) + `"}`)
	h.env.OnActivity(l2.ProposeActivity, mock.Anything, mock.Anything).Return(loops.ProposeResponse{Candidate: big}, nil)
	out, err := h.run(t, confirmed(t, irOf(t, referenceIR, nil)))
	if err != nil {
		t.Fatalf("workflow error: %v", err)
	}
	if out.Status != l2.StatusEscalated || out.Reason != string(loops.ReasonInvalidResponse) || out.Graph != nil {
		t.Fatalf("output %s %s, graph %v; want escalated invalid_response without graph", out.Status, out.Reason, out.Graph != nil)
	}
	if len(out.Explanation) != 1 || out.Explanation[0].Code != activities.CodePayloadTooLarge {
		t.Errorf("explanation %+v; want only payload_too_large", out.Explanation)
	}
}

func TestL2ThirdIterationKeepsOtherEdges(t *testing.T) {
	raw, err := os.ReadFile(sshGraph)
	if err != nil {
		t.Fatal(err)
	}
	var g graphdomain.Graph
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	str := func(s string) *string { return &s }
	yes, port := true, 8080
	for i := range g.Edges {
		if g.Edges[i].ID == "exposes|lb:legacy-vms-22|internet|tcp/22" {
			g.Edges[i].Attrs.AllowedSources = []string{"203.0.113.0/24"}
		}
	}
	g.Nodes = append(g.Nodes, graphdomain.Node{ID: "lb:raw-8080", Kind: graphdomain.KindLoadBalancer, Attrs: graphdomain.NodeAttrs{
		Cloud: str("aws"), Region: str("eu-west-3"), Public: &yes, Listeners: &[]graphdomain.Listener{{Protocol: "tcp", Port: 8080}},
	}})
	g.Edges = append(g.Edges,
		graphdomain.Edge{
			ID: "exposes|lb:raw-8080|internet|tcp/8080", Type: graphdomain.EdgeExposes, Src: "lb:raw-8080", Dst: "internet",
			Attrs: graphdomain.EdgeAttrs{Protocol: str("tcp"), PortFrom: &port, PortTo: &port},
		},
		graphdomain.Edge{ID: "member_of|lb:raw-8080|net:aws-eu-west-3-staging-public", Type: graphdomain.EdgeMemberOf, Src: "lb:raw-8080", Dst: "net:aws-eu-west-3-staging-public"},
	)
	slices.SortFunc(g.Nodes, func(a, b graphdomain.Node) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(g.Edges, func(a, b graphdomain.Edge) int {
		return strings.Compare(string(a.Type)+"|"+a.Src+"|"+a.Dst, string(b.Type)+"|"+b.Src+"|"+b.Dst)
	})
	d, err := confirm.DigestOfGraph(g)
	if err != nil {
		t.Fatal(err)
	}
	out := mustRun(t, l2.Input{Graph: &g, Confirmation: confirm.Confirmation{Subject: d.Subject, SubjectSHA256: d.SubjectSHA256, Exposures: d.Exposures, ConfirmedBy: "tester"}})
	if out.Status != l2.StatusEscalated || out.Graph != nil {
		t.Fatalf("output %s %s, applied %+v: a source lent by another edge silenced NET-006", out.Status, out.Reason, out.Applied)
	}
	if out.Reason != "strategies_exhausted" {
		t.Errorf("reason %q, want strategies_exhausted (a corrupted candidate fails the reviser: activity_failed)", out.Reason)
	}
	for _, it := range out.Loop.Trace {
		if it.Failed {
			t.Errorf("iteration %d: proposal failed", it.Iteration)
		}
	}
	if !slices.ContainsFunc(out.Explanation, func(e l2.Explanation) bool {
		return e.Code == "manual_fix_required" && e.ControlID == "NET-006" && e.Resource == "exposes|lb:raw-8080|internet|tcp/8080"
	}) {
		t.Errorf("explanation %+v, want NET-006 on the open exposure, manual_fix_required", out.Explanation)
	}
	if out.Loop.Iterations < 3 {
		t.Errorf("%d iterations, want the third one that used to inherit the source", out.Loop.Iterations)
	}
}
