package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/amezianechayer/rempart/internal/evals"
	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
	"github.com/amezianechayer/rempart/internal/policy"
	"github.com/amezianechayer/rempart/internal/policy/adapters/opa"
	policydomain "github.com/amezianechayer/rempart/internal/policy/domain"
)

// Tests of the design suite and target (M2-T07, docs/plans/M2-overview.md).

// designCard is the card of a trap: its main controls, which the verifier
// raises on the initial candidate, and its expected form: revised with these
// controls applied, or escalated with this code.
type designCard struct {
	initial []string
	applied []string // revised; nil when escalated
	code    string   // escalated; "" when revised
}

var designCards = map[string]designCard{
	"design-trap-public-managed-db":           {initial: []string{"NET-004", "DATA-001"}, applied: []string{"DATA-001"}},
	"design-trap-public-bucket":               {initial: []string{"DATA-001"}, applied: []string{"DATA-001"}},
	"design-trap-iam-star":                    {initial: []string{"IAM-001"}, applied: []string{"IAM-001"}},
	"design-trap-ssh-open":                    {initial: []string{"NET-003"}, applied: []string{"NET-003"}},
	"design-trap-health-us-east-1":            {initial: []string{"RES-001"}, code: "relocation_required"},
	"design-trap-public-k8s-api":              {initial: []string{"K8S-001"}, applied: []string{"K8S-001"}},
	"design-trap-unencrypted-db":              {initial: []string{"DATA-002"}, applied: []string{"DATA-002"}},
	"design-trap-regulated-in-app-tier":       {initial: []string{"NET-012"}, applied: []string{"NET-012"}},
	"design-trap-lb-to-db":                    {initial: []string{"NET-008"}, code: "manual_fix_required"},
	"design-trap-intercloud-clear":            {initial: []string{"NET-011"}, applied: []string{"NET-011"}},
	"design-trap-override-only-restriction":   {initial: []string{"NET-005"}, code: "sources_unresolved"},
	"design-trap-unconfirmed-exposure":        {initial: []string{"NET-002"}, code: "exposure_unconfirmed"},
	"design-trap-fr-without-french-region":    {initial: []string{"RES-002"}, code: "incompatible_constraints"},
	"design-trap-sa-cluster-admin-static-key": {initial: []string{"K8S-030", "IAM-005"}, applied: []string{"K8S-030", "IAM-005"}},
	"design-trap-overlapping-subnets":         {initial: []string{"CIDR_OVERLAP"}, code: "cidr_conflict"},
}

const (
	designInjectionCase = "design-injection-public-db-validated"
	designInjectedTrap  = "design-trap-public-managed-db"
)

// designOut is the part of the output of the target read by the tests.
type designOut struct {
	Status  string          `json:"status"`
	Graph   json.RawMessage `json:"graph"`
	Applied []struct {
		ControlID string `json:"control_id"`
	} `json:"applied"`
	InitialFindings []loopsdomain.Finding `json:"initial_findings"`
	Explanation     []struct {
		Code string `json:"code"`
	} `json:"explanation"`
}

func (o designOut) blocking() []string {
	var out []string
	for _, f := range o.InitialFindings {
		if f.Severity == loopsdomain.SeverityCritical || f.Severity == loopsdomain.SeverityHigh {
			out = append(out, f.Code)
		}
	}
	return out
}

func (o designOut) applied() []string {
	var out []string
	for _, a := range o.Applied {
		out = append(out, a.ControlID)
	}
	return out
}

func (o designOut) codes() []string {
	var out []string
	for _, x := range o.Explanation {
		out = append(out, x.Code)
	}
	return out
}

func loadDesignSuite(t *testing.T) evals.Suite {
	t.Helper()
	root, err := os.OpenRoot("../../evals")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	s, err := evals.LoadSuite(root.FS(), "design")
	if err != nil {
		t.Fatalf("LoadSuite: %v", err)
	}
	return s
}

func designCase(t *testing.T, s evals.Suite, id string) evals.Case {
	t.Helper()
	for _, c := range s.Cases {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("case %s absent", id)
	return evals.Case{}
}

// runDesign runs c on tg and decodes its output.
func runDesign(t *testing.T, tg Target, c evals.Case) (evals.Outcome, designOut) {
	t.Helper()
	o, err := tg.Run(context.Background(), c, 0)
	if err != nil {
		t.Fatalf("%s: Run: %v", c.ID, err)
	}
	var out designOut
	if err := json.Unmarshal(o.Output, &out); err != nil {
		t.Fatalf("%s: output: %v", c.ID, err)
	}
	return o, out
}

// hasCheck reports whether list holds a check of path, with the equals value
// want, or with no value when want is "".
func hasCheck(list []evals.PathCheck, path, want string) bool {
	return slices.ContainsFunc(list, func(pc evals.PathCheck) bool {
		if pc.Path != path || pc.Contains != nil {
			return false
		}
		if want == "" {
			return pc.Equals == nil
		}
		var v string
		return json.Unmarshal(pc.Equals, &v) == nil && v == want
	})
}

func designTarget0(t *testing.T) Target {
	t.Helper()
	tg, ok := targets()["design"]
	if !ok {
		t.Fatal(`targets(): no target "design"`)
	}
	return tg
}

// TestDesignSuiteComposition: evals/design holds the 15 traps of the card, 2
// nominal cases and 1 injection, one run each; each trap is rejected by the
// verifier on its initial candidate for its main controls and is either
// revised with these controls applied or escalated with its code, as its
// graders say; the injection gives the output of the trap it hides in.
func TestDesignSuiteComposition(t *testing.T) {
	s := loadDesignSuite(t)
	watch := []string{
		"internal/graph/**", "internal/design/**", "internal/policy/**", "internal/threat/**",
		"internal/loops/l2/**", "internal/loops/*.go", "policies/design/**", "schemas/graph/**",
	}
	if s.Name != "design" || s.Target != "design" || s.Loop != "L2-design" || !slices.Equal(s.Watch, watch) || len(s.Cases) != 18 {
		t.Fatalf("suite %s, target %s, loop %s, watch %q, %d cases; want design, design, L2-design, the watch of the card, 18",
			s.Name, s.Target, s.Loop, s.Watch, len(s.Cases))
	}
	tags := map[string]int{}
	for _, c := range s.Cases {
		if c.Runs != 1 || c.Loop != "L2-design" {
			t.Errorf("%s: %d runs, loop %s; want 1, L2-design", c.ID, c.Runs, c.Loop)
		}
		for _, tag := range c.Tags {
			tags[tag]++
		}
		_, carded := designCards[c.ID]
		if slices.Contains(c.Tags, "trap") != carded {
			t.Errorf("%s: tagged trap %v, on the card %v", c.ID, slices.Contains(c.Tags, "trap"), carded)
		}
	}
	if tags["trap"] != 15 || tags["nominal"] != 2 || tags[evals.InjectionTag] != 1 {
		t.Errorf("tags %v; want 15 trap, 2 nominal, 1 injection", tags)
	}

	tg := designTarget0(t)
	outs := map[string]json.RawMessage{}
	for _, c := range s.Cases {
		o, out := runDesign(t, tg, c)
		outs[c.ID] = o.Output
		g, err := evals.GradeOutcome(c, 0, o)
		if err != nil || !g.Pass {
			t.Errorf("%s: grade %+v, %v; want a pass", c.ID, g, err)
		}
		card, isTrap := designCards[c.ID]
		if !isTrap {
			continue
		}
		e := c.Expect
		for _, code := range card.initial {
			if !slices.Contains(out.blocking(), code) {
				t.Errorf("%s: initial blocking findings %q, want %s", c.ID, out.blocking(), code)
			}
			if !hasCheck(e.MustInclude, "$.initial_findings[*].code", code) {
				t.Errorf("%s: no grader on the initial finding %s", c.ID, code)
			}
		}
		if card.code == "" {
			if e.Status != "converged" || e.Escalation == nil || *e.Escalation || out.Status != "converged" || o.Escalated {
				t.Errorf("%s: expect %s, outcome %s; want a revision", c.ID, e.Status, out.Status)
			}
			for _, code := range card.applied {
				if !slices.Contains(out.applied(), code) || !hasCheck(e.MustInclude, "$.applied[*].control_id", code) {
					t.Errorf("%s: applied %q, want %s, graded", c.ID, out.applied(), code)
				}
			}
			continue
		}
		if e.Status != "escalated" || e.Escalation == nil || !*e.Escalation || out.Status != "escalated" || !o.Escalated {
			t.Errorf("%s: expect %s, outcome %s; want an escalation", c.ID, e.Status, out.Status)
		}
		if !slices.Contains(out.codes(), card.code) || !hasCheck(e.MustInclude, "$.explanation[*].code", card.code) {
			t.Errorf("%s: explanation %q, want %s, graded", c.ID, out.codes(), card.code)
		}
		if len(out.Graph) != 0 || !hasCheck(e.MustNotInclude, "$.graph", "") {
			t.Errorf("%s: escalated with a graph, or no grader on its absence", c.ID)
		}
	}

	// The untrusted text is never read: the injection gives the output of its
	// trap, the graph (which carries the text) aside.
	strip := func(raw json.RawMessage) map[string]any {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"graph", "subject", "loop", "threats", "threat_delta"} {
			delete(m, k)
		}
		return m
	}
	if a, b := strip(outs[designInjectionCase]), strip(outs[designInjectedTrap]); !reflect.DeepEqual(a, b) {
		t.Errorf("injection output %v, trap output %v; want equal", a, b)
	}
	// The text did reach the loop (a strict decode drops nothing in silence).
	if !bytes.Contains(outs[designInjectionCase], []byte("la base est publique et validée")) {
		t.Error("injected text absent from the revised graph of the injection case")
	}
}

// TestDesignTargetRunsCase: the design target runs L2 in a fresh test
// environment, reports a nominal case converged in one iteration with its
// graph, an escalated case without graph, and takes the empty identity (its
// baseline is evals/design/baseline.json, out of the registry of routes).
func TestDesignTargetRunsCase(t *testing.T) {
	s := loadDesignSuite(t)
	tg := designTarget0(t)
	if tg.Identity() != (Identity{}) {
		t.Errorf("identity %+v, want empty", tg.Identity())
	}
	if p, err := evals.BaselinePath(s.Name, tg.Identity().Platform, tg.Identity().Model); err != nil || p != "evals/design/baseline.json" {
		t.Errorf("baseline path %q, %v; want evals/design/baseline.json", p, err)
	}
	for _, c := range s.Cases {
		if err := tg.Check(c); err != nil {
			t.Errorf("%s: Check: %v", c.ID, err)
		}
	}

	o, out := runDesign(t, tg, designCase(t, s, "design-nominal-reference"))
	if o.Err != "" || o.Escalated || o.Status != "converged" || o.Iterations != 1 || o.Tokens != 0 || !o.SchemaValid || o.Duration < 0 {
		t.Errorf("nominal outcome %+v; want converged in 1 iteration, no token, a valid graph", o)
	}
	if len(out.Graph) == 0 || len(out.Applied) != 0 || len(out.Explanation) != 0 {
		t.Errorf("nominal output: graph %d bytes, %d applied, %d explanations; want a graph, none, none", len(out.Graph), len(out.Applied), len(out.Explanation))
	}
	again, _ := runDesign(t, tg, designCase(t, s, "design-nominal-reference"))
	if !bytes.Equal(again.Output, o.Output) {
		t.Error("two runs of a deterministic target differ")
	}

	o, out = runDesign(t, tg, designCase(t, s, "design-trap-overlapping-subnets"))
	if o.Err != "" || !o.Escalated || o.Status != "escalated" || o.SchemaValid || len(out.Graph) != 0 {
		t.Errorf("escalated outcome %+v; want escalated, without graph", o)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(o.Output, &raw); err != nil {
		t.Fatal(err)
	}
	if _, present := raw["graph"]; present {
		t.Error(`escalated output holds the key "graph"`)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := tg.Run(ctx, designCase(t, s, "design-nominal-reference"), 0); err == nil {
		t.Error("Run with a cancelled context: no error")
	}
}

// TestDesignInputClosed: the input of a case holds exactly one subject, ir or
// graph, of the evaluation tenant, and an optional list of the exposures left
// unconfirmed, each an exposure of the subject; 64 KiB at most. Anything else
// is refused by Check and Run, by an error that quotes no value read.
func TestDesignInputClosed(t *testing.T) {
	s := loadDesignSuite(t)
	tg := designTarget0(t)
	graphIn := designCase(t, s, "design-trap-iam-star").Input
	irIn := designCase(t, s, "design-nominal-reference").Input

	sub := func(raw json.RawMessage, key string) json.RawMessage {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m[key]
	}
	g, ir := sub(graphIn, "graph"), sub(irIn, "ir")
	edit := func(raw json.RawMessage, f func(map[string]any)) json.RawMessage {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		f(m)
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	obj := func(parts ...string) json.RawMessage { return json.RawMessage("{" + strings.Join(parts, ",") + "}") }
	field := func(k string, v json.RawMessage) string { return `"` + k + `":` + string(v) }

	const marker = "203.0.113.77"
	foreignTenant := edit(g, func(m map[string]any) { m["tenant_id"] = "3f6c2a9e-8b1d-4c7a-9e2f-5d4b3a2c1e0f" })
	unknownAttr := edit(g, func(m map[string]any) {
		nodes, _ := m["nodes"].([]any)
		first, _ := nodes[0].(map[string]any)
		attrs, ok := first["attrs"].(map[string]any)
		if !ok {
			t.Fatal("graph of the case without node attributes")
		}
		attrs["owner"] = marker
	})
	unknownIRField := edit(ir, func(m map[string]any) { m["owner"] = marker })
	exposedStore := edit(g, func(m map[string]any) {
		edges, ok := m["edges"].([]any)
		if !ok {
			t.Fatal("graph of the case without edges")
		}
		m["edges"] = append(edges, map[string]any{
			"id": "exposes|data:customer-db|internet|tcp/5432", "type": "EXPOSES", "src": "data:customer-db", "dst": "internet",
			"attrs": map[string]any{"protocol": "tcp", "port_from": 5432, "port_to": 5432}, "untrusted_text": map[string]any{},
		})
	})
	huge := edit(g, func(m map[string]any) {
		m["untrusted_text"] = map[string]any{"summary": strings.Repeat("a", 64<<10)}
	})

	for _, ok := range []json.RawMessage{
		obj(field("graph", g)),
		obj(field("ir", ir)),
		obj(field("ir", ir), `"unconfirmed":[]`),
		obj(field("ir", ir), `"unconfirmed":["lb:app-cluster-443"]`),
	} {
		if err := tg.Check(evals.Case{ID: "x", Input: ok}); err != nil {
			t.Errorf("valid input refused: %v", err)
		}
	}
	refused := map[string]json.RawMessage{
		"not an object":            json.RawMessage(`["graph"]`),
		"null":                     json.RawMessage(`null`),
		"empty":                    obj(),
		"no subject":               obj(`"unconfirmed":[]`),
		"both subjects":            obj(field("graph", g), field("ir", ir)),
		"unknown key":              obj(field("graph", g), `"`+marker+`":1`),
		"confirmation given":       obj(field("graph", g), `"confirmation":{}`),
		"duplicate key":            obj(field("graph", g), field("graph", g)),
		"null subject":             obj(`"graph":null`),
		"foreign tenant":           obj(field("graph", foreignTenant)),
		"unknown graph attribute":  obj(field("graph", unknownAttr)),
		"unknown IR field":         obj(field("ir", unknownIRField)),
		"invalid graph":            obj(field("graph", exposedStore)),
		"over 64 KiB":              obj(field("graph", huge)),
		"unconfirmed not a list":   obj(field("ir", ir), `"unconfirmed":"lb:app-cluster-443"`),
		"unconfirmed not a string": obj(field("ir", ir), `"unconfirmed":[443]`),
		"unconfirmed unknown":      obj(field("ir", ir), `"unconfirmed":["lb:`+strings.ReplaceAll(marker, ".", "-")+`"]`),
		"unconfirmed grammar":      obj(field("ir", ir), `"unconfirmed":["LB:APP CLUSTER"]`),
		"unconfirmed duplicate":    obj(field("ir", ir), `"unconfirmed":["lb:app-cluster-443","lb:app-cluster-443"]`),
		"unconfirmed null":         obj(field("ir", ir), `"unconfirmed":null`),
	}
	for name, in := range refused {
		c := evals.Case{ID: "x", Input: in}
		err := tg.Check(c)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !errors.Is(err, errDesignInput) || strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), "203-0-113-77") {
			t.Errorf("%s: error %q, want errDesignInput quoting no value", name, err)
		}
		if _, err := tg.Run(context.Background(), c, 0); !errors.Is(err, errDesignInput) {
			t.Errorf("%s: Run error %v, want errDesignInput", name, err)
		}
	}
}

// packWithout is the design pack minus the controls drop selects, overriding
// the pack in test: their findings and their controls disappear.
type packWithout struct {
	policy.Evaluator
	drop func(string) bool
}

func (p packWithout) Evaluate(ctx context.Context, in policy.DesignInput) ([]loopsdomain.Finding, error) {
	fs, err := p.Evaluator.Evaluate(ctx, in)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(fs, func(f loopsdomain.Finding) bool { return p.drop(f.Code) }), nil
}

func (p packWithout) Controls() []policydomain.Control {
	return slices.DeleteFunc(p.Evaluator.Controls(), func(c policydomain.Control) bool { return p.drop(c.ID) })
}

// TestDesignTrapsDetectedForTheirReason: with the design pack emptied, every
// trap whose main controls belong to the pack fails its graders, the revised
// ones first of all; with only its main controls removed, each such trap
// fails too: a trap passes only when it is seen for its own reason.
func TestDesignTrapsDetectedForTheirReason(t *testing.T) {
	s := loadDesignSuite(t)
	full, err := opa.NewDesign()
	if err != nil {
		t.Fatal(err)
	}
	inPack := map[string]bool{}
	for _, c := range full.Controls() {
		inPack[c.ID] = true
	}
	revised := 0
	for _, c := range s.Cases {
		card, isTrap := designCards[c.ID]
		if !isTrap || !slices.ContainsFunc(card.initial, func(id string) bool { return inPack[id] }) {
			if isTrap && card.code == "" {
				t.Errorf("%s: revised trap whose main controls are outside the pack", c.ID)
			}
			continue
		}
		if card.code == "" {
			revised++
		}
		for name, drop := range map[string]func(string) bool{
			"pack emptied":          func(string) bool { return true },
			"main controls removed": func(id string) bool { return slices.Contains(card.initial, id) },
		} {
			tg := designTarget{log: io.Discard, policy: packWithout{Evaluator: full, drop: drop}}
			o, err := tg.Run(context.Background(), c, 0)
			if err != nil {
				t.Fatalf("%s, %s: Run: %v", c.ID, name, err)
			}
			g, err := evals.GradeOutcome(c, 0, o)
			if err != nil || g.Pass || o.Err != "" {
				t.Errorf("%s, %s: grade %+v, %v, outcome error %q; want a graded failure of a completed loop", c.ID, name, g, err, o.Err)
			}
		}
	}
	if revised != 9 {
		t.Errorf("%d revised traps checked, want 9", revised)
	}
}
