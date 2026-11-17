package main

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"go.temporal.io/sdk/client"

	intentdomain "github.com/amezianechayer/rempart/internal/intent/domain"
	"github.com/amezianechayer/rempart/internal/loops/l1"
	l1activities "github.com/amezianechayer/rempart/internal/loops/l1/activities"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

// M1-T05: the worker runs one L1 workflow (make l1-demo), registered behind
// codec.Check like the demo.

const (
	l1Script  = "internal/loops/l1/testdata/scripts/converge.json"
	l1Request = "internal/intent/testdata/reference-request.txt"
)

// l1Args returns the command line of make l1-demo.
func l1Args() []string {
	args := slices.DeleteFunc(demoArgs(), func(a string) bool { return a == "-demo-once" || strings.HasPrefix(a, "-fake-script=") })
	return append(args, "-l1-once", "-fake-script="+l1Script, "-l1-request="+l1Request)
}

// TestLoadConfigL1Once: -l1-once and -demo-once exclude each other;
// -l1-request is required with -l1-once only, a relative .txt path.
func TestLoadConfigL1Once(t *testing.T) {
	cfg, err := LoadConfig(l1Args())
	if err != nil {
		t.Fatalf("LoadConfig(make l1-demo) = %v", err)
	}
	if !cfg.L1Once || cfg.DemoOnce || cfg.L1Request != l1Request || cfg.FakeScript != l1Script {
		t.Errorf("LoadConfig(make l1-demo) = %+v", cfg)
	}
	del := func(name string, extra ...string) []string {
		args := slices.DeleteFunc(l1Args(), func(a string) bool { return a == "-"+name || strings.HasPrefix(a, "-"+name+"=") })
		return append(args, extra...)
	}
	for name, args := range map[string][]string{
		"both_modes":        append(l1Args(), "-demo-once"),
		"request_absent":    del("l1-request"),
		"request_with_demo": append(demoArgs(), "-l1-request="+l1Request),
		"request_absolute":  del("l1-request", "-l1-request=/etc/passwd.txt"),
		"request_parent":    del("l1-request", "-l1-request=../x.txt"),
		"request_json":      del("l1-request", "-l1-request=x.json"),
		"request_repeated":  append(l1Args(), "-l1-request="+l1Request),
	} {
		t.Run(name, func(t *testing.T) { refused(t, args, ErrConfig) })
	}
	refused(t, del("l1-once"), ErrDemoOnceRequired) // -l1-request without a mode
}

// TestWorkerRequiresRempartConverterL1: registerL1 refuses options without
// the converters of Rempart and registers nothing.
func TestWorkerRequiresRempartConverterL1(t *testing.T) {
	t.Chdir("../..")
	cfg := demoConfig()
	cfg.FakeScript = l1Script
	cl, err := fakeClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a := &l1activities.Activities{LLM: cl, Tenant: cfg.Tenant}
	good, err := clientOptions(cfg, testSealer(t))
	if err != nil {
		t.Fatal(err)
	}
	bad := good
	bad.DataConverter = nil
	for name, o := range map[string]client.Options{"no_data_converter": bad, "zero": {}} {
		r := &registry{}
		if err := registerL1(r, o, a); !errors.Is(err, ErrConverterRequired) || r.n != 0 {
			t.Errorf("%s: registerL1 = %v with %d registrations", name, err, r.n)
		}
	}
	r := &registry{}
	if err := registerL1(r, good, a); err != nil || r.n == 0 {
		t.Errorf("registerL1(clientOptions) = %v with %d registrations", err, r.n)
	}
}

// TestL1Document (C3 end to end, without Temporal): a converged output gets
// the graph of internal/design; an escalation gets none.
func TestL1Document(t *testing.T) {
	raw, err := os.ReadFile("../../internal/intent/testdata/reference-ir.json")
	if err != nil {
		t.Fatal(err)
	}
	var ir intentdomain.IR
	if err := json.Unmarshal(raw, &ir); err != nil {
		t.Fatal(err)
	}
	ir.TenantID = demoTenant
	doc, err := l1Document("l1-intent-x", l1.Output{Status: l1.StatusConverged, IR: &ir, Contradictions: []intentdomain.Contradiction{}})
	if err != nil {
		t.Fatalf("l1Document: %v", err)
	}
	if doc.Graph == nil || len(doc.Graph.Nodes) == 0 || doc.WorkflowID != "l1-intent-x" || doc.IR.TenantID != demoTenant {
		t.Errorf("document %+v, want the graph of the IR", doc)
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil || m["status"] != "converged" || m["graph"] == nil || m["ir"] == nil {
		t.Errorf("document JSON %s", b)
	}
	esc, err := l1Document("l1-intent-y", l1.Output{Status: l1.StatusEscalated, Reason: l1.ReasonLanguageUnsupported, Contradictions: []intentdomain.Contradiction{}})
	if err != nil || esc.Graph != nil || esc.IR != nil {
		t.Errorf("escalation document %+v, %v; want no IR and no graph", esc, err)
	}
	if _, err := tenancy.ParseID(demoTenant); err != nil {
		t.Fatal(err)
	}
}
