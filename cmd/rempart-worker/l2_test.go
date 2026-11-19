package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/testsuite"

	"github.com/amezianechayer/rempart/internal/loops/l2"
	l2activities "github.com/amezianechayer/rempart/internal/loops/l2/activities"
	"github.com/amezianechayer/rempart/internal/policy/adapters/opa"
)

const l2Input = "internal/loops/l2/testdata/demo-input.json"

func l2Args(extra ...string) []string {
	return append(withFlag("demo-once", "-l2-once", "-l2-input="+l2Input), extra...)
}

// TestL2Config proves ADR 0012 D6: -l2-once excludes -demo-once and -l1-once,
// requires -l2-input, a relative .json path under the working directory, and
// -l2-input requires -l2-once.
func TestL2Config(t *testing.T) {
	cfg, err := LoadConfig(l2Args())
	if err != nil || !cfg.L2Once || cfg.L2Input != l2Input || cfg.DemoOnce || cfg.L1Once {
		t.Fatalf("LoadConfig(l2) = %+v, %v", cfg, err)
	}
	refused(t, withFlag("demo-once", "-l2-once"), ErrConfig)
	refused(t, append(demoArgs(), "-l2-input="+l2Input), ErrConfig)
	refused(t, append(demoArgs(), "-l2-once", "-l2-input="+l2Input), ErrConfig)
	refused(t, l2Args("-l1-once", "-l1-request=internal/intent/testdata/reference-request.txt"), ErrConfig)
	for _, p := range []string{"demo-input.txt", "../escape.json", "/etc/input.json", ""} {
		refused(t, withFlag("demo-once", "-l2-once", "-l2-input="+p), ErrConfig)
	}
	refused(t, l2Args("-l2-input="+l2Input), ErrConfig)
}

// TestWorkerRequiresRempartConverterL2 proves §4.1 of the threat model and
// ADR 0012 D6: registerL2 refuses options without the converters of Rempart,
// or activities without a compiled pack, and registers nothing.
func TestWorkerRequiresRempartConverterL2(t *testing.T) {
	e, err := opa.NewDesign()
	if err != nil {
		t.Fatal(err)
	}
	cfg := demoConfig()
	a := &l2activities.Activities{Tenant: cfg.Tenant, Policy: e}
	good, err := clientOptions(cfg, testSealer(t))
	if err != nil {
		t.Fatal(err)
	}
	bad := good
	bad.DataConverter = nil
	for name, o := range map[string]client.Options{"no_data_converter": bad, "zero": {}} {
		r := &registry{}
		if err := registerL2(r, o, a); !errors.Is(err, ErrConverterRequired) || r.n != 0 {
			t.Errorf("%s: registerL2 = %v with %d registrations", name, err, r.n)
		}
	}
	r := &registry{}
	if err := registerL2(r, good, &l2activities.Activities{Tenant: cfg.Tenant}); err == nil || r.n != 0 {
		t.Errorf("registerL2 without pack = %v with %d registrations", err, r.n)
	}
	r = &registry{}
	if err := registerL2(r, good, a); err != nil || r.n == 0 {
		t.Errorf("registerL2(clientOptions) = %v with %d registrations", err, r.n)
	}
}

// TestReadL2Input proves ADR 0012 D6 and obligation (cr): -l2-input reads a
// regular file under the working directory, 256 KiB at most, strictly (one
// value, no unknown key), with a fixed error.
func TestReadL2Input(t *testing.T) {
	t.Chdir("../..")
	in, err := readL2Input(l2Input)
	if err != nil || in.IR == nil || in.Graph != nil || in.Confirmation.Subject != "ir" || len(in.Confirmation.Exposures) != 1 {
		t.Fatalf("readL2Input(demo) = %+v, %v", in, err)
	}
	raw, err := os.ReadFile(l2Input)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	t.Chdir(dir)
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil { //nolint:gosec // G703: under t.TempDir, constant name
			t.Fatal(err)
		}
	}
	const marker = "x-canary-l2"
	if !strings.Contains(string(raw), `"ir":`) {
		t.Fatal("fixture without an ir key")
	}
	write("unknown.json", strings.Replace(string(raw), `"ir":`, `"`+marker+`": 1, "ir":`, 1))
	write("trailing.json", string(raw)+"{}")
	write("large.json", string(raw)+strings.Repeat(" ", 256<<10))
	for _, name := range []string{"unknown.json", "trailing.json", "large.json", "missing.json"} {
		if _, err := readL2Input(name); !errors.Is(err, ErrL2Input) || strings.Contains(err.Error(), marker) {
			t.Errorf("readL2Input(%s) = %v, want ErrL2Input without the content", name, err)
		}
	}
}

// TestL2DemoInputConverges proves criterion 5 of the fiche without the dev
// stack: the input of make l2-demo, run for the demo tenant, converges
// unchanged with its threat model, and the document written on stdout
// satisfies the jq filter of the criterion.
func TestL2DemoInputConverges(t *testing.T) {
	t.Chdir("../..")
	in, err := readL2Input(l2Input)
	if err != nil {
		t.Fatal(err)
	}
	e, err := opa.NewDesign()
	if err != nil {
		t.Fatal(err)
	}
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	if err := l2.Register(env, &l2activities.Activities{Tenant: demoConfig().Tenant, Policy: e}); err != nil {
		t.Fatal(err)
	}
	env.ExecuteWorkflow(l2.WorkflowName, in)
	if err := env.GetWorkflowError(); err != nil {
		t.Fatal(err)
	}
	var out l2.Output
	if err := env.GetWorkflowResult(&out); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(l2Document("l2-design-test", out))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		WorkflowID string `json:"workflow_id"`
		Status     string `json:"status"`
		Subject    string `json:"subject"`
		Applied    []any  `json:"applied"`
		Threats    struct {
			Threats []any `json:"threats"`
		} `json:"threats"`
		ThreatDelta struct{ From, To string } `json:"threat_delta"`
		Loop        map[string]any            `json:"loop"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.WorkflowID == "" || doc.Status != "converged" || doc.Subject != "ir" || doc.Applied == nil || len(doc.Applied) != 0 ||
		len(doc.Threats.Threats) == 0 || doc.ThreatDelta.From == "" || doc.ThreatDelta.From != doc.ThreatDelta.To {
		t.Fatalf("document of make l2-demo: %s", raw)
	}
	if _, ok := doc.Loop["best"]; ok {
		t.Errorf("document carries a best")
	}
}
