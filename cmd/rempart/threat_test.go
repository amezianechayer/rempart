package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/amezianechayer/rempart/internal/threat"
)

var (
	graphA = filepath.Join("..", "..", "internal", "threat", "testdata", "reference.graph.json")
	graphB = filepath.Join("..", "..", "internal", "threat", "testdata", "reference-ssh.graph.json")
)

// TestThreatDiffCommand proves the subcommands threat model and threat diff
// of the fiche M2-T04 (C4): findings of the embedded pack, a model and a
// delta that decode strictly, the same bytes from one run to the next, fixed
// messages and the exit codes 0, 1, 2.
func TestThreatDiffCommand(t *testing.T) {
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)

	model := runCLI("threat", "model", graphA)
	if model.code != 0 {
		t.Fatalf("threat model: code %d, stderr %q", model.code, model.stderr)
	}
	m, err := threat.DecodeModel([]byte(model.stdout))
	if err != nil {
		t.Fatalf("threat model output: %v", err)
	}
	if !hex64.MatchString(m.GraphRevision) || !hex64.MatchString(m.PackDigest) || m.Catalog != "stride-v1" || len(m.Threats) == 0 {
		t.Fatalf("model header %s %s %s, %d threats", m.GraphRevision, m.PackDigest, m.Catalog, len(m.Threats))
	}

	diff := runCLI("threat", "diff", graphA, graphB)
	if diff.code != 0 {
		t.Fatalf("threat diff: code %d, stderr %q", diff.code, diff.stderr)
	}
	d, err := threat.DecodeDelta([]byte(diff.stdout))
	if err != nil {
		t.Fatalf("threat diff output: %v", err)
	}
	if d.SchemaVersion != "1" || d.Catalog != "stride-v1" || d.From == d.To || len(d.Added) == 0 || d.PackDigest != m.PackDigest {
		t.Fatalf("delta %+v", d)
	}
	opened := false
	for _, c := range d.Changed {
		if c.To.Target == "wl:legacy-vms" && c.To.Status == "open" {
			opened = true
		}
	}
	if !opened {
		t.Errorf("the SSH exposure opened no threat of wl:legacy-vms (findings of the pack not applied)")
	}
	if again := runCLI("threat", "diff", graphA, graphB); again.stdout != diff.stdout {
		t.Errorf("two runs differ")
	}

	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil { //nolint:gosec // G703: p is under t.TempDir, name is a constant of the test.
			t.Fatal(err)
		}
		return p
	}
	raw, err := os.ReadFile(graphA) //nolint:gosec // G304: fixed path of the testdata.
	if err != nil {
		t.Fatal(err)
	}
	const marker = "x-canary-7f3a"
	otherTenant := write("other.json", strings.Replace(string(raw), "3f6c2a9e-8b1d-4c7a-9e2f-5d4b3a2c1e0f", "4f6c2a9e-8b1d-4c7a-9e2f-5d4b3a2c1e0f", 1))
	unknownKey := write("unknown.json", strings.Replace(string(raw), `"version"`, `"`+marker+`":1,"version"`, 1))
	invalid := write("invalid.json", strings.Replace(string(raw), `"Compute"`, `"Mainframe"`, 1))
	for name, args := range map[string][]string{
		"cross_tenant":  {"threat", "diff", graphA, otherTenant},
		"unknown_key":   {"threat", "model", unknownKey},
		"invalid_graph": {"threat", "model", invalid},
		"missing_file":  {"threat", "model", filepath.Join(dir, "missing-"+marker+".json")},
	} {
		t.Run(name, func(t *testing.T) {
			r := runCLI(args...)
			if r.code != 1 || r.stdout != "" || !strings.HasPrefix(r.stderr, "rempart threat: ") || strings.Contains(r.stderr, marker) {
				t.Fatalf("code %d, stdout %q, stderr %q; want 1, empty, a fixed message", r.code, r.stdout, r.stderr)
			}
		})
	}
	for name, args := range map[string][]string{
		"no_subcommand": {"threat"},
		"model_no_file": {"threat", "model"},
		"diff_one_file": {"threat", "diff", graphA},
		"unknown":       {"threat", "frobnicate", graphA},
		"model_two":     {"threat", "model", graphA, graphB},
	} {
		t.Run(name, func(t *testing.T) {
			if r := runCLI(args...); r.code != 2 || r.stdout != "" {
				t.Fatalf("code %d, stdout %q; want 2 (usage)", r.code, r.stdout)
			}
		})
	}
}
