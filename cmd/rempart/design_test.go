package main

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/amezianechayer/rempart/internal/graph"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
)

var (
	referenceIRPath = filepath.Join("..", "..", "internal", "intent", "testdata", "reference-ir.json")
	canariesIRPath  = filepath.Join("..", "..", "internal", "design", "testdata", "reference-canaries.json")
)

type result struct {
	code           int
	stdout, stderr string
}

func runCLI(args ...string) result {
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	return result{code: code, stdout: out.String(), stderr: errOut.String()}
}

func lineMatches(t *testing.T, text, pattern string) {
	t.Helper()
	if !regexp.MustCompile(`(?m)` + pattern).MatchString(text) {
		t.Errorf("no line matches %q in:\n%s", pattern, text)
	}
}

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteFile(name, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, name)
}

// sectionSevenNetworks is the --cidr-only line of plan section 7, as [name, cidr, parent].
var sectionSevenNetworks = [][3]any{
	{"aws-eu-west-3-staging", "10.0.0.0/20", nil},
	{"aws-eu-west-3-staging-app", "10.0.0.0/23", "aws-eu-west-3-staging"},
	{"aws-eu-west-3-staging-public", "10.0.2.0/26", "aws-eu-west-3-staging"},
	{"azure-francecentral-staging", "10.0.16.0/25", nil},
	{"azure-francecentral-staging-data", "10.0.16.0/27", "azure-francecentral-staging"},
}

// decodeCIDROnly checks the exact keys of the cidr_check.py input format and
// returns its networks as [name, cidr, parent] and its external ranges.
func decodeCIDROnly(t *testing.T, stdout string) ([][3]any, []map[string]any) {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("--cidr-only output is not JSON: %v\n%s", err, stdout)
	}
	if keys := slices.Sorted(maps.Keys(doc)); !slices.Equal(keys, []string{"external", "networks", "superblock"}) {
		t.Fatalf("top-level keys %v, want external, networks, superblock", keys)
	}
	nets, ok := doc["networks"].([]any)
	if !ok {
		t.Fatalf("networks is %T", doc["networks"])
	}
	ext, ok := doc["external"].([]any)
	if !ok {
		t.Fatalf("external is %T, want an array (cidr_check.py iterates it)", doc["external"])
	}
	var out [][3]any
	for _, n := range nets {
		m, _ := n.(map[string]any)
		for k := range m {
			if k != "name" && k != "cidr" && k != "parent" {
				t.Fatalf("network key %q outside the reference format", k)
			}
		}
		if p, present := m["parent"]; present && p == nil {
			t.Fatalf("network %v: parent present and null, want absent for a VPC", m["name"])
		}
		out = append(out, [3]any{m["name"], m["cidr"], m["parent"]})
	}
	var exts []map[string]any
	for _, e := range ext {
		m, _ := e.(map[string]any)
		exts = append(exts, m)
	}
	return out, exts
}

// TestDesignCommand proves the `rempart design` command of plan section 4:
// readable facts by default, --json and --cidr-only, --reserve honoured, fixed
// messages and stable exit codes (0 success, 1 refused, 2 usage).
func TestDesignCommand(t *testing.T) {
	t.Run("text", func(t *testing.T) {
		r := runCLI("design", referenceIRPath)
		if r.code != 0 {
			t.Fatalf("code %d, stderr %q", r.code, r.stderr)
		}
		for _, p := range []string{
			`^rempart design: deterministic plan, no LLM$`,
			`^tenant\s+3f6c2a9e-8b1d-4c7a-9e2f-5d4b3a2c1e0f$`,
			`^environment\s+staging$`,
			`^superblock\s+10\.0\.0\.0/8 \(growth x4\)$`,
			`^reserved\s+none\b`,
			`^aws-eu-west-3-staging\s+10\.0\.0\.0/20\s+vpc\s+-\s+-$`,
			`^aws-eu-west-3-staging-app\s+10\.0\.0\.0/23\s+app\s+96\s+507$`,
			`^aws-eu-west-3-staging-public\s+10\.0\.2\.0/26\s+public\s+8\s+59$`,
			`^azure-francecentral-staging\s+10\.0\.16\.0/25\s+vpc\s+-\s+-$`,
			`^azure-francecentral-staging-data\s+10\.0\.16\.0/27\s+data\s+3\s+27$`,
			`^legacy-vms\s+vm_group\s+azure-francecentral-staging-data$`,
			`^obs\s+observability_stack\s+runs on app-cluster$`,
			`^exposure\s+internet -> lb:app-cluster-443 https/443 -> app-cluster$`,
			`^flow\s+app-cluster -> legacy-vms tcp/5432 via vpn_site_to_site$`,
			`^data\s+customer-db confidential on legacy-vms \(tier data\)$`,
			`^graph\s+12 nodes, 13 edges$`,
			`^cidr check\s+0 findings$`,
		} {
			lineMatches(t, r.stdout, p)
		}
	})

	t.Run("text_without_untrusted_text", func(t *testing.T) {
		r := runCLI("design", canariesIRPath)
		if r.code != 0 {
			t.Fatalf("code %d, stderr %q", r.code, r.stderr)
		}
		for _, c := range []string{"CANARY-", "\x1b", "\a", "pwned", "ignore previous"} {
			if strings.Contains(r.stdout+r.stderr, c) {
				t.Errorf("readable output contains %q:\n%s", c, r.stdout)
			}
		}
	})

	t.Run("json", func(t *testing.T) {
		r := runCLI("design", "--json", referenceIRPath)
		if r.code != 0 {
			t.Fatalf("code %d, stderr %q", r.code, r.stderr)
		}
		var doc struct {
			Version      string            `json:"version"`
			Graph        graphdomain.Graph `json:"graph"`
			CIDRPlan     json.RawMessage   `json:"cidr_plan"`
			CIDRFindings []json.RawMessage `json:"cidr_findings"`
		}
		dec := json.NewDecoder(strings.NewReader(r.stdout))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&doc); err != nil {
			t.Fatalf("--json output: %v\n%s", err, r.stdout)
		}
		if doc.Version != "1" || doc.CIDRFindings == nil || len(doc.CIDRFindings) != 0 || len(doc.CIDRPlan) == 0 {
			t.Fatalf("version %q, cidr_findings %v, cidr_plan %s", doc.Version, doc.CIDRFindings, doc.CIDRPlan)
		}
		if err := graph.ValidateSchema(doc.Graph); err != nil {
			t.Fatalf("decoded graph: ValidateSchema: %v", err)
		}
		g := doc.Graph
		if len(g.Nodes) != 12 || len(g.Edges) != 13 || g.Source != "design" || g.TenantID != "3f6c2a9e-8b1d-4c7a-9e2f-5d4b3a2c1e0f" {
			t.Fatalf("graph: %d nodes, %d edges, source %q, tenant %q", len(g.Nodes), len(g.Edges), g.Source, g.TenantID)
		}
		if g.Edges[0].ID != "can_reach|lb:app-cluster-443|wl:app-cluster|https/443" {
			t.Fatalf("first edge %q", g.Edges[0].ID)
		}
		var plan struct {
			Superblock string `json:"superblock"`
			Growth     int    `json:"growth"`
			Networks   []struct {
				Name   string `json:"name"`
				CIDR   string `json:"cidr"`
				Usable int    `json:"usable"`
			} `json:"networks"`
		}
		if err := json.Unmarshal(doc.CIDRPlan, &plan); err != nil {
			t.Fatal(err)
		}
		if plan.Superblock != "10.0.0.0/8" || plan.Growth != 4 || len(plan.Networks) != 5 || plan.Networks[1].Usable != 507 {
			t.Fatalf("cidr_plan %s", doc.CIDRPlan)
		}
		if again := runCLI("design", "--json", referenceIRPath); again.stdout != r.stdout {
			t.Fatalf("two --json runs differ")
		}
	})

	t.Run("cidr_only", func(t *testing.T) {
		r := runCLI("design", "--cidr-only", referenceIRPath)
		if r.code != 0 {
			t.Fatalf("code %d, stderr %q", r.code, r.stderr)
		}
		nets, ext := decodeCIDROnly(t, r.stdout)
		if !reflect.DeepEqual(nets, sectionSevenNetworks) || len(ext) != 0 {
			t.Fatalf("networks %v external %v, want %v and none", nets, ext, sectionSevenNetworks)
		}
	})

	t.Run("reserve", func(t *testing.T) {
		r := runCLI("design", "--cidr-only", "--reserve", "10.0.0.0/9", referenceIRPath)
		if r.code != 0 {
			t.Fatalf("code %d, stderr %q", r.code, r.stderr)
		}
		nets, ext := decodeCIDROnly(t, r.stdout)
		if len(nets) == 0 || nets[0] != [3]any{"aws-eu-west-3-staging", "10.128.0.0/20", nil} {
			t.Fatalf("first network %v, want aws-eu-west-3-staging 10.128.0.0/20", nets)
		}
		if len(ext) != 1 || ext[0]["name"] != "reserved-1" || ext[0]["cidr"] != "10.0.0.0/9" {
			t.Fatalf("external %v, want reserved-1 10.0.0.0/9", ext)
		}
		text := runCLI("design", "--reserve", "10.0.0.0/9", "--reserve", "192.168.0.0/16", referenceIRPath)
		if text.code != 0 || regexp.MustCompile(`(?m)^reserved\s+none`).MatchString(text.stdout) {
			t.Fatalf("code %d, reserved ranges not reported:\n%s", text.code, text.stdout)
		}
		lineMatches(t, text.stdout, `^aws-eu-west-3-staging\s+10\.128\.0\.0/20\s+vpc\b`)
	})

	t.Run("refused", func(t *testing.T) {
		ref, err := fs.ReadFile(os.DirFS(filepath.Join("..", "..")), "internal/intent/testdata/reference-ir.json")
		if err != nil {
			t.Fatal(err)
		}
		const marker = "CANARY-INPUT-9c1e"
		dir := t.TempDir()
		cases := map[string]string{
			"system_tenant": writeFile(t, dir, "system.json", bytes.Replace(ref,
				[]byte("3f6c2a9e-8b1d-4c7a-9e2f-5d4b3a2c1e0f"), []byte("00000000-0000-8000-8000-000000000001"), 1)),
			"unknown_field": writeFile(t, dir, "unknown.json", bytes.Replace(ref,
				[]byte(`"version": "1",`), []byte(`"version": "1", "zz_`+marker+`": "`+marker+`",`), 1)),
			"duplicate_key": writeFile(t, dir, "duplicate.json", bytes.Replace(ref,
				[]byte(`"version": "1",`), []byte(`"version": "1", "summary": "`+marker+`",`), 1)),
		}
		var messages []string
		for name, path := range cases {
			r := runCLI("design", path)
			if r.code != 1 || r.stdout != "" {
				t.Errorf("%s: code %d stdout %q, want 1 and empty", name, r.code, r.stdout)
			}
			if !strings.HasPrefix(r.stderr, "rempart design:") || strings.Contains(r.stderr, marker) || strings.Contains(r.stderr, dir) {
				t.Errorf("%s: stderr %q, want a fixed rempart design: message without input", name, r.stderr)
			}
			messages = append(messages, r.stderr)
		}
		if len(slices.Compact(slices.Sorted(slices.Values(messages)))) != 1 {
			t.Errorf("messages are not fixed: %q", messages)
		}

		for name, args := range map[string][]string{
			"missing_file":   {"design", filepath.Join(dir, "absent.json")},
			"directory":      {"design", dir},
			"oversized_file": {"design", writeFile(t, dir, "big.json", append(slices.Clone(ref), bytes.Repeat([]byte(" "), 1<<20)...))},
			"growth_99":      {"design", "--growth", "99", referenceIRPath},
			"exhausted":      {"design", "--superblock", "10.0.0.0/24", referenceIRPath},
		} {
			if r := runCLI(args...); r.code != 1 || r.stdout != "" || !strings.HasPrefix(r.stderr, "rempart design:") {
				t.Errorf("%s: code %d stdout %q stderr %q, want 1", name, r.code, r.stdout, r.stderr)
			}
		}
	})

	t.Run("usage", func(t *testing.T) {
		for name, args := range map[string][]string{
			"no_command":        {},
			"no_file":           {"design"},
			"two_files":         {"design", referenceIRPath, referenceIRPath},
			"unknown_option":    {"design", "--frob", referenceIRPath},
			"json_and_cidronly": {"design", "--json", "--cidr-only", referenceIRPath},
			"unknown_command":   {"frobnicate"},
		} {
			if r := runCLI(args...); r.code != 2 || r.stdout != "" {
				t.Errorf("%s: code %d stdout %q, want 2 and empty", name, r.code, r.stdout)
			}
		}
	})
}
