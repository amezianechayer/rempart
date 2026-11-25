package opa

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	opaast "github.com/open-policy-agent/opa/v1/ast"

	"github.com/amezianechayer/rempart/internal/design"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	"github.com/amezianechayer/rempart/internal/graph/reach"
	"github.com/amezianechayer/rempart/internal/intent"
	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
	"github.com/amezianechayer/rempart/internal/policy"
	policydomain "github.com/amezianechayer/rempart/internal/policy/domain"
)

var update = flag.Bool("update", false, "rewrite capabilities.json from the construction of the engine")

// repo is the repository root seen from this package.
const repo = "../../../../"

var _ policy.Evaluator = (*Engine)(nil)

// referenceFacts is the graph of the reference IR, optionally edited, with
// its reachability recomputed.
func referenceInput(t testing.TB, edit func(f *graphdomain.FactsGraph)) policy.DesignInput {
	t.Helper()
	raw, err := os.ReadFile(repo + "internal/intent/testdata/reference-ir.json")
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
	f := graphdomain.FactsOf(g)
	if edit != nil {
		edit(&f)
	}
	m, err := reach.FromGraph(f)
	if err != nil {
		t.Fatal(err)
	}
	r, err := reach.Compute(m, reach.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	in, err := policy.NewDesignInput(f, r, policy.DesignContext{Environment: "staging"})
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func meta(id, sev, rem string) string {
	return "# METADATA\n# title: Contrôle de test\n# custom:\n#   control_id: " + id +
		"\n#   severity: " + sev + "\n#   remediation: " + rem + "\n#   frameworks: {}\n"
}

func module(pkg, header, body string) string {
	return "package rempart.design." + pkg + "\n\n" + header + "deny contains f if {\n" + body + "\n}\n"
}

// computeBody yields one output per Compute node (one in the reference graph).
const computeBody = "\tsome n in input.graph.nodes\n\tn.kind == \"Compute\"\n\tmeta := rego.metadata.rule()\n" +
	"\tf := {\"control_id\": meta.custom.control_id, \"resource\": n.id}"

// outBody yields one output per Compute node, the output being fields.
func outBody(fields string) string {
	return "\tsome n in input.graph.nodes\n\tn.kind == \"Compute\"\n\tmeta := rego.metadata.rule()\n\tmeta.custom.control_id != \"\"\n\tf := " + fields
}

func pack(files map[string]string) fstest.MapFS {
	fsys := fstest.MapFS{}
	for name, src := range files {
		fsys["design/"+name] = &fstest.MapFile{Data: []byte(src)}
	}
	return fsys
}

func validPack() fstest.MapFS {
	return pack(map[string]string{"t.rego": module("t", meta("TST-001", "high", "escalate"), computeBody)})
}

// forbiddenFamily reports whether a builtin belongs to a family refused by
// ADR 0011 D3 (input-output, network, environment, clock, randomness, print,
// decoding, cryptography, patterns, graph walks).
func forbiddenFamily(name string) bool {
	re := regexp.MustCompile(`^(http|net|opa|time|rand|uuid|io|crypto|regex|glob|graph|json|yaml|base64|base64url|hex|urlquery|units|strings|semver)[.]`)
	return re.MatchString(name) || slices.Contains([]string{"print", "internal.print", "trace", "walk", "sprintf", "format_int"}, name)
}

// TestEngineCapabilitiesDenyIO proves ADR 0011 D3 (T8, T109): the
// capabilities are the closed list of pure builtins, written to
// capabilities.json for opa check; a rule calling a builtin outside it
// (input-output, environment, clock, randomness, print, decoding, patterns)
// is refused when the pack is compiled.
func TestEngineCapabilitiesDenyIO(t *testing.T) {
	want := []string{
		"abs", "and", "array.concat", "array.slice", "assign", "concat", "contains", "count", "div", "endswith",
		"eq", "equal", "gt", "gte", "internal.member_2", "internal.member_3", "intersection", "is_array",
		"is_boolean", "is_null", "is_number", "is_object", "is_set", "is_string", "lt", "lte", "max", "min",
		"minus", "mul", "neq", "object.get", "object.keys", "object.union", "or", "plus", "rego.metadata.rule",
		"rem", "sort", "startswith", "sum", "type_name", "union",
	}
	caps := capabilities()
	var names []string
	for _, b := range caps.Builtins {
		names = append(names, b.Name)
		if forbiddenFamily(b.Name) {
			t.Errorf("builtin %s of a refused family", b.Name)
		}
		if d, ok := opaast.BuiltinMap[b.Name]; !ok || d.Nondeterministic {
			t.Errorf("builtin %s unknown or nondeterministic", b.Name)
		}
	}
	sort.Strings(names)
	if !slices.Equal(names, want) {
		t.Errorf("capabilities %q, want exactly the reviewed list %q", names, want)
	}
	if caps.AllowNet == nil || len(caps.AllowNet) != 0 {
		t.Errorf("allow_net = %v, want [] (no host)", caps.AllowNet)
	}

	raw, err := capabilitiesJSON()
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.WriteFile("capabilities.json", raw, 0o644); err != nil { //nolint:gosec // generated file read by opa check
			t.Fatal(err)
		}
	}
	file, err := os.ReadFile("capabilities.json")
	if err != nil || !bytes.Equal(file, raw) {
		t.Fatalf("capabilities.json differs from the construction of the engine (go test -run TestEngineCapabilitiesDenyIO -update): %v", err)
	}

	if _, err := newEngine(validPack(), DefaultOptions); err != nil {
		t.Fatalf("control: valid pack refused: %v", err)
	}
	calls := map[string]string{
		"http_send":   `r := http.send({"method": "get", "url": "https://example.invalid"}); r.status_code == 200`,
		"opa_runtime": `r := opa.runtime(); r.env.HOME != ""`,
		"time_now":    `time.now_ns() > 0`,
		"rand":        `rand.intn("k", 10) > 0`,
		"uuid":        `uuid.rfc4122("k") != ""`,
		"net_lookup":  `count(net.lookup_ip_addr("example.invalid")) > 0`,
		"net_cidr":    `net.cidr_contains("10.0.0.0/8", "10.0.0.1")`,
		"regex":       `regex.match("a", n.id)`,
		"jwt":         `[_, _, _] := io.jwt.decode(n.id)`,
		"json":        `json.unmarshal(n.id) != null`,
		"print":       `print(n.id)`,
		"trace":       `trace(n.id)`,
		"walk":        `walk(input, [_, _])`,
		"sprintf":     `sprintf("%s", [n.id]) != ""`,
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			body := "\tsome n in input.graph.nodes\n\t" + call + "\n\tmeta := rego.metadata.rule()\n" +
				"\tf := {\"control_id\": meta.custom.control_id, \"resource\": n.id}"
			e, err := newEngine(pack(map[string]string{"t.rego": module("t", meta("TST-001", "high", "escalate"), body)}), DefaultOptions)
			if !errors.Is(err, ErrPackInvalid) || e != nil {
				t.Fatalf("newEngine = %v, %v; want ErrPackInvalid", e, err)
			}
		})
	}
}

// TestEngineFailsClosed proves ADR 0011 D3 and D4 (T108, T119, T24): an
// incomplete or inconsistent pack is refused at compilation; an evaluation
// error, a time-out, an input too large, an output outside the closed form or
// too many outputs give an error, never an empty or truncated list.
func TestEngineFailsClosed(t *testing.T) {
	compileCases := map[string]map[string]string{
		"no_metadata":          {"t.rego": module("t", "", computeBody)},
		"custom_key_typo":      {"t.rego": module("t", strings.Replace(meta("TST-001", "high", "escalate"), "remediation:", "remediation_hint:", 1), computeBody)},
		"custom_key_extra":     {"t.rego": module("t", strings.Replace(meta("TST-001", "high", "escalate"), "#   frameworks: {}\n", "#   frameworks: {}\n#   skip: true\n", 1), computeBody)},
		"severity_unknown":     {"t.rego": module("t", meta("TST-001", "urgent", "escalate"), computeBody)},
		"control_id_pattern":   {"t.rego": module("t", meta("tst-1", "high", "escalate"), computeBody)},
		"control_id_twice":     {"a.rego": module("a", meta("TST-001", "high", "escalate"), computeBody), "b.rego": module("b", meta("TST-001", "high", "escalate"), computeBody)},
		"remediation_unknown":  {"t.rego": module("t", meta("TST-001", "high", "ignore"), computeBody)},
		"advisory_high":        {"t.rego": module("t", meta("TST-001", "high", "advisory"), computeBody)},
		"frameworks_not_empty": {"t.rego": module("t", strings.Replace(meta("TST-001", "high", "escalate"), "frameworks: {}", "frameworks: {nis2: [\"21\"]}", 1), computeBody)},
		"title_missing":        {"t.rego": module("t", strings.Replace(meta("TST-001", "high", "escalate"), "# title: Contrôle de test\n", "", 1), computeBody)},
		"package_outside":      {"t.rego": strings.Replace(module("t", meta("TST-001", "high", "escalate"), computeBody), "package rempart.design.t", "package other.t", 1)},
		"package_nested":       {"t.rego": strings.Replace(module("t", meta("TST-001", "high", "escalate"), computeBody), "package rempart.design.t", "package rempart.design.t.sub", 1)},
		"no_metadata_call":     {"t.rego": module("t", meta("TST-001", "high", "escalate"), "\tsome n in input.graph.nodes\n\tn.kind == \"Compute\"\n\tf := {\"control_id\": \"TST-001\", \"resource\": n.id}")},
		"control_on_other_rule": {"t.rego": module("t", meta("TST-001", "high", "escalate"), computeBody) +
			"\n" + meta("TST-002", "high", "escalate") + "allow if { count(input.graph.nodes) > 0 }\n"},
		"schema_typo": {"t.rego": module("t", meta("TST-001", "high", "escalate"),
			"\tsome n in input.graph.nodes\n\tnot n.attrs.encrpted == true\n\tmeta := rego.metadata.rule()\n\tf := {\"control_id\": meta.custom.control_id, \"resource\": n.id}")},
		"data_file":  {"t.rego": module("t", meta("TST-001", "high", "escalate"), computeBody)},
		"empty_pack": {},
		// Obligation (fe) (T108, T120): a rule can only emit its own control_id.
		"control_literal":     {"t.rego": module("t", meta("TST-001", "high", "escalate"), outBody(`{"control_id": "TST-001", "resource": n.id}`))},
		"control_substituted": {"a.rego": module("a", meta("TST-001", "critical", "escalate"), computeBody), "b.rego": module("b", meta("TST-002", "low", "advisory"), outBody(`{"control_id": "TST-001", "resource": n.id}`))},
		"control_in_helper":   {"t.rego": module("t", meta("TST-001", "high", "escalate"), computeBody) + "\nother_id := \"TST-002\"\n"},
		"control_from_var":    {"t.rego": module("t", meta("TST-001", "high", "escalate"), outBody(`{"control_id": id, "resource": n.id}`)+"\n\tid := meta.custom.control_id")},
		"control_other_field": {"t.rego": module("t", meta("TST-001", "high", "escalate"), outBody(`{"control_id": meta.title, "resource": n.id}`))},
		"control_other_meta":  {"t.rego": module("t", meta("TST-001", "high", "escalate"), outBody(`{"control_id": other.custom.control_id, "resource": n.id}`)+"\n\tother := {\"custom\": {\"control_id\": meta.custom.control_id}}")},
		"output_extra_key":    {"t.rego": module("t", meta("TST-001", "high", "escalate"), outBody(`{"control_id": meta.custom.control_id, "resource": n.id, "severity": "low"}`))},
		"output_no_resource":  {"t.rego": module("t", meta("TST-001", "high", "escalate"), outBody(`{"control_id": meta.custom.control_id}`))},
		"output_not_object":   {"t.rego": module("t", meta("TST-001", "high", "escalate"), outBody(`n.id`))},
		"output_computed":     {"t.rego": module("t", meta("TST-001", "high", "escalate"), outBody(`object.union({"control_id": meta.custom.control_id}, {"resource": n.id})`))},
		"output_twice":        {"t.rego": module("t", meta("TST-001", "high", "escalate"), outBody(`{"control_id": meta.custom.control_id, "resource": n.id}`)+"\n\tf = {\"control_id\": \"TST-001\", \"resource\": n.id}")},
		"deny_ref_head": {"t.rego": "package rempart.design.t\n\ndeny[k] := v if {\n\tsome n in input.graph.nodes\n\tk := n.id\n\t" +
			"v := {\"control_id\": \"TST-001\", \"resource\": n.id}\n}\n" + meta("TST-002", "high", "escalate") + "deny contains f if {\n" + computeBody + "\n}\n"},
		"deny_ref_head_meta": {"t.rego": "package rempart.design.t\n\n" + meta("TST-001", "high", "escalate") + "deny[k] := v if {\n\tsome n in input.graph.nodes\n\tk := n.id\n\t" +
			"meta := rego.metadata.rule()\n\tv := {\"control_id\": meta.custom.control_id, \"resource\": n.id}\n}\n"},
		// Obligation (fr): a deny rule without key (complete rule, default,
		// whole set) is refused, never a panic.
		"deny_complete":  {"t.rego": "package rempart.design.t\n\n" + meta("TST-001", "high", "escalate") + "deny if {\n\tsome n in input.graph.nodes\n\tn.kind == \"Compute\"\n\tmeta := rego.metadata.rule()\n}\n"},
		"deny_default":   {"t.rego": "package rempart.design.t\n\ndefault deny := set()\n"},
		"deny_whole_set": {"t.rego": "package rempart.design.t\n\n" + meta("TST-001", "high", "escalate") + "deny := {\"x\"} if {\n\tmeta := rego.metadata.rule()\n\tmeta.custom.control_id\n}\n"},
		"deny_contains_term": {"t.rego": "package rempart.design.t\n\n" + meta("TST-001", "high", "escalate") + "deny contains {\"control_id\": meta.custom.control_id, \"resource\": n.id} if {\n" +
			"\tsome n in input.graph.nodes\n\tmeta := rego.metadata.rule()\n}\n"},
	}
	for name, files := range compileCases {
		t.Run("compile_"+name, func(t *testing.T) {
			fsys := pack(files)
			if name == "data_file" {
				fsys["design/data.json"] = &fstest.MapFile{Data: []byte(`{"skip": true}`)}
			}
			e, err := newEngine(fsys, DefaultOptions)
			if !errors.Is(err, ErrPackInvalid) || e != nil {
				t.Fatalf("newEngine = %v, %v; want ErrPackInvalid", e, err)
			}
		})
	}
	t.Run("compile_escalate_medium_refused", func(t *testing.T) {
		// ADR 0011 D4: advisory if and only if the severity is medium or low.
		e, err := newEngine(pack(map[string]string{"t.rego": module("t", meta("TST-001", "medium", "escalate"), computeBody)}), DefaultOptions)
		if !errors.Is(err, ErrPackInvalid) || e != nil {
			t.Fatalf("newEngine = %v, %v; want ErrPackInvalid", e, err)
		}
	})

	in := referenceInput(t, nil)
	evalCases := []struct {
		name string
		body string
		opts Options
		want error
	}{
		{"unknown_resource", outBody(`{"control_id": meta.custom.control_id, "resource": "wl:ghost"}`), DefaultOptions, ErrPolicyOutput},
		{"resource_not_string", outBody(`{"control_id": meta.custom.control_id, "resource": 3}`), DefaultOptions, ErrPolicyOutput},
		{"builtin_error", "\tsome n in input.graph.nodes\n\tx := count(input.graph.nodes) / 0\n\tx > 0\n\tmeta := rego.metadata.rule()\n\tf := {\"control_id\": meta.custom.control_id, \"resource\": n.id}", DefaultOptions, ErrEvaluation},
		{"timeout", computeBody, Options{Timeout: time.Nanosecond, MaxInputBytes: DefaultOptions.MaxInputBytes, MaxFindings: DefaultOptions.MaxFindings}, ErrEvaluation},
		{"input_too_large", computeBody, Options{Timeout: DefaultOptions.Timeout, MaxInputBytes: 64, MaxFindings: DefaultOptions.MaxFindings}, ErrInputTooLarge},
		{
			"too_many_findings", "\tsome n in input.graph.nodes\n\tmeta := rego.metadata.rule()\n\tf := {\"control_id\": meta.custom.control_id, \"resource\": n.id}",
			Options{Timeout: DefaultOptions.Timeout, MaxInputBytes: DefaultOptions.MaxInputBytes, MaxFindings: 1},
			ErrPolicyOutput,
		},
	}
	for _, c := range evalCases {
		t.Run("eval_"+c.name, func(t *testing.T) {
			e, err := newEngine(pack(map[string]string{"t.rego": module("t", meta("TST-001", "high", "escalate"), c.body)}), c.opts)
			if err != nil {
				t.Fatalf("newEngine: %v", err)
			}
			got, err := e.Evaluate(context.Background(), in)
			if !errors.Is(err, c.want) || got != nil {
				t.Fatalf("Evaluate = %v, %v; want nil, %v", got, err, c.want)
			}
		})
	}

	t.Run("options_refused", func(t *testing.T) {
		for _, o := range []Options{{}, {Timeout: time.Second, MaxInputBytes: 1}, {Timeout: -1, MaxInputBytes: 1, MaxFindings: 1}} {
			if _, err := newEngine(validPack(), o); !errors.Is(err, ErrPackInvalid) {
				t.Errorf("newEngine(%+v) = %v, want ErrPackInvalid", o, err)
			}
		}
	})

	t.Run("control_translated", func(t *testing.T) {
		e, err := newEngine(validPack(), DefaultOptions)
		if err != nil {
			t.Fatal(err)
		}
		got, err := e.Evaluate(context.Background(), in)
		want := []loopsdomain.Finding{{Code: "TST-001", Source: "policy:design", Severity: loopsdomain.SeverityHigh, Resource: "wl:legacy-vms", Message: "Contrôle de test"}}
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("Evaluate = %+v, %v; want %+v", got, err, want)
		}
	})
}

// TestEvaluateRevalidatesInput proves obligation (ff) (T3, T119): Evaluate
// refuses, before any evaluation, an input that NewDesignInput would not have
// produced from its graph and its reachability (zero value, null list,
// environment absent or below that of the networks, jurisdiction or world
// sources forged, reachability naming a node outside the graph), and accepts
// the same input permuted.
func TestEvaluateRevalidatesInput(t *testing.T) {
	e, err := NewDesign()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(in *policy.DesignInput){
		"zero_value":          func(in *policy.DesignInput) { *in = policy.DesignInput{} },
		"environment_empty":   func(in *policy.DesignInput) { in.Derived.Environment = "" },
		"environment_lowered": func(in *policy.DesignInput) { in.Derived.Environment = "dev" },
		"null_list":           func(in *policy.DesignInput) { in.Derived.UnconfirmedExposures = nil },
		"null_nodes":          func(in *policy.DesignInput) { in.Graph.Nodes = nil },
		"jurisdiction_forged": func(in *policy.DesignInput) {
			j := map[string]policydomain.Zone{}
			for k := range in.Derived.Jurisdiction {
				j[k] = policydomain.ZoneFR
			}
			j["wl:legacy-vms"] = policydomain.ZoneEU
			in.Derived.Jurisdiction = j
		},
		"world_sources_forged": func(in *policy.DesignInput) { in.Derived.WorldSources = []string{} },
		"reach_other_graph": func(in *policy.DesignInput) {
			in.Reach.Hops = append(slices.Clone(in.Reach.Hops), reach.Hop{Src: "internet", Dst: "wl:ghost", Proto: "tcp", Ports: []reach.PortRange{{From: 22, To: 22}}, World: true})
		},
		"path_other_graph": func(in *policy.DesignInput) {
			in.Reach.FromInternet = append(slices.Clone(in.Reach.FromInternet), reach.Path{Target: "wl:ghost", Nodes: []string{"internet", "wl:ghost"}})
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			in := referenceInput(t, nil)
			if len(in.Derived.WorldSources) == 0 {
				t.Fatalf("control: the reference exposure is open to the world, world_sources %v", in.Derived.WorldSources)
			}
			edit(&in)
			got, err := e.Evaluate(context.Background(), in)
			if !errors.Is(err, policy.ErrDesignInput) || got != nil {
				t.Fatalf("Evaluate = %v, %v; want nil, ErrDesignInput", got, err)
			}
		})
	}
	t.Run("permuted_accepted", func(t *testing.T) {
		in := referenceInput(t, nil)
		in.Graph.Nodes = slices.Clone(in.Graph.Nodes)
		slices.Reverse(in.Graph.Nodes)
		if got, err := e.Evaluate(context.Background(), in); err != nil || len(got) != 0 {
			t.Fatalf("Evaluate(permuted reference) = %v, %v; want no finding", got, err)
		}
	})
}

// netstringDigest recomputes the digest of ADR 0011 D4 independently.
func netstringDigest(t *testing.T, root string) string {
	t.Helper()
	var paths []string
	err := fs.WalkDir(os.DirFS(root), "design", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".rego") && !strings.HasSuffix(p, "_test.rego") {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, p := range paths {
		raw, err := os.ReadFile(root + "/" + p) //nolint:gosec // G304: a file of the pack listed by WalkDir under the repository
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fmt.Fprintf(h, "%d:%s,%d:%s,", len(p), p, len(raw), raw)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// TestEngineDeterministic proves ADR 0011 D1 and D4 (T3, T113): the embedded
// pack gives the same findings for the same facts whatever their order, an
// evaluation sees nothing of the previous one, concurrent evaluations agree,
// and the digest is the netstring SHA-256 of the compiled files.
func TestEngineDeterministic(t *testing.T) {
	e, err := NewDesign()
	if err != nil {
		t.Fatalf("NewDesign: %v", err)
	}
	ctx := context.Background()
	clean := referenceInput(t, nil)
	dirty := referenceInput(t, func(f *graphdomain.FactsGraph) {
		for i := range f.Nodes {
			if f.Nodes[i].ID == "data:customer-db" {
				v := true
				f.Nodes[i].Attrs.PublicAccess = &v
			}
		}
	})
	got, err := e.Evaluate(ctx, clean)
	if err != nil || len(got) != 0 || got == nil {
		t.Fatalf("reference scenario: %+v, %v; want an empty, non-nil list", got, err)
	}
	first, err := e.Evaluate(ctx, dirty)
	if err != nil {
		t.Fatal(err)
	}
	codes := map[string]bool{}
	for _, f := range first {
		codes[f.Code+"@"+f.Resource] = true
		if f.Source != "policy:design" || f.File != "" || f.Line != 0 || f.Message == "" {
			t.Errorf("finding %+v outside the translation of D4", f)
		}
	}
	for _, w := range []string{"DATA-001@data:customer-db", "NET-001@data:customer-db"} {
		if !codes[w] {
			t.Errorf("public dataset: missing %s in %+v", w, first)
		}
	}
	if !slices.Equal(first, loopsdomain.Sort(first)) {
		t.Errorf("findings not in the order of loopsdomain.Sort")
	}

	permuted := dirty
	permuted.Graph.Nodes = slices.Clone(dirty.Graph.Nodes)
	permuted.Graph.Edges = slices.Clone(dirty.Graph.Edges)
	permuted.Reach.Hops = slices.Clone(dirty.Reach.Hops)
	slices.Reverse(permuted.Graph.Nodes)
	slices.Reverse(permuted.Graph.Edges)
	slices.Reverse(permuted.Reach.Hops)
	for _, c := range []struct {
		in   policy.DesignInput
		want []loopsdomain.Finding
	}{{permuted, first}, {clean, []loopsdomain.Finding{}}, {dirty, first}} {
		got, err := e.Evaluate(ctx, c.in)
		if err != nil || !slices.Equal(got, c.want) {
			t.Fatalf("Evaluate = %+v, %v; want %+v (no state, no order)", got, err, c.want)
		}
	}
	var wg sync.WaitGroup
	results := make([][]loopsdomain.Finding, 8)
	for i := range results {
		wg.Go(func() { results[i], _ = e.Evaluate(ctx, dirty) })
	}
	wg.Wait()
	for i, r := range results {
		if !slices.Equal(r, first) {
			t.Errorf("concurrent evaluation %d differs: %+v", i, r)
		}
	}

	if d := e.Digest(); !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(d) || d != netstringDigest(t, repo+"policies") {
		t.Errorf("Digest() = %q, want the netstring SHA-256 %q", d, netstringDigest(t, repo+"policies"))
	}
	again, err := NewDesign()
	if err != nil || again.Digest() != e.Digest() {
		t.Errorf("second NewDesign: %v, digest %q vs %q", err, again.Digest(), e.Digest())
	}
	a, err := newEngine(validPack(), DefaultOptions)
	if err != nil {
		t.Fatal(err)
	}
	changed := validPack()
	changed["design/t.rego"].Data = append(slices.Clone(changed["design/t.rego"].Data), '\n')
	b, err := newEngine(changed, DefaultOptions)
	if err != nil || a.Digest() == b.Digest() {
		t.Errorf("digest unchanged by a changed file: %v", err)
	}
	ids := make([]string, 0, len(e.Controls()))
	for _, c := range e.Controls() {
		ids = append(ids, c.ID)
	}
	if !slices.IsSorted(ids) || len(ids) == 0 {
		t.Errorf("Controls() not sorted by control_id: %q", ids)
	}
}
