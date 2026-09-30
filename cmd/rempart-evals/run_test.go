package main

// Tests of docs/plans/M0-evals-cli.md section 8.2. Fixtures: testdata/<scenario>/,
// each a fake repository root (go.mod and evals/), opened by os.OpenRoot.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/amezianechayer/rempart/internal/evals"
)

const (
	demoBaselinePath = "evals/demo/baseline/fake/fake-model-v1.json"
	runLine          = "evals : suite demo, cas 1, exécutions 1"
	// D11, fixed text.
	missingMessage = "evals : baseline absente pour la suite demo (evals/demo/baseline/fake/fake-model-v1.json) : " +
		"à créer par l'humain avec make update-baseline EVAL=demo, puis à commiter (étape H3)."
	aSHA = "abababababababababababababababababababab"
)

// demoReport is the report of the demo suite (section 7).
func demoReport() evals.Report {
	return evals.Report{
		Loop: "L0-demo", Platform: "fake", Model: "fake-model-v1", Cases: 1, Runs: 1, EscalationRuns: 1,
		SuccessRate: 1, CorrectEscalationRate: 1, InjectionResistance: 1, AvgIterations: 2, AvgTokens: 30,
		RegressionsVsBaseline: []evals.Regression{},
	}
}

// stubTarget answers every case at once: converged, 1 iteration, 10 tokens.
type stubTarget struct{ runs *int }

func (stubTarget) Identity() Identity     { return Identity{Platform: "fake", Model: "stub-v1"} }
func (stubTarget) Check(evals.Case) error { return nil }
func (s stubTarget) Run(context.Context, evals.Case, int) (evals.Outcome, error) {
	if s.runs != nil {
		*s.runs++
	}
	return evals.Outcome{Output: json.RawMessage(`{}`), Status: "converged", Iterations: 1, Tokens: 10}, nil
}

// counting wraps a target and counts its runs.
type counting struct {
	Target
	runs *int
}

func (c counting) Run(ctx context.Context, cs evals.Case, run int) (evals.Outcome, error) {
	*c.runs++
	return c.Target.Run(ctx, cs, run)
}

type gitCall struct {
	dir  string
	args []string
}

// fakeGit answers the three commands of D14 by their subcommand and records every call.
type fakeGit struct {
	mu        sync.Mutex
	calls     []gitCall
	mergeCode int
	mergeErr  error
	diff      []byte
	diffCode  int
	others    []byte
	lsCode    int
}

func (f *fakeGit) run(_ context.Context, dir string, args ...string) ([]byte, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, gitCall{dir, slices.Clone(args)})
	sub := ""
	if len(args) > 3 {
		sub = args[3]
	}
	switch sub {
	case "merge-base":
		return nil, f.mergeCode, f.mergeErr
	case "diff":
		return f.diff, f.diffCode, nil
	case "ls-files":
		return f.others, f.lsCode, nil
	}
	return nil, 129, nil
}

// noGit fails the test if git is run.
func noGit(t *testing.T) gitRunner {
	return func(_ context.Context, _ string, args ...string) ([]byte, int, error) {
		t.Errorf("git run with %q, want no git command", args)
		return nil, 128, errors.New("no git")
	}
}

func openRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

// newEnv opens dir as the repository root, with the targets of targets() plus stub.
func newEnv(t *testing.T, dir string, git gitRunner) env {
	t.Helper()
	ts := targets()
	ts["stub"] = stubTarget{}
	return env{repo: openRoot(t, dir), git: git, targets: ts, environ: []string{"PATH=" + os.Getenv("PATH"), "HOME=/nonexistent"}}
}

func runArgs(t *testing.T, e env, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runWith(context.Background(), e, args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// copyFixture copies testdata/name into a new temporary directory.
func copyFixture(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(filepath.Join("testdata", name))); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeFile(t *testing.T, dir, name, data string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.FromSlash(name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func replaceIn(t *testing.T, dir, name, old, new string) {
	t.Helper()
	data := readFile(t, filepath.Join(dir, name))
	if strings.Count(data, old) != 1 {
		t.Fatalf("%s: %q found %d times, want once", name, old, strings.Count(data, old))
	}
	writeFile(t, dir, name, strings.Replace(data, old, new, 1))
}

// snapshot maps every entry under dir to its content ("<dir>" for a
// directory, "-> target" for a link).
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			out[rel] = "-> " + target
			return err
		case d.IsDir():
			out[rel] = "<dir>"
		default:
			data, err := os.ReadFile(p)
			out[rel] = string(data)
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// oneDocument decodes stdout as exactly one JSON document into v.
func oneDocument(t *testing.T, stdout string, v any) {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(stdout))
	if err := dec.Decode(v); err != nil {
		t.Fatalf("stdout is not a JSON document: %v\n%s", err, stdout)
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		t.Fatalf("stdout holds more than one JSON document: %v\n%s", err, stdout)
	}
}

type selection struct {
	Selection struct {
		Mode     string `json:"mode"`
		Fallback string `json:"fallback"`
	} `json:"selection"`
	Suites []struct {
		Suite  string        `json:"suite"`
		Code   int           `json:"code"`
		Report *evals.Report `json:"report"`
	} `json:"suites"`
}

func (s selection) names() []string {
	out := []string{}
	for _, x := range s.Suites {
		out = append(out, x.Suite)
	}
	return out
}

func metrics(r evals.Report) []string {
	var out []string
	for _, reg := range r.RegressionsVsBaseline {
		out = append(out, reg.Metric)
	}
	return out
}

func TestRunOKAgainstBaseline(t *testing.T) {
	code, stdout, stderr := runArgs(t, newEnv(t, "testdata/ok", noGit(t)), "--suite", "demo")
	if code != 0 {
		t.Fatalf("code %d, want 0\n%s", code, stderr)
	}
	var r evals.Report
	oneDocument(t, stdout, &r)
	if !reflect.DeepEqual(r, demoReport()) {
		t.Errorf("report %+v, want %+v", r, demoReport())
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, []byte(stdout)); err != nil || !strings.Contains(compact.String(), `"regressions_vs_baseline":[]`) ||
		!strings.Contains(compact.String(), `"cases":1`) || !strings.Contains(compact.String(), `"platform":"fake"`) ||
		!strings.Contains(compact.String(), `"model":"fake-model-v1"`) {
		t.Errorf("report form (criterion 5): %v\n%s", err, stdout)
	}
	if !strings.Contains(stderr, runLine+"\n") {
		t.Errorf("stderr %q, want the line %q", stderr, runLine)
	}
}

func TestRegressionDetected(t *testing.T) {
	code, stdout, stderr := runArgs(t, newEnv(t, "testdata/regression", noGit(t)), "--suite", "demo")
	var r evals.Report
	if code != 1 {
		t.Fatalf("code %d, want 1\n%s", code, stderr)
	}
	oneDocument(t, stdout, &r)
	if !slices.Contains(r.RegressionsVsBaseline, evals.Regression{Metric: "avg_iterations", Baseline: 1, Current: 2}) || r.Cases != 1 {
		t.Errorf("regressions %+v, want avg_iterations 1 -> 2", r.RegressionsVsBaseline)
	}
	for name, c := range map[string]struct {
		fixture, old, new string
		code              int
		want              []string
	}{
		// ADR 0002: a baseline of another model is an identity regression.
		"other_model": {"ok", `"model": "fake-model-v1"`, `"model": "fake-model-v2"`, 1, []string{"identity"}},
		"other_loop":  {"ok", `"loop": "L0-demo"`, `"loop": "L1-intent"`, 1, []string{"identity"}},
		"fewer_cases": {"ok", `"runs": 1,`, `"runs": 2,`, 1, []string{"cases"}},
		"tokens":      {"ok", `"avg_tokens": 30,`, `"avg_tokens": 20,`, 1, []string{"avg_tokens"}},
		// The tolerances of the baseline are applied.
		"tolerated": {"regression", `"avg_iterations_rise": 0,`, `"avg_iterations_rise": 1,`, 0, nil},
	} {
		dir := copyFixture(t, c.fixture)
		replaceIn(t, dir, demoBaselinePath, c.old, c.new)
		code, stdout, stderr := runArgs(t, newEnv(t, dir, noGit(t)), "--suite", "demo")
		if code != c.code {
			t.Errorf("%s: code %d, want %d\n%s", name, code, c.code, stderr)
			continue
		}
		var r evals.Report
		oneDocument(t, stdout, &r)
		if got := metrics(r); !slices.Equal(got, c.want) {
			t.Errorf("%s: regressions %q, want %q", name, got, c.want)
		}
	}
}

func TestMissingBaselineAsksHuman(t *testing.T) {
	check := func(name, dir string) {
		t.Helper()
		before := snapshot(t, dir)
		code, stdout, stderr := runArgs(t, newEnv(t, dir, noGit(t)), "--suite", "demo")
		if code != 3 || stdout != "" {
			t.Errorf("%s: code %d, stdout %q; want 3 and nothing", name, code, stdout)
		}
		// D9: the case ran before the baseline was looked for.
		if !strings.Contains(stderr, missingMessage) || !strings.Contains(stderr, runLine) ||
			strings.Index(stderr, runLine) > strings.Index(stderr, missingMessage) {
			t.Errorf("%s: stderr %q, want the run line then %q", name, stderr, missingMessage)
		}
		if after := snapshot(t, dir); !reflect.DeepEqual(after, before) {
			t.Errorf("%s: the tree changed without --write-baseline", name)
		}
	}
	check("fixture", "testdata/missing")
	partial := copyFixture(t, "missing")
	if err := os.MkdirAll(filepath.Join(partial, "evals/demo/baseline"), 0o755); err != nil {
		t.Fatal(err)
	}
	check("parent_absent", partial)
	other := copyFixture(t, "ok")
	if err := os.Rename(filepath.Join(other, demoBaselinePath), filepath.Join(other, "evals/demo/baseline/fake/other-model.json")); err != nil {
		t.Fatal(err)
	}
	check("other_model_only", other)

	// With all: one selection document, the suite with code 3 and no report.
	code, stdout, stderr := runArgs(t, newEnv(t, "testdata/missing", noGit(t)), "--suite", "all")
	var s selection
	if code != 3 {
		t.Fatalf("all: code %d, want 3\n%s", code, stderr)
	}
	oneDocument(t, stdout, &s)
	if s.Selection.Mode != "all" || s.Selection.Fallback != "" || len(s.Suites) != 1 || s.Suites[0].Suite != "demo" ||
		s.Suites[0].Code != 3 || s.Suites[0].Report != nil || !strings.Contains(stderr, missingMessage) {
		t.Errorf("all: %+v\n%s", s, stderr)
	}
}

func TestWriteBaselineOnlyWithFlag(t *testing.T) {
	dir := copyFixture(t, "missing")
	before := snapshot(t, dir)
	if code, _, _ := runArgs(t, newEnv(t, dir, noGit(t)), "--suite", "demo"); code != 3 || !reflect.DeepEqual(snapshot(t, dir), before) {
		t.Fatalf("without the flag: code %d, or a file was written", code)
	}
	code, stdout, stderr := runArgs(t, newEnv(t, dir, noGit(t)), "--suite", "demo", "--write-baseline")
	if code != 0 {
		t.Fatalf("with the flag: code %d, want 0\n%s", code, stderr)
	}
	var r evals.Report
	oneDocument(t, stdout, &r)
	if !reflect.DeepEqual(r, demoReport()) || !strings.Contains(stderr, demoBaselinePath) {
		t.Errorf("report %+v, stderr %q", r, stderr)
	}
	b, err := evals.LoadBaseline(os.DirFS(dir), demoBaselinePath)
	if err != nil || b.Tolerances != (evals.Tolerances{}) || !reflect.DeepEqual(b.Report, demoReport()) {
		t.Fatalf("written baseline %+v, %v; want the report and zero tolerances (O3)", b, err)
	}
	if canonical, err := evals.EncodeBaseline(b); err != nil || readFile(t, filepath.Join(dir, demoBaselinePath)) != string(canonical) {
		t.Errorf("written baseline is not the canonical encoding: %v", err)
	}
	// Exactly the baseline and its parents were created: no temporary file left.
	after := snapshot(t, dir)
	var created []string
	for k := range after {
		if _, ok := before[k]; !ok {
			created = append(created, filepath.ToSlash(k))
		}
	}
	slices.Sort(created)
	if want := []string{"evals/demo/baseline", "evals/demo/baseline/fake", demoBaselinePath}; !slices.Equal(created, want) {
		t.Errorf("created %q, want %q", created, want)
	}
	if code, _, stderr := runArgs(t, newEnv(t, dir, noGit(t)), "--suite", "demo"); code != 0 {
		t.Errorf("second run without the flag: code %d, want 0\n%s", code, stderr)
	}

	// Refused before any write: all, changed (D12), a link on the way (D19, T59).
	for name, args := range map[string][]string{
		"all":     {"--suite", "all", "--write-baseline"},
		"changed": {"--suite", "changed", "--base", "", "--write-baseline"},
	} {
		dir := copyFixture(t, "missing")
		before := snapshot(t, dir)
		code, stdout, _ := runArgs(t, newEnv(t, dir, noGit(t)), args...)
		if code != 2 || stdout != "" || !reflect.DeepEqual(snapshot(t, dir), before) {
			t.Errorf("%s: code %d, stdout %q, or a file was written", name, code, stdout)
		}
	}
	for name, link := range map[string][2]string{
		"baseline_link": {"evals/demo/baseline", "../../elsewhere"},
		"platform_link": {"evals/demo/baseline/fake", "../../../elsewhere"},
	} {
		dir := copyFixture(t, "missing")
		if err := os.MkdirAll(filepath.Join(dir, "elsewhere"), 0o755); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, filepath.FromSlash(link[0]))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(link[1], p); err != nil {
			t.Fatal(err)
		}
		before := snapshot(t, dir)
		code, stdout, _ := runArgs(t, newEnv(t, dir, noGit(t)), "--suite", "demo", "--write-baseline")
		entries, _ := os.ReadDir(filepath.Join(dir, "elsewhere"))
		if code != 2 || stdout != "" || len(entries) != 0 || !reflect.DeepEqual(snapshot(t, dir), before) {
			t.Errorf("%s: code %d, stdout %q, %d entries written through the link", name, code, stdout, len(entries))
		}
	}
}

func TestBaselineReadStrictly(t *testing.T) {
	good := readFile(t, "testdata/ok/"+demoBaselinePath)
	withRegion := func(v string) string { return strings.Replace(good, `"region": ""`, `"region": "`+v+`"`, 1) }
	variants := map[string]string{
		"zero_width":   withRegion("can​ary"),
		"line_161":     withRegion("canary" + strings.Repeat("é", 161-15-2-6)),
		"unknown_key":  strings.Replace(withRegion("canary"), `"cases": 1,`, `"cases": 1, "canary": 1,`, 1),
		"duplicate":    strings.Replace(withRegion("canary"), `"cases": 1,`, `"cases": 1, "cases": 1,`, 1),
		"exponent":     strings.Replace(withRegion("canary"), `"avg_tokens": 30,`, `"avg_tokens": 3e1,`, 1),
		"not_json":     "canary\n",
		"case_folding": strings.Replace(withRegion("canary"), `"success_rate": 1,`, `"Success_Rate": 1,`, 1),
	}
	dirs := map[string]string{"fixture": "testdata/badbaseline"}
	for name, data := range variants {
		dir := copyFixture(t, "missing")
		writeFile(t, dir, demoBaselinePath, data)
		dirs[name] = dir
	}
	linked := copyFixture(t, "ok")
	if err := os.Rename(filepath.Join(linked, demoBaselinePath), filepath.Join(linked, "evals/demo/baseline/fake/real.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real.json", filepath.Join(linked, demoBaselinePath)); err != nil {
		t.Fatal(err)
	}
	dirs["file_link"] = linked
	for name, dir := range dirs {
		code, stdout, stderr := runArgs(t, newEnv(t, dir, noGit(t)), "--suite", "demo")
		// Code 2 (D8, D18), after the run (D9); no value read is quoted (T64).
		if code != 2 || stdout != "" || strings.Contains(stderr, "canary") || !strings.Contains(stderr, runLine) {
			t.Errorf("%s: code %d, stdout %q, stderr %q; want 2, nothing, no canary", name, code, stdout, stderr)
		}
	}
	// A baseline Validate refuses is read, then reported by Compare (code 1).
	dir := copyFixture(t, "ok")
	replaceIn(t, dir, demoBaselinePath, `"success_rate_drop": 0,`, `"success_rate_drop": 0.5,`)
	code, stdout, stderr := runArgs(t, newEnv(t, dir, noGit(t)), "--suite", "demo")
	if code != 1 {
		t.Fatalf("out of bounds: code %d, want 1\n%s", code, stderr)
	}
	var r evals.Report
	oneDocument(t, stdout, &r)
	if got := metrics(r); len(got) == 0 || got[0] != "baseline" {
		t.Errorf("out of bounds: regressions %q, want baseline first", got)
	}
}

func TestDemoTargetRunsWorkflow(t *testing.T) {
	target := targets()["demo"]
	if target == nil || target.Identity() != (Identity{Platform: "fake", Model: "fake-model-v1"}) {
		t.Fatalf("demo target %v", target)
	}
	// The case of the repository (section 7), the one of the fixtures too.
	repo, err := evals.LoadSuite(os.DirFS("../../evals"), "demo")
	if err != nil || len(repo.Cases) != 1 || repo.Target != "demo" || repo.Loop != "L0-demo" {
		t.Fatalf("evals/demo: %+v, %v", repo, err)
	}
	if fixture, err := evals.LoadSuite(os.DirFS("testdata/ok/evals"), "demo"); err != nil || !reflect.DeepEqual(fixture, repo) {
		t.Errorf("testdata/ok/evals/demo differs from evals/demo: %v", err)
	}
	c := repo.Cases[0]
	if err := target.Check(c); err != nil {
		t.Fatalf("Check: %v", err)
	}
	o, err := target.Run(context.Background(), c, 0)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(o.Output, &out); err != nil {
		t.Fatalf("output: %v", err)
	}
	keys := []string{}
	for k := range out {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if want := []string{"approval", "best", "committed", "iterations", "reason", "status", "tokens"}; !slices.Equal(keys, want) {
		t.Errorf("output keys %q, want %q (D6)", keys, want)
	}
	best, _ := out["best"].(map[string]any)
	if o.Status != "converged" || o.Escalated || o.Iterations != 2 || o.Tokens != 30 || !o.SchemaValid || o.Err != "" || o.Duration < 0 ||
		out["status"] != "converged" || out["approval"] != "timed_out" || out["committed"] != false || best["greeting"] != "bonjour" ||
		out["iterations"] != 2.0 || out["tokens"] != 30.0 {
		t.Errorf("outcome %+v, output %s", o, o.Output)
	}
	if g, err := evals.GradeOutcome(c, 0, o); err != nil || !g.Pass {
		t.Errorf("grade %+v, %v", g, err)
	}

	mk := func(input string, runs int) evals.Case {
		return evals.Case{ID: "demo-t-001", Loop: "L0-demo", Input: json.RawMessage(input), Expect: evals.Expect{Status: "converged"}, Runs: runs}
	}
	runCase := func(input string) (evals.Outcome, map[string]any) {
		t.Helper()
		cs := mk(input, 1)
		if err := target.Check(cs); err != nil {
			t.Fatalf("Check %s: %v", input, err)
		}
		o, err := target.Run(context.Background(), cs, 0)
		if err != nil {
			t.Fatalf("Run %s: %v", input, err)
		}
		var out map[string]any
		if err := json.Unmarshal(o.Output, &out); err != nil {
			t.Fatalf("output %s: %v", input, err)
		}
		return o, out
	}
	// The script comes from input.replies (D4): one right answer, one iteration.
	if o, _ := runCase(`{"target":"bonjour","replies":[{"greeting":"bonjour"}]}`); o.Status != "converged" || o.Iterations != 1 || o.Tokens != 15 {
		t.Errorf("one reply: %+v", o)
	}
	if o, out := runCase(`{"target":"salut","replies":[{"greeting":"salut"}]}`); o.Status != "converged" || o.Iterations != 1 || out["approval"] != "timed_out" {
		t.Errorf("other target: %+v %s", o, o.Output)
	}
	o3, out3 := runCase(`{"target":"bonjour","replies":[{"greeting":"salut"},{"greeting":"salut"},{"greeting":"salut"}]}`)
	if o3.Status != "escalated" || !o3.Escalated || out3["status"] != "escalated" || out3["approval"] != "" || out3["committed"] != false {
		t.Errorf("three wrong replies: %+v %s", o3, o3.Output)
	}
	if o, out := runCase(`{"target":"bonjour","replies":[{"x":1}]}`); o.SchemaValid || o.Status == "converged" || out["best"] != nil {
		t.Errorf("reply out of schema: %+v %s", o, o.Output)
	}
	// A fresh environment and a fresh script for each run (M21).
	twice := mk(string(c.Input), 2)
	a, errA := target.Run(context.Background(), twice, 0)
	b, errB := target.Run(context.Background(), twice, 1)
	a.Duration, b.Duration, o.Duration = 0, 0, 0
	if errA != nil || errB != nil || !reflect.DeepEqual(a, b) || !reflect.DeepEqual(a, o) {
		t.Errorf("successive runs differ: %+v, %v; %+v, %v", a, errA, b, errB)
	}

	reply := func(n int) string { return `{"greeting":"` + strings.Repeat("a", n-len(`{"greeting":""}`)) + `"}` }
	replies := func(n int) string {
		return `{"target":"bonjour","replies":[` + strings.TrimSuffix(strings.Repeat(`{"greeting":"bonjour"},`, n), ",") + `]}`
	}
	for i, input := range []string{replies(8), `{"target":"bonjour","replies":[` + reply(1024) + `]}`, `{"replies":[{"g":1}],"target":"a b-c"}`} {
		if err := target.Check(mk(input, 1)); err != nil {
			t.Errorf("admitted %d: %v", i, err)
		}
	}
	for i, input := range []string{
		`{"target":"bonjour","replies":[{"greeting":"bonjour"}],"canary":1}`,
		replies(9),
		replies(0),
		`{"target":"bonjour"}`,
		`{"replies":[{"greeting":"bonjour"}]}`,
		`{"target":"CANARY","replies":[{"greeting":"bonjour"}]}`,
		`{"target":"canary!","replies":[{"greeting":"bonjour"}]}`,
		`{"target":"","replies":[{"greeting":"bonjour"}]}`,
		`{"target":1,"replies":[{"greeting":"bonjour"}]}`,
		`{"target":"bonjour","replies":[1]}`,
		`{"target":"bonjour","replies":["canary"]}`,
		`{"target":"bonjour","replies":[[{"greeting":"bonjour"}]]}`,
		`{"target":"bonjour","replies":{"greeting":"bonjour"}}`,
		`{"target":"bonjour","replies":[` + reply(1025) + `]}`,
		`["bonjour"]`,
	} {
		err := target.Check(mk(input, 1))
		if err == nil || strings.Contains(strings.ToLower(err.Error()), "canary") {
			t.Errorf("refused %d: %v", i, err)
		}
	}
}

func TestUsageErrors(t *testing.T) {
	type tc struct {
		dir     string
		args    []string
		environ []string
	}
	demo := []string{"--suite", "demo"}
	cases := map[string]tc{
		"no_suite":            {"testdata/ok", nil, nil},
		"suite_without_value": {"testdata/ok", []string{"--suite"}, nil},
		"unknown_suite":       {"testdata/ok", []string{"--suite", "nope"}, nil},
		"suite_not_a_suite":   {"testdata/ok", []string{"--suite", "demo/cases"}, nil},
		"invalid_suite_name":  {"testdata/ok", []string{"--suite", "../ok"}, nil},
		"empty_suite_name":    {"testdata/ok", []string{"--suite", ""}, nil},
		"upper_suite_name":    {"testdata/ok", []string{"--suite", "Demo"}, nil},
		"positional":          {"testdata/ok", []string{"--suite", "demo", "extra"}, nil},
		"repeated_suite":      {"testdata/ok", []string{"--suite", "demo", "--suite", "demo"}, nil},
		"base_with_named":     {"testdata/ok", []string{"--suite", "demo", "--base", aSHA}, nil},
		"base_with_all":       {"testdata/ok", []string{"--suite", "all", "--base", aSHA}, nil},
		"changed_no_base":     {"testdata/ok", []string{"--suite", "changed"}, nil},
		"repeated_base":       {"testdata/ok", []string{"--suite", "changed", "--base", "", "--base", ""}, nil},
		"unknown_flag":        {"testdata/ok", []string{"--suite", "demo", "--unknown"}, nil},
		"help":                {"testdata/ok", []string{"-h"}, nil},
		"single_dash_suite":   {"testdata/ok", []string{"-suite=demo", "extra"}, nil},
		"temporal_debug":      {"testdata/ok", demo, []string{"TEMPORAL_DEBUG=1"}},
		"temporal_debug_set":  {"testdata/ok", demo, []string{"TEMPORAL_DEBUG="}},
		"temporal_sdk_flag":   {"testdata/ok", demo, []string{"TEMPORAL_SDK_FLAG_5=1"}},
		"temporal_with_all":   {"testdata/ok", []string{"--suite", "all"}, []string{"TEMPORAL_SDK_FLAG_1=true"}},
	}
	edited := func(fixture string, f func(dir string)) string {
		dir := copyFixture(t, fixture)
		f(dir)
		return dir
	}
	symlink := func(dir, target, name string) {
		if err := os.Symlink(target, filepath.Join(dir, filepath.FromSlash(name))); err != nil {
			t.Fatal(err)
		}
	}
	// A write request always runs on a copy: a faulty runner must not write into testdata.
	cases["write_with_all"] = tc{copyFixture(t, "missing"), []string{"--suite", "all", "--write-baseline"}, nil}
	cases["write_with_changed"] = tc{copyFixture(t, "missing"), []string{"--suite", "changed", "--base", "", "--write-baseline"}, nil}
	cases["repeated_write"] = tc{copyFixture(t, "missing"), []string{"--suite", "demo", "--write-baseline", "--write-baseline"}, nil}
	cases["write_false"] = tc{copyFixture(t, "missing"), []string{"--suite", "demo", "--write-baseline=false", "extra"}, nil}
	cases["unknown_target"] = tc{edited("ok", func(d string) { replaceIn(t, d, "evals/demo/suite.yaml", "target: demo", "target: nosuch") }), demo, nil}
	cases["unknown_target_all"] = tc{edited("ok", func(d string) { replaceIn(t, d, "evals/demo/suite.yaml", "target: demo", "target: nosuch") }), []string{"--suite", "all"}, nil}
	cases["case_input_refused"] = tc{edited("ok", func(d string) {
		replaceIn(t, d, "evals/demo/cases/demo-converge-001.yaml", "target: bonjour", "target: Bonjour")
	}), demo, nil}
	cases["invalid_suite_all"] = tc{edited("ok", func(d string) { writeFile(t, d, "evals/bad/suite.yaml", "name: bad\ncanary: 1\n") }), []string{"--suite", "all"}, nil}
	cases["link_in_evals_all"] = tc{edited("ok", func(d string) { symlink(d, "demo", "evals/l") }), []string{"--suite", "all"}, nil}
	cases["no_go_mod"] = tc{edited("ok", func(d string) {
		if err := os.Remove(filepath.Join(d, "go.mod")); err != nil {
			t.Fatal(err)
		}
	}), demo, nil}
	cases["go_mod_link"] = tc{edited("ok", func(d string) {
		if err := os.Rename(filepath.Join(d, "go.mod"), filepath.Join(d, "real.mod")); err != nil {
			t.Fatal(err)
		}
		symlink(d, "real.mod", "go.mod")
	}), demo, nil}
	cases["evals_link"] = tc{edited("ok", func(d string) {
		if err := os.Rename(filepath.Join(d, "evals"), filepath.Join(d, "real")); err != nil {
			t.Fatal(err)
		}
		symlink(d, "real", "evals")
	}), demo, nil}
	cases["evals_absent"] = tc{edited("ok", func(d string) {
		if err := os.RemoveAll(filepath.Join(d, "evals")); err != nil {
			t.Fatal(err)
		}
	}), demo, nil}
	cases["evals_file"] = tc{edited("ok", func(d string) {
		if err := os.RemoveAll(filepath.Join(d, "evals")); err != nil {
			t.Fatal(err)
		}
		writeFile(t, d, "evals", "x")
	}), []string{"--suite", "all"}, nil}

	for name, c := range cases {
		e := newEnv(t, c.dir, noGit(t))
		runs := 0
		e.targets["demo"] = counting{e.targets["demo"], &runs}
		e.targets["stub"] = stubTarget{&runs}
		e.environ = append(e.environ, c.environ...)
		before := snapshot(t, c.dir)
		code, stdout, stderr := runArgs(t, e, c.args...)
		if code != 2 || stdout != "" || runs != 0 || strings.Contains(stderr, "canary") {
			t.Errorf("%s: code %d, stdout %q, %d runs; want 2, nothing, no run\n%s", name, code, stdout, runs, stderr)
		}
		if !reflect.DeepEqual(snapshot(t, c.dir), before) {
			t.Errorf("%s: the tree changed", name)
		}
	}
	// Controls: the same environment without the refused variable runs.
	e := newEnv(t, "testdata/ok", noGit(t))
	e.environ = append(e.environ, "TEMPORAL=1", "XTEMPORAL_DEBUG=1", "TEMPORAL_SDK=1")
	if code, _, stderr := runArgs(t, e, demo...); code != 0 {
		t.Errorf("control: code %d\n%s", code, stderr)
	}
}

func TestStdoutSingleJSONDocument(t *testing.T) {
	// D2: without SetLogger, the SDK logs on the process standard output.
	capture := func(f func()) string {
		t.Helper()
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		old := os.Stdout
		os.Stdout = w
		done := make(chan string)
		go func() {
			data, _ := io.ReadAll(r)
			done <- string(data)
		}()
		defer func() { os.Stdout = old }()
		f()
		os.Stdout = old
		_ = w.Close()
		return <-done
	}
	for name, c := range map[string]struct {
		dir  string
		args []string
		code int
	}{
		"named":           {"testdata/ok", []string{"--suite", "demo"}, 0},
		"named_escalated": {"", []string{"--suite", "demo"}, 1},
		"all":             {"testdata/select", []string{"--suite", "all"}, 0},
		"changed":         {"testdata/select", []string{"--suite", "changed", "--base", ""}, 0},
		"all_missing":     {"testdata/missing", []string{"--suite", "all"}, 3},
	} {
		dir := c.dir
		if dir == "" {
			dir = copyFixture(t, "ok")
			replaceIn(t, dir, "evals/demo/cases/demo-converge-001.yaml", "- {greeting: bonjour}", "- {greeting: salut}\n    - {greeting: salut}")
		}
		var code int
		var stdout, stderr bytes.Buffer
		process := capture(func() {
			code = runWith(context.Background(), newEnv(t, dir, noGit(t)), c.args, &stdout, &stderr)
		})
		if code != c.code || process != "" {
			t.Errorf("%s: code %d (want %d), process stdout %q\n%s", name, code, c.code, process, stderr.String())
		}
		var v any
		oneDocument(t, stdout.String(), &v)
	}
}
