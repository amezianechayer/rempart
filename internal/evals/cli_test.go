package evals

// Tests of M0-T23 (docs/plans/M0-evals-cli.md section 8.1): obligations (s) to
// (w) and (y) of M0-T22, LoadBaseline, EncodeBaseline, DiscoverSuites.

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"
	"unicode/utf8"
)

// baselineText is the canonical encoding of refBaseline (D19): JSON indented
// by two spaces, LF line ends, a final newline.
const baselineText = `{
  "report": {
    "loop": "L0-demo",
    "platform": "fake",
    "region": "",
    "model": "fake-model-v1",
    "cases": 1,
    "runs": 1,
    "injection_runs": 0,
    "escalation_runs": 1,
    "success_rate": 1,
    "correct_escalation_rate": 1,
    "injection_resistance": 1,
    "avg_iterations": 2,
    "avg_tokens": 30,
    "regressions_vs_baseline": []
  },
  "tolerances": {
    "success_rate_drop": 0.05,
    "correct_escalation_drop": 0.05,
    "avg_iterations_rise": 0.5,
    "avg_tokens_rise_pct": 10
  }
}
`

const baselineFile = "evals/demo/baseline/fake/fake-model-v1.json"

func refBaseline() Baseline {
	return Baseline{
		Report: Report{
			Loop: "L0-demo", Platform: "fake", Model: "fake-model-v1", Cases: 1, Runs: 1, EscalationRuns: 1,
			SuccessRate: 1, CorrectEscalationRate: 1, InjectionResistance: 1, AvgIterations: 2, AvgTokens: 30,
			RegressionsVsBaseline: []Regression{},
		},
		Tolerances: Tolerances{SuccessRateDrop: 0.05, CorrectEscalationDrop: 0.05, AvgIterationsRise: 0.5, AvgTokensRisePct: 10},
	}
}

// withRegion returns baselineText with the region set to v (a free text field:
// where a hostile baseline hides its witness value).
func withRegion(v string) string {
	return strings.Replace(baselineText, `"region": ""`, `"region": "`+v+`"`, 1)
}

// commentFill returns n bytes of YAML comment lines, each at most 100 bytes.
func commentFill(n int) string {
	var b strings.Builder
	for n > 0 {
		k := min(n, 100)
		if k == 1 {
			b.WriteString("\n")
		} else {
			b.WriteString("#" + strings.Repeat("x", k-2) + "\n")
		}
		n -= k
	}
	return b.String()
}

// realTree writes files and symbolic links (name -> target) under a new
// temporary directory and returns it.
func realTree(t *testing.T, files, links map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, data := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range links {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLoadBaselineStrict(t *testing.T) {
	want := refBaseline()
	for i, fsys := range []fs.FS{
		os.DirFS(realTree(t, map[string]string{baselineFile: baselineText}, nil)),
		fstest.MapFS{baselineFile: {Data: []byte(baselineText)}},
		fstest.MapFS{"b.json": {Data: []byte(strings.ReplaceAll(baselineText, "\n", "\r\n"))}},
	} {
		name := baselineFile
		if i == 2 {
			name = "b.json"
		}
		if b, err := LoadBaseline(fsys, name); err != nil || !reflect.DeepEqual(b, want) {
			t.Errorf("control %d: %+v, %v", i, b, err)
		}
	}
	// The file size bound is MaxFileBytes: exactly that is read, one more byte refused.
	exact := baselineText + strings.Repeat("\n", MaxFileBytes-len(baselineText))
	if _, err := LoadBaseline(fstest.MapFS{"b.json": {Data: []byte(exact)}}, "b.json"); err != nil {
		t.Errorf("64 KiB: %v", err)
	}

	canary := withRegion("canary")
	invalid := map[string]string{
		// T60: a key differing by case only, which encoding/json would fold.
		"case_folded_key":  strings.Replace(canary, `"success_rate": 1,`, `"Success_Rate": 0,`+"\n    "+`"success_rate": 1,`, 1),
		"case_folded_only": strings.Replace(canary, `"success_rate": 1,`, `"Success_Rate": 1,`, 1),
		"unicode_folded":   strings.Replace(canary, `"success_rate": 1,`, `"\u017fuccess_rate": 1,`, 1),
		"unknown_key":      strings.Replace(canary, `"cases": 1,`, `"cases": 1,`+"\n    "+`"canary": 1,`, 1),
		"unknown_top_key":  strings.Replace(canary, `"tolerances": {`, `"canary": {},`+"\n  "+`"tolerances": {`, 1),
		"duplicate_key":    strings.Replace(canary, `"cases": 1,`, `"cases": 1,`+"\n    "+`"cases": 9,`, 1),
		"exponent":         strings.Replace(canary, `"avg_tokens": 30,`, `"avg_tokens": 3e1,`, 1),
		"zero_width_rune":  withRegion("can\u200bary"),
		"bidi_rune":        withRegion("\u202ecanary"),
		"raw_tab":          withRegion("can\tary"),
		"line_161_runes":   withRegion("canary" + strings.Repeat("é", 161-15-2-6)),
		"too_large":        canary + strings.Repeat("\n", MaxFileBytes+1-len(canary)),
		"trailing_data":    canary + "{}\n",
		"not_an_object":    `["canary"]` + "\n",
		"string_number":    strings.Replace(canary, `"cases": 1,`, `"cases": "1",`, 1),
		"yaml_not_json":    "report: {loop: canary}\n",
		"invalid_utf8":     withRegion("canary\xff"),
	}
	for name, data := range invalid {
		_, err := LoadBaseline(fstest.MapFS{baselineFile: {Data: []byte(data)}}, baselineFile)
		if !errors.Is(err, ErrInvalidBaseline) || errors.Is(err, ErrNoBaseline) || strings.Contains(fmt.Sprint(err), "canary") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The same refusals on the real file system.
	if _, err := LoadBaseline(os.DirFS(realTree(t, map[string]string{baselineFile: invalid["case_folded_key"]}, nil)), baselineFile); !errors.Is(err, ErrInvalidBaseline) {
		t.Errorf("case folded key, real file system: %v", err)
	}

	// T59: the file and each parent directory are real: a link or a file there is refused.
	for name, c := range map[string]struct{ files, links map[string]string }{
		"file_link": {
			map[string]string{"evals/demo/baseline/fake/real.json": canary},
			map[string]string{baselineFile: "real.json"},
		},
		"parent_link": {
			map[string]string{"evals/demo/baseline/real/fake-model-v1.json": canary},
			map[string]string{"evals/demo/baseline/fake": "real"},
		},
		"grand_parent_link": {
			map[string]string{"elsewhere/fake/fake-model-v1.json": canary},
			map[string]string{"evals/demo/baseline": "../../elsewhere"},
		},
		"root_link": {
			map[string]string{"other/demo/baseline/fake/fake-model-v1.json": canary},
			map[string]string{"evals": "other"},
		},
		"parent_file": {map[string]string{"evals/demo/baseline/fake": canary}, nil},
		"dangling_link": {
			map[string]string{"evals/demo/baseline/fake/x": ""},
			map[string]string{baselineFile: "absent.json"},
		},
	} {
		_, err := LoadBaseline(os.DirFS(realTree(t, c.files, c.links)), baselineFile)
		if !errors.Is(err, ErrInvalidBaseline) || errors.Is(err, ErrNoBaseline) || strings.Contains(fmt.Sprint(err), "canary") {
			t.Errorf("%s: %v", name, err)
		}
	}
	dirAsFile := realTree(t, map[string]string{baselineFile + "/x": ""}, nil)
	if _, err := LoadBaseline(os.DirFS(dirAsFile), baselineFile); !errors.Is(err, ErrInvalidBaseline) {
		t.Errorf("directory at the file path: %v", err)
	}
	link := fstest.MapFS{"b/real.json": {Data: []byte(baselineText)}, "b/f.json": {Data: []byte("real.json"), Mode: fs.ModeSymlink}}
	if _, err := LoadBaseline(link, "b/f.json"); !errors.Is(err, ErrInvalidBaseline) {
		t.Errorf("file link, map file system: %v", err)
	}

	// Absent file or absent parent: ErrNoBaseline, never ErrInvalidBaseline.
	for i, dir := range []string{
		realTree(t, map[string]string{"evals/demo/baseline/fake/other.json": baselineText}, nil),
		realTree(t, map[string]string{"evals/demo/suite.yaml": "name: demo\n"}, nil),
		realTree(t, map[string]string{"go.mod": "module x\n"}, nil),
	} {
		if _, err := LoadBaseline(os.DirFS(dir), baselineFile); !errors.Is(err, ErrNoBaseline) || errors.Is(err, ErrInvalidBaseline) {
			t.Errorf("absent %d: %v", i, err)
		}
	}
	// A file system that cannot tell a link from a file is refused (D18).
	if _, err := LoadBaseline(openOnly{fstest.MapFS{baselineFile: {Data: []byte(baselineText)}}}, baselineFile); !errors.Is(err, ErrInvalidBaseline) {
		t.Errorf("open only: %v", err)
	}
	for _, name := range []string{"", ".", "/" + baselineFile, "../" + baselineFile, "evals//demo/b.json"} {
		if _, err := LoadBaseline(fstest.MapFS{baselineFile: {Data: []byte(baselineText)}}, name); !errors.Is(err, ErrInvalidBaseline) {
			t.Errorf("name %q: %v", name, err)
		}
	}
	// A baseline out of the bounds of Validate is read as is: Compare reports it (D18).
	loose := strings.Replace(baselineText, `"success_rate_drop": 0.05`, `"success_rate_drop": 0.5`, 1)
	b, err := LoadBaseline(fstest.MapFS{"b.json": {Data: []byte(loose)}}, "b.json")
	if err != nil || b.Tolerances.SuccessRateDrop != 0.5 || len(Compare(b, b.Report)) == 0 || Compare(b, b.Report)[0].Metric != "baseline" {
		t.Errorf("out of bounds: %+v, %v", b, err)
	}
}

func TestEncodeBaselineRoundTrip(t *testing.T) {
	data, err := EncodeBaseline(refBaseline())
	if err != nil || string(data) != baselineText {
		t.Fatalf("canonical form: %v\n%s", err, data)
	}
	variants := []func(*Baseline){
		func(*Baseline) {},
		func(b *Baseline) { b.Tolerances = Tolerances{} },
		func(b *Baseline) { b.Tolerances = Tolerances{0.1, 0.1, 2, 25} },
		func(b *Baseline) { b.Report.Region, b.Report.Model = "eu-west-3", "eu.a-v1:0" },
		func(b *Baseline) { b.Report.Region = "Crée à Évry" },
		func(b *Baseline) {
			b.Report.Cases, b.Report.Runs, b.Report.InjectionRuns, b.Report.EscalationRuns = 4, 12, 3, 6
			b.Report.SuccessRate, b.Report.CorrectEscalationRate, b.Report.AvgIterations, b.Report.AvgTokens = 2.0/3, 0.75, 2.25, 1234.5
		},
		func(b *Baseline) { b.Report.RegressionsVsBaseline = nil },
	}
	for i, f := range variants {
		b := refBaseline()
		f(&b)
		data, err := EncodeBaseline(b)
		if err != nil {
			t.Errorf("variant %d: %v", i, err)
			continue
		}
		back, err := LoadBaseline(fstest.MapFS{"b.json": {Data: data}}, "b.json")
		if err != nil || !reflect.DeepEqual(back, b) {
			t.Errorf("variant %d: read back %+v, %v", i, back, err)
		}
		if !admitted(data) || !strings.HasSuffix(string(data), "}\n") || strings.Contains(string(data), "\r") || !strings.HasPrefix(string(data), "{\n  \"report\": {\n") {
			t.Errorf("variant %d: not canonical:\n%s", i, data)
		}
		for n, line := range strings.Split(string(data), "\n") {
			if utf8.RuneCountInString(line) > MaxLineRunes {
				t.Errorf("variant %d: line %d longer than %d runes", i, n+1, MaxLineRunes)
			}
		}
	}
	// Refused: Validate fails, or LoadBaseline would not read the result back equal.
	for i, f := range []func(*Baseline){
		func(b *Baseline) { b.Tolerances.SuccessRateDrop = 0.2 },
		func(b *Baseline) { b.Tolerances.AvgTokensRisePct = 26 },
		func(b *Baseline) { b.Report.AvgTokens = math.NaN() },
		func(b *Baseline) { b.Report.SuccessRate = math.Inf(1) },
		func(b *Baseline) { b.Report.Cases = 0 },
		func(b *Baseline) { b.Report.RegressionsVsBaseline = []Regression{{Metric: "avg_iterations"}} },
		func(b *Baseline) { b.Report.AvgTokens = 1e-7 },                  // encoded with an exponent
		func(b *Baseline) { b.Report.Region = "eu\u200b" },               // outside the admission list
		func(b *Baseline) { b.Report.Region = strings.Repeat("a", 200) }, // line longer than 160 runes
	} {
		b := refBaseline()
		f(&b)
		if data, err := EncodeBaseline(b); err == nil || data != nil {
			t.Errorf("refused %d: %q, %v", i, data, err)
		}
	}
	nan := refBaseline()
	nan.Tolerances.CorrectEscalationDrop = math.NaN()
	if _, err := EncodeBaseline(nan); !errors.Is(err, ErrInvalidBaseline) {
		t.Errorf("NaN tolerance: %v", err)
	}
}

func TestDiscoverSuites(t *testing.T) {
	base := map[string]string{
		".gitkeep":                  "",
		"demo/suite.yaml":           "x",
		"demo/cases/c-001.yaml":     "x",
		"demo/baseline/fake/m.json": "x",
		"a/b/suite.yaml":            "x",
		"a/b/cases/c-001.yaml":      "x",
		"a/README.md":               "x",
	}
	with := func(extra map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	for name, files := range map[string]map[string]string{
		"tree": base,
		// cases/ and baseline/ of a suite are not searched for suites.
		"cases_not_explored":    with(map[string]string{"demo/cases/sub/suite.yaml": "x", "a/b/cases/x/y/suite.yaml": "x"}),
		"baseline_not_explored": with(map[string]string{"demo/baseline/fake/suite.yaml": "x"}),
	} {
		for _, fsys := range []fs.FS{os.DirFS(realTree(t, files, nil)), mapOf(files)} {
			if got, err := DiscoverSuites(fsys); err != nil || !slices.Equal(got, []string{"a/b", "demo"}) {
				t.Errorf("%s: %q, %v", name, got, err)
			}
		}
	}
	many := func(n int) map[string]string {
		m := map[string]string{}
		for i := range n {
			m[fmt.Sprintf("s%03d/suite.yaml", i)] = "x"
		}
		return m
	}
	if got, err := DiscoverSuites(mapOf(many(256))); err != nil || len(got) != 256 {
		t.Errorf("256 suites: %d, %v", len(got), err)
	}
	if got, err := DiscoverSuites(mapOf(nil)); err != nil || len(got) != 0 {
		t.Errorf("empty: %q, %v", got, err)
	}

	refused := map[string]struct{ files, links map[string]string }{
		// O6: any link under evals/, wherever it is and whatever it points to.
		"link_top":        {base, map[string]string{"l": "demo"}},
		"link_to_file":    {base, map[string]string{"x.yaml": ".gitkeep"}},
		"link_in_suite":   {base, map[string]string{"demo/graders": "../a"}},
		"link_deep":       {base, map[string]string{"z/y/x/l": "../../../a"}},
		"link_suite_file": {with(map[string]string{"c/real.yaml": "x"}), map[string]string{"c/suite.yaml": "real.yaml"}},
		"link_outside":    {base, map[string]string{"out": "/"}},
		"link_dangling":   {base, map[string]string{"dangling": "absent"}},
		"named_all":       {with(map[string]string{"all/suite.yaml": "x"}), nil},
		"named_changed":   {with(map[string]string{"changed/suite.yaml": "x"}), nil},
		"nested":          {with(map[string]string{"demo/sub/suite.yaml": "x"}), nil},
		"nested_deep":     {with(map[string]string{"a/b/c/d/suite.yaml": "x"}), nil},
		"invalid_name":    {with(map[string]string{"Bad/suite.yaml": "x"}), nil},
		"invalid_segment": {with(map[string]string{"a/-x/suite.yaml": "x"}), nil},
		"too_deep":        {with(map[string]string{"p/q/r/s/t/suite.yaml": "x"}), nil},
		"root_suite":      {with(map[string]string{"suite.yaml": "x"}), nil},
		"too_many_suites": {many(257), nil},
	}
	for name, c := range refused {
		if got, err := DiscoverSuites(os.DirFS(realTree(t, c.files, c.links))); !errors.Is(err, ErrInvalidSuite) || got != nil {
			t.Errorf("%s: %q, %v", name, got, err)
		}
	}
	if _, err := DiscoverSuites(openOnly{mapOf(base)}); !errors.Is(err, ErrInvalidSuite) {
		t.Errorf("open only: %v", err)
	}
}

// mapOf is fstest.MapFS of files (name -> content).
func mapOf(files map[string]string) fstest.MapFS {
	m := fstest.MapFS{}
	for k, v := range files {
		m[k] = &fstest.MapFile{Data: []byte(v)}
	}
	return m
}

func TestCaseTagsClosedVocabulary(t *testing.T) {
	if want := []string{"nominal", "trap", "injection", "limit", "regression", "storage"}; !slices.Equal(CaseTags, want) {
		t.Fatalf("CaseTags = %q, want %q", CaseTags, want)
	}
	for _, tag := range CaseTags {
		s, err := LoadSuite(suiteFS(caseF, caseY+"tags: ["+tag+"]\n"), "s")
		c := mk(Expect{Status: "converged"})
		c.Tags = []string{tag}
		if _, gerr := GradeOutcome(c, 0, Outcome{Status: "converged"}); err != nil || gerr != nil || !slices.Equal(s.Cases[0].Tags, []string{tag}) {
			t.Errorf("%s: %v, %v", tag, err, gerr)
		}
	}
	// T66: a look-alike of injection, a well-formed tag outside the vocabulary.
	for _, tag := range []string{"lnjection", "injecti0n", "demo", "Injection", "injections", "storage-2", "nominal-", "0-a", "-", "trap-injection"} {
		_, err := LoadSuite(suiteFS(caseF, caseY+"tags: [nominal, "+tag+"]\n"), "s")
		c := mk(Expect{Status: "converged"})
		c.Tags = []string{"nominal", tag}
		_, gerr := GradeOutcome(c, 0, Outcome{Status: "converged"})
		if !errors.Is(err, ErrInvalidSuite) || !errors.Is(err, ErrInvalidCase) || !errors.Is(gerr, ErrInvalidCase) || (len(tag) > 3 && strings.Contains(err.Error(), tag)) {
			t.Errorf("%s: %v, %v", tag, err, gerr)
		}
	}
}

func TestNeedleHardening(t *testing.T) {
	check := func(field string) string { return "{must_not_include: [{path: $.a, " + field + "}]}" }
	// Obligation (s), T65: a backslash in contains or equals only inside double
	// quotes, where the escape is visible; (t), T64: never two consecutive spaces.
	refused := []string{
		check(`contains: public\u005fbucket`),
		check(`contains: 'public\u005fbucket'`),
		check(`equals: 'C:\x'`),
		check(`equals: a\b`),
		check(`equals: [x, 'a\b']`),
		check(`equals: {k: a\b}`),
		check(`equals: {a\b: k}`),
		check(`contains: [public\_bucket]`),
		check(`contains: "a  b"`),
		check(`equals: "a  b"`),
		check(`equals: 'a  b'`),
		check(`equals: {k: a  b}`),
		check(`contains: [x, "public   bucket"]`),
		check(`equals: "a\u0020 b"`),
	}
	for i, needle := range refused {
		_, err := LoadSuite(suiteFS(caseF, edit(sc, needle)), "s")
		reason, _ := strings.CutPrefix(fmt.Sprint(err), ErrInvalidSuite.Error()+": "+caseF)
		if !errors.Is(err, ErrInvalidSuite) || errors.Is(err, ErrInvalidCase) || strings.ContainsAny(reason, `0123456789\`) || strings.Contains(reason, "public") {
			t.Errorf("refused %d: %v", i, err)
		}
	}
	for i, c := range [][2]string{
		{check(`contains: "public\u005fbucket"`), `"public_bucket"`},
		{check(`contains: "public\\bucket"`), `"public\\bucket"`},
		{check(`equals: "a b"`), `"a b"`},
		{check(`equals: {k: 'it''s'}`), `{"k":"it's"}`},
	} {
		s, err := LoadSuite(suiteFS(caseF, edit(sc, c[0])), "s")
		if err != nil {
			t.Errorf("admitted %d: %v", i, err)
			continue
		}
		pc := s.Cases[0].Expect.MustNotInclude[0]
		if got := string(pc.Contains) + string(pc.Equals); got != c[1] {
			t.Errorf("admitted %d: %s, want %s", i, got, c[1])
		}
	}
	// The same values under input stay admitted: input is opaque.
	s, err := LoadSuite(suiteFS(caseF, edit("{a: 1}", `{t: "a  b", u: a\b, v: 'C:\x'}`)), "s")
	if err != nil || string(s.Cases[0].Input) != `{"t":"a  b","u":"a\\b","v":"C:\\x"}` {
		t.Errorf("input: %v", err)
	}
}

func TestLineLengthBounded(t *testing.T) {
	line := func(n int) string { return "#" + strings.Repeat("é", n-1) + "\n" } // n runes, 2n-1 bytes
	for _, n := range []int{160, 161} {
		ok := n == 160
		for name, fsys := range map[string]fstest.MapFS{
			"suite":      suiteFS("s/suite.yaml", suiteY+line(n)),
			"suite_top":  suiteFS("s/suite.yaml", line(n)+suiteY),
			"case":       suiteFS(caseF, caseY+line(n)),
			"case_crlf":  suiteFS(caseF, strings.ReplaceAll(caseY+line(n), "\n", "\r\n")),
			"case_value": suiteFS(caseF, edit("{a: 1}", "{a: "+strings.Repeat("b", n-len("input: {a: }"))+"}")),
		} {
			_, err := LoadSuite(fsys, "s")
			if ok != (err == nil) || (!ok && (!errors.Is(err, ErrInvalidSuite) || errors.Is(err, ErrInvalidCase))) {
				t.Errorf("%s, %d runes: %v", name, n, err)
			}
		}
		// Baseline: "    \"region\": \"" is 15 runes, "\"," 2 more.
		data := withRegion(strings.Repeat("é", n-17))
		_, err := LoadBaseline(fstest.MapFS{"b.json": {Data: []byte(data)}}, "b.json")
		if ok != (err == nil) || (!ok && !errors.Is(err, ErrInvalidBaseline)) {
			t.Errorf("baseline, %d runes: %v", n, err)
		}
	}
}

func TestWatchPatternCharset(t *testing.T) {
	s, err := LoadSuite(suiteFS("s/suite.yaml", suiteY+"watch: [internal/x/**, docs/*.md, a-b_c.D9/x.go, go.sum]\n"), "s")
	if err != nil || !slices.Equal(s.Watch, []string{"internal/x/**", "docs/*.md", "a-b_c.D9/x.go", "go.sum"}) {
		t.Errorf("admitted: %q, %v", s.Watch, err)
	}
	// T67: ? and [ ] match runes the reviewer does not see, a space or a
	// non-ASCII letter gives two readings of the same line.
	for _, p := range []string{`"a?b"`, `"[ab]"`, `"a b"`, `"é/**"`, `"docs/[!x].md"`, `a+b`, `a~b`, `"a:b"`, `"a,b"`, `"x/\u00e9"`, `"a\\b"`} {
		_, err := LoadSuite(suiteFS("s/suite.yaml", suiteY+"watch: ["+p+"]\n"), "s")
		if !errors.Is(err, ErrInvalidSuite) || strings.Contains(err.Error(), strings.Trim(p, `"`)) {
			t.Errorf("%s: %v", p, err)
		}
	}
	// SelectChanged keeps its behavior: an invalid pattern selects the suite.
	for _, p := range []string{"a?b", "[ab]", "a b", "é/**"} {
		if got := SelectChanged([]Suite{{Name: "z", Watch: []string{p}}}, []string{"q"}); len(got) != 1 {
			t.Errorf("SelectChanged %q: %v", p, got)
		}
	}
}

// altInfo is a FileInfo whose size, mode, time and system information may differ.
type altInfo struct {
	fs.FileInfo
	size  int64
	mode  fs.FileMode
	mtime time.Time
	sys   any
}

func (a altInfo) Size() int64        { return a.size }
func (a altInfo) Mode() fs.FileMode  { return a.mode }
func (a altInfo) ModTime() time.Time { return a.mtime }
func (a altInfo) Sys() any           { return a.sys }
func (a altInfo) IsDir() bool        { return a.mode.IsDir() }

func alter(i fs.FileInfo, f func(*altInfo)) fs.FileInfo {
	a := altInfo{i, i.Size(), i.Mode(), i.ModTime(), i.Sys()}
	f(&a)
	return a
}

// swapStatFS keeps the Lstat of its base; the file opened under target
// answers Stat with stat(info): the file was replaced between the two calls (T59).
type swapStatFS struct {
	fs.ReadLinkFS
	target string
	stat   func(fs.FileInfo) fs.FileInfo
}

type swapStatFile struct {
	fs.File
	info fs.FileInfo
}

func (f swapStatFile) Stat() (fs.FileInfo, error) { return f.info, nil }

func (s swapStatFS) Open(name string) (fs.File, error) {
	f, err := s.ReadLinkFS.Open(name)
	if err != nil || name != s.target {
		return f, err
	}
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	return swapStatFile{f, s.stat(info)}, nil
}

func TestReadRegularSameFile(t *testing.T) {
	files := map[string]string{"s/suite.yaml": suiteY, caseF: caseY, baselineFile: baselineText}
	dir := realTree(t, files, nil)
	twin := realTree(t, files, nil) // same names, sizes and modes, other files
	for name := range files {
		mtime := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
		for _, d := range []string{dir, twin} {
			if err := os.Chtimes(filepath.Join(d, filepath.FromSlash(name)), mtime, mtime); err != nil {
				t.Fatal(err)
			}
		}
	}
	load := func(fsys fs.FS, target string) error {
		if target == baselineFile {
			_, err := LoadBaseline(fsys, baselineFile)
			return err
		}
		_, err := LoadSuite(fsys, "s")
		return err
	}
	same := func(i fs.FileInfo) fs.FileInfo { return i }
	for target := range files {
		real := os.DirFS(dir).(fs.ReadLinkFS)
		mapped := fstest.MapFS(mapOf(files))
		twinInfo := func(i fs.FileInfo) fs.FileInfo {
			info, err := os.Stat(filepath.Join(twin, filepath.FromSlash(target)))
			if err != nil {
				t.Fatal(err)
			}
			return info
		}
		for name, c := range map[string]struct {
			fsys fs.FS
			ok   bool
		}{
			"dirfs":          {real, true},
			"mapfs":          {mapped, true},
			"dirfs_identity": {swapStatFS{real, target, same}, true},
			"mapfs_identity": {swapStatFS{mapped, target, same}, true},
			"mapfs_size":     {swapStatFS{mapped, target, func(i fs.FileInfo) fs.FileInfo { return alter(i, func(a *altInfo) { a.size++ }) }}, false},
			"mapfs_mode":     {swapStatFS{mapped, target, func(i fs.FileInfo) fs.FileInfo { return alter(i, func(a *altInfo) { a.mode = 0o600 }) }}, false},
			"mapfs_time": {swapStatFS{mapped, target, func(i fs.FileInfo) fs.FileInfo {
				return alter(i, func(a *altInfo) { a.mtime = a.mtime.Add(time.Second) })
			}}, false},
			"mapfs_sys_added":   {swapStatFS{mapped, target, func(i fs.FileInfo) fs.FileInfo { return alter(i, func(a *altInfo) { a.sys = struct{}{} }) }}, false},
			"dirfs_other_file":  {swapStatFS{real, target, twinInfo}, false},
			"dirfs_sys_removed": {swapStatFS{real, target, func(i fs.FileInfo) fs.FileInfo { return alter(i, func(a *altInfo) { a.sys = nil }) }}, false},
			"dirfs_size":        {swapStatFS{real, target, func(i fs.FileInfo) fs.FileInfo { return alter(i, func(a *altInfo) { a.size++ }) }}, false},
		} {
			err := load(c.fsys, target)
			if c.ok != (err == nil) {
				t.Errorf("%s, %s: %v", target, name, err)
			}
			if !c.ok && !errors.Is(err, ErrInvalidSuite) && !errors.Is(err, ErrInvalidBaseline) {
				t.Errorf("%s, %s: %v, want an invalid suite or baseline", target, name, err)
			}
		}
	}
}
