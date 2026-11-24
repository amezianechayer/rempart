package evals

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"go.yaml.in/yaml/v3"
)

// Obligations of M0-T22 closed by M2-T06: (s), (t), (v) and (by), (w), (y).

// TestWatchPatternCharset proves obligations (v) and (by) (threat T67): a
// watch pattern outside the closed set [a-z0-9._/*-] (upper case, blank,
// control character, ?, [ ], backslash, letter outside ASCII) is refused when
// the suite is loaded; the patterns of the repository stay admitted.
func TestWatchPatternCharset(t *testing.T) {
	for i, w := range []string{
		`[Internal/loops/**]`, `["internal/a b.go"]`, `["internal/a\tb.go"]`, `["internal/x?.go"]`,
		`["internal/[ab].go"]`, `["internal/a\\b.go"]`, `["internal/é.go"]`, `["internal/a\u0085b"]`,
	} {
		if _, err := LoadSuite(suiteFS("s/suite.yaml", suiteY+"watch: "+w+"\n"), "s"); !errors.Is(err, ErrInvalidSuite) {
			t.Errorf("pattern %d %s: %v, want ErrInvalidSuite", i, w, err)
		}
	}
	ok := "watch: [internal/loops/*.go, internal/graph/**, go.mod, evals/design/**, policies/design/**, schemas/graph/**]\n"
	if s, err := LoadSuite(suiteFS("s/suite.yaml", suiteY+ok), "s"); err != nil || len(s.Watch) != 6 {
		t.Errorf("admitted patterns: %+v, %v", s.Watch, err)
	}
}

// TestNeedleBackslashOutsideDoubleQuotes proves obligation (s) (threat T65):
// in contains and equals, a backslash outside double quotes (plain or single
// quoted scalar, at any depth) reads as an escape it is not and is refused;
// inside double quotes, escapes stay admitted.
func TestNeedleBackslashOutsideDoubleQuotes(t *testing.T) {
	for i, e := range []string{
		`{must_include: [{path: $.a, contains: a\nb}]}`,
		`{must_include: [{path: $.a, contains: 'a\tb'}]}`,
		`{must_not_include: [{path: $.a, contains: x\_y}]}`,
		`{must_include: [{path: $.a, equals: {k: 'x\y'}}]}`,
		`{must_include: [{path: $.a, equals: [ok, 'p\u0041']}]}`,
	} {
		if _, err := LoadSuite(suiteFS(caseF, edit(sc, e)), "s"); !errors.Is(err, ErrInvalidSuite) {
			t.Errorf("needle %d %s: %v, want ErrInvalidSuite", i, e, err)
		}
	}
	for i, e := range []string{
		`{must_include: [{path: $.a, contains: "a\\b"}]}`,
		`{must_include: [{path: $.a, contains: "a\tb"}]}`,
		`{must_include: [{path: $.a, equals: {k: "x\\y"}}]}`,
	} {
		if _, err := LoadSuite(suiteFS(caseF, edit(sc, e)), "s"); err != nil {
			t.Errorf("double-quoted needle %d %s: %v", i, e, err)
		}
	}
}

// TestNeedleLineLengthAndDoubleSpaces proves obligation (t) (threat T64):
// every line of a suite or case file holds at most 160 runes, except the
// lines of the opaque input of a case; two consecutive blanks in a needle of
// contains or equals, at any depth and in any style, are refused.
func TestNeedleLineLengthAndDoubleSpaces(t *testing.T) {
	long := strings.Repeat("é", 161)
	for i, c := range [][2]string{
		{caseF, edit(sc, `{must_include: [{path: $.a, contains: "a  b"}]}`)},
		{caseF, edit(sc, `{must_include: [{path: $.a, contains: a  b}]}`)},
		{caseF, edit(sc, `{must_not_include: [{path: $.a, equals: {k: "x  y"}}]}`)},
		{caseF, edit(sc, `{must_include: [{path: $.a, contains: "`+long+`"}]}`)},
		{caseF, caseY + "tags: [" + strings.Repeat("injection, ", 15) + "injection]\n"},
		{"s/suite.yaml", suiteY + "watch: [" + strings.Repeat("internal/loops/**, ", 9) + "internal/loops/**]\n"},
	} {
		if _, err := LoadSuite(suiteFS(c[0], c[1]), "s"); !errors.Is(err, ErrInvalidSuite) {
			t.Errorf("case %d: %v, want ErrInvalidSuite", i, err)
		}
	}
	for i, in := range []string{
		"input: {a: \"" + long + long + "\"}\n",
		"input:\n  request: \"" + long + long + "\"\n  replies:\n    - {\"summary\": \"" + long + "\"}\n",
	} {
		c := strings.Replace(caseY, "input: {a: 1}\n", in, 1)
		if _, err := LoadSuite(suiteFS(caseF, c), "s"); err != nil {
			t.Errorf("long input %d: %v (the input is opaque, not bounded per line)", i, err)
		}
	}
	if _, err := LoadSuite(suiteFS(caseF, edit(sc, `{must_include: [{path: $.a, contains: "a b c"}]}`)), "s"); err != nil {
		t.Errorf("single blanks: %v", err)
	}
}

// TestBaselineLoadedWithCaseRules proves obligation (w): a baseline is read
// with the rules of a case file (closed rune list, lines of 160 runes, one
// strict JSON document without duplicate key, exact keys, no unknown field);
// a baseline whose values Validate refuses is read, then reported first by
// Compare as the regression "baseline", every tolerance cancelled (decision
// pinned by TestRegressionDetected of cmd/rempart-evals).
func TestBaselineLoadedWithCaseRules(t *testing.T) {
	good, err := EncodeBaseline(base())
	if err != nil {
		t.Fatal(err)
	}
	const name = "s/baseline.json"
	load := func(data string) (Baseline, error) {
		return LoadBaseline(fstest.MapFS{name: {Data: []byte(data)}}, name)
	}
	if b, err := load(string(good)); err != nil || !reflect.DeepEqual(b, base()) {
		t.Fatalf("canonical baseline: %+v, %v", b, err)
	}
	g := string(good)
	replace := func(from, to string) string {
		if !strings.Contains(g, from) {
			t.Fatalf("canonical baseline lacks %q:\n%s", from, g)
		}
		return strings.Replace(g, from, to, 1)
	}
	for i, data := range []string{
		replace(`"loop": "L1"`, "\"loop\": \"L1\u200b\""),
		replace(`"loop": "L1"`, "\"loop\": \"L1\u202e\""),
		replace(`"loop": "L1"`, `"loop": "L1", "loop": "L2"`),
		replace(`"tolerances"`, `"Tolerances"`),
		replace(`"loop": "L1"`, `"loop": "L1", "extra": 1`),
		replace(`"model": "m1"`, `"model": "`+strings.Repeat("m", 170)+`"`),
		g + "{}",
		strings.Repeat("[", 100) + strings.Repeat("]", 100),
	} {
		if _, err := load(data); !errors.Is(err, ErrInvalidBaseline) {
			t.Errorf("baseline %d: %v, want ErrInvalidBaseline", i, err)
		}
	}
	out := base()
	out.Tolerances.SuccessRateDrop = 0.5
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	b, err := load(string(data) + "\n")
	if err != nil {
		t.Fatalf("out-of-range baseline: %v, want read", err)
	}
	if reg := Compare(b, out.Report); len(reg) == 0 || reg[0].Metric != "baseline" {
		t.Errorf("out-of-range baseline: regressions %+v, want baseline first", reg)
	}
}

// swapFS is the os.Root file system of a directory whose Open answers for
// name with another regular file of the same content (the file swapped
// between Lstat and Open).
type swapFS struct {
	fs.ReadLinkFS
	name, decoy string
}

func (s swapFS) Open(name string) (fs.File, error) {
	if name == s.name {
		name = s.decoy
	}
	return s.ReadLinkFS.Open(name)
}

// TestSuiteRootedSameFile proves obligation (y) (TOCTOU): on the file system
// of an os.Root, a case file or a baseline whose opened file is not the file
// checked by Lstat (os.SameFile) is refused, even when the opened file is a
// regular file with the same content; the same tree without swap loads.
func TestSuiteRootedSameFile(t *testing.T) {
	dir := t.TempDir()
	good, err := EncodeBaseline(base())
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"s/suite.yaml": []byte(suiteY), caseF: []byte(caseY), "s/decoy.yaml": []byte(caseY),
		"s/baseline.json": good, "s/decoy.json": good,
	} {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if s, err := LoadSuite(root.FS(), "s"); err != nil || len(s.Cases) != 1 {
		t.Fatalf("control suite: %+v, %v", s, err)
	}
	if _, err := LoadBaseline(root.FS(), "s/baseline.json"); err != nil {
		t.Fatalf("control baseline: %v", err)
	}
	rfs, ok := root.FS().(fs.ReadLinkFS)
	if !ok {
		t.Fatal("os.Root.FS is not a ReadLinkFS")
	}
	if _, err := LoadSuite(swapFS{rfs, caseF, "s/decoy.yaml"}, "s"); !errors.Is(err, ErrInvalidSuite) {
		t.Errorf("swapped case file: %v, want ErrInvalidSuite", err)
	}
	if _, err := LoadBaseline(swapFS{rfs, "s/baseline.json", "s/decoy.json"}, "s/baseline.json"); !errors.Is(err, ErrInvalidBaseline) {
		t.Errorf("swapped baseline: %v, want ErrInvalidBaseline", err)
	}
}

// TestOpaqueInputIsBlockOnly proves obligations (fw) and (fz) (review of
// M2-T06, T64): a case or suite whose top level is a flow mapping, or whose
// content starts on the "---" line, is refused, so expect can never share a
// line with input; the lines of the input value stay free of the 160-rune
// bound but carry no run of blanks after their indentation and at most 4096
// runes; the exemption never covers more lines than the file holds.
func TestOpaqueInputIsBlockOnly(t *testing.T) {
	pad := strings.Repeat(" ", 200)
	for i, c := range [][2]string{
		{caseF, "{id: c-001, loop: L1, expect: {status: converged," + pad + "must_not_include: [{path: $.a, contains: x}]}, input: {a: 1}}\n"},
		{caseF, "{id: c-001, loop: L1, expect: {status: converged}, input: {a: 1}}\n"},
		{caseF, "{id: c-001, loop: L1, expect: {status: converged}, input: {a: 1},\n loop2: x}\n"},
		{caseF, "--- {id: c-001, loop: L1, input: {a: 1}, expect: {status: converged}}\n"},
		{caseF, "--- id: c-001\nloop: L1\ninput: {a: 1}\nexpect: {status: converged}\n"},
		{"s/suite.yaml", "{name: s, loop: L1, target: fake}\n"},
		{caseF, strings.Replace(caseY, "input: {a: 1}\n", "input:\n  request: \"x"+pad+"y\"\n", 1)},
		{caseF, strings.Replace(caseY, "input: {a: 1}\n", "input:\n  request: \""+strings.Repeat("é", 4097)+"\"\n", 1)},
	} {
		if _, err := LoadSuite(suiteFS(c[0], c[1]), "s"); !errors.Is(err, ErrInvalidSuite) {
			t.Errorf("case %d: %v, want ErrInvalidSuite", i, err)
		}
	}
	if _, err := LoadSuite(suiteFS(caseF, "---\n"+caseY), "s"); err != nil {
		t.Errorf("a bare document marker: %v", err)
	}
	last := "id: c-001\nloop: L1\nexpect: {status: converged}\ninput:\n  request: \"" + strings.Repeat("é", 300) + "\"\n"
	if _, err := LoadSuite(suiteFS(caseF, last), "s"); err != nil {
		t.Fatalf("input as the last key: %v", err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(last), &doc); err != nil {
		t.Fatal(err)
	}
	if got := opaqueLines(&doc, strings.Count(last, "\n")+1); len(got) > strings.Count(last, "\n")+1 {
		t.Errorf("opaqueLines covers %d lines of a %d-line file", len(got), strings.Count(last, "\n")+1)
	}
}
