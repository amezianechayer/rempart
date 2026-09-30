package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/amezianechayer/rempart/internal/evals"
)

// Exit codes (D8).
const (
	codeOK         = 0
	codeRegression = 1
	codeUsage      = 2
	codeNoBaseline = 3
	codeExec       = 4
)

type env struct {
	repo    *os.Root          // repository root (D16)
	git     gitRunner         // D14; a fake in tests
	targets map[string]Target // targets(); a stub may be added in tests
	environ []string          // D3
}

// run opens the repository root on ".", uses the real git runner, targets()
// and os.Environ(), then calls runWith. Codes: D8.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	repo, err := os.OpenRoot(".")
	if err != nil {
		say(stderr, "evals : répertoire courant illisible.")
		return codeUsage
	}
	defer func() { _ = repo.Close() }()
	return runWith(ctx, env{repo: repo, git: execGit, targets: targets(), environ: os.Environ()}, args, stdout, stderr)
}

// counted is a flag value that remembers how many times it was set (D12).
type counted struct {
	value string
	n     int
	bool  bool
}

func (c *counted) String() string { return c.value }
func (c *counted) Set(s string) error {
	c.value, c.n = s, c.n+1
	return nil
}
func (c *counted) IsBoolFlag() bool { return c.bool }

type options struct {
	suite, base string
	write       bool
}

func parseArgs(args []string, stderr io.Writer) (options, bool) {
	fs := flag.NewFlagSet("rempart-evals", flag.ContinueOnError)
	fs.SetOutput(stderr)
	suite, base, write := &counted{}, &counted{}, &counted{bool: true}
	fs.Var(suite, "suite", "suite name, all or changed")
	fs.Var(base, "base", "base commit (with changed)")
	fs.Var(write, "write-baseline", "write the baseline (humans only)")
	if fs.Parse(args) != nil {
		return options{}, false
	}
	named := suite.value != "all" && suite.value != "changed"
	_, nameErr := evals.BaselinePath(suite.value, "", "")
	switch {
	case fs.NArg() != 0 || suite.n != 1 || base.n > 1 || write.n > 1:
	case named && nameErr != nil:
	case (suite.value == "changed") != (base.n == 1):
	case write.n == 1 && (!named || write.value != "true"):
	default:
		return options{suite: suite.value, base: base.value, write: write.n == 1}, true
	}
	say(stderr, "evals : usage : --suite <nom|all|changed> [--base <sha> avec changed] [--write-baseline avec une suite nommée].")
	return options{}, false
}

func runWith(ctx context.Context, e env, args []string, stdout, stderr io.Writer) int {
	opts, ok := parseArgs(args, stderr)
	if !ok {
		return codeUsage
	}
	for _, kv := range e.environ {
		if k, _, _ := strings.Cut(kv, "="); k == "TEMPORAL_DEBUG" || strings.HasPrefix(k, "TEMPORAL_SDK_FLAG_") {
			say(stderr, "evals : variable TEMPORAL_DEBUG ou TEMPORAL_SDK_FLAG_* présente : refus (T84).")
			return codeUsage
		}
	}
	evalsRoot, ok := openEvals(e.repo, stderr)
	if !ok {
		return codeUsage
	}
	defer func() { _ = evalsRoot.Close() }()
	if opts.suite == "all" || opts.suite == "changed" {
		return runMany(ctx, e, evalsRoot, opts, stdout, stderr)
	}
	res := runSuite(ctx, e, evalsRoot, opts.suite, stderr, opts.write)
	if res.code == codeUsage || res.code == codeExec {
		return res.code
	}
	if opts.write {
		r := *res.report
		r.RegressionsVsBaseline = []evals.Regression{}
		p, err := writeBaseline(e.repo, opts.suite, res.id, r)
		if err != nil {
			say(stderr, "evals : écriture de la baseline refusée.")
			return codeUsage
		}
		if !emit(stdout, r) {
			return codeExec
		}
		say(stderr, "evals : baseline écrite : "+p)
		return codeOK
	}
	if res.code == codeOK || res.code == codeRegression {
		if !emit(stdout, res.report) {
			return codeExec
		}
	}
	return res.code
}

// openEvals applies D16: go.mod regular, evals a real directory, opened as a
// root that is the same directory.
func openEvals(repo *os.Root, stderr io.Writer) (*os.Root, bool) {
	gomod, err := repo.Lstat("go.mod")
	info, lerr := repo.Lstat("evals")
	if err != nil || !gomod.Mode().IsRegular() || lerr != nil || !info.IsDir() {
		say(stderr, "evals : lancer depuis la racine du dépôt (go.mod et répertoire evals réel requis).")
		return nil, false
	}
	root, err := repo.OpenRoot("evals")
	if err != nil {
		say(stderr, "evals : répertoire evals illisible.")
		return nil, false
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		_ = root.Close()
		say(stderr, "evals : répertoire evals remplacé pendant l'ouverture.")
		return nil, false
	}
	return root, true
}

type suiteResult struct {
	code   int
	report *evals.Report
	id     Identity
}

// runSuite: D9. A code 2 or 4 stops before the baseline; write skips the comparison.
func runSuite(ctx context.Context, e env, evalsRoot *os.Root, name string, stderr io.Writer, write bool) suiteResult {
	s, err := evals.LoadSuite(evalsRoot.FS(), name)
	if err != nil {
		say(stderr, "evals : suite "+name+" introuvable ou invalide.")
		return suiteResult{code: codeUsage}
	}
	t, ok := e.targets[s.Target]
	if !ok {
		say(stderr, "evals : suite "+name+" : cible inconnue.")
		return suiteResult{code: codeUsage}
	}
	runs := 0
	for _, c := range s.Cases {
		if t.Check(c) != nil {
			say(stderr, "evals : suite "+name+", cas "+c.ID+" : entrée refusée par la cible.")
			return suiteResult{code: codeUsage}
		}
		runs += c.Runs
	}
	_, _ = fmt.Fprintf(stderr, "evals : suite %s, cas %d, exécutions %d\n", name, len(s.Cases), runs)
	var grades []evals.Grade
	var outcomes []evals.Outcome
	for _, c := range s.Cases {
		for r := range c.Runs {
			o, err := t.Run(ctx, c, r)
			if err != nil {
				say(stderr, "evals : suite "+name+", cas "+c.ID+" : erreur d'exécution.")
				return suiteResult{code: codeExec}
			}
			g, err := evals.GradeOutcome(c, r, o)
			if err != nil {
				say(stderr, "evals : suite "+name+", cas "+c.ID+" : notation impossible.")
				return suiteResult{code: codeExec}
			}
			grades, outcomes = append(grades, g), append(outcomes, o)
		}
	}
	rep, err := evals.Aggregate(s, grades, outcomes)
	if err != nil {
		say(stderr, "evals : suite "+name+" : agrégation impossible.")
		return suiteResult{code: codeExec}
	}
	id := t.Identity()
	rep.Platform, rep.Region, rep.Model = id.Platform, id.Region, id.Model
	b, err := readBaseline(e.repo, name, id)
	switch {
	case errors.Is(err, evals.ErrNoBaseline):
		if write {
			return suiteResult{code: codeNoBaseline, report: &rep, id: id}
		}
		p, _ := evals.BaselinePath(name, id.Platform, id.Model)
		say(stderr, "evals : baseline absente pour la suite "+name+" ("+p+") : à créer par l'humain avec make update-baseline EVAL="+
			name+", puis à commiter (étape H3).")
		return suiteResult{code: codeNoBaseline, id: id}
	case err != nil:
		say(stderr, "evals : suite "+name+" : baseline illisible ou invalide.")
		return suiteResult{code: codeUsage}
	}
	rep.RegressionsVsBaseline = evals.Compare(b, rep)
	if len(rep.RegressionsVsBaseline) > 0 {
		return suiteResult{code: codeRegression, report: &rep, id: id}
	}
	return suiteResult{code: codeOK, report: &rep, id: id}
}

type selectionDoc struct {
	Selection struct {
		Mode     string `json:"mode"`
		Fallback string `json:"fallback"`
	} `json:"selection"`
	Suites []suiteEntry `json:"suites"`
}

type suiteEntry struct {
	Suite  string        `json:"suite"`
	Code   int           `json:"code"`
	Report *evals.Report `json:"report"`
}

// runMany: all and changed (D10, D13 to D17).
func runMany(ctx context.Context, e env, evalsRoot *os.Root, opts options, stdout, stderr io.Writer) int {
	names, err := evals.DiscoverSuites(evalsRoot.FS())
	if err != nil {
		say(stderr, "evals : découverte des suites refusée.")
		return codeUsage
	}
	suites := make([]evals.Suite, 0, len(names))
	for _, n := range names {
		s, err := evals.LoadSuite(evalsRoot.FS(), n)
		if err != nil {
			say(stderr, "evals : suite "+n+" invalide.")
			return codeUsage
		}
		suites = append(suites, s)
	}
	var doc selectionDoc
	doc.Selection.Mode = opts.suite
	doc.Suites = []suiteEntry{}
	if opts.suite == "changed" {
		paths, reason, ok := changedPaths(ctx, e.git, e.repo.Name(), opts.base)
		if ok {
			suites = evals.SelectChanged(suites, paths)
		}
		doc.Selection.Fallback = reason
	}
	worst := codeOK
	for _, s := range suites {
		res := runSuite(ctx, e, evalsRoot, s.Name, stderr, false)
		if res.code == codeUsage {
			return codeUsage
		}
		doc.Suites = append(doc.Suites, suiteEntry{Suite: s.Name, Code: res.code, Report: res.report})
		worst = worse(worst, res.code)
	}
	if !emit(stdout, doc) {
		return codeExec
	}
	return worst
}

// worse orders codes 4, 3, 1, 0 (D8).
func worse(a, b int) int {
	rank := map[int]int{codeOK: 0, codeRegression: 1, codeNoBaseline: 2, codeExec: 3}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

func emit(w io.Writer, v any) bool {
	return json.NewEncoder(w).Encode(v) == nil
}

func say(w io.Writer, msg string) { _, _ = fmt.Fprintln(w, msg) }
