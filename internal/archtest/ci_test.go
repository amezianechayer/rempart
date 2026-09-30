package archtest

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"go.yaml.in/yaml/v3"
)

// M0-T04 (docs/plans/M0-ci.md), threats T6, T32, T82. Synthetic SHAs.
const (
	ciPath  = ".github/workflows/verify.yml"
	ciBase  = "${{ github.event.pull_request.base.sha || github.event.before }}"
	ciGroup = "github.event.pull_request.number || github.ref"
	ciSHAA  = "0123456789abcdef0123456789abcdef01234567"
	ciSHAB  = "89abcdef0123456789abcdef0123456789abcdef"
)

const validCIWorkflow = `name: verify

on:
  pull_request:
  push:
    branches:
      - main

permissions:
  contents: read

concurrency:
  group: verify-${{ ` + ciGroup + ` }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

jobs:
  verify:
    name: verify
    runs-on: ubuntu-24.04
    timeout-minutes: 45
    permissions:
      contents: read
    env:
      GOTOOLCHAIN: local
    steps:
      - name: Checkout
        uses: actions/checkout@` + ciSHAA + ` # v5.0.0
        with:
          fetch-depth: 0
          persist-credentials: false
      - name: Set up Go
        uses: actions/setup-go@` + ciSHAB + ` # v6.0.0
        with:
          go-version-file: go.mod
          cache: false
      - name: Install golangci-lint
        run: go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2
      - name: Docker preflight
        run: make -f Makefile dev-preflight
      - name: make verify
        env:
          EVAL_BASE: ` + ciBase + `
        run: make -f Makefile verify
      - name: Stop the dev stack
        if: always()
        run: make -f Makefile dev-down
`

type ciWorkflow struct {
	Name        string
	On          map[string]*struct{ Branches []string }
	Permissions map[string]string
	Concurrency struct {
		Group  string
		Cancel string `yaml:"cancel-in-progress"`
	}
	Jobs map[string]struct {
		Name        string
		RunsOn      string `yaml:"runs-on"`
		Timeout     int    `yaml:"timeout-minutes"`
		Permissions map[string]string
		Env         map[string]string
		Steps       []struct {
			Name, If, Uses, Run string
			With, Env           map[string]string
		}
	}
}

func parseCIWorkflow(src string) (wf ciWorkflow, err error) {
	dec := yaml.NewDecoder(strings.NewReader(src))
	var doc yaml.Node
	if err = dec.Decode(&doc); err == nil {
		if !errors.Is(dec.Decode(new(yaml.Node)), io.EOF) {
			err = errors.New("second YAML document")
		} else if err = checkComposeNode(&doc); err == nil {
			strict := yaml.NewDecoder(strings.NewReader(src))
			strict.KnownFields(true)
			err = strict.Decode(&wf)
		}
	}
	if err != nil {
		err = fmt.Errorf("%s: %w", ciPath, err)
	}
	return wf, err
}

func checkCITriggers(wf ciWorkflow, _ string) (p problemList) {
	if k := slices.Sorted(maps.Keys(wf.On)); !slices.Equal(k, []string{"pull_request", "push"}) {
		p.addf("triggers %q, want exactly [pull_request push]", k)
	}
	if wf.On["pull_request"] != nil {
		p.addf("pull_request must have no filter")
	}
	if tr := wf.On["push"]; tr == nil || !slices.Equal(tr.Branches, []string{"main"}) {
		p.addf("push must be limited to branches [main]")
	}
	return p
}

func checkCIPermissions(wf ciWorkflow, _ string) (p problemList) {
	ro := map[string]string{"contents": "read"}
	if !maps.Equal(wf.Permissions, ro) {
		p.addf("top-level permissions %v", wf.Permissions)
	}
	for id, j := range wf.Jobs {
		if j.Permissions != nil && !maps.Equal(j.Permissions, ro) {
			p.addf("job %s permissions %v", id, j.Permissions)
		}
	}
	return p
}

func checkCIPinned(wf ciWorkflow, src string) (p problemList) {
	allowed := []string{"actions/checkout", "actions/setup-go"}
	var got []string
	for _, j := range wf.Jobs {
		for _, s := range j.Steps {
			if s.Uses != "" {
				name, sha, _ := strings.Cut(s.Uses, "@")
				if !slices.Contains(allowed, name) || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(sha) {
					p.addf("uses %q: want %q pinned by a 40-hex commit SHA", s.Uses, allowed)
				}
				got = append(got, name)
			}
		}
	}
	if slices.Sort(got); !slices.Equal(got, allowed) {
		p.addf("actions %q, want each exactly once", got)
	}
	line := regexp.MustCompile(`^ *(- )?uses: [a-z0-9-]+/[a-z0-9._-]+@[0-9a-f]{40} # v[0-9]+\.[0-9]+\.[0-9]+$`)
	for i, l := range strings.Split(src, "\n") {
		if strings.Contains(l, "uses:") && !line.MatchString(l) {
			p.addf("line %d: want uses: owner/repo@<sha> # vX.Y.Z", i+1)
		}
	}
	return p
}

func checkCIVerify(wf ciWorkflow, golangci string) (p problemList) {
	j, ok := wf.Jobs["verify"]
	if len(wf.Jobs) != 1 || !ok || wf.Name != "verify" || j.Name != "verify" {
		p.addf("want one workflow and one job, both named verify")
	}
	if j.RunsOn != "ubuntu-24.04" || j.Timeout < 1 || j.Timeout > 60 {
		p.addf("runs-on %q timeout-minutes %d", j.RunsOn, j.Timeout)
	}
	if !strings.Contains(wf.Concurrency.Group, ciGroup) || !maps.Equal(j.Env, map[string]string{"GOTOOLCHAIN": "local"}) {
		p.addf("concurrency group %q or job env %v", wf.Concurrency.Group, j.Env)
	}
	want := []string{
		"uses:actions/checkout", "uses:actions/setup-go",
		"run:go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@" + golangci,
		"run:make -f Makefile dev-preflight", "run:make -f Makefile verify", "run:make -f Makefile dev-down",
	}
	var got []string
	for i, s := range j.Steps {
		name, _, _ := strings.Cut(s.Uses, "@")
		step := "run:" + strings.TrimSpace(s.Run)
		if s.Uses != "" {
			step = "uses:" + name
		}
		got = append(got, step)
		if strings.Contains(s.Run, "${{") {
			p.addf("step %d: expression in run (template injection)", i+1)
		}
		var env map[string]string
		if step == "run:make -f Makefile verify" {
			env = map[string]string{"EVAL_BASE": ciBase}
		}
		if !maps.Equal(s.Env, env) {
			p.addf("step %d: env %v", i+1, s.Env)
		}
		if last := i == len(j.Steps)-1; last != (s.If == "always()") || !last && s.If != "" {
			p.addf("step %d: if %q, want always() on the last step only", i+1, s.If)
		}
		if name == "actions/checkout" && !maps.Equal(s.With, map[string]string{"fetch-depth": "0", "persist-credentials": "false"}) {
			p.addf("checkout with %v", s.With)
		}
	}
	if !slices.Equal(got, want) {
		p.addf("steps %q, want %q", got, want)
	}
	return p
}

func checkCINoSecrets(_ ciWorkflow, src string) (p problemList) {
	if regexp.MustCompile(`(?i)secrets|github\.token|github_token`).MatchString(src) {
		p.addf("the workflow names a secret or the workflow token")
	}
	return p
}

func checkCIGoVersion(wf ciWorkflow, _ string) (p problemList) {
	var with []map[string]string
	for _, j := range wf.Jobs {
		for _, s := range j.Steps {
			if strings.HasPrefix(s.Uses, "actions/setup-go@") {
				with = append(with, s.With)
			}
		}
		if j.Env["GOTOOLCHAIN"] != "local" {
			p.addf("GOTOOLCHAIN %q", j.Env["GOTOOLCHAIN"])
		}
	}
	if len(with) != 1 || !maps.Equal(with[0], map[string]string{"go-version-file": "go.mod", "cache": "false"}) {
		p.addf("setup-go with %v", with)
	}
	return p
}

func wants(s string) []string {
	return slices.DeleteFunc([]string{s}, func(x string) bool { return x == "" })
}

// runCI: valid control, (old, new, want) mutations ("err:": parse error), repository.
func runCI(t *testing.T, check, repo func(ciWorkflow, string) problemList, muts ...string) {
	t.Helper()
	muts = append([]string{"", "", ""}, muts...)
	for i := 0; i+2 < len(muts); i += 3 {
		t.Run(fmt.Sprint("m", i/3), func(t *testing.T) {
			src := validCIWorkflow
			if muts[i] != "" {
				src = mustReplace(t, src, muts[i], muts[i+1])
			}
			wf, err := parseCIWorkflow(src)
			if e, ok := strings.CutPrefix(muts[i+2], "err:"); ok {
				expectError(t, err, e)
			} else if err != nil {
				t.Fatal(err)
			} else {
				expectProblems(t, check(wf, src), wants(muts[i+2]))
			}
		})
	}
	_, fsys := repoRoot(t)
	src, err := readRepoFile(fsys, ciPath, "M0-T04")
	if err != nil {
		t.Fatal(err)
	}
	wf, err := parseCIWorkflow(src)
	if err != nil {
		t.Fatal(err)
	}
	reportProblems(t, repo(wf, src))
}

func TestCIWorkflowTriggers(t *testing.T) {
	_, fsys := repoRoot(t)
	for dir, want := range map[string]string{".github": "CODEOWNERS workflows", ".github/workflows": "verify.yml"} {
		entries, _ := fs.ReadDir(fsys, dir)
		var got []string
		for _, e := range entries {
			got = append(got, e.Name())
		}
		if strings.Join(got, " ") != want {
			t.Errorf("%s holds %q, want exactly %q", dir, got, want)
		}
	}
	runCI(t, checkCITriggers, checkCITriggers,
		"  pull_request:\n", "  pull_request_target:\n", "want exactly",
		"  push:\n", "  workflow_dispatch:\n  push:\n", "want exactly",
		"  pull_request:\n", "  pull_request:\n    branches:\n      - main\n", "no filter",
		"      - main\n", "      - '**'\n", "branches [main]",
		"  push:\n", "  push:\n    paths-ignore:\n      - docs\n", "err:paths-ignore not found")
}

func TestCIPermissionsReadOnly(t *testing.T) {
	const top = "\npermissions:\n  contents: read\n"
	runCI(t, checkCIPermissions, checkCIPermissions,
		top, "\npermissions:\n  contents: write\n", "top-level",
		top, "\npermissions: read-all\n", "err:cannot unmarshal",
		"      contents: read\n", "      contents: read\n      id-token: write\n", "job verify")
}

func TestCIActionsPinnedBySHA(t *testing.T) {
	const pinned = "pinned by a 40-hex commit SHA"
	runCI(t, checkCIPinned, checkCIPinned,
		"@"+ciSHAA, "@v5", pinned,
		"@"+ciSHAB, "@89abcde", pinned,
		ciSHAB+" # v6.0.0", ciSHAB, "want uses:",
		"actions/setup-go@", "actionz/setup-go@", "exactly once")
}

func TestCIRunsMakeVerify(t *testing.T) {
	_, fsys := repoRoot(t)
	setup, err := readRepoFile(fsys, "docs/SETUP.md", "M0")
	m := regexp.MustCompile(`golangci-lint@(v2\.[0-9]+\.[0-9]+)\b`).FindStringSubmatch(setup)
	if err != nil || m == nil {
		t.Fatalf("docs/SETUP.md: no golangci-lint@v2.x.y (%v)", err)
	}
	runCI(t,
		func(wf ciWorkflow, _ string) problemList { return checkCIVerify(wf, "v2.13.2") },
		func(wf ciWorkflow, _ string) problemList { return checkCIVerify(wf, m[1]) },
		"make -f Makefile verify\n", "make verify\n", "steps",
		"ubuntu-24.04", "ubuntu-latest", "runs-on",
		"        if: always()\n", "", "always()",
		ciBase, "${{ github.head_ref }}", "env map[EVAL_BASE",
		"dev-preflight\n", "dev-preflight ${{ github.head_ref }}\n", "template injection",
		"@v2.13.2", "@v2.13.1", "steps",
		"      GOTOOLCHAIN: local\n", "      GOTOOLCHAIN: local\n      MAKEFILES: x.mk\n", "job env",
		"          persist-credentials: false\n", "", "checkout with")
}

func TestCINoSecrets(t *testing.T) {
	const at = "          EVAL_BASE: "
	runCI(t, checkCINoSecrets, checkCINoSecrets,
		at, "          K: ${{ secrets.K }}\n"+at, "names a secret",
		at, "          K: ${{ github.token }}\n"+at, "names a secret")
}

func TestCIGoVersionFromGoMod(t *testing.T) {
	runCI(t, checkCIGoVersion, checkCIGoVersion,
		"go-version-file: go.mod", "go-version: stable", "setup-go with",
		"cache: false", "cache: true", "setup-go with",
		"GOTOOLCHAIN: local", "GOTOOLCHAIN: auto", `GOTOOLCHAIN "auto"`)
}

func checkCodeowners(src string) (p problemList, err error) {
	type rule struct {
		re     *regexp.Regexp
		owners []string
	}
	var rules []rule
	for i, raw := range strings.Split(src, "\n") {
		f := strings.Fields(raw)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if !regexp.MustCompile(`^/[A-Za-z0-9._/*-]+$`).MatchString(f[0]) {
			return nil, fmt.Errorf("line %d: pattern %q not supported", i+1, f[0])
		}
		for _, o := range f[1:] {
			if !regexp.MustCompile(`^@[A-Za-z0-9-]+(/[A-Za-z0-9._-]+)?$`).MatchString(o) {
				return nil, fmt.Errorf("line %d: owner %q not supported", i+1, o)
			}
		}
		expr := strings.NewReplacer(`\*\*`, ".*", `\*`, "[^/]*").Replace(regexp.QuoteMeta(strings.TrimSuffix(f[0][1:], "/")))
		rules = append(rules, rule{regexp.MustCompile("^" + expr + "(/.*)?$"), f[1:]})
	}
	for _, path := range []string{
		"CLAUDE.md", ".claude/settings.json", ".github/CODEOWNERS", ".github/workflows/verify.yml",
		"docs/decisions/0001-x.md", "Makefile", "evals/demo/baseline.json", "evals/demo/baseline/fake/m.json", "evals/demo/suite.yaml",
	} {
		var owners []string // the last matching rule wins
		for _, r := range rules {
			if r.re.MatchString(path) {
				owners = r.owners
			}
		}
		if !slices.Equal(owners, []string{"@amezianechayer"}) {
			p.addf("CODEOWNERS: %s is owned by %q", path, owners)
		}
	}
	return p, nil
}

func TestCodeownersProtectsBaselines(t *testing.T) {
	const valid = "# Human review.\n/CLAUDE.md @amezianechayer\n/.claude/ @amezianechayer\n/.github/ @amezianechayer\n" +
		"/evals/ @amezianechayer\n/docs/decisions/ @amezianechayer\n/Makefile @amezianechayer\n"
	for i, c := range [][2]string{
		{valid, ""},
		{mustReplace(t, valid, "/Makefile @amezianechayer\n", ""), "Makefile is owned by []"},
		{valid + "/evals/demo/\n", "evals/demo/baseline.json is owned by []"},
		{valid + "/evals/**/baseline* @x\n", "baseline/fake/m.json is owned by [\"@x\"]"},
		{valid + "evals/ @x\n", "err:pattern \"evals/\" not supported"},
		{valid + "/x @amezianechayer # note\n", "err:owner \"#\" not supported"},
	} {
		t.Run(fmt.Sprint("c", i), func(t *testing.T) {
			p, err := checkCodeowners(c[0])
			if e, ok := strings.CutPrefix(c[1], "err:"); ok {
				expectError(t, err, e)
			} else if err != nil {
				t.Fatal(err)
			} else {
				expectProblems(t, p, wants(c[1]))
			}
		})
	}
	_, fsys := repoRoot(t)
	src, err := readRepoFile(fsys, ".github/CODEOWNERS", "human, proposal 0007")
	if err != nil {
		t.Fatal(err)
	}
	p, err := checkCodeowners(src)
	if err != nil {
		t.Fatal(err)
	}
	reportProblems(t, p)
}

func checkNoShadowMakefile(fsys fs.FS) (p problemList) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		p.addf("repository root: %v", err)
	}
	for _, e := range entries {
		if n := e.Name(); n != "Makefile" && (strings.EqualFold(n, "makefile") || strings.EqualFold(n, "gnumakefile")) {
			p.addf("%s at the repository root would replace Makefile (T32)", n)
		}
	}
	return p
}

// TestNoShadowMakefile (T32): nothing at the repository root may replace the
// Makefile (a default makefile name) or, V3 D17, let GNU make remake it by a
// built-in implicit rule before any recipe, even under -n: Makefile.<suffix>
// (%: %.sh, %: %.c...), Makefile,v and RCS/ (RCS), s.Makefile and SCCS/ (SCCS).
// Subtests: map/<name> on a synthetic tree, dir/<name> on a real temporary
// directory, repository.
func TestNoShadowMakefile(t *testing.T) {
	const remade = "at the repository root lets GNU make remake Makefile by a built-in implicit rule (D17, T32)"
	type fsCase struct {
		name  string
		files fstest.MapFS // besides Makefile
		want  []string     // nil: conforming
	}
	file := func(name string) fstest.MapFS { return fstest.MapFS{name: {}} }
	dir := func(name string) fstest.MapFS { return fstest.MapFS{name: {Mode: fs.ModeDir | 0o755}} }
	cases := []fsCase{
		{name: "go_mod", files: file("go.mod")},
		{name: "scripts_dir", files: fstest.MapFS{"scripts/check-tools.sh": {}}},
		{name: "nested_makefile_sh", files: fstest.MapFS{"docs/Makefile.sh": {}, "scripts/RCS/Makefile,v": {}}},
		{name: "makefile_prefix_word", files: file("Makefiles")},
		{name: "GNUmakefile", files: file("GNUmakefile"), want: []string{"GNUmakefile at"}},
		{name: "makefile", files: file("makefile"), want: []string{"makefile at"}},
		{name: "GNUMakefile", files: file("GNUMakefile"), want: []string{"GNUMakefile at"}},
		// V3, D17 (third BLOCK): sources of a built-in rule remaking the Makefile.
		{name: "makefile_sh", files: file("Makefile.sh"), want: []string{"Makefile.sh " + remade}},
		{name: "makefile_c", files: file("Makefile.c"), want: []string{"Makefile.c " + remade}},
		{name: "makefile_o", files: file("Makefile.o"), want: []string{"Makefile.o " + remade}},
		{name: "makefile_bak", files: file("Makefile.bak"), want: []string{"Makefile.bak " + remade}},
		{name: "makefile_dot", files: file("Makefile."), want: []string{"Makefile. " + remade}},
		{name: "makefile_sh_dir", files: dir("Makefile.sh"), want: []string{"Makefile.sh " + remade}},
		{name: "makefile_sh_lower", files: file("makefile.sh"), want: []string{"makefile.sh " + remade}},
		{name: "rcs_file", files: file("Makefile,v"), want: []string{"Makefile,v " + remade}},
		{name: "sccs_file", files: file("s.Makefile"), want: []string{"s.Makefile " + remade}},
		{name: "rcs_dir", files: fstest.MapFS{"RCS/Makefile,v": {}}, want: []string{"RCS " + remade}},
		{name: "rcs_dir_empty", files: dir("RCS"), want: []string{"RCS " + remade}},
		{name: "sccs_dir", files: fstest.MapFS{"SCCS/s.Makefile": {}}, want: []string{"SCCS " + remade}},
		{name: "sccs_dir_empty", files: dir("SCCS"), want: []string{"SCCS " + remade}},
		{name: "all_at_once", files: fstest.MapFS{"Makefile.sh": {}, "Makefile,v": {}, "s.Makefile": {}, "RCS/x": {}, "SCCS/x": {}},
			want: []string{"Makefile.sh " + remade, "Makefile,v " + remade, "s.Makefile " + remade, "RCS " + remade, "SCCS " + remade}},
	}
	for _, c := range cases {
		t.Run("map/"+c.name, func(t *testing.T) {
			fsys := fstest.MapFS{"Makefile": {}}
			maps.Copy(fsys, c.files)
			problems := checkNoShadowMakefile(fsys)
			expectProblems(t, problems, c.want)
			if c.want != nil && len(problems) != len(c.want) {
				t.Errorf("%d problems, want %d (one per refused entry):\n%s", len(problems), len(c.want), strings.Join(problems, "\n"))
			}
		})
	}
	// The same check on a real directory (os.DirFS), as the repository is read:
	// the attack of the third BLOCK, then each RCS and SCCS form.
	for _, c := range []struct {
		name  string
		files []string // "d/" creates a directory
		want  []string
	}{
		{name: "conforming", files: []string{"go.mod", "scripts/"}},
		{name: "makefile_sh", files: []string{"Makefile.sh"}, want: []string{"Makefile.sh " + remade}},
		{name: "rcs", files: []string{"RCS/", "Makefile,v"}, want: []string{"RCS " + remade, "Makefile,v " + remade}},
		{name: "sccs", files: []string{"SCCS/", "s.Makefile"}, want: []string{"SCCS " + remade, "s.Makefile " + remade}},
	} {
		t.Run("dir/"+c.name, func(t *testing.T) {
			root := t.TempDir()
			for _, name := range append([]string{"Makefile"}, c.files...) {
				var err error
				if d, ok := strings.CutSuffix(name, "/"); ok {
					err = os.Mkdir(filepath.Join(root, d), 0o755)
				} else {
					err = os.WriteFile(filepath.Join(root, name), []byte("verify-quick:\n\t@echo fake\n"), 0o600)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			problems := checkNoShadowMakefile(os.DirFS(root))
			expectProblems(t, problems, c.want)
			if c.want != nil && len(problems) != len(c.want) {
				t.Errorf("%d problems, want %d:\n%s", len(problems), len(c.want), strings.Join(problems, "\n"))
			}
		})
	}
	t.Run("repository", func(t *testing.T) {
		_, fsys := repoRoot(t)
		reportProblems(t, checkNoShadowMakefile(fsys))
	})
}

// allCIChecks runs every workflow check on one decoded workflow.
func allCIChecks(wf ciWorkflow, src string) (p problemList) {
	for _, check := range []func(ciWorkflow, string) problemList{
		checkCITriggers, checkCIPermissions, checkCIPinned, checkCINoSecrets, checkCIGoVersion,
		func(wf ciWorkflow, _ string) problemList { return checkCIVerify(wf, "v2.13.2") },
	} {
		p = append(p, check(wf, src)...)
	}
	return p
}

// TestParseCIWorkflowDecoding lifts risk R6 of docs/plans/M0-ci.md: how
// go.yaml.in/yaml/v3 decodes the key "on", a key with a null value, the
// scalars 0 and false into string fields, and fields without a yaml tag. Its
// name does not start with TestCI so acceptance criterion 1 still counts 7.
func TestParseCIWorkflowDecoding(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		wf, err := parseCIWorkflow(validCIWorkflow)
		if err != nil {
			t.Fatal(err)
		}
		// "on" is a YAML 1.1 boolean: v3 must still decode it as the string key "on".
		if k := slices.Sorted(maps.Keys(wf.On)); !slices.Equal(k, []string{"pull_request", "push"}) {
			t.Errorf("on keys %q", k)
		}
		// A key with no value decodes to a nil pointer, a filter to a non-nil one.
		if wf.On["pull_request"] != nil || wf.On["push"] == nil || !slices.Equal(wf.On["push"].Branches, []string{"main"}) {
			t.Errorf("on %+v", wf.On)
		}
		if wf.Concurrency.Cancel != "${{ github.event_name == 'pull_request' }}" {
			t.Errorf("cancel-in-progress %q", wf.Concurrency.Cancel)
		}
		j := wf.Jobs["verify"]
		if len(j.Steps) != 6 || j.Timeout != 45 || j.RunsOn != "ubuntu-24.04" {
			t.Fatalf("job %+v", j)
		}
		// 0 and false decode into string fields as their literal text.
		if !maps.Equal(j.Steps[0].With, map[string]string{"fetch-depth": "0", "persist-credentials": "false"}) ||
			j.Steps[1].With["cache"] != "false" {
			t.Errorf("with %v %v", j.Steps[0].With, j.Steps[1].With)
		}
		// Untagged fields match their lowercased name.
		if s := j.Steps[5]; s.Name != "Stop the dev stack" || s.If != "always()" || s.Run == "" || j.Steps[0].Uses == "" {
			t.Errorf("untagged step fields %+v", s)
		}
		expectProblems(t, allCIChecks(wf, validCIWorkflow), nil)
	})

	// Spellings GitHub reads the same way: accepted, no problem.
	for i, m := range [][2]string{
		{"\non:\n", "\n'on':\n"},
		{"\non:\n", "\n\"on\":\n"},
		{"  pull_request:\n", "  pull_request: ~\n"},
		{"  pull_request:\n", "  pull_request: null\n"},
		{"cache: false", "cache: 'false'"},
		{"fetch-depth: 0", "fetch-depth: '0'"},
	} {
		t.Run(fmt.Sprint("same", i), func(t *testing.T) {
			src := mustReplace(t, validCIWorkflow, m[0], m[1])
			wf, err := parseCIWorkflow(src)
			if err != nil {
				t.Fatal(err)
			}
			expectProblems(t, allCIChecks(wf, src), nil)
		})
	}

	// Rejected by the parser: unknown or miscased keys (strict decoding), wrong
	// shapes, and the YAML features that could hide a key from the checks.
	for i, m := range [][3]string{
		{"\non:\n", "\nOn:\n", "field On not found"},
		{"\non:\n", "\ntrue:\n", "field true not found"},
		{"on:\n  pull_request:\n  push:\n    branches:\n      - main\n", "on: [pull_request, push]\n", "cannot unmarshal !!seq"},
		{"  pull_request:\n", "  pull_request: \"\"\n", "cannot unmarshal !!str"},
		{"  pull_request:\n", "  pull_request:\n    types: [opened]\n", "field types not found"},
		{"runs-on: ubuntu-24.04", "runs_on: ubuntu-24.04", "field runs_on not found"},
		{"runs-on: ubuntu-24.04", "runs-on: [self-hosted]", "cannot unmarshal !!seq"},
		{"timeout-minutes: 45", "timeout-minutes: '45'", "cannot unmarshal !!str"},
		{"      - name: Checkout\n", "      - Name: Checkout\n", "field Name not found"},
		{"\npermissions:\n", "\nenv:\n  MAKEFILES: x.mk\npermissions:\n", "field env not found"},
		{"\npermissions:\n", "\ndefaults:\n  run:\n    shell: sh\npermissions:\n", "field defaults not found"},
		{"    runs-on:", "    container: alpine\n    runs-on:", "field container not found"},
		{"    runs-on:", "    strategy:\n      matrix:\n        x: [1]\n    runs-on:", "field strategy not found"},
		{"    runs-on:", "    if: false\n    runs-on:", "field if not found"},
		{"        run: make -f Makefile verify\n", "        shell: sh\n        run: make -f Makefile verify\n", "field shell not found"},
		{"        run: make -f Makefile verify\n", "        continue-on-error: true\n        run: make -f Makefile verify\n", "field continue-on-error not found"},
		{"        run: make -f Makefile verify\n", "        run: make -f Makefile verify\n        run: true\n", "duplicate key \"run\""},
		{"      GOTOOLCHAIN: local\n", "      GOTOOLCHAIN: local\n      GOTOOLCHAIN: auto\n", "duplicate key \"GOTOOLCHAIN\""},
		{"      GOTOOLCHAIN: local\n", "      GOTOOLCHAIN: &t local\n", "anchor &t not allowed"},
		{"cache: false", "cache: !!str false", "explicit tag"},
		{"        run: make -f Makefile dev-down\n", "        run: make -f Makefile dev-down\n---\nname: x\n", "second YAML document"},
	} {
		t.Run(fmt.Sprint("reject", i), func(t *testing.T) {
			_, err := parseCIWorkflow(mustReplace(t, validCIWorkflow, m[0], m[1]))
			expectError(t, err, m[2])
		})
	}

	// Decoded, then flagged: the checks, not the decoder, reject these values.
	for i, m := range [][3]string{
		{"  pull_request:\n", "  pull_request: {}\n", "no filter"},
		{"on:\n  pull_request:\n  push:\n    branches:\n      - main\n", "on:\n", "want exactly"},
		{"  push:\n    branches:\n      - main\n", "  push:\n", "branches [main]"},
		{"cache: false", "cache: no", "setup-go with"},
		{"fetch-depth: 0", "fetch-depth: 00", "checkout with"},
		{"persist-credentials: false", "persist-credentials: False", "checkout with"},
	} {
		t.Run(fmt.Sprint("flag", i), func(t *testing.T) {
			src := mustReplace(t, validCIWorkflow, m[0], m[1])
			wf, err := parseCIWorkflow(src)
			if err != nil {
				t.Fatal(err)
			}
			expectProblems(t, allCIChecks(wf, src), wants(m[2]))
		})
	}
}
