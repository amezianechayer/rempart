# M0-T04 `ci` : GitHub Actions exécutant `make verify` sur chaque PR

- Date : 2026-09-29. Auteur : `architect`. Statut : proposé.
- Sources : fiche M0-T04 et H1 (`docs/plans/M0-overview.md`), `Makefile`, `scripts/dev-preflight.sh`, `docs/SETUP.md`, `.github/CODEOWNERS` (0005), `docs/STATUS.md` (T32), menaces T6 et T32.

## 1. Objectif et périmètre

Chaque PR et chaque push sur `main` exécutent `make -f Makefile verify` sur un runner GitHub, chaîne d'approvisionnement durcie (dépôt public, T6).

Dans le périmètre : `.github/workflows/verify.yml` ; `internal/archtest/ci_test.go` (7 tests de la fiche, `TestNoShadowMakefile` pour T32) ; proposition `docs/proposals/0007-ci-makefile-codeowners.md` (agent principal).

Hors périmètre : `.github/CODEOWNERS` (protégé par `guard_edit.py`, lu tel quel) ; Dependabot ; OPA en CI (aucun `.rego` en M0, `opa-test` échoue fermé ensuite) ; lecture de `EVAL_BASE` par le `Makefile` (T23) ; H1. Ni API Go, ni dépendance, ni ADR (réversible par une PR revue par le propriétaire de `/.github/`).

## 2. Décisions (option la plus stricte)

- D1 : `pull_request` sans filtre, `push` sur `main` ; jamais `pull_request_target`, `workflow_run`, `workflow_dispatch`, filtre de chemins.
- D2 : `permissions: contents: read` (workflow et job), `persist-credentials: false`, aucune mention de `secrets`, `github.token`, `GITHUB_TOKEN`.
- D3 : deux actions (`actions/checkout`, `actions/setup-go`) épinglées par SHA de commit suivi de `# vX.Y.Z` ; golangci-lint par `go install ...@v2.13.2` (vérifié par `sum.golang.org`), version lue dans `docs/SETUP.md`.
- D4 : `go-version-file: go.mod`, `cache: false` (pas de cache empoisonnable), `GOTOOLCHAIN: local`.
- D5 : `make -f Makefile` partout, aucune autre variable de job (`MAKEFILES`, `GOFLAGS`). Sans `-f`, make et chaque `$(MAKE)` récursif lisent d'abord `GNUmakefile` puis `makefile`.
- D6 : `EVAL_BASE` = SHA de base (`pull_request.base.sha`, sinon `before`) par `env`, jamais `${{ }}` dans un `run`.
- D7 : `ubuntu-24.04`, `timeout-minutes: 45`, `concurrency` par PR.
- D8 : `.github/` contient exactement `CODEOWNERS` et `workflows/verify.yml`.
- D9 : `/Makefile` exigé dans `CODEOWNERS` (T32), prérequis humain (0007).

## 3. Runner et `dev-preflight`

`ubuntu-24.04` fournit Docker Engine et compose v2, contexte `default` sur `unix:///var/run/docker.sock`, `DOCKER_HOST` non défini, `runner` dans le groupe `docker` : socket local et démon passent. Version 28 ou plus : 28.x à la date de connaissance, à confirmer avant H1 par `gh api repos/actions/runner-images/contents/images/ubuntu/Ubuntu2404-Readme.md --jq .content | base64 -d | grep -i docker`. Sinon l'étape `Docker preflight` échoue tôt ; pas d'installation de Docker sans décision humaine. `bash`, `od`, `tr` présents.

## 4. Code de référence

Indentation à deux espaces dans ce plan ; `gofumpt` rétablit les tabulations.

### 4.1 `.github/workflows/verify.yml`

Texte exact de `validCIWorkflow` (4.2), précédé des deux lignes ci-dessous, avec les SHA et versions de la section 5 à la place de `ciSHAA`, `v5.0.0`, `ciSHAB`, `v6.0.0` :

```yaml
# M0-T04: make verify on every pull request and on main (docs/plans/M0-ci.md).
# Actions pinned by commit SHA; read-only token; no credential of any kind.
```

### 4.2 `internal/archtest/ci_test.go`

Réutilise `repoRoot`, `readRepoFile`, `problemList`, `expectProblems`, `expectError`, `reportProblems`, `mustReplace`, `checkComposeNode` (ancres, alias, fusions, étiquettes, doublons refusés).

```go
package archtest

import (
  "errors"
  "fmt"
  "io"
  "io/fs"
  "maps"
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

// Closed schema (KnownFields): any other key (services, container,
// continue-on-error, paths-ignore, job-level uses) is a decoding error.
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
      err = errors.New("second YAML document not allowed")
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

var (
  ciSHARe  = regexp.MustCompile(`^[0-9a-f]{40}$`)
  ciUsesRe = regexp.MustCompile(`^ *(- )?uses: [a-z0-9-]+/[a-z0-9._-]+@[0-9a-f]{40} # v[0-9]+\.[0-9]+\.[0-9]+$`)
)

func checkCITriggers(wf ciWorkflow, _ string) (p problemList) {
  if k := slices.Sorted(maps.Keys(wf.On)); !slices.Equal(k, []string{"pull_request", "push"}) {
    p.addf("triggers %q, want exactly [pull_request push]", k)
  }
  if wf.On["pull_request"] != nil {
    p.addf("trigger pull_request must have no filter")
  }
  if tr := wf.On["push"]; tr == nil || !slices.Equal(tr.Branches, []string{"main"}) {
    p.addf("trigger push must be limited to branches [main]")
  }
  return p
}

func checkCIPermissions(wf ciWorkflow, _ string) (p problemList) {
  ro := map[string]string{"contents": "read"}
  if !maps.Equal(wf.Permissions, ro) {
    p.addf("top-level permissions %v, want contents: read", wf.Permissions)
  }
  for id, j := range wf.Jobs {
    if j.Permissions != nil && !maps.Equal(j.Permissions, ro) {
      p.addf("job %s permissions %v, want contents: read", id, j.Permissions)
    }
    for _, s := range j.Steps {
      if strings.HasPrefix(s.Uses, "actions/checkout@") && s.With["persist-credentials"] != "false" {
        p.addf("actions/checkout must set persist-credentials: false")
      }
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
        if !slices.Contains(allowed, name) || !ciSHARe.MatchString(sha) {
          p.addf("uses %q: want one of %q pinned by a 40-hex commit SHA", s.Uses, allowed)
        }
        got = append(got, name)
      }
    }
  }
  if slices.Sort(got); !slices.Equal(got, allowed) {
    p.addf("actions %q, want each of %q exactly once", got, allowed)
  }
  for i, l := range strings.Split(src, "\n") {
    if strings.Contains(l, "uses:") && !ciUsesRe.MatchString(l) {
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
    p.addf("runs-on %q timeout-minutes %d, want ubuntu-24.04 and 1 to 60", j.RunsOn, j.Timeout)
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
      p.addf("step %d: env %v, want %v", i+1, s.Env, env)
    }
    if last := i == len(j.Steps)-1; last != (s.If == "always()") || !last && s.If != "" {
      p.addf("step %d: if %q, want always() on the last step only", i+1, s.If)
    }
    if name == "actions/checkout" && !maps.Equal(s.With, map[string]string{"fetch-depth": "0", "persist-credentials": "false"}) {
      p.addf("checkout with %v", s.With)
    }
  }
  if !slices.Equal(got, want) {
    p.addf("steps %q, want exactly %q", got, want)
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
      p.addf("GOTOOLCHAIN %q, want local", j.Env["GOTOOLCHAIN"])
    }
  }
  if len(with) != 1 || !maps.Equal(with[0], map[string]string{"go-version-file": "go.mod", "cache": "false"}) {
    p.addf("setup-go with %v, want once go-version-file: go.mod and cache: false", with)
  }
  return p
}

// checkGithubDir: closed lists (a second workflow could use pull_request_target).
func checkGithubDir(fsys fs.FS) (p problemList) {
  for dir, want := range map[string][]string{".github": {"CODEOWNERS", "workflows"}, ".github/workflows": {"verify.yml"}} {
    entries, err := fs.ReadDir(fsys, dir)
    var got []string
    for _, e := range entries {
      got = append(got, e.Name())
    }
    if err != nil || !slices.Equal(got, want) {
      p.addf("%s holds %q (%v), want exactly %q", dir, got, err, want)
    }
  }
  return p
}

func wants(s string) []string { return slices.DeleteFunc([]string{s}, func(x string) bool { return x == "" }) }

// runCI checks validCIWorkflow, then each (old, new, want) mutation (want: a
// problem substring, or "err:" and a parse error substring), then repo on the
// repository workflow.
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
  src, err := readRepoFile(fsys, ciPath, "created by M0-T04")
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
  fsys := fstest.MapFS{".github/CODEOWNERS": {}, ".github/workflows/verify.yml": {}}
  expectProblems(t, checkGithubDir(fsys), nil)
  fsys[".github/workflows/x.yml"] = &fstest.MapFile{}
  expectProblems(t, checkGithubDir(fsys), []string{".github/workflows holds"})
  _, repo := repoRoot(t)
  reportProblems(t, checkGithubDir(repo))
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
    "      contents: read\n", "      contents: read\n      id-token: write\n", "job verify",
    "          persist-credentials: false\n", "", "persist-credentials")
}

func TestCIActionsPinnedBySHA(t *testing.T) {
  const pinned = "pinned by a 40-hex commit SHA"
  runCI(t, checkCIPinned, checkCIPinned,
    "@"+ciSHAA, "@v5", pinned,
    "@"+ciSHAB, "@89abcde", pinned,
    ciSHAA, strings.ToUpper(ciSHAA), pinned,
    ciSHAB+" # v6.0.0", ciSHAB, "want uses:",
    "actions/setup-go@", "actionz/setup-go@", "exactly once")
}

func TestCIRunsMakeVerify(t *testing.T) {
  _, fsys := repoRoot(t)
  setup, err := readRepoFile(fsys, "docs/SETUP.md", "M0")
  m := regexp.MustCompile(`golangci-lint@(v2\.[0-9]+\.[0-9]+)\b`).FindStringSubmatch(setup)
  if err != nil || m == nil {
    t.Fatalf("docs/SETUP.md: no pinned golangci-lint@v2.x.y (%v)", err)
  }
  runCI(t,
    func(wf ciWorkflow, _ string) problemList { return checkCIVerify(wf, "v2.13.2") },
    func(wf ciWorkflow, _ string) problemList { return checkCIVerify(wf, m[1]) },
    "make -f Makefile verify\n", "make verify\n", "steps",
    "ubuntu-24.04", "ubuntu-latest", "runs-on",
    "ubuntu-24.04", "[self-hosted]", "err:cannot unmarshal",
    "    timeout-minutes: 45\n", "", "timeout-minutes 0",
    "${{ "+ciGroup+" }}", "x", "concurrency",
    "        if: always()\n", "", "always()",
    "        if: always()\n", "        if: always()\n        continue-on-error: true\n", "err:not found",
    ciBase, "${{ github.head_ref }}", "env map[EVAL_BASE",
    "dev-preflight\n", "dev-preflight ${{ github.head_ref }}\n", "template injection",
    "@v2.13.2", "@v2.13.1", "steps",
    "      GOTOOLCHAIN: local\n", "      GOTOOLCHAIN: local\n      MAKEFILES: x.mk\n", "job env",
    "fetch-depth: 0", "fetch-depth: 1", "checkout with")
}

func TestCINoSecrets(t *testing.T) {
  const at = "          EVAL_BASE: "
  runCI(t, checkCINoSecrets, checkCINoSecrets,
    at, "          K: ${{ secrets.K }}\n"+at, "names a secret",
    at, "          K: ${{ github.token }}\n"+at, "names a secret",
    "run: make -f Makefile verify", "run: GITHUB_TOKEN=x make -f Makefile verify", "names a secret")
}

func TestCIGoVersionFromGoMod(t *testing.T) {
  const cache = "          cache: false\n"
  runCI(t, checkCIGoVersion, checkCIGoVersion,
    "go-version-file: go.mod", "go-version: stable", "setup-go with",
    cache, cache+"          check-latest: true\n", "setup-go with",
    "GOTOOLCHAIN: local", "GOTOOLCHAIN: auto", `GOTOOLCHAIN "auto"`)
  _, fsys := repoRoot(t)
  src, err := readRepoFile(fsys, "go.mod", "M0-T01")
  if err != nil || !regexp.MustCompile(`(?m)^go [0-9]+\.[0-9]+\.[0-9]+$`).MatchString(src) || strings.Contains(src, "\ntoolchain ") {
    t.Errorf("go.mod must declare go X.Y.Z and no toolchain line (%v)", err)
  }
}

// checkCodeowners reads "/anchored-pattern owner..." lines and comments only
// (negation, brackets, unanchored patterns, inline comments are errors); "**"
// crosses directories, "*" does not, a pattern covers everything below it. For
// each protected path, the last matching rule (owner-less: unset) must name
// exactly the human.
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
      return nil, fmt.Errorf("CODEOWNERS line %d: pattern %q not supported", i+1, f[0])
    }
    for _, o := range f[1:] {
      if !regexp.MustCompile(`^@[A-Za-z0-9-]+(/[A-Za-z0-9._-]+)?$`).MatchString(o) {
        return nil, fmt.Errorf("CODEOWNERS line %d: owner %q not supported", i+1, o)
      }
    }
    expr := strings.NewReplacer(`\*\*`, ".*", `\*`, "[^/]*").Replace(regexp.QuoteMeta(strings.TrimSuffix(f[0][1:], "/")))
    rules = append(rules, rule{regexp.MustCompile("^" + expr + "(/.*)?$"), f[1:]})
  }
  for _, path := range []string{
    "CLAUDE.md", ".claude/settings.json", ".claude/hooks/guard_edit.py", ".github/CODEOWNERS",
    ".github/workflows/verify.yml", "docs/decisions/0001-x.md", "Makefile", "evals/demo/baseline.json",
    "evals/demo/baseline/fake/m.json", "evals/demo/suite.yaml", "evals/demo/cases/c.yaml",
  } {
    var owners []string
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
    {mustReplace(t, valid, "/.github/ ", "/.github/CODEOWNERS "), "verify.yml is owned"},
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
  src, err := readRepoFile(fsys, ".github/CODEOWNERS", "human, proposals 0005 and 0007")
  if err != nil {
    t.Fatal(err)
  }
  p, err := checkCodeowners(src)
  if err != nil {
    t.Fatal(err)
  }
  reportProblems(t, p)
  for _, alt := range []string{"CODEOWNERS", "docs/CODEOWNERS"} {
    if _, err := fs.Stat(fsys, alt); err == nil {
      t.Errorf("%s exists: only .github/CODEOWNERS is allowed", alt)
    }
  }
}

// checkNoShadowMakefile (T32): make without -f, recursive $(MAKE) included,
// reads GNUmakefile then makefile before Makefile.
func checkNoShadowMakefile(fsys fs.FS) (p problemList) {
  entries, err := fs.ReadDir(fsys, ".")
  if err != nil {
    p.addf("repository root: %v", err)
  }
  for _, e := range entries {
    if n := e.Name(); n != "Makefile" && (strings.EqualFold(n, "makefile") || strings.EqualFold(n, "gnumakefile")) {
      p.addf("%s at the repository root would replace Makefile (threat T32)", n)
    }
  }
  return p
}

func TestNoShadowMakefile(t *testing.T) {
  for file, want := range map[string]string{"go.mod": "", "GNUmakefile": "GNUmakefile at", "makefile": "makefile at", "GNUMakefile": "GNUMakefile at"} {
    expectProblems(t, checkNoShadowMakefile(fstest.MapFS{"Makefile": {}, file: {}}), wants(want))
  }
  _, fsys := repoRoot(t)
  reportProblems(t, checkNoShadowMakefile(fsys))
}
```

À vérifier en phase tests : `go.yaml.in/yaml/v3` lit la clé `on` comme chaîne, garde une clé à valeur nulle (`pull_request:`), décode `0` et `false` dans un `string`, associe les champs sans étiquette aux clés en minuscules ; sinon ajouter des étiquettes, sans affaiblir un contrôle.

## 5. SHA des actions

Aucun SHA dans ce plan. L'agent principal passe par l'API GitHub (MCP `get_latest_release`, `list_tags`, `get_tag`, ou `gh api`), pour `actions/checkout` puis `actions/setup-go` :
1. Version : `gh api repos/actions/checkout/releases/latest --jq .tag_name` (au moins `v5.0.0` ; `v6.0.0` pour setup-go).
2. SHA : `gh api repos/actions/checkout/git/ref/tags/vX.Y.Z --jq '.object.type+" "+.object.sha'` ; type `tag` (annoté) : `gh api repos/actions/checkout/git/tags/<sha> --jq '.object.type+" "+.object.sha'` jusqu'à `commit`.
3. Seconde source : `list_tags` (`commit.sha`) ou `gh api repos/actions/checkout/commits/vX.Y.Z --jq .sha`, égalité exigée. Toujours un tag amont, jamais un SHA de fork (GitHub résout aussi le réseau de forks).
4. Runtime : `gh api 'repos/actions/checkout/contents/action.yml?ref=<sha>' --jq .content | base64 -d | grep -c 'using: .node24.'` : `1`.
5. Consigner action, tag, SHA et sorties dans `docs/STATUS.md` ; l'humain rejoue le critère 6.

## 6. Tests d'acceptation

1. `go test ./internal/archtest/ -run 'TestCI|TestCodeowners' -v 2>&1 | grep -c '^--- PASS'` : `7`.
2. `go test ./internal/archtest/ -run '^TestNoShadowMakefile$' -v 2>&1 | grep -c '^--- PASS'` : `1`.
3. `test "$(grep -c 'uses:' .github/workflows/verify.yml)" = "$(grep -Ec 'uses: [a-z0-9-]+/[a-z0-9._-]+@[0-9a-f]{40} # v[0-9]+\.[0-9]+\.[0-9]+$' .github/workflows/verify.yml)"; echo rc=$?` : `rc=0`.
4. `grep -Eci 'secrets|github\.token|github_token|pull_request_target|ciSHA|0123456789abcdef' .github/workflows/verify.yml` : `0`.
5. `grep -E 'run: .*make ' .github/workflows/verify.yml | grep -vc 'make -f Makefile '` : `0`.
6. `grep -Eo 'uses: [^@ ]+@[0-9a-f]{40} # v[0-9.]+' .github/workflows/verify.yml | while read -r _ ref _ tag; do r=${ref%@*}; [ "$(gh api "repos/$r/commits/$tag" --jq .sha)" = "${ref#*@}" ] && echo "ok $r" || echo "MISMATCH $r"; done` : `ok actions/checkout`, `ok actions/setup-go`.
7. `LC_ALL=C grep -c '[^[:print:]]' .github/workflows/verify.yml` : `0`.
8. `make verify-quick; echo rc=$?` : `rc=0`.
9. Après H1 : `gh run list --workflow verify.yml --limit 1 --json conclusion --jq '.[0].conclusion'` : `success` ; le journal (`gh run view <id> --log`) contient `dev-preflight : Docker Engine 28`.

Mutations, une à la fois, restaurées par `git checkout -- <fichier>` ou suppression ; `go test ./internal/archtest/ -run '^<Test>$'` finit par `FAIL`. Ancres uniques ; les mutations G compilent.
- W1 `  pull_request:` en `  pull_request_target:` : TestCIWorkflowTriggers.
- W2 `      contents: read` (6 espaces) en `      contents: write` ; W3 ligne `persist-credentials: false` supprimée : TestCIPermissionsReadOnly.
- W4 `actions/checkout@<sha>` en `actions/checkout@v5` : TestCIActionsPinnedBySHA.
- W5 `run: make -f Makefile verify` en `run: make verify` ; W6 `github.event.pull_request.base.sha || github.event.before` en `github.head_ref` ; W7 `ubuntu-24.04` en `ubuntu-latest` ; W8 ligne `if: always()` supprimée : TestCIRunsMakeVerify.
- W9 ligne `      K: ${{ secrets.K }}` après `      GOTOOLCHAIN: local` : TestCINoSecrets.
- W10 `go-version-file: go.mod` en `go-version: stable` : TestCIGoVersionFromGoMod.
- W11 `GNUmakefile` vide à la racine (sans lancer make) : TestNoShadowMakefile.
- G1 `owners = r.owners` suivi d'une ligne `break` : TestCodeownersProtectsBaselines (témoin `/evals/demo/`).
- G2 `` `^[0-9a-f]{40}$` `` en `` `^[0-9a-f]{7,40}$` `` : TestCIActionsPinnedBySHA (témoin `@89abcde`).
- G3 `|github\.token` supprimé : TestCINoSecrets.
- G4 `strings.Contains(s.Run, "${{")` en `strings.Contains(s.Run, "${{ secrets")` : TestCIRunsMakeVerify.
- G5 `strings.EqualFold(n, "gnumakefile")` en `n == "GNUmakefile"` : TestNoShadowMakefile (témoin `GNUMakefile`).

## 7. Risques

- R1 : image `ubuntu-24.04` avec un autre Docker : échec précoce et lisible.
- R2 : limite de Docker Hub : images épinglées par empreinte, échec visible.
- R3 : SHA vieillissants (runtime Node retiré, correctif) : revue humaine périodique.
- R4 : PR de fork exécutant du code non fiable : jeton en lecture, aucun identifiant, approbation des contributeurs externes (H1).
- R5 : `go install` dépend de `proxy.golang.org` et `sum.golang.org` : échec fermé.
- R6 : `EVAL_BASE` vu par make : T23 doit le figer (`override EVAL_BASE := $(value EVAL_BASE)`, `callerVariables()`) ; `before` hors historique : T23 lance toutes les suites.
- R7 : `TestCodeownersProtectsBaselines` rouge tant que 0007 n'est pas appliquée : l'impl attend l'humain.

## 8. Modèle de menace (écrit par l'agent principal)

- T6 : tests `TestCIActionsPinnedBySHA`, `TestCIGoVersionFromGoMod`.
- T32 : `TestNoShadowMakefile`, `-f Makefile` en CI (`TestCIRunsMakeVerify`), `/Makefile` dans CODEOWNERS et Stop hook en `-f Makefile` (0007).
- T82 (nouvelle, S, T, E) : CI détournée (`pull_request_target` ou `workflow_run` avec jeton en écriture, action à étiquette mobile ou SHA de fork, injection `${{ }}` dans `run`, cache empoisonné, second workflow, runner self-hosted). Mitigations D1 à D8 ; tests de la fiche et `checkGithubDir`.

## 9. Décisions ouvertes (défaut : le plus strict)

1. `pull_request` sans filtre (défaut) ou limité à `main`.
2. `go install` (défaut) ou `golangci/golangci-lint-action` épinglée.
3. `cache: false` (défaut, plus lent) ou cache de `setup-go`.
4. `/Makefile` exigé (défaut) ; si 0007 est refusée, retirer `"Makefile"` de `checkCodeowners` et consigner le résidu T32.
5. Docker inférieur à 28 : échec (défaut) ou `docker-ce` épinglé (ADR).
6. Dependabot : non (défaut) ; sinon ajout à la liste fermée de `checkGithubDir`.

## 10. Tâches ordonnées

1. (principal) `docs/proposals/0007-ci-makefile-codeowners.md` et `.patch` : `/Makefile @amezianechayer` dans `.github/CODEOWNERS`, `stop_verify.py` en `make -f Makefile verify-quick`, cas `test_hooks.sh` ; application par l'humain.
2. (tests, `test-author`) `ci_test.go` (4.2) : rouges, les 6 `TestCI*` et `TestCodeownersProtectsBaselines` avant 0007 ; `TestNoShadowMakefile` vert ; `go build ./...` vert.
3. (principal) SHA et versions (section 5), consignés dans `docs/STATUS.md`.
4. (impl, après 0007) `verify.yml` (4.1) ; critères 1 à 8.
5. `security-reviewer` (T6, T32, T82) ; `acceptance-verifier` : critères 1 à 8, mutations W1 à W11, G1 à G5.
6. (principal) T6, T32, T82 dans `docs/02-THREAT-MODEL.md` ; R6 et solde de T32 dans `docs/STATUS.md` ; CI dans `docs/SETUP.md`.
7. (humain, H1) Pousser, ouvrir la PR, rejouer le critère 6 ; protéger `main` (contrôle requis `verify`, "Require review from Code Owners", pas de push forcé) ; Actions : jeton par défaut en lecture, actions limitées à `actions/*` avec SHA obligatoire, approbation des workflows de contributeurs externes ; critère 9.
