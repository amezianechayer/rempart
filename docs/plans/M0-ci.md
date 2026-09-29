# M0-T04 `ci` : GitHub Actions exécutant `make verify` sur chaque PR

2026-09-29, `architect`, proposé. Sources : fiche M0-T04 et H1, `Makefile`, `scripts/dev-preflight.sh`, `docs/SETUP.md`, `.github/CODEOWNERS`, `docs/STATUS.md`, T6, T32.

## 1. Objectif et périmètre

Chaque PR et chaque push sur `main` exécutent `make -f Makefile verify` sur GitHub Actions, chaîne d'approvisionnement durcie (T6). Livrables : `.github/workflows/verify.yml`, `internal/archtest/ci_test.go` (7 tests de la fiche et `TestNoShadowMakefile`), proposition 0007. Hors périmètre : modifier `.github/CODEOWNERS` (protégé), Dependabot, OPA en CI, `EVAL_BASE` dans le `Makefile` (T23), H1. Ni API, ni dépendance, ni ADR.

## 2. Décisions (les plus strictes)

D1 `pull_request` sans filtre, `push` sur `main`, rien d'autre. D2 `contents: read`, `persist-credentials: false`, aucun secret ni jeton. D3 `actions/checkout`, `actions/setup-go` seulement, par SHA et `# vX.Y.Z` ; golangci-lint par `go install`, version de `docs/SETUP.md`. D4 `go-version-file: go.mod`, `cache: false`, `GOTOOLCHAIN: local`. D5 `make -f Makefile`, aucune autre variable. D6 `EVAL_BASE` = SHA de base par `env`, jamais `${{ }}` dans `run`. D7 `ubuntu-24.04`, 45 minutes, `concurrency`. D8 `.github/` = `CODEOWNERS`, `workflows/verify.yml`. D9 `/Makefile` dans `CODEOWNERS`.

## 3. Runner

`ubuntu-24.04` : Docker, compose v2, contexte `default` en socket unix local, `DOCKER_HOST` vide : `dev-preflight` passe si le moteur est en 28 ou plus (28.x à la date de connaissance, à confirmer avant H1 dans `Ubuntu2404-Readme.md` de `actions/runner-images`).

## 4. Code de référence

`verify.yml` = `validCIWorkflow` précédé de `# M0-T04: make verify on every pull request and on main.`, avec les SHA et versions de la section 5 au lieu de `ciSHAA`, `v5.0.0`, `ciSHAB`, `v6.0.0`. `ci_test.go`, indenté ici à deux espaces (`gofumpt` rétablit les tabulations), réutilise les aides de `repo_test.go` et `checkComposeNode` :

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

func wants(s string) []string { return slices.DeleteFunc([]string{s}, func(x string) bool { return x == "" }) }

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

func TestNoShadowMakefile(t *testing.T) {
  for file, want := range map[string]string{"go.mod": "", "GNUmakefile": "GNUmakefile at", "makefile": "makefile at", "GNUMakefile": "GNUMakefile at"} {
    expectProblems(t, checkNoShadowMakefile(fstest.MapFS{"Makefile": {}, file: {}}), wants(want))
  }
  _, fsys := repoRoot(t)
  reportProblems(t, checkNoShadowMakefile(fsys))
}
```

## 5. SHA des actions

Aucun SHA n'est écrit ici. Pour chaque action, l'agent principal (MCP GitHub ou `gh api`) : (1) `releases/latest`, au moins `v5.0.0` (checkout), `v6.0.0` (setup-go) ; (2) `gh api repos/OWNER/REPO/git/ref/tags/TAG --jq '.object.type+" "+.object.sha'`, déréférencé par `git/tags/<sha>` tant que le type est `tag` ; (3) seconde source égale : MCP `list_tags` (`commit.sha`), jamais un SHA de fork ; (4) `node24` dans `action.yml` à ce SHA ; (5) sorties dans `docs/STATUS.md`.

## 6. Tests d'acceptation

1. `go test ./internal/archtest/ -run 'TestCI|TestCodeowners' -v 2>&1 | grep -c '^--- PASS'` : `7`.
2. `go test ./internal/archtest/ -run '^TestNoShadowMakefile$' -v 2>&1 | grep -c '^--- PASS'` : `1`.
3. `test "$(grep -c 'uses:' .github/workflows/verify.yml)" = "$(grep -Ec 'uses: [a-z0-9-]+/[a-z0-9._-]+@[0-9a-f]{40} # v[0-9]+\.[0-9]+\.[0-9]+$' .github/workflows/verify.yml)"; echo rc=$?` : `rc=0`.
4. `grep -Eci 'secrets|github\.token|github_token|pull_request_target|0123456789abcdef' .github/workflows/verify.yml` : `0`.
5. `grep -Eo 'uses: [^@ ]+@[0-9a-f]{40} # v[0-9.]+' .github/workflows/verify.yml | while read -r _ ref _ tag; do r=${ref%@*}; [ "$(gh api "repos/$r/commits/$tag" --jq .sha)" = "${ref#*@}" ] && echo "ok $r" || echo "MISMATCH $r"; done` : `ok actions/checkout`, `ok actions/setup-go`.
6. `LC_ALL=C grep -c '[^[:print:]]' .github/workflows/verify.yml` : `0`.
7. `make verify-quick; echo rc=$?` : `rc=0`.
8. Après H1 : `gh run list --workflow verify.yml --limit 1 --json conclusion --jq '.[0].conclusion'` : `success` ; le journal contient `dev-preflight : Docker Engine 28`.

Mutations, une à la fois puis restaurées ; `go test ./internal/archtest/ -run '^<Test>$'` finit par `FAIL` (ancres uniques, G compilables) :
- TestCIWorkflowTriggers : W1 `  pull_request:` en `  pull_request_target:`.
- TestCIPermissionsReadOnly : W2 `      contents: read` en `      contents: write`.
- TestCIActionsPinnedBySHA : W3 `actions/checkout@<sha>` en `actions/checkout@v5` ; G1 `` `^[0-9a-f]{40}$` `` en `` `^[0-9a-f]{7,40}$` ``.
- TestCIRunsMakeVerify : W4 `make -f Makefile verify` en `make verify` ; W5 `base.sha || github.event.before` en `head_ref` ; W6 `ubuntu-24.04` en `ubuntu-latest` ; W7 et W8 lignes `if: always()` et `persist-credentials: false` supprimées ; G2 `strings.Contains(s.Run, "${{")` en `strings.Contains(s.Run, "${{ secrets")`.
- TestCINoSecrets : W9 ligne `      K: ${{ secrets.K }}` après `      GOTOOLCHAIN: local` ; G3 `|github\.token` supprimé.
- TestCIGoVersionFromGoMod : W10 `go-version-file: go.mod` en `go-version: stable`.
- TestCodeownersProtectsBaselines : G4 ligne `break` après `owners = r.owners`.
- TestNoShadowMakefile : W11 `GNUmakefile` vide à la racine (sans lancer make) ; G5 `strings.EqualFold(n, "gnumakefile")` en `n == "GNUmakefile"`.

## 7. Risques

R1 Docker de l'image inférieur à 28 : échec précoce. R2 SHA vieillissants : revue humaine. R3 PR de fork : jeton en lecture, aucun identifiant. R4 `EVAL_BASE` vu par make : T23 le fige (`override EVAL_BASE := $(value EVAL_BASE)`, `callerVariables()`). R5 TestCodeowners rouge avant 0007. R6 `go.yaml.in/yaml/v3` (clé `on`, clé nulle, `0` et `false` en `string`, champs sans étiquette) à confirmer en phase tests, sans affaiblir un contrôle.

## 8. Menaces (écrites par l'agent principal)

T6, T32 : tests ci-dessus, 0007. T82 (nouvelle, S, T, E) : CI détournée (`pull_request_target`, jeton en écriture, étiquette mobile, SHA de fork, injection `${{ }}`, cache, second workflow, runner self-hosted) ; D1 à D8.

## 9. Décisions ouvertes (défaut le plus strict)

1. `pull_request` sans filtre (défaut) ou `main`. 2. `go install` (défaut) ou `golangci-lint-action`. 3. `cache: false` (défaut). 4. `/Makefile` exigé (défaut) ; si 0007 est refusée, le retirer de `checkCodeowners`. 5. Docker inférieur à 28 : échec (défaut). 6. Dependabot : non (défaut).

## 10. Tâches ordonnées

1. (principal) Proposition 0007 : `/Makefile @amezianechayer` dans `CODEOWNERS`, `stop_verify.py` en `make -f Makefile verify-quick`, cas `test_hooks.sh`.
2. (tests) `ci_test.go` : `TestCI*` rouges, TestCodeowners rouge avant 0007 ; `go build ./...` vert.
3. (principal) SHA (section 5) dans `docs/STATUS.md`.
4. (impl, 0007 appliquée) `verify.yml` ; critères 1 à 7.
5. `security-reviewer` ; `acceptance-verifier` : critères 1 à 7, W1 à W11, G1 à G5.
6. (principal) T6, T32, T82 dans `docs/02-THREAT-MODEL.md` ; R4 et T32 dans `docs/STATUS.md`.
7. (humain, H1) Pousser, ouvrir la PR, rejouer le critère 5 ; protéger `main` (contrôle `verify` requis, "Require review from Code Owners") ; Actions : jeton en lecture, `actions/*` seulement avec SHA obligatoire, approbation des contributeurs externes ; critère 8.
