# M0-T04 `ci` : GitHub Actions exécutant `make verify` sur chaque PR

2026-09-29, `architect`, proposé. Sources : fiche M0-T04 et H1 (`docs/plans/M0-overview.md`), `Makefile`, `scripts/dev-preflight.sh`, `docs/SETUP.md`, `.github/CODEOWNERS`, `docs/STATUS.md`, menaces T6, T32.

## 1. Objectif et périmètre

Chaque PR et chaque push sur `main` exécutent `make -f Makefile verify` sur un runner GitHub, chaîne d'approvisionnement durcie (dépôt public, T6). Dans le périmètre : `.github/workflows/verify.yml`, `internal/archtest/ci_test.go` (7 tests de la fiche et `TestNoShadowMakefile`, T32), proposition `docs/proposals/0007-ci-makefile-codeowners.md`. Hors périmètre : `.github/CODEOWNERS` (protégé, lu tel quel), Dependabot, OPA en CI (aucun `.rego` en M0), lecture de `EVAL_BASE` par le `Makefile` (T23), H1. Ni API, ni dépendance, ni ADR (réversible par PR revue).

## 2. Décisions (option la plus stricte)

- D1 : `pull_request` sans filtre, `push` sur `main`, rien d'autre.
- D2 : `contents: read` (workflow et job), `persist-credentials: false`, ni `secrets`, ni `github.token`, ni `GITHUB_TOKEN`.
- D3 : `actions/checkout` et `actions/setup-go` seulement, par SHA de commit et `# vX.Y.Z` ; golangci-lint par `go install` (vérifié par `sum.golang.org`), version de `docs/SETUP.md`.
- D4 : `go-version-file: go.mod`, `cache: false`, `GOTOOLCHAIN: local`.
- D5 : `make -f Makefile` partout, aucune autre variable de job : sans `-f`, make et chaque `$(MAKE)` récursif lisent `GNUmakefile` puis `makefile` d'abord.
- D6 : `EVAL_BASE` = SHA de base par `env`, jamais `${{ }}` dans un `run`.
- D7 : `ubuntu-24.04`, `timeout-minutes: 45`, `concurrency` par PR.
- D8 : `.github/` = `CODEOWNERS` et `workflows/verify.yml`, liste fermée.
- D9 : `/Makefile` exigé dans `CODEOWNERS` (T32), via 0007.

## 3. Runner et `dev-preflight`

`ubuntu-24.04` : Docker et compose v2, contexte `default` sur `unix:///var/run/docker.sock`, `DOCKER_HOST` vide, `runner` dans le groupe `docker` : socket local et démon passent. Version 28 ou plus (28.x à la date de connaissance), à confirmer avant H1 : `gh api repos/actions/runner-images/contents/images/ubuntu/Ubuntu2404-Readme.md --jq .content | base64 -d | grep -i docker`. Sinon `Docker preflight` échoue tôt.

## 4. Code de référence

Indentation à deux espaces ici ; `gofumpt` rétablit les tabulations. `verify.yml` est le texte exact de `validCIWorkflow`, précédé de ces deux lignes, avec les SHA et versions de la section 5 à la place de `ciSHAA`, `v5.0.0`, `ciSHAB`, `v6.0.0` :

```yaml
# M0-T04: make verify on every pull request and on main (docs/plans/M0-ci.md).
# Actions pinned by commit SHA; read-only token; no credential of any kind.
```

`internal/archtest/ci_test.go` réutilise `repoRoot`, `readRepoFile`, `problemList`, `expectProblems`, `expectError`, `reportProblems`, `mustReplace` et `checkComposeNode` (ancres, alias, fusions, étiquettes, doublons refusés) :

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

// Closed schema (KnownFields): any other key is a decoding error.
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

var ciSHARe = regexp.MustCompile(`^[0-9a-f]{40}$`)

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

// checkGithubDir: closed lists (a second workflow could use pull_request_target).
func checkGithubDir(fsys fs.FS) (p problemList) {
  for dir, want := range map[string][]string{".github": {"CODEOWNERS", "workflows"}, ".github/workflows": {"verify.yml"}} {
    entries, err := fs.ReadDir(fsys, dir)
    var got []string
    for _, e := range entries {
      got = append(got, e.Name())
    }
    if err != nil || !slices.Equal(got, want) {
      p.addf("%s holds %q (%v)", dir, got, err)
    }
  }
  return p
}

func wants(s string) []string { return slices.DeleteFunc([]string{s}, func(x string) bool { return x == "" }) }

// runCI: validCIWorkflow, then (old, new, want) mutations (want: a problem
// substring, or "err:" then an error substring), then the repository file.
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
  mfs := fstest.MapFS{".github/CODEOWNERS": {}, ".github/workflows/verify.yml": {}, ".github/workflows/x.yml": {}}
  expectProblems(t, checkGithubDir(mfs), []string{".github/workflows holds"})
  _, fsys := repoRoot(t)
  reportProblems(t, checkGithubDir(fsys))
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
    at, "          K: ${{ github.token }}\n"+at, "names a secret",
    "run: make -f", "run: GITHUB_TOKEN=x make -f", "err:occurs 3 times")
}

func TestCIGoVersionFromGoMod(t *testing.T) {
  const cache = "          cache: false\n"
  runCI(t, checkCIGoVersion, checkCIGoVersion,
    "go-version-file: go.mod", "go-version: stable", "setup-go with",
    cache, cache+"          check-latest: true\n", "setup-go with",
    "GOTOOLCHAIN: local", "GOTOOLCHAIN: auto", `GOTOOLCHAIN "auto"`)
}

// checkCodeowners accepts comments and "/anchored-pattern @owner..." lines
// only; "**" crosses directories, "*" does not, a pattern covers everything
// below it. For each protected path, the last matching rule (owner-less:
// unset) must name exactly the human.
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
      p.addf("%s at the repository root would replace Makefile", n)
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

À vérifier en phase tests, sans affaiblir un contrôle : `go.yaml.in/yaml/v3` lit `on` comme chaîne, garde une clé à valeur nulle, décode `0` et `false` dans un `string`, associe les champs sans étiquette aux clés en minuscules.

## 5. SHA des actions

Aucun SHA n'est écrit ici. Pour `actions/checkout` puis `actions/setup-go`, l'agent principal (MCP GitHub `get_latest_release`, `list_tags`, `get_tag`, ou `gh api`) :
1. version : `gh api repos/actions/checkout/releases/latest --jq .tag_name` (au moins `v5.0.0` ; `v6.0.0` pour setup-go) ;
2. SHA : `gh api repos/actions/checkout/git/ref/tags/vX.Y.Z --jq '.object.type+" "+.object.sha'` ; si le type est `tag`, `gh api repos/actions/checkout/git/tags/<sha>` (même `--jq`) jusqu'à `commit` ;
3. seconde source égale : `list_tags` (`commit.sha`) ou `gh api repos/actions/checkout/commits/vX.Y.Z --jq .sha` ; toujours un tag amont, jamais un SHA de fork ;
4. `gh api 'repos/actions/checkout/contents/action.yml?ref=<sha>' --jq .content | base64 -d | grep -c 'using: .node24.'` : `1` ;
5. tag, SHA et sorties dans `docs/STATUS.md` ; l'humain rejoue le critère 6.

## 6. Tests d'acceptation

1. `go test ./internal/archtest/ -run 'TestCI|TestCodeowners' -v 2>&1 | grep -c '^--- PASS'` : `7`.
2. `go test ./internal/archtest/ -run '^TestNoShadowMakefile$' -v 2>&1 | grep -c '^--- PASS'` : `1`.
3. `test "$(grep -c 'uses:' .github/workflows/verify.yml)" = "$(grep -Ec 'uses: [a-z0-9-]+/[a-z0-9._-]+@[0-9a-f]{40} # v[0-9]+\.[0-9]+\.[0-9]+$' .github/workflows/verify.yml)"; echo rc=$?` : `rc=0`.
4. `grep -Eci 'secrets|github\.token|github_token|pull_request_target|0123456789abcdef' .github/workflows/verify.yml` : `0`.
5. `grep -E 'run: .*make ' .github/workflows/verify.yml | grep -vc 'make -f Makefile '` : `0`.
6. `grep -Eo 'uses: [^@ ]+@[0-9a-f]{40} # v[0-9.]+' .github/workflows/verify.yml | while read -r _ ref _ tag; do r=${ref%@*}; [ "$(gh api "repos/$r/commits/$tag" --jq .sha)" = "${ref#*@}" ] && echo "ok $r" || echo "MISMATCH $r"; done` : `ok actions/checkout`, `ok actions/setup-go`.
7. `LC_ALL=C grep -c '[^[:print:]]' .github/workflows/verify.yml` : `0`.
8. `make verify-quick; echo rc=$?` : `rc=0`.
9. Après H1 : `gh run list --workflow verify.yml --limit 1 --json conclusion --jq '.[0].conclusion'` : `success` ; `gh run view <id> --log` contient `dev-preflight : Docker Engine 28`.

Mutations, une à la fois puis restaurées : `go test ./internal/archtest/ -run '^<Test>$'` finit par `FAIL` ; ancres uniques, mutations G compilables.
- TestCIWorkflowTriggers : W1 `  pull_request:` en `  pull_request_target:`.
- TestCIPermissionsReadOnly : W2 `      contents: read` (6 espaces) en `      contents: write`.
- TestCIActionsPinnedBySHA : W3 `actions/checkout@<sha>` en `actions/checkout@v5` ; G1 `` `^[0-9a-f]{40}$` `` en `` `^[0-9a-f]{7,40}$` ``.
- TestCIRunsMakeVerify : W4 `run: make -f Makefile verify` en `run: make verify` ; W5 `github.event.pull_request.base.sha || github.event.before` en `github.head_ref` ; W6 `ubuntu-24.04` en `ubuntu-latest` ; W7 ligne `if: always()` supprimée ; W8 ligne `persist-credentials: false` supprimée ; G2 `strings.Contains(s.Run, "${{")` en `strings.Contains(s.Run, "${{ secrets")`.
- TestCINoSecrets : W9 ligne `      K: ${{ secrets.K }}` après `      GOTOOLCHAIN: local` ; G3 `|github\.token` supprimé.
- TestCIGoVersionFromGoMod : W10 `go-version-file: go.mod` en `go-version: stable`.
- TestCodeownersProtectsBaselines : G4 `owners = r.owners` suivi d'une ligne `break`.
- TestNoShadowMakefile : W11 `GNUmakefile` vide à la racine (sans lancer make) ; G5 `strings.EqualFold(n, "gnumakefile")` en `n == "GNUmakefile"`.

## 7. Risques

R1 autre Docker sur l'image : échec précoce et lisible. R2 limite de Docker Hub : images épinglées, échec visible. R3 SHA vieillissants : revue humaine périodique. R4 PR de fork : code non fiable, jeton en lecture, aucun identifiant, approbation des contributeurs externes (H1). R5 `proxy.golang.org` indisponible : échec fermé. R6 `EVAL_BASE` vu par make : T23 le fige (`override EVAL_BASE := $(value EVAL_BASE)`, `callerVariables()`) ; `before` hors historique : toutes les suites. R7 TestCodeowners rouge avant 0007 : l'impl attend l'humain.

## 8. Modèle de menace (écrit par l'agent principal)

T6 : `TestCIActionsPinnedBySHA`, `TestCIGoVersionFromGoMod`. T32 : `TestNoShadowMakefile`, `-f Makefile` en CI, CODEOWNERS et Stop hook (0007). T82 (nouvelle, S, T, E) : CI détournée (`pull_request_target`, jeton en écriture, étiquette mobile ou SHA de fork, injection `${{ }}`, cache empoisonné, second workflow, runner self-hosted) ; D1 à D8 ; tests de la fiche et `checkGithubDir`.

## 9. Décisions ouvertes (défaut : le plus strict)

1. `pull_request` sans filtre (défaut) ou `main` seulement. 2. `go install` (défaut) ou `golangci-lint-action` épinglée. 3. `cache: false` (défaut) ou cache. 4. `/Makefile` exigé (défaut) ; si 0007 est refusée, le retirer de `checkCodeowners` et consigner le résidu T32. 5. Docker inférieur à 28 : échec (défaut) ou `docker-ce` épinglé (ADR). 6. Dependabot : non (défaut).

## 10. Tâches ordonnées

1. (principal) `docs/proposals/0007-ci-makefile-codeowners.md` et `.patch` : `/Makefile @amezianechayer` dans `CODEOWNERS`, `stop_verify.py` en `make -f Makefile verify-quick`, cas `test_hooks.sh`.
2. (tests) `ci_test.go` : rouges, les 6 `TestCI*` et TestCodeowners avant 0007 ; `go build ./...` vert.
3. (principal) SHA (section 5) consignés dans `docs/STATUS.md`.
4. (impl, après application de 0007 par l'humain) `verify.yml` ; critères 1 à 8.
5. `security-reviewer` (T6, T32, T82) ; `acceptance-verifier` : critères 1 à 8, W1 à W11, G1 à G5.
6. (principal) T6, T32, T82 dans `docs/02-THREAT-MODEL.md` ; R6 et T32 dans `docs/STATUS.md` ; CI dans `docs/SETUP.md`.
7. (humain, H1) Pousser, ouvrir la PR, rejouer le critère 6 ; protéger `main` (contrôle `verify` requis, "Require review from Code Owners", pas de push forcé) ; Actions : jeton en lecture par défaut, `actions/*` seulement avec SHA obligatoire, approbation des contributeurs externes ; critère 9.
