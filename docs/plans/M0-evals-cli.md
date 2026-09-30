# M0-T23 `evals-cli` : `cmd/rempart-evals`, suite `demo`, `make evals` (critère 5 de M0)

2026-09-30, `architect`, proposé. Sources : fiche M0-T23 et H3 (`docs/plans/M0-overview.md` sections 6 et 7), matrice 8.1 (critères 1 et 5) ; `docs/plans/M0-evals-core.md` (sections 10.7, 11 à 13) et le code livré de `internal/evals` ; skill `agent-evals` et `references/case-format.md` ; ADR 0002 (baseline par couple plateforme et modèle) ; `internal/loops/demo`, `internal/loops/demo/activities`, `cmd/rempart-worker/run.go` ; `Makefile` ; `internal/archtest/{makefile_test.go,makeoracle_test.go,compose_test.go,ci_test.go,rules.go}` ; `.github/workflows/verify.yml` ; `.github/CODEOWNERS` ; `.claude/hooks/{guard_edit.py,guard_bash.py}` (lecture) ; proposition 0005 ; `docs/STATUS.md` obligations (r) à (z) et (bs) ; `docs/02-THREAT-MODEL.md` T8, T21, T58 à T67 ; SDK Temporal v1.49.0 (`internal/workflow_testsuite.go`, `internal/internal_workflow_testsuite.go`, `internal/log/default_logger.go`, `internal/internal_flags.go`). ADR : **0005 proposé** (`docs/decisions/0005-executeur-d-evals.md`). Revue sécurité : **oui** (exécution de `git`, porte de fusion).

## 0. Écarts à la fiche (ce plan prévaut)

| Fiche M0-T23 | Ce plan | Raison |
|---|---|---|
| `verify` ajoute `$(MAKE) evals EVAL=changed` | `verify` lance directement `go run ./cmd/rempart-evals --suite changed --base "$${EVAL_BASE:-}"` | M0-T04b : un sous-make n'a que la forme exacte `$(MAKE) -f Makefile --no-print-directory <cible>`, sans affectation (`canonicalSubMakeRe`) |
| 7 tests dans `cmd/rempart-evals` | 11 tests (section 8.2) | codes 2, forme de la commande `git`, sortie standard unique, lecture stricte de la baseline |
| `internal/evals` hors périmètre | solde des obligations (s) à (w), (y), (z) de M0-T22 dans le noyau, plus `LoadBaseline`, `EncodeBaseline`, `DiscoverSuites` | `docs/STATUS.md` : « Obligations issues de M0-T22, avant T23 » ; aucune n'est faite dans le code actuel (vérifié : pas de borne de ligne, `tagToken` n'est pas un vocabulaire fermé, `validPattern` admet tout caractère que `fs.ValidPath` admet, pas de `os.SameFile`, aucune fonction de lecture de baseline) |
| `.gitignore` (`evals/**/reports/`) | inchangé | déjà présent ; l'exécuteur n'écrit aucun rapport sur disque |
| baseline `evals/demo/baseline*` | `evals/demo/baseline/fake/fake-model-v1.json` | ADR 0002 ; le rapport porte `platform: fake`, `model: fake-model-v1` |

## 1. Objectif

`make evals EVAL=demo` exécute le cas trivial de la suite `demo` (workflow `rempart.demo.v1` en processus, faux LLM scripté par l'entrée du cas) et le compare à la baseline commitée par l'humain (critère 5) ; `make verify` exécute les suites concernées par le diff depuis `EVAL_BASE`, et toutes les suites en cas de doute (critère 1, obligation (bs)).

## 2. Périmètre

**Dans** :
- `internal/evals` : obligations (s), (t), (u), (v), (w), (y) ; nouvelles fonctions `LoadBaseline`, `EncodeBaseline`, `DiscoverSuites` ; `SelectChanged` : noyau élargi (`Makefile`, `.github/workflows/**`).
- `cmd/rempart-evals/` : `main.go`, `run.go` (drapeaux, codes, sortie), `targets.go` (interface `Target`, cible `demo`), `git.go` (seule exécution de commande), `baseline.go` (lecture et écriture par `os.Root`), tests et `testdata/`.
- `evals/demo/suite.yaml`, `evals/demo/cases/demo-converge-001.yaml` (écrits en phase tests, gelés ensuite).
- `Makefile` : `EVAL_BASE` figée et exportée, `evals` qui gère `changed`, ligne d'evals dans `verify`, commentaires mis à jour.
- `internal/archtest/makefile_test.go` (et, si nécessaire, les constantes synthétiques de `compose_test.go`) : grammaire et règles étendues à `EVAL_BASE` et aux lignes d'evals.
- `docs/STATUS.md`, `docs/02-THREAT-MODEL.md` (par l'agent principal après la revue), proposition de harnais 0010 (par l'agent principal, section 9).

**Hors** :
- Écriture de toute baseline sous `evals/` par l'agent (bloquée par `guard_edit.py` et `guard_bash.py`) : étape humaine H3.
- `.github/workflows/verify.yml` et `internal/archtest/ci_test.go` : inchangés (`EVAL_BASE` déjà fourni par `env`, D6 de M0-T04).
- `.github/CODEOWNERS` (protégé) : proposition 0010 seulement.
- Appel réel à un modèle, job nocturne, suites d'injection (`evals/security/`) : M1 et M5.
- Rapports sur disque, juge LLM, parallélisme des exécutions.
- Rejeu d'historique réel (M1, obligation (ag)).

## 3. Préconditions (vérifiées par commande avant la phase tests)

| # | Précondition | Commande | Attendu |
|---|---|---|---|
| P1 | Propositions 0001 et 0005 appliquées | `grep -c 'suite\\.yaml' .claude/hooks/guard_edit.py` ; `grep -c 'write-baseline' .claude/hooks/guard_bash.py` | au moins `1` ; au moins `1` |
| P2 | Gardes des baselines éprouvées | `bash .claude/hooks/test_hooks.sh 2>&1 \| tail -1` | aucun échec |
| P3 | Revue des code owners exigée sur `main` (obligation (r)) | `gh api repos/amezianechayer/rempart/branches/main/protection --jq .required_pull_request_reviews.require_code_owner_reviews` (par l'humain si `gh` est absent) | `true` ; à défaut, attestation humaine consignée dans `docs/STATUS.md` (réglages H1 déclarés faits le 2026-09-30) |
| P4 | Arbre propre, phase free | `git status --porcelain \| wc -l` ; `python3 .claude/bin/rempart-state show` | `0` ; `phase=free` |
| P5 | `cmd/rempart-evals` absent (la garde du `Makefile` rend encore 2) | `make -s -f Makefile evals EVAL=demo; echo rc=$?` | message contenant `M0-T23`, `rc=2` |
| P6 | SHA de départ consigné | `git rev-parse HEAD`, noté `T23_START` dans `docs/STATUS.md` | 40 caractères hexadécimaux |

La proposition 0009 (en attente humaine) ne bloque pas T23.

## 4. Décisions

Les décisions marquées « ouverte » sont reprises en section 12 : l'option retenue est la plus stricte et réversible, sur délégation de l'humain.

| # | Décision |
|---|---|
| D1 | **Cible `demo` en processus** (ADR 0005, option 2) : `testsuite.WorkflowTestSuite` avec `SetLogger` (slog vers la sortie d'erreur, niveau `Warn`), `NewTestWorkflowEnvironment` neuf **par exécution**, `SetTestTimeout(60 s)`, `demo.Register` sur l'environnement, faux fournisseur construit en mémoire (aucun fichier de script), vérificateur d'approbation local `denyAll` (comme `cmd/rempart-worker` ; `internal/loops/fake` reste interdit hors tests, règle `loops-fake-tests-only`). Ni réseau, ni Docker, ni Temporal réel. Le délai d'approbation de 5 s est franchi par l'horloge simulée. `StartDevServer` jamais appelé. |
| D2 | Journal du SDK : sans `SetLogger`, le journal par défaut écrit sur **la sortie standard** (`internal/log/default_logger.go` : `golog.New(os.Stdout, ...)`) et casserait le document JSON : `SetLogger` est obligatoire, testé par `TestStdoutSingleJSONDocument`. |
| D3 | Environnement : `TEMPORAL_DEBUG` (délai de test porté à 24 h par le SDK) ou toute variable `TEMPORAL_SDK_FLAG_*` (lues au chargement du paquet) présente : code 2 avant toute exécution (T84). |
| D4 | Entrée d'un cas `demo` (fermée, lue par `schema.DecodeStrict` sur `Case.Input`, déjà admise par `LoadSuite`) : objet à exactement deux clés, `target` (chaîne, `activities.ValidTarget`) et `replies` (tableau de 1 à 8 objets JSON, chacun réencodé compact en au plus 1024 octets). Chaque réponse devient une étape du script du faux pour `demo.greeting.v1` : `Output` = la réponse compacte, `Model` = `fake-model-v1`, `RequestID` = `req-eval-<n>`, `Usage` = 10 en entrée, 5 en sortie. Entrée non conforme : code 2, message citant l'identifiant du cas (jeton déjà validé), jamais une valeur lue. |
| D5 | Câblage : tenant de démo fixe `0d3e0000-0000-4000-8000-000000000001` (celui de `make demo`) ; route `fake`, modèle `fake-model-v1`, résidence `eu`, rétention nulle ; `llm.Config{MaxTokensPerCall: activities.MaxTokensPerCall, AllowFakeRoute: true}` (binaire d'outillage jamais livré, T41) ; `demo.Input{Target, Author: "demo-author", ApprovalTimeout: 5 s}`. |
| D6 | `Outcome` de la cible `demo` : `Output` = projection JSON fermée `{"status","reason","best","iterations","tokens","approval","committed"}` (`best` = `LoopResult.Best` brut ou `null`, `approval` = `ApprovalResult.Outcome` ou `""`) ; `SchemaValid` = `Best` non vide et conforme au schéma du prompt (`prompts.Load(activities.PromptID)`, hash égal à `activities.PromptHash`, `Schema.Validate`) ; `Status` = `LoopResult.Status` ; `Escalated` = statut `escalated` ; `Iterations`, `Tokens` du `LoopResult` ; `Duration` mesurée (non reportée) ; erreur de workflow : `Err = "workflow_failed"` (notée, donc régression) ; panique ou environnement impossible à créer : erreur d'exécution (code 4). |
| D7 | Identité de la cible `demo` : `platform=fake`, `region=""`, `model=fake-model-v1`. Baseline : `evals.BaselinePath("demo","fake","fake-model-v1")` = `evals/demo/baseline/fake/fake-model-v1.json` (ADR 0002). |
| D8 | Codes de sortie de `run` : `0` conforme, `1` régression, `2` usage ou configuration (drapeaux, suite introuvable ou invalide, cible inconnue, entrée de cas refusée, baseline présente mais illisible, environnement D3, répertoire courant sans `go.mod` ou sans `evals/` réel), `3` baseline absente, `4` erreur d'exécution. Les erreurs de code 2 arrêtent tout ; ensuite, pire code parmi les suites selon l'ordre `4`, `3`, `1`, `0`. |
| D9 | Ordre dans une suite : chargement (`LoadSuite`, seul chemin vers un `Case`, obligation (z)), contrôle de toutes les entrées (`Target.Check`), exécutions, `GradeOutcome`, `Aggregate`, **puis** lecture de la baseline : le code 3 prouve que le cas a tourné. Une ligne fixe sur la sortie d'erreur : `evals : suite <nom>, cas <n>, exécutions <m>`. |
| D10 | Sortie standard, un seul document JSON. Avec une suite nommée : le `Report` (forme du skill, critère 5), seulement pour les codes 0 et 1, rien sinon. Avec `all` ou `changed` : `{"selection":{"mode":<"all" ou "changed">,"fallback":<raison ou "">},"suites":[{"suite":<nom>,"code":<n>,"report":<Report ou null>}]}`, toujours écrit sauf code 2. |
| D11 | Message du code 3, sur la sortie d'erreur, texte fixe : `evals : baseline absente pour la suite <nom> (<chemin>) : à créer par l'humain avec make update-baseline EVAL=<nom>, puis à commiter (étape H3).` |
| D12 | Drapeaux (`flag.ContinueOnError`, sortie d'erreur) : `--suite` obligatoire (`all`, `changed`, ou nom valide) ; `--base` obligatoire avec `changed` (valeur vide admise : base absente), interdit sinon ; `--write-baseline` seulement avec une suite nommée ; chaque drapeau au plus une fois ; aucun argument positionnel. Toute violation : code 2. |
| D13 | Référence de base (**ouverte**) : admise seulement si elle est un identifiant d'objet hexadécimal minuscule complet de 40 ou 64 caractères, non entièrement `0`. Sinon aucune commande `git` n'est lancée avec elle et toutes les suites sont retenues : vide (`base_absent`), nulle (`base_null`), autre (`base_invalid`). Un nom symbolique (`origin/main`) fait tout rejouer. |
| D14 | Commandes `git` (seules exécutions du binaire, T8), construites par une fonction qui ne les lance pas, testée à l'argument près : `exec.CommandContext(ctx, "git", args...)`, jamais de shell, `cmd.Dir` = racine, `cmd.Env` exactement `PATH=<hérité>`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_TERMINAL_PROMPT=0`, `GIT_OPTIONAL_LOCKS=0`, `LC_ALL=C` ; délai 30 s, `WaitDelay` 5 s ; sortie standard bornée à 1 Mio, sortie d'erreur jetée (jamais citée). Arguments : (1) `-c core.fsmonitor=false --no-pager merge-base --is-ancestor --end-of-options <base> HEAD` : code 0 ancêtre, 1 non ancêtre (`base_not_ancestor`), autre (`git_failed`) ; (2) `-c core.fsmonitor=false --no-pager diff --no-renames --no-ext-diff --no-textconv --name-only -z --end-of-options <base> --` (base contre l'arbre de travail, T61) ; (3) `-c core.fsmonitor=false --no-pager ls-files --others --exclude-standard -z` (fichiers non suivis). `git` absent, code non nul, délai, sortie tronquée ou plus de 10 000 chemins : toutes les suites (`git_failed`, `diff_too_large`). Chemins découpés sur NUL puis passés à `evals.SelectChanged` (chemin invalide : toutes les suites). |
| D15 | Portée du diff (**ouverte**) : base contre arbre de travail, plus fichiers non suivis, et non `base..HEAD` : un `make verify` local avant commit rejoue aussi ce qui n'est pas encore commité. |
| D16 | Racine : `os.OpenRoot(".")` ; `go.mod` régulier et `evals` répertoire réel (`Lstat`, pas un lien), puis `repo.OpenRoot("evals")` et `os.SameFile` entre ce `Lstat` et le `Stat` de la racine ouverte (T59, TOCTOU) ; suites chargées par `evals.LoadSuite(evalsRoot.FS(), <nom>)` (obligation (y)). |
| D17 | Découverte (`all`, `changed`) : `evals.DiscoverSuites(evalsRoot.FS())` : parcours sans suivre de lien, tout lien rencontré sous `evals/` refusé (**ouverte**), au plus 10 000 entrées et 256 suites, suite = répertoire contenant `suite.yaml`, nom validé (`validSuiteName`), noms `all` et `changed` refusés, suite imbriquée dans une autre refusée ; `cases/` et `baseline/` ne sont pas explorés pour y chercher des suites. Erreur : code 2. |
| D18 | Baseline lue par `evals.LoadBaseline(repo.FS(), path)` : chaque composant parent est un répertoire réel (absent : `ErrNoBaseline`, code 3 ; lien ou fichier : invalide, code 2), fichier régulier, `sameFile` entre `Lstat` et `Stat` du fichier ouvert, 64 Kio, liste d'admission de `admitted`, lignes d'au plus 160 runes, `schema.DecodeStrict`, `exactKeys` sur `Baseline`, `DisallowUnknownFields` (obligation (w), T60, T62, T64). `Validate` en échec : régression `baseline` par `Compare` (code 1), comme dans le noyau. |
| D19 | Écriture (`--write-baseline`, humain seulement) : suite nommée ; codes 2 et 4 d'abord ; `Baseline{Report, Tolerances: {0, 0, 0, 0}}` (**ouverte**) ; `EncodeBaseline` (JSON indenté de deux espaces, fins de ligne LF, saut de ligne final, refus si `Validate` échoue, relu par `LoadBaseline` avant écriture) ; parents créés par `repo.MkdirAll` après contrôle qu'aucun composant existant n'est un lien ; fichier temporaire `O_CREATE` et `O_EXCL` dans le même répertoire puis `repo.Rename`. Sortie standard : le rapport ; sortie d'erreur : le chemin écrit. Sans le drapeau : aucune écriture, jamais. |
| D20 | Obligation (s) : dans `contains` et `equals`, un scalaire qui n'est pas entre guillemets doubles et contient une barre oblique inverse est refusé (T65). Obligation (t) : toute ligne d'un fichier d'eval ou de baseline tient en au plus 160 runes ; deux espaces consécutives sont refusées dans la valeur d'un scalaire de `contains` ou `equals` (T64). Raisons fixes, sans citation. |
| D21 | Obligation (u) (**ouverte**) : `tags` pris dans le vocabulaire fermé `evals.CaseTags` = `nominal`, `trap`, `injection`, `limit`, `regression` (catégories du skill), `storage` (exemple de `case-format.md`) ; toute nouvelle étiquette passe par une modification de code revue (T66). |
| D22 | Obligation (v) : motifs `watch` au jeu fermé `[A-Za-z0-9._/*-]`, en plus de `validPattern` (`[` et `?` refusés au chargement ; `SelectChanged` garde son comportement « motif invalide : suite retenue ») (T67). |
| D23 | Obligation (y) dans le noyau : `readRegular` compare l'information du `Lstat` à celle du `Stat` du fichier ouvert : `os.SameFile` si les deux portent une information système, sinon (FS synthétique, `Sys() == nil` des deux côtés) égalité du nom, du mode, de la taille et de la date. `"os"` est importé dans `internal/evals` pour ce seul appel. |
| D24 | `SelectChanged` (**ouverte**) : noyau complété par `Makefile` et `.github/workflows/**`. |
| D25 | `verify` lance les evals **avant** la pile (`dev`) : elles n'ont besoin ni de Docker ni de réseau et échouent tôt. |
| D26 | Suite `demo` : `watch` = `internal/loops/**`, `internal/llm/**`, `internal/tenancy/**` (le noyau couvre déjà `cmd/rempart-evals/**`, `internal/evals/**`, `internal/llm/schema/**`, `go.mod`, `go.sum`). Un seul cas, `runs: 1` (cible déterministe ; le skill demande 3 exécutions pour un cas non déterministe). |

## 5. Interfaces

### 5.1 `internal/evals` (ajouts)

```go
var ErrNoBaseline = errors.New("evals: no baseline") // file or a parent directory absent

// CaseTags is the closed vocabulary of case tags (obligation (u), T66).
var CaseTags = []string{"nominal", "trap", "injection", "limit", "regression", "storage"}

// LoadBaseline reads name (slash path from the root of fsys) under the rules of
// a case file (D18): real parent directories, regular file compared by
// sameFile, 64 KiB, admission list, lines of at most 160 runes, DecodeStrict,
// exact keys, DisallowUnknownFields. Absent: ErrNoBaseline. Otherwise invalid:
// ErrInvalidBaseline. Errors quote no value read.
func LoadBaseline(fsys fs.FS, name string) (Baseline, error)

// EncodeBaseline returns the canonical file content of b (D19); it refuses a
// baseline that fails Validate or that LoadBaseline would not read back equal.
func EncodeBaseline(b Baseline) ([]byte, error)

// DiscoverSuites returns, sorted, the names of the suites under the root of
// fsys, the evals directory (D17).
func DiscoverSuites(fsys fs.FS) ([]string, error)
```

Modifiés : `decodeFile` (borne de ligne), `plain` (D20), `compileCase` (D21), `validPattern` (D22), `readRegular` (D23), `SelectChanged` (D24).

### 5.2 `cmd/rempart-evals`

```go
// main.go
func main() // signal.NotifyContext(SIGINT, SIGTERM); os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))

// run.go
// run opens the repository root on ".", uses the real git runner, targets()
// and os.Environ(), then calls runWith. Codes: D8.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int

type env struct {
	repo    *os.Root          // repository root (D16)
	git     gitRunner         // D14; a fake in tests
	targets map[string]Target // targets(); a stub may be added in tests
	environ []string          // D3
}

func runWith(ctx context.Context, e env, args []string, stdout, stderr io.Writer) int

// targets.go
type Identity struct{ Platform, Region, Model string }

// Target runs the cases of the suites whose suite.yaml names it.
type Target interface {
	Identity() Identity
	// Check refuses, before any run, an input the target cannot run (code 2).
	Check(c evals.Case) error
	// Run executes run number run of c. A behavior, even failed, is an Outcome;
	// an error is an execution failure (code 4).
	Run(ctx context.Context, c evals.Case, run int) (evals.Outcome, error)
}

func targets() map[string]Target // {"demo": demoTarget{}}

// git.go
type gitRunner func(ctx context.Context, dir string, args ...string) (stdout []byte, code int, err error)

// gitCmd builds, without running it, the only command the binary executes (D14).
func gitCmd(ctx context.Context, dir, path string, args []string) *exec.Cmd

// validRef: D13.
func validRef(s string) bool

// changedPaths returns the changed and untracked paths since base, or
// ok == false with a fallback reason (base_absent, base_null, base_invalid,
// base_not_ancestor, git_failed, diff_too_large): every suite is then selected.
func changedPaths(ctx context.Context, git gitRunner, dir, base string) (paths []string, reason string, ok bool)

// baseline.go
func readBaseline(repo *os.Root, suite string, id Identity) (evals.Baseline, error)          // D18
func writeBaseline(repo *os.Root, suite string, id Identity, r evals.Report) (string, error) // D19
```

Règles d'architecture existantes respectées : `cmd/...` peut importer `go.temporal.io/sdk/testsuite` (`sdk-confine-temporal`) et `internal/llm/fake` (`fakes-wired-in-cmd`) ; jamais `internal/loops/fake` (`loops-fake-tests-only`) ni `internal/llm/adapters/anthropic` (`anthropic-unwired-m0`). `cmd/rempart-evals` est déjà déclaré `ToolingCmd` dans `TestLayoutMatchesVision`.

### 5.3 `Makefile` (texte de référence des lignes changées)

```make
override EVAL := $(value EVAL)
override EVAL_BASE := $(value EVAL_BASE)
override POLICIES_DIR := $(value POLICIES_DIR)
override OPA := $(value OPA)
export SCENARIO EVAL EVAL_BASE POLICIES_DIR OPA

verify: verify-quick
	go run ./cmd/rempart-evals --suite changed --base "$${EVAL_BASE:-}"
	$(MAKE) -f Makefile --no-print-directory dev
	go test -tags=integration $$(go list ./... | grep -v '/internal/archtest$$')
	bash scripts/dev-env.sh run go test -count=1 -tags=integration ./internal/archtest
	go tool govulncheck ./...

# Evals (M0-T23) : EVAL=<suite>, all ou changed ; changed lit EVAL_BASE (SHA de base, sinon toutes les suites).
evals:
	@test -d cmd/rempart-evals || { echo "evals : indisponible avant M0-T23 (cmd/rempart-evals absent) ; aucune action." >&2; exit 2; }
	@[[ "$${EVAL:-}" =~ ^[a-z0-9][a-z0-9/_-]{0,126}$$ ]] || { echo "EVAL requis, au format [a-z0-9/_-] (ex. EVAL=demo)." >&2; exit 2; }
	@if [ "$$EVAL" = changed ]; then go run ./cmd/rempart-evals --suite changed --base "$${EVAL_BASE:-}"; else go run ./cmd/rempart-evals --suite "$$EVAL"; fi
```

`update-baseline` : recette inchangée (`--write-baseline`) ; l'exécuteur refuse `all` et `changed`. `EVAL_BASE` suit la règle des variables de l'appelant (T28) : figée par `$(value ...)` avant export, lue par le shell, jamais développée par make ; aucune expansion make en recette hors sous-make canonique (D7 de M0-T04b : seuls des `$$` apparaissent). Pas de valeur par défaut (`makeAssignForms` n'admet `?=` qu'avec une valeur non vide) : absente, elle est exportée vide et l'exécuteur retient toutes les suites. L'évaluation dans `verify` n'est pas un sous-make : elle n'hérite que de l'environnement exporté.

## 6. Flux de données

```
make evals EVAL=demo
  -> go run ./cmd/rempart-evals --suite demo
     -> TEMPORAL_* ? code 2 ; os.OpenRoot(".") ; go.mod ; evals réel ; OpenRoot("evals") ; SameFile
     -> evals.LoadSuite(evalsFS, "demo")      (liste d'admission, arbre validé, étiquettes fermées)
     -> targets()["demo"].Check(chaque cas)   (entrée fermée D4, sinon code 2)
     -> pour chaque cas et chaque exécution :
          TestWorkflowEnvironment neuve (journal vers stderr) ; faux LLM scripté par input.replies
          demo.Workflow : RunLoop (Propose via llm.Client vers le faux ; Verify déterministe)
                          -> AwaitApprovals (denyAll, 5 s simulées) -> timed_out, rien de commis
          -> Outcome (projection D6) -> evals.GradeOutcome
     -> evals.Aggregate -> Report (platform fake, model fake-model-v1)
     -> evals.LoadBaseline(repoFS, "evals/demo/baseline/fake/fake-model-v1.json")
          absente : code 3, message D11, stdout vide
          illisible : code 2
          sinon evals.Compare -> regressions_vs_baseline -> stdout : Report ; code 0 ou 1

make verify (CI : EVAL_BASE = SHA de base de la PR, ou github.event.before sur main)
  -> go run ./cmd/rempart-evals --suite changed --base "$EVAL_BASE"
     -> validRef ? sinon toutes les suites (base_absent, base_null, base_invalid)
     -> git merge-base --is-ancestor --end-of-options <base> HEAD ? sinon toutes (base_not_ancestor, git_failed)
     -> git diff --no-renames ... -z --end-of-options <base> --  +  git ls-files --others --exclude-standard -z
     -> evals.DiscoverSuites -> LoadSuite de chacune -> evals.SelectChanged(suites, chemins)
     -> exécution des suites retenues -> document de sélection sur stdout ; pire code
```

Données non fiables : le texte des fichiers d'eval et de baseline (règles du noyau), la valeur d'`EVAL_BASE` (D13), la sortie de `git` (bornée, découpée sur NUL, chemins validés par `SelectChanged`), la sortie du faux LLM (validée par schéma dans `llm.Client`). Aucune donnée cloud.

## 7. Spécification de boucle et fichiers de la suite

Aucune boucle nouvelle : la suite évalue `L0-demo` (`docs/loops/L0-demo.md`, champ `evals: evals/demo/`), inchangée. Fichiers de la suite, écrits en phase tests par `test-author` (texte de référence) :

`evals/demo/suite.yaml`
```yaml
name: demo
loop: L0-demo
target: demo
watch:
  - internal/loops/**
  - internal/llm/**
  - internal/tenancy/**
```

`evals/demo/cases/demo-converge-001.yaml`
```yaml
id: demo-converge-001
loop: L0-demo
tags: [nominal]
input:
  target: bonjour
  replies:
    - {greeting: salut}
    - {greeting: bonjour}
expect:
  schema_valid: true
  status: converged
  escalation: false
  max_iterations: 2
  must_include:
    - path: "$.best.greeting"
      equals: "bonjour"
    - path: "$.approval"
      equals: "timed_out"
  must_not_include:
    - path: "$.committed"
      equals: true
runs: 1
```

Rapport attendu (contenu de la baseline H3) : `loop` `L0-demo`, `platform` `fake`, `region` `""`, `model` `fake-model-v1`, `cases` 1, `runs` 1, `injection_runs` 0, `escalation_runs` 1, `success_rate` 1, `correct_escalation_rate` 1, `injection_resistance` 1, `avg_iterations` 2, `avg_tokens` 30, `regressions_vs_baseline` `[]`.

## 8. Tests

### 8.1 `internal/evals` (8 nouvelles fonctions ; les 14 existantes restent, leurs lignes ajustées en phase tests si D21 ou D22 les invalident)

| Test | Contenu |
|---|---|
| `TestLoadBaselineStrict` | lecture conforme d'une baseline encodée ; refus : clé `Success_Rate` à côté de `success_rate` (T60), clé inconnue, doublon, exposant, rune hors liste d'admission, ligne de 161 runes, 64 Kio + 1, fichier lien, parent lien, parent fichier ; absent et parent absent : `ErrNoBaseline` ; aucune erreur ne contient la valeur témoin `canary` |
| `TestEncodeBaselineRoundTrip` | `EncodeBaseline` puis `LoadBaseline` : égalité profonde ; sortie admise, lignes d'au plus 160 runes, saut de ligne final ; refus d'une baseline qui échoue `Validate` (tolérance 0,2, `NaN`) |
| `TestDiscoverSuites` | arbre `demo`, `a/b`, `.gitkeep` : `[a/b demo]` ; refus : lien n'importe où, suite nommée `all` ou `changed`, suite imbriquée, nom invalide, plus de 256 suites ; `cases/` et `baseline/` non explorés |
| `TestCaseTagsClosedVocabulary` | chaque étiquette de `CaseTags` acceptée ; `lnjection`, `injecti0n`, `demo`, `Injection` refusées par `LoadSuite` et `GradeOutcome` |
| `TestNeedleHardening` | obligations (s) et (t) : sous `contains`, le scalaire simple formé de `public`, d'une barre oblique inverse, de `u005f` et de `bucket` est refusé, le même texte entre guillemets doubles est admis (échappement visible) ; sous `equals`, un scalaire entre guillemets simples contenant une barre oblique inverse est refusé ; `contains` et `equals` valant `"a` suivi de deux espaces puis `b"` sont refusés ; la même valeur sous `input` est admise |
| `TestLineLengthBounded` | ligne de 160 runes admise (lettres accentuées comptées une fois), 161 refusée, dans une suite, un cas et une baseline |
| `TestWatchPatternCharset` | `internal/x/**`, `docs/*.md` admis ; `a?b`, `[ab]`, `a b`, `é/**` refusés au chargement |
| `TestReadRegularSameFile` | FS hostile dont le `Stat` du fichier ouvert diffère du `Lstat` (taille, mode, puis information système) : refus pour une suite, un cas et une baseline ; `os.DirFS` et `fstest.MapFS` conformes acceptés |

Et une ligne de table dans `TestSelectChanged` : `Makefile` et `.github/workflows/verify.yml` retiennent toutes les suites (D24).

### 8.2 `cmd/rempart-evals` (11 fonctions)

Fixtures sous `cmd/rempart-evals/testdata/<scénario>/` (hors du répertoire `evals/` de la racine, donc hors de la règle `BASELINE` de `guard_edit`, ancrée sur `^evals/`) : `ok/`, `regression/`, `missing/`, `badbaseline/`, `select/` (suites `demo` et `other`, cible de test `stub`), chacun avec un `go.mod` factice et son `evals/`. Elles s'écrivent **par l'outil d'édition** en phase tests, jamais par une commande (`guard_bash` refuse toute écriture par commande sur un chemin qui contient `evals/` suivi de `baseline`, `suite.yaml` ou `/cases/`). Les tests ouvrent ces répertoires par `os.OpenRoot` et appellent `runWith`.

| Test | Attendu |
|---|---|
| `TestRunOKAgainstBaseline` | `ok/`, `--suite demo` : code 0 ; stdout = un document, `"regressions_vs_baseline":[]`, `cases` 1, `platform` `fake`, `model` `fake-model-v1` ; stderr contient `evals : suite demo, cas 1, exécutions 1` |
| `TestRegressionDetected` | `regression/` (baseline `avg_iterations` 1, tolérances nulles) : code 1 ; `regressions_vs_baseline` contient `avg_iterations` ; seconde ligne de table : baseline d'un autre modèle : `identity` |
| `TestMissingBaselineAsksHuman` | `missing/` : code 3 ; stderr contient `make update-baseline EVAL=demo` et `evals/demo/baseline/fake/fake-model-v1.json` ; stdout vide ; arbre identique avant et après (aucune écriture) |
| `TestWriteBaselineOnlyWithFlag` | copie de `missing/` dans `t.TempDir()` : sans drapeau, aucun fichier créé ; avec `--write-baseline`, fichier créé au chemin D7, relu par `evals.LoadBaseline`, tolérances nulles ; second passage sans drapeau : code 0 ; `--write-baseline` avec `all` ou `changed` : code 2, rien écrit ; répertoire `baseline` remplacé par un lien : code 2, rien écrit |
| `TestSuiteChangedSelection` | `select/` avec exécuteur `git` factice : chemin sous `evals/other/` : `[other]` ; `internal/loops/x.go` : `[demo]` ; `docs/x.md` : `[]`, code 0 ; `go.sum` : toutes ; sortie de 1 Mio + 1 octet ou 10 001 chemins : toutes (`diff_too_large`) ; `merge-base` en code 1 : toutes (`base_not_ancestor`), en code 128 : toutes (`git_failed`) ; sous-test `real_repo` : dépôt `git` réel dans `t.TempDir()` (commit de base, modification suivie, fichier non suivi sous `evals/other/`, commit hors ascendance par `git commit-tree`) : sélections et replis conformes, ce qui prouve `--end-of-options` et `--no-renames` sur le `git` installé |
| `TestRejectsUnsafeGitRef` | valeurs de `--base` : `--output=x`, `a;b`, `HEAD`, `main`, 40 zéros, 39 et 41 caractères hexadécimaux, hexadécimal en majuscules : l'exécuteur `git` factice n'est jamais appelé avec la valeur, repli `base_invalid` ou `base_null`, toutes les suites, aucun fichier `x` créé ; valeur vide : `base_absent` |
| `TestDemoTargetRunsWorkflow` | cas `demo-converge-001` : `converged`, 2 itérations, 30 tokens, `approval` `timed_out`, `committed` faux, `SchemaValid` ; réponses `salut` trois fois : `escalated`, `Escalated` vrai ; réponse hors schéma `{x: 1}` : `SchemaValid` faux ; deux exécutions successives indépendantes (même `Outcome`) ; entrée avec une clé en trop ou 9 réponses : `Check` refuse |
| `TestUsageErrors` | code 2 : sans `--suite`, suite inconnue, argument positionnel, drapeau répété, `--base` avec `demo`, `changed` sans `--base`, `--write-baseline` avec `all`, cible inconnue dans `suite.yaml`, `TEMPORAL_DEBUG=1` ou `TEMPORAL_SDK_FLAG_5=1` dans `environ`, racine sans `go.mod`, `evals` lien symbolique |
| `TestGitCommandShape` | `gitCmd` : `Path` de base `git`, `Args` exactement ceux de D14 (base après `--end-of-options`, `--no-renames` présent), `Env` exactement la liste de D14 (aucune variable `GIT_*` héritée, même si l'environnement du test en définit), `Dir`, `WaitDelay` |
| `TestStdoutSingleJSONDocument` | `ok/` et `select/` : un `json.Decoder` sur stdout lit exactement un document puis `io.EOF` ; aucune ligne de journal du SDK sur stdout |
| `TestBaselineReadStrictly` | `badbaseline/` (clé `Success_Rate`, rune U+200B brute, ligne de 161 runes, chaque variante avec la valeur témoin `canary`) : code 2, stderr sans `canary` ; baseline hors bornes (`tolerances.success_rate_drop` 0,5) : code 1, régression `baseline` |

### 8.3 `internal/archtest` (phase tests, fichiers code-owned)

- `makeVariables`, `makeExportable`, `callerVariables` : ajout de `EVAL_BASE` ; `callerVarRe` couvre `EVAL_BASE` ; `targetMakefile` suit la section 5.3.
- `checkEvalsTargets` étendu : la recette de `evals` contient la branche `changed` avec exactement `go run ./cmd/rempart-evals --suite changed --base "$${EVAL_BASE:-}"` ; la recette de `verify` contient exactement cette ligne, avant la ligne du sous-make `dev` ; `--write-baseline` n'apparaît que dans `update-baseline`.
- Témoins négatifs ajoutés à `TestMakefileTargets` : `verify` sans ligne d'evals ; branche `changed` sans `--base` ; `override EVAL_BASE := $(EVAL_BASE)` ; `EVAL_BASE` exportée avant d'être figée ; `--write-baseline` dans `verify` ; ligne d'evals après le sous-make `dev`.
- `TestMakefileOracle`, `TestMakefileGrammar` et les contrôles de `compose_test.go` (`checkVerifyIntegration`) restent verts sur le dépôt : aucune règle nouvelle, une variable et une ligne de recette de plus.

## 9. Harnais (propositions, jamais appliquées par l'agent)

- **Proposition 0010** (agent principal, `docs/proposals/0010-codeowners-executeur-evals.md`) : `/cmd/rempart-evals/` et `/internal/evals/` ajoutés à `.github/CODEOWNERS`. Raison : un grader, une cible ou une sélection affaiblis masquent une régression aussi sûrement qu'une baseline falsifiée, sans toucher à `evals/` (T83). Recommandée **avant la fusion de la PR de T23**.
- Rien d'autre : les gardes de 0001 et 0005 couvrent déjà `--write-baseline` (un ou deux tirets), `make update-baseline`, l'édition et l'écriture par commande des baselines, suites et cas.

## 10. Critères d'acceptation

`rc=` : code de sortie affiché par `echo rc=$?`. Commandes lancées depuis la racine, pile de dev arrêtée sauf mention. `T23_START` : SHA consigné en P6. Aucune commande n'est refusée par `guard_bash` (pas de `$(` après `make`, aucune écriture par commande sous `evals/`), sauf B9, dont le refus est l'attendu.

### 10.1 Noyau

| # | Commande | Attendu |
|---|---|---|
| A1 | `go test ./internal/evals/... -count=1 -v 2>&1 \| grep -c '^--- PASS'` ; même sortie `\| grep -cE -- '--- (FAIL\|SKIP)'` | `22` ; `0` |
| A2 | `go test ./internal/evals/ -count=1 -race; echo rc=$?` | `rc=0` |
| A3 | `ls internal/evals/*.go \| grep -v _test.go \| xargs grep -l '"os"'` ; `ls internal/evals/*.go \| grep -v _test.go \| xargs grep -hoE '\bos\.[A-Za-z]+' \| sort -u` | un seul fichier ; `os.SameFile` seulement |
| A4 | `ls internal/evals/*.go \| grep -v _test.go \| xargs grep -nE 'time\.Now\|panic\(\|//[[:space:]]*(nolint\|#nosec)' \| wc -l` | `0` |
| A5 | mutations N1 à N12 (section 11) sur copie privée | 12 détectées |

### 10.2 Exécuteur, avant H3

| # | Commande | Attendu |
|---|---|---|
| B1 | `go test ./cmd/rempart-evals/... -count=1 -v 2>&1 \| grep -c '^--- PASS'` ; même sortie `\| grep -cE -- '--- (FAIL\|SKIP)'` | `11` ; `0` |
| B2 | `go test ./cmd/rempart-evals/ -count=1 -race; echo rc=$?` | `rc=0` |
| B3 | `d=$(mktemp -d); make -s -f Makefile evals EVAL=demo >"$d/o" 2>"$d/e"; echo rc=$?; wc -c <"$d/o"; grep -c 'make update-baseline EVAL=demo' "$d/e"; grep -c 'evals : suite demo, cas 1, exécutions 1' "$d/e"` | `rc=3` ; `0` ; `1` ; `1` (le cas a tourné hors `go test` : critère « avant H3 ») |
| B4 | `go run ./cmd/rempart-evals --suite changed --base 0000000000000000000000000000000000000000 \| jq -r .selection.fallback; echo "rc=${PIPESTATUS[0]}"` | `base_null` ; `rc=3` (toutes les suites, baseline absente) |
| B5 | `go run ./cmd/rempart-evals --suite changed --base=--output=x \| jq -r .selection.fallback; test ! -e x; echo rc=$?` | `base_invalid` ; `rc=0` |
| B6 | `go run ./cmd/rempart-evals --suite changed --base '' \| jq -r .selection.fallback` | `base_absent` |
| B7 | `b=$(git commit-tree -m probe 'HEAD^{tree}'); go run ./cmd/rempart-evals --suite changed --base "$b" \| jq -r .selection.fallback` | `base_not_ancestor` |
| B8 | après le commit de la tâche, arbre propre : `go run ./cmd/rempart-evals --suite changed --base "$(git rev-parse HEAD)" \| jq -c '[.selection.fallback, (.suites \| length)]'` | `["",0]` |
| B9 | `go run ./cmd/rempart-evals --suite all --write-baseline` lancée par l'agent | refusée par `guard_bash` (« BLOQUÉ ») ; le comportement est prouvé par `TestWriteBaselineOnlyWithFlag` et `TestUsageErrors` |
| B10 | `ls cmd/rempart-evals/*.go \| grep -v _test.go \| xargs grep -n 'exec\.Command' \| wc -l` ; `ls cmd/rempart-evals/*.go \| grep -v _test.go \| xargs grep -nE 'StartDevServer\|DevServer\|"bash"\|"sh"' \| wc -l` | `1` ; `0` |
| B11 | `ls cmd/rempart-evals/*.go \| grep -v _test.go \| xargs grep -n 'nolint'` | au plus une ligne : `//nolint:gosec // G204: ...` sur `gitCmd`, explication citant D13 et D14 |
| B12 | `go mod tidy -diff; echo rc=$?` ; `git diff "$T23_START" -- go.mod go.sum \| wc -l` | `rc=0` ; `0` (aucune dépendance ajoutée) |
| B13 | `go test ./internal/archtest/ -count=1 -run 'TestMakefile\|TestRepositoryConforms\|TestLayoutMatchesVision' -v 2>&1 \| grep -cE -- '--- (FAIL\|SKIP)'` | `0` |
| B14 | `grep -c '^override EVAL_BASE := $(value EVAL_BASE)$' Makefile` ; `grep -cF 'go run ./cmd/rempart-evals --suite changed --base "$${EVAL_BASE:-}"' Makefile` | `1` ; `2` |
| B15 | `golangci-lint run ./cmd/rempart-evals/... ./internal/evals/...; echo rc=$?` ; `golangci-lint fmt --diff ./cmd/... ./internal/... \| wc -l` | `rc=0` ; `0` |
| B16 | `make -f Makefile verify-quick; echo rc=$?` | `rc=0` |
| B17 | mutations M1 à M28 (section 11) sur copie privée | 28 détectées |
| B18 | `make -f Makefile verify; echo rc=$?` avant H3 | `rc` non nul, sortie d'erreur contenant `make update-baseline EVAL=demo` (voulu : H3 manquante) |

### 10.3 Étape humaine H3 (dans la PR de T23, avant fusion)

L'agent pousse la branche de T23 (push soumis à approbation). La CI de la PR est **rouge** au pas `make -f Makefile verify` (code 3, message D11) : c'est voulu. L'humain, **dans son terminal, pas par Claude**, sur la branche de la PR, arbre propre :

```bash
git switch <branche de la PR M0-T23> && git pull --ff-only
git status --porcelain                        # vide
make -f Makefile update-baseline EVAL=demo    # rc=0 ; écrit evals/demo/baseline/fake/fake-model-v1.json
cat evals/demo/baseline/fake/fake-model-v1.json
#   relire : loop L0-demo, platform fake, model fake-model-v1, cases 1, runs 1,
#   success_rate 1, injection_resistance 1, avg_iterations 2, avg_tokens 30,
#   tolerances toutes à 0, regressions_vs_baseline []
git add evals/demo/baseline/fake/fake-model-v1.json
git commit -S -m "test(evals): initial baseline for demo suite"   # sans -S si aucune clé de signature (décision O10)
make -s -f Makefile evals EVAL=demo | jq -e '.cases == 1 and .regressions_vs_baseline == []'
git push
```

Le commit de H3 ne touche que la baseline et ne porte pas de ligne `Co-Authored-By` (tout commit de l'agent en porte une, `CLAUDE.md`). L'agent ne lance jamais `make update-baseline` ni `--write-baseline` (hook) et n'écrit jamais sous `evals/**/baseline*`.

### 10.4 Après H3

| # | Commande | Attendu |
|---|---|---|
| C1 | `make -s -f Makefile evals EVAL=demo \| jq -e '.cases == 1 and .regressions_vs_baseline == []'; echo "rc=${PIPESTATUS[0]} jq=${PIPESTATUS[1]}"` | `true` ; `rc=0 jq=0` (critère 5) |
| C2 | `git log --format=%H -- evals/demo/baseline \| wc -l` ; pour ce SHA `s` : `git show --name-only --format= "$s"` ; `git log -1 --format=%s "$s"` ; `git log -1 --format=%B "$s" \| grep -c 'Co-Authored-By'` ; `git log -1 --format=%G? "$s"` | `1` ; `evals/demo/baseline/fake/fake-model-v1.json` seul ; `test(evals): initial baseline for demo suite` ; `0` ; `G` si signé (sinon `N`, consigné) |
| C3 | `jq -e '.tolerances == {"success_rate_drop":0,"correct_escalation_drop":0,"avg_iterations_rise":0,"avg_tokens_rise_pct":0} and .report.cases == 1' evals/demo/baseline/fake/fake-model-v1.json` | `true` |
| C4 | `make -f Makefile verify; echo rc=$?` (sans `EVAL_BASE` : toutes les suites) | `rc=0` (critère 1, local) |
| C5 | `export EVAL_BASE=$(git merge-base origin/main HEAD)` puis `make -f Makefile verify; echo rc=$?` | `rc=0` |
| C6 | `make -f Makefile dev-down && make -s -f Makefile evals EVAL=demo \| jq -e .; echo "rc=${PIPESTATUS[0]}"` | `rc=0` (aucune pile requise) |
| C7 | si les espaces de noms sont permis : `GOFLAGS=-mod=readonly GOPROXY=off unshare -rn make -s -f Makefile evals EVAL=demo \| jq -e '.regressions_vs_baseline == []'` | `true` (aucun réseau) ; sinon « non vérifiable ici », consigné |
| C8 | `gh run list --workflow verify.yml --branch <branche> --limit 1 --json conclusion --jq '.[0].conclusion'` (par l'humain si `gh` est absent) | `success` |
| C9 | Témoin du critère 5 : `go test ./cmd/rempart-evals/ -run TestRegressionDetected -count=1; echo rc=$?` | `rc=0` |

## 11. Mutations à tuer

Rejouées par `acceptance-verifier` sur une copie privée (`mktemp -d`, SHA consigné) ; `test-author` fixe les ancres exactes (`OLD`, `NEW`) dans un amendement V1 après avoir écrit et vérifié le code de référence.

| # | Mutation | Test qui doit échouer |
|---|---|---|
| N1 | `LoadBaseline` sans liste d'admission | `TestLoadBaselineStrict` |
| N2 | `LoadBaseline` sans `exactKeys` | `TestLoadBaselineStrict` |
| N3 | `LoadBaseline` sans `DisallowUnknownFields` | `TestLoadBaselineStrict` |
| N4 | parent lien accepté (`realDir` retiré de `LoadBaseline`) | `TestLoadBaselineStrict` |
| N5 | `sameFile` rend toujours vrai | `TestReadRegularSameFile` |
| N6 | `EncodeBaseline` sans `Validate` | `TestEncodeBaselineRoundTrip` |
| N7 | `DiscoverSuites` sans refus des liens | `TestDiscoverSuites` |
| N8 | contrôle de `CaseTags` retiré | `TestCaseTagsClosedVocabulary` |
| N9 | borne de 160 portée à 161 | `TestLineLengthBounded` |
| N10 | refus de la barre oblique inverse hors guillemets doubles retiré (s) | `TestNeedleHardening` |
| N11 | refus des deux espaces retiré (t) | `TestNeedleHardening` |
| N12 | jeu fermé des motifs `watch` retiré | `TestWatchPatternCharset` |
| M1 | `validRef` rend toujours vrai | `TestRejectsUnsafeGitRef` |
| M2 | `--end-of-options` retiré des arguments | `TestGitCommandShape` |
| M3 | `--no-renames` retiré | `TestGitCommandShape` |
| M4 | SHA nul admis | `TestRejectsUnsafeGitRef` |
| M5 | code 1 de `merge-base` traité comme ancêtre | `TestSuiteChangedSelection` |
| M6 | échec de `git` : aucune suite au lieu de toutes | `TestSuiteChangedSelection` |
| M7 | fichiers non suivis ignorés (commande 3 retirée) | `TestSuiteChangedSelection` (`real_repo`) |
| M8 | borne de sortie de `git` retirée | `TestSuiteChangedSelection` |
| M9 | `cmd.Env` laissé nul (environnement hérité) | `TestGitCommandShape` |
| M10 | baseline absente : code 0 | `TestMissingBaselineAsksHuman` |
| M11 | message du code 3 sans `make update-baseline EVAL=` | `TestMissingBaselineAsksHuman` |
| M12 | rapport écrit sur stdout avec le code 3 | `TestMissingBaselineAsksHuman` |
| M13 | `regressions_vs_baseline` forcé à `[]` (pas de `Compare`) | `TestRegressionDetected` |
| M14 | écriture de la baseline même sans le drapeau | `TestWriteBaselineOnlyWithFlag` |
| M15 | `--write-baseline` admis avec `all` | `TestUsageErrors` |
| M16 | tolérances écrites à la valeur maximale de `Validate` | `TestWriteBaselineOnlyWithFlag` |
| M17 | `SetLogger` retiré (journal du SDK sur stdout) | `TestStdoutSingleJSONDocument` |
| M18 | script fixe (`salut`, `bonjour`) au lieu de `input.replies` | `TestDemoTargetRunsWorkflow` |
| M19 | `Escalated` toujours faux | `TestDemoTargetRunsWorkflow` |
| M20 | `SchemaValid` toujours vrai | `TestDemoTargetRunsWorkflow` |
| M21 | environnement de test partagé entre exécutions | `TestDemoTargetRunsWorkflow` |
| M22 | refus de `TEMPORAL_DEBUG` retiré | `TestUsageErrors` |
| M23 | `--base` admis avec une suite nommée | `TestUsageErrors` |
| M24 | baseline illisible : code 3 au lieu de 2 | `TestBaselineReadStrictly` |
| M25 | `Makefile` : ligne d'evals retirée de `verify` | `TestMakefileTargets` |
| M26 | `Makefile` : `override EVAL_BASE := $(EVAL_BASE)` | `TestMakefileTargets` |
| M27 | `Makefile` : branche `changed` sans `--base` | `TestMakefileTargets` |
| M28 | `Makefile` : ligne d'evals de `verify` après le sous-make `dev` | `TestMakefileTargets` |

## 12. Décisions ouvertes (retenues sur délégation, réversibles, à relire par l'humain)

| # | Question | Options | Retenue |
|---|---|---|---|
| O1 | Forme de `EVAL_BASE` (D13) | (a) SHA hexadécimal complet seulement ; (b) références symboliques en liste blanche `[A-Za-z0-9._/-]`, sans `-` initial ni `..` | (a) : plus strict ; un nom symbolique fait tout rejouer (plus d'evals, jamais moins) |
| O2 | Portée du diff (D15) | (a) base contre arbre de travail, plus non suivis ; (b) `base..HEAD` | (a) : couvre le travail non commité |
| O3 | Tolérances écrites par `--write-baseline` (D19) | (a) nulles ; (b) maximales admises par `Validate` | (a) : l'humain relâche explicitement dans sa PR |
| O4 | Vocabulaire des étiquettes (D21) | (a) liste fermée de 6 ; (b) catégories fermées plus étiquettes de domaine libres | (a) : seule forme qui ferme T66 |
| O5 | Noyau de `SelectChanged` (D24) | (a) ajouter `Makefile` et `.github/workflows/**` ; (b) inchangé | (a) |
| O6 | Liens sous `evals/` (D17) | (a) refus total ; (b) ignorés | (a) |
| O7 | Variables `TEMPORAL_*` (D3) | (a) code 2 ; (b) ignorées | (a) |
| O8 | Place des evals dans `verify` (D25) | (a) avant `dev` ; (b) après l'intégration | (a) : échec tôt, sans Docker |
| O9 | Sortie multi-suites (D10) | (a) un document `{"selection","suites"}` ; (b) une ligne JSON par suite | (a) : `jq` direct, un seul document |
| O10 | Preuve d'auteur de la baseline (C2) | (a) commit signé par l'humain (`%G?` = `G`) ; (b) commit ne touchant que la baseline, sans `Co-Authored-By` | (b) exigé, (a) recommandé : l'agent pousse avec l'identité de l'humain (obligation (bu), risque accepté), donc `%an` ne prouve rien ; la garantie réelle reste le hook plus CODEOWNERS |
| O11 | Proposition 0010 (section 9) | appliquer avant la fusion ; après | avant la fusion (recommandé) |
| O12 | ADR 0005 | accepter ; amender (exécution contre `make dev`) | accepter (proposé) |

## 13. Risques

| # | Risque | Atténuation |
|---|---|---|
| R1 | `testsuite` hors `go test` : comportements constatés dans le SDK (journal sur stdout, délai de 3 s, `TEMPORAL_DEBUG`, `TEMPORAL_SDK_FLAG_*`) et d'autres possibles | D1 à D3 ; B3 exécute la cible par `go run` avant H3 ; si l'environnement de test échoue hors `go test` : arrêt et deux options présentées à l'humain (cible contre la pile `make dev`, ADR 0005 option 1 ; ou exécution par un binaire de test) |
| R2 | `--end-of-options` non reconnu par `git diff` ou `merge-base` du poste ou de la CI (introduit en git 2.24) | sous-test `real_repo` sur le `git` installé ; à l'exécution, un échec donne `git_failed`, donc toutes les suites (jamais moins) |
| R3 | `GIT_CONFIG_GLOBAL=/dev/null` : dépôt d'un autre propriétaire refusé (`safe.directory`) | repli `git_failed`, toutes les suites ; l'espace de travail du runner GitHub appartient à son utilisateur |
| R4 | CI rouge sur la PR jusqu'à H3 | voulu (fiche, R3 du jalon) ; H3 dans la même PR |
| R5 | Dérive entre le câblage de `cmd/rempart-worker` et la cible `demo` | D5 reprend les mêmes constantes ; revue ; `TestDemoTargetRunsWorkflow` et `make demo` |
| R6 | L'obligation (u) invalide des lignes des tests de M0-T22 | lignes ajustées en phase tests, jamais en impl ; décompte des 14 fonctions inchangé |
| R7 | `guard_bash` refuse une commande de vérification qui écrit en citant `evals/.../baseline` | critères rédigés sans redirection vers ces chemins ; fixtures écrites par l'outil d'édition |
| R8 | Durée de `go test -short ./...` (hook Stop, 840 s) | exécutions de démo à horloge simulée, en millisecondes |
| R9 | `go run` recompile à chaque `make evals` | coût accepté en M0 (binaire d'outillage) |
| R10 | Une base de PR qui n'est plus ancêtre (réécriture de `main`) | `base_not_ancestor` : toutes les suites |

## 14. Impact sur le modèle de menace (`docs/02-THREAT-MODEL.md`, par l'agent principal après la revue)

| Menace | Changement |
|---|---|
| T8 | Seconde exécution de commande du dépôt : `git` depuis `cmd/rempart-evals`, trois formes fixes, SHA hexadécimal, `--end-of-options`, environnement en liste blanche, sorties bornées, jamais de shell ; résidu : `git` résolu par `PATH`. Vérification : `TestGitCommandShape`, `TestRejectsUnsafeGitRef` |
| T28 | `EVAL_BASE` figée par `$(value ...)` et exportée. Vérification : `TestMakefileTargets` |
| T58 | Baseline de `demo` écrite par l'humain (H3), tolérances nulles, lecture stricte. Vérification : C2, C3, `TestBaselineReadStrictly` |
| T59 | TOCTOU : `sameFile` et racines `os.Root`. Vérification : `TestReadRegularSameFile`, `TestUsageErrors` (`evals` lien) |
| T60, T62, T64 | Mêmes règles pour la baseline que pour les cas (liste d'admission, clés exactes, lignes bornées). Vérification : `TestLoadBaselineStrict` |
| T61 | Soldée côté exécuteur : `--no-renames`, `-z`, fichiers non suivis inclus, repli sur toutes les suites (obligation (bs)). Vérification : `TestSuiteChangedSelection` |
| T64, T65 | Résidus (s) et (t) soldés. Vérification : `TestNeedleHardening`, `TestLineLengthBounded` |
| T66 | Vocabulaire fermé des étiquettes. Vérification : `TestCaseTagsClosedVocabulary` |
| T67 | Jeu fermé des motifs `watch`. Vérification : `TestWatchPatternCharset` |
| T41 | Faux fournisseur câblé dans un binaire d'outillage jamais livré (`ToolingCmd`) ; `internal/loops/fake` toujours interdit hors tests. Vérification : `TestRepositoryConforms` |
| **T83 (nouvelle)** | Exécuteur d'evals affaibli (grader, cible, sélection, `Compare` dans `cmd/rempart-evals` ou `internal/evals`) pour masquer une régression sans toucher `evals/` (T, R). Atténuation : mutations de la section 11 et de M0-T22, revue humaine, proposition 0010 (CODEOWNERS). Vérification : `.github/CODEOWNERS` contient `/cmd/rempart-evals/` et `/internal/evals/` |
| **T84 (nouvelle)** | Sortie ou comportement de l'exécuteur modifiés par l'environnement : journal du SDK Temporal sur stdout, `TEMPORAL_DEBUG`, `TEMPORAL_SDK_FLAG_*`, variables `GIT_*` (T, D). Atténuation : D2, D3, D14. Vérification : `TestStdoutSingleJSONDocument`, `TestUsageErrors`, `TestGitCommandShape` |

## 15. Tâches ordonnées (chacune un cycle tests puis impl)

| # | Tâche | Qui | Vérification |
|---|---|---|---|
| 0 | Phase free : préconditions P1 à P6 ; ADR 0005 consigné « proposé » dans `docs/STATUS.md` | principal | P1 à P6 conformes |
| A1 | `rempart-state phase tests` ; tests 8.1 (8 fonctions, ligne de `TestSelectChanged`, lignes existantes ajustées pour D21 et D22) ; code de référence écrit et vérifié sur copie privée, ancres N1 à N12 fixées (amendement V1 si écart) | `test-author` | `go vet ./internal/evals/` : `undefined: LoadBaseline` et voisins seulement |
| A2 | `rempart-state phase impl` ; code du noyau (5.1, D18 à D24) | principal | A1 à A4 ; `make -f Makefile verify-quick` |
| B1 | `phase tests` ; tests 8.2 sauf `TestSuiteChangedSelection`, `TestRejectsUnsafeGitRef`, `TestGitCommandShape` ; fixtures `testdata/{ok,regression,missing,badbaseline}` ; `evals/demo/suite.yaml` et `evals/demo/cases/demo-converge-001.yaml` (section 7) ; vérification sur copie que la cible tourne par `go run` (R1) | `test-author` | `go vet ./cmd/rempart-evals/` : `undefined: runWith` et voisins seulement |
| B2 | `phase impl` ; `main.go`, `run.go`, `targets.go`, `baseline.go` (D1 à D12, D16, D18, D19) | principal | les 8 fonctions de B1 vertes ; B3 (`rc=3`) ; `make -f Makefile verify-quick` |
| C1 | `phase tests` ; `TestSuiteChangedSelection` (dont `real_repo`), `TestRejectsUnsafeGitRef`, `TestGitCommandShape` ; fixture `testdata/select` et cible `stub` de test | `test-author` | `undefined: gitCmd` et voisins seulement |
| C2 | `phase impl` ; `git.go`, modes `all` et `changed`, `DiscoverSuites` branché (D13 à D15, D17) | principal | B1, B2, B4 à B8, B10, B11 |
| D1 | `phase tests` ; `internal/archtest/makefile_test.go` (8.3) | `test-author` | `TestMakefileTargets` rouge sur le `Makefile` actuel, pour `EVAL_BASE` et la ligne d'evals |
| D2 | `phase impl` ; `Makefile` (5.3) | principal | B12 à B14, B16, B18 |
| E1 | `security-reviewer` sur le diff de la tâche (T8, T28, T58 à T67, T83, T84) ; en cas de BLOCK : amendement V2 et retour en phase tests | subagent | PASS |
| E2 | `acceptance-verifier` : critères 10.1 et 10.2, mutations de la section 11 | subagent | PASS avec preuves |
| E3 | Phase free : proposition 0010 ; `docs/02-THREAT-MODEL.md` (section 14) ; `docs/STATUS.md` (obligations (r) à (z) et (bs) soldées ou restantes, O1 à O12, ADR 0005 à trancher, H3 attendue) ; commit `feat(evals): eval runner, demo suite and targeted evals in verify (M0-T23)` ; push (approbation) | principal | `git status --porcelain` vide ; CI de la PR rouge au code 3, attendue |
| H3 | Baseline initiale (section 10.3) | **humain** | C1 à C3 |
| F1 | `acceptance-verifier` : critères 10.4 ; `docs/STATUS.md` : M0-T23 terminée, critère 5 prouvé ; prochaine étape `/close-milestone M0` | principal, subagent | C1 à C9 ; `make -f Makefile verify` rc=0 |
