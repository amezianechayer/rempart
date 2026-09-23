# M0-T01 `squelette` : squelette compilable, Makefile, lint, `make verify-quick` vert

- Date : 2026-09-23
- Auteur : subagent `architect`
- Statut : relu par l'agent principal ; **amendé** le 2026-09-23 par R1 (section 0), après la revue `security-reviewer` (verdict PASS avec constats moyens)
- Fiche d'origine : `docs/plans/M0-overview.md` section 7 (M0-T01), précisée par les sections 2.2, 3, 4 et 5.5. Ce plan ne l'élargit pas ; les précisions sont listées en section 2.3.
- Sources lues : `prompts/M0.md` ; `docs/00-VISION.md` §4 ; `docs/02-THREAT-MODEL.md` ; `docs/04-INTERFACE.md` §8 ; `docs/STATUS.md` ; `docs/SETUP.md` ; `Makefile.template` ; `.gitignore` ; `README.md` ; skill `go-platform-conventions` ; `.claude/settings.json` ; hooks `guard_edit.py`, `guard_bash.py`, `stop_verify.py`, `post_edit_check.py`, `_common.py` ; `.claude/bin/rempart-state` (état actuel, patch 0001 non appliqué) ; `scripts/check-tools.sh`.
- Faits d'environnement au 2026-09-23 (fournis par l'agent principal) : Go stable le plus récent 1.27.1 ; Go local 1.24.7 avec `GOTOOLCHAIN=auto` ; golangci-lint v2.13.2 ; gofumpt v0.12.0 ; govulncheck `golang.org/x/vuln` v1.8.0 (exige go >= 1.26) ; OPA 1.20.2 ; `proxy.golang.org` et `sum.golang.org` joignables, `github.com` (releases) et `go.dev` bloqués ; démon Docker injoignable dans le conteneur.

---

## 0. Amendement R1 (revue sécurité du 2026-09-23, prime sur le reste du document)

La revue `security-reviewer` de l'implémentation conforme à la première version de ce plan a rendu PASS avec trois constats moyens et deux bas, tous démontrés sur copie. Ils sont corrigés dans T01 (retour journalisé en phase tests) plutôt que reportés, car ils contredisent la précision P6 et la section 13.

| # | Constat | Correctif (sections 6.1 et 6.2 mises à jour) | Règle de test ajoutée |
|---|---|---|---|
| R1-a (moyen) | GNU make développe une variable passée en ligne de commande quand il l'exporte : `make sandbox-plan SCENARIO='$(shell ...)'` exécute la commande avant la garde et la liste blanche (même chose pour `EVAL`). P6 « jamais interpolées par make » était faux. | `override X := $(value X)` puis `export`, pour `SCENARIO`, `EVAL`, `POLICIES_DIR`, `OPA` | `TestMakefileTargets` règle 13 |
| R1-b (moyen) | La confirmation « oui » se fournit par un tube (`printf 'oui\n' \| make sandbox-apply`). | `read ... </dev/tty` : sans terminal, la recette échoue | règle 14 |
| R1-c (moyen) | Un `// #nosec` fait taire gosec sans passer par nolintlint. | `linters.settings.gosec.config.global.nosec: true` | `TestGolangciConfig` règle 7 ; critère 8 étendu |
| R1-d (bas) | `POLICIES_DIR` et `OPA` interpolés par make entre apostrophes : échappement possible. | lus par le shell (`"$$POLICIES_DIR"`, `"$$OPA"`) | règle 5 étendue à ces deux variables ; règle 10 accepte `"$$OPA" test` |
| R1-e (bas) | `EVAL` sans liste blanche. | `^[a-z0-9][a-z0-9/_-]{0,126}$` avant `go run`, après la garde de présence de `cmd/rempart-evals` | règle 15 |

Portée de R1-b (corrigée après la contre-revue) : la lecture sur `/dev/tty` ferme le tube sur l'entrée standard, mais **pas** `make -i` (ou `MAKEFLAGS=i`), le préfixe `-` sur une ligne de recette, `.IGNORE`, ni un pseudo-terminal (`script`, `pty`). Elle n'est donc pas une approbation humaine ; elle reste sans effet tant que `scripts/sandbox.sh` n'existe pas (la garde échoue d'abord). Mesures hors dépôt proposées à l'humain (harnais) : `docs/proposals/0003-garde-make-variables.md`. Menaces nouvelles : T28 à T32 de `docs/02-THREAT-MODEL.md`.

### Contre-revue R1 (2026-09-23) : verdicts PASS, constats reportés avant M3

`security-reviewer` et `acceptance-verifier` ont rendu PASS sur l'implémentation R1. Constats moyens restants, à corriger par une tâche dédiée **avant** la création de `scripts/sandbox.sh` (M3), et au plus tard avec M0-T04 pour le point 2 :

1. Confirmation contournable par le moteur make (`-i`, `MAKEFLAGS`, préfixe `-`, `.IGNORE`) ou par un pseudo-terminal : validation, lecture, test et appel sur une seule ligne logique chaînée par `&&` ; en M3, approbation par un canal hors de portée de l'agent (T31).
2. `GNUmakefile` ou `makefile` écrit par l'agent : il remplace `Makefile` pour toute commande `make`, y compris celle du hook Stop et de la CI (T32). Correctifs : règle archtest qui refuse ces fichiers ; `make -f Makefile` dans le hook Stop (harnais) et dans la CI (M0-T04).
3. Mutations non détectées par `TestMakefileTargets` : préfixe `-` retiré par l'analyseur, `[ ... ] || true`, `</dev/tty || a=oui`, `MAKEFLAGS +=`, `.IGNORE`, `$(value X)` en recette.

---

## 1. Objectif

Amener le dépôt à `make verify-quick` vert avant toute logique : module Go, arborescence de `docs/00-VISION.md` §4 avec un `doc.go` par domaine, cinq binaires réduits à un stub, `Makefile` corrigé, configuration golangci-lint v2, et quatre tests d'architecture (`internal/archtest`) qui rendent ces propriétés mécaniques.

---

## 2. Périmètre

### 2.1 Dans le périmètre
- `go.mod` et `go.sum` (étape 0) : module `github.com/amezianechayer/rempart`, directive `go 1.27.1`, directive `tool golang.org/x/vuln/cmd/govulncheck` (v1.8.0).
- 21 domaines `internal/<d>/doc.go`, plus `internal/archtest/doc.go`.
- 5 stubs `cmd/<b>/main.go`.
- Dossiers de premier niveau : `policies/{design,iac,runtime,k8s}`, `modules`, `schemas`, `evals`, `web`, chacun avec `.gitkeep`.
- `Makefile` (`git mv Makefile.template Makefile`, puis réécriture selon la section 6.1).
- `.golangci.yml` (section 6.2), `.gitignore` (ajouts `/bin/` et `evals/**/reports/`).
- Tests `internal/archtest/*_test.go` : `TestLayoutMatchesVision`, `TestGoDirective`, `TestMakefileTargets`, `TestGolangciConfig`.
- Mise à jour documentaire induite : `README.md` (ligne `Makefile.template`), `docs/SETUP.md` (versions épinglées, exigence de la section 2.3 de la vue d'ensemble), `docs/STATUS.md` à la clôture.

### 2.2 Hors périmètre
- Toute logique dans les stubs (pas d'analyse d'arguments, pas de configuration, pas de `slog`).
- Règles d'import R1 à R5 et `go list` (M0-T02).
- `docker-compose.yml`, `scripts/dev-*`, `make dev` réel, `dev-preflight` en prérequis de `dev` (M0-T03).
- CI GitHub Actions, CODEOWNERS (M0-T04).
- `cmd/rempart-evals`, `internal/evals`, `make evals` et `update-baseline` fonctionnels (M0-T22, M0-T23).
- `scripts/sandbox.sh` (M3). `scripts/check-tools.sh` reste inchangé (il exige encore un binaire `govulncheck` dans le `PATH`, ce qui est inoffensif).
- Toute modification de `docs/00-VISION.md` (le test la lit, il ne la réécrit pas).

### 2.3 Précisions par rapport à la fiche (sans élargissement)

| # | Point de la fiche | Précision retenue | Raison |
|---|---|---|---|
| P1 | Critère 7 : `go run ./cmd/rempartd; echo rc=$?` attend `rc=2` | Commande principale : binaire construit dans `bin/` puis exécuté (section 9) | `go run` ne propage pas le code de sortie du programme : il affiche `exit status 2` et sort lui-même en 1 (comportement de `cmd/go` constaté jusqu'à 1.24 au moins ; à reconfirmer sous 1.27.1). |
| P2 | Critère 8 : `grep -rn 'nolint' --include='*.go' .` vaut 0 | Motif `//[[:space:]]*nolint` | `TestGolangciConfig` contient légitimement la chaîne `nolintlint` (nom du linter vérifié) : le motif de la fiche compterait ce test. Seules les directives comptent. |
| P3 | Critère 3 : « 4 `--- PASS` » | Comptage des seules lignes de premier niveau, plus témoins négatifs comptés à part | Les sous-tests affichent aussi `--- PASS` (indentés). |
| P4 | `TestGoDirective` : « au moins 1.23 » | Seuil 1.24, plus chemin du module et directive `tool` govulncheck | La directive `tool` (dont dépend `go tool govulncheck` dans `verify`) exige go >= 1.24. |
| P5 | « Étape OPA conditionnée à la présence d'un `.rego` » | Cible dédiée `opa-test` (variables `POLICIES_DIR`, `OPA`) appelée par `verify-quick` | Rend les trois branches (aucun `.rego`, `.rego` et `opa` présent, `.rego` et `opa` absent) vérifiables par commande sans toucher au dépôt. |
| P6 | Cibles `sandbox-*` et `evals` du modèle | `SCENARIO` et `EVAL` lus par le shell depuis l'environnement, jamais interpolés par make ; `SCENARIO` validé par liste blanche | Menace T8 : une valeur `SCENARIO='x; commande'` serait exécutée par l'interpolation textuelle du modèle. |
| P7 | `dev-preflight`, `dev-down` en T01 | `dev-preflight` réel (lecture seule, code 2 et renvoi à `docs/SETUP.md`) mais pas encore prérequis de `dev` ; `dev-down` sans action, code 0 | `make dev` doit nommer M0-T03 (critère 6) même sans Docker ; un arrêt sans pile démarrée est un succès (idempotence). |
| P8 | `evals`, `update-baseline` en code 2 | Garde sur la présence de `cmd/rempart-evals`, commande du modèle conservée derrière | M0-T23 n'aura qu'à livrer le binaire ; `update-baseline` reste réservé à l'humain. |
| P9 | `arch-test` | `go test -count=1 ./internal/archtest/...` | Ces tests lisent des fichiers hors sources Go ; on écarte tout doute sur le cache de tests. |
| P10 | `TestLayoutMatchesVision` | Concordance vérifiée avec le bloc « Modules » de `docs/00-VISION.md` §4 ; refus des dossiers `internal/*` et `cmd/*` absents de la vision et de la liste d'outillage | La vision est la référence : un domaine ajouté sans ADR ou un domaine retiré de la vision fait échouer le test. |
| P11 | Tests « rouges » | Chaque test porte des témoins négatifs (arbres `testing/fstest.MapFS`, contenus synthétiques) | Prouve que les vérifications ne sont pas vides. |

---

## 3. Conditions d'entrée et écarts dus au harnais non patché

### 3.1 Conditions d'entrée
- H0 partiel : patch 0001 **non appliqué** (étape humaine ouverte, l'agent n'a pas le droit de l'appliquer) ; outils installés, `bash scripts/check-tools.sh` vert, tag `m0-start` posé, jalon M0.
- D0 fait (vision amendée, liste d'outillage dans `docs/00-VISION.md` §4).
- `python3 .claude/bin/rempart-state show` : `jalon=M0 phase=free` avant `/task`.

### 3.2 Écarts dus au harnais non patché

La section 2.2 de la vue d'ensemble décrit le harnais **après** le patch 0001. Avec le harnais actuel :

1. **Porte `phase impl` aveugle aux fichiers d'un dossier non suivi.** `rempart-state` lit `git status --porcelain` sans `-uall` : tant que `internal/` n'est pas suivi, Git n'affiche que `?? internal/` et la porte répond « aucun test nouveau ou modifié ». Contournement légitime (il ne trompe pas la porte, il lui montre les vrais fichiers) : `git add go.mod go.sum internal/archtest/` juste avant `phase impl`, ce qui fait apparaître chaque `A  internal/archtest/<f>_test.go`. La porte lance alors `go test ./internal/archtest` sans tag, qui doit échouer. Rien n'est commité à ce stade. Une fois le patch appliqué, ce `git add` reste inoffensif.
2. **Hook Stop.** Il exige `make verify-quick` dans toutes les phases dès que `Makefile` contient la cible. En phase tests, `Makefile` n'existe pas (seul `Makefile.template` existe, et le hook ne le lit pas) : aucun blocage malgré les tests rouges. Conséquences : (a) le `git mv Makefile.template Makefile` se fait en phase impl ; (b) il se fait **en dernier**, après tous les autres fichiers, et dans le même tour que la réécriture du Makefile et le premier `make verify-quick` vert. Tant que `Makefile` est absent, l'agent peut terminer un tour sans risque ; dès qu'il existe, chaque fin de tour exige le vert (trois échecs, puis BLOCAGE consigné).
3. **`post_edit_check.py` lance `go vet` sur le paquet d'un `_test.go` en phase tests.** Donc : les tests ne référencent **aucun** symbole de production ; ils compilent seuls en `package archtest`, sans `doc.go` (qui est du code de production sous `internal/`, bloqué par `guard_edit` en phase tests). **Aucun fichier non test n'est nécessaire** : racine du dépôt, analyseurs et vérifications vivent tous dans des `_test.go`. `go vet` accepte un paquet composé uniquement de fichiers de test (il vérifie la variante de test) ; si ce n'était pas le cas sous 1.27.1, le message du hook serait informatif (le fichier est déjà écrit) et la preuve de compilation se ferait par `go test`. Ordre d'écriture recommandé : `repo_test.go` d'abord (utilitaires communs), puis les quatre fichiers de test, chacun important seulement ce qu'il utilise, pour éviter des échecs transitoires de `go vet`.
4. **Baselines non protégées dans toutes les phases** : sans objet pour T01 (aucune baseline).
5. **Fichiers racine non gardés en phase tests.** `guard_edit` ne classe comme code de production que `internal/`, `cmd/`, `pkg/`, `policies/`, `modules/`, `web/src/`. `Makefile`, `.golangci.yml`, `.gitignore` pourraient donc techniquement être écrits en phase tests. Règle de discipline de ce plan : en phase tests, seuls `go.mod` et `go.sum` (étape 0) et `internal/archtest/*_test.go` sont créés. Vérification avant `phase impl` : `test ! -e Makefile && test ! -e .golangci.yml; echo rc=$?` affiche `rc=0`.
6. **`guard_bash` actuel** ne bloque que `make update-baseline` (pas encore `--write-baseline` seul) : sans incidence en T01, `cmd/rempart-evals` n'existant pas.

### 3.3 Étape 0 (agent principal, juste après `phase tests`, avant délégation à `test-author`)

```bash
python3 .claude/bin/rempart-state phase tests
go mod init github.com/amezianechayer/rempart
go mod edit -go=1.27.1
go get -tool golang.org/x/vuln/cmd/govulncheck@v1.8.0
```

Aucun hook ne bloque ces commandes : ce sont des appels Bash (pas d'Edit/Write, donc ni `guard_edit` ni `post_edit_check`), et aucune règle de `guard_bash` ne vise `go mod` ou `go get`. `go.mod` et `go.sum` sont à la racine, hors des motifs de code de production.

Vérifications de l'étape 0 :

| Commande | Résultat attendu |
|---|---|
| `grep -E '^(module\|go\|tool) ' go.mod` | `module github.com/amezianechayer/rempart`, `go 1.27.1`, `tool golang.org/x/vuln/cmd/govulncheck` |
| `grep -c '^toolchain' go.mod` | `0` (aucune directive `toolchain` nécessaire) |
| `go version` (depuis la racine) | `go version go1.27.1 linux/amd64` (chaîne téléchargée par `GOTOOLCHAIN=auto`) |
| `go list -m golang.org/x/vuln` | `golang.org/x/vuln v1.8.0` |
| `go mod verify` | `all modules verified` |

`go mod tidy` n'est **pas** lancé à l'étape 0 (module sans paquet à ce stade) ; `go mod tidy -diff` est vérifié en fin d'impl (tâche I7).

---

## 4. Fichiers exacts

| Fichier | Phase | Contenu |
|---|---|---|
| `go.mod`, `go.sum` | tests (étape 0) | section 3.3 |
| `internal/archtest/repo_test.go` | tests | racine du dépôt, accès fichiers par `fs.FS` |
| `internal/archtest/layout_test.go` | tests | `TestLayoutMatchesVision` |
| `internal/archtest/gomod_test.go` | tests | `TestGoDirective` |
| `internal/archtest/makefile_test.go` | tests | `TestMakefileTargets` |
| `internal/archtest/golangci_test.go` | tests | `TestGolangciConfig` |
| `internal/{intent,design,threat,policy,iacgen,validate,plan,apply,runner,inventory,graph,attackpath,remediate,drift,finops,compliance,evidence,loops,llm,secrets,tenancy}/doc.go` (21) | impl | section 5.2 |
| `internal/archtest/doc.go` | impl | section 5.2 |
| `cmd/{rempartd,rempart-worker,rempart-runner,rempart,rempart-mcp}/main.go` (5) | impl | section 5.1 |
| `policies/design/.gitkeep`, `policies/iac/.gitkeep`, `policies/runtime/.gitkeep`, `policies/k8s/.gitkeep`, `modules/.gitkeep`, `schemas/.gitkeep`, `evals/.gitkeep`, `web/.gitkeep` (8, vides) | impl | vide |
| `.golangci.yml` | impl | section 6.2 |
| `.gitignore` | impl | ajouts `/bin/` et `evals/**/reports/` |
| `Makefile` (`git mv Makefile.template Makefile`) | impl, en dernier | section 6.1 |
| `README.md`, `docs/SETUP.md` | impl (documentation) | section 10, tâche I8 |

Aucun fichier `testdata/` en T01 : toutes les entrées des témoins sont en ligne dans les tests.

---

## 5. Interfaces

### 5.1 Stub de `main` (identique pour les 5 binaires, seuls `name` et le commentaire changent)

```go
// Command rempartd is the Rempart control plane API server.
//
// Stub (M0-T01): prints "not implemented" on stderr and exits with status 2.
package main

import (
	"fmt"
	"os"
)

const name = "rempartd"

func main() {
	_, _ = fmt.Fprintln(os.Stderr, name+": not implemented (M0)")
	os.Exit(2)
}
```

- Sortie standard vide ; stderr : exactement `<binaire>: not implemented (M0)` ; code 2 (« non disponible » ; cohérent avec le code 2 « usage ou configuration » de `rempart-evals` en M0-T23 ; la table des codes stables de la CLI, `docs/04-INTERFACE.md` §8, sera fixée avec la première commande réelle).
- `_, _ =` explicite : ni `errcheck` ni `gosec` G104 ne dépendent d'une liste d'exclusions implicite.
- Commentaires de paquet :

| Binaire | Première ligne du commentaire |
|---|---|
| `rempartd` | `Command rempartd is the Rempart control plane API server.` |
| `rempart-worker` | `Command rempart-worker runs the Rempart Temporal workers.` |
| `rempart-runner` | `Command rempart-runner is the customer-side runner that executes signed, approved plans.` |
| `rempart` | `Command rempart is the Rempart command-line interface.` |
| `rempart-mcp` | `Command rempart-mcp is the Rempart MCP server.` |

### 5.2 `doc.go` des domaines

Gabarit (anglais, comme tout le code) :

```go
// Package intent turns a natural-language request into the Intent IR and handles clarifications.
//
// No code yet: created by M0-T01 from docs/00-VISION.md section 4.
package intent
```

| Paquet | Première phrase (après `Package <nom> `) |
|---|---|
| `intent` | `turns a natural-language request into the Intent IR and handles clarifications.` |
| `design` | `builds the architecture graph, plans CIDR ranges and applies patterns.` |
| `threat` | `runs STRIDE threat modelling on the architecture graph.` |
| `policy` | `wraps the OPA engine, policy packs and the compliance mapping.` |
| `iacgen` | `generates OpenTofu code from the validated architecture graph.` |
| `validate` | `runs the IaC validation chain and normalizes its errors.` |
| `plan` | `handles OpenTofu plans, blast radius, risk and graph/plan equivalence.` |
| `apply` | `orchestrates applies through the runner, post-deployment checks and rollback.` |
| `runner` | `implements the runner protocol: signed plan retrieval, execution and attestations.` |
| `inventory` | `holds the cloud collectors (AWS, Azure, OVHcloud, Scaleway, Kubernetes).` |
| `graph` | `holds the unified security graph, reachability and effective permissions.` |
| `attackpath` | `computes non-destructive attack paths.` |
| `remediate` | `maps a finding to its IaC source, a fix and a pull request.` |
| `drift` | `detects drift between the IaC and the deployed infrastructure.` |
| `finops` | `covers costs, anomalies and recommendations.` |
| `compliance` | `maps controls, collects evidence and produces exports.` |
| `evidence` | `builds signed evidence bundles and the hash-chained journal.` |
| `loops` | `holds the Temporal workflows, one per loop.` |
| `llm` | `holds ModelProvider, versioned prompts, redaction and untrusted-data quarantine.` |
| `secrets` | `integrates OpenBao and dynamic credentials.` |
| `tenancy` | `handles tenant isolation, RBAC and identities.` |
| `archtest` | `holds the repository architecture and configuration tests. Development tooling only, never shipped to customers.` |

### 5.3 Contrat des utilitaires de test (tous dans des `_test.go`, `package archtest`, bibliothèque standard seulement)

```go
// repo_test.go
const modulePath = "github.com/amezianechayer/rempart"

// repoRoot remonte depuis os.Getwd() (répertoire du paquet pendant go test) jusqu'au premier
// dossier contenant un fichier go.mod ; vérifie que sa ligne module vaut modulePath ;
// t.Fatal si la racine du système de fichiers est atteinte ou si le module diffère.
// Renvoie le chemin et os.DirFS(chemin) : toute lecture passe par fs.ReadFile, fs.Stat, fs.ReadDir
// (jamais os.ReadFile(variable), signalé par gosec G304).
func repoRoot(t *testing.T) (dir string, fsys fs.FS)

// layout_test.go
type visionLayout struct {
	Binaries, Domains, TopLevel, PolicySubdirs, ToolingCmd, ToolingInternal []string
}
func parseVisionLayout(markdown string) (visionLayout, error)
func checkLayout(fsys fs.FS) []string // problèmes lisibles, vide si conforme

// gomod_test.go
const minGoMinor = 24 // directive tool : go >= 1.24
type goMod struct {
	Module string
	Go     []string // valeurs de chaque directive go rencontrée
	Tools  []string // chemins des directives tool (ligne simple ou bloc)
}
func parseGoMod(src string) (goMod, error)
func checkGoMod(m goMod) []string

// makefile_test.go
type makeRule struct {
	Prereqs []string
	Recipe  []string // lignes logiques, continuations jointes, préfixes @ - + retirés
	Line    int
}
type parsedMakefile struct {
	Rules map[string]makeRule
	Phony map[string]bool
}
func parseMakefile(src string) (parsedMakefile, error)
func checkMakefile(mf parsedMakefile) []string

// golangci_test.go
type yamlDoc map[string][]string // chemin pointé -> valeurs (1 pour un scalaire, n pour une séquence)
func parseYAMLSubset(src string) (yamlDoc, error)
func checkGolangci(doc yamlDoc) []string
func checkGolangciFiles(fsys fs.FS) []string // un seul fichier de configuration golangci-lint
```

Messages de problème en anglais, chacun nommant l'élément fautif (chemin, cible, clé) : les témoins vérifient par `strings.Contains`.

---

## 6. Contenu cible des fichiers de configuration

### 6.1 `Makefile` (les lignes de recette commencent par une tabulation)

```make
# Rempart : vérification et outillage. Issu de Makefile.template (M0-T01).
# Le hook Stop exige `make verify-quick` : cette cible ne demande ni réseau ni Docker
# (hors premier téléchargement des modules Go et de la chaîne d'outils).
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := verify-quick

EVAL ?= all
POLICIES_DIR ?= policies
OPA ?= opa

# Variables fournies par l'appelant (menace T8). $(value ...) fige le texte brut : une valeur
# passée en ligne de commande, par exemple SCENARIO='$(shell ...)', n'est jamais développée
# par make. Les recettes les lisent par le shell ("$$VAR"), jamais par make.
override SCENARIO := $(value SCENARIO)
override EVAL := $(value EVAL)
override POLICIES_DIR := $(value POLICIES_DIR)
override OPA := $(value OPA)
export SCENARIO EVAL POLICIES_DIR OPA

.PHONY: verify-quick verify opa-test arch-test evals update-baseline
.PHONY: dev dev-preflight dev-down sandbox-guard sandbox-plan sandbox-apply sandbox-destroy

verify-quick:
	go build ./...
	golangci-lint run ./...
	go test -short ./...
	$(MAKE) --no-print-directory opa-test
	$(MAKE) --no-print-directory arch-test

verify: verify-quick
	go test -tags=integration ./...
	go tool govulncheck ./...

# Étape OPA active seulement s'il existe au moins un fichier .rego sous POLICIES_DIR.
# Dans ce cas, opa absent est une erreur : jamais de saut silencieux.
opa-test:
	@if [ -z "$$(find "$$POLICIES_DIR" -type f -name '*.rego' -print -quit 2>/dev/null)" ]; then \
		echo "opa-test : aucun fichier .rego sous $$POLICIES_DIR, étape OPA sans objet."; \
	elif ! command -v "$$OPA" >/dev/null 2>&1; then \
		echo "opa-test : fichiers .rego présents sous $$POLICIES_DIR mais $$OPA introuvable (voir docs/SETUP.md)." >&2; \
		exit 2; \
	else \
		"$$OPA" check "$$POLICIES_DIR"; \
		"$$OPA" test "$$POLICIES_DIR"; \
	fi

arch-test:
	go test -count=1 ./internal/archtest/...

# Evals : livrées par M0-T23 (cmd/rempart-evals). Avant : code 2, aucune action.
evals:
	@test -d cmd/rempart-evals || { echo "evals : indisponible avant M0-T23 (cmd/rempart-evals absent) ; aucune action." >&2; exit 2; }
	@[[ "$${EVAL:-}" =~ ^[a-z0-9][a-z0-9/_-]{0,126}$$ ]] || { echo "EVAL requis, au format [a-z0-9/_-] (ex. EVAL=demo)." >&2; exit 2; }
	go run ./cmd/rempart-evals --suite "$$EVAL"

# Réservé aux humains (bloqué pour l'agent par le hook guard_bash). Fonctionnel à partir de M0-T23.
update-baseline:
	@test -d cmd/rempart-evals || { echo "update-baseline : indisponible avant M0-T23 (cmd/rempart-evals absent) ; aucune action." >&2; exit 2; }
	@[[ "$${EVAL:-}" =~ ^[a-z0-9][a-z0-9/_-]{0,126}$$ ]] || { echo "EVAL requis, au format [a-z0-9/_-] (ex. EVAL=demo)." >&2; exit 2; }
	go run ./cmd/rempart-evals --suite "$$EVAL" --write-baseline

# Pile de développement : livrée par M0-T03 (docker-compose.yml, dev-preflight en prérequis).
dev:
	@echo "dev : pile de développement livrée par M0-T03 (docker-compose.yml absent) ; aucune action." >&2
	@exit 2

# Vérifie Docker Engine, le plugin compose v2 et l'accès au démon, sans rien démarrer.
dev-preflight:
	@docker compose version >/dev/null 2>&1 || { echo "dev-preflight : Docker Engine et le plugin compose v2 sont requis (voir docs/SETUP.md)." >&2; exit 2; }
	@docker info >/dev/null 2>&1 || { echo "dev-preflight : démon Docker injoignable (voir docs/SETUP.md)." >&2; exit 2; }
	@echo "dev-preflight : Docker et compose v2 disponibles."

# Arrêt idempotent : rien à arrêter tant que M0-T03 n'a pas livré docker-compose.yml.
dev-down:
	@echo "dev-down : aucune pile à arrêter avant M0-T03 (docker-compose.yml absent)."

# Garde des trois cibles de bac à sable (scripts/sandbox.sh arrive en M3).
# Prérequis : s'exécute avant toute validation et toute question interactive.
sandbox-guard:
	@test -e scripts/sandbox.sh || { echo "sandbox : scripts/sandbox.sh absent (livré en M3) ; aucune action." >&2; exit 2; }
	@test -x scripts/sandbox.sh || { echo "sandbox : scripts/sandbox.sh non exécutable ; aucune action." >&2; exit 2; }

sandbox-plan: sandbox-guard
	@[[ "$${SCENARIO:-}" =~ ^[a-z0-9][a-z0-9-]{0,62}$$ ]] || { echo "SCENARIO requis, au format [a-z0-9-] (ex. SCENARIO=demo)." >&2; exit 2; }
	./scripts/sandbox.sh plan "$$SCENARIO"

# Approbation humaine exigée deux fois : permission "ask" de Claude Code ET confirmation
# tapée au terminal (lue sur /dev/tty : un tube sur l'entrée standard ne suffit pas).
sandbox-apply: sandbox-guard
	@[[ "$${SCENARIO:-}" =~ ^[a-z0-9][a-z0-9-]{0,62}$$ ]] || { echo "SCENARIO requis, au format [a-z0-9-] (ex. SCENARIO=demo)." >&2; exit 2; }
	@read -r -p "Appliquer $$SCENARIO sur le compte SANDBOX ? Tape 'oui' : " a </dev/tty; [ "$$a" = "oui" ]
	./scripts/sandbox.sh apply "$$SCENARIO"

sandbox-destroy: sandbox-guard
	@[[ "$${SCENARIO:-}" =~ ^[a-z0-9][a-z0-9-]{0,62}$$ ]] || { echo "SCENARIO requis, au format [a-z0-9-] (ex. SCENARIO=demo)." >&2; exit 2; }
	@read -r -p "Détruire $$SCENARIO sur le compte SANDBOX ? Tape 'oui' : " a </dev/tty; [ "$$a" = "oui" ]
	./scripts/sandbox.sh destroy "$$SCENARIO"
```

Comportement cible par cible :

| Cible | Comportement en T01 | Réseau | Docker |
|---|---|---|---|
| `verify-quick` (défaut) | build, lint (dont formateurs), tests unitaires, `opa-test`, `arch-test` | non (modules en cache) | non |
| `verify` | `verify-quick`, puis `go test -tags=integration ./...` (aucun test taggé en T01), `go tool govulncheck ./...` | oui (`vuln.go.dev`) | non |
| `opa-test` | aucun `.rego` : message, code 0 ; `.rego` et `opa` absent : message, code 2 ; sinon `opa check` puis `opa test` | non | non |
| `arch-test` | tests d'architecture, sans cache | non | non |
| `evals` | `cmd/rempart-evals` absent : message nommant `M0-T23`, code 2 | non | non |
| `update-baseline` | idem ; réservé à l'humain (`guard_bash`) | non | non |
| `dev` | message nommant `M0-T03`, code 2, aucune commande Docker | non | non |
| `dev-preflight` | `docker compose version` puis `docker info` ; échec : message renvoyant à `docs/SETUP.md`, code 2 | non | lecture seule |
| `dev-down` | message nommant `M0-T03`, code 0 | non | non |
| `sandbox-guard` | `scripts/sandbox.sh` absent : message `scripts/sandbox.sh absent`, code 2 | non | non |
| `sandbox-plan`, `sandbox-apply`, `sandbox-destroy` | `sandbox-guard` en prérequis, donc code 2 avant la validation de `SCENARIO` et avant toute question | non | non |

Notes :
- GNU make sort en code 2 dès qu'une recette échoue, quel que soit le code de la commande ; les recettes font quand même `exit 2` pour la lisibilité, et les critères discriminent par le message.
- `make` de macOS (3.81) ignore `.SHELLFLAGS` ; les recettes restent correctes (le shell reste bash), seul le mode strict est perdu. Linux et WSL2 ont GNU make 4.x.

### 6.2 `.golangci.yml` (format v2)

```yaml
# golangci-lint v2 (M0-T01). Pinned version: docs/SETUP.md, CI from M0-T04.
# Every nolint directive must name the linter and give a reason (nolintlint).
version: "2"

run:
  timeout: 5m
  tests: true
  modules-download-mode: readonly
  build-tags:
    - integration

linters:
  # standard = errcheck, govet, ineffassign, staticcheck, unused
  default: standard
  enable:
    # Required by the go-platform-conventions skill
    - contextcheck
    - errorlint
    - gosec
    - nolintlint
    # Resources, context, HTTP and SQL
    - bodyclose
    - fatcontext
    - noctx
    - rowserrcheck
    - sqlclosecheck
    # Correctness
    - copyloopvar
    - durationcheck
    - errchkjson
    - forcetypeassert
    - nilerr
    - predeclared
    - reassign
    - unconvert
    - usestdlibvars
    - wastedassign
    # Source integrity and supply chain
    - asciicheck
    - bidichk
    - gocheckcompilerdirectives
    - gomoddirectives
  settings:
    errcheck:
      check-type-assertions: true
    govet:
      enable-all: true
      disable:
        - fieldalignment
        - shadow
    gosec:
      config:
        global:
          # Ignore gosec's own nosec annotations: a gosec finding is silenced
          # only by a nolint directive naming gosec, which nolintlint checks.
          nosec: true
    nolintlint:
      require-explanation: true
      require-specific: true
      allow-unused: false

formatters:
  enable:
    - gofumpt
    - goimports
  settings:
    gofumpt:
      module-path: github.com/amezianechayer/rempart
    goimports:
      local-prefixes:
        - github.com/amezianechayer/rempart

issues:
  max-issues-per-linter: 0
  max-same-issues: 0
```

Choix :
- `default: standard` garde le socle (errcheck, govet, ineffassign, staticcheck, unused). Aucune exclusion globale, aucun préréglage `linters.exclusions.presets` (ils masqueraient des erreurs non vérifiées).
- `run.tests: true` : les tests sont lintés (ils sont gelés en impl : voir risque K4). `build-tags: integration` : les tests d'intégration (à partir de M0-T03) sont lintés dans `verify-quick`, sans être exécutés.
- `bidichk` et `asciicheck` : défense contre le code source piégé (caractères bidirectionnels) dans un dépôt public qui recevra des PR. `gomoddirectives` (réglages par défaut) : refuse les directives `replace` dans `go.mod` (T6) ; la directive `tool` reste permise.
- Écartés volontairement en T01 (bruit sans gain de sécurité à ce stade) : `revive`, `gocritic`, `unparam`, `wrapcheck`, `err113`, `godot`, `paralleltest`, `misspell` (commentaires et messages en français). À réévaluer par une tâche dédiée, jamais par `//nolint`.
- Sur les stubs et `doc.go`, ce jeu ne signale rien : `_, _ =` sur `Fprintln`, pas de contexte, pas d'E/S.

### 6.3 `.gitignore` (ajouts en fin de fichier)

```
/bin/
evals/**/reports/
```

---

## 7. Flux de données

Aucun flux applicatif en T01 (stubs sans comportement, aucune donnée cloud ni LLM). Chaîne de vérification :

```
make verify-quick
  -> go build ./...                     (5 stubs, 22 paquets doc.go ; archtest ignoré par build car sans fichier non test)
  -> golangci-lint run ./...            (lit .golangci.yml ; linters et formateurs, tests et fichiers "integration" inclus)
  -> go test -short ./...               (dont internal/archtest)
  -> make opa-test                      (aucun .rego sous policies/ : étape sans objet, code 0)
  -> make arch-test                     (go test -count=1 ./internal/archtest/...)
internal/archtest (tests) : racine trouvée en remontant jusqu'à go.mod,
  lecture seule via os.DirFS(racine) de : go.mod, Makefile, .golangci.yml, docs/00-VISION.md,
  arborescence cmd/, internal/, policies/, modules/, schemas/, evals/, web/
  ; aucune écriture, aucun réseau, aucun processus lancé
```

---

## 8. Tests (phase tests, subagent `test-author`)

### 8.1 Règles communes
- `package archtest`, bibliothèque standard seulement (`go/ast`, `go/parser`, `go/token`, `io/fs`, `os`, `path`, `path/filepath`, `regexp`, `slices`, `strconv`, `strings`, `errors`, `fmt`, `testing`, `testing/fstest`). Aucune dépendance ajoutée à `go.mod`.
- Aucun symbole de production référencé ; aucun `exec`, aucun réseau, aucune écriture ; pas de `t.Skip`.
- Racine : `repoRoot(t)` (section 5.3). Pendant `go test`, le répertoire courant est `internal/archtest` : la remontée trouve `go.mod` deux niveaux plus haut. Le module lu doit valoir `github.com/amezianechayer/rempart`, sinon `t.Fatal` (évite de valider un autre module).
- Toute lecture via `fs.ReadFile`, `fs.Stat`, `fs.ReadDir` sur `os.DirFS(racine)` ; les chemins sont relatifs, séparés par `/`. Un fichier absent produit un message explicite (`errors.Is(err, fs.ErrNotExist)`) : `Makefile: file does not exist at repository root (created by M0-T01)`.
- Structure de chaque test : sous-test `negative_controls` (témoin positif `valid...` puis un sous-test par défaut injecté), puis sous-test `repository` sur le dépôt réel. Noms de sous-tests en `snake_case` ASCII.
- Le code de test doit passer le lint de la section 6.2 **dès la phase tests** (il sera gelé en impl) : chaînes d'erreur en minuscule (staticcheck ST1005), assertions de type avec `ok` (`forcetypeassert`), pas d'`os.ReadFile` sur un chemin variable (gosec G304), imports groupés (goimports, gofumpt).

### 8.2 `TestLayoutMatchesVision`

Listes codées dans le test (valeurs de référence) :
- binaires : `rempartd rempart-worker rempart-runner rempart rempart-mcp` ;
- domaines : `intent design threat policy iacgen validate plan apply runner inventory graph attackpath remediate drift finops compliance evidence loops llm secrets tenancy` (21) ;
- sous-dossiers de politiques : `design iac runtime k8s` ; dossiers de premier niveau hors `cmd` et `internal` : `policies modules schemas evals web` ;
- outillage : `internal/archtest`, `internal/evals`, `cmd/rempart-evals`.

Sous-test `vision_concordance` : `parseVisionLayout` lit `docs/00-VISION.md` et doit renvoyer exactement ces listes (comparaison d'ensembles). Règles d'analyse :
1. repérer la ligne exactement égale à `### Modules`, puis le premier bloc délimité par des lignes commençant par trois accents graves ; absence du titre ou du bloc : erreur ;
2. dans le bloc, ligne `^cmd/\s+(.*)$` : découper le groupe sur `,`, garder le premier mot de chaque morceau (binaires) ;
3. ligne `^internal/\s*$` : les lignes suivantes de la forme `^  ([a-z][a-z0-9]*)/` sont les domaines, jusqu'à la première ligne qui ne commence pas par deux espaces ;
4. ligne `^policies/\s+(.*)$` : chaque correspondance de `([a-z0-9]+)/` dans le groupe est un sous-dossier ;
5. lignes `^([a-z]+)/\s` : dossiers de premier niveau ;
6. hors bloc, la ligne qui commence par `Outillage de développement` : `` `internal/([a-z][a-z0-9]*)` `` et `` `cmd/([a-z][a-z0-9-]*)` `` donnent l'outillage.

Sous-test `repository`, `checkLayout(fsys)` exige :
1. chaque `internal/<d>` (21 domaines et `archtest`) est un dossier contenant `doc.go` ; `parser.ParseFile(fset, nom, contenu, parser.PackageClauseOnly|parser.ParseComments)` donne `f.Name.Name == <d>` et `f.Doc.Text()` commence par `Package <d> ` ;
2. chaque `cmd/<b>` (5 binaires) contient `main.go` en `package main`, avec une déclaration `func main()` sans récepteur, sans paramètre ni résultat (analyse complète du fichier) ;
3. chaque dossier présent sous `cmd/` contient au moins un fichier `.go` hors test, tous en `package main`, et appartient aux binaires ou à l'outillage ;
4. chaque dossier présent sous `internal/` appartient aux domaines ou à l'outillage ;
5. `policies/design`, `policies/iac`, `policies/runtime`, `policies/k8s`, `modules`, `schemas`, `evals`, `web` sont des dossiers.

`internal/evals` et `cmd/rempart-evals` sont permis, pas exigés.

Témoins (`negative_controls`, arbre `fstest.MapFS` valide construit par une fonction de test, puis une mutation par cas), au moins 10 : `valid_tree` (zéro problème) ; `missing_domain` (`internal/graph` supprimé) ; `doc_wrong_package` ; `doc_without_package_comment` ; `unknown_internal_dir` (`internal/utils`) ; `cmd_not_main` ; `cmd_without_main_func` ; `unknown_cmd_dir` (`cmd/rempart-debug`) ; `missing_policy_subdir` (`policies/k8s`) ; `vision_without_modules_block` (erreur de `parseVisionLayout`).

En phase tests : **FAIL**, sous-test `repository`, parce que `cmd/`, les 22 `doc.go` et les dossiers de premier niveau n'existent pas. `vision_concordance` et `negative_controls` passent.

### 8.3 `TestGoDirective`

`parseGoMod` : lignes de `go.mod` ; commentaire `//` retiré jusqu'à la fin de ligne ; blocs `verbe (` ... `)` gérés ; directives lues : `module`, `go`, `tool` (ligne simple ou bloc) ; les autres verbes sont ignorés.

`checkGoMod` exige :
1. `module` vaut `github.com/amezianechayer/rempart` ;
2. exactement une directive `go`, de forme `^1\.(\d+)(\.(\d+))?$` (préversions `rc` et `beta` refusées), avec un mineur au moins égal à `minGoMinor` (24) ;
3. une directive `tool golang.org/x/vuln/cmd/govulncheck`.

La valeur exacte `1.27.1` n'est pas codée dans le test (une montée de version ne doit pas casser le test) : elle est vérifiée par le critère 1.

Témoins, au moins 9 : `valid` ; `valid_tool_block` ; `too_old` (`go 1.23`) ; `missing_go` ; `duplicate_go` ; `prerelease` (`go 1.28rc1`) ; `wrong_module` ; `missing_govulncheck_tool` ; `commented_directive_ignored` (`// go 1.30` seul : directive absente).

En phase tests : **PASS**. `go.mod` est créé à l'étape 0, avant les tests ; c'est un test de non-régression (un abaissement de version ou le retrait de la directive `tool` casserait `make verify`). La porte `phase impl` reste satisfaite : elle exige qu'au moins un test du paquet échoue, ce que font les trois autres.

### 8.4 `TestMakefileTargets`

`parseMakefile`, sous-ensemble de la syntaxe GNU make, règles documentées dans le test :
1. les lignes terminées par `\` sont jointes à la suivante avant toute classification ;
2. ligne vide ou commençant par `#` (hors recette) : ignorée ;
3. affectation `^[A-Za-z0-9_.]+\s*(::?=|:::=|\?=|\+=|!=|=)` : ignorée ;
4. directives `include`, `-include`, `sinclude`, `export`, `unexport`, `override`, `vpath` : ignorées ;
5. directives `ifeq`, `ifneq`, `ifdef`, `ifndef`, `else`, `endif`, `define`, `endef` : **erreur** explicite (« directive non prise en charge : mettre à jour le test ») ;
6. règle : ligne ne commençant pas par une tabulation, dont le premier `:` n'est pas suivi de `=` ; cibles avant `:`, prérequis après (jusqu'à `;` ou `#`, prérequis d'ordre après `|` inclus) ; `.PHONY` alimente l'ensemble des cibles factices (plusieurs lignes permises) ;
7. recette : lignes commençant par une tabulation qui suivent une règle ; préfixes `@`, `-`, `+` retirés ; une ligne vide ou un commentaire en colonne 0 ne termine pas la recette ;
8. deux règles avec recette pour une même cible : erreur.

`checkMakefile` exige (motifs appliqués aux lignes de recette) :
1. cibles définies une seule fois et déclarées `.PHONY` : `verify-quick verify evals dev dev-preflight dev-down sandbox-guard sandbox-plan sandbox-apply sandbox-destroy update-baseline arch-test opa-test` ;
2. `sandbox-plan`, `sandbox-apply`, `sandbox-destroy` ont `sandbox-guard` parmi leurs prérequis ;
3. la recette de `sandbox-guard` contient `scripts/sandbox.sh absent` et `exit 2`, et aucune ligne correspondant à `\bread\b` ;
4. les recettes de `sandbox-apply` et `sandbox-destroy` contiennent une ligne `\bread\b` contenant `"oui"`, placée avant la ligne qui appelle `scripts/sandbox.sh` (confirmation humaine conservée) ;
5. aucune ligne du Makefile ne correspond à `(^|[^$])\$[({](SCENARIO|EVAL|POLICIES_DIR|OPA)[)}:]` (pas d'interpolation par make des variables de l'appelant ; R1-d) ;
6. recette de `verify-quick` : lignes correspondant, dans cet ordre, à `^go build \./\.\.\.$`, `^golangci-lint run\b`, `^go test\b.*-short.*\./\.\.\.`, puis des appels `$(MAKE)` à `opa-test` et à `arch-test` ;
7. ensemble atteignable depuis `verify-quick` (prérequis, et cibles nommées sur une ligne contenant `$(MAKE)`, récursivement) : aucune ligne de recette ne correspond à `\bdocker\b|govulncheck|-tags[= ]?integration|\bcurl\b|\bwget\b|\bgo (get|install)\b` ;
8. `verify` a `verify-quick` en prérequis ; sa recette contient `go test -tags=integration ./...` et `go tool govulncheck ./...` ;
9. toute ligne du Makefile qui contient `govulncheck` contient `go tool govulncheck` ;
10. recette jointe de `opa-test` : contient `\*\.rego` et `command -v`, et la première occurrence de `.rego` précède la première occurrence de `(opa|\$\(OPA\)'?|"\$\$OPA") test` (R1-d) ; aucune ligne du Makefile ne correspond à `\[\s*-d\s+policies\s*\]` (condition du modèle, qui lançait OPA sur des dossiers vides) ;
11. recette de `update-baseline` : contient `--write-baseline` ;
12. recette de `arch-test` : contient `./internal/archtest/...`.
13. (R1-a) pour chacune de `SCENARIO`, `EVAL`, `POLICIES_DIR`, `OPA` : une ligne `^override\s+X\s*:=\s*\$\(value X\)\s*$` existe, placée avant toute ligne `export` qui nomme `X` ; et chacune est exportée (ligne `export` qui la nomme) ;
14. (R1-b) dans `sandbox-apply` et `sandbox-destroy`, la ligne `\bread\b` qui contient `"oui"` contient aussi `</dev/tty` ;
15. (R1-e) les recettes de `evals` et `update-baseline` contiennent, avant la ligne `go run`, une ligne qui valide `EVAL` par `=~` ; la garde de présence de `cmd/rempart-evals` reste la première ligne (critère 6a).

Les propriétés transitoires (messages `M0-T23`, `M0-T03`) ne sont **pas** testées ici : elles changent en M0-T03 et M0-T23 et sont prouvées par les critères 6.

Témoins (Makefile synthétique conforme écrit dans le test, puis mutations), au moins 14 : `valid` ; `missing_target` (`dev-down`) ; `not_phony` (`sandbox-guard` retiré de `.PHONY`) ; `sandbox_apply_without_guard` ; `guard_without_message` ; `apply_without_confirmation` ; `opa_unconditional` (`opa check policies && opa test policies`) ; `template_opa_condition` (`[ -d policies ]`) ; `docker_reachable_from_verify_quick` (`$(MAKE) dev` dans `verify-quick`, `docker compose up` dans `dev`) ; `bare_govulncheck` ; `verify_without_integration` ; `scenario_interpolated` (`./scripts/sandbox.sh plan $(SCENARIO)`) ; `duplicate_rule` (erreur) ; `unsupported_conditional` (`ifeq`, erreur).

En phase tests : **FAIL**, sous-test `repository`, parce que `Makefile` n'existe pas (le test ne lit jamais `Makefile.template`).

### 8.5 `TestGolangciConfig`

`parseYAMLSubset`, sous-ensemble de YAML en style bloc, règles documentées dans le test :
1. indentation par espaces seulement ; une tabulation en début de ligne : erreur ;
2. commentaire : `#` en début de ligne (après espaces) ou ` #` hors guillemets après une valeur ;
3. `clé:` ouvre une table ; `clé: valeur` enregistre un scalaire au chemin pointé (`linters.settings.nolintlint.require-specific`) ; valeurs entre guillemets simples ou doubles désimbriquées ;
4. `- valeur` sous une clé (indentation supérieure ou égale) ajoute un élément de séquence au chemin de la clé ;
5. `- clé: valeur` (élément de séquence qui est une table) : enregistré comme élément opaque, lignes plus indentées ignorées (permet des règles d'exclusion futures sans les interpréter) ;
6. erreur explicite sur : clé en double au même chemin, séquence ou table en ligne (`[`, `{`), ancre ou alias (`&`, `*`), étiquette (`!`), scalaire multiligne (`|`, `>`), document multiple (`---` après du contenu).

`checkGolangci` exige :
1. `version` vaut `2` (guillemets ou non) ;
2. `linters.default` vaut `standard` ou `all` ;
3. `linters.enable` contient `gosec`, `errorlint`, `contextcheck`, `nolintlint`, et `linters.disable` n'en contient aucun ;
4. `linters.settings.nolintlint.require-explanation` et `linters.settings.nolintlint.require-specific` valent `true` ;
5. `formatters.enable` contient `gofumpt` ;
6. `run.tests`, s'il est présent, vaut `true`.
7. (R1-c) `linters.settings.gosec.config.global.nosec` vaut `true` (les annotations propres à gosec ne font plus taire gosec ; seul `//nolint:gosec`, contrôlé par nolintlint, le peut).

`checkGolangciFiles` exige `.golangci.yml` présent et `.golangci.yaml`, `.golangci.toml`, `.golangci.json` absents (une seule configuration, sans ambiguïté sur celle que lit golangci-lint).

Témoins, au moins 13 : `valid` ; `v1_format` (sans `version`, clé `linters-settings`) ; `missing_gosec` ; `gosec_disabled` ; `default_none` ; `nolintlint_not_specific` ; `nolintlint_without_explanation` ; `gofumpt_as_linter_only` ; `tests_disabled` ; `tab_indentation` (erreur) ; `flow_sequence` (`enable: [gosec]`, erreur) ; `duplicate_key` (erreur) ; `second_config_file` (`MapFS` avec `.golangci.yml` et `.golangci.yaml`).

En phase tests : **FAIL**, sous-test `repository`, parce que `.golangci.yml` n'existe pas.

### 8.6 Preuve de rouge (fin de phase tests, avant `phase impl`)

| Commande | Résultat attendu |
|---|---|
| `go vet ./internal/archtest; echo rc=$?` | `rc=0` (les tests compilent : pas d'échec pour une mauvaise raison) |
| `go test ./internal/archtest/ -count=1 -v 2>&1 \| grep -E '^--- (PASS\|FAIL)'` | 4 lignes : `--- FAIL: TestGolangciConfig`, `--- PASS: TestGoDirective`, `--- FAIL: TestLayoutMatchesVision`, `--- FAIL: TestMakefileTargets` (ordre des fichiers) |
| `go test ./internal/archtest/ -count=1 -v 2>&1 \| grep -cE -- '--- FAIL: Test[A-Za-z]+/negative_controls'` | `0` |
| `go test ./internal/archtest/ -count=1 -v 2>&1 \| grep -cE 'undefined:\|setup failed\|build failed\|cannot find'` | `0` |
| `go test ./internal/archtest/ -count=1 2>&1 \| grep -cE 'Makefile: .*does not exist\|\.golangci\.yml: .*does not exist'` | `2` au moins |
| `S=<répertoire scratch> ; cp` du contenu de la section 6.2 vers `"$S/golangci.yml"` ; `golangci-lint run -c "$S/golangci.yml" ./internal/archtest/...; echo rc=$?` | `rc=0` (tests déjà propres au lint qui les jugera en impl ; aucun fichier de configuration écrit dans le dépôt) |
| `test ! -e Makefile && test ! -e .golangci.yml; echo rc=$?` | `rc=0` |

Puis :

```bash
git add go.mod go.sum internal/archtest/
git status --porcelain | grep -cE '^A  internal/archtest/[a-z]+_test\.go$'   # attendu : 5
python3 .claude/bin/rempart-state phase impl                                   # attendu : "Phase : tests -> impl"
```

---

## 9. Critères d'acceptation (fiche, précisés)

Chaque commande se lance depuis la racine du dépôt, en phase impl terminée ou en phase free.

| # | Commande | Résultat attendu |
|---|---|---|
| 1 | `grep -E '^go 1\.[0-9]+' go.mod` | exactement une ligne : `go 1.27.1` |
| 1 bis | `go list -m -versions golang.org/toolchain \| tr ' ' '\n' \| sed -nE 's/^v0\.0\.1-go(1\.[0-9]+\.[0-9]+)\.linux-amd64$/\1/p' \| sort -V \| tail -n1` | `1.27.1` (dernière stable du jour ; réseau vers `proxy.golang.org`) |
| 2 | `make verify-quick; echo rc=$?` | dernière ligne `rc=0` |
| 3 | `go test ./internal/archtest/ -count=1 -v -run '^(TestLayoutMatchesVision\|TestGoDirective\|TestMakefileTargets\|TestGolangciConfig)$' 2>&1 \| grep -cE '^--- PASS: Test(LayoutMatchesVision\|GoDirective\|MakefileTargets\|GolangciConfig) '` | `4` |
| 3 bis | même commande `go test`, suivie de `\| grep -c -- '--- FAIL'` | `0` |
| 3 ter | même commande `go test`, suivie de `\| grep -cE -- '--- PASS: Test(LayoutMatchesVision\|GoDirective\|MakefileTargets\|GolangciConfig)/negative_controls/'` | au moins `46` (10 + 9 + 14 + 13) |
| 4 | `golangci-lint config verify; echo rc=$?` | `rc=0` (voir risque K3 : télécharge le schéma JSON ; repli par `--schema` local) |
| 5 | `out=$(make sandbox-plan SCENARIO=demo 2>&1); rc=$?; printf '%s\n' "$out" \| grep -c 'scripts/sandbox.sh absent'; echo rc=$rc` | `1` puis `rc=2` |
| 6a | `out=$(make evals 2>&1); rc=$?; printf '%s\n' "$out" \| grep -c 'M0-T23'; echo rc=$rc` | `1` puis `rc=2` |
| 6b | `out=$(make dev 2>&1); rc=$?; printf '%s\n' "$out" \| grep -c 'M0-T03'; echo rc=$rc` | `1` puis `rc=2` |
| 7 | `for b in rempartd rempart-worker rempart-runner rempart rempart-mcp; do go build -o "bin/$b" "./cmd/$b" && "./bin/$b"; echo "$b rc=$?"; done 2>&1` | pour chaque binaire, une ligne `<b>: not implemented (M0)` puis `<b> rc=2` (10 lignes) |
| 7 bis | `git status --porcelain bin/ \| wc -l` | `0` (`bin/` ignoré) |
| 8 | `grep -rnE '//[[:space:]]*(nolint\|#nosec)' --include='*.go' . \| wc -l` | `0` (R1-c : aucune directive nolint ni annotation nosec) |

Note sur 7 : la commande de la fiche, `go run ./cmd/rempartd; echo rc=$?`, affiche `rempartd: not implemented (M0)`, `exit status 2` puis `rc=1` (précision P1). Si la chaîne 1.27.1 propageait le code, elle afficherait `rc=2` : les deux sont cohérents avec un stub correct ; le critère fait foi par la commande ci-dessus.

### 9.1 Vérifications complémentaires (précisions P5 à P9, harnais, documentation)

| # | Commande | Résultat attendu |
|---|---|---|
| C1 | `out=$(make sandbox-guard 2>&1); rc=$?; printf '%s\n' "$out" \| grep -c 'scripts/sandbox.sh absent'; echo rc=$rc` | `1` puis `rc=2` |
| C2 | `out=$(make dev-preflight 2>&1); rc=$?; printf '%s\n' "$out" \| grep -c 'docs/SETUP.md'; echo rc=$rc` | conteneur sans démon Docker : `1` puis `rc=2` ; poste avec Docker démarré : `0` puis `rc=0` |
| C3 | `out=$(make dev-down 2>&1); rc=$?; printf '%s\n' "$out" \| grep -c 'M0-T03'; echo rc=$rc` | `1` puis `rc=0` |
| C4 | `make -s opa-test; echo rc=$?` | message `aucun fichier .rego`, `rc=0` |
| C5 | `d=$(mktemp -d); printf 'package t\n\ntest_ok if { true }\n' > "$d/t_test.rego"; make -s opa-test POLICIES_DIR="$d"; echo rc=$?` | sortie d'OPA contenant `PASS: 1/1`, `rc=0` |
| C6 | avec le même `$d` : `out=$(make -s opa-test POLICIES_DIR="$d" OPA=opa-absent 2>&1); rc=$?; printf '%s\n' "$out" \| grep -c 'introuvable'; echo rc=$rc` | `1` puis `rc=2` |
| C7 | `GOPROXY=off make verify-quick; echo rc=$?` | `rc=0` (aucun accès réseau ; modules et chaîne 1.27.1 en cache) |
| C8 | `go mod tidy -diff; echo rc=$?` | `rc=0` |
| C9 | `go mod verify` | `all modules verified` |
| C10 | `grep -c '^tool golang.org/x/vuln/cmd/govulncheck$' go.mod` ; `go list -m golang.org/x/vuln` | `1` ; `golang.org/x/vuln v1.8.0` |
| C11 | `git check-ignore bin/rempartd evals/demo/reports/run.json` | les deux chemins affichés, code 0 |
| C12 | `test -f Makefile && test ! -e Makefile.template; echo rc=$?` | `rc=0` |
| C13 | `grep -c 'v2.13.2' docs/SETUP.md` ; `grep -c 'Makefile.template' README.md` | au moins `1` ; `0` |
| C14 | `curl -sS -o /dev/null -w '%{http_code}\n' https://vuln.go.dev/index/db.json` puis, si `200` : `make verify; echo rc=$?` | `rc=0` (sinon limite d'environnement consignée, voir K6) |
| C15 | `sandbox-apply` sans prompt (humain uniquement, permission « ask ») : `make sandbox-apply SCENARIO=demo </dev/null 2>&1 \| grep -c "Tape 'oui'"` | `0` (la garde échoue avant la question) ; côté agent, la preuve est C1 et la règle 2 de `TestMakefileTargets` |

---

## 10. Documentation induite (tâche I8)
- `README.md` ligne 9 : `Makefile                  cibles de vérification (dont verify-quick, exigée par le hook Stop)` à la place de `Makefile.template`.
- `docs/SETUP.md`, tableau des outils : Go « version de la directive `go` de `go.mod` (1.27.1 au 2026-09-23) ; `GOTOOLCHAIN=auto` télécharge la chaîne si besoin » ; golangci-lint « v2.13.2 (épinglée ; CI en M0-T04) » ; govulncheck « `go tool govulncheck` (directive `tool` de `go.mod`, v1.8.0) ; binaire séparé facultatif ».
- `docs/STATUS.md` à la clôture : versions, écarts de la section 3.2 appliqués (dont le `git add` avant `phase impl`), précisions P1 à P11.

---

## 11. Spécification de boucle
Sans objet : T01 ne crée aucune boucle.

---

## 12. Risques

| # | Risque | Atténuation |
|---|---|---|
| K1 | `go run` ne propage pas le code de sortie : le critère 7 de la fiche serait faux | P1 : binaire construit puis exécuté. |
| K2 | Le motif `nolint` de la fiche compte le nom `nolintlint` présent dans les tests | P2 : motif de directive `//[[:space:]]*nolint`. |
| K3 | `golangci-lint config verify` télécharge le schéma JSON depuis `golangci-lint.run` (hôte dont l'accès n'est pas établi dans le conteneur) | Si le critère 4 échoue pour une raison réseau : `golangci-lint config verify --help` pour confirmer l'option `--schema`, puis `--schema "file://$(go env GOMODCACHE)/github.com/golangci/golangci-lint/v2@v2.13.2/jsonschema/golangci.jsonschema.json"` si golangci-lint a été installé par `go install` (fichier à vérifier par `ls`). À défaut, critère prouvé sur un poste connecté et limite consignée dans `docs/STATUS.md`. La validité structurelle est aussi couverte par `golangci-lint run` (critère 2) et `TestGolangciConfig`. |
| K4 | Les tests sont gelés en impl mais lintés par `verify-quick` : un signalement sur un test imposerait un retour journalisé en phase tests | Lint des tests en phase tests avec une copie hors dépôt de la configuration (section 8.6) ; règles de la section 8.1. |
| K5 | Hook Stop actif dès que `Makefile` existe | `git mv` et réécriture du Makefile en dernier (I7), dans le même tour que le premier `make verify-quick` vert. |
| K6 | `vuln.go.dev` non joignable : `make verify` (lancé par `acceptance-verifier`) rouge pour une raison d'environnement ; une vulnérabilité publiée rend `verify` rouge sans changement de code | C14 vérifie l'accès d'abord ; `make verify` ne fait pas partie des critères de T01 ; toute vulnérabilité se traite par une tâche de montée de version, jamais par exclusion (risque R10 de la vue d'ensemble). |
| K7 | Analyseurs maison (Makefile, YAML, VISION) trop stricts pour les tâches futures (conditionnelles make, `-include .env.dev` en M0-T03, listes de tables YAML dans compose) | Limites documentées et erreurs explicites ; `include` et `-include` acceptés ; les tâches qui ont besoin de plus étendent l'analyseur dans leur phase tests. |
| K8 | Le test lit `docs/00-VISION.md` : une modification de la vision casse le test | Voulu : la vision ne change que par ADR, qui met à jour le test et l'arborescence dans le même changement. |
| K9 | `GOTOOLCHAIN=local` ou poste sans accès au proxy : `go 1.27.1` refusé par un Go local plus ancien | `docs/SETUP.md` (I8) ; CI avec `go-version-file: go.mod` (M0-T04). |
| K10 | `go vet` refuserait un paquet sans fichier non test (hook PostToolUse en phase tests) | Non attendu (vet analyse la variante de test) ; sinon message informatif sans effet, compilation prouvée par `go test` (section 8.6). |
| K11 | Nouvelles règles dans une future version de golangci-lint | Version épinglée (`docs/SETUP.md`, CI en M0-T04) ; montée de version par tâche dédiée. |
| K12 | `make` 3.81 de macOS ignore `.SHELLFLAGS` | Recettes correctes sans le mode strict ; Linux et WSL2 recommandés (`docs/SETUP.md`). |

---

## 13. Impact sur le modèle de menace et revue

- **T6 (dépendance piégée)** : `go.sum` versionné ; govulncheck épinglé par directive `tool` et lancé par `go tool` ; `gomoddirectives` refuse les `replace` ; `bidichk` et `asciicheck` contre le code source piégé dans un dépôt public (complète N1 de la vue d'ensemble). Vérification : `TestGoDirective`, `TestGolangciConfig`, C9, C10.
- **T8 (exécution de commandes)** : `SCENARIO` et `EVAL` ne sont plus interpolés par make dans le shell ; `SCENARIO` validé par liste blanche ; `sandbox-guard` échoue avant toute question ; la double confirmation humaine de `sandbox-apply` et `sandbox-destroy` est conservée et testée. Vérification : règles 2 à 5 de `TestMakefileTargets`, critère 5, C1.
- **R7 de la vue d'ensemble (tentation du `//nolint`)** : `nolintlint` avec explication et linter précis, testé ; critère 8.
- Aucune menace nouvelle ; aucune modification de `docs/02-THREAT-MODEL.md` en T01. À la clôture de M0 (H4), N1 pourra citer `bidichk` et `gomoddirectives` parmi ses atténuations.
- **Revue sécurité** : non obligatoire selon la fiche (stubs). Recommandation : un passage court de `security-reviewer` limité au diff du `Makefile` (cibles `sandbox-*`, `evals`, `update-baseline`), parce que T01 réécrit une garde d'approbation humaine et la façon dont des valeurs de l'appelant arrivent dans des commandes shell (point 5 de sa checklist, T8). Coût faible ; décision de l'agent principal.
- **ADR** : aucun. Aucune décision structurante ni difficile à inverser : version de Go, jeu de linters et forme du Makefile se changent par une tâche ordinaire ; le chemin du module est déjà tranché (Q1).

---

## 14. Tâches ordonnées

Phase tests (un seul cycle TDD pour la tâche, puis des incréments d'implémentation courts) :

| # | Tâche | Qui | Vérification immédiate |
|---|---|---|---|
| T0 | `python3 .claude/bin/rempart-state show` (`jalon=M0 phase=free`), puis `phase tests` et étape 0 (section 3.3) | agent principal | tableau de la section 3.3 |
| T1 | `internal/archtest/repo_test.go` : `modulePath`, `repoRoot` | `test-author` | `go vet ./internal/archtest; echo rc=$?` : `rc=0` |
| T2 | `layout_test.go` : `TestLayoutMatchesVision`, `parseVisionLayout`, `checkLayout`, 10 témoins | `test-author` | `go test ./internal/archtest/ -run TestLayoutMatchesVision -v` : `vision_concordance` et `negative_controls` PASS, `repository` FAIL (dossiers absents) |
| T3 | `gomod_test.go` : `TestGoDirective`, `parseGoMod`, `checkGoMod`, 9 témoins | `test-author` | `go test ./internal/archtest/ -run TestGoDirective -v` : PASS |
| T4 | `makefile_test.go` : `TestMakefileTargets`, `parseMakefile`, `checkMakefile`, 14 témoins | `test-author` | `negative_controls` PASS, `repository` FAIL (`Makefile` absent) |
| T5 | `golangci_test.go` : `TestGolangciConfig`, `parseYAMLSubset`, `checkGolangci`, `checkGolangciFiles`, 13 témoins | `test-author` | `negative_controls` PASS, `repository` FAIL (`.golangci.yml` absent) |
| T6 | Lint des tests avec la configuration copiée hors dépôt, preuve de rouge (section 8.6), `git add go.mod go.sum internal/archtest/`, `phase impl` | `test-author` puis agent principal | section 8.6 ; `Phase : tests -> impl` |

Phase impl (dans cet ordre ; tant que `Makefile` n'existe pas, un tour peut se terminer sans que le hook Stop n'exige le vert) :

| # | Incrément | Vérification immédiate |
|---|---|---|
| I1 | 22 `doc.go` (section 5.2) | `go build ./... && go vet ./internal/...; echo rc=$?` : `rc=0` |
| I2 | 5 stubs `cmd/<b>/main.go` (section 5.1) | critère 7 |
| I3 | 8 `.gitkeep` | `go test ./internal/archtest/ -count=1 -run TestLayoutMatchesVision` : `ok` |
| I4 | `.golangci.yml` (section 6.2) | `go test ./internal/archtest/ -count=1 -run TestGolangciConfig` : `ok` ; `golangci-lint run ./...; echo rc=$?` : `rc=0` ; critère 4 |
| I5 | `.gitignore` (section 6.3) | C11 |
| I6 | `go mod tidy -diff` (et `go mod tidy` seulement si un écart apparaît) | C8, C9, C10 |
| I7 | `git mv Makefile.template Makefile`, puis réécriture complète (section 6.1), puis `make verify-quick`, **dans le même tour** | `go test ./internal/archtest/ -count=1 -run TestMakefileTargets` : `ok` ; critère 2 ; C12 |
| I8 | `README.md`, `docs/SETUP.md` (section 10) | C13 |
| I9 | Critères 1 à 8 et C1 à C14 ; C7 (`GOPROXY=off`) | tableaux des sections 9 et 9.1 |

Clôture :

| # | Étape | Vérification |
|---|---|---|
| V1 | Revue sécurité courte du diff du `Makefile` si l'agent principal la retient (section 13) | verdict PASS |
| V2 | `acceptance-verifier` sur les critères 1 à 8 (et C1 à C14 à titre de preuve complémentaire) | verdict PASS |
| V3 | `python3 .claude/bin/rempart-state phase free --reason "tâche squelette terminée"` ; `docs/STATUS.md` (section 10) ; commit conventionnel `build: scaffold Go module, repository layout, Makefile and lint config (M0-T01)` | `git status --porcelain \| wc -l` : `0` après commit |
