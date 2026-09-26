# M0-T02 `archtest-imports` : règles de dépendance et découplage de `internal/loops`

- Date : 2026-09-23
- Auteur : subagent `architect`
- Statut : proposé à l'agent principal
- Fiche d'origine : `docs/plans/M0-overview.md` section 7 (M0-T02), précisée par les sections 2.2 et 5.2. Ce plan ne l'élargit pas ; les précisions sont listées en section 2.3.
- Sources lues : `prompts/M0.md` (critère 9) ; `docs/plans/M0-overview.md` (sections 2.2, 5.1, 5.2, fiches T08, T15, T19, T22, T23) ; `docs/plans/M0-squelette.md` (sections 0, 3.2, 5.3, 8, 12) ; `docs/02-THREAT-MODEL.md` (T2, T7, T8, T23, T28 à T32) ; ADR 0002 (tableau « Vérifié dès M0 ») ; skill `go-platform-conventions` ; `.golangci.yml` ; `internal/archtest/*.go` ; hooks `guard_edit.py`, `post_edit_check.py` ; `.claude/bin/rempart-state`.
- État de départ : M0-T01 faite (commit 780328c). 21 domaines avec seulement `doc.go`, 5 stubs `cmd/`, `internal/archtest` avec `doc.go` et 5 fichiers de test (`repo_test.go`, `layout_test.go`, `gomod_test.go`, `makefile_test.go`, `golangci_test.go`). Go 1.27.1 (chaîne téléchargée par `GOTOOLCHAIN=auto`), golangci-lint v2.13.2. Harnais **non patché** (proposition 0001 non appliquée).

---

## 1. Objectif

Rendre mécaniques les règles de dépendance R1 à R5 de la section 5.2 de la vue d'ensemble, dont le critère 9 de `prompts/M0.md` (seul l'adaptateur Anthropic importe `github.com/anthropics/anthropic-sdk-go`, aucun domaine n'importe `internal/llm/adapters`) et le piège « ne pas coupler `internal/loops` à un domaine ». Les règles sont vérifiées sur la sortie réelle de `go list`, et chacune est prouvée par un témoin en violation et un témoin conforme.

---

## 2. Périmètre

### 2.1 Dans le périmètre
- `internal/archtest/packages.go` : type `Package`, chargement par `go list`, décodage du flux JSON, erreurs sentinelles.
- `internal/archtest/rules.go` : `RuleKind`, `Rule`, `Violation`, `Match`, `Check`, `DefaultRules`.
- `internal/archtest/doc.go` : commentaire de paquet mis à jour (il affirme aujourd'hui que les règles vivent dans les `_test.go`).
- Tests : `internal/archtest/rules_test.go`, `internal/archtest/packages_test.go`, `internal/archtest/imports_test.go`.
- Fixtures : `internal/archtest/testdata/golist/*.json` (14 fichiers, section 7.2).
- `docs/STATUS.md` à la clôture.

### 2.2 Hors périmètre
- Toute modification du `Makefile` : `arch-test` (`go test -count=1 ./internal/archtest/...`) et `go test -short ./...` couvrent déjà les nouveaux tests.
- Toute nouvelle dépendance dans `go.mod` (bibliothèque standard seulement).
- Règles au-delà de R1 à R5. En particulier, la règle « aucun paquet n'importe `internal/archtest` » (le paquet contient désormais du code non test qui lance un processus) est **recommandée** pour la tâche de durcissement déjà prévue avant M3 (plan M0-T01, contre-revue R1), pas ajoutée ici (sections 9 et 12).
- Vérification sous plusieurs contextes de build (`-tags`, `GOOS`) : une seule invocation, celle de la fiche (risque K2).
- Annotation de la section 5.2 de la vue d'ensemble avec les précisions P1 à P5 : faite par l'agent principal à la clôture (étape F3), pas par ce plan.

### 2.3 Précisions par rapport à la fiche (sans élargissement)

| # | Point de la fiche | Précision retenue | Raison |
|---|---|---|---|
| P1 | R3 `sdk-confine`, une seule règle | Trois règles : `sdk-confine-anthropic`, `sdk-confine-temporal`, `sdk-confine-sql` | Les listes `AllowedFrom` diffèrent ; un nom par règle rend chaque violation lisible et donne un témoin par confinement. |
| P2 | `Restrict` : « From n'importe, parmi les paquets du module, que AllowedTargets » | `Targets` d'une règle `Restrict` fixe la portée contrôlée ; vide, la portée est le module (sens de la fiche). Deux motifs réservés : `std` (bibliothèque standard) et `...` (tout chemin). | R1 interdit aussi les dépendances tierces dans `domain` : la portée « module seul » ne suffit pas. R1 s'écrit `Targets: ["..."]`, `AllowedTargets: ["std", <domaines>]`. |
| P3 | R4 : cibles permises `internal/loops/{domain,codec,fake}`, `internal/tenancy`, `internal/secrets/{secret,ports,envelope}` | `internal/loops` lui-même ajouté aux cibles permises | La fiche T15 fait importer `internal/loops` par `internal/loops/fake` (`loops.Approval`). Sans cet ajout, T15 violerait R4. Aucun cycle n'est possible dans l'autre sens (le compilateur l'interdit). |
| P4 | R3 : `go.temporal.io/sdk/...` | Ajout de `go.temporal.io/api/...` aux cibles | Les types de protocole (`common/v1.Payload`, utilisés par le codec) couplent autant à Temporal que le SDK. |
| P5 | R3 : « pilotes SQL » | Liste explicite : `database/sql/...`, `github.com/jackc/pgx/...`, `github.com/jackc/pgconn/...`, `github.com/lib/pq/...` | Décision en section 5.7. |
| P6 | `Check` renvoie `[]Violation` | Règle ou module invalide : violation spéciale (`Importer: "(invalid)"`), jamais une règle ignorée en silence | Échec fermé : un motif mal écrit ne doit pas rendre une règle vide. |
| P7 | `LoadPackages` lance `go list -json ./...` | Environnement hérité, sauf `GOFLAGS` et `GOWORK` remplacés par `GOFLAGS=-mod=readonly` et `GOWORK=off` | Section 5.5. |
| P8 | Critère 1 : « au moins 5 » lignes `--- PASS: TestRuleDetectsViolation/` | Exactement 21 (7 règles, chacune avec `violation` et `conforming`) | Un sous-test par règle, deux témoins chacun. |
| P9 | `TestRepositoryConforms` | Le test fait entrer les fichiers sources lus par `go list` dans la clé du cache de `go test` | Sans cela, `go test` sans `-count=1` peut rejouer un PASS périmé (risque K1). |
| P10 | Critère 9 : « seul `internal/llm/adapters/...` » | Règle plus étroite de la fiche : `internal/llm/adapters/anthropic/...` | Elle implique le critère 9. Les adaptateurs Bedrock et Vertex (M5), s'ils utilisent les clients du même SDK, élargiront `AllowedFrom` dans leur tâche. |
| P11 | API de la fiche | Ajouts : 4 erreurs sentinelles exportées ; fonctions non exportées `goListCmd`, `goListEnv`, `decodePackages`, `isStdlib`, `inModule`, `validPattern` | Conventions (erreurs sentinelles par paquet) et testabilité sans lancer de processus. |
| P12 | Noms de sous-tests en `snake_case` (plan T01, section 8.1) | Exception : les sous-tests de premier niveau de `TestRuleDetectsViolation` portent le nom de la règle (`domain-pure`) | La fiche impose `TestRuleDetectsViolation/<règle>`. |

---

## 3. Conditions d'entrée et contraintes du harnais non patché

### 3.1 Conditions d'entrée
- `python3 .claude/bin/rempart-state show` : `jalon=M0 phase=free`.
- `make verify-quick; echo rc=$?` : `rc=0` sur `HEAD` (780328c ou plus récent).
- `git status --porcelain | wc -l` : `0`.

### 3.2 Contraintes (harnais actuel)
1. **Hook Stop** : il exige `make verify-quick` vert à chaque fin de tour de l'agent principal, dans toutes les phases, puisque le `Makefile` existe. Les tests rouges de la phase tests cassent `verify-quick` (le paquet `internal/archtest` ne compile plus). **Tout le cycle, de `phase tests` au premier `make verify-quick` vert en phase impl, se fait donc dans un seul tour de l'agent principal**, délégations à `test-author` comprises. Aucune question à l'humain entre les deux phases.
2. **`post_edit_check.py`** lance `go vet ./internal/archtest` après chaque écriture d'un `.go`. En phase tests, les tests référencent des symboles pas encore écrits : vet échoue avec `undefined: Match` (etc.). Le message est informatif, le fichier est écrit. C'est la bonne raison d'échec (section 2.2 de la vue d'ensemble). Conséquence : les tests de T01 ne s'exécutent pas pendant la phase tests (paquet non compilable) ; ils sont rejoués en fin d'impl (critère 13).
3. **Porte `phase impl`** : `rempart-state` lit `git status --porcelain` sans `-uall`. `internal/archtest/` est suivi : chaque nouveau `_test.go` apparaît individuellement (`?? internal/archtest/rules_test.go`), **aucun `git add` n'est nécessaire**. `testdata/golist/` (nouveau dossier) apparaît groupé, sans incidence (pas un `_test.go`). La porte lance `go test ./internal/archtest` sans tag : échec de compilation, donc passage accepté.
4. **`guard_edit`** : `internal/archtest/testdata/` est classé test (modifiable en phase tests, gelé en impl) ; `rules.go`, `packages.go`, `doc.go` sont du code de production (interdits en phase tests, permis en impl).
5. **Lint des tests** : `golangci-lint` ne peut pas analyser un paquet qui ne compile pas. Les tests sont gelés en impl et lintés par `verify-quick`. Parade (comme la section 8.6 du plan T01) : en fin de phase tests, copie du dépôt dans le répertoire scratch, ajout de **stubs** hors dépôt (section 7.7), puis `go vet` et `golangci-lint` sur la copie. Aucun stub n'est écrit dans le dépôt.

---

## 4. Fichiers exacts

| Fichier | Phase | Contenu |
|---|---|---|
| `internal/archtest/testdata/golist/<règle>.violation.json` (7) | tests | section 7.2 |
| `internal/archtest/testdata/golist/<règle>.conforming.json` (7) | tests | section 7.2 |
| `internal/archtest/rules_test.go` | tests | `TestMatch`, `TestStdlibDetection`, `TestCheck`, `TestDefaultRules`, `TestRuleFixturesCoverDefaultRules`, `TestRuleDetectsViolation` |
| `internal/archtest/packages_test.go` | tests | `TestDecodePackages`, `TestGoListEnv`, `TestGoListCommand`, `TestLoadPackagesNoShell`, `TestLoadPackagesErrors` |
| `internal/archtest/imports_test.go` | tests | `TestRepositoryConforms`, `trackSources` |
| `internal/archtest/packages.go` | impl | section 5.1 |
| `internal/archtest/rules.go` | impl | sections 5.2 à 5.6 |
| `internal/archtest/doc.go` | impl | section 5.6 |
| `docs/STATUS.md` | clôture | section 13, étape F3 |

---

## 5. Interfaces

### 5.1 `packages.go`

```go
package archtest

// Package is one package of `go list -json` output, reduced to the fields the
// import rules need. The JSON names are those of cmd/go, not snake_case.
type Package struct {
	ImportPath string   `json:"ImportPath"`
	Imports    []string `json:"Imports"` // non-test imports only; omitted by go list when empty
}

var (
	ErrModuleDir  = errors.New("archtest: empty module directory")
	ErrGoList     = errors.New("archtest: go list failed")
	ErrDecode     = errors.New("archtest: invalid go list output")
	ErrNoPackages = errors.New("archtest: go list returned no package")
)

// LoadPackages runs `go list -json ./...` in moduleDir, without a shell, and
// decodes its output. Test files are not listed: their imports are not subject
// to the rules.
func LoadPackages(ctx context.Context, moduleDir string) ([]Package, error)

// goListCmd builds, without running it, the only command this package executes.
func goListCmd(ctx context.Context, moduleDir string, environ []string) *exec.Cmd

// goListEnv returns environ without GOFLAGS and GOWORK entries, followed by
// "GOFLAGS=-mod=readonly" and "GOWORK=off".
func goListEnv(environ []string) []string

// decodePackages decodes the concatenated JSON objects printed by go list -json.
func decodePackages(r io.Reader) ([]Package, error)
```

Comportement de `LoadPackages` :
1. `moduleDir == ""` : `ErrModuleDir`, aucun processus lancé.
2. `cmd := goListCmd(ctx, moduleDir, os.Environ())`, puis `out, err := cmd.Output()`.
3. Erreur : si `errors.As(err, &exitErr)` (`*exec.ExitError`), `fmt.Errorf("%w: %w: %s", ErrGoList, err, tail)` où `tail` est au plus les 2048 derniers octets de `exitErr.Stderr`, espaces de bord retirés ; sinon `fmt.Errorf("%w: %w", ErrGoList, err)`, ce qui couvre le contexte déjà annulé (`Start` renvoie alors `ctx.Err()` sans lancer de processus, donc `errors.Is(err, context.Canceled)`).
4. `decodePackages(bytes.NewReader(out))`.

`goListCmd` :

```go
cmd := exec.CommandContext(ctx, "go", "list", "-json", "./...")
cmd.Dir = moduleDir
cmd.Env = goListEnv(environ)
cmd.WaitDelay = 10 * time.Second
return cmd
```

- Tous les arguments sont des **littéraux de chaîne écrits dans l'appel** : gosec G204 ne signale un appel que si un argument est une variable ou un appel de fonction. **Aucune directive `//nolint` ni `#nosec` n'est nécessaire** ; le critère 8 de T01 reste vrai (critère 5 ci-dessous). Ne pas factoriser les arguments dans une variable (`args...`), ce qui déclencherait G204.
- `noctx` : satisfait (`CommandContext`). `contextcheck` : le contexte vient de l'appelant.
- `"go"` est résolu par `exec.LookPath` dans le `PATH` du processus. Pendant `go test`, cmd/go place `$GOROOT/bin` en tête du `PATH` des binaires de test : le `go` lancé est celui de la chaîne qui exécute le test (1.27.1). `LookPath` refuse un résultat relatif au répertoire courant (`exec.ErrDot`).
- `WaitDelay` borne l'attente des tubes si un processus enfant survit à l'annulation.
- Entrée standard : nulle (`/dev/null`).

`decodePackages` :
- `json.NewDecoder(r)` ; boucle `Decode(&p)` jusqu'à `io.EOF` ; les champs inconnus sont ignorés (la sortie réelle en compte une vingtaine).
- Erreur `ErrDecode` (enveloppant l'erreur JSON éventuelle : `fmt.Errorf("%w: %w", ErrDecode, err)`) si : valeur qui n'est pas un objet, JSON tronqué ou invalide, `ImportPath` vide, `ImportPath` en double.
- Zéro paquet : `ErrNoPackages` (un dépôt vide ne doit jamais passer pour conforme).

### 5.2 `rules.go` : types

```go
type RuleKind int

const (
	Confine  RuleKind = iota // only importers matching AllowedFrom may import a path matching Targets
	Restrict                 // importers matching From may import, among in-scope paths, only AllowedTargets
)

// Rule is an import rule. Patterns: exact path, "/..." suffix, "*" for exactly
// one segment, and the reserved patterns "std" and "...".
type Rule struct {
	Name                                       string
	Kind                                       RuleKind
	From, Targets, AllowedFrom, AllowedTargets []string
}

type Violation struct{ Rule, Importer, Imported string }

func Match(pattern, importPath string) bool
func Check(module string, pkgs []Package, rules []Rule) []Violation
func DefaultRules(module string) []Rule

func isStdlib(importPath string) bool         // premier segment non vide et sans "."
func inModule(module, importPath string) bool // importPath == module, ou préfixe module + "/"
func validPattern(p string) bool
```

### 5.3 Sémantique des motifs (`validPattern`, `Match`) et de la bibliothèque standard

Un chemin est **bien formé** s'il est non vide, sans `/` initial ni final, sans segment vide. Un motif est **valide** (`validPattern`) si :
- il vaut `std` ou `...` ; ou
- il est bien formé, chaque segment qui contient `*` vaut exactement `*`, chaque segment qui contient `...` vaut exactement `...`, et `...` n'apparaît qu'en dernier segment.

`Match(pattern, importPath)` vaut `false` si le motif est invalide ou si le chemin est mal formé. Sinon :

| Forme du motif | Correspond à |
|---|---|
| `std` | tout chemin dont `isStdlib` est vrai |
| `...` | tout chemin |
| `a/b/c` (exact) | exactement `a/b/c`, comparaison segment par segment |
| `a/*/c` | `a/X/c` pour tout segment non vide `X` (un seul segment) |
| `a/b/...` | `a/b` lui-même et tout chemin qui commence par les segments `a`, `b` (jamais `a/bc`) |
| `a/*/c/...` | combinaison : `a/X/c`, `a/X/c/Y/Z` |

`*` ne correspond jamais à zéro segment ni à plusieurs. Un `*` dans un segment (`l*`) rend le motif invalide (un chemin d'import Go ne peut pas contenir `*`).

Bibliothèque standard (`isStdlib`) : le premier segment ne contient pas de point (`fmt`, `net/http`, `database/sql`, et le pseudo-paquet cgo `C`). Go réserve les chemins sans point dans le premier élément à la bibliothèque standard et à la chaîne d'outils ; un module tiers a toujours un nom de domaine en tête. Pour que la détection reste sans ambiguïté, `Check` refuse un module dont le premier segment ne contient pas de point (section 5.4) : aucun paquet du module ne peut être pris pour la bibliothèque standard.

### 5.4 Sémantique de `Check`

```
Check(module, pkgs, rules) :
  si module n'est pas un chemin bien formé, contient "*" ou "...", ou si son premier segment
     n'a pas de point : renvoie [{Rule: "(module)", Importer: "(invalid)", Imported: module}]
  pour chaque règle invalide : ajoute {Rule: r.Name, Importer: "(invalid)", Imported: ""} et l'écarte
     (invalide : Name vide, Kind hors {Confine, Restrict}, motif invalide,
      Confine sans Targets, Restrict sans From)
  pour chaque paquet p tel que inModule(module, p.ImportPath)   // paquets tiers jamais importateurs
    pour chaque import i distinct de p.Imports
      pour chaque règle valide r
        Confine  : i correspond à un Targets et p.ImportPath ne correspond à aucun AllowedFrom -> violation
        Restrict : p.ImportPath correspond à un From
                   et i est dans la portée (Targets vide : inModule(module, i) ; sinon i correspond à un Targets)
                   et i ne correspond à aucun AllowedTargets -> violation
  violations dédoublonnées, triées par (Rule, Importer, Imported) ; nil si aucune
```

- **Imports directs seulement.** La transitivité s'obtient par composition : le SDK Anthropic n'est importé que par l'adaptateur (R3), l'adaptateur n'est importé que par `cmd/` et d'autres adaptateurs (R2), donc aucun domaine n'atteint le SDK, même indirectement.
- **Paquets hors module (tiers)** : `go list ./...` sans `-deps` ne liste que les paquets du module. Si un flux contient un paquet tiers (fixture, ou future option `-deps`), il n'est jamais soumis aux règles en tant qu'importateur. Comme cible, un paquet tiers est contrôlé par les règles `Confine` qui le nomment et par `domain-pure` (portée `...`) ; il est hors portée de `loops-agnostic` (portée module).
- Les règles sont indépendantes et toutes évaluées ; la plus stricte l'emporte (exemple : `internal/loops/domain` qui importe `internal/llm/domain` respecte R1 mais viole R4).

### 5.5 Pourquoi `go list` sans tests, et environnement de la commande

- `go list -json ./...` sans `-test` ne liste pas les variantes de test. Son champ `Imports` ne contient que les imports des fichiers non test ; ceux des `_test.go` sont dans `TestImports` et `XTestImports`, que `Package` ne décode pas. Les tests peuvent donc importer faux, `testsuite` Temporal ou serveurs `httptest` sans violer R2, R3 ou R5, alors que tout code livré, y compris un utilitaire de test écrit dans un fichier non test, est soumis aux règles. Preuve sur le dépôt réel : sous-test `test_imports_excluded` (section 7.4).
- `GOFLAGS=-mod=readonly` : `go list` ne modifie jamais `go.mod` ni `go.sum`, même si l'environnement porte `GOFLAGS=-mod=mod` ; il échoue si `go.mod` n'est pas à jour. Retirer le `GOFLAGS` hérité empêche aussi un `-tags=...` de retirer des fichiers de l'analyse.
- `GOWORK=off` : un `go.work` placé dans un dossier parent ne peut pas changer le module analysé.
- Le reste de l'environnement est hérité (`PATH`, `HOME`, `GOCACHE`, `GOMODCACHE`, `GOPROXY`, `GOTOOLCHAIN`, variables de proxy et de certificats). Une liste blanche casserait la résolution des modules derrière un proxy (CI, conteneur) sans gain : le risque visé ici est la **falsification du résultat**, pas l'exfiltration (processus de la chaîne d'outils locale, lecture seule). Une variable d'environnement prime sur le fichier `go env -w` : les `GOFLAGS` et `GOWORK` fixés s'appliquent quoi qu'il contienne.
- Rejeté : `-json=ImportPath,Imports` (sortie réduite). La fiche fixe `-json` ; la sortie complète reste de quelques centaines de kilo-octets et le décodeur ignore les champs inconnus.

### 5.6 `DefaultRules` et `doc.go`

```go
func DefaultRules(module string) []Rule {
	m := func(p string) string { return module + "/" + p }
	return []Rule{
		{ // R1
			Name: "domain-pure", Kind: Restrict,
			From:           []string{m("internal/*/domain/...")},
			Targets:        []string{"..."},
			AllowedTargets: []string{"std", m("internal/*/domain/...")},
		},
		{ // R2
			Name: "adapters-edge", Kind: Confine,
			Targets:     []string{m("internal/*/adapters/...")},
			AllowedFrom: []string{m("cmd/..."), m("internal/*/adapters/...")},
		},
		{ // R3, critère 9 de prompts/M0.md (ADR 0002)
			Name: "sdk-confine-anthropic", Kind: Confine,
			Targets:     []string{"github.com/anthropics/anthropic-sdk-go/..."},
			AllowedFrom: []string{m("internal/llm/adapters/anthropic/...")},
		},
		{ // R3
			Name: "sdk-confine-temporal", Kind: Confine,
			Targets:     []string{"go.temporal.io/sdk/...", "go.temporal.io/api/..."},
			AllowedFrom: []string{m("internal/loops/..."), m("cmd/...")},
		},
		{ // R3
			Name: "sdk-confine-sql", Kind: Confine,
			Targets: []string{
				"database/sql/...", "github.com/jackc/pgx/...",
				"github.com/jackc/pgconn/...", "github.com/lib/pq/...",
			},
			AllowedFrom: []string{m("internal/*/adapters/...")},
		},
		{ // R4
			Name: "loops-agnostic", Kind: Restrict,
			From: []string{
				m("internal/loops"), m("internal/loops/domain/..."),
				m("internal/loops/codec/..."), m("internal/loops/fake/..."),
			},
			AllowedTargets: []string{
				m("internal/loops"), m("internal/loops/domain/..."),
				m("internal/loops/codec/..."), m("internal/loops/fake/..."),
				m("internal/tenancy"), m("internal/secrets/secret"),
				m("internal/secrets/ports"), m("internal/secrets/envelope"),
			},
		},
		{ // R5
			Name: "fakes-wired-in-cmd", Kind: Confine,
			Targets:     []string{m("internal/*/fake/...")},
			AllowedFrom: []string{m("cmd/...")},
		},
	}
}
```

Traduction règle par règle :

| Règle | Traduction | Notes |
|---|---|---|
| R1 `domain-pure` | `Restrict`, portée `...` : tout import non standard hors `internal/*/domain/...` est une violation | `domain` n'importe ni `tenancy`, ni `ports`, ni un paquet tiers (JSON Schema reste dans `internal/llm/schema`, fiche T09). |
| R2 `adapters-edge` | `Confine` des adaptateurs vers `cmd/...` et les autres adaptateurs | Seconde moitié du critère 9 : `internal/llm` (service `Client`) n'importe pas `internal/llm/adapters/anthropic`, le câblage se fait dans `cmd/`. |
| R3 `sdk-confine-anthropic` | `Confine` du SDK vers l'adaptateur Anthropic | `cmd/` lui-même ne l'importe pas : il construit l'adaptateur, jamais le client du SDK. |
| R3 `sdk-confine-temporal` | `Confine` de `sdk` et `api` vers `internal/loops/...` et `cmd/...` | `cmd/rempart-evals` (T23) peut utiliser `testsuite` ; `internal/evals` (T22) non. `internal/loops/domain` reste pur par R1. |
| R3 `sdk-confine-sql` | `Confine` des pilotes et de `database/sql` vers `internal/*/adapters/...` | Section 5.7. `cmd/` crée le pool par un constructeur d'adaptateur, jamais directement. |
| R4 `loops-agnostic` | `Restrict`, portée module | Seuls les sous-paquets de boucle (`internal/loops/demo`, puis `l1`...) importent un domaine ou `internal/llm`. Chemins exacts pour `tenancy` et `secrets/*`, sous-arbres (`/...`) pour les paquets de `loops`. |
| R5 `fakes-wired-in-cmd` | `Confine` de `internal/*/fake/...` vers `cmd/...` | Un faux importé par un fichier de test n'apparaît pas (section 5.5). |

`doc.go` (impl) :

```go
// Package archtest holds the repository architecture and configuration tests.
// Development tooling only, never shipped to customers.
//
// rules.go and packages.go hold the import rules R1 to R5 (docs/plans/M0-overview.md
// section 5.2) and their only process execution, `go list -json ./...`; the layout,
// go.mod, Makefile and golangci-lint checks live in the _test.go files.
package archtest
```

La première ligne reste celle qu'exige `TestLayoutMatchesVision` (`Package archtest `).

### 5.7 Décision : `database/sql` dans les cibles de `sdk-confine-sql`

| Option | Pour | Contre |
|---|---|---|
| A. Pilotes tiers seulement (`pgx`, `pgconn`, `pq`) | Plus souple : un domaine pourrait manipuler `sql.NullString` | `database/sql` est la porte d'entrée de tout pilote enregistré par import anonyme ; du SQL écrit hors adaptateur échapperait au positionnement du tenant par transaction (T23) et à la revue des requêtes paramétrées (gosec G201, G202) |
| B. Pilotes tiers **et** `database/sql/...` | Tout accès SQL, quelle que soit la bibliothèque, passe par `internal/*/adapters/...` ; R1 ne l'interdit pas (bibliothèque standard), R3 comble ce trou | Types `sql.Null*` interdits hors adaptateurs : les domaines utiliseront des pointeurs ou des types propres |

**Retenue : B.** Réversible par une tâche ordinaire ; pas d'ADR. Les imports anonymes (`_ "github.com/lib/pq"`) figurent dans `Imports` et sont donc contrôlés. MySQL et SQLite sont absents : PostgreSQL est le seul moteur (ADR 0003) ; un nouveau pilote s'ajoute à la liste dans la tâche qui l'introduit.

---

## 6. Flux de données

```
go test ./internal/archtest/ (TestRepositoryConforms)
  -> repoRoot(t) : remonte jusqu'à go.mod, vérifie le module github.com/amezianechayer/rempart
  -> trackSources(t, fsys) : fs.WalkDir + fs.Stat des go.mod, go.sum, *.go
     (hors .git, testdata, bin, dossiers cachés) -> entrent dans la clé du cache de go test
  -> LoadPackages(ctx 2 min, racine)
       -> exec "go" "list" "-json" "./..."  (sans shell ; Dir = racine ;
          env hérité moins GOFLAGS, GOWORK ; plus GOFLAGS=-mod=readonly, GOWORK=off)
       <- stdout : objets JSON concaténés -> decodePackages -> []Package
       <- échec : ErrGoList + fin de stderr (2 Kio au plus)
  -> Check(modulePath, pkgs, DefaultRules(modulePath)) -> []Violation triées
  <- t.Errorf("%s: %s imports %s", v.Rule, v.Importer, v.Imported) par violation
Fixtures : testdata/golist/*.json -> decodePackages -> Check (sans processus)
```

Aucune écriture dans le dépôt. Aucun réseau tant que les modules requis sont en cache ; `go list` ne réécrit jamais `go.mod`.

---

## 7. Tests (phase tests, subagent `test-author`)

### 7.1 Règles communes
- `package archtest`, bibliothèque standard seulement ; réutiliser `repoRoot`, `modulePath`, `expectProblems`, `expectError`, `referenceLayout()` (fichiers de T01, non modifiés).
- Style de T01 : table de cas ; témoin conforme (`valid...`) puis mutations ; messages en anglais qui nomment l'élément fautif ; pas de `t.Skip` ; `t.Context()` pour les contextes.
- Lint (vérifié en section 7.7) : assertions de type avec `ok`, `errors.Is` et `errors.As`, pas d'`os.ReadFile` sur un chemin variable (fixtures lues par `fs.ReadFile(os.DirFS("testdata/golist"), nom)`), fichiers temporaires en `0o600`.
- **Aucun test ne lance un shell ni n'écrit d'exécutable** (un faux `go` en script exigerait un fichier `0o755`, signalé par gosec G306 et G302 ; la forme de la commande est prouvée sans l'exécuter, section 7.3).
- **Aucun test n'est sauté sous `-short`** : `TestRepositoryConforms` et `TestLoadPackagesErrors` lancent `go list` en local, sans réseau, en quelques secondes au plus. Ce sont les gardes réelles : elles tournent dans `go test -short ./...` comme dans `arch-test`, et tout humain qui lance `go test ./...` les exécute.

### 7.2 Fixtures `internal/archtest/testdata/golist/`

Format : sortie de `go list -json` réduite à `ImportPath` et `Imports`, objets concaténés, indentation par tabulation, `Imports` omis quand vide (comme cmd/go). `M` désigne ci-dessous `github.com/amezianechayer/rempart`, écrit en entier dans les fichiers. Chaque fichier `violation` ne viole **que** sa règle (les six autres restent muettes) ; chaque fichier `conforming` est le même graphe corrigé et ne produit aucune violation.

| Règle | `violation` : paquets (imports) | Violations attendues, dans l'ordre de tri |
|---|---|---|
| `domain-pure` | `M/internal/llm/domain` (`encoding/json`, `M/internal/tenancy`, `github.com/santhosh-tekuri/jsonschema/v6`) ; `M/internal/evidence/domain` (`M/internal/llm/domain`, `sort`) ; `M/internal/tenancy` (`context`, `errors`) | `M/internal/llm/domain` -> `M/internal/tenancy` ; `M/internal/llm/domain` -> `github.com/santhosh-tekuri/jsonschema/v6` |
| `adapters-edge` | `M/internal/llm` (`context`, `M/internal/llm/adapters/anthropic`, `M/internal/llm/ports`) ; `M/internal/loops/demo` (`M/internal/loops`, `M/internal/secrets/adapters/openbao`) ; `M/internal/llm/adapters/anthropic` (`M/internal/llm/domain`, `net/http`) ; `M/internal/secrets/adapters/openbao` (`net/http`) ; `M/cmd/rempart-worker` (`M/internal/llm/adapters/anthropic`) | `M/internal/llm` -> `M/internal/llm/adapters/anthropic` ; `M/internal/loops/demo` -> `M/internal/secrets/adapters/openbao` |
| `sdk-confine-anthropic` | `M/internal/llm` (`github.com/anthropics/anthropic-sdk-go`) ; `M/cmd/rempart-worker` (`M/internal/llm/adapters/anthropic`, `github.com/anthropics/anthropic-sdk-go/option`) ; `M/internal/llm/adapters/anthropic` (`github.com/anthropics/anthropic-sdk-go`, `github.com/anthropics/anthropic-sdk-go/option`) ; paquet tiers `github.com/anthropics/anthropic-sdk-go/option` (`github.com/anthropics/anthropic-sdk-go/internal/requestconfig`) | `M/cmd/rempart-worker` -> `github.com/anthropics/anthropic-sdk-go/option` ; `M/internal/llm` -> `github.com/anthropics/anthropic-sdk-go` |
| `sdk-confine-temporal` | `M/internal/llm` (`go.temporal.io/sdk/activity`) ; `M/internal/evals` (`go.temporal.io/sdk/testsuite`) ; `M/internal/secrets/adapters/openbao` (`go.temporal.io/api/common/v1`) ; `M/internal/loops` (`go.temporal.io/sdk/workflow`) ; `M/cmd/rempart-worker` (`go.temporal.io/sdk/client`, `go.temporal.io/sdk/worker`, `M/internal/secrets/adapters/openbao`) | `M/internal/evals` -> `go.temporal.io/sdk/testsuite` ; `M/internal/llm` -> `go.temporal.io/sdk/activity` ; `M/internal/secrets/adapters/openbao` -> `go.temporal.io/api/common/v1` |
| `sdk-confine-sql` | `M/internal/graph` (`github.com/jackc/pgx/v5/pgxpool`) ; `M/cmd/rempartd` (`github.com/lib/pq`, `M/internal/graph/adapters/postgres`) ; `M/internal/evidence/domain` (`database/sql`) ; `M/internal/graph/adapters/postgres` (`database/sql`, `github.com/jackc/pgx/v5`, `github.com/jackc/pgx/v5/pgxpool`) | `M/cmd/rempartd` -> `github.com/lib/pq` ; `M/internal/evidence/domain` -> `database/sql` ; `M/internal/graph` -> `github.com/jackc/pgx/v5/pgxpool` |
| `loops-agnostic` | `M/internal/loops` (`M/internal/llm`, `M/internal/loops/domain`, `M/internal/tenancy`, `go.temporal.io/sdk/workflow`, `time`) ; `M/internal/loops/domain` (`M/internal/llm/domain`, `sort`) ; `M/internal/loops/codec` (`M/internal/graph`, `M/internal/secrets/envelope`, `go.temporal.io/api/common/v1`) ; `M/internal/loops/fake` (`M/internal/loops`) ; `M/internal/loops/demo` (`M/internal/llm`, `M/internal/loops`) | `M/internal/loops` -> `M/internal/llm` ; `M/internal/loops/codec` -> `M/internal/graph` ; `M/internal/loops/domain` -> `M/internal/llm/domain` |
| `fakes-wired-in-cmd` | `M/internal/llm` (`M/internal/llm/fake`) ; `M/internal/loops/demo` (`M/internal/loops`, `M/internal/loops/fake`) ; `M/internal/llm/fake` (`M/internal/llm/ports`) ; `M/internal/loops/fake` (`M/internal/loops`) ; `M/cmd/rempart-worker` (`M/internal/llm/fake`, `M/internal/loops/fake`) | `M/internal/llm` -> `M/internal/llm/fake` ; `M/internal/loops/demo` -> `M/internal/loops/fake` |

Témoins de voisinage intégrés : import entre domaines (`evidence/domain` -> `llm/domain`, permis par R1) ; `database/sql` dans un domaine (permis par R1, interdit par R3) ; `loops/domain` -> `llm/domain` (permis par R1, interdit par R4) ; paquet tiers importateur ignoré ; `loops/demo` libre d'importer `internal/llm`.

Fixtures `conforming` (mêmes paquets, imports corrigés) :
- `domain-pure` : `M/internal/llm/domain` (`crypto/sha256`, `encoding/json`) ; `M/internal/evidence/domain` (`M/internal/llm/domain`, `sort`) ; `M/internal/tenancy` sans `Imports` (cas « champ omis »).
- `adapters-edge` : `M/internal/llm` (`context`, `M/internal/llm/ports`) ; `M/internal/loops/demo` (`M/internal/loops`) ; `M/internal/llm/adapters/anthropic` (`M/internal/llm/adapters/anthropic/internal/wire`, `net/http`) ; `M/internal/llm/adapters/anthropic/internal/wire` (`encoding/json`) ; `M/internal/secrets/adapters/openbao` (`net/http`) ; `M/cmd/rempart-worker` (les deux adaptateurs).
- `sdk-confine-anthropic` : `M/internal/llm` (`context`) ; `M/cmd/rempart-worker` (`M/internal/llm/adapters/anthropic`) ; l'adaptateur et le paquet tiers inchangés.
- `sdk-confine-temporal` : `M/internal/loops` (`go.temporal.io/sdk/workflow`) ; `M/internal/loops/codec` (`go.temporal.io/api/common/v1`, `go.temporal.io/sdk/converter`) ; `M/internal/loops/demo` (`go.temporal.io/sdk/activity`) ; `M/cmd/rempart-worker` (`go.temporal.io/sdk/client`, `go.temporal.io/sdk/worker`) ; `M/internal/llm` (`context`) ; `M/internal/evals` (`encoding/json`).
- `sdk-confine-sql` : `M/internal/graph` (`M/internal/graph/ports`) ; `M/cmd/rempartd` (`M/internal/graph/adapters/postgres`) ; `M/internal/evidence/domain` (`crypto/sha256`) ; l'adaptateur inchangé.
- `loops-agnostic` : `M/internal/loops` (`M/internal/loops/domain`, `M/internal/tenancy`, `go.temporal.io/sdk/workflow`, `time`) ; `M/internal/loops/domain` (`sort`) ; `M/internal/loops/codec` (`M/internal/secrets/envelope`, `go.temporal.io/api/common/v1`) ; `M/internal/loops/fake` (`M/internal/loops`) ; `M/internal/loops/demo` (`M/internal/llm`, `M/internal/loops`).
- `fakes-wired-in-cmd` : `M/internal/llm` (`M/internal/llm/ports`) ; `M/internal/loops/demo` (`M/internal/loops`) ; les deux faux inchangés ; `M/cmd/rempart-worker` (les deux faux) ; `M/cmd/rempart-evals` (`M/internal/llm/fake`).

Aucune fixture ne contient de motif ressemblant à un secret.

### 7.3 `rules_test.go` et `packages_test.go`

**`TestMatch`** (table, au moins 26 cas, noms `snake_case`) :
- exact : `a.com/x/y` contre `a.com/x/y` vrai, contre `a.com/x/y/z` faux, contre `a.com/x` faux ;
- suffixe : `a.com/x/...` contre `a.com/x` vrai, `a.com/x/y/z` vrai, `a.com/xy` faux ; `go.temporal.io/sdk/...` contre `go.temporal.io/sdkx` faux ;
- joker : `M/internal/*/domain` contre `M/internal/llm/domain` vrai, `M/internal/llm/sub/domain` faux, `M/internal/domain` faux ; `M/internal/*/domain/...` contre `M/internal/llm/domain/x` vrai ;
- réservés : `std` contre `fmt`, `net/http`, `C` vrai, contre `github.com/x/y` faux ; `...` contre `fmt` et `github.com/x` vrai ;
- invalides (toujours faux) : motif vide ; `a/.../b` contre `a/x/b` ; `l*/b` contre `lx/b` ; `/a` contre `/a` ; `a/` contre `a/` ; `a//b` contre `a//b` ; chemin vide contre `...` ; chemin mal formé `M/internal//domain` contre `M/internal/*/domain`.

**`TestStdlibDetection`** : sous-test `is_stdlib` (table : `fmt`, `net/http`, `crypto/sha256`, `database/sql`, `C` vrai ; `github.com/x/y`, `go.temporal.io/sdk`, `golang.org/x/vuln`, `example.com`, `modulePath`, chaîne vide faux) ; sous-test `std_pattern_agrees` (`Match("std", p) == isStdlib(p)` sur la même table) ; sous-test `dotless_module_rejected` (`Check("corp/mod", pkgs, rules)` avec une règle valide renvoie exactement `[{(module) (invalid) corp/mod}]`).

**`TestCheck`** (règles et module `example.com/m` écrits dans le test, pour prouver que rien n'est lié au module réel) : `confine_violation` ; `confine_allowed_importer` ; `restrict_default_scope_is_module` (import tiers non signalé) ; `restrict_explicit_scope_all` (tiers signalé, `std` permis) ; `out_of_module_importer_ignored` ; `duplicate_import_reported_once` ; `output_sorted` (trois violations dans le désordre d'entrée) ; `stricter_rule_wins` (deux règles, une seule viole) ; `no_violation_returns_nil` ; règles invalides, chacune donnant `Importer == "(invalid)"` : `invalid_kind` (`RuleKind(7)`), `invalid_pattern` (`a/.../b`), `empty_rule_name`, `confine_without_targets`, `restrict_without_from` ; `empty_module`.

**`TestDefaultRules`** : `names_and_kinds` (exactement, dans l'ordre : `domain-pure` Restrict, `adapters-edge` Confine, `sdk-confine-anthropic` Confine, `sdk-confine-temporal` Confine, `sdk-confine-sql` Confine, `loops-agnostic` Restrict, `fakes-wired-in-cmd` Confine) ; `all_rules_valid` (`Check(modulePath, nil, DefaultRules(modulePath))` vaut `nil` et chaque motif passe `validPattern`) ; `critical_patterns` (critère 9 : `sdk-confine-anthropic` a pour `Targets` exactement `github.com/anthropics/anthropic-sdk-go/...` et pour `AllowedFrom` exactement `M/internal/llm/adapters/anthropic/...` ; `adapters-edge` a `M/internal/*/adapters/...` dans `Targets` et aucun `AllowedFrom` hors `M/cmd/...` et `M/internal/*/adapters/...`) ; `module_parameter` (`DefaultRules("example.com/other")` : aucun motif ne contient `amezianechayer`, tout motif interne commence par `example.com/other/`).

**`TestRuleFixturesCoverDefaultRules`** : l'ensemble des noms de `testdata/golist/*.json` (préfixe avant `.violation.json` ou `.conforming.json`) est égal à l'ensemble des noms de `DefaultRules(modulePath)` ; chaque règle a ses deux fichiers ; aucun autre fichier dans le dossier.

**`TestRuleDetectsViolation`** : itère sur une liste de 7 noms **codée dans le test** (jamais sur `DefaultRules`, qui pourrait renvoyer une liste vide et rendre le test vide). Pour chaque nom, sous-test `<règle>` avec :
- `violation` : `decodePackages` du fichier, `got := Check(modulePath, pkgs, DefaultRules(modulePath))` ; `got` est égal (`slices.Equal`) à la liste attendue de la section 7.2, codée dans le test, ce qui prouve aussi le tri et le silence des six autres règles ; chaque `Rule` vaut le nom du sous-test ;
- `conforming` : `Check` renvoie `nil`.

**`TestDecodePackages`** (entrées en ligne) : `valid_stream` (trois objets concaténés, dont un sans `Imports` : `Imports == nil`) ; `unknown_fields_ignored` (`Dir`, `GoFiles`, `Standard`) ; puis `ErrDecode` pour `truncated`, `not_an_object` (`[1]`), `empty_import_path`, `duplicate_import_path`, `trailing_garbage` (`}{`) ; enfin `empty_stream` : `ErrNoPackages`.

**`TestGoListEnv`** (table) : `GOFLAGS=-mod=mod` et `GOFLAGS=-tags=x` retirés ; `GOWORK=/tmp/go.work` retiré ; `PATH`, `HOME`, `GOCACHE`, `GOPROXY`, `GOTOOLCHAIN` conservés dans l'ordre ; exactement une entrée `GOFLAGS=-mod=readonly` et une `GOWORK=off`, en fin de liste ; entrée vide : seulement ces deux ; clé voisine `GOFLAGSX=1` conservée.

**`TestGoListCommand`** (commande construite, jamais lancée) : `goListCmd(t.Context(), "/nonexistent/module", env)` ; `cmd.Args` égal à `["go", "list", "-json", "./..."]` ; `filepath.Base(cmd.Path)` vaut `go` ou `go.exe` ; `cmd.Dir` égal au répertoire passé ; `cmd.Env` égal à `goListEnv(env)` ; `cmd.WaitDelay > 0` ; `cmd.Stdin == nil`.

**`TestLoadPackagesNoShell`** (analyse syntaxique du code de production : preuve statique de l'absence de shell) : fonction pure `checkExecUsage(files map[string]string) []string`, puis :
- `negative_controls` : `valid` (source conforme en ligne) ; `shell_wrapper` (`exec.CommandContext(ctx, "sh", "-c", "go list -json ./...")`) ; `variable_args` (`args...`) ; `command_without_context` (`exec.Command("go", ...)`) ; `exec_outside_packages_go` (import de `os/exec` dans `rules.go`) ; `start_process` (`os.StartProcess`) ; `syscall_exec` (`syscall.Exec`) ; `second_command` (deux appels) ;
- `repository` : fichiers non test `internal/archtest/*.go`, lus par `repoRoot` ;
- exigences : `os/exec` importé par `packages.go` seulement ; exactement un appel `exec.CommandContext`, aucun `exec.Command` ; ses arguments après le contexte sont exactement quatre littéraux de chaîne `"go"`, `"list"`, `"-json"`, `"./..."` ; aucun sélecteur `os.StartProcess`, `syscall.Exec`, `syscall.ForkExec` ; aucun littéral de chaîne parmi `sh`, `bash`, `/bin/sh`, `/bin/bash`, `-c`, `cmd.exe`, `powershell`.

**`TestLoadPackagesErrors`** : `empty_dir` (`ErrModuleDir`) ; `canceled_context` (contexte annulé avant l'appel : `errors.Is(err, ErrGoList)` et `errors.Is(err, context.Canceled)`) ; `no_go_mod` (`t.TempDir()` sans `go.mod` : `ErrGoList`, message contenant `go.mod`) ; `module_without_packages` (`t.TempDir()` avec seulement un `go.mod` écrit en `0o600`, contenu `module example.com/empty\n\ngo 1.24\n` : `ErrNoPackages`, sous réserve de la vérification V0 de la section 7.5).

### 7.4 `imports_test.go` : `TestRepositoryConforms`

```go
func TestRepositoryConforms(t *testing.T) {
	dir, fsys := repoRoot(t)
	trackSources(t, fsys)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	pkgs, err := LoadPackages(ctx, dir)
	if err != nil {
		t.Fatalf("LoadPackages: %v", err)
	}
	t.Run("loaded", ...)
	t.Run("test_imports_excluded", ...)
	t.Run("negative_control_on_real_packages", ...)
	t.Run("no_violation", ...)
}
```

- `loaded` : chaque `ImportPath` est dans le module ; aucun doublon ; présence de `M/cmd/<b>` pour les 5 binaires, de `M/internal/<d>` pour les 21 domaines de `referenceLayout()` et de `M/internal/archtest`. Prouve que la vérification ne porte pas sur un ensemble vide ou partiel.
- `test_imports_excluded` : le paquet `M/internal/archtest` a `os/exec` dans `Imports` (import de `packages.go`) et **pas** `testing` (importé seulement par ses `_test.go`). Preuve réelle de la section 5.5.
- `negative_control_on_real_packages` : copie profonde des paquets réels, ajout de `M/internal/llm` aux imports de `M/internal/loops` ; `Check` renvoie exactement `[{loops-agnostic M/internal/loops M/internal/llm}]`. Prouve que les règles mordent sur la sortie réelle, pas seulement sur les fixtures.
- `no_violation` : `Check(modulePath, pkgs, DefaultRules(modulePath))` ; chaque violation donne `t.Errorf("%s: %s imports %s", v.Rule, v.Importer, v.Imported)`.
- `trackSources(t, fsys)` : `fs.WalkDir` sur la racine (sans `.git`, `testdata`, `bin`, dossiers cachés), `fs.Stat` de `go.mod`, `go.sum` et de chaque `.go`. `go test` met en cache le résultat d'un test selon les fichiers et dossiers que **le binaire de test** ouvre ou inspecte ; ceux que lit le sous-processus `go list` n'y figurent pas. Ouvrir chaque dossier (liste des entrées) et inspecter chaque source les fait entrer dans la clé du cache : un fichier ajouté ou modifié invalide le résultat (preuve : C4). `arch-test` garde `-count=1`.
- Durée attendue : moins de 10 s à chaud (C2) ; délai de 2 min contre un blocage.

### 7.5 Vérification préalable V0 (`test-author`, avant d'écrire `TestLoadPackagesErrors`)

```bash
d=$(mktemp -d) && cd "$d" && printf 'module example.com/empty\n\ngo 1.24\n' > go.mod \
  && GOFLAGS=-mod=readonly GOWORK=off go list -json ./... ; echo "rc=$?"
e=$(mktemp -d) && cd "$e" && go list -json ./... ; echo "rc=$?"
```

Attendu : premier cas, sortie standard vide, avertissement `matched no packages` sur stderr, `rc=0` (donc `ErrNoPackages`) ; second cas, message contenant `go.mod`, code non nul (donc `ErrGoList`). Si la chaîne 1.27.1 renvoie un code non nul dans le premier cas, le sous-test attend `ErrGoList` et le constat est consigné dans `docs/STATUS.md`.

### 7.6 Preuve de rouge (fin de phase tests, avant `phase impl`)

| Commande | Résultat attendu |
|---|---|
| `test ! -e internal/archtest/rules.go && test ! -e internal/archtest/packages.go; echo rc=$?` | `rc=0` |
| `ls internal/archtest/testdata/golist/*.json \| wc -l` | `14` |
| `go vet ./internal/archtest 2>&1 \| grep -c 'undefined: '` | au moins `1` |
| `go vet ./internal/archtest 2>&1 \| grep -E '\.go:[0-9]+:[0-9]+: ' \| grep -vc 'undefined: '` | `0` (seule raison d'échec : symboles à écrire) |
| Section 7.7 (copie scratch avec stubs) : `go vet ./internal/archtest; echo rc=$?` | `rc=0` |
| Section 7.7 : `golangci-lint run ./internal/archtest/... 2>&1 \| grep -c '_test\.go:'` | `0` |
| `git status --porcelain \| grep -cE '^\?\? internal/archtest/(rules\|packages\|imports)_test\.go$'` | `3` |
| `python3 .claude/bin/rempart-state phase impl` | `Phase : tests -> impl` |

### 7.7 Copie scratch avec stubs (lint des tests avant gel)

```bash
S=<scratchpad de session>/t02 && rm -rf "$S" && mkdir -p "$S" && cp -a . "$S/r" && cd "$S/r"
# internal/archtest/stubs.go, écrit dans la copie seulement : toutes les déclarations de la
# section 5 (types, constantes, 4 erreurs, fonctions) avec des corps minimaux sans panic
go vet ./internal/archtest; echo rc=$?                                  # attendu rc=0
golangci-lint run ./internal/archtest/... 2>&1 | grep -c '_test\.go:'  # attendu 0
```

Les tests échouent dans la copie (stubs vides) : seules la compilation et la conformité au lint des tests sont visées. La copie est supprimée ensuite ; aucun fichier de production n'est écrit dans le dépôt en phase tests.

---

## 8. Critères d'acceptation

Depuis la racine du dépôt, phase impl terminée ou phase free. `-count=1` partout, sauf en C4 qui prouve justement le comportement du cache.

### 8.1 Critères de la fiche, précisés

| # | Commande | Résultat attendu |
|---|---|---|
| 1 | `go test ./internal/archtest/ -count=1 -run '^TestRuleDetectsViolation$' -v 2>&1 \| grep -c -- '--- PASS: TestRuleDetectsViolation/'` | `21` (fiche : au moins 5) |
| 1 bis | même `go test`, `\| grep -cE -- '--- PASS: TestRuleDetectsViolation/[a-z-]+/(violation\|conforming) '` | `14` |
| 1 ter | même `go test`, `\| grep -c -- '--- FAIL'` | `0` |
| 2 | `go test ./internal/archtest/ -count=1 -run '^TestRepositoryConforms$' -v 2>&1 \| grep -cE -- '--- PASS: TestRepositoryConforms( \|/(loaded\|test_imports_excluded\|negative_control_on_real_packages\|no_violation) )'` | `5` |
| 3 | `make verify-quick; echo rc=$?` | dernière ligne `rc=0` |

### 8.2 Critères complémentaires

| # | Commande | Résultat attendu |
|---|---|---|
| 4 | Critère 9 de `prompts/M0.md` : `go test ./internal/archtest/... -count=1; echo rc=$?` puis `go test ./internal/archtest/ -count=1 -v -run 'TestRuleDetectsViolation/^(adapters-edge\|sdk-confine-anthropic)$' 2>&1 \| grep -c -- '--- PASS: TestRuleDetectsViolation/'` | `rc=0` puis `6` |
| 5 | `grep -rnE '//[[:space:]]*(nolint\|#nosec)' --include='*.go' . \| wc -l` | `0` (critère 8 de T01 toujours vrai) |
| 6 | `grep -cF 'exec.CommandContext(ctx, "go", "list", "-json", "./...")' internal/archtest/packages.go` ; `grep -lF '"os/exec"' internal/archtest/*.go \| grep -v '_test\.go$'` ; `grep -nE '"(sh\|bash\|/bin/sh\|-c)"' internal/archtest/rules.go internal/archtest/packages.go \| wc -l` | `1` ; `internal/archtest/packages.go` seul ; `0` |
| 7 | `go test ./internal/archtest/ -count=1 -v -run '^(TestMatch\|TestStdlibDetection\|TestCheck\|TestDefaultRules\|TestRuleFixturesCoverDefaultRules\|TestDecodePackages\|TestGoListEnv\|TestGoListCommand\|TestLoadPackagesNoShell\|TestLoadPackagesErrors)$' 2>&1 \| grep -cE '^--- PASS'` | `10` |
| 8 | `go test ./internal/archtest/ -count=1 -v -run '^TestMatch$' 2>&1 \| grep -c -- '--- PASS: TestMatch/'` | au moins `26` |
| 9 | `go test ./internal/archtest/ -count=1 -v -run '^TestLoadPackagesNoShell$' 2>&1 \| grep -c -- '--- PASS: TestLoadPackagesNoShell/negative_controls/'` | au moins `8` |
| 10 | `go test -short ./internal/archtest/ -count=1 -v -run '^TestRepositoryConforms$' 2>&1 \| grep -cE -- '--- (SKIP\|FAIL)'` | `0` (tourne sous `-short`) |
| 11 | `GOPROXY=off GOFLAGS=-mod=mod go test ./internal/archtest/ -count=1 -run '^TestRepositoryConforms$'; echo rc=$?` puis `git status --porcelain go.mod go.sum \| wc -l` | `rc=0` puis `0` (hors ligne ; `GOFLAGS` hérité neutralisé ; aucune réécriture) |
| 12 | `go mod tidy -diff; echo rc=$?` | `rc=0` (aucune dépendance ajoutée) |
| 13 | `go test ./internal/archtest/ -count=1 -v -run '^(TestLayoutMatchesVision\|TestGoDirective\|TestMakefileTargets\|TestGolangciConfig)$' 2>&1 \| grep -cE '^--- PASS'` | `4` (tests de T01 intacts) |
| 14 | `grep -c 'the rules live in the _test.go' internal/archtest/doc.go` ; `head -1 internal/archtest/doc.go` | `0` ; `// Package archtest holds the repository architecture and configuration tests.` |
| 15 | `grep -rnF '"github.com/amezianechayer/rempart/internal/archtest"' --include='*.go' . \| wc -l` | `0` (aucun paquet n'importe le code non test d'`archtest`) |

### 8.3 Preuves par mutation sur une copie (jamais dans le dépôt)

Chaque commande part d'une copie neuve : `S=$(mktemp -d) && cp -a . "$S/r" && cd "$S/r"` (ou le scratchpad de session).

| # | Commande (dans la copie) | Résultat attendu |
|---|---|---|
| C1 | `mkdir -p internal/llm/adapters/anthropic && printf 'package anthropic\n' > internal/llm/adapters/anthropic/doc.go && printf 'package llm\n\nimport _ "github.com/amezianechayer/rempart/internal/llm/adapters/anthropic"\n' > internal/llm/wire.go && go test ./internal/archtest/ -count=1 -run '^TestRepositoryConforms$' 2>&1 \| grep -E 'imports_test.go:[0-9]+: adapters-edge: ' \| grep -cF 'adapters-edge: github.com/amezianechayer/rempart/internal/llm imports github.com/amezianechayer/rempart/internal/llm/adapters/anthropic'` | `1` (critère 9, seconde moitié, sur du vrai code) |
| C2 | Dans le dépôt, cache chaud : `go test ./internal/archtest/ -count=1 -run '^TestRepositoryConforms$' -v 2>&1 \| sed -nE 's/^--- PASS: TestRepositoryConforms \(([0-9.]+)s\)$/\1/p' \| awk '{ exit !($1 < 10) }'; echo rc=$?` | `rc=0` (moins de 10 s) |
| C3 | `printf 'package loops\n\nimport _ "github.com/amezianechayer/rempart/internal/graph"\n' > internal/loops/bad.go && go test ./internal/archtest/ -count=1 -run '^TestRepositoryConforms$' 2>&1 \| grep -E 'imports_test.go:[0-9]+: loops-agnostic: ' \| grep -cF 'loops-agnostic: github.com/amezianechayer/rempart/internal/loops imports github.com/amezianechayer/rempart/internal/graph'` | `1` (piège de `prompts/M0.md`) |
| C4 | **Sans** `-count=1` : `go test ./internal/archtest/ -run '^TestRepositoryConforms$' >/dev/null; sleep 3; go test ./internal/archtest/ -run '^TestRepositoryConforms$' \| grep -c '(cached)'` ; puis même ajout de `internal/loops/bad.go` qu'en C3 ; `go test ./internal/archtest/ -run '^TestRepositoryConforms$' 2>&1 \| grep -c 'loops-agnostic'` | `1` ; puis au moins `1` (cache invalidé par l'ajout ; précision P9) |
| C5 | `mkdir -p internal/llm/domain && printf 'package domain\n\nimport _ "github.com/amezianechayer/rempart/internal/tenancy"\n' > internal/llm/domain/doc.go && go test ./internal/archtest/ -count=1 -run '^TestRepositoryConforms$' 2>&1 \| grep -cE 'imports_test.go:[0-9]+: domain-pure: '` | `1` |

Correction du 2026-09-23 (vérification d'acceptation) : C1, C3 et C5 ne comptent que les lignes du sous-test `no_violation` (`imports_test.go:<ligne>: <règle>: `). Le sous-test `negative_control_on_real_packages` répète la liste complète des violations dans son message d'échec quand le dépôt en contient une vraie : le décompte brut valait 2 pour une seule violation détectée.

Le `sleep 3` de C4 dépasse le délai en deçà duquel cmd/go refuse de mettre en cache un résultat dont un fichier lu vient d'être modifié ; `cp -a` conserve les dates.

---

## 9. Revue sécurité légère (`security-reviewer`, diff de `internal/archtest/`)

Points à vérifier, chacun avec sa preuve :
1. Exécution sans shell, arguments littéraux, un seul point d'exécution : `TestLoadPackagesNoShell`, `TestGoListCommand`, critère 6.
2. Aucune directive `nolint` ni `#nosec` ; gosec G204 non déclenché : critère 5 et `make verify-quick`.
3. Répertoire de travail : racine trouvée par `repoRoot`, module vérifié ; aucun chemin issu d'une donnée externe.
4. Environnement : `GOFLAGS` et `GOWORK` neutralisés, aucune réécriture de `go.mod` (critère 11) ; reste hérité, justification en section 5.5.
5. Bornes : délai de 2 min, `WaitDelay`, message d'erreur limité à 2 Kio de stderr.
6. Échec fermé : zéro paquet, flux invalide, règle ou module invalide ne donnent jamais « conforme » (`TestDecodePackages`, `TestCheck`, `TestStdlibDetection/dotless_module_rejected`).
7. Code non test d'`internal/archtest` importé par aucun paquet (critère 15) ; recommandation d'une règle dédiée pour la tâche de durcissement (section 2.2).

Verdict attendu : PASS. Un BLOCK qui exige de changer un test renvoie en phase tests (retour journalisé).

---

## 10. Spécification de boucle

Sans objet : T02 ne crée aucune boucle. Elle rend vérifiable le piège « ne pas coupler `internal/loops` à un domaine » (R4), dont dépendent T14, T15 et T19.

---

## 11. Risques

| # | Risque | Atténuation |
|---|---|---|
| K1 | Cache de `go test` : `go list` lit des sources que le binaire de test n'ouvre pas ; un `go test ./...` sans `-count=1` pourrait rejouer un PASS périmé | `trackSources` (P9) ; `arch-test` en `-count=1` ; critères en `-count=1` ; preuve C4. |
| K2 | Un seul contexte de build : un fichier non test sous contrainte (`//go:build integration`, `_windows.go`) échappe aux règles | Aucun fichier de ce type n'est prévu en M0 (intégration dans des `_test.go` seulement). Menace proposée (section 12). Évolution possible : seconde invocation `-tags=integration` par une tâche dédiée. |
| K3 | R4 liste explicitement ses paquets : un nouveau paquet d'infrastructure sous `internal/loops/` (hors `domain`, `codec`, `fake`) serait libre comme un sous-paquet de boucle | Toute tâche qui crée un tel paquet l'ajoute à `From` et `AllowedTargets` dans sa phase tests, avec fixture ; la revue de T14 le vérifie. |
| K4 | Règles trop strictes pour des tâches futures : T15 (`loops/fake` importe `loops`, traité par P3) ; T19 et T20 (faux câblés dans `cmd/rempart-worker`, jamais importés par `internal/loops/demo`) ; T22 et T23 (`testsuite` Temporal seulement dans `cmd/rempart-evals`) ; M1 (pool PostgreSQL créé par l'adaptateur) ; M5 (Bedrock, P10) | Contraintes consignées dans `docs/STATUS.md` (F3) et à rappeler dans les plans de ces tâches ; une règle se modifie dans la phase tests de la tâche qui en a besoin, avec sa fixture. |
| K5 | Lint des tests impossible pendant la phase tests (paquet non compilable), tests gelés en impl | Copie scratch avec stubs (section 7.7) ; retour journalisé en phase tests si un signalement survient quand même. |
| K6 | Hook Stop : tout le cycle doit tenir dans un tour ; trois échecs de `verify-quick` en fin de tour produisent un BLOCAGE | Incréments courts (section 13) ; `go vet` et `go test` ciblés après chaque incrément ; `make verify-quick` avant de rendre la main. |
| K7 | `go list` a besoin du cache de modules : après T12 (SDK Anthropic) et T14 (SDK Temporal), un poste sans cache ni réseau échoue | `ErrGoList` avec la fin de stderr, jamais un faux PASS ; CI avec réseau (T04) ; C7 de T01 (`GOPROXY=off`) reste vrai une fois le cache rempli. |
| K8 | Dérive entre fixtures et format réel de `go list` | Même décodeur pour les deux ; `TestRepositoryConforms/loaded` décode la sortie réelle à chaque exécution. |
| K9 | Contournement hors graphe d'imports (réflexion, `plugin`, `//go:linkname`, appel HTTP direct à l'API du fournisseur avec `net/http`) | Hors portée d'un test d'imports. `gocheckcompilerdirectives` lint les directives ; `TestNoSecretInOutgoingRequest` (T12) et la revue couvrent l'appel direct ; menace proposée (section 12). |
| K10 | `go test ./...` et `arch-test` lancent tous deux `go list` : `verify-quick` le fait deux fois | Coût de l'ordre de la seconde à chaud ; accepté. |

---

## 12. Impact sur le modèle de menace (`docs/02-THREAT-MODEL.md`)

- **T2 et T7 (injection, fuite vers le fournisseur)** : R2 et R3 garantissent mécaniquement que le seul chemin vers le SDK Anthropic passe par l'adaptateur, câblé dans `cmd/` derrière `llm.Client` (rédaction, schéma, politique de route). L'invariant « cœur déterministe, LLM en périphérie » devient vérifiable. Preuves : `TestRuleDetectsViolation/sdk-confine-anthropic`, `/adapters-edge`, C1.
- **T8 (exécution de commandes)** : la seule exécution de T02 suit la règle du skill (`exec.CommandContext`, arguments en tableau, pas de shell, environnement maîtrisé pour ce qui change le résultat). Preuves : `TestLoadPackagesNoShell`, `TestGoListCommand`, critères 5 et 6.
- **T23 (SQL dynamique, réglage du tenant)** : tout accès SQL confiné aux adaptateurs (`sdk-confine-sql`, option B de la section 5.7), où le positionnement du tenant par transaction sera centralisé en M1.
- **Piège de M0 (couplage de `internal/loops`)** : R4 ; preuves `TestRuleDetectsViolation/loops-agnostic` et C3.
- **Menace nouvelle proposée à `security-reviewer` pour la clôture (H4)**, sans modification du modèle par ce plan : « Affaiblissement ou contournement des règles d'architecture » (T) : modification de `DefaultRules` ou d'une fixture dans la même PR que le code fautif ; fichier sous contrainte de build non analysé (K2) ; contournement hors graphe d'imports (K9) ; résultat de test mis en cache (K1) ; code non test d'`archtest` lié dans un binaire livré. Atténuations : CODEOWNERS sur `internal/archtest/` (M0-T04), revue humaine des changements de règles, `trackSources`, `-count=1` dans `arch-test`, critère 15 puis règle dédiée (tâche de durcissement). Tests : ceux de ce plan ; seconde invocation avec tags à créer si un fichier livré sous contrainte apparaît.
- **ADR** : aucun. Les règles viennent de la vue d'ensemble validée ; les précisions P1 à P12 et l'option B se changent par une tâche ordinaire.

---

## 13. Tâches ordonnées (un seul tour de l'agent principal, section 3.2)

Phase tests :

| # | Tâche | Qui | Vérification immédiate |
|---|---|---|---|
| A0 | Conditions d'entrée (section 3.1) ; `python3 .claude/bin/rempart-state phase tests` | agent principal | `Phase : free -> tests` |
| A1 | V0 (section 7.5) : comportement de `go list` dans un module vide et hors module | `test-author` | codes et messages notés pour A4 |
| A2 | 14 fixtures `testdata/golist/*.json` (section 7.2) | `test-author` | `ls internal/archtest/testdata/golist/*.json \| wc -l` : `14` ; relecture croisée avec le tableau 7.2 |
| A3 | `rules_test.go` : `TestMatch`, `TestStdlibDetection`, `TestCheck`, `TestDefaultRules`, `TestRuleFixturesCoverDefaultRules`, `TestRuleDetectsViolation` | `test-author` | message de `post_edit_check` limité à `undefined:` sur des symboles de la section 5 |
| A4 | `packages_test.go` : `TestDecodePackages`, `TestGoListEnv`, `TestGoListCommand`, `TestLoadPackagesNoShell`, `TestLoadPackagesErrors` | `test-author` | idem |
| A5 | `imports_test.go` : `TestRepositoryConforms`, `trackSources` | `test-author` | idem |
| A6 | Copie scratch avec stubs (section 7.7), preuve de rouge (section 7.6), `phase impl` | `test-author` puis agent principal | tableau 7.6 ; `Phase : tests -> impl` |

Phase impl (dans le même tour) :

| # | Incrément | Vérification immédiate |
|---|---|---|
| I1 | `packages.go` et `rules.go` : toutes les déclarations de la section 5 avec des corps minimaux (valeurs nulles, sans `panic`) | `go vet ./internal/archtest; echo rc=$?` : `rc=0` ; `go test ./internal/archtest/ -count=1` échoue sur des assertions, jamais à la compilation |
| I2 | `decodePackages` | `go test ./internal/archtest/ -count=1 -run '^TestDecodePackages$'` : `ok` |
| I3 | `goListEnv`, `goListCmd`, `LoadPackages` | `-run '^(TestGoListEnv\|TestGoListCommand\|TestLoadPackagesNoShell\|TestLoadPackagesErrors)$'` : `ok` |
| I4 | `isStdlib`, `inModule`, `validPattern`, `Match` | `-run '^TestMatch$'` : `ok` ; `-run '^TestStdlibDetection$'` : seul `dotless_module_rejected` échoue encore |
| I5 | `Check` | `-run '^(TestCheck\|TestStdlibDetection)$'` : `ok` |
| I6 | `DefaultRules` | `-run '^(TestDefaultRules\|TestRuleFixturesCoverDefaultRules\|TestRuleDetectsViolation\|TestRepositoryConforms)$'` : `ok` ; critères 1 et 2 |
| I7 | `doc.go` (section 5.6) | critère 14 ; `-run '^TestLayoutMatchesVision$'` : `ok` |
| I8 | `golangci-lint run ./...`, `go mod tidy -diff`, puis `make verify-quick` | critères 3, 5, 12, 13 ; fin de tour possible |

Clôture :

| # | Étape | Vérification |
|---|---|---|
| F1 | Critères 4 à 15, puis C1 à C5 sur copies | tableaux des sections 8.2 et 8.3 |
| F2 | `security-reviewer` (section 9), puis `acceptance-verifier` (critères 1 à 15, C1 à C5) | verdicts PASS |
| F3 | `docs/STATUS.md` : précisions P1 à P12, option B de la section 5.7, résultat de V0, contraintes K3 et K4 pour T14, T15, T19, T20, T22, T23, M1, M5 ; note dans la section 5.2 de `docs/plans/M0-overview.md` renvoyant à P1 à P5 ; `python3 .claude/bin/rempart-state phase free --reason "tâche archtest-imports terminée"` ; commit `test(archtest): enforce import rules R1 to R5 with go list (M0-T02)` | `git status --porcelain \| wc -l` : `0` après commit ; `make verify-quick; echo rc=$?` : `rc=0` |
