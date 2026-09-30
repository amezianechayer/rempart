# M0-T04b `make-subcalls` : chaque sous-make porte `-f Makefile`

2026-09-30, `architect`, proposé ; amendement V1 le même jour après le BLOCK de `security-reviewer`. Sources : `Makefile`, `docs/STATUS.md` obligation (bp), `docs/02-THREAT-MODEL.md` T31 et T32, `docs/plans/M0-ci.md`, `internal/archtest/makefile_test.go`, `internal/archtest/compose_test.go`, `internal/archtest/ci_test.go` (`TestNoShadowMakefile`), `.claude/hooks/guard_bash.py` (ligne 52), `.github/CODEOWNERS`, propositions 0003, 0007, 0008.

## Amendement V1 (après BLOCK de la revue sécurité)

### Constats du BLOCK

Reproduits par le relecteur : tests verts, `make -n` confirmant l'exécution.

| # | Gravité | Constat | Cause dans la V0 | Réponse V1 |
|---|---|---|---|---|
| 1 | haute | `$(eval include evil.mk) # :` en fin de fichier ; variante `X := evil.mk` puis `$(eval -include $(X)) # :` | `parseMakefile` classe comme règle toute ligne contenant `:`, commentaire compris ; `makeIncludeRe` (`compose_test.go` l. 985) est ancrée en début de ligne ; la cible `$(eval` n'est pas contrôlée | D8 : `#` interdit hors commentaire, cibles au format `[a-z][a-z0-9-]*`, nom `X` hors ensemble |
| 2 | haute | `\t$(MAKE_COMMAND) -f evil.mk arch-test`, `\t$(MA$(NOTHING)KE) -f evil.mk arch-test` | `subMakeRefRe` ne voit que des mots ; `MAKE_COMMAND` et un nom calculé n'en sont pas | D7 : tout `$` de recette hors préfixe canonique est refusé |
| 3 | haute | `.RECIPEPREFIX := >` puis `verify-quick:` et `>@echo SHADOW # :` | `makeAssignRe` ignore l'affectation (étape 3) ; la ligne `>@echo SHADOW # :` est prise pour une règle à cause du `:` du commentaire | D8 : `.RECIPEPREFIX` hors ensemble, erreur à l'affectation même |
| 4 | moyenne | Déguisements shell : `m''ake -f evil.mk`, `bash -c`, `$$(printf ma)ke` | Aucune analyse statique du texte shell ne ferme ce cas | Résidu assumé, section 6 : CODEOWNERS et revue humaine du diff |
| 5 | basse | `MAKE=` et `MAKE_COMMAND=` hérités de l'environnement du lanceur | `guard_bash` refuse `MAKEFLAGS`, `MAKEFILES`, `GNUMAKEFLAGS`, pas `MAKE` ni `MAKE_COMMAND` | Obligation harnais, section 6 ; proposition jointe à celle du cas `test_hooks.sh` |
| 6 | basse | Faux positif : le mot `make` dans un `echo` de recette | D2 (détection large) | Accepté (section 8) |

Cause racine commune aux constats 1 à 3 : la V0 validait les lignes qu'elle reconnaissait comme appels à make, et `parseMakefile` ignorait (étapes 3 et 4) ce qu'il ne comprenait pas. Principe V1 : **tout ce que la grammaire de test ne reconnaît pas est une erreur, jamais ignoré.**

### Changements, par section

- Section 1 : périmètre étendu à la grammaire fermée du `Makefile` et aux expansions en recette ; hors périmètre complété (déguisement shell, `MAKE` et `MAKE_COMMAND` d'environnement).
- Section 2 : décisions D7 (recettes), D8 (grammaire fermée, dans `parseMakefile`), D9 (détection V0 conservée), D10 (modèle de menace). Correspondance avec la décision du BLOCK : D1 devient D7, D2 devient D8, D3 devient D9, D4 devient D10 (renumérotées pour ne pas heurter D1 à D6 de la V0).
- Section 3 : interfaces de la grammaire, messages d'erreur stables, nouveau test `TestMakefileGrammar`, ordre de décision de `checkSubMakeCalls`.
- Section 4 : fixtures existantes à adapter (six cas deviennent des erreurs du parseur).
- Section 5 : M13, M21, M22, M23 déplacés vers la grammaire (G11, G14, G15, G29) ; P6 devient le cas négatif M31 ; nouveaux cas M27 à M38 et G1 à G36 (G34 à G36 en V1.1) ; mutations du vérificateur C1 à C15 (révisées) et K1 à K17 (parseur).
- Section 6 : réécrite. L'affirmation V0 « une recette à autre préfixe fait échouer `parseMakefile`, donc échec franc » était fausse (constat 3) ; le résidu adverse n'est pas « fermé ».
- Section 7 : critères mis à jour (comptes, formes D7 et D8 par `grep`, rejeu des trois attaques, mutations K).
- Sections 8 et 9 : risques et tâches V1.

### Ce qui ne change pas

- Le `Makefile` : vérifié ligne à ligne, il satisfait déjà D7 et D8 (section 2, D8). Aucune modification de code de production.
- Phase : tout le travail V1 est du code de test (`internal/archtest/*_test.go`). Il se fait en phase **tests** ; pas de passage en impl (rien à implémenter hors tests). La preuve que les nouveaux cas ne sont pas vides est le critère 7 (rouge avant le durcissement du parseur) et les mutations K et C (critère 10).
- Pas d'ADR : la grammaire est un sous-ensemble de GNU make propre aux tests, réversible par un commit, sous CODEOWNERS (`/internal/archtest/`, `/Makefile`). La contrainte qu'elle impose aux évolutions futures du `Makefile` est voulue et documentée en section 8.

## 1. Objectif et périmètre

GNU make ne transmet pas `-f` dans `MAKEFLAGS`. Les 4 sous-make du `Makefile` (lignes 31, 32, 35, 79) relisaient donc le fichier par défaut du répertoire : un `GNUmakefile` ou un `makefile` à la racine remplacerait `opa-test`, `arch-test` et `dev`, même quand le parent est lancé par `make -f Makefile` (hook Stop, CI). `TestNoShadowMakefile` refuse déjà ces fichiers ; ce plan ajoute la seconde ligne de défense, portée par la forme des appels, et (V1) ferme par test les indirections de niveau make qui contournaient cette forme.

Dans le périmètre :
- forme canonique unique d'un sous-make : `$(MAKE) -f Makefile --no-print-directory <cible>`, seule sur sa ligne de recette, préfixe `@` seul admis, suffixe ` >&2` seul admis ;
- règle archtest `checkSubMakeCalls` sur `mf.Lines` (tout le fichier) et test `TestMakefileSubMakeCalls` ;
- (V1) aucune expansion make en recette hors préfixe canonique (D7) ;
- (V1) grammaire fermée des lignes hors recette, appliquée par `parseMakefile` (D8), et test `TestMakefileGrammar` ;
- mise à jour des tests qui figent la forme actuelle (section 4) ;
- réécriture des 4 lignes du `Makefile` (faite en V0).

Hors périmètre :
- cas `test_hooks.sh` avec sous-make imbriqué : les hooks sont protégés, il relève d'une proposition de harnais (section 9, tâche V1-8) ;
- options de l'agent sur sa propre ligne de commande (`make -C`, `-n`, `-t`, `-q` : obligation (bt)) ;
- variables d'environnement du lanceur (hook Stop, CI) : `MAKEFILES`, et (V1) `MAKE`, `MAKE_COMMAND` ; hors du `Makefile`, section 6 ;
- (V1) modification adverse du `Makefile` par déguisement shell (`m''ake`, `bash -c`, `$$(printf ma)ke`, écriture d'un fichier puis appel) : aucune analyse statique ne la ferme ; défense par CODEOWNERS et revue humaine (section 6) ;
- préfixe `-` et `MAKEFLAGS` hors sous-make (durcissement T31 avant M3) : la règle refuse seulement le préfixe `-` devant un sous-make, par effet de l'ancrage ; `.IGNORE` est désormais refusé par D8, par effet de bord.

Aucune API, aucune dépendance, aucune boucle.

## 2. Décisions

Décisions V0 (inchangées sauf mention) :

- D1 **Liste blanche, pas liste noire.** Une ligne qui mentionne un appel à make est acceptée seulement si elle correspond exactement à la forme canonique. `-f` vers un autre fichier, `-f ./Makefile`, `-fMakefile`, `--file`, `--makefile`, `-C`, `--directory`, `-I`, `MAKEFILES=`, options ou variables supplémentaires, second appel sur la ligne : tous refusés par le même ancrage, sans règle dédiée.
- D2 **Détection large.** Une ligne mentionne un appel à make si elle contient le mot `MAKE`, le mot `make` ou `gmake`, ou le mot `MAKEFILES`. `MAKEFLAGS`, `MAKECMDGOALS`, `MAKE_COMMAND` et `Makefile` ne sont pas ces mots : non détectés par D2 (V1 : les formes `$(...)` correspondantes sont refusées par D7).
- D3 **Commentaires.** Seuls les commentaires de make sont ignorés : ligne logique qui ne commence pas par une tabulation et dont le texte, espaces retirés, commence par `#`. Une ligne de recette qui commence par `#` est du texte shell dans lequel make développe les `$` : elle est vérifiée (D2 et D7).
- D4 **Ligne de recette seulement.** Un appel hors ligne de recette est refusé. V1 : les affectations, recettes en ligne et directives concernées sont désormais refusées plus tôt par D8.
- D5 **Cible définie.** La cible nommée doit être une règle de `mf.Rules`.
- D6 **Constante partagée.** `subMakePrefix = "$(MAKE) -f Makefile --no-print-directory "` est la seule écriture de la forme dans les tests.

Décisions V1 :

- D7 **Recettes sans expansion make hors préfixe canonique.** Pour chaque ligne logique de recette (commençant par une tabulation, y compris celles dont le texte shell commence par `#`), on supprime les paires `$$` de gauche à droite (`strings.ReplaceAll(text, "$$", "")`, qui laisse le troisième `$` de `$$$`) ; s'il reste un `$`, la ligne doit correspondre à `canonicalSubMakeRe`, sinon c'est un problème. Ferme `$(eval ...)`, `$(call ...)`, `$(shell ...)`, `$(MAKE_COMMAND)`, les noms calculés (`$(MA$(X)KE)`), les variables de make (`$(MAKEFLAGS)`, `$(SUB)`) et les variables automatiques (`$@`, `$<`) en recette. Porté par `checkSubMakeCalls` (problème, pas erreur de parseur) : les contrôles négatifs de `checkMakefile` (`scenario_interpolated` et suivants) et de `checkDemoTarget` (`tenant_variable`, `namespace_braces`) injectent volontairement `$(...)` en recette et doivent rester atteignables. L'échec reste franc : `TestMakefileSubMakeCalls/repository` fait partie de `verify-quick`.
- D8 **Grammaire fermée hors recette, dans `parseMakefile`.** Toute ligne logique non vide, qui n'est ni un commentaire make (D3) ni une ligne de recette, doit relever d'une des formes ci-dessous ; sinon `parseMakefile` renvoie une erreur (tous les tests qui lisent le `Makefile` échouent). Ordre d'examen, texte espaces retirés aux extrémités :
  1. **Aucun `#`.** Un `#` sur une ligne hors commentaire est une erreur (commentaire de fin interdit partout, pas seulement sur les règles). Ferme le constat 1 et l'astuce `# :`.
  2. **Conditionnels et `define`** (`ifeq`, `ifneq`, `ifdef`, `ifndef`, `else`, `endif`, `define`, `endef`) : erreur, message V0 conservé.
  3. **Affectation** : toute ligne de forme `[override|export] NOM op valeur`, avec `op` parmi `=`, `:=`, `::=`, `:::=`, `?=`, `+=`, `!=`. Si `NOM` n'appartient pas à l'ensemble fermé `SHELL`, `.SHELLFLAGS`, `.DEFAULT_GOAL`, `EVAL`, `POLICIES_DIR`, `OPA`, `SCENARIO`, `GOWORK`, `GOFLAGS` : erreur (donc `MAKE`, `MAKE_COMMAND`, `MAKEFILES`, `MAKEFLAGS`, `GNUMAKEFLAGS`, `.RECIPEPREFIX`, `.EXTRA_PREREQS`, tout autre nom en `.` et tout nom arbitraire comme `SUB` ou `X`). Si `NOM` appartient à l'ensemble, la ligne entière doit être une des formes admises, sinon erreur :

     | Nom | Seules formes admises |
     |---|---|
     | `SHELL` | `SHELL := /bin/bash` |
     | `.SHELLFLAGS` | `.SHELLFLAGS := -eu -o pipefail -c` |
     | `.DEFAULT_GOAL` | `.DEFAULT_GOAL := verify-quick` |
     | `EVAL`, `POLICIES_DIR`, `OPA` | `NOM ?= valeur`, valeur au format `[A-Za-z0-9._/-]+` ; `override NOM := $(value NOM)` |
     | `SCENARIO` | `override SCENARIO := $(value SCENARIO)` |
     | `GOWORK` | `export GOWORK := off` |
     | `GOFLAGS` | `override GOFLAGS := -mod=readonly` |

     Ajustements de l'architecte par rapport à la décision du BLOCK, tous restrictifs : (i) opérateurs limités à `:=` et `?=` (les seuls utilisés ; `!=` exécute un shell à la lecture du fichier, sans aucun `$`) ; (ii) la forme `$(value NOM)` exige le même nom des deux côtés et un nom parmi les quatre variables de l'appelant (`callerVariables()`) ; (iii) valeurs figées pour `SHELL`, `.SHELLFLAGS`, `GOWORK`, `GOFLAGS` et `.DEFAULT_GOAL` : une valeur sans `$` suffit à détourner l'exécution (`SHELL := ./evil.sh`, `.SHELLFLAGS := -c evil`, `GOWORK := /tmp/go.work`), c'est une indirection de niveau make au même titre que `$(eval)`.
  4. **`export` suivi de noms** : `export` puis un ou plusieurs noms parmi `SCENARIO`, `EVAL`, `POLICIES_DIR`, `OPA`, `GOWORK`, `GOFLAGS`. `export` seul (qui exporte tout) ou suivi d'un autre nom : erreur.
  5. **`.PHONY:`** suivi d'un ou plusieurs noms au format `[a-z][a-z0-9-]*`. Une ligne `.PHONY` n'ouvre pas de contexte de recette : une ligne tabulée qui la suit est « recipe line outside a rule ».
  6. **Règle** : exactement une cible au format `[a-z][a-z0-9-]*`, `:`, puis zéro ou plusieurs prérequis au même format, séparés par une espace. Donc ni `$`, ni `;` (recette en ligne), ni `|`, ni `%` (règle de motif), ni `::`, ni cible spéciale (`.SECONDEXPANSION`, `.ONESHELL`, `.IGNORE`, `.RECIPEPREFIX`), ni variable propre à une cible (`arch-test: export MAKEFILES = evil.mk`). Une cible nommée par deux lignes de règle est une erreur (hors `.PHONY`).
  7. Toute autre ligne : erreur. Couvre `include`, `-include`, `sinclude`, `vpath`, `unexport`, `override` sans affectation, ligne sans `:`.

  Vérification sur le `Makefile` actuel (115 lignes) : lignes hors recette non commentaires = 4, 5, 6 (formes figées), 8 à 10 (`?=`), 15 à 18 (`$(value)`), 19 et 22 (`export` de noms), 20 (`export GOWORK := off`), 21 (`override GOFLAGS := -mod=readonly`), 24 et 25 (`.PHONY`), 14 lignes de règle à une cible dont les prérequis sont `verify-quick`, `dev-preflight` ou `sandbox-guard`. Aucun `#` hors commentaire. Toutes conformes, ensemble non élargi.
- D9 **Détection V0 conservée.** D2 reste appliquée à toutes les lignes non commentaires. D7 la rend redondante pour les formes `$(...)`, elle reste nécessaire pour `make`, `gmake`, `MAKE=`, `MAKEFILES=` littéraux en texte shell. Ordre de décision dans `checkSubMakeCalls`, un seul problème par ligne : forme canonique, puis cible définie ; sinon ligne qui mentionne make (D2) : message V0 ; sinon ligne de recette qui viole D7 : message D7.
- D10 **Modèle de menace.** Les tests ferment la forme accidentelle et les indirections de niveau make énumérées aux sections 5 et 6. La modification adverse par déguisement shell ne repose que sur CODEOWNERS et la revue humaine du diff du `Makefile`. Résidu d'environnement `MAKE`, `MAKE_COMMAND` : obligation harnais.

## 3. Interfaces (code de test, `internal/archtest/makefile_test.go`)

```go
// T32, obligation (bp): GNU make does not pass -f to sub-makes through MAKEFLAGS.
const subMakePrefix = "$(MAKE) -f Makefile --no-print-directory "

var (
	subMakeRefRe       = regexp.MustCompile(`\bMAKE\b|\bg?make\b|\bMAKEFILES\b`)
	canonicalSubMakeRe = regexp.MustCompile(`^\t@?\$\(MAKE\) -f Makefile --no-print-directory ([a-z][a-z0-9-]*)( >&2)?$`)
)

// expandsMake reports whether make expands something in a recipe line (D7):
// a "$" left once the "$$" pairs are removed.
func expandsMake(recipeLine string) bool

// checkSubMakeCalls reports every non-comment logical line of the Makefile that
// mentions make (D2) or, for a recipe line, expands make syntax (D7), and is
// not exactly a canonical sub-make recipe line naming a defined target (D1,
// D3, D5, D9). At most one problem per line.
func checkSubMakeCalls(mf parsedMakefile) []string

// TestMakefileSubMakeCalls: subtests negative_controls/<name>,
// positive_controls/<name>, repository.
func TestMakefileSubMakeCalls(t *testing.T)
```

Messages de `checkSubMakeCalls`, contenu stable pour les `want` :
- D2 : `Makefile line %d: sub-make must be exactly "$(MAKE) -f Makefile --no-print-directory <target>" on its own recipe line (T32): %q` (inchangé) ;
- D5 : `Makefile line %d: sub-make target %q is not defined` (inchangé) ;
- D7 : `Makefile line %d: recipe line expands make syntax outside the canonical sub-make (D7, T32): %q`.

Grammaire D8 (remplace `makeAssignRe` et `makeIgnoredRe`, qui disparaissent ; `makeUnsupportedRe` et `overrideValueRe` sont réutilisées) :

```go
var (
	// Any assignment shape, recognized to be refused unless allowed (D8 step 3).
	makeAssignShapeRe = regexp.MustCompile(`^(?:(?:override|export)\s+)?([^\s:#=!?+]+)\s*(?::{1,3}=|[?+!]?=)`)
	makeExportRe      = regexp.MustCompile(`^export((?: [A-Z_]+)+)$`)
	makePhonyRe       = regexp.MustCompile(`^\.PHONY:((?: [a-z][a-z0-9-]*)+)$`)
	makeRuleRe        = regexp.MustCompile(`^([a-z][a-z0-9-]*):((?: [a-z][a-z0-9-]*)*)$`)
)

// makeVariables: the only variables the Makefile may assign (D8 step 3).
func makeVariables() []string // SHELL .SHELLFLAGS .DEFAULT_GOAL EVAL POLICIES_DIR OPA SCENARIO GOWORK GOFLAGS

// makeExportable: the only names "export" may list (D8 step 4).
func makeExportable() []string // SCENARIO EVAL POLICIES_DIR OPA GOWORK GOFLAGS

// makeAssignForms: whole-line forms allowed for the variables of makeVariables,
// besides "override NAME := $(value NAME)" for callerVariables() (overrideValueRe,
// both names equal).
var makeAssignForms = []*regexp.Regexp{
	regexp.MustCompile(`^SHELL := /bin/bash$`),
	regexp.MustCompile(`^\.SHELLFLAGS := -eu -o pipefail -c$`),
	regexp.MustCompile(`^\.DEFAULT_GOAL := verify-quick$`),
	regexp.MustCompile(`^(EVAL|POLICIES_DIR|OPA) \?= [A-Za-z0-9._/-]+$`),
	regexp.MustCompile(`^export GOWORK := off$`),
	regexp.MustCompile(`^override GOFLAGS := -mod=readonly$`),
}

// parseMakefile parses the closed grammar of docs/plans/M0-make-subcalls.md D8.
func parseMakefile(src string) (parsedMakefile, error)

// TestMakefileGrammar (M0-T04b V1, T32): parseMakefile refuses every line
// outside D8. Subtests negative_controls/<name>, positive_controls/<name>,
// repository.
func TestMakefileGrammar(t *testing.T)
```

Messages d'erreur de `parseMakefile`, fragments stables pour les `wantErr` (toujours précédés de `line %d: `, numéro de la première ligne physique de la ligne logique) :

| Code | Message | Étape D8 |
|---|---|---|
| E1 | `comment after make syntax not allowed (D8): %q` | 1 |
| E2 | `unsupported directive %q: update the test parser before using it` (V0) | 2 |
| E3 | `variable %q not allowed in the Makefile (D8)` | 3, nom hors ensemble |
| E4 | `form not allowed for variable %s (D8): %q` | 3, nom dans l'ensemble |
| E5 | `export not allowed (D8): %q` | 4 |
| E6 | `line outside the Makefile grammar of the tests (D8): %q` | 7 (et 5, 6 non conformes) |
| E7 | `target %q already named by the rule of line %d (D8)` | 6 |
| E8 | `recipe line outside a rule` (V0) | recette sans règle, ou après `.PHONY` |

Le commentaire de `parseMakefile` (règles 1 à 8 citant M0-squelette 8.4) est réécrit pour citer D8 ; la vérification « second recipe for target » devient inatteignable (une seconde recette exige une seconde ligne de règle, refusée par E7) et est supprimée. `reachableTargets` reste inchangé.

Dans les tests, un `wantErr` est construit par `fmt.Sprintf("line %d: ", physicalLine(t, src, fragment)) + code`, pour vérifier que l'erreur porte sur la ligne mutée.

## 4. Tests existants à faire évoluer (phase tests)

V0 (faits) :

| Fichier, emplacement | Changement |
|---|---|
| `makefile_test.go` `verifyQuickSteps` | regex exactes sur `subMakePrefix` |
| `makefile_test.go` `targetMakefile` | deux lignes canoniques ; commentaire du gabarit amendé |
| `makefile_test.go` `checkDemoTarget`, `devLine` | forme canonique |
| `compose_test.go` `verifyDevCallRe`, `referenceVerifyRule`, `devCall` | forme canonique |

V1, fixtures à adapter (les gabarits `targetMakefile`, `referenceDevMakefile(t)` et le `valid` de `TestMakefileDemoTarget` sont conformes à D7 et D8 sans changement) :

| Fichier, cas | Aujourd'hui | V1 |
|---|---|---|
| `makefile_test.go` `TestMakefileTargets/negative_controls/docker_in_inline_recipe` | `want` docker via `checkMakefile` | `wantErr` E6 (`arch-test: ; docker compose up -d`) |
| `TestMakefileTargets/.../duplicate_rule` | `wantErr` `second recipe for target "dev-down"` | `wantErr` E7 `target "dev-down" already named by the rule of line` |
| `TestMakefileTargets/.../double_colon_rule` | `wantErr` `double-colon rule` | `wantErr` E6 |
| `TestMakefileTargets/.../bare_export_before_override` | `want` « exported before » | `wantErr` E5 (ligne `export` seule) |
| `TestMakefileTargets/.../override_expands_caller_value` | `want` « not frozen », « interpolated » | `wantErr` E4 `form not allowed for variable SCENARIO` |
| `TestMakefileSubMakeCalls` M13, M21, M22, M23 | cas de `checkSubMakeCalls` | déplacés vers `TestMakefileGrammar` (G14, G15, G11, G29) |
| `TestMakefileSubMakeCalls/positive_controls/makeflags_in_echo` (P6) | positif | devient le négatif M31 `makeflags_in_recipe` ; nouveau P6 `shell_dollar` |
| `compose_test.go` `TestMakeDevUsesWait/negative_controls/include_env` | `want` `include directive not allowed` | ajouter un champ `wantErr` à la table et la branche `expectError` dans la boucle ; `wantErr` E6 sur la ligne `-include .env.dev` |
| `compose_test.go` l. 985 et 1111 `makeIncludeRe` | vérification hors recette | inatteignable (D8 refuse la ligne avant) : entrée supprimée de `checkDevTargets`, la propriété reste portée par `include_env` (`wantErr`) |

Les autres cas de `TestMakefileTargets`, `TestMakeDevUsesWait` et `TestMakefileDemoTarget` restent inchangés : leurs mutations portent sur des recettes (D7 n'est pas appliquée par `checkMakefile`, `checkDevTargets` ni `checkDemoTarget`) ou sur des lignes conformes à D8 (`export EVAL`, `export SCENARIO EVAL OPA`, `verify-quick: dev-preflight`, `sandbox-apply:`).

## 5. Mutations que les tests doivent tuer

### 5.1 `TestMakefileSubMakeCalls/negative_controls` (problèmes de `checkSubMakeCalls`)

Chaque cas est appliqué au gabarit `targetMakefile` et exige exactement un problème, sur la ligne mutée. `mustBe` désigne le message D2, `D7` le message D7.

| # | Nom du cas | Ligne mutée | Message |
|---|---|---|---|
| M1 | `without_file` | `$(MAKE) --no-print-directory opa-test` | mustBe |
| M2 | `file_after_option` | `$(MAKE) --no-print-directory -f Makefile dev` | mustBe |
| M3 | `other_file` | `$(MAKE) -f GNUmakefile --no-print-directory arch-test` | mustBe |
| M4 | `dot_slash_file` | `$(MAKE) -f ./Makefile --no-print-directory arch-test` | mustBe |
| M5 | `glued_file` | `$(MAKE) -fMakefile --no-print-directory arch-test` | mustBe |
| M6 | `second_file` | `$(MAKE) -f Makefile -f evil.mk --no-print-directory arch-test` | mustBe |
| M7 | `long_file` | `$(MAKE) --file=Makefile --no-print-directory arch-test` | mustBe |
| M8 | `long_makefile` | `$(MAKE) --makefile Makefile --no-print-directory arch-test` | mustBe |
| M9 | `change_directory` | `$(MAKE) -f Makefile -C sub --no-print-directory arch-test` | mustBe |
| M10 | `long_directory` | `$(MAKE) -f Makefile --directory=sub --no-print-directory arch-test` | mustBe |
| M11 | `include_dir` | `$(MAKE) -f Makefile -I inc --no-print-directory arch-test` | mustBe |
| M12 | `makefiles_env` | `MAKEFILES=evil.mk $(MAKE) -f Makefile --no-print-directory arch-test` | mustBe |
| M13 | (déplacé : G14) | | |
| M14 | `braces` | `${MAKE} -f Makefile --no-print-directory arch-test` | mustBe |
| M15 | `literal_make` | `make -f Makefile --no-print-directory arch-test` | mustBe |
| M16 | `gmake_path` | `/usr/bin/gmake -f Makefile --no-print-directory arch-test` | mustBe |
| M17 | `ignore_errors_prefix` | `-$(MAKE) -f Makefile --no-print-directory arch-test` | mustBe |
| M18 | `second_call` | canonique puis ` && $(MAKE) --no-print-directory dev` | mustBe |
| M19 | `trailing_make` | canonique puis `; make dev` | mustBe |
| M20 | `extra_variable` | canonique puis ` EVAL=x` | mustBe |
| M21 | (déplacé : G15) | | |
| M22 | (déplacé : G11) | | |
| M23 | (déplacé : G29) | | |
| M24 | `undefined_target` | `$(MAKE) -f Makefile --no-print-directory nope` | D5 |
| M25 | `hidden_in_continuation` | `$(MAKE) -f Makefile \` puis `--no-print-directory -f evil.mk dev` | mustBe |
| M26 | `shell_comment_in_recipe` | ligne de recette `# $(MAKE) --no-print-directory dev` | mustBe |
| M27 | `make_command` | `$(MAKE_COMMAND) -f evil.mk arch-test` (constat 2) | D7 |
| M28 | `computed_name` | `$(MA$(NOTHING)KE) -f evil.mk arch-test` (constat 2) | D7 |
| M29 | `dollar_in_recipe_other` | ligne ajoutée à `dev` : `$(shell id)` | D7 |
| M30 | `automatic_var_in_recipe` | ligne ajoutée à `dev` : `echo $@` | D7 |
| M31 | `makeflags_in_recipe` | ligne ajoutée à `dev` : `@echo "$(MAKEFLAGS)"` (ex-P6) | D7 |
| M32 | `triple_dollar` | ligne ajoutée à `dev` : `echo $$$(shell id)` | D7 |
| M33 | `eval_in_recipe` | ligne ajoutée à `dev` : `$(eval include evil.mk)` | D7 |
| M34 | `indirect_reference` | `$(SUB) -f Makefile --no-print-directory dev` (sans l'affectation, refusée par D8) | D7 |
| M35 | `shell_comment_expansion` | ligne ajoutée à `verify` : `# $(shell id)` | D7 |
| M36 | `expansion_in_continuation` | ligne ajoutée à `dev` : `echo ok \` puis `$(shell id)` ; numéro attendu : première ligne physique | D7 |
| M37 | `shell_make_variable` | ligne ajoutée à `dev` : `MAKE=/tmp/x true` | mustBe |
| M38 | `makefiles_shell_env` | ligne ajoutée à `dev` : `MAKEFILES=evil.mk go test ./...` | mustBe |

Total : 34 cas négatifs.

Contrôles positifs (`positive_controls`, aucun problème attendu) : P1 `valid_template` ; P2 `make_comment` (`# Le hook Stop exige make verify-quick` et `  # ... $(MAKE) -C ailleurs`) ; P3 `silenced_to_stderr` ; P4 `canonical_continuation` ; P5 `echo_makefile_word` ; P6 `shell_dollar` : ligne ajoutée à `dev` `@echo "$$HOME $${USER:-x} $$(id -u)"`. Total : 6.

### 5.2 `TestMakefileGrammar/negative_controls` (erreurs de `parseMakefile`)

Chaque cas part de `targetMakefile` ; `wantErr` = `line <n>: ` + fragment du code indiqué, `<n>` étant la ligne physique de la ligne mutée (via `physicalLine`). « fin » : ajouté après la dernière ligne ; « après OPA » : inséré après `OPA ?= opa`.

| # | Nom du cas | Mutation | Erreur |
|---|---|---|---|
| G1 | `eval_include_comment_colon` | fin : `$(eval include evil.mk) # :` (constat 1) | E1 |
| G2 | `eval_include_indirect` | fin : `X := evil.mk` puis `$(eval -include $(X)) # :` ; erreur sur la ligne `X` | E3 |
| G3 | `recipeprefix` | fin : `.RECIPEPREFIX := >`, `verify-quick:`, `>@echo SHADOW # :` ; erreur sur `.RECIPEPREFIX` (constat 3) | E3 |
| G4 | `include_directive` | après OPA : `include evil.mk` | E6 |
| G5 | `dash_include_directive` | après OPA : `-include evil.mk` | E6 |
| G6 | `sinclude_directive` | après OPA : `sinclude evil.mk` | E6 |
| G7 | `vpath_directive` | après OPA : `vpath %.mk evil` | E6 |
| G8 | `unexport_directive` | après OPA : `unexport OPA` | E6 |
| G9 | `define_block` | après OPA : `define X` puis `endef` | E2 |
| G10 | `assign_make` | après OPA : `MAKE := make -f GNUmakefile` | E3 |
| G11 | `redefine_make` | après `override OPA := $(value OPA)` : `override MAKE := make -f GNUmakefile` (ex-M22) | E3 |
| G12 | `assign_make_command` | après OPA : `MAKE_COMMAND := evil` | E3 |
| G13 | `assign_makeflags` | après OPA : `MAKEFLAGS := -i` | E3 |
| G14 | `makefiles_assignment` | après `export SCENARIO ...` : `export MAKEFILES := evil.mk` (ex-M13) | E3 |
| G15 | `indirect_variable` | après OPA : `SUB := $(MAKE)`, et `$(SUB) -f Makefile --no-print-directory dev` en recette (ex-M21) ; erreur sur `SUB` | E3 |
| G16 | `value_other_name` | `override EVAL := $(value EVAL)` devient `override EVAL := $(value OPA)` | E4 |
| G17 | `assign_dollar_value` | `EVAL ?= all` devient `EVAL ?= $(shell id)` | E4 |
| G18 | `shell_assign` | `EVAL ?= all` devient `EVAL != id` | E4 |
| G19 | `assign_shell_other` | `SHELL := /bin/bash` devient `SHELL := /tmp/evil.sh` | E4 |
| G20 | `shellflags_changed` | `.SHELLFLAGS := -eu -o pipefail -c` devient `.SHELLFLAGS := -c evil` | E4 |
| G21 | `bare_export` | après OPA : `export` | E5 |
| G22 | `export_other_name` | après `export SCENARIO ...` : `export MAKEFLAGS` | E5 |
| G23 | `unknown_special_var` | fin : `.SECONDEXPANSION:` | E6 |
| G24 | `ignore_special_target` | fin : `.IGNORE:` | E6 |
| G25 | `target_bad_chars` | fin : `%:` puis recette `@echo x` | E6 |
| G26 | `target_specific_variable` | règle `arch-test:` devient `arch-test: export MAKEFILES = evil.mk` | E6 |
| G27 | `prereq_expansion` | règle `verify: verify-quick` devient `verify: verify-quick $(eval include evil.mk)` | E6 |
| G28 | `phony_expansion` | `.PHONY: dev dev-preflight` devient `.PHONY: $(eval include evil.mk) dev dev-preflight` | E6 |
| G29 | `inline_recipe` | règle `arch-test: ; $(MAKE) -f Makefile --no-print-directory opa-test` (ex-M23) | E6 |
| G30 | `rule_trailing_comment` | règle `dev-down:` devient `dev-down: # arrêt` | E1 |
| G31 | `assign_trailing_comment` | `EVAL ?= all` devient `EVAL ?= all # défaut` | E1 |
| G32 | `duplicate_rule_line` | fin : `arch-test: opa-test` (sans recette) | E7 |
| G33 | `phony_with_recipe` | après la seconde ligne `.PHONY` : `\t@echo x` | E8 |
| G34 | `gowork_changed` | `export GOWORK := off` devient `export GOWORK := /tmp/go.work` | E4 |
| G35 | `goflags_changed` | `override GOFLAGS := -mod=readonly` devient `override GOFLAGS := -mod=mod` | E4 |
| G36 | `default_goal_changed` | `.DEFAULT_GOAL := verify-quick` devient `.DEFAULT_GOAL := demo` | E4 |

Total : 36 cas négatifs. G34 à G36 (V1.1) : ajoutés après la campagne de mutations de V1-3, où la mutation K7b (valeurs figées de `GOWORK`, `GOFLAGS`, `.DEFAULT_GOAL` remplacées par « valeur sans `$` ») survivait.

Contrôles positifs (`positive_controls`, `parseMakefile` sans erreur) : GP1 `valid_template` ; GP2 `go_env_lines` (après `export SCENARIO ...` : `export GOWORK := off`, `override GOFLAGS := -mod=readonly`, `export GOFLAGS`) ; GP3 `comments_with_syntax` (`# $(eval include evil.mk) # :` et `  # include evil.mk`) ; GP4 `reference_dev_makefile` (`referenceDevMakefile(t)`). Total : 4. Sous-test `repository` : `parseMakefile` du `Makefile` sans erreur.

### 5.3 Mutations du vérificateur

Appliquées par `acceptance-verifier` sur une copie de travail ; chacune doit faire échouer le test indiqué.

`checkSubMakeCalls` (tuées dans `TestMakefileSubMakeCalls`) :

| # | Mutation | Tuée par |
|---|---|---|
| C1 | ignore les lignes de recette | M1 et suivants |
| C2 | lit `mf.Rules[*].Recipe` au lieu de `mf.Lines` (tabulation et `@` perdus) | P1, `repository` |
| C3 | ne saute plus les commentaires make | P2, `repository` |
| C4 | saute aussi les lignes de recette commençant par `#` | M26, M35 |
| C5 | ne vérifie pas que la cible est définie | M24 |
| C6 | regex canonique sans `$` final | M18, M19, M20 |
| C7 | regex canonique sans `^\t@?` | M12, M17 |
| C8 | détection sans `\bMAKE\b` | M37 (M14 par le message : D7 au lieu de mustBe) |
| C9 | détection sans `\bg?make\b` | M15, M16 |
| C10 | détection sans `\bMAKEFILES\b` | M38 |
| C11 | `checkSubMakeCalls` renvoie toujours `nil` | tous les M |
| C12 | vérification D7 supprimée | M27 à M36 |
| C13 | D7 ne cherche que `$(` et `${` | M30 |
| C14 | D7 exempte toute ligne contenant `$$` | M32 |
| C15 | D7 sans suppression préalable des `$$` | P1, P6, `repository` |

`parseMakefile` (tuées dans `TestMakefileGrammar`, sauf mention) :

| # | Mutation | Tuée par |
|---|---|---|
| K1 | ligne non reconnue ignorée au lieu de E6 (comportement V0) | G4 à G8, G23 à G29 |
| K2 | pas de contrôle du `#` (étape 1) | G1, G30, G31 (erreur E6 ou E4 au lieu de E1) |
| K3 | nom hors ensemble accepté sans contrôle | G2, G3, G10 à G15 |
| K4 | formes non contrôlées pour les noms de l'ensemble | G16 à G20 |
| K5 | forme `$(value)` sans égalité des deux noms | G16 |
| K6 | valeur de `EVAL`, `POLICIES_DIR`, `OPA` après `?=` libre | G17 |
| K7 | valeurs figées remplacées par « valeur sans `$` » | G19, G20 |
| K8 | `export` seul accepté | G21, `TestMakefileTargets/.../bare_export_before_override` |
| K9 | noms après `export` non contrôlés | G22 |
| K10 | format de cible remplacé par `\S+` | G23, G24, G25 |
| K11 | prérequis non contrôlés | G26, G27, G29 |
| K12 | noms de `.PHONY` non contrôlés | G28 |
| K13 | pas de contrôle E7 | G32, `TestMakefileTargets/.../duplicate_rule` |
| K14 | `.PHONY` ouvre un contexte de recette | G33 |
| K15 | conditionnels et `define` acceptés | G9, `TestMakefileTargets/.../unsupported_conditional` |
| K16 | `parseMakefile` renvoie toujours une erreur `nil` | tous les G |
| K17 | `makeRuleRe` sans `$` final | G26, G27, G29 |

## 6. Menaces (`docs/02-THREAT-MODEL.md`)

Correction de la V0. Deux affirmations de la V0 étaient fausses et sont retirées :
- « `.RECIPEPREFIX` non analysé : une recette à autre préfixe fait échouer `parseMakefile`, donc échec franc » : faux. `.RECIPEPREFIX := >` était ignoré comme affectation (étape 3 V0) et `>@echo SHADOW # :` était classé comme règle grâce au `:` de son commentaire ; le `Makefile` ainsi modifié passait tous les tests (constat 3). V1 : l'affectation elle-même est refusée (D8, G3).
- Le résidu « sous-make sans `-f` » n'est pas « fermé » au sens adverse : seule la forme accidentelle et les indirections de niveau make énumérées le sont.

Nouvelle rédaction de la ligne T32, colonnes contrôle et test (à reporter par le principal, tâche V1-7) :

- **Couvert par test** : forme accidentelle (sous-make sans `-f Makefile` ou non canonique : `TestMakefileSubMakeCalls`, D1 à D5) ; indirections de niveau make énumérées : expansions en recette (`$(eval)`, `$(call)`, `$(shell)`, `$(MAKE_COMMAND)`, noms calculés, `$(MAKEFLAGS)`, variables automatiques : D7), directives et affectations hors grammaire (`include` et variantes, `vpath`, `unexport`, `define`, conditionnels, affectation de `MAKE`, `MAKE_COMMAND`, `MAKEFILES`, `MAKEFLAGS`, `.RECIPEPREFIX` ou de tout nom hors ensemble, `!=`, valeurs de `SHELL`, `.SHELLFLAGS`, `GOWORK` modifiées, cibles spéciales, variables propres à une cible, recettes en ligne, commentaires de fin : D8, `TestMakefileGrammar`).
- **Non couvert par analyse statique** : modification adverse du `Makefile` par déguisement shell (`m''ake -f evil.mk`, `bash -c "..."`, `$$(printf ma)ke`, recette qui écrit un fichier puis l'exécute). Ce cas ne repose que sur CODEOWNERS (`/Makefile` et `/internal/archtest/`, revue obligatoire par la protection de branche) et sur la revue humaine du diff du `Makefile`. D7 et D8 réduisent la surface à relire au seul texte shell des recettes.
- **Environnement du lanceur** : `MAKEFILES` (le hook Stop et la CI ne le posent pas, `guard_bash` le refuse sur la ligne de commande, D5 de M0-ci) ; nouveau résidu (constat 5) : `MAKE` et `MAKE_COMMAND` hérités de l'environnement remplacent la commande des sous-make canoniques, et `guard_bash` (`.claude/hooks/guard_bash.py` l. 52) ne les refuse pas. Obligation harnais, à joindre à la proposition du cas `test_hooks.sh` : diff proposé à l'humain sur l'expression de la ligne 52, `\b(MAKEFLAGS|MAKEFILES|GNUMAKEFLAGS)\s*=` devient `\b(MAKEFLAGS|MAKEFILES|GNUMAKEFLAGS|MAKE|MAKE_COMMAND)\s*=` ; cas `test_hooks.sh` : `MAKE=/tmp/x make verify-quick` et `env MAKE_COMMAND=/tmp/x make verify-quick` refusés ; option complémentaire pour le hook Stop : lancer `env -u MAKE -u MAKE_COMMAND -u MAKEFILES -u MAKEFLAGS make -f Makefile verify-quick`. Épingler `MAKE` dans le `Makefile` est écarté : D8 interdit d'affecter `MAKE`, et toute valeur épinglée (`make`) dépendrait encore de `PATH`, lui aussi hérité.
- **Inchangé** : cas `test_hooks.sh` avec sous-make imbriqué (proposition harnais).

Effet de bord sur T31 (à noter dans sa colonne contrôle) : `.IGNORE` et l'affectation de `MAKEFLAGS` dans le `Makefile` sont désormais refusés par D8, `$(MAKEFLAGS)` en recette par D7 ; le préfixe `-` hors sous-make et `MAKEFLAGS=` en texte shell restent à la tâche de durcissement avant M3. Aucune menace nouvelle.

## 7. Critères d'acceptation

Tous lancés depuis `/home/user/rempart`.

1. `go test -count=1 -run 'TestMakefileSubMakeCalls|TestMakefileGrammar' ./internal/archtest/` : `ok`.
2. Comptes :
   - `go test -count=1 -v -run 'TestMakefileSubMakeCalls/negative_controls' ./internal/archtest/ | grep -c -- '--- PASS: TestMakefileSubMakeCalls/negative_controls/'` : `34` ; même commande avec `positive_controls` : `6` ;
   - `go test -count=1 -v -run 'TestMakefileGrammar/negative_controls' ./internal/archtest/ | grep -c -- '--- PASS: TestMakefileGrammar/negative_controls/'` : `36` (V1.1) ; même commande avec `positive_controls` : `4`.
3. `go test -count=1 -run 'TestMakefileTargets|TestMakeDevUsesWait|TestMakefileDemoTarget|TestMakefileGoflagsNeutralized|TestNoShadowMakefile|TestCIRunsMakeVerify' ./internal/archtest/` : `ok`.
4. Forme du `Makefile`, indépendamment du code Go :
   - sous-make (V0) : `grep -cP '^\t@?\$\(MAKE\) -f Makefile --no-print-directory [a-z][a-z0-9-]*( >&2)?$' Makefile` affiche `4` ; `grep -nE '\bMAKE\b|\bg?make\b|\bMAKEFILES\b' Makefile | grep -vE '^[0-9]+:[[:blank:]]*#' | grep -cvP '^[0-9]+:\t@?\$\(MAKE\) -f Makefile --no-print-directory [a-z][a-z0-9-]*( >&2)?$'` affiche `0` ;
   - D7 : `grep -P '^\t' Makefile | sed 's/\$\$//g' | grep -cF '$'` affiche `4` et `grep -P '^\t' Makefile | sed 's/\$\$//g' | grep -F '$' | grep -cvP '^\t@?\$\(MAKE\) -f Makefile --no-print-directory [a-z][a-z0-9-]*( >&2)?$'` affiche `0` ;
   - D8 : `grep -vP '^(\t| *(#|$))' Makefile | grep -cF '#'` affiche `0`, et
     `grep -vP '^(\t| *(#|$))' Makefile | grep -cvP '^(SHELL := /bin/bash|\.SHELLFLAGS := -eu -o pipefail -c|\.DEFAULT_GOAL := verify-quick|(EVAL|POLICIES_DIR|OPA) \?= [A-Za-z0-9._/-]+|override (SCENARIO|EVAL|POLICIES_DIR|OPA) := \$\(value (SCENARIO|EVAL|POLICIES_DIR|OPA)\)|export GOWORK := off|override GOFLAGS := -mod=readonly|export( (SCENARIO|EVAL|POLICIES_DIR|OPA|GOWORK|GOFLAGS))+|\.PHONY:( [a-z][a-z0-9-]*)+|[a-z][a-z0-9-]*:( [a-z][a-z0-9-]*)*)$'` affiche `0`.
5. Comportement, sans rien exécuter (`-n` n'exécute que les lignes `$(MAKE)`) :
   `d=$(mktemp -d) && cp Makefile "$d/" && printf 'opa-test arch-test dev:\n\t@echo SHADOW\n' > "$d/GNUmakefile" && (cd "$d" && make -f Makefile -n verify-quick verify demo 2>&1) | grep -c SHADOW; rm -rf "$d"`
   affiche `0`.
6. Rejeu des trois attaques hautes du BLOCK sur une copie du commit V1 (après le commit de la tâche V1-3). Gabarit, `<MUT>` et `<TEST>` pris dans la liste :
   `d=$(mktemp -d) && git archive HEAD | tar -x -C "$d" && <MUT> && (cd "$d" && go test -count=1 -run '<TEST>' ./internal/archtest/ >/dev/null 2>&1); echo "exit=$?"; rm -rf "$d"`
   - témoin : `<MUT>` = `true`, `<TEST>` = `TestMakefileGrammar/repository|TestMakefileSubMakeCalls/repository` : affiche `exit=0` ;
   - constat 1 : `<MUT>` = `printf '\n$(eval include evil.mk) # :\n' >> "$d/Makefile"`, `<TEST>` = `TestMakefileGrammar/repository` : affiche `exit=1` ;
   - constat 2 : `<MUT>` = `sed -i 's/^\t\$(MAKE) -f Makefile --no-print-directory arch-test$/\t$(MAKE_COMMAND) -f evil.mk arch-test/' "$d/Makefile" && grep -q MAKE_COMMAND "$d/Makefile"`, `<TEST>` = `TestMakefileSubMakeCalls/repository` : affiche `exit=1` ;
   - constat 3 : `<MUT>` = `printf '\n.RECIPEPREFIX := >\nverify-quick:\n>@echo SHADOW # :\n' >> "$d/Makefile"`, `<TEST>` = `TestMakefileGrammar/repository` : affiche `exit=1`.
7. Rouge d'abord (constaté par `test-author` à la fin de la tâche V1-1, avant toute modification de `parseMakefile` et `checkSubMakeCalls`, sortie consignée dans `docs/STATUS.md`) :
   - `go test -count=1 -v -run 'TestMakefileGrammar/negative_controls' ./internal/archtest/ 2>&1 | grep -c -- '--- FAIL: TestMakefileGrammar/negative_controls/'` affiche `32` (seul G9 passe, E2 existant) ;
   - `go test -count=1 -v -run 'TestMakefileSubMakeCalls/negative_controls' ./internal/archtest/ 2>&1 | grep -c -- '--- FAIL: TestMakefileSubMakeCalls/negative_controls/'` affiche `10` (M27 à M36) ;
   - `go test -count=1 -v -run 'TestMakefileTargets/negative_controls|TestMakeDevUsesWait/negative_controls' ./internal/archtest/ 2>&1 | grep -cE -- '--- FAIL: Test[A-Za-z]+/negative_controls/'` affiche `6` (les cinq cas de `TestMakefileTargets` et `include_env` de la section 4).
8. `make -f Makefile verify-quick` : code 0.
9. Intégrité : sur chaque commit V1, `git diff --name-only HEAD~ -- CLAUDE.md .claude/settings.json .claude/hooks .claude/bin .claude/agents .claude/commands Makefile` n'affiche rien.
10. Mutations C1 à C15 et K1 à K17 (section 5.3) : pour chacune, sur une copie de travail, `go test -count=1 -run 'TestMakefileSubMakeCalls|TestMakefileGrammar|TestMakefileTargets' ./internal/archtest/` échoue ; `git status --porcelain internal/archtest` vide après restauration.
11. Documentation (tâche V1-7) : `grep -E '^\| T32 ' docs/02-THREAT-MODEL.md | grep -c 'TestMakefileGrammar'` affiche `1` ; `grep -E '^\| T32 ' docs/02-THREAT-MODEL.md | grep -c 'MAKE_COMMAND'` affiche `1` ; `grep -E '^\| T32 ' docs/02-THREAT-MODEL.md | grep -ciE 'ferm[ée]'` affiche `0` ; `grep -c 'MAKE_COMMAND' docs/STATUS.md` affiche au moins `1`.

## 8. Risques

- Faux positif (constat 6) : un `echo` contenant le mot `make` en recette est refusé (D2). Accepté : reformuler le message.
- Rigidité voulue : toute évolution du `Makefile` hors grammaire (nouvelle variable, `include`, `$@` ou `$(...)` en recette, cible avec `_` ou `.`, deux espaces dans une forme figée) fait échouer les tests. L'extension passe par une modification de `makeVariables`, `makeAssignForms` ou des regex de D8, sous CODEOWNERS `/internal/archtest/`, et doit être relue comme une modification de sécurité. Un reformatage anodin donne un échec franc, jamais une acceptation silencieuse.
- Écart entre la grammaire de test et GNU make : un sous-ensemble strict et ancré limite le risque qu'une ligne acceptée soit lue autrement par make ; les continuations sont jointes avant classement, comme make (y compris pour les commentaires, que make prolonge aussi par `\`). Le critère 5 exerce le vrai make.
- Divergence gabarit et plan d'origine : `targetMakefile` n'est plus verbatim de M0-squelette 6.1 ; son commentaire le dit.
- Code supprimé : la vérification « second recipe for target » et l'entrée `makeIncludeRe` de `checkDevTargets` deviennent inatteignables ; les garder laisserait des mutations survivantes sans valeur. Leur propriété est portée par E7 (`duplicate_rule`) et E6 (`include_env`).
- Résidu d'environnement `MAKE`, `MAKE_COMMAND` ouvert jusqu'à l'acceptation de la proposition harnais ; le hook Stop et la CI ne posent pas ces variables.
- Déguisement shell : résidu permanent, défense humaine seulement (section 6). Un relecteur qui approuve un diff du `Makefile` sans le lire le rouvre.
- Un seul sous-make restant sans `-f` suffit à rouvrir T32 : la règle porte sur toutes les lignes, pas sur une liste de cibles.

## 9. Tâches ordonnées

V0 : tâches 1 à 3 faites (cas M1 à M26, évolutions de la section 4, réécriture des 4 lignes du `Makefile`) ; tâche 4 : BLOCK de `security-reviewer`, retour en phase tests (STATUS, 2026-09-30 01:48).

V1, toutes en phase **tests** (aucun code de production, aucun passage en impl) :

1. V1-1 (`test-author`) Écrire les cas sans toucher `parseMakefile` ni `checkSubMakeCalls` : `TestMakefileGrammar` (G1 à G33, GP1 à GP4, `repository`) avec les codes d'erreur de la section 3 comme fragments ; dans `TestMakefileSubMakeCalls`, retirer M13, M21, M22, M23, ajouter M27 à M38, remplacer P6 ; adapter les six fixtures de la section 4 (champ `wantErr` dans la table de `TestMakeDevUsesWait`). Constater le critère 7 et consigner la sortie dans `docs/STATUS.md`.
2. V1-2 (`test-author`) Réécrire `parseMakefile` selon D8 (étapes 1 à 7, messages E1 à E8, commentaire de doc citant D8) ; supprimer `makeAssignRe`, `makeIgnoredRe` et la vérification « second recipe » ; supprimer l'entrée `makeIncludeRe` de `checkDevTargets`. Critères 1 (partie grammaire), 2 (grammaire), 3.
3. V1-3 (`test-author`) Ajouter `expandsMake` et D7 dans `checkSubMakeCalls` avec l'ordre D9 et le message D7. Critères 1, 2, 4, 8 ; commit ; puis critère 6 sur ce commit.
4. V1-4 (`security-reviewer`) Verdict PASS ou BLOCK, en rejouant au minimum les constats 1 à 3 du BLOCK (critère 6).
5. V1-5 (`acceptance-verifier`) Critères 1 à 10 avec preuves, dont la campagne de mutations C1 à C15 et K1 à K17.
6. V1-6 (principal) Si PASS : clôturer la tâche M0-T04b.
7. V1-7 (principal) `docs/02-THREAT-MODEL.md` : T32 selon la section 6 (sans le mot « fermé » pour le résidu adverse), note sur T31 ; `docs/STATUS.md` : (bp) partie `Makefile` et archtest faite, obligation harnais `MAKE` et `MAKE_COMMAND` ajoutée à celle du cas `test_hooks.sh`. Critère 11.
8. V1-8 (principal, hors critères) Proposition de harnais pour l'humain : cas `test_hooks.sh` avec un sous-make imbriqué et un `GNUmakefile` d'ombre, vérifiant que le hook Stop reste vert grâce à `-f Makefile` ; diff de `guard_bash.py` l. 52 ajoutant `MAKE` et `MAKE_COMMAND` ; cas de refus `MAKE=/tmp/x make verify-quick` et `env MAKE_COMMAND=/tmp/x make verify-quick` ; option `env -u` pour la commande du hook Stop.
