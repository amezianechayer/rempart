# M0-T04b `make-subcalls` : chaque sous-make porte `-f Makefile`

2026-09-30, `architect`, proposé. Sources : `Makefile`, `docs/STATUS.md` obligation (bp), `docs/02-THREAT-MODEL.md` T32, `docs/plans/M0-ci.md`, `internal/archtest/makefile_test.go`, `internal/archtest/compose_test.go`, `internal/archtest/ci_test.go` (`TestNoShadowMakefile`), propositions 0003, 0007, 0008.

## 1. Objectif et périmètre

GNU make ne transmet pas `-f` dans `MAKEFLAGS`. Les 4 sous-make du `Makefile` (lignes 31, 32, 35, 79) relisent donc le fichier par défaut du répertoire : un `GNUmakefile` ou un `makefile` à la racine remplacerait `opa-test`, `arch-test` et `dev`, même quand le parent est lancé par `make -f Makefile` (hook Stop, CI). `TestNoShadowMakefile` refuse déjà ces fichiers ; ce plan ajoute la seconde ligne de défense, portée par la forme des appels.

Dans le périmètre :
- forme canonique unique d'un sous-make : `$(MAKE) -f Makefile --no-print-directory <cible>`, seule sur sa ligne de recette, préfixe `@` seul admis, suffixe ` >&2` seul admis ;
- règle archtest `checkSubMakeCalls` sur `mf.Lines` (tout le fichier) et test `TestMakefileSubMakeCalls` ;
- mise à jour des tests qui figent la forme actuelle (section 4) ;
- réécriture des 4 lignes du `Makefile`.

Hors périmètre :
- cas `test_hooks.sh` avec sous-make imbriqué : les hooks sont protégés, il relève d'une proposition de harnais (reste à faire, section 7) ;
- options de l'agent sur sa propre ligne de commande (`make -C`, `-n`, `-t`, `-q` : obligation (bt)) ;
- `MAKEFILES` hérité de l'environnement du lanceur (hook Stop, CI) : hors du `Makefile`, section 6 ;
- préfixe `-`, `.IGNORE`, `MAKEFLAGS` hors sous-make (durcissement T31 avant M3) : la règle refuse seulement le préfixe `-` devant un sous-make, par effet de l'ancrage.

Aucune API, aucune dépendance, aucune boucle. Pas d'ADR : la décision est locale au `Makefile` et à ses tests, réversible par un commit, sans effet sur une interface ni sur un autre composant.

## 2. Décisions

- D1 **Liste blanche, pas liste noire.** Une ligne qui mentionne un appel à make est acceptée seulement si elle correspond exactement à la forme canonique. `-f` vers un autre fichier, `-f ./Makefile`, `-fMakefile`, `--file`, `--makefile`, `-C`, `--directory`, `-I`, `MAKEFILES=`, options ou variables supplémentaires, second appel sur la ligne : tous refusés par le même ancrage, sans règle dédiée.
- D2 **Détection large.** Une ligne mentionne un appel à make si elle contient le mot `MAKE` (couvre `$(MAKE)`, `${MAKE}`, `$(MAKE:...)`, `$(value MAKE)`, `MAKE :=`, `override MAKE`), le mot `make` ou `gmake` (couvre `make`, `/usr/bin/make`), ou le mot `MAKEFILES`. `MAKEFLAGS`, `MAKECMDGOALS` et `Makefile` ne sont pas des mots `MAKE` ou `make` : non détectés.
- D3 **Commentaires.** Seuls les commentaires de make sont ignorés : ligne logique qui ne commence pas par une tabulation et dont le texte, espaces retirés, commence par `#`. Une ligne de recette qui commence par `#` est du texte shell dans lequel make développe `$(MAKE)` : elle est vérifiée.
- D4 **Ligne de recette seulement.** Un appel hors ligne de recette (affectation, recette en ligne après `;`, directive `export`) est refusé : la forme canonique commence par une tabulation.
- D5 **Cible définie.** La cible nommée doit être une règle de `mf.Rules`.
- D6 **Constante partagée.** `subMakePrefix = "$(MAKE) -f Makefile --no-print-directory "` est la seule écriture de la forme dans les tests ; `verifyQuickSteps`, `verifyDevCallRe`, `checkDemoTarget` et les gabarits l'utilisent.

## 3. Interfaces (code de test, `internal/archtest/makefile_test.go`)

```go
// T32, obligation (bp): GNU make does not pass -f to sub-makes through MAKEFLAGS.
const subMakePrefix = "$(MAKE) -f Makefile --no-print-directory "

var (
	subMakeRefRe       = regexp.MustCompile(`\bMAKE\b|\bg?make\b|\bMAKEFILES\b`)
	canonicalSubMakeRe = regexp.MustCompile(`^\t@?\$\(MAKE\) -f Makefile --no-print-directory ([a-z][a-z0-9-]*)( >&2)?$`)
)

// checkSubMakeCalls reports every non-comment logical line of the Makefile that
// mentions make (D2) and is not exactly a canonical sub-make recipe line naming
// a defined target (D1, D3, D4, D5).
func checkSubMakeCalls(mf parsedMakefile) []string

// TestMakefileSubMakeCalls: subtests negative_controls/<name>,
// positive_controls/<name>, repository.
func TestMakefileSubMakeCalls(t *testing.T)
```

Message de refus, contenu stable pour les `want` : `Makefile line %d: sub-make must be exactly "$(MAKE) -f Makefile --no-print-directory <target>" on its own recipe line (T32): %q`. Cible absente : `Makefile line %d: sub-make target %q is not defined`.

`reachableTargets` reste inchangé : le jeton `Makefile` de la forme canonique n'est pas une règle.

## 4. Tests existants à faire évoluer (phase tests)

| Fichier, emplacement | Changement |
|---|---|
| `makefile_test.go` l. 216-217 `verifyQuickSteps` | regex exactes `^` + `regexp.QuoteMeta(subMakePrefix+"opa-test")` + `$` (idem `arch-test`) ; `desc` = forme canonique |
| `makefile_test.go` l. 443 | message listant les étapes : forme canonique |
| `makefile_test.go` l. 563-564 `targetMakefile` | deux lignes canoniques ; commentaire du gabarit : « section 6.1, amendé par M0-make-subcalls » |
| `makefile_test.go` l. 790, 824-825 | gabarits et `want` canoniques |
| `makefile_test.go` l. 1122-1123 `checkDemoTarget` | première ligne attendue `subMakePrefix + "dev >&2"` |
| `makefile_test.go` l. 1144 `devLine` | `"\t@" + subMakePrefix + "dev >&2\n"` |
| `compose_test.go` l. 990 `verifyDevCallRe` | `^` + `QuoteMeta(subMakePrefix+"dev")` + `$` |
| `compose_test.go` l. 1131 | message canonique |
| `compose_test.go` l. 1174, 1203 | `referenceVerifyRule` et `devCall` canoniques |

Nouveaux cas de contrôle dans les tests existants : `TestMakefileTargets/negative_controls/verify_quick_sub_make_without_file` (ligne 563 sans `-f Makefile` : `step ... missing or out of order`), `TestMakeDevUsesWait/negative_controls/verify_dev_without_file`, `TestMakefileDemoTarget/dev_without_file` (`first demo recipe line`).

## 5. Mutations que les tests doivent tuer

Chaque mutation est un cas nommé de `TestMakefileSubMakeCalls/negative_controls`, appliqué au gabarit `targetMakefile` (plus la règle `demo` de `TestMakefileDemoTarget` quand utile) ; le cas échoue si `checkSubMakeCalls` ne signale rien.

Mutations du `Makefile` :

| # | Nom du cas | Ligne mutée |
|---|---|---|
| M1 | `without_file` | `$(MAKE) --no-print-directory opa-test` (forme actuelle) |
| M2 | `file_after_option` | `$(MAKE) --no-print-directory -f Makefile dev` |
| M3 | `other_file` | `$(MAKE) -f GNUmakefile --no-print-directory arch-test` |
| M4 | `dot_slash_file` | `$(MAKE) -f ./Makefile --no-print-directory arch-test` |
| M5 | `glued_file` | `$(MAKE) -fMakefile --no-print-directory arch-test` |
| M6 | `second_file` | `$(MAKE) -f Makefile -f evil.mk --no-print-directory arch-test` |
| M7 | `long_file` | `$(MAKE) --file=Makefile --no-print-directory arch-test` |
| M8 | `long_makefile` | `$(MAKE) --makefile Makefile --no-print-directory arch-test` |
| M9 | `change_directory` | `$(MAKE) -f Makefile -C sub --no-print-directory arch-test` |
| M10 | `long_directory` | `$(MAKE) -f Makefile --directory=sub --no-print-directory arch-test` |
| M11 | `include_dir` | `$(MAKE) -f Makefile -I inc --no-print-directory arch-test` |
| M12 | `makefiles_env` | `MAKEFILES=evil.mk $(MAKE) -f Makefile --no-print-directory arch-test` |
| M13 | `makefiles_assignment` | ligne hors recette `export MAKEFILES := evil.mk` |
| M14 | `braces` | `${MAKE} -f Makefile --no-print-directory arch-test` |
| M15 | `literal_make` | `make -f Makefile --no-print-directory arch-test` |
| M16 | `gmake_path` | `/usr/bin/gmake -f Makefile --no-print-directory arch-test` |
| M17 | `ignore_errors_prefix` | `-$(MAKE) -f Makefile --no-print-directory arch-test` |
| M18 | `second_call` | canonique puis ` && $(MAKE) --no-print-directory dev` |
| M19 | `trailing_make` | canonique puis `; make dev` |
| M20 | `extra_variable` | canonique puis ` EVAL=x` |
| M21 | `indirect_variable` | `SUB := $(MAKE)` hors recette et `$(SUB) -f Makefile --no-print-directory dev` |
| M22 | `redefine_make` | `override MAKE := make -f GNUmakefile` |
| M23 | `inline_recipe` | `arch-test: ; $(MAKE) -f Makefile --no-print-directory opa-test` |
| M24 | `undefined_target` | `$(MAKE) -f Makefile --no-print-directory nope` |
| M25 | `hidden_in_continuation` | `$(MAKE) -f Makefile \` puis `--no-print-directory -f evil.mk dev` |
| M26 | `shell_comment_in_recipe` | ligne de recette `# $(MAKE) --no-print-directory dev` |

Contrôles positifs (`positive_controls`, aucun problème attendu) : P1 gabarit valide ; P2 commentaire make `# Le hook Stop exige make verify-quick` ; P3 `@` + canonique + ` >&2` ; P4 canonique coupée par `\` puis rejointe ; P5 `@echo "voir Makefile"` ; P6 `$(MAKEFLAGS)` dans un `echo` (non détecté, D2).

Mutations du vérificateur (appliquées par `acceptance-verifier` sur une copie de travail, chacune doit faire échouer `TestMakefileSubMakeCalls`) :

| # | Mutation de `checkSubMakeCalls` | Tuée par |
|---|---|---|
| C1 | ignore les lignes de recette | M1 |
| C2 | lit `mf.Rules[*].Recipe` au lieu de `mf.Lines` | M13, M21, M22 |
| C3 | ne saute plus les commentaires make | P2 et `repository` |
| C4 | saute aussi les lignes de recette commençant par `#` | M26 |
| C5 | ne vérifie pas que la cible est définie | M24 |
| C6 | regex canonique sans `$` final | M18, M19, M20 |
| C7 | regex canonique sans `^\t@?` (préfixe libre) | M12, M17 |
| C8 | détection sans `\bMAKE\b` (seulement `$(MAKE)`) | M14 (M22 contient aussi `make`, détecté par `\bg?make\b` ; constat de la campagne de mutation) |
| C9 | détection sans `\bg?make\b` | M15, M16 |
| C10 | détection sans `\bMAKEFILES\b` | M13 |
| C11 | `checkSubMakeCalls` renvoie toujours `nil` | tous les M |

## 6. Menaces (`docs/02-THREAT-MODEL.md`)

T32 : le résidu « sous-make sans `-f` » est fermé par `TestMakefileSubMakeCalls` ; la colonne test cite ce test. Restent en T32 : cas `test_hooks.sh` avec sous-make imbriqué (proposition harnais) ; `MAKEFILES` dans l'environnement du lanceur (le hook Stop et le workflow CI ne le posent pas, `guard_bash` le refuse sur la ligne de commande, D5 de M0-ci) ; `.RECIPEPREFIX` non analysé (aujourd'hui une recette à autre préfixe fait échouer `parseMakefile`, donc échec franc). Aucune menace nouvelle.

## 7. Critères d'acceptation

Tous lancés depuis `/home/user/rempart`.

1. `go test -count=1 -run 'TestMakefileSubMakeCalls' ./internal/archtest/` : `ok`.
2. `go test -count=1 -v -run 'TestMakefileSubMakeCalls/negative_controls' ./internal/archtest/ | grep -c -- '--- PASS: TestMakefileSubMakeCalls/negative_controls/'` : `26` ; même commande avec `positive_controls` : `6`.
3. `go test -count=1 -run 'TestMakefileTargets|TestMakeDevUsesWait|TestMakefileDemoTarget|TestNoShadowMakefile|TestCIRunsMakeVerify' ./internal/archtest/` : `ok`.
4. Forme du `Makefile` : `grep -cE '^[[:blank:]]@?\$\(MAKE\) -f Makefile --no-print-directory [a-z][a-z0-9-]*( >&2)?$' Makefile` affiche `4` ; `grep -nE '\bMAKE\b|\bg?make\b|\bMAKEFILES\b' Makefile | grep -vE '^[0-9]+:[[:blank:]]*#' | grep -cvE '^[0-9]+:[[:blank:]]@?\$\(MAKE\) -f Makefile --no-print-directory [a-z][a-z0-9-]*( >&2)?$'` affiche `0`.
5. Comportement, sans rien exécuter (`-n` n'exécute que les lignes `$(MAKE)`) :
   `d=$(mktemp -d) && cp Makefile "$d/" && printf 'opa-test arch-test dev:\n\t@echo SHADOW\n' > "$d/GNUmakefile" && (cd "$d" && make -f Makefile -n verify-quick verify demo 2>&1) | grep -c SHADOW; rm -rf "$d"`
   affiche `0` (avant la correction : `4`).
6. Phase tests : sur le `Makefile` actuel, `go test -count=1 -run 'TestMakefileSubMakeCalls/repository|TestMakefileTargets/repository|TestMakefileDemoTarget/repository' ./internal/archtest/` échoue, et `TestMakefileSubMakeCalls/repository` signale les lignes 31, 32, 35 et 79.
7. `make -f Makefile verify-quick` : code 0.
8. Harnais intact : `git diff --name-only HEAD~ -- CLAUDE.md .claude/settings.json .claude/hooks .claude/bin .claude/agents .claude/commands` n'affiche rien (sur chaque commit de la tâche).
9. Mutations C1 à C11 : pour chacune, sur une copie de travail, `go test -count=1 -run TestMakefileSubMakeCalls ./internal/archtest/` échoue ; `git status --porcelain internal/archtest` vide après restauration.

## 8. Risques

- Faux positif : un `echo` contenant le mot `make` en recette est refusé (D2). Accepté : reformuler le message.
- Divergence gabarit et plan d'origine : `targetMakefile` n'est plus verbatim de M0-squelette 6.1 ; le commentaire le dit.
- Un seul sous-make restant sans `-f` suffit à rouvrir T32 : la règle porte sur toutes les lignes, pas sur une liste de cibles.

## 9. Tâches ordonnées

1. (tests, `test-author`) `subMakePrefix`, `subMakeRefRe`, `canonicalSubMakeRe`, `checkSubMakeCalls`, `TestMakefileSubMakeCalls` avec M1 à M26, P1 à P6 et `repository`.
2. (tests, `test-author`) Évolutions de la section 4 et les trois nouveaux cas de contrôle ; critère 6 constaté (échecs sur le `Makefile` actuel seulement dans les sous-tests `repository`), puis `phase impl`.
3. (impl) Réécrire les lignes 31, 32, 35 et 79 du `Makefile` en forme canonique ; critères 1 à 5 et 7.
4. (`security-reviewer`) Verdict PASS ou BLOCK ; (`acceptance-verifier`) critères 1 à 9 avec preuves.
5. (principal) `docs/02-THREAT-MODEL.md` T32 (section 6) ; `docs/STATUS.md` : (bp) partie `Makefile` et archtest faite, partie `test_hooks.sh` en attente.
6. (principal, reste à faire hors critères) Proposition de harnais : cas `test_hooks.sh` avec un sous-make imbriqué et un `GNUmakefile` d'ombre, vérifiant que le hook Stop reste vert grâce à `-f Makefile` sur le parent et les sous-make.
