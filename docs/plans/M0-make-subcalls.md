# M0-T04b `make-subcalls` : chaque sous-make porte `-f Makefile`

2026-09-30, `architect`, proposé ; amendement V1 le même jour après le BLOCK de `security-reviewer` ; amendement V2 après le second BLOCK (commit `74bd92a`). Sources : `Makefile`, `docs/STATUS.md` obligation (bp), `docs/02-THREAT-MODEL.md` T31 et T32, `docs/plans/M0-ci.md`, `internal/archtest/makefile_test.go`, `internal/archtest/compose_test.go`, `internal/archtest/ci_test.go` (`TestNoShadowMakefile`), `internal/archtest/devharden_test.go` (`runInEnv`), `.claude/hooks/guard_bash.py` (ligne 52), `.github/CODEOWNERS`, propositions 0003, 0007, 0008.

## Amendement V2 (après le second BLOCK de la revue sécurité)

### Constats du second BLOCK

| # | Gravité | Constat | Cause dans la V1 | Réponse V2 |
|---|---|---|---|---|
| N1 | critique | Commentaire en colonne 0 finissant par `\\`, puis `include evil.mk` | `joinMakeLines` (`makefile_test.go` l. 111) joint toute ligne finissant par `\` (`strings.HasSuffix`) ; GNU make ne joint que si le nombre de `\` finaux est impair. Le parseur avale la ligne suivante dans le commentaire, make la lit | D11 (E10) |
| N1b | critique | Idem avec un commentaire indenté et `-include evil.mk` | Même cause | D11 (E10) |
| N1c | critique | Commentaire `...\\`, puis `verify-quick:` et `\t@echo SHADOW-dup` : make remplace la recette de `verify-quick` (exécution réelle), tests verts | Même cause ; la ligne tabulée est rattachée par le parseur à la règle précédente | D11 (E10) ; oracle D15 (avertissement « overriding recipe ») |
| N3 | critique | Ligne de recette finissant par `\\`, puis `include evil.mk` en colonne 0 | Même cause, en recette | D11 (E10) |
| 5 | basse | `strings.TrimSpace` (l. 132 et `checkSubMakeCalls` l. 264) retire NBSP, NEL, U+2028, que make ne tient pas pour des blancs | Rognage Unicode dans un lexeur d'octets ASCII | D13 (E9, E12, E13) et D14 |

Le rapport de revue ne transmet pas de cas N2 distinct : la numérotation du relecteur est conservée telle quelle.

### Changement d'approche (même classe d'échec deux fois)

Les deux BLOCK relèvent de la même classe : **le lexeur des tests diverge de celui de GNU make**, et toute divergence ouvre une ligne que make lit et que les tests ne voient pas (V1 : `# :` classé comme règle ; V2 : parité des `\`). Deux corrections ponctuelles successives n'ont pas fermé la classe. Conformément au protocole (même échec deux fois), l'approche change et le principal le consigne dans `docs/STATUS.md` (tâche V2-7) :

- **Avant (V0, V1)** : le lexeur cherche à imiter make au plus près.
- **Après (V2)** : le lexeur admet un sous-ensemble où son découpage et celui de make coïncident par construction, et **rejette toute forme ambiguë** (continuation hors recette, nombre pair de `\`, octets de contrôle, blancs Unicode, caractères invisibles). Aucune forme rejetée n'est utilisée par le `Makefile` actuel (vérifié ci-dessous).
- **En plus (D15)** : un oracle différentiel confronte le résultat du parseur à la base de données de make (`make -p`) sur le `Makefile` du dépôt, pour détecter une troisième divergence que personne n'a encore imaginée.

Principe ajouté à T32 : **lexeur des tests identique à make ou rejet des formes ambiguës.**

### Décisions V2

- D11 **Parité des `\`.** Une ligne physique ne se prolonge que si elle appartient à une ligne de recette et finit par un nombre impair de `\` (1, 3, 5...). Une ligne physique finissant par un nombre pair non nul de `\` est une erreur partout (commentaire, recette, autre) : E10. Une continuation encore ouverte à la fin du fichier (dernière ligne sans saut de ligne final, finissant par un nombre impair de `\`) est une erreur : E14.
- D12 **Pas de continuation hors recette.** Toute ligne physique qui commence une ligne logique hors recette (commentaire compris, en colonne 0 ou indenté, affectation, règle, `.PHONY`) et finit par `\` est une erreur : E11. La grammaire fermée D8 n'en a pas besoin. Seules les lignes de recette (première ligne physique commençant par une tabulation) et leurs lignes physiques de continuation peuvent se prolonger.
- D13 **Octets.** (i) CR (`0x0d`), NUL et tout octet de contrôle autre que la tabulation (`0x00` à `0x08`, `0x0b` à `0x1f`, `0x7f`) sont une erreur partout : E9. Le CR n'est plus retiré (fin de `strings.TrimSuffix(raw, "\r")`). (ii) Tout octet non ASCII est une erreur hors commentaire en colonne 0 (ligne physique dont le premier octet est `#`) et hors ligne de recette (toutes ses lignes physiques) : E12. (iii) Conséquence de (i) et (ii) : un blanc de tête hors recette ne peut être qu'espace ou tabulation. (iv) Ajustement de l'architecte, restrictif : dans un commentaire en colonne 0 et dans une ligne de recette, le texte doit être de l'UTF-8 valide et tout caractère non ASCII doit relever des catégories Unicode L, M, N, P ou S, hors U+FFFD ; sont donc refusés les espaces Unicode (Zs, dont NBSP et U+202F), les séparateurs U+2028 et U+2029, les contrôles C1 (dont NEL), les caractères de format (Cf : U+200B à U+200F, U+202A à U+202E, U+2066 à U+2069, U+FEFF) : E13. Motif : le déguisement shell ne repose que sur la revue humaine du diff (section 6) ; un caractère invisible ou bidirectionnel en recette la trompe (classe « Trojan Source »), et (iv) rend `strings.Fields` (utilisé sur le texte des recettes) équivalent à un découpage sur blancs ASCII. Le texte français (lettres accentuées, `«`, `»`, `’`) reste admis.
- D14 **Rognage ASCII.** `strings.TrimSpace` est remplacé par `makeTrim` (`strings.Trim(s, " \t")`) dans le parseur (`parseLine`, `addRecipe`) et partout où une ligne de `mf.Lines` est classée comme commentaire : `checkSubMakeCalls`, `makefile_test.go` l. 413 et 1167, `compose_test.go` l. 1017 et 1094, par le prédicat unique `isMakeComment`. Une fois D13 appliquée, `TrimSpace` et `makeTrim` coïncident sur toute entrée acceptée par `parseMakefile` : D14 est une défense en profondeur, prouvée par des tests directs des deux fonctions (section 5.5), et non par `TestMakefileGrammar`.
- D15 **Oracle différentiel.** Le test `TestMakefileOracle` lance GNU Make 4.x sur le `Makefile` (sans exécuter de recette, sans réseau) et compare sa base de données à ce que le parseur a lu : liste des makefiles lus, variables définies et lignes, cibles explicites, prérequis et ligne de recette, règles implicites, sortie d'erreur. Spécification en section 3, justification et résidus en section 6.

Vérification sur le `Makefile` actuel (115 lignes, lu ligne à ligne) : aucun octet de contrôle ; aucune ligne finissant par un nombre pair de `\` ; aucune ligne ne commençant pas par une tabulation et finissant par `\` (les continuations sont toutes dans des recettes : lignes 43 à 50, 80 et 81, 90 et 91, toutes à un seul `\`) ; les octets non ASCII sont tous des lettres accentuées (é, è, ê, à, î, É) situées sur des commentaires en colonne 0 (lignes 1 à 3, 13, 40, 57, 63, 69, 76, 77, 84, 88, 94, 95, 104, 105) ou des lignes de recette (44, 46, 91, 97, 98, 113). Aucune ligne légitime n'est touchée ; le `Makefile` n'est pas modifié.

### Changements, par section

- Section 1 : périmètre complété (lexeur D11 à D14, oracle D15).
- Section 3 : `lexMakefile` remplace `joinMakeLines` ; `makeTrim`, `isMakeComment`, `trailingBackslashes`, `allowedMakeRune` ; champs `Vars` et `RecipeLine` ; messages E9 à E14 (lexeur, numéro de la ligne physique en cause) ; oracle (types, commande, messages O1 à O6).
- Section 4 : fixtures G30 et G31 passées en ASCII ; cinq sites de classement des commentaires passent par `isMakeComment`.
- Section 5 : cas N1, N1b, N1c, N3, N4 à N14 dans `TestMakefileGrammar` ; contrôles positifs GP5 et GP6 ; `TestMakeLexerHelpers` (H1 à H3) ; `TestMakefileOracle` (OC1 à OC6, OP1, OP2, `repository`) ; mutations L1 à L11 et R1 à R8.
- Section 6 : principe T32 ajouté ; affirmation fausse de la V1 retirée (section 8 : « les continuations sont jointes comme make, y compris pour les commentaires ») ; résidus de l'oracle.
- Section 7 : comptes du critère 2, formes D11 à D13 par `grep`, rejeu des quatre attaques N, rouge d'abord V2, mutations L et R, documentation.
- Sections 8 et 9 : risques et tâches V2.

### Ce qui ne change pas

- Le `Makefile` (voir la vérification ci-dessus). Aucune modification de code de production.
- Phase : tout le travail V2 est du code de test (`internal/archtest/*_test.go`), en phase **tests**, sans passage en impl. La preuve que les nouveaux cas ne sont pas vides est le critère 7 (rouge avant le nouveau lexeur et avant l'oracle) et les mutations L et R (critère 10).
- Pas d'ADR. Le lexeur et l'oracle sont du code de test sous CODEOWNERS (`/internal/archtest/`), réversibles par un commit. La dépendance de `go test ./internal/archtest/` à GNU Make 4.x n'est pas nouvelle en pratique (le `Makefile` exige déjà GNU make, le hook Stop et la CI le lancent) ; elle est rendue explicite (échec franc, jamais de saut) et consignée en section 8.

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
- (V2) lexeur qui rejette les formes ambiguës (D11 à D14) et oracle différentiel contre `make -p` (D15, `TestMakefileOracle`) ;
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
- D3 **Commentaires.** Seuls les commentaires de make sont ignorés : ligne logique qui ne commence pas par une tabulation et dont le texte, espaces et tabulations retirés (V2, D14 : `makeTrim`, jamais `strings.TrimSpace`), commence par `#`. Une ligne de recette qui commence par `#` est du texte shell dans lequel make développe les `$` : elle est vérifiée (D2 et D7).
- D4 **Ligne de recette seulement.** Un appel hors ligne de recette est refusé. V1 : les affectations, recettes en ligne et directives concernées sont désormais refusées plus tôt par D8.
- D5 **Cible définie.** La cible nommée doit être une règle de `mf.Rules`.
- D6 **Constante partagée.** `subMakePrefix = "$(MAKE) -f Makefile --no-print-directory "` est la seule écriture de la forme dans les tests.

Décisions V1 :

- D7 **Recettes sans expansion make hors préfixe canonique.** Pour chaque ligne logique de recette (commençant par une tabulation, y compris celles dont le texte shell commence par `#`), on supprime les paires `$$` de gauche à droite (`strings.ReplaceAll(text, "$$", "")`, qui laisse le troisième `$` de `$$$`) ; s'il reste un `$`, la ligne doit correspondre à `canonicalSubMakeRe`, sinon c'est un problème. Ferme `$(eval ...)`, `$(call ...)`, `$(shell ...)`, `$(MAKE_COMMAND)`, les noms calculés (`$(MA$(X)KE)`), les variables de make (`$(MAKEFLAGS)`, `$(SUB)`) et les variables automatiques (`$@`, `$<`) en recette. Porté par `checkSubMakeCalls` (problème, pas erreur de parseur) : les contrôles négatifs de `checkMakefile` (`scenario_interpolated` et suivants) et de `checkDemoTarget` (`tenant_variable`, `namespace_braces`) injectent volontairement `$(...)` en recette et doivent rester atteignables. L'échec reste franc : `TestMakefileSubMakeCalls/repository` fait partie de `verify-quick`.
- D8 **Grammaire fermée hors recette, dans `parseMakefile`.** Toute ligne logique non vide, qui n'est ni un commentaire make (D3) ni une ligne de recette, doit relever d'une des formes ci-dessous ; sinon `parseMakefile` renvoie une erreur (tous les tests qui lisent le `Makefile` échouent). Ordre d'examen, texte rogné aux extrémités (V2 : espaces et tabulations seulement, D14) :
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

Décisions V2 : D11 à D15, énoncées dans l'amendement V2 en tête du document.

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
// D3, D5, D9). At most one problem per line. Comments are recognized by
// isMakeComment only (V2, D14).
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

// parseMakefile lexes src with lexMakefile (D11 to D14), then parses the
// closed grammar of docs/plans/M0-make-subcalls.md D8.
func parseMakefile(src string) (parsedMakefile, error)

// TestMakefileGrammar (M0-T04b V1, T32): parseMakefile refuses every line
// outside D8 and, V2, every ambiguous form of D11 to D13. Subtests
// negative_controls/<name>, positive_controls/<name>, repository.
func TestMakefileGrammar(t *testing.T)
```

V2, lexeur et prédicats (`joinMakeLines` disparaît, remplacé par `lexMakefile`) :

```go
type makeRule struct {
	Prereqs    []string
	Recipe     []string // logical lines, continuations joined, @ - + prefixes removed
	Line       int      // line of the rule naming the target (a single one, D8)
	RecipeLine int      // V2: first physical line of the first recipe line (empty ones included), 0 if none
}

type parsedMakefile struct {
	Rules map[string]makeRule
	Phony map[string]bool
	Lines []makeLine
	Vars  map[string]int // V2: variable name -> line of its last assignment (D8 step 3), for the oracle
}

// lexMakefile splits src into logical lines (M0-T04b V2, D11 to D13). A
// physical line joins the next one only if it belongs to a recipe line and
// ends with an odd number of backslashes; every form on which this lexer and
// GNU make could disagree is an error naming the physical line at fault.
// Checks, in this order, for each physical line: E9 (control byte), E10 (even
// number of trailing backslashes), E11 (a line starting a non-recipe logical
// line ends with a backslash), E12 or E13 (non-ASCII text); then E14 if a
// continuation is still open at the end of src. A logical line is a recipe
// line if its first physical line starts with a tab, a column-0 comment if its
// first physical line starts with "#". Joining keeps the V1 text: the final
// backslash and the spaces before it removed, one space, the next physical
// line with leading spaces and tabs removed.
func lexMakefile(src string) ([]makeLine, error)

// trailingBackslashes counts the backslashes ending s.
func trailingBackslashes(s string) int

// makeTrim removes leading and trailing spaces and tabs only (D14): GNU make
// does not treat NBSP, NEL or U+2028 as blanks.
func makeTrim(s string) string // strings.Trim(s, " \t")

// isMakeComment reports whether l is a make comment (D3): its text does not
// start with a tab and, makeTrim applied, starts with "#".
func isMakeComment(l makeLine) bool

// allowedMakeRune reports whether a non-ASCII rune may appear in a column-0
// comment or a recipe line (D13 (iv)): categories L, M, N, P, S, U+FFFD excluded.
func allowedMakeRune(r rune) bool
```

`parseLine` utilise `makeTrim` au lieu de `strings.TrimSpace`, et enregistre `p.mf.Vars[name] = ln.Num` pour chaque affectation acceptée et `RecipeLine` à la première ligne tabulée d'une règle (même vide). `addRecipe` utilise `makeTrim`. Les sites `makefile_test.go` l. 264 (`checkSubMakeCalls`), 413 et 1167, `compose_test.go` l. 1017 et 1094 classent les commentaires par `isMakeComment` ; aucun appel à `strings.TrimSpace` ne subsiste sur une ligne de `mf.Lines` (critère 4).

Messages d'erreur de `parseMakefile`, fragments stables pour les `wantErr`. E1 à E8 : toujours précédés de `line %d: `, numéro de la première ligne physique de la ligne logique. E9 à E14 (V2, lexeur) : précédés de `line %d: `, numéro de **la ligne physique en cause** (celle qui porte l'octet, les `\` ou la continuation ouverte), y compris quand c'est une ligne de continuation d'une recette.

| Code | Message | Origine |
|---|---|---|
| E1 | `comment after make syntax not allowed (D8): %q` | D8 étape 1 |
| E2 | `unsupported directive %q: update the test parser before using it` (V0) | D8 étape 2 |
| E3 | `variable %q not allowed in the Makefile (D8)` | D8 étape 3, nom hors ensemble |
| E4 | `form not allowed for variable %s (D8): %q` | D8 étape 3, nom dans l'ensemble |
| E5 | `export not allowed (D8): %q` | D8 étape 4 |
| E6 | `line outside the Makefile grammar of the tests (D8): %q` | D8 étape 7 (et 5, 6 non conformes) |
| E7 | `target %q already named by the rule of line %d (D8)` | D8 étape 6 |
| E8 | `recipe line outside a rule` (V0) | recette sans règle, ou après `.PHONY` |
| E9 | `control byte 0x%02x not allowed (D13): %q` | D13 (i), octet `0x00` à `0x08`, `0x0b` à `0x1f`, `0x7f` ; premier octet fautif de la ligne |
| E10 | `line ends with an even number of backslashes (D11): %q` | D11 |
| E11 | `continuation outside a recipe line not allowed (D12): %q` | D12 |
| E12 | `non-ASCII byte outside a column-0 comment or a recipe line (D13): %q` | D13 (ii) |
| E13 | `character %U not allowed in a comment or recipe line (D13): %q` | D13 (iv) ; UTF-8 invalide rapporté comme `U+FFFD` |
| E14 | `continuation at end of file (D11)` | D11 |

Le commentaire de `parseMakefile` (règles 1 à 8 citant M0-squelette 8.4) est réécrit pour citer D8 ; la vérification « second recipe for target » devient inatteignable (une seconde recette exige une seconde ligne de règle, refusée par E7) et est supprimée. `reachableTargets` reste inchangé. V2 : le commentaire de grammaire en tête (règle 1 « lines ending with a backslash are joined ») est réécrit pour citer D11 à D14.

Dans les tests, un `wantErr` est construit par `fmt.Sprintf("line %d: ", physicalLine(t, src, fragment)) + code`, pour vérifier que l'erreur porte sur la ligne mutée.

V2, oracle différentiel (D15), fichier `internal/archtest/makeoracle_test.go` :

```go
// makeOracleGoal: the only goal given to make; defined by --eval, with neither
// prerequisite nor recipe, so no recipe runs.
const makeOracleGoal = "__rempart_oracle__"

// makeDatabase is what GNU Make 4.x reports with -p after reading one makefile.
type makeDatabase struct {
	Code          int
	Stderr        string
	MakefileList  []string                // fields of MAKEFILE_LIST
	Vars          map[string][]int        // every "(from 'Makefile', line N)" variable header, any section
	Targets       map[string]makeDBTarget // "# Files" section, "# Not a target:" entries excluded
	ImplicitRules int                     // "# N implicit rules"
}

type makeDBTarget struct {
	Prereqs    []string // sorted
	RecipeLine int      // "recipe to execute (from 'Makefile', line N)", 0 if none
}

// runMakeDatabase runs, in dir, through runInEnv (minimal environment: no
// MAKEFLAGS, MAKELEVEL, MAKEFILES, MAKE, MAKE_COMMAND, GNUMAKEFLAGS; LC_ALL=C;
// timeout 30 s):
//   make -n -r -p -f Makefile --eval=__rempart_oracle__: __rempart_oracle__
// It first checks that "make --version" starts with "GNU Make 4.": otherwise
// t.Fatal, never t.Skip.
func runMakeDatabase(t *testing.T, dir string) makeDatabase

// parseMakeDatabase reads the standard output of make -p. A missing
// "# Variables", "# Files" or "# N implicit rules" section, or a Makefile
// variable header not followed by "NAME = ..." or "NAME := ...", is an error
// (format drift fails the test, it never passes it).
func parseMakeDatabase(out string) (makeDatabase, error)

// compareMakeDatabase compares what parseMakefile read (mf) with what make
// read (db); base is the database of an empty Makefile read the same way,
// whose targets and implicit rules are subtracted (built-ins, oracle goal).
// Problems in the order O1 (then stop), O2, O3, O4 by name, O5 by name, O6.
func compareMakeDatabase(mf parsedMakefile, db, base makeDatabase) []string

// TestMakefileOracle (M0-T04b V2, D15, T32): subtests
// negative_controls/<name>, positive_controls/<name>, repository.
func TestMakefileOracle(t *testing.T)
```

Règles de comparaison :
- `MAKEFILE_LIST` : exactement `["Makefile"]` ;
- variables : pour chaque nom de `db.Vars`, les lignes valent exactement `[mf.Vars[nom]]` ; tout nom de `mf.Vars` est dans `db.Vars` ;
- cibles : `db.Targets` privé des entrées identiques (nom, prérequis, ligne de recette) de `base.Targets` doit être égal à l'ensemble attendu : une entrée par règle de `mf.Rules` (prérequis triés, `RecipeLine`) plus `.PHONY` (prérequis = noms de `mf.Phony` triés, ligne 0) ;
- `db.ImplicitRules - base.ImplicitRules` vaut 0 ;
- `db.Code` vaut 0 et `db.Stderr` est vide.

Messages de l'oracle, fragments stables :

| Code | Message |
|---|---|
| O1 | `make exited with code %d (oracle): %q` (stderr) |
| O2 | `make wrote on stderr (oracle): %q` |
| O3 | `MAKEFILE_LIST is %q, want [Makefile] (oracle)` |
| O4 | `variable %s: make defines it at lines %v, the test parser at %v (oracle)` |
| O5 | `target %s: make read %s, the test parser %s (oracle)` |
| O6 | `%d implicit rules defined by the Makefile, want 0 (oracle)` |

L'oracle ne lance make qu'après un `parseMakefile` sans erreur (sinon `t.Fatal` avec l'erreur du parseur) ; il n'est jamais lancé sur les fixtures négatives de `TestMakefileGrammar`. Les fixtures de l'oracle sont écrites dans `t.TempDir()` sous le nom `Makefile` ; le sous-test `repository` lance make dans la racine du dépôt (`repoRoot`).

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

V2 :

| Fichier, cas | Aujourd'hui | V2 |
|---|---|---|
| `TestMakefileGrammar` G30 `rule_trailing_comment` | `dev-down: # arrêt` (non ASCII sur une ligne de règle : D13 le refuserait par E12 avant E1) | `dev-down: # stop`, `wantErr` E1 inchangé |
| `TestMakefileGrammar` G31 `assign_trailing_comment` | `EVAL ?= all # défaut` (même raison) | `EVAL ?= all # default`, `wantErr` E1 inchangé |
| `makefile_test.go` l. 264, 413, 1167 ; `compose_test.go` l. 1017, 1094 | `strings.HasPrefix(strings.TrimSpace(...), "#")` | `isMakeComment(l)` ; refactorisation à comportement V1 constant en V2-1 (`makeTrim` = `strings.TrimSpace` provisoirement), puis D14 en V2-2 |

Vérifié : les autres fixtures de `makefile_test.go` et `compose_test.go` ne portent d'octet non ASCII que sur des commentaires en colonne 0 ou des lignes de recette, aucune ne contient de CR ni de commentaire finissant par `\`. Si `referenceDevMakefile(t)` ou une fixture de `TestMakefileTargets` était refusée par le lexeur V2, le constat est consigné et la fixture passe en ASCII (code de test), jamais le lexeur élargi.

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

Total : 34 cas négatifs (inchangé en V2).

Contrôles positifs (`positive_controls`, aucun problème attendu) : P1 `valid_template` ; P2 `make_comment` (`# Le hook Stop exige make verify-quick` et `  # ... $(MAKE) -C ailleurs`) ; P3 `silenced_to_stderr` ; P4 `canonical_continuation` ; P5 `echo_makefile_word` ; P6 `shell_dollar` : ligne ajoutée à `dev` `@echo "$$HOME $${USER:-x} $$(id -u)"`. Total : 6 (inchangé en V2).

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
| G30 | `rule_trailing_comment` | règle `dev-down:` devient `dev-down: # stop` (V2 : ASCII, section 4) | E1 |
| G31 | `assign_trailing_comment` | `EVAL ?= all` devient `EVAL ?= all # default` (V2 : ASCII, section 4) | E1 |
| G32 | `duplicate_rule_line` | fin : `arch-test: opa-test` (sans recette) | E7 |
| G33 | `phony_with_recipe` | après la seconde ligne `.PHONY` : `\t@echo x` | E8 |
| G34 | `gowork_changed` | `export GOWORK := off` devient `export GOWORK := /tmp/go.work` | E4 |
| G35 | `goflags_changed` | `override GOFLAGS := -mod=readonly` devient `override GOFLAGS := -mod=mod` | E4 |
| G36 | `default_goal_changed` | `.DEFAULT_GOAL := verify-quick` devient `.DEFAULT_GOAL := demo` | E4 |

Cas V2, même table de test (`TestMakefileGrammar/negative_controls`). Notation des mutations en chaîne Go (`\t`, `\\` pour un `\`, `\r`, `\x00`, `\u00a0`). « Ligne en cause » : la ligne physique dont le numéro doit figurer dans `wantErr`, obtenue par `physicalLine` ou `exactLine` sur le fragment indiqué.

| # | Nom du cas | Mutation | Erreur | Ligne en cause |
|---|---|---|---|---|
| N1 | `comment_even_backslash_include` | fin : `"# fin \\\\\n"` puis `"include evil.mk\n"` (second BLOCK) | E10 | le commentaire `# fin \\` |
| N1b | `indented_comment_even_backslash` | après OPA : `"  # x \\\\\n"` puis `"-include evil.mk\n"` (second BLOCK) | E10 | le commentaire indenté |
| N1c | `comment_even_backslash_shadow_rule` | fin : `"# fin \\\\\n"`, `"verify-quick:\n"`, `"\t@echo SHADOW-dup\n"` (second BLOCK) | E10 | le commentaire `# fin \\` |
| N3 | `recipe_even_backslash_include` | recette de `dev` complétée (via `editRule`) par `"\t@echo ok \\\\"` puis, en colonne 0, `"include evil.mk"` (second BLOCK) | E10 | la ligne `\t@echo ok \\` |
| N4 | `crlf_line` | `"SHELL := /bin/bash\n"` devient `"SHELL := /bin/bash\r\n"` | E9, `0x0d` | la ligne `SHELL` |
| N5 | `nul_byte` | après OPA : `"# a\x00b\n"` (commentaire en colonne 0 : « partout ») | E9, `0x00` | le commentaire |
| N6 | `nbsp_before_comment` | après OPA : `"\u00a0# include evil.mk\n"` | E12 | la ligne ajoutée |
| N7 | `control_char` | dans la recette de `opa-test`, la ligne physique de continuation `étape OPA sans objet.` devient `étape OPA\x1b[8m sans objet.` (échappement ANSI qui masque le texte au terminal) | E9, `0x1b` | la ligne de continuation, pas la première ligne de la recette |
| N8 | `even_backslash_recipe` | recette de `dev` complétée par `"\t@echo a \\\\\\\\"` (quatre `\`) puis `"\t@true"` | E10 | la ligne `\t@echo a \\\\` |
| N9 | `comment_continuation` | fin : `"# fin \\\n"` (un `\`) puis `"include evil.mk\n"` | E11 | le commentaire |
| N10 | `assign_continuation` | `"EVAL ?= all\n"` devient `"EVAL ?= \\\nall\n"` | E11 | la ligne `EVAL ?= \` |
| N11 | `bidi_in_recipe` | recette de `dev` complétée par `"\t@echo \"a\u202eb\""` | E13, `U+202E` | la ligne ajoutée |
| N12 | `invalid_utf8_comment` | après OPA : `"# a\xffb\n"` | E13, `U+FFFD` | le commentaire |
| N13 | `nonascii_indented_comment` | après OPA : `"  # arrêt\n"` (commentaire indenté, pas en colonne 0) | E12 | la ligne ajoutée |
| N14 | `continuation_at_eof` | fin, sans saut de ligne final : `"\t@echo x \\"` | E14 | la ligne ajoutée (dernière) |

Total : 36 cas V1 + 15 cas V2 = 51 cas négatifs. G34 à G36 (V1.1) : ajoutés après la campagne de mutations de V1-3, où la mutation K7b (valeurs figées de `GOWORK`, `GOFLAGS`, `.DEFAULT_GOAL` remplacées par « valeur sans `$` ») survivait.

Contrôles positifs (`positive_controls`, `parseMakefile` sans erreur) : GP1 `valid_template` ; GP2 `go_env_lines` (après `export SCENARIO ...` : `export GOWORK := off`, `override GOFLAGS := -mod=readonly`, `export GOFLAGS`) ; GP3 `comments_with_syntax` (`# $(eval include evil.mk) # :` et `  # include evil.mk`) ; GP4 `reference_dev_makefile` (`referenceDevMakefile(t)`) ; V2 : GP5 `french_text` (après OPA : `"# Étape « démo » d’essai, arrêt : à revoir\n"` ; recette de `dev-down` complétée par `"\t@echo \"arrêt : terminé, « rien » à faire\""`) ; GP6 `odd_backslash_recipe` (recette de `dev` complétée par `"\t@echo a \\\\\\"` (trois `\`) puis `"\t\tb"` : continuation impaire à plus d'un `\`, admise). Total : 6. Sous-test `repository` : `parseMakefile` du `Makefile` sans erreur.

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

V2, lexeur et prédicats (tuées dans `TestMakefileGrammar` ou `TestMakeLexerHelpers`) :

| # | Mutation | Tuée par |
|---|---|---|
| L1 | remettre `strings.HasSuffix(text, "\\")` comme condition de continuation (parité et E10 supprimées) | N1, N1b, N1c (E11 au lieu de E10), N3, N8 (aucune erreur) |
| L2 | remettre `strings.TrimSpace` dans `makeTrim` (donc dans `parseLine`, `addRecipe`, `isMakeComment`, `checkSubMakeCalls`) | H1, H2, H3. Mutation équivalente pour `parseMakefile` tant que D13 tient (aucune entrée acceptée ne porte de blanc Unicode) : c'est pourquoi D14 est prouvée par des tests directs |
| L3 | retirer le contrôle des octets (E9, E12, E13) | N4 (E4 au lieu de E9), N5, N7, N11, N12, N13 (aucune erreur), N6 (E1 au lieu de E12) |
| L4 | retirer D12 (E11) | N9 et N10 (aucune erreur : jointure, commentaire ou affectation acceptés) |
| L5 | continuation seulement pour exactement un `\` (3 traité comme pair ou sans jointure) | GP6 |
| L6 | E13 réduit à la validité UTF-8 (catégories non contrôlées) | N11 |
| L7 | validité UTF-8 non contrôlée ou U+FFFD admis | N12 |
| L8 | non ASCII admis dans tout commentaire, indenté compris | N13 |
| L9 | continuation ouverte en fin de fichier ignorée (E14 supprimée) | N14 |
| L10 | contrôles E9 à E13 appliqués à la seule première ligne physique d'une ligne logique | N7 |
| L11 | erreurs E9 à E14 numérotées à la première ligne physique de la ligne logique | N7 (numéro de ligne) |

V2, oracle (tuées dans `TestMakefileOracle`) :

| # | Mutation | Tuée par |
|---|---|---|
| R1 | code de sortie de make ignoré | OC6 (O1 attendu seul) |
| R2 | stderr de make ignoré | OC2 (O2 attendu) |
| R3 | `MAKEFILE_LIST` non comparé | OC1 |
| R4 | variables non comparées | OC3 |
| R5 | cibles non comparées | OC4, OC2 |
| R6 | règles implicites non comparées | OC5 |
| R7 | base vide non soustraite | OP1, OP2, `repository` (la cible `__rempart_oracle__` et les entrées intégrées apparaissent en trop) |
| R8 | `t.Skip` si make est absent ou n'est pas GNU Make 4.x | critère 4 (`grep`), non tuable par un test dans un environnement où make est présent |

### 5.4 `TestMakefileGrammar` : contrôle des comptes

Voir critère 2 : 51 négatifs, 6 positifs.

### 5.5 `TestMakeLexerHelpers` (D14, tests directs)

Sous-tests, sans passer par `parseMakefile` :

| # | Nom | Vérification |
|---|---|---|
| H1 | `trim_ascii_blanks_only` | `makeTrim(" \t\u00a0x\u0085\t ")` vaut `"\u00a0x\u0085"` ; `makeTrim(" \tx\t ")` vaut `"x"` |
| H2 | `comment_after_unicode_blank` | `isMakeComment(makeLine{Num: 1, Text: "\u00a0# x"})` faux ; `isMakeComment(makeLine{Num: 1, Text: "  \t# x"})` vrai ; `isMakeComment(makeLine{Num: 1, Text: "\t# x"})` faux |
| H3 | `submake_after_unicode_blank` | `checkSubMakeCalls(parsedMakefile{Rules: map[string]makeRule{}, Lines: []makeLine{{Num: 1, Text: "\u2028# $(MAKE) -C x"}}})` renvoie exactement un problème, `Makefile line 1: ` + mustBe |

### 5.6 `TestMakefileOracle` (D15)

Faits du parseur : `parseMakefile(targetMakefile)` ; make lancé sur la fixture mutée, écrite en `Makefile` dans `t.TempDir()`. La base vide (`Makefile` vide dans un autre `t.TempDir()`) est calculée une fois par test. Chaque cas négatif exige exactement la liste de problèmes indiquée (nombre et fragments, dans l'ordre O1 à O6).

| # | Nom | Fixture pour make | Problèmes attendus |
|---|---|---|---|
| OC1 | `extra_makefile` | gabarit + `include extra.mk`, `extra.mk` = `# vide\n` dans le même répertoire | O3 |
| OC2 | `hidden_duplicate_recipe` | gabarit + `verify-quick:\n\t@echo SHADOW-dup\n` (forme de N1c, sans le commentaire) | O2, O5 `verify-quick` |
| OC3 | `hidden_assignment` | gabarit + `EXTRA_X := 1\n` | O4 `EXTRA_X` |
| OC4 | `hidden_target` | gabarit + `extra:\n` | O5 `extra` |
| OC5 | `hidden_pattern_rule` | gabarit + `%.x:\n\t@true\n` | O6 |
| OC6 | `missing_include` | gabarit + `include absent.mk\n` | O1 seul |

Contrôles positifs : OP1 `valid_template` (gabarit contre gabarit), OP2 `reference_dev_makefile` (`referenceDevMakefile(t)` contre lui-même). Sous-test `repository` : `parseMakefile` du `Makefile` puis make dans la racine du dépôt, aucun problème. Aucune fixture de l'oracle ne contient de règle de remise à jour d'un makefile ni d'expansion à la lecture : aucune recette n'est exécutée.

## 6. Menaces (`docs/02-THREAT-MODEL.md`)

Correction de la V0. Deux affirmations de la V0 étaient fausses et sont retirées :
- « `.RECIPEPREFIX` non analysé : une recette à autre préfixe fait échouer `parseMakefile`, donc échec franc » : faux. `.RECIPEPREFIX := >` était ignoré comme affectation (étape 3 V0) et `>@echo SHADOW # :` était classé comme règle grâce au `:` de son commentaire ; le `Makefile` ainsi modifié passait tous les tests (constat 3). V1 : l'affectation elle-même est refusée (D8, G3).
- Le résidu « sous-make sans `-f` » n'est pas « fermé » au sens adverse : seule la forme accidentelle et les indirections de niveau make énumérées le sont.

Correction de la V1, retirée : « les continuations sont jointes avant classement, comme make (y compris pour les commentaires, que make prolonge aussi par `\`) » (section 8 V1). Faux : make ne joint que sur un nombre impair de `\` ; le parseur V1 joignait sur tout `\` final et avalait une ligne que make lit (second BLOCK, N1 à N3). V2 : aucune continuation hors recette (D12), parité exigée et nombre pair refusé partout (D11).

Nouvelle rédaction de la ligne T32, colonnes contrôle et test (à reporter par le principal, tâches V1-7 et V2-7) :

- **Principe (V2)** : lexeur des tests identique à make ou rejet des formes ambiguës. Toute forme sur laquelle le découpage des tests et celui de GNU make pourraient diverger (continuation hors recette, nombre pair de `\` final, octet de contrôle dont CR, blanc Unicode, caractère invisible ou bidirectionnel, UTF-8 invalide, non ASCII hors commentaire en colonne 0 et hors recette) est une erreur de `parseMakefile`, jamais une interprétation. Un oracle différentiel (`TestMakefileOracle`) confronte en plus le résultat du parseur à la base de données de make (`make -p`) sur le `Makefile` du dépôt.
- **Couvert par test** : forme accidentelle (sous-make sans `-f Makefile` ou non canonique : `TestMakefileSubMakeCalls`, D1 à D5) ; indirections de niveau make énumérées : expansions en recette (`$(eval)`, `$(call)`, `$(shell)`, `$(MAKE_COMMAND)`, noms calculés, `$(MAKEFLAGS)`, variables automatiques : D7), directives et affectations hors grammaire (`include` et variantes, `vpath`, `unexport`, `define`, conditionnels, affectation de `MAKE`, `MAKE_COMMAND`, `MAKEFILES`, `MAKEFLAGS`, `.RECIPEPREFIX` ou de tout nom hors ensemble, `!=`, valeurs de `SHELL`, `.SHELLFLAGS`, `GOWORK` modifiées, cibles spéciales, variables propres à une cible, recettes en ligne, commentaires de fin : D8, `TestMakefileGrammar`) ; (V2) lignes masquées au parseur par une continuation ou un octet ambigu (D11 à D14, `TestMakefileGrammar`, `TestMakeLexerHelpers`) ; divergence résiduelle entre parseur et make sur le `Makefile` du dépôt : makefile lu en plus, variable, cible, prérequis ou recette en plus ou déplacés, règle implicite, avertissement de make (D15, `TestMakefileOracle`).
- **Non couvert par analyse statique** : modification adverse du `Makefile` par déguisement shell (`m''ake -f evil.mk`, `bash -c "..."`, `$$(printf ma)ke`, recette qui écrit un fichier puis l'exécute). Ce cas ne repose que sur CODEOWNERS (`/Makefile` et `/internal/archtest/`, revue obligatoire par la protection de branche) et sur la revue humaine du diff du `Makefile`. D7 et D8 réduisent la surface à relire au seul texte shell des recettes ; (V2) D13 (iv) garantit que ce texte ne contient ni caractère invisible ni caractère bidirectionnel qui tromperait le relecteur.
- **Environnement du lanceur** : `MAKEFILES` (le hook Stop et la CI ne le posent pas, `guard_bash` le refuse sur la ligne de commande, D5 de M0-ci) ; nouveau résidu (constat 5) : `MAKE` et `MAKE_COMMAND` hérités de l'environnement remplacent la commande des sous-make canoniques, et `guard_bash` (`.claude/hooks/guard_bash.py` l. 52) ne les refuse pas. Obligation harnais, à joindre à la proposition du cas `test_hooks.sh` : diff proposé à l'humain sur l'expression de la ligne 52, `\b(MAKEFLAGS|MAKEFILES|GNUMAKEFLAGS)\s*=` devient `\b(MAKEFLAGS|MAKEFILES|GNUMAKEFLAGS|MAKE|MAKE_COMMAND)\s*=` ; cas `test_hooks.sh` : `MAKE=/tmp/x make verify-quick` et `env MAKE_COMMAND=/tmp/x make verify-quick` refusés ; option complémentaire pour le hook Stop : lancer `env -u MAKE -u MAKE_COMMAND -u MAKEFILES -u MAKEFLAGS make -f Makefile verify-quick`. Épingler `MAKE` dans le `Makefile` est écarté : D8 interdit d'affecter `MAKE`, et toute valeur épinglée (`make`) dépendrait encore de `PATH`, lui aussi hérité.
- **Inchangé** : cas `test_hooks.sh` avec sous-make imbriqué (proposition harnais).

Oracle (D15) : évaluation et résidus.
- **Pourquoi maintenant** : deux BLOCK successifs de la même classe (divergence de lexeur) montrent que l'énumération des formes dangereuses par l'architecte ne suffit pas. Le rejet des formes ambiguës ferme les divergences connues ; l'oracle détecte sur le `Makefile` réel une divergence encore inconnue, sans dépendre de la liste. Écarté : le report. Son coût (un appel à make de quelques dizaines de millisecondes, un analyseur de la sortie `-p`) est faible devant un troisième BLOCK.
- **Pas d'exécution de recette** : but unique `__rempart_oracle__` défini par `--eval`, sans prérequis ni recette ; `-n` ; `-r` (aucune règle implicite intégrée, donc aucune règle pour refaire `Makefile`) ; environnement minimal de `runInEnv` (pas de `MAKEFLAGS`, `MAKEFILES`, `MAKE`, `MAKE_COMMAND`) ; délai de 30 s. Pas de réseau : le `Makefile` accepté par D8 ne contient aucune expansion à la lecture (ni `$(shell)`, ni `!=`, ni `include`).
- **Exposition résiduelle** : sur un `Makefile` adverse qui masquerait encore une ligne au parseur (troisième divergence), make lit cette ligne pendant l'oracle ; une expansion à la lecture ou une règle qui refait un makefile inclus s'exécuterait (make refait les makefiles même sous `-n` quand ils ne sont pas des buts). Cette exposition est identique à celle de `make verify-quick`, qui lit le même fichier avant de lancer `arch-test` (hook Stop, CI) : l'oracle n'ajoute aucune surface pour ces lanceurs ; il en ajoute une pour un développeur qui lance `go test ./internal/archtest/` directement sur un `Makefile` non relu, atténuée par l'ordre (make n'est lancé qu'après un `parseMakefile` sans erreur). L'oracle n'est jamais lancé sur les fixtures négatives de la grammaire.
- **Angles morts de l'oracle** : un `-include` d'un fichier absent sans règle pour le produire ne laisse aucune trace dans la base (sans effet tant que le fichier n'existe pas ; masqué au parseur, il reste refusé par D11 à D13) ; une cible spéciale identique à une entrée de la base vide (`.SUFFIXES:` sans prérequis) est soustraite (sans effet sous `-r`, inoffensive sinon) ; le texte shell des recettes n'est pas comparé, seule la ligne de début (D7 couvre le `$`) ; la base dépend du format de GNU Make 4.x : une dérive de format fait échouer l'oracle (E de `parseMakeDatabase`), jamais passer.

Effet de bord sur T31 (à noter dans sa colonne contrôle) : `.IGNORE` et l'affectation de `MAKEFLAGS` dans le `Makefile` sont désormais refusés par D8, `$(MAKEFLAGS)` en recette par D7 ; le préfixe `-` hors sous-make et `MAKEFLAGS=` en texte shell restent à la tâche de durcissement avant M3. Aucune menace nouvelle.

## 7. Critères d'acceptation

Tous lancés depuis `/home/user/rempart`.

1. `go test -count=1 -run 'TestMakefileSubMakeCalls|TestMakefileGrammar|TestMakeLexerHelpers|TestMakefileOracle' ./internal/archtest/` : `ok`.
2. Comptes (V2) :
   - `go test -count=1 -v -run 'TestMakefileSubMakeCalls/negative_controls' ./internal/archtest/ | grep -c -- '--- PASS: TestMakefileSubMakeCalls/negative_controls/'` : `34` ; même commande avec `positive_controls` : `6` ;
   - `go test -count=1 -v -run 'TestMakefileGrammar/negative_controls' ./internal/archtest/ | grep -c -- '--- PASS: TestMakefileGrammar/negative_controls/'` : `51` (36 V1 + 15 V2) ; même commande avec `positive_controls` : `6` ;
   - `go test -count=1 -v -run 'TestMakeLexerHelpers' ./internal/archtest/ | grep -c -- '--- PASS: TestMakeLexerHelpers/'` : `3` ;
   - `go test -count=1 -v -run 'TestMakefileOracle/negative_controls' ./internal/archtest/ | grep -c -- '--- PASS: TestMakefileOracle/negative_controls/'` : `6` ; même commande avec `positive_controls` : `2` ; `go test -count=1 -v -run 'TestMakefileOracle/repository' ./internal/archtest/ | grep -c -- '--- PASS: TestMakefileOracle/repository'` : `1`.
3. `go test -count=1 -run 'TestMakefileTargets|TestMakeDevUsesWait|TestMakefileDemoTarget|TestMakefileGoflagsNeutralized|TestNoShadowMakefile|TestCIRunsMakeVerify' ./internal/archtest/` : `ok`.
4. Forme du `Makefile` et du code de test, indépendamment du code Go :
   - sous-make (V0) : `grep -cP '^\t@?\$\(MAKE\) -f Makefile --no-print-directory [a-z][a-z0-9-]*( >&2)?$' Makefile` affiche `4` ; `grep -nE '\bMAKE\b|\bg?make\b|\bMAKEFILES\b' Makefile | grep -vE '^[0-9]+:[[:blank:]]*#' | grep -cvP '^[0-9]+:\t@?\$\(MAKE\) -f Makefile --no-print-directory [a-z][a-z0-9-]*( >&2)?$'` affiche `0` ;
   - D7 : `grep -P '^\t' Makefile | sed 's/\$\$//g' | grep -cF '$'` affiche `4` et `grep -P '^\t' Makefile | sed 's/\$\$//g' | grep -F '$' | grep -cvP '^\t@?\$\(MAKE\) -f Makefile --no-print-directory [a-z][a-z0-9-]*( >&2)?$'` affiche `0` ;
   - D8 : `grep -vP '^(\t| *(#|$))' Makefile | grep -cF '#'` affiche `0`, et
     `grep -vP '^(\t| *(#|$))' Makefile | grep -cvP '^(SHELL := /bin/bash|\.SHELLFLAGS := -eu -o pipefail -c|\.DEFAULT_GOAL := verify-quick|(EVAL|POLICIES_DIR|OPA) \?= [A-Za-z0-9._/-]+|override (SCENARIO|EVAL|POLICIES_DIR|OPA) := \$\(value (SCENARIO|EVAL|POLICIES_DIR|OPA)\)|export GOWORK := off|override GOFLAGS := -mod=readonly|export( (SCENARIO|EVAL|POLICIES_DIR|OPA|GOWORK|GOFLAGS))+|\.PHONY:( [a-z][a-z0-9-]*)+|[a-z][a-z0-9-]*:( [a-z][a-z0-9-]*)*)$'` affiche `0` ;
   - D13 (i) : `LC_ALL=C grep -cP '[\x00-\x08\x0B-\x1F\x7F]' Makefile` affiche `0` ;
   - D11 : `grep -cP '(^|[^\\])(\\\\)+$' Makefile` affiche `0` ;
   - D12 : `grep -cP '^[^\t].*\\$' Makefile` affiche `0` ;
   - D13 (ii) : `LC_ALL=C grep -nP '[\x80-\xFF]' Makefile | grep -cvP '^[0-9]+:(#|\t)'` affiche `0` ;
   - D13 (iv) : `LC_ALL=C.UTF-8 grep -cP '[^\x00-\x7F\p{L}\p{M}\p{N}\p{P}\p{S}]|\x{FFFD}' Makefile` affiche `0` ;
   - D14 : `grep -nE 'TrimSpace' internal/archtest/makefile_test.go | grep -cE 'l\.Text|ln\.Text|text'` affiche `0`, et `grep -c 'isMakeComment(' internal/archtest/compose_test.go` affiche au moins `2` ;
   - D15 : `make --version | head -n1 | grep -c '^GNU Make 4\.'` affiche `1` ; `grep -c 'Skip' internal/archtest/makeoracle_test.go` affiche `0`.
5. Comportement, sans rien exécuter (`-n` n'exécute que les lignes `$(MAKE)`) :
   `d=$(mktemp -d) && cp Makefile "$d/" && printf 'opa-test arch-test dev:\n\t@echo SHADOW\n' > "$d/GNUmakefile" && (cd "$d" && make -f Makefile -n verify-quick verify demo 2>&1) | grep -c SHADOW; rm -rf "$d"`
   affiche `0`.
6. Rejeu des attaques des deux BLOCK sur une copie du commit V2 (après le commit de la tâche V2-4). Gabarit, `<MUT>` et `<TEST>` pris dans la liste :
   `d=$(mktemp -d) && git archive HEAD | tar -x -C "$d" && <MUT> && (cd "$d" && go test -count=1 -run '<TEST>' ./internal/archtest/ >/dev/null 2>&1); echo "exit=$?"; rm -rf "$d"`
   - témoin : `<MUT>` = `true`, `<TEST>` = `TestMakefileGrammar/repository|TestMakefileSubMakeCalls/repository|TestMakefileOracle/repository` : affiche `exit=0` ;
   - constat 1 (V1) : `<MUT>` = `printf '\n$(eval include evil.mk) # :\n' >> "$d/Makefile"`, `<TEST>` = `TestMakefileGrammar/repository` : affiche `exit=1` ;
   - constat 2 (V1) : `<MUT>` = `sed -i 's/^\t\$(MAKE) -f Makefile --no-print-directory arch-test$/\t$(MAKE_COMMAND) -f evil.mk arch-test/' "$d/Makefile" && grep -q MAKE_COMMAND "$d/Makefile"`, `<TEST>` = `TestMakefileSubMakeCalls/repository` : affiche `exit=1` ;
   - constat 3 (V1) : `<MUT>` = `printf '\n.RECIPEPREFIX := >\nverify-quick:\n>@echo SHADOW # :\n' >> "$d/Makefile"`, `<TEST>` = `TestMakefileGrammar/repository` : affiche `exit=1` ;
   - N1 (V2) : `<MUT>` = `printf '\n# fin \\\\\ninclude evil.mk\n' >> "$d/Makefile"`, `<TEST>` = `TestMakefileGrammar/repository` : affiche `exit=1` ;
   - N1b (V2) : `<MUT>` = `printf '\n  # x \\\\\n-include evil.mk\n' >> "$d/Makefile"`, `<TEST>` = `TestMakefileGrammar/repository` : affiche `exit=1` ;
   - N1c (V2) : `<MUT>` = `printf '\n# fin \\\\\nverify-quick:\n\t@echo SHADOW-dup\n' >> "$d/Makefile"`, `<TEST>` = `TestMakefileGrammar/repository` : affiche `exit=1` ;
   - N3 (V2) : `<MUT>` = `printf '\t@echo ok \\\\\ninclude evil.mk\n' >> "$d/Makefile"` (ajouté à la recette de `sandbox-destroy`, dernière règle), `<TEST>` = `TestMakefileGrammar/repository` : affiche `exit=1` ;
   - témoin make de N1c (preuve que l'attaque est réelle, sans exécuter de recette : `-n`, recette de remplacement sans `$(MAKE)`) : `d=$(mktemp -d) && cp Makefile "$d/" && printf '\n# fin \\\\\nverify-quick:\n\t@echo SHADOW-dup\n' >> "$d/Makefile" && (cd "$d" && env -u MAKEFLAGS -u MAKEFILES make -f Makefile -n verify-quick 2>/dev/null) | grep -c SHADOW-dup; rm -rf "$d"` affiche `1`.
7. Rouge d'abord V2 (constaté par `test-author`, sortie consignée dans `docs/STATUS.md`) :
   - à la fin de V2-1 (cas écrits, `makeTrim` et `isMakeComment` extraits avec le comportement V1 `strings.TrimSpace`, `joinMakeLines` inchangée) : `go test -count=1 -v -run 'TestMakefileGrammar/negative_controls' ./internal/archtest/ 2>&1 | grep -c -- '--- FAIL: TestMakefileGrammar/negative_controls/'` affiche `15` (N1 à N14, les 36 cas V1 passent) ; `go test -count=1 -v -run 'TestMakeLexerHelpers' ./internal/archtest/ 2>&1 | grep -c -- '--- FAIL: TestMakeLexerHelpers/'` affiche `3` ; `go test -count=1 -v -run 'TestMakefileGrammar/positive_controls' ./internal/archtest/ 2>&1 | grep -c -- '--- FAIL:'` affiche `0` ;
   - à la fin de V2-3a (cas de l'oracle écrits, `compareMakeDatabase` renvoyant `nil`) : `go test -count=1 -v -run 'TestMakefileOracle/negative_controls' ./internal/archtest/ 2>&1 | grep -c -- '--- FAIL: TestMakefileOracle/negative_controls/'` affiche `6`.
8. `make -f Makefile verify-quick` : code 0.
9. Intégrité : sur chaque commit V1 et V2, `git diff --name-only HEAD~ -- CLAUDE.md .claude/settings.json .claude/hooks .claude/bin .claude/agents .claude/commands Makefile` n'affiche rien.
10. Mutations C1 à C15, K1 à K17, L1 à L11 et R1 à R7 (section 5.3) : pour chacune, sur une copie de travail, `go test -count=1 -run 'TestMakefileSubMakeCalls|TestMakefileGrammar|TestMakefileTargets|TestMakeLexerHelpers|TestMakefileOracle' ./internal/archtest/` échoue ; `git status --porcelain internal/archtest` vide après restauration. R8 est vérifiée par le critère 4 (D15).
11. Documentation (tâches V1-7 et V2-7) : `grep -E '^\| T32 ' docs/02-THREAT-MODEL.md | grep -c 'TestMakefileGrammar'` affiche `1` ; `grep -E '^\| T32 ' docs/02-THREAT-MODEL.md | grep -c 'MAKE_COMMAND'` affiche `1` ; `grep -E '^\| T32 ' docs/02-THREAT-MODEL.md | grep -ciE 'ferm[ée]'` affiche `0` ; `grep -c 'MAKE_COMMAND' docs/STATUS.md` affiche au moins `1` ; V2 : `grep -E '^\| T32 ' docs/02-THREAT-MODEL.md | grep -c 'rejet des formes ambiguës'` affiche `1` ; `grep -E '^\| T32 ' docs/02-THREAT-MODEL.md | grep -c 'TestMakefileOracle'` affiche `1` ; `grep -c "M0-T04b V2 : changement d'approche" docs/STATUS.md` affiche au moins `1`.

## 8. Risques

- Faux positif (constat 6) : un `echo` contenant le mot `make` en recette est refusé (D2). Accepté : reformuler le message.
- Rigidité voulue : toute évolution du `Makefile` hors grammaire (nouvelle variable, `include`, `$@` ou `$(...)` en recette, cible avec `_` ou `.`, deux espaces dans une forme figée) fait échouer les tests. L'extension passe par une modification de `makeVariables`, `makeAssignForms` ou des regex de D8, sous CODEOWNERS `/internal/archtest/`, et doit être relue comme une modification de sécurité. Un reformatage anodin donne un échec franc, jamais une acceptation silencieuse.
- Écart entre la grammaire de test et GNU make : un sous-ensemble strict et ancré limite le risque qu'une ligne acceptée soit lue autrement par make. V2 : l'affirmation V1 « continuations jointes comme make, y compris pour les commentaires » était fausse (parité, section 6). Le lexeur V2 n'imite plus make, il rejette les formes ambiguës (D11 à D14) ; l'oracle (D15) et le critère 5 exercent le vrai make.
- (V2) Rigidité typographique : la typographie française avec espace insécable (U+00A0, U+202F avant `:`, `»`) est refusée dans les commentaires et les `echo` (D13 (iv)). Le `Makefile` actuel n'en contient pas. Accepté : écrire une espace ordinaire.
- (V2) Commentaires longs : un commentaire ne peut plus se prolonger par `\` (D12) ; écrire plusieurs lignes `#`. Le `Makefile` actuel n'en utilise pas.
- (V2) Dépendance à GNU Make 4.x : `TestMakefileOracle` échoue (sans saut) si `make` est absent ou d'une autre famille ; `go test ./internal/archtest/` exige donc GNU Make 4.x, déjà exigé par le `Makefile`, le hook Stop et la CI. Un passage à GNU Make 5 ou un changement du format `-p` fait échouer l'oracle : l'analyseur `parseMakeDatabase` est alors adapté, sous CODEOWNERS.
- (V2) Surface nouvelle : `parseMakeDatabase` est un second analyseur. Il ne décide jamais d'accepter : toute section attendue manquante ou tout en-tête de variable illisible est une erreur, et les contrôles OC1 à OC6 prouvent qu'il voit les divergences.
- (V2) Exposition de l'oracle : identique à `make verify-quick` pour le hook Stop et la CI, nouvelle pour un `go test` direct sur un `Makefile` non relu (section 6).
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
4. V1-4 (`security-reviewer`) Verdict PASS ou BLOCK, en rejouant au minimum les constats 1 à 3 du BLOCK (critère 6). Résultat : second BLOCK (constats N1, N1b, N1c, N3 et 5 de l'amendement V2).
5. V1-5 (`acceptance-verifier`) Critères 1 à 10 avec preuves, dont la campagne de mutations C1 à C15 et K1 à K17. Remplacée par V2-6.
6. V1-6 (principal) Si PASS : clôturer la tâche M0-T04b. Remplacée par V2-8.
7. V1-7 (principal) `docs/02-THREAT-MODEL.md` : T32 selon la section 6 (sans le mot « fermé » pour le résidu adverse), note sur T31 ; `docs/STATUS.md` : (bp) partie `Makefile` et archtest faite, obligation harnais `MAKE` et `MAKE_COMMAND` ajoutée à celle du cas `test_hooks.sh`. Critère 11. Fusionnée avec V2-7.
8. V1-8 (principal, hors critères) Proposition de harnais pour l'humain : cas `test_hooks.sh` avec un sous-make imbriqué et un `GNUmakefile` d'ombre, vérifiant que le hook Stop reste vert grâce à `-f Makefile` ; diff de `guard_bash.py` l. 52 ajoutant `MAKE` et `MAKE_COMMAND` ; cas de refus `MAKE=/tmp/x make verify-quick` et `env MAKE_COMMAND=/tmp/x make verify-quick` ; option `env -u` pour la commande du hook Stop.

V2, toutes en phase **tests** (aucun code de production, aucun passage en impl) :

1. V2-1 (`test-author`) Refactorisation à comportement constant puis cas rouges. (a) Extraire `makeTrim` (provisoirement `strings.TrimSpace`) et `isMakeComment`, et y faire passer les cinq sites de la section 4 V2 ; `make -f Makefile verify-quick` reste vert. (b) Passer G30 et G31 en ASCII. (c) Ajouter N1 à N14 (avec `physicalLine` ou `exactLine` sur la ligne en cause), GP5, GP6 et `TestMakeLexerHelpers` (H1 à H3), fragments E9 à E14 en constantes. Constater le critère 7 (première partie : 15, 3, 0) et consigner la sortie dans `docs/STATUS.md`.
2. V2-2 (`test-author`) Écrire `lexMakefile`, `trailingBackslashes`, `allowedMakeRune` selon D11 à D13 (ordre E9, E10, E11, E12 ou E13, puis E14), remplacer `joinMakeLines`, retirer le `TrimSuffix` du CR ; `makeTrim` devient `strings.Trim(s, " \t")` (D14) ; commentaire de grammaire réécrit. Critères 1 (sans l'oracle), 2 (grammaire, lexeur), 3, 4 (D11 à D14), 8.
3. V2-3a (`test-author`) Ajouter `Vars` et `RecipeLine` au parseur ; écrire `makeoracle_test.go` : `runMakeDatabase`, `parseMakeDatabase`, `TestMakefileOracle` (OC1 à OC6, OP1, OP2, `repository`) avec `compareMakeDatabase` provisoirement `return nil`. Constater le critère 7 (seconde partie : 6) et consigner la sortie.
4. V2-3b (`test-author`) Écrire `compareMakeDatabase` (O1 à O6, base soustraite). Critères 1, 2 (oracle), 4 (D15), 8.
5. V2-4 (`test-author`) Commit (commits conventionnels, pied de message du `CLAUDE.md`) ; puis critère 6 sur ce commit, dont le témoin make de N1c.
6. V2-5 (`security-reviewer`) Verdict PASS ou BLOCK, en rejouant au minimum les constats des deux BLOCK (critère 6) et en cherchant une troisième divergence de lexeur contre l'oracle.
7. V2-6 (`acceptance-verifier`) Critères 1 à 11 avec preuves, dont la campagne de mutations C1 à C15, K1 à K17, L1 à L11, R1 à R7.
8. V2-7 (principal) `docs/STATUS.md` : ligne « M0-T04b V2 : changement d'approche » (même classe d'échec deux fois : le lexeur des tests n'imite plus make, il rejette les formes ambiguës ; oracle `make -p` ajouté) ; `docs/02-THREAT-MODEL.md` : T32 selon la section 6 (principe, oracle, résidus), avec les éléments de V1-7. Critère 11.
9. V2-8 (principal) Si PASS : clôturer la tâche M0-T04b. La proposition de harnais V1-8 reste à présenter à l'humain.
