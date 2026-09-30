# Proposition 0009 : make sans environnement hérité dans le hook Stop, options de make restreintes

- Date : 2026-09-30
- Statut : proposé, **à appliquer par l'humain** (l'agent n'a pas le droit de modifier le harnais), avant `/close-milestone M0`
- Patch : `docs/proposals/0009-garde-make-environnement.patch`
- Origine : obligations (bp) (cas de sous-make imbriqué) et (bt) de M0-T04, résidu T32 de la revue sécurité de M0-T04b

## Pourquoi

1. **T32, environnement.** `MAKE` et `MAKE_COMMAND` hérités de l'environnement remplacent la commande de chaque sous-make, même sous la forme canonique `$(MAKE) -f Makefile --no-print-directory <cible>` : `MAKE=true` rend vert un `verify-quick` dont une sous-cible échoue. `MAKEFLAGS=-i` fait ignorer les échecs de recette. `BASH_ENV`, `ENV` et les fonctions exportées (`BASH_FUNC_*`) injectent du code dans le `SHELL := /bin/bash` des recettes. Le hook Stop transmet aujourd'hui tout son environnement à make.
2. **(bt).** `guard_bash` admet encore des options qui changent ce que make exécute : `-C`/`--directory` (autre répertoire, donc autre `Makefile`), `-t`/`--touch` et `-q`/`--question` (recettes non exécutées), `-e` (l'environnement l'emporte sur `SHELL`, `GOFLAGS` du `Makefile`), `-W`, `-o` (cibles forcées ou ignorées), `-I` (répertoires d'inclusion). Il admet aussi `MAKE=` et `MAKE_COMMAND=` en tête de commande.
3. **(bp).** Le hook Stop n'avait pas de cas de test avec un sous-make imbriqué.
4. **Troisième revue sécurité de M0-T04b (V2).** GNU make accepte les options longues abrégées (`--fil=evil.mk`, `--dir=sub`, `--makef=`) : une liste noire d'options est contournable. Et une règle implicite intégrée (`%: %.sh`, RCS, SCCS) refait le `Makefile` à partir d'un fichier voisin plus récent (`Makefile.sh`), même sous `-n`.

## Ce qui change

| Fichier | Changement |
|---|---|
| `.claude/hooks/stop_verify.py` | Commande `make -r -f Makefile verify-quick` (`-r` : aucune règle implicite intégrée, défense en profondeur de la ligne `Makefile: ;` du `Makefile`, M0-T04b D16). Toutes les commandes du hook sont lancées sans `MAKE`, `MAKE_COMMAND`, `MAKEFLAGS`, `MFLAGS`, `GNUMAKEFLAGS`, `MAKEFILES`, `MAKELEVEL`, `MAKEOVERRIDES`, `BASH_ENV`, `ENV` ni `BASH_FUNC_*`. |
| `.claude/hooks/guard_bash.py` | Règle T31/T32 en **liste blanche** : après `make`, seules les options `-s`, `-n`, `-k`, `-r`, `-R` (groupables entre elles), `-j<n>`, `--no-print-directory` et `-f Makefile` sont admises, toute autre option courte ou longue (abrégée comprise) est refusée ; affectations `MAKE=`, `MAKE_COMMAND=`, `MFLAGS=`, `MAKELEVEL=`, `MAKEOVERRIDES=` refusées comme `MAKEFLAGS=`. |
| `.claude/hooks/test_hooks.sh` | `make -C . arch-test` passe de admis à refusé ; 24 cas de commande (dont les formes abrégées `--fil=`, `--dir=`, `--makef=`, `--ign`, `--ev=`, `--quest`, et `-sf`, `--`) ; 4 cas du hook Stop (sous-make imbriqué avec `GNUmakefile` d'ombre, `MAKE=true` et `MAKEFLAGS=-i` hérités, `Makefile.sh` plus récent). |

## Décision prise sur délégation

`-n` (`--dry-run`) reste **admis**, contrairement à la liste initiale de (bt) : il n'exécute que les lignes `$(MAKE)` et sert de preuve de comportement dans les critères des plans (M0-T04b, fichier d'ombre). Il ne peut pas faire passer le hook Stop, qui lance sa propre commande. Réversible : retirer `n` de la liste blanche. Groupements hors liste (`-sf Makefile`) refusés : forme plus stricte, `-s -f Makefile` reste admis.

## Vérification faite par l'agent

- Copie du harnais à jour dans le scratchpad, modifications appliquées : `bash .claude/hooks/test_hooks.sh` sur la copie, **148 réussis, 0 échoués**.
- Contre-épreuve, première version : même copie avec l'ancien `stop_verify.py`, **2 échecs** attendus (`MAKE` hérité, `MAKEFLAGS` hérité) ; le cas du `GNUmakefile` d'ombre passait déjà grâce à `-f Makefile` (proposition 0007) et aux sous-make canoniques (M0-T04b).
- Contre-épreuve, version finale : même copie avec le hook Stop sans `-r`, **1 échec** attendu (`Makefile.sh` plus récent refait le `Makefile` et rend `verify-quick` vert) ; avec `-r`, 148 réussis.
- `git apply --check` du patch sur le dépôt : rc=0.

Limite : `guard_bash` reste un filtre, pas un bac à sable ; une commande déguisée (nom de variable ou option construits par le shell, `eval`) n'est pas couverte. Le hook Stop, lui, nettoie l'environnement quelle que soit la façon dont il a été construit.

## Appliquer

```bash
git apply docs/proposals/0009-garde-make-environnement.patch
bash .claude/hooks/test_hooks.sh
git add .claude && git commit -m "fix(harness): apply proposal 0009"
git push
```
