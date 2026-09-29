# Proposition 0007 : `make -f Makefile` pour la CI et le hook Stop, `/Makefile` en revue humaine, lectures de secrets dans la pile

- Date : 2026-09-29
- Statut : proposé, **à appliquer par l'humain** (l'agent n'a pas le droit de modifier le harnais), **après la proposition 0006**, **avant la phase impl de M0-T04**
- Patch : `docs/proposals/0007-garde-ci-et-pile.patch`
- Origine : plan `docs/plans/M0-ci.md` (T32, T6), obligation (aq) de M0-T03 (T76), obligations (bo) de M0-T03b

## Pourquoi

1. **T32.** La CI de M0-T04 lance `make -f Makefile verify` : un `GNUmakefile` ou un `makefile` ajouté par une PR serait lu avant le `Makefile` par un simple `make`. Le hook Stop lance aujourd'hui `make verify-quick`, exposé de la même façon. Or `guard_bash` refuse tout `make -f`, même `-f Makefile` : l'agent ne pourrait pas rejouer les commandes de la CI.
2. **Revue humaine du `Makefile`.** Le `Makefile` décide de ce que la CI vérifie ; une PR qui l'affaiblit doit passer par une revue humaine (règle « Require review from Code Owners »). `TestCodeownersProtectsBaselines` de M0-T04 l'exige.
3. **(aq), T76.** La proposition 0006 bloque `docker compose config`, `docker inspect` non filtré, `exec ... env`. Il reste la lecture directe de fichiers de secrets dans les conteneurs (`/etc/temporal/config/docker.yaml`, `/proc/*/environ`), par `docker exec`, `docker compose exec` ou `docker cp`.

## Ce qui change

| Fichier | Changement |
|---|---|
| `.claude/hooks/stop_verify.py` | Le hook Stop lance `make -f Makefile verify-quick`. |
| `.claude/hooks/guard_bash.py` | Règle T31/T32 : `-f` admis seulement sous la forme exacte `-f Makefile` ; `-i`, `--file`, `--makefile`, `--eval`, `MAKEFLAGS`, `MAKEFILES` restent refusés, comme `-f` vers tout autre fichier. Nouvelle règle (aq) : `docker exec`, `docker compose exec` ou `docker cp` suivis d'un lecteur de fichier (`cat`, `head`, `grep`...), de `/proc/` ou de `/etc/temporal/config`, et toute mention de `/proc/<pid>/environ`, sont refusés. |
| `.claude/hooks/test_hooks.sh` | 12 cas de commande (lectures de secrets refusées, commandes utiles de la pile admises, formes de `-f`) et 1 cas du hook Stop (`GNUmakefile` en échec ignoré). |
| `.github/CODEOWNERS` | `/Makefile @amezianechayer`. |

## Vérification faite par l'agent

- Sur une copie du dépôt à jour (`8394e11`) : `git apply` de 0006 puis de 0007, rc=0.
- `bash .claude/hooks/test_hooks.sh` sur cette copie : **120 réussis, 0 échoués**.
- Expressions régulières éprouvées hors harnais sur 17 commandes : résultats attendus sur 17.

Limite : c'est un filtre, pas un bac à sable (en-tête de `guard_bash.py`).

## Appliquer

Depuis la racine du dépôt, dans ton terminal (pas via Claude), après 0006 :

```bash
git apply docs/proposals/0006-garde-secrets-pile-dev.patch   # si pas encore fait
git apply docs/proposals/0007-garde-ci-et-pile.patch
bash .claude/hooks/test_hooks.sh
git add .claude .github && git commit -m "fix(harness): make -f Makefile for CI and Stop hook, Makefile code owner, guard secret reads in dev stack"
git push
```
