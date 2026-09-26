# Proposition 0005 : suites d'eval gelées en phase impl et `CODEOWNERS`

- Date : 2026-09-26
- Statut : proposé, **à appliquer par l'humain** (l'agent n'a pas le droit de modifier le harnais), **après** les propositions 0001 à 0004, **avant M0-T23** (condition de la revue sécurité de M0-T22)
- Patch : `docs/proposals/0005-garde-suites-eval-et-codeowners.patch`
- Origine : revues `security-reviewer` de M0-T22 (deux verdicts BLOCK, constats moyens sur les protections de baselines), menaces T58, T61 et T63 de `docs/02-THREAT-MODEL.md`

## Pourquoi

Une fois 0001 appliquée, `guard_edit.py` bloque déjà toute écriture de l'agent dans `evals/<suite>/baseline.json` et `evals/<suite>/baseline/<plateforme>/<modèle>.json`, et `guard_bash.py` refuse `--write-baseline` et `make update-baseline`. Deux trous restent :

1. **`suite.yaml` jamais gelé.** Il porte la cible et les motifs `watch` qui décident quelles suites sont rejouées par `EVAL=changed`. En phase impl, les cas sont gelés mais pas la suite qui les sélectionne : l'agent peut donc retirer un motif `watch` pour qu'une suite qui échoue ne soit plus rejouée (T61), ou changer sa cible (T58).
2. **Pas de revue humaine obligatoire côté forge.** Les gardes ne protègent que l'agent local ; une PR peut toujours modifier `evals/**`, le harnais ou les ADR sans revue explicite.

## Ce qui change

| Fichier | Changement |
|---|---|
| `.claude/hooks/guard_edit.py` | `^evals/.*/suite\.yaml$` (suites imbriquées comprises) ajouté à `TEST_FILE` : écriture permise en phase tests et free (création d'une suite en T23), refusée en phase impl comme les cas. `\.github/CODEOWNERS$` ajouté à `PROTECTED`. |
| `.claude/hooks/guard_bash.py` | Nouvelle règle : toute commande qui mentionne `evals/.../baseline`, `evals/.../suite.yaml` ou `evals/.../cases/` et contient une écriture (`>`, `tee`, `cp`, `sed -i`, etc.) est refusée : les gardes d'édition ne couvraient que l'outil Edit (T63). `--write-baseline` devient `-{1,2}write-baseline` (le paquet `flag` de Go accepte un seul tiret). |
| `.claude/hooks/test_hooks.sh` | 11 cas : `CODEOWNERS` refusé ; `suite.yaml` permis en phase tests, refusé en impl, imbriqué compris ; `-write-baseline` ; `cp`, `sed -i`, `>`, `tee` vers baselines, suites et cas refusés ; lecture permise. |
| `.github/CODEOWNERS` | Nouveau : `CLAUDE.md`, `.claude/`, `.github/`, `evals/`, `docs/decisions/` à `@amezianechayer`. |

À faire en plus dans GitHub (réglage, pas un fichier) : protection de la branche par défaut avec « Require review from Code Owners ». C'est le seul garde-fou qui ne dépend pas de l'agent local (T63).

## Vérification faite par l'agent

- `git apply --check` des patchs 0004 puis 0005 sur un clone où 0001, 0002 et 0003 sont appliqués : rc=0.
- Expressions régulières de `guard_bash` éprouvées hors harnais sur les 9 commandes des nouveaux cas : résultats attendus.
- Non exécuté : le garde refuse, à juste titre, toute écriture sous `.claude/hooks/`, même dans une copie. `bash .claude/hooks/test_hooks.sh` reste à lancer par l'humain.

## Appliquer

Depuis la racine du dépôt, dans ton terminal (pas via Claude), après 0001 à 0004 :

```bash
git apply docs/proposals/0005-garde-suites-eval-et-codeowners.patch
bash .claude/hooks/test_hooks.sh
git add .claude .github && git commit -m "fix(harness): freeze eval suites in impl phase and require code owner review"
```
