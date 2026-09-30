# Proposition 0010 : code owners sur l'exécuteur et le noyau d'evals

- Date : 2026-09-30
- Statut : proposé, **à appliquer par l'humain** (`.github/CODEOWNERS` est protégé), avant la fusion de la PR de M0-T23
- Patch : `docs/proposals/0010-codeowners-executeur-evals.patch`
- Origine : plan `docs/plans/M0-evals-cli.md` (section 9, menace T83)

## Pourquoi

`evals/` (cas, suites, baselines) a déjà un code owner. Mais un grader, une cible, la sélection des suites ou la comparaison à la baseline, dans `cmd/rempart-evals/` ou `internal/evals/`, peuvent être affaiblis pour masquer une régression sans toucher `evals/`, donc sans revue humaine obligatoire.

## Ce qui change

`.github/CODEOWNERS` gagne `/cmd/rempart-evals/` et `/internal/evals/`, à `@amezianechayer`.

## Appliquer

```bash
git apply docs/proposals/0010-codeowners-executeur-evals.patch
git add .github/CODEOWNERS && git commit -m "chore(github): code owners on the eval runner and core"
git push
```
