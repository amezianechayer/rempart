# Proposition 0008 : code owners sur tout ce qui définit `verify`

- Date : 2026-09-30
- Statut : proposé, **à appliquer par l'humain** (`.github/CODEOWNERS` est protégé), avant la fusion de la première PR vers `main`
- Patch : `docs/proposals/0008-codeowners-verify.patch`
- Origine : revue sécurité de M0-T04 (constats moyens T32 et T82)

## Pourquoi

La CI exécute `make -f Makefile verify`. Une PR qui affaiblit les tests d'architecture (`internal/archtest/`), la configuration du lint (`.golangci.yml`), les scripts de la pile, les dépendances ou un `GNUmakefile` pourrait obtenir un `verify` vert sans revue humaine, car ces chemins n'ont pas de code owner.

## Ce qui change

`.github/CODEOWNERS` gagne : `/GNUmakefile`, `/makefile`, `/GNUMakefile`, `/internal/archtest/`, `/.golangci.yml`, `/scripts/`, `/docker-compose.yml`, `/go.mod`, `/go.sum`, `/policies/`, tous à `@amezianechayer`.

`TestCodeownersProtectsBaselines` reste vert (il n'exige que des ajouts).

## Appliquer

```bash
git apply docs/proposals/0008-codeowners-verify.patch
git add .github/CODEOWNERS && git commit -m "chore(github): code owners on everything that defines verify"
git push
```
