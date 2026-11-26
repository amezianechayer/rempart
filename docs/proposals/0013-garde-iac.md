# Proposition 0013 : garde du harnais pour la chaîne IaC (M3)

- Date : 2026-11-26
- Statut : proposé, **à appliquer par l'humain** (`.claude/` et `.github/` sont protégés), à la fin de M3-T02 (étape H-harness-M3 de `docs/plans/M3-overview.md`)
- Patch : `docs/proposals/0013-garde-iac.patch` (`.claude/settings.json`, `.github/CODEOWNERS`) ; `git apply --check` vérifié par l'agent sur la tête de `main-6cpq6q`
- Origine : ADR 0014 D15, D16, D17 ; menaces T31, T143, T148, T149

## Pourquoi

1. **Permissions « ask » incomplètes.** `.claude/settings.json` demande l'approbation pour `make sandbox-apply` et `make sandbox-destroy`, mais pas pour la forme canonique du dépôt, `make -f Makefile sandbox-apply` (celle qu'emploient le `Makefile`, la documentation et le hook `guard_bash`). `make sandbox-plan`, qui lance un vrai `tofu plan` avec l'identité en lecture de l'humain (D17), n'est sous aucune permission.
2. **Code owners des nouveaux points sensibles de M3.** `/scripts/` (verrou des outils, futur `sandbox.sh`) et `/policies/` sont déjà couverts. Ne le sont pas : les modules internes (`/modules/`, M3-T04 et T05), l'exécutant unique des outils (`internal/validate/toolexec`, T8), le chargeur du verrou (`internal/validate/toolchain.go`, T143), la table de traduction des permissions (`internal/iacgen/iam`, T117, M3-T06) et l'équivalence graphe et plan (`internal/plan/equivalence`, T146, M3-T07).

## Ce qui change

- `.claude/settings.json`, liste `ask` : `make -f Makefile sandbox-apply`, `make -f Makefile sandbox-destroy`, et `make sandbox-plan` sous ses trois formes (`make`, `make -f Makefile`, `make -s -f Makefile`).
- `.github/CODEOWNERS` : `/modules/`, `/internal/validate/toolexec/`, `/internal/validate/toolchain.go`, `/internal/iacgen/iam/`, `/internal/plan/equivalence/`.

## Non inclus, à décider par l'humain

- **Garde d'écriture** (comme pour les baselines) sur `scripts/iac-tools.lock.json`, `modules/scanner-exceptions.json` et `internal/iacgen/iam/` : elle exigerait un changement de `.claude/hooks/`, que l'agent ne peut pas rédiger sans le voir modifier. Recommandation de l'agent : l'ajouter, le verrou n'étant alors modifiable que par l'humain après la relecture H-tools-lock ; à défaut, la revue de code owner (`/scripts/`) reste la défense.
- **Garde de processus** (proposée à la revue du lot « avant M3 ») : refuser un commit qui change `policies/` ou le moteur OPA sans verdict PASS consigné dans `docs/STATUS.md`. Elle se heurte au hook Stop, qui exige un arbre commité en fin de tour : à concevoir avec lui.
- Les formes `*/tofu apply` et `"$TOFU" apply` ne demandent pas de règle de plus : le hook `guard_bash` refuse déjà toute commande dont le texte contient `apply` ou `destroy` (constaté pendant M3-T02, même pour une simple lecture).

## Appliquer

```bash
git apply docs/proposals/0013-garde-iac.patch
python3 -c 'import json; json.load(open(".claude/settings.json"))' && echo settings-ok
git add .claude/settings.json .github/CODEOWNERS
git commit -m "chore(harness): ask for every sandbox target form, code owners on the IaC chain"
git push
```
