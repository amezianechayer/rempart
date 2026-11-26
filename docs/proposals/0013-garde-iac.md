# Proposition 0013 : garde du harnais pour la chaîne IaC (M3)

- Date : 2026-11-26 ; seconde version le 2026-11-26, après la revue sécurité de M3-T02 (constat moyen : la première version visait un trou qui n'existe pas et laissait ouvert celui de `sandbox-plan`)
- Statut : proposé, **à appliquer par l'humain** (`.claude/` et `.github/` sont protégés), à la fin de M3-T02 et en tout cas avant la création de `scripts/sandbox.sh` (étape H-harness-M3 de `docs/plans/M3-overview.md`, obligation (hh))
- Patch : `docs/proposals/0013-garde-iac.patch` (`.claude/settings.json`, `.claude/hooks/guard_bash.py`, `.claude/hooks/test_hooks.sh`, `.github/CODEOWNERS`) ; vérifié par l'agent sur la tête de `main-6cpq6q` : le patch s'applique (`git apply --check`), et `test_hooks.sh` patché, lancé dans une copie jetable, donne 169 réussis et 0 échoué (157 avant). Contrôle négatif : les 12 nouveaux cas échouent contre le `guard_bash.py` actuel.
- Origine : ADR 0014 D15, D16, D17 ; menaces T31, T143, T148, T149

## Pourquoi

1. **`make sandbox-plan` n'a pas de verrou.** Sa recette lance un vrai `tofu plan` avec l'identité en lecture de l'humain (D17) et, à la différence de `sandbox-apply` et `sandbox-destroy`, ne demande aucune confirmation sur `/dev/tty`. Aucune permission « ask » ne la couvre. Les douze formes des nouveaux cas de test passent aujourd'hui le hook (contrôle négatif ci-dessus ; la revue en a sondé neuf) : options avant la cible (`-s`, `-j1`, `-k`, `--no-print-directory`, `-f Makefile`), variable avant la cible, cible enchaînée (`make sandbox-guard sandbox-plan`), commande composée, appel direct de `scripts/sandbox.sh plan`. Une fois `sandbox.sh` livré, l'agent pourrait lancer un plan réel sans approbation (T149).
2. **Correction du diagnostic de la première version.** Pour `sandbox-apply` et `sandbox-destroy`, il n'y a **pas** de trou : la règle T29 de `guard_bash.py` refuse déjà toute forme autre que `make sandbox-apply SCENARIO=<nom>` seule sur la ligne (sondé : `make -f Makefile sandbox-apply SCENARIO=demo` rend 2), et cette forme est sous « ask ». Les deux entrées « ask » ajoutées par la première version pour la forme `-f Makefile` étaient des règles mortes : retirées.
3. **Code owners des nouveaux points sensibles de M3.** `/scripts/` (verrou des outils, futur `sandbox.sh`) et `/policies/` sont déjà couverts. Ne le sont pas : les modules internes (`/modules/`, M3-T04 et T05), l'exécutant unique des outils (`internal/validate/toolexec`, T8), le chargeur du verrou (`internal/validate/toolchain.go`, T143, T156), la table de traduction des permissions (`internal/iacgen/iam`, T117, M3-T06) et l'équivalence graphe et plan (`internal/plan/equivalence`, T146, M3-T07).

## Ce qui change

- `.claude/hooks/guard_bash.py` : une règle calquée sur T29. Seule `make sandbox-plan SCENARIO=<nom>`, seule sur la ligne, atteint la cible ; toute autre forme de `make ... sandbox-plan`, et tout `sandbox.sh ... plan`, est refusée (code 2).
- `.claude/settings.json`, liste `ask` : une seule entrée de plus, `Bash(make sandbox-plan:*)`, qui couvre la seule forme admise par le hook.
- `.claude/hooks/test_hooks.sh` : 12 cas refusés (les formes de la revue) ; le cas existant qui employait `sandbox-plan` dans une substitution de commande pour tester T28 emploie désormais `opa-test`, et la forme canonique reste admise.
- `.github/CODEOWNERS` : `/modules/`, `/internal/validate/toolexec/`, `/internal/validate/toolchain.go`, `/internal/iacgen/iam/`, `/internal/plan/equivalence/`.

## Non inclus, à décider par l'humain

- **Garde d'écriture** (comme pour les baselines) sur `scripts/iac-tools.lock.json`, `modules/scanner-exceptions.json` et `internal/iacgen/iam/`. Recommandation de l'agent : ne pas l'ajouter sur le verrou, que l'agent doit pouvoir monter de version ; l'ajouter sur la table IAM et les exceptions. Résidu sans garde d'écriture : un verrou modifié par l'agent sous injection n'est arrêté que par sa grammaire fermée (chargeur Go, script, archtest), par la relecture humaine (H-tools-lock) et par la revue de code owner (`/scripts/`). Depuis la revue de M3-T02, le script relit le verrou sous cette grammaire avant toute écriture (T158).
- **Garde de processus** (proposée à la revue du lot « avant M3 ») : refuser un commit qui change `policies/` ou le moteur OPA sans verdict PASS consigné dans `docs/STATUS.md`. Elle se heurte au hook Stop, qui exige un arbre commité en fin de tour : à concevoir avec lui.
- Les formes `*/tofu apply` et `"$TOFU" apply` ne demandent pas de règle de plus : le hook `guard_bash` refuse déjà toute commande dont le texte contient `apply` ou `destroy` (constaté pendant M3-T02, même pour une simple lecture).

## Appliquer

```bash
git apply docs/proposals/0013-garde-iac.patch
python3 -c 'import json; json.load(open(".claude/settings.json"))' && echo settings-ok
bash .claude/hooks/test_hooks.sh
git add .claude/settings.json .claude/hooks/guard_bash.py .claude/hooks/test_hooks.sh .github/CODEOWNERS
git commit -m "chore(harness): sandbox-plan in its canonical form only, code owners on the IaC chain"
git push
```
