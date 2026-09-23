# Proposition 0003 : garde du harnais sur les variables de make et le bac à sable

- Date : 2026-09-23
- Statut : proposé, **à appliquer par l'humain** (l'agent n'a pas le droit de modifier le harnais), **après** les propositions 0001 et 0002
- Patch : `docs/proposals/0003-garde-make-variables.patch`
- Origine : revue et contre-revue `security-reviewer` de M0-T01 (verdicts PASS, constats moyens), menaces T28, T29, T31 et T32 de `docs/02-THREAT-MODEL.md`

## Pourquoi

Le `Makefile` de M0-T01 protège déjà ses propres variables (amendement R1 de `docs/plans/M0-squelette.md`) et lit la confirmation du bac à sable sur `/dev/tty`. Deux faiblesses restent hors de portée du dépôt :

1. **T28** : GNU make développe `$(...)` et `${...}` dans toute variable passée en ligne de commande, y compris une variable que le `Makefile` ne connaît pas (`make dev FOO='$(shell ...)'` exécute la commande). Le `Makefile` ne peut pas s'en protéger pour une variable inconnue ; seul le garde Bash le peut.
2. **T29** : la permission « ask » de `.claude/settings.json` porte sur le préfixe `make sandbox-apply`. Les formes `make -s sandbox-apply ...`, `make SCENARIO=x sandbox-apply`, un enchaînement `...; echo`, un tube vers make ou un appel direct à `scripts/sandbox.sh apply` y échappent.

## Ce qui change

| Fichier | Changement |
|---|---|
| `.claude/hooks/guard_bash.py` | Toutes les règles visent `make` et `gmake`. Règle T28 : refus de toute commande où un argument de make contient `$(` ou `${`. Règle T29 : une commande qui lance `sandbox-apply`, `sandbox-destroy` ou `sandbox.sh apply\|destroy` n'est permise que sous la forme canonique `make sandbox-apply SCENARIO=<nom>` (ou `sandbox-destroy`), seule sur la ligne ; cette forme reste soumise à la permission « ask ». Règle T31 et T32 : refus de `-i`, `-f`, `--ignore-errors`, `--eval`, `--file`, `--makefile` et des affectations de `MAKEFLAGS`, `MAKEFILES`, `GNUMAKEFLAGS`. Règle des baselines élargie : `update-baseline` refusé quelles que soient les options de make. |
| `.claude/hooks/test_hooks.sh` | 22 cas ajoutés (8 permis, 14 refusés). |

## Appliquer

Depuis la racine du dépôt, dans ton terminal (pas via Claude), après 0001 et 0002 :

```bash
git apply docs/proposals/0003-garde-make-variables.patch
bash .claude/hooks/test_hooks.sh
git add .claude && git commit -m "fix(harness): refuse make expansion, make engine flags and non-canonical sandbox commands"
```

Puis redémarre Claude Code.

## Résultat des tests

Clone neuf du dépôt dans un conteneur Linux (Python 3.11, Go 1.27.1, GNU make 4.3), patchs 0001, 0002 puis 0003 appliqués : `hooks : 81 réussis, 0 échoués` (59 d'origine et 22 nouveaux).

## Limites

- Les filtres restent contournables par un agent déterminé (limite déjà écrite dans le README) ; le `Makefile` durci et la confirmation sur `/dev/tty` restent la protection principale.
- Faux positifs acceptés : `make X="$(commande)"` (substitution du shell) est refusé, passer par une variable d'environnement ; `make -f` est refusé à l'agent (le hook Stop, qui ne passe pas par Bash, n'est pas concerné).
- Trous connus (contre-revue M0-T01), non couverts par des expressions régulières : indirection (`T=sandbox-apply; make "$T"`), `xargs make`, découpage par guillemets (`make sandbox-ap''ply`), pseudo-terminal (`script`, `pty`). La protection de fond reste l'approbation hors de portée de l'agent, à construire en M3 (T31).
- Complément à proposer séparément : `stop_verify.py` lance `make -f Makefile verify-quick`, pour qu'un `GNUmakefile` écrit par l'agent ne remplace pas la vérification (T32).
