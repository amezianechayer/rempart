# Proposition 0006 : `guard_bash` empêche l'affichage des secrets de la pile de dev

- Date : 2026-09-27
- Statut : proposé, **à appliquer par l'humain** (l'agent n'a pas le droit de modifier le harnais), après 0001 à 0005
- Patch : `docs/proposals/0006-garde-secrets-pile-dev.patch`
- Origine : M0-T03 `pile-dev`, menace N7 du plan `docs/plans/M0-pile-dev.md` (T76 de `docs/02-THREAT-MODEL.md`), décision retenue sur délégation de l'humain

## Pourquoi

La pile de dev (M0-T03) garde ses secrets dans `.env.dev` (droits 600, ignoré par Git) et les passe aux conteneurs par variables. Tout ce que l'agent affiche entre dans son contexte, donc chez le fournisseur du modèle. Plusieurs commandes courantes afficheraient ces valeurs :

- `cat .env.dev`, `grep ... .env.dev`, `source .env.dev` ;
- `docker compose config` (le fichier compose avec les secrets substitués) ;
- `docker inspect <conteneur>` (section `Env`) ;
- `docker compose exec <service> env` ;
- `docker compose logs openbao` (la bannière du mode dev affiche le jeton root ; les journaux d'OpenBao sont déjà coupés, la règle double cette protection).

`.claude/settings.json` refuse déjà la lecture de `.env.*` par l'outil Read, pas par le shell.

## Ce qui change

| Fichier | Changement |
|---|---|
| `.claude/hooks/guard_bash.py` | Quatre règles (T76) : lecture directe de `.env.dev` par un lecteur de fichier ou par `source`/`.` ; `docker compose config` sauf `--images`, `--services`, `--volumes`, `--profiles`, `--networks` ou sortie filtrée par `jq` ; `docker inspect` sans `--format` ; `docker exec`/`run` suivi de `env`, `printenv`, `export`, `set`, et `docker logs` d'OpenBao. |
| `.claude/hooks/test_hooks.sh` | 15 cas : 8 refus, 7 formes permises (`git check-ignore .env.dev`, `stat -c %a .env.dev`, `bash scripts/dev-env.sh ensure`, `config --images`, `config --format json \| jq ...`, `inspect --format`, `logs postgres`). |

Les commandes du flux normal restent permises : `make dev`, `make dev-down`, `bash scripts/dev-env.sh run go test ...`, critères d'acceptation du plan.

Limite : c'est un filtre, pas un bac à sable (voir l'en-tête de `guard_bash.py`) ; un programme écrit pour l'occasion peut toujours lire le fichier. Les autres filets restent la revue et le test `TestDevStackLogsHaveNoSecrets`.

## Vérification faite par l'agent

- `git apply --check` du patch sur `main-6cpq6q` : rc=0.
- Expressions régulières éprouvées hors harnais sur les 14 commandes de test qui mentionnent `.env.dev` ou `docker` : 14 résultats attendus sur 14.
- Non exécuté : le garde refuse, à juste titre, toute écriture sous `.claude/hooks/`. `bash .claude/hooks/test_hooks.sh` reste à lancer par l'humain.

## Remarque sur une règle existante

`go test ... -skip` est refusé même pour exclure un test lent le temps d'une vérification (signalé par `test-author` en M0-T03). Rien n'est proposé : la règle est volontairement stricte et le contournement est simple (lancer sans filtre).

## Appliquer

Depuis la racine du dépôt, dans ton terminal (pas via Claude) :

```bash
git apply docs/proposals/0006-garde-secrets-pile-dev.patch
bash .claude/hooks/test_hooks.sh
git add .claude && git commit -m "fix(harness): block commands that print dev stack secrets"
```
