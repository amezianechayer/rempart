# Proposition 0004 : `post_edit_check` ignore les fichiers hors du dépôt

- Date : 2026-09-25
- Statut : proposé, **à appliquer par l'humain** (l'agent n'a pas le droit de modifier le harnais), **après** les propositions 0001, 0002 et 0003
- Patch : `docs/proposals/0004-post-edit-hors-depot.patch`
- Origine : M0-T14, étape de vérification sur copie par `test-author` (voir `docs/STATUS.md`, M0-T14)

## Pourquoi

Le protocole de `/task` fait vérifier le code de référence d'un plan sur une copie du dépôt placée dans le répertoire de travail temporaire de la session, hors du dépôt. Quand un subagent édite un fichier Go de cette copie, le hook `PostToolUse` `.claude/hooks/post_edit_check.py` :

1. calcule `rel(path)`, qui rend le chemin absolu inchangé pour un fichier hors du dépôt ;
2. lance `go vet ./<chemin absolu>` depuis la racine du dépôt, ce qui échoue (« directory not found ») ;
3. bloque l'édition (exit 2) alors que le fichier est correct.

Le hook formate aussi ce fichier avec `gofmt -w`, ce qui n'est pas son rôle hors du dépôt. Contournement actuel : écrire les copies avec des commandes shell au lieu des outils d'édition, moins traçable.

## Ce qui change

| Fichier | Changement |
|---|---|
| `.claude/hooks/post_edit_check.py` | Sortie en 0, sans formatage ni vérification, si le chemin résolu n'est pas sous `PROJECT_DIR` (`CLAUDE_PROJECT_DIR`). Les fichiers du dépôt sont traités comme avant. |
| `.claude/hooks/test_hooks.sh` | 1 cas ajouté : un fichier Go à erreur de syntaxe hors du dépôt est ignoré (0), alors que le même défaut dans le dépôt reste signalé (cas existant « post_edit : erreur de syntaxe signalée »). |

Sécurité : le hook n'est pas une barrière de sécurité (il formate et vérifie) ; les gardes d'écriture restent dans `guard_edit.py` et `guard_bash.py`, inchangés. Le hook Stop continue d'imposer `make verify-quick` sur le dépôt.

## Vérification faite par l'agent

- `git apply --check` du patch sur un clone où 0001, 0002 et 0003 sont appliqués : rc=0, sans décalage.
- Le patch n'a **pas** été exécuté : le garde `guard_bash.py` refuse, à juste titre, toute écriture sous `.claude/hooks/`, même dans une copie. `bash .claude/hooks/test_hooks.sh` reste donc à lancer par l'humain.

## Appliquer

Depuis la racine du dépôt, dans ton terminal (pas via Claude), après 0001, 0002 et 0003 :

```bash
git apply docs/proposals/0004-post-edit-hors-depot.patch
bash .claude/hooks/test_hooks.sh
git add .claude && git commit -m "fix(harness): skip post-edit checks for files outside the repository"
```
