# STATUS

> Tenu à jour par l'agent à chaque fin de tâche et par le harnais. Un BLOCAGE reste affiché au démarrage de session tant qu'il n'est pas marqué « RÉSOLU ».

## Jalon courant
M0 (non démarré)

## Jalons acceptés
aucun

## Fait (avec preuves)
- 2026-09-23 : critique initiale de la spécification, `docs/reviews/2026-09-23-critique-initiale.md`.
- 2026-09-23 : correctif du harnais proposé et testé sur une copie, `docs/proposals/0001-harnais-portable-et-tdd.md`. Preuve : `bash .claude/hooks/test_hooks.sh` sur la copie corrigée, 57 réussis sous Windows (Git Bash, Go 1.16), 48 réussis sous Ubuntu WSL2 (cas Go sautés). **Pas encore appliqué au dépôt.**
- 2026-09-23 : dépôt git initialisé (branche `main`), `.gitattributes` force les fins de ligne LF.

## En cours
Décisions humaines attendues avant `/milestone M0` (détail en fin de `docs/reviews/2026-09-23-critique-initiale.md`) :
1. Appliquer le patch 0001 du harnais.
2. Choisir le point d'entrée produit (lecture seule et preuves sur l'existant, ou feuille de route actuelle).
3. Valider les ADR de départ.

## Reste à faire
- Installer la chaîne d'outils sur le poste principal : `docs/SETUP.md`, puis `bash scripts/check-tools.sh`.
- Rédiger les ADR validés (`/adr`).
- Démarrer M0 (`/milestone M0`).

## Journal
- 2026-09-23 [session de démarrage] Poste de travail Windows sans `python3` ni dépôt git : aucun hook n'a tourné pendant cette session. Travail limité à la documentation et à une proposition de patch testée hors du dépôt. Suite du projet prévue sur le poste personnel, via GitHub.
