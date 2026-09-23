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
- 2026-09-23 : dépôt publié sur https://github.com/amezianechayer/rempart. Visibilité **publique**, choix explicite de l'humain : spec, modèle de menace et stratégie sont lisibles par tous.
- 2026-09-23 : à la demande de l'humain, les commits se terminent par `Co-Authored-By: Ameziane Chayer <amezianechayer9@gmail.com>` ; les 3 premiers commits ont été réécrits en ce sens. Règle proposée pour `CLAUDE.md` : `docs/proposals/0002-claude-md-trailer-commits.md`.
- 2026-09-23 : **skill modifié, à relire** : `loop-engineering` (SKILL.md règles 5 et 8, tests obligatoires ; `references/temporal-loop-skeleton.md`). `AwaitApproval` remplacé par `AwaitApprovals` : un signal invalide ne met plus fin à l'attente, signature de l'approbateur vérifiée par activité, quorum, rôle sécurité, exclusion de l'auteur. Sémantique de stagnation rendue explicite (inchangée). Preuve : `gofmt -e` sur l'extrait Go, sans erreur ; non compilé (SDK Temporal absent du poste).
- 2026-09-23 : **skills modifiés, à relire** :
  - `intent-to-spec` : règle 9 (`tenant_id` jamais produit par le LLM, injecté par le serveur, menace T3), règle 10 (références croisées et CIDR vérifiés en code) ; scénario de référence : VPN `bidirectional: false` (le cluster initie les deux flux, 5432 et 9100).
  - `safe-autonomy/references/risk-rules.yaml` : type de ressource inconnu classé `high` ; `low` seulement si le delta de graphe recalculé est vide et la journalisation seulement renforcée ; nouvelles règles `high` (atteignabilité nouvelle hors conception, réduction de journalisation, version de provider ou de module, politique de clé) ; durcissement `low` hors prod seulement.
  - Preuve : sous WSL, `yaml.safe_load` charge les 12 règles, `jsonschema` (Draft 2020-12) valide le scénario contre `intent-ir-v1.schema.json`.

## En cours
Décisions humaines attendues avant `/milestone M0` (détail en fin de `docs/reviews/2026-09-23-critique-initiale.md`) :
1. Appliquer les propositions 0001 (harnais) et 0002 (CLAUDE.md).
2. Choisir le point d'entrée produit (lecture seule et preuves sur l'existant, ou feuille de route actuelle).
3. Valider les ADR de départ (`docs/decisions/`, statut « proposé »).
4. Relire la modification du skill `loop-engineering`.

## Reste à faire
- Installer la chaîne d'outils sur le poste principal : `docs/SETUP.md`, puis `bash scripts/check-tools.sh`.
- ADR non encore rédigés : plan calculé par le runner et approbations signées par des clés du client ; L3 en compilateur déterministe ; pas de mode hébergé au MVP.
- Démarrer M0 (`/milestone M0`).

## Journal
- 2026-09-23 [session de démarrage] Poste de travail Windows sans `python3` ni dépôt git : aucun hook n'a tourné pendant cette session. Travail limité à la documentation et à une proposition de patch testée hors du dépôt. Suite du projet prévue sur le poste personnel, via GitHub.
