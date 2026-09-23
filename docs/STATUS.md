# STATUS

> Tenu à jour par l'agent à chaque fin de tâche et par le harnais. Un BLOCAGE reste affiché au démarrage de session tant qu'il n'est pas marqué « RÉSOLU ».

## Jalon courant
M0 (démarré le 2026-09-23 ; découpage proposé dans `docs/plans/M0-overview.md`, en attente de validation humaine avant la première `/task`)

## Jalons acceptés
aucun

## Fait (avec preuves)
- 2026-09-23 : critique initiale de la spécification, `docs/reviews/2026-09-23-critique-initiale.md`.
- 2026-09-23 : correctif du harnais proposé et testé sur une copie, `docs/proposals/0001-harnais-portable-et-tdd.md`. Preuve : `bash .claude/hooks/test_hooks.sh` sur la copie corrigée, 59 réussis sous Windows (Git Bash, Go 1.16), 50 réussis sous Ubuntu WSL2 (cas Go sautés) ; 59 réussis sur un clone neuf avec 0001 et 0002 appliqués. Protège aussi les baselines rangées par plateforme et modèle (ADR 0002). **Pas encore appliqué au dépôt.**
- 2026-09-23 : dépôt git initialisé (branche `main`), `.gitattributes` force les fins de ligne LF.
- 2026-09-23 : dépôt publié sur https://github.com/amezianechayer/rempart. Visibilité **publique**, choix explicite de l'humain : spec, modèle de menace et stratégie sont lisibles par tous.
- 2026-09-23 : à la demande de l'humain, les commits se terminent par `Co-Authored-By: Ameziane Chayer <amezianechayer9@gmail.com>` ; les 3 premiers commits ont été réécrits en ce sens. Règle proposée pour `CLAUDE.md` : `docs/proposals/0002-claude-md-trailer-commits.md`.
- 2026-09-23 : **skill modifié, à relire** : `loop-engineering` (SKILL.md règles 5 et 8, tests obligatoires ; `references/temporal-loop-skeleton.md`). `AwaitApproval` remplacé par `AwaitApprovals` : un signal invalide ne met plus fin à l'attente, signature de l'approbateur vérifiée par activité, quorum, rôle sécurité, exclusion de l'auteur. Sémantique de stagnation rendue explicite (inchangée). Preuve : `gofmt -e` sur l'extrait Go, sans erreur ; non compilé (SDK Temporal absent du poste).
- 2026-09-23 : **skills modifiés, à relire** :
  - `intent-to-spec` : règle 9 (`tenant_id` jamais produit par le LLM, injecté par le serveur, menace T3), règle 10 (références croisées et CIDR vérifiés en code) ; scénario de référence : VPN `bidirectional: false` (le cluster initie les deux flux, 5432 et 9100).
  - `safe-autonomy/references/risk-rules.yaml` : type de ressource inconnu classé `high` ; `low` seulement si le delta de graphe recalculé est vide et la journalisation seulement renforcée ; nouvelles règles `high` (atteignabilité nouvelle hors conception, réduction de journalisation, version de provider ou de module, politique de clé) ; durcissement `low` hors prod seulement.
  - Preuve : sous WSL, `yaml.safe_load` charge les 12 règles, `jsonschema` (Draft 2020-12) valide le scénario contre `intent-ir-v1.schema.json`.
- 2026-09-23 : ADR rédigés par le subagent `architect`, statut **proposé**, relus par l'agent principal :
  - `docs/decisions/0001-chiffrement-payloads-temporal.md` : payloads Temporal chiffrés AES-256-GCM par tenant (enveloppe OpenBao Transit), sans repli en clair, références chiffrées pour les gros objets, versioning par `workflow.GetVersion` et tests de rejeu dès M0.
  - `docs/decisions/0002-model-provider-multi-plateforme.md` : `ModelProvider` minimal (appel structuré sans outils, appel avec outils), route explicite par tenant sans défaut, résidence UE et rétention contrôlées à chaque appel, baseline d'evals par couple plateforme et modèle ; M0 : service, faux déterministe, adaptateur Anthropic direct.
  - `docs/decisions/0003-stockage-du-graphe.md` : PostgreSQL relationnel sous RLS forcé, calculs de graphe en mémoire en Go, image PostgreSQL standard dès M0, critères de réévaluation chiffrés.
  - Faits externes marqués « à revérifier » dans chaque ADR ; seuils proposés, pas mesurés.

## En cours
`/milestone M0` lancé : découpage en 23 tâches (M0-T01 à M0-T23) et étapes humaines H0, D0, H1, H3, H4 dans `docs/plans/M0-overview.md` (rédigé par `architect`, relu par l'agent principal). Aucune `/task` avant la validation humaine.

Préalables humains (étape H0 du plan) :
1. Valider le découpage et répondre aux questions Q1 à Q5 (section 12 du plan).
2. Appliquer les propositions 0001 (harnais) et 0002 (CLAUDE.md), redémarrer Claude Code.
3. Valider (ou amender) les ADR 0001, 0002 et 0003 ; en cas de refus, section 9 du plan.
4. Poste Linux, macOS ou WSL2, dépôt dans `~/rempart`, `bash scripts/check-tools.sh` vert ; `git tag m0-start`.
5. Relire les modifications des skills `loop-engineering`, `intent-to-spec` et `safe-autonomy`.
6. Choisir le point d'entrée produit (n'affecte pas M0, mais M1 à M4).

## Reste à faire
- Installer la chaîne d'outils sur le poste principal : `docs/SETUP.md`, puis `bash scripts/check-tools.sh`.
- Une fois les ADR acceptés (listé dans leur section « Conséquences ») : ajouter les critères de 0001 à `prompts/M0.md` ; `ContinueAsNew` avant l'attente d'approbation dans `temporal-loop-skeleton.md` ; baseline par couple plateforme et modèle dans le skill `agent-evals` ; amender `docs/00-VISION.md` §4 et `MASTER_PROMPT.md` (fin d'AGE, `ModelProvider` multi-plateforme) ; `security-reviewer` intègre les menaces nouvelles au modèle de menace.
- ADR non encore rédigés (après le choix du point d'entrée) : plan calculé par le runner et approbations signées par des clés du client ; L3 en compilateur déterministe ; pas de mode hébergé au MVP.
- Après H0 : D0 (alignement documentaire des ADR acceptés), puis `/task` M0-T01.

## Journal
- 2026-09-23 [session de démarrage] Poste de travail Windows sans `python3` ni dépôt git : aucun hook n'a tourné pendant cette session. Travail limité à la documentation et à une proposition de patch testée hors du dépôt. Suite du projet prévue sur le poste personnel, via GitHub.

- 2026-09-23 12:31 [harnais] jalon courant : M0
