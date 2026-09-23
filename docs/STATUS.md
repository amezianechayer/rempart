# STATUS

> Tenu à jour par l'agent à chaque fin de tâche et par le harnais. Un BLOCAGE reste affiché au démarrage de session tant qu'il n'est pas marqué « RÉSOLU ».

## Jalon courant
M0 (démarré le 2026-09-23 ; découpage **validé** le 2026-09-23 avec l'amendement A1 : 19 tâches, chiffrement Temporal reporté au début de M1 ; voir `docs/plans/M0-overview.md` section 0)

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
- 2026-09-23 : ADR rédigés par le subagent `architect`, relus par l'agent principal, **acceptés par l'humain le 2026-09-23** (0001 mis en œuvre au début de M1) :
  - `docs/decisions/0001-chiffrement-payloads-temporal.md` : payloads Temporal chiffrés AES-256-GCM par tenant (enveloppe OpenBao Transit), sans repli en clair, références chiffrées pour les gros objets, versioning par `workflow.GetVersion` et tests de rejeu dès M0.
  - `docs/decisions/0002-model-provider-multi-plateforme.md` : `ModelProvider` minimal (appel structuré sans outils, appel avec outils), route explicite par tenant sans défaut, résidence UE et rétention contrôlées à chaque appel, baseline d'evals par couple plateforme et modèle ; M0 : service, faux déterministe, adaptateur Anthropic direct.
  - `docs/decisions/0003-stockage-du-graphe.md` : PostgreSQL relationnel sous RLS forcé, calculs de graphe en mémoire en Go, image PostgreSQL standard dès M0, critères de réévaluation chiffrés.
  - Faits externes marqués « à revérifier » dans chaque ADR ; seuils proposés, pas mesurés.
- 2026-09-23 : étape D0 (alignement documentaire, phase free journalisée, sans code) :
  - `prompts/M0.md` : critères 6 à 11 issus des ADR 0002 et 0003 ; ceux de 0001 sont dans `prompts/M1.md`.
  - `docs/00-VISION.md` §4 et `MASTER_PROMPT.md` : pile amendée (PostgreSQL sous RLS et graphe en Go, `ModelProvider` multi-plateforme), dossiers d'outillage ajoutés (Q2) ; `MASTER_PROMPT.md` déclaré instantané, `docs/` et `prompts/` font foi.
  - **Skill modifié, à relire** : `agent-evals` (baseline par couple plateforme et modèle, suites de fumée par région, route sans baseline refusée à partir de M1).
  - Preuves : `grep -c 'Apache AGE' docs/00-VISION.md MASTER_PROMPT.md` vaut 0 et 0 ; `grep -c 'baseline/' .claude/skills/agent-evals/SKILL.md` vaut 1 ; `grep -c 'TestHistoryHasNoPlaintext' prompts/M1.md` vaut 1.
  - Modèle de menace : revue `security-reviewer` des ADR 0001 à 0003, **verdict PASS avec réserves** (7 constats moyens, 8 bas, aucun critique ni haut). `docs/02-THREAT-MODEL.md` : menaces T13 à T27 ajoutées, vérifications de T1, T3, T5 et T7 complétées, §4.1 risques résiduels acceptés (historique Temporal en clair en M0), §4.2 menaces à formaliser avec les ADR runner. Réserves inscrites dans chaque ADR (section « Réserves de la revue sécurité ») ; gardes de début de M1 dans `prompts/M1.md` ; amendement A2 du plan M0 (`TestCheckPolicyRejectsEmptyResidency` dans M0-T08). Preuve : 27 lignes de menace, 5 colonnes chacune, contrôle par script.

## En cours
`/milestone M0` lancé et découpage validé par l'humain le 2026-09-23 (« validé, chiffrement en M1 ») : 19 tâches (M0-T01 à T15, T19, T20, T22, T23) et étapes humaines H0, D0, H1, H3, H4 dans `docs/plans/M0-overview.md`. Réponses par défaut retenues pour Q1 à Q5. M0-T16, T17, T18 et T21 (ADR 0001) deviennent les premières tâches de M1 (`prompts/M1.md`). Risque résiduel accepté : historique Temporal en clair en M0, sans données client.

Préalables humains restants (étape H0 du plan) avant `/task` M0-T01 :
1. ~~Valider le découpage et répondre aux questions Q1 à Q5~~ : fait le 2026-09-23.
2. Appliquer les propositions 0001 (harnais) et 0002 (CLAUDE.md), redémarrer Claude Code.
3. ~~Trancher les ADR 0001, 0002 et 0003~~ : acceptés le 2026-09-23.
4. Poste Linux, macOS ou WSL2 (décision : M0 se code sur le poste personnel), dépôt dans `~/rempart`, `bash scripts/check-tools.sh` vert ; `git tag m0-start`.
5. Relire les modifications des skills `loop-engineering`, `intent-to-spec`, `safe-autonomy` et `agent-evals`.
6. Choisir le point d'entrée produit (n'affecte pas M0, mais M1 à M4).

## Reste à faire
- Installer la chaîne d'outils sur le poste principal : `docs/SETUP.md`, puis `bash scripts/check-tools.sh`.
- `ContinueAsNew` avant l'attente d'approbation dans `temporal-loop-skeleton.md` : avec les tâches ADR 0001, au début de M1.
- ADR non encore rédigés (après le choix du point d'entrée) : plan calculé par le runner et approbations signées par des clés du client ; L3 en compilateur déterministe ; pas de mode hébergé au MVP.
- ADR « intégration Git » (T25) à rédiger avant M4 : `security-reviewer` rendra BLOCK en M4 sans lui. Il doit trancher la contradiction entre l'écran E1 de `docs/04-INTERFACE.md` (application Git centrale) et l'invariant « le plan de contrôle ne détient pas d'identifiant d'écriture ».
- Après H0 (poste personnel) : `/resume`, puis `/task` M0-T01.

## Journal
- 2026-09-23 [session de démarrage] Poste de travail Windows sans `python3` ni dépôt git : aucun hook n'a tourné pendant cette session. Travail limité à la documentation et à une proposition de patch testée hors du dépôt. Suite du projet prévue sur le poste personnel, via GitHub.

- 2026-09-23 12:31 [harnais] jalon courant : M0

- 2026-09-23 15:23 [harnais] PHASE FREE (discipline TDD suspendue) : D0 alignement documentaire des ADR 0001 a 0003 acceptes (sans code)

- 2026-09-23 15:23 [harnais] phase : free -> free
