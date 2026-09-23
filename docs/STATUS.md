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

- 2026-09-23 : **M0-T01 `squelette` terminée** (plan `docs/plans/M0-squelette.md`, amendement R1) dans une session cloud (conteneur Linux) :
  - Module `github.com/amezianechayer/rempart`, `go 1.27.1`, govulncheck v1.8.0 par directive `tool` ; 21 domaines de la vision et `internal/archtest` avec `doc.go` ; 5 binaires stub (code 2) ; `policies/{design,iac,runtime,k8s}`, `modules`, `schemas`, `evals`, `web` ; `Makefile` (issu du modèle, `verify-quick` sans réseau ni Docker, OPA seulement si un `.rego` existe, `dev` et `evals` en code 2 nommant M0-T03 et M0-T23, gardes `sandbox-*`) ; `.golangci.yml` v2 (gosec, errorlint, contextcheck, nolintlint strict, gofumpt, `#nosec` neutralisé) ; `README.md` et `docs/SETUP.md` (versions épinglées).
  - Tests : `TestLayoutMatchesVision`, `TestGoDirective`, `TestMakefileTargets`, `TestGolangciConfig` (133 témoins négatifs), écrits par `test-author`, rouges pour la bonne raison avant l'implémentation.
  - Preuves : `make verify-quick` rc=0, aussi avec `GOPROXY=off` ; critères 1 à 8 et C1 à C13 conformes ; `acceptance-verifier` **PASS** (deux passages) ; `security-reviewer` **PASS** (revue puis contre-revue).
  - Amendement R1 (revue sécurité) : variables de l'appelant figées par `override X := $(value X)` (make développait `SCENARIO='$(shell ...)'`), confirmation lue sur `/dev/tty`, liste blanche d'`EVAL`, `nosec: true` pour gosec ; retour journalisé en phase tests pour rendre ces règles mécaniques.
  - Écarts dus au harnais non patché : `git add` des tests avant `phase impl` (porte aveugle aux fichiers d'un dossier non suivi) ; `Makefile` créé en dernier (hook Stop actif dès sa création). Critère 7 prouvé par binaire construit (`go run` rend 1, pas 2) ; critère 8 par motif de directive.
  - Limite d'environnement : `make verify` rouge ici uniquement parce que `vuln.go.dev` est bloqué par la politique réseau de la session cloud (govulncheck) ; tout le reste de `verify` est vert.
  - Documents : menaces T28 à T32 (`docs/02-THREAT-MODEL.md`) ; proposition de harnais `docs/proposals/0003-garde-make-variables.md` (81 cas de test des hooks verts sur clone avec 0001, 0002 et 0003).
  - Incident de revue (sans effet) : lors de la contre-revue, `security-reviewer` a lancé par erreur `make --no-print-directory update-baseline EVAL='$(shell ...)'` et `make sandbox-apply SCENARIO=demo </dev/null` sur le vrai dépôt ; les deux se sont arrêtées aux gardes (code 2), aucun fichier créé, `git status` inchangé. Le garde Bash actuel ne les bloque pas : la proposition 0003 les refuse.

- 2026-09-23 : **M0-T02 `archtest-imports` terminée** (plan `docs/plans/M0-archtest-imports.md`) :
  - `internal/archtest/packages.go` (`LoadPackages` : `go list -json ./...` sans shell, arguments littéraux, `GOFLAGS=-mod=readonly`, `GOWORK=off`, échec fermé) et `rules.go` (`Match`, `Check`, `DefaultRules` : 7 règles, R3 découpée en Anthropic, Temporal, SQL avec `database/sql`) ; R4 autorise `internal/loops` lui-même (sinon le faux de T15 violerait la règle).
  - Tests écrits par `test-author` (rouges sur `undefined:` avant l'implémentation) ; implémentation écrite par l'agent principal d'après le plan, sans reprendre la référence hors dépôt de `test-author`, verte au premier passage.
  - Preuves : critères 1 à 15 conformes (21 sous-tests `TestRuleDetectsViolation`, 38 cas `TestMatch`, `TestRepositoryConforms` sous `-short` en 0,1 s, hors ligne sans réécriture de `go.mod`) ; `make verify-quick` rc=0 ; `security-reviewer` **PASS** ; `acceptance-verifier` FAIL sur la seule lettre de C1, C3 et C5 (décompte du plan faux : le sous-test gelé répète la violation), plan corrigé, puis **PASS** par un second vérificateur.
  - Constat Go 1.27.1 : `go list ./...` sans `go.mod` répond `directory prefix . does not contain main module` (sans mentionner `go.mod`) ; `TestLoadPackagesErrors/no_go_mod` accepte `main module` ou `go.mod`.
  - Menace T33 ajoutée (contournement des règles d'architecture).

- 2026-09-23 : **M0-T05 `tenancy` terminée** (plan `docs/plans/M0-tenancy.md`) :
  - `internal/tenancy/tenant.go` : `ID` (UUID canonique en minuscules, version 4 et variante RFC 9562, sans normalisation, nul et max refusés), `System` = `00000000-0000-8000-8000-000000000001` (UUID version 8, hors de l'espace client), `ParseID`, `WithTenant` (jamais d'écrasement d'un autre tenant : `ErrTenantMismatch`), `FromContext` (revalide la valeur stockée), `Require`, `ErrNilContext` ; clé de contexte non exportée ; messages d'erreur sans donnée.
  - Dépendance de test `pgregory.net/rapid v1.3.0` (MPL-2.0, tests seulement, aucune dépendance de module, absente des binaires).
  - **ADR 0004 proposé** (`docs/decisions/0004-identifiant-de-tenant-et-tenant-systeme.md`) : format des identifiants et tenant système ; **à trancher par l'humain avant la première tâche de M1 qui stocke un identifiant**, avec la condition de la revue sécurité (`ParseCustomerID` qui refuse `System` aux frontières externes).
  - Tests écrits par `test-author` (14 tests, 103 sous-tests, deux propriétés `rapid`), rouges sur `undefined:` ; implémentation conforme au code de référence de la section 5.1.
  - Preuves : 15 critères conformes (critère 8 `go mod graph` et critère 15 corrigés dans le plan : valeurs attendues mal écrites, code conforme) ; mutations M1 à M8 toutes détectées ; `make verify-quick` rc=0 ; `security-reviewer` **PASS** (1 moyen, 3 bas, 19 mutations détectées) ; `acceptance-verifier` **PASS**.
  - Menaces T34 (usurpation du tenant système) et T35 (conversion directe `tenancy.ID(x)`).
  - Note : `go test ./... -rapid.nofailfile` échoue sur les paquets qui n'importent pas rapid (drapeau inconnu) ; le drapeau ne se passe qu'aux paquets qui l'utilisent.

- 2026-09-23 : **M0-T06 `secret-value` terminée** (plan `docs/plans/M0-secret-value.md`, amendement V1) :
  - `internal/secrets/secret` : `Value` et `Bytes` (valeur derrière un pointeur, non comparables) ; `fmt` (tout verbe, drapeau, largeur), `slog`, JSON, XML, texte et templates n'affichent que `[REDACTED]` ; `gob` refuse d'encoder ; tout décodage refusé (`ErrDecodeRefused`, `null` compris) ; `Bytes.Wipe` met à zéro le tableau et les vues rendues, vide toutes les copies (effort, garanties mémoire documentées).
  - **Amendement V1** : la vérification préalable de `test-author` a trouvé une fuite réelle dans le code de référence du plan (`p *[]byte` : `%s` ou `%q` sur un champ non exporté affichait les octets en décimal) ; corrigé par `p **[]byte` avant le gel des tests.
  - Preuves : 14 tests (dont une propriété `rapid` à 10 000 cas), verts sous `-race` ; 17 mutations détectées ; `make verify-quick` rc=0 ; `security-reviewer` **PASS** (3 constats bas, dont la note sur `append` ajoutée au commentaire de `Reveal`) ; `acceptance-verifier` **PASS** (critère 8 et ancres M13, M14 du plan corrigés : défauts de rédaction, code conforme).
  - Menace T36 (contournement du masquage des secrets).

## En cours
`/milestone M0` lancé et découpage validé par l'humain le 2026-09-23 (« validé, chiffrement en M1 ») : 19 tâches (M0-T01 à T15, T19, T20, T22, T23) et étapes humaines H0, D0, H1, H3, H4 dans `docs/plans/M0-overview.md`. Réponses par défaut retenues pour Q1 à Q5. M0-T16, T17, T18 et T21 (ADR 0001) deviennent les premières tâches de M1 (`prompts/M1.md`). Risque résiduel accepté : historique Temporal en clair en M0, sans données client.

Préalables humains (étape H0 du plan) :
1. ~~Valider le découpage et répondre aux questions Q1 à Q5~~ : fait le 2026-09-23.
2. Appliquer les propositions 0001 (harnais), 0002 (CLAUDE.md) puis 0003 (garde make et bac à sable), redémarrer Claude Code. M0-T01 a été faite sans elles (écarts consignés ci-dessus).
3. ~~Trancher les ADR 0001, 0002 et 0003~~ : acceptés le 2026-09-23.
4. ~~Poste Linux, macOS ou WSL2, `bash scripts/check-tools.sh` vert ; `git tag m0-start`~~ : fait le 2026-09-23 dans une session Claude Code cloud (conteneur Linux) à la demande de l'humain (« continue et fais le nécessaire »). Outils installés : Go 1.27.1 (dernière stable), golangci-lint v2.13.2, gofumpt v0.12.0, govulncheck v1.8.0, OPA 1.20.2 ; `bash scripts/check-tools.sh` affiche `Outils requis pour M0 : OK.` ; démon Docker non joignable dans ce conteneur (nécessaire à partir de M0-T03). Tag `m0-start` posé sur `1eca7a7` par l'agent. Jalon courant réglé à M0 (`rempart-state milestone M0`, l'état n'est pas versionné). Le tag n'a pas pu être poussé depuis la session cloud : `git tag m0-start 1eca7a7 && git push origin m0-start` depuis le poste de l'humain.
5. Relire les modifications des skills `loop-engineering`, `intent-to-spec`, `safe-autonomy` et `agent-evals`.
6. Choisir le point d'entrée produit (n'affecte pas M0, mais M1 à M4).

## Reste à faire
- Installer la chaîne d'outils sur le poste principal : `docs/SETUP.md`, puis `bash scripts/check-tools.sh`.
- `ContinueAsNew` avant l'attente d'approbation dans `temporal-loop-skeleton.md` : avec les tâches ADR 0001, au début de M1.
- ADR non encore rédigés (après le choix du point d'entrée) : plan calculé par le runner et approbations signées par des clés du client ; L3 en compilateur déterministe ; pas de mode hébergé au MVP.
- ADR « intégration Git » (T25) à rédiger avant M4 : `security-reviewer` rendra BLOCK en M4 sans lui. Il doit trancher la contradiction entre l'écran E1 de `docs/04-INTERFACE.md` (application Git centrale) et l'invariant « le plan de contrôle ne détient pas d'identifiant d'écriture ».
- Prochaine tâche : `/task` M0-T03 (pile de dev : exige un démon Docker, absent de la session cloud) ; sinon M0-T07, T13 ou T22, qui n'en ont pas besoin.
- Humain : trancher l'ADR 0004 (identifiant de tenant, tenant système) avant M1.
- Tâche de durcissement de `internal/archtest` (revue M0-T02, 3 constats moyens, T33) : fichiers exclus par build tags ou GOOS (`IgnoredGoFiles`), `go.mod` imbriqué, SDK atteint par un module tiers ; en bas : `internal/*/*/{domain,adapters,fake}`, `C` et `unsafe` dans R1, règle « personne n'importe `internal/archtest` ». À faire avant le premier fichier `//go:build` non test ou la première dépendance qui enveloppe un SDK confiné.
- **Avant M3 (création de `scripts/sandbox.sh`), obligatoire** : tâche de durcissement issue de la contre-revue de M0-T01 (plan `docs/plans/M0-squelette.md`, section 0) : confirmation et appel sur une ligne chaînée par `&&`, refus par test du préfixe `-`, de `.IGNORE` et de `MAKEFLAGS`, approbation hors de portée de l'agent (T31).
- Avec M0-T04 au plus tard : règle archtest refusant `GNUmakefile` et `makefile`, `make -f Makefile` dans la CI, et proposition de harnais pour `make -f Makefile` dans le hook Stop (T32).
- Session cloud : autoriser `vuln.go.dev` dans la politique réseau de l'environnement pour que `make verify` (govulncheck) passe ; démon Docker nécessaire à partir de M0-T03 (poste personnel ou environnement qui le fournit).

## Journal
- 2026-09-23 [session de démarrage] Poste de travail Windows sans `python3` ni dépôt git : aucun hook n'a tourné pendant cette session. Travail limité à la documentation et à une proposition de patch testée hors du dépôt. Suite du projet prévue sur le poste personnel, via GitHub.

- 2026-09-23 12:31 [harnais] jalon courant : M0

- 2026-09-23 15:23 [harnais] PHASE FREE (discipline TDD suspendue) : D0 alignement documentaire des ADR 0001 a 0003 acceptes (sans code)

- 2026-09-23 15:23 [harnais] phase : free -> free

- 2026-09-23 17:32 [harnais] jalon courant : M0

- 2026-09-23 17:53 [harnais] phase : free -> tests

- 2026-09-23 18:13 [harnais] phase : tests -> impl

- 2026-09-23 18:29 [harnais] RETOUR EN PHASE TESTS depuis impl : M0-T01 amendement R1 : revue securite (injection make par variables de ligne de commande, confirmation par tube, #nosec) a rendre mecanique dans TestMakefileTargets et TestGolangciConfig

- 2026-09-23 18:29 [harnais] phase : impl -> tests

- 2026-09-23 18:39 [harnais] phase : tests -> impl

- 2026-09-23 18:51 [harnais] PHASE FREE (discipline TDD suspendue) : tâche squelette (M0-T01) terminée

- 2026-09-23 18:51 [harnais] phase : impl -> free

- 2026-09-23 19:20 [harnais] phase : free -> tests

- 2026-09-23 19:32 [harnais] phase : tests -> impl

- 2026-09-23 19:40 [harnais] PHASE FREE (discipline TDD suspendue) : tâche archtest-imports (M0-T02) terminée

- 2026-09-23 19:40 [harnais] phase : impl -> free

- 2026-09-23 22:18 [harnais] phase : free -> tests

- 2026-09-23 22:26 [harnais] phase : tests -> impl

- 2026-09-23 22:32 [harnais] PHASE FREE (discipline TDD suspendue) : tâche tenancy (M0-T05) terminée

- 2026-09-23 22:32 [harnais] phase : impl -> free

- 2026-09-23 22:51 [harnais] phase : free -> tests

- 2026-09-23 23:01 [harnais] phase : tests -> impl

- 2026-09-23 23:08 [harnais] PHASE FREE (discipline TDD suspendue) : tâche secret-value (M0-T06) terminée

- 2026-09-23 23:08 [harnais] phase : impl -> free
