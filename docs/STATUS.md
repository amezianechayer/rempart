# STATUS

> Tenu à jour par l'agent à chaque fin de tâche et par le harnais. Un BLOCAGE reste affiché au démarrage de session tant qu'il n'est pas marqué « RÉSOLU ».

## Jalon courant
M1 (démarré le 2026-09-30 ; découpage `docs/plans/M1-overview.md` **validé** par l'humain le 2026-09-30 : options recommandées Q1 à Q5, plus vrais LLM multi-fournisseurs, voir « En cours »). M0 accepté le 2026-09-30, tag `m0-done` sur `6d93551`.

## Jalons acceptés

### M0 ACCEPTÉ (2026-09-30)

Tête vérifiée : `b964f73` (branche `main-6cpq6q`, PR #5). Tag proposé : `m0-done`, posé par l'humain.

- **`acceptance-verifier` (jalon)** : critères 2 à 11 de `prompts/M0.md` PASS par exécution réelle (boucles : convergence, stagnation, budget, délai d'approbation ; rédacteur et schéma ; pile de dev et démo `make demo` ; evals comparées à la baseline ; faux LLM déterministe ; routage et rétention ; contrat du fournisseur et résidence UE contre `httptest` ; confinement du SDK Anthropic ; image PostgreSQL officielle épinglée ; pas d'Apache AGE). Critère 1 PASS en local (`make -f Makefile verify` rc=0) et **en CI** : exécution 36731420003 du workflow `verify` sur `b964f73`, conclusion `success` (lint, tests, evals ciblées `demo` code 0 sans régression, intégration contre la pile, archtest, govulncheck « No vulnerabilities found »). Aucune triche détectée.
- **`security-reviewer` (jalon, `m0-start..HEAD`)** : **PASS**, aucun constat critique ou haut ; obligations (cd) à (cg) pour M1.
- `make -s -f Makefile evals EVAL=all` : suite `demo`, code 0, `regressions_vs_baseline: []` ; baseline `evals/demo/baseline/fake/fake-model-v1.json` écrite et commitée par l'humain (`5fc5d25`).
- Écarts acceptés par l'humain : périmètre réduit de M0-T23 (étape A reportée à M1), mode accéléré des revues, identité GitHub distincte de l'agent refusée (risque accepté), (bq) et (br) reportées à M1, code 2 au lieu de 3 pour `make evals` sans baseline.
- Décisions humaines encore ouvertes, sans effet sur les critères : ADR 0005 (proposé), relecture du skill `loop-engineering`, décisions prises sur délégation (section « En cours »).

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

- 2026-09-24 : **M0-T07 `redaction` close avec réserves** (plan `docs/plans/M0-redaction.md`, amendements V1 à V3 et section « Clôture avec réserves ») :
  - `internal/llm/redact` : rédacteur déterministe (16 familles, règles de forme et à clé, exemptions étroites, placeholders opaques, paires `name`/`value`, coût linéaire) ; 17 tests (85 cas positifs, 31 négatifs, propriétés `rapid`), `make verify-quick` vert.
  - Parcours : le code de référence du plan fuyait (V1, 2 fuites trouvées par `rapid` avant le gel) ; revue sécurité BLOCK (V2 : 4 hautes, 5 moyennes), corrigées (V3) ; contre-revue BLOCK (1 haute : paire JSON `name`/`value` perdue si une chaîne contient `{` ; 3 moyennes ; 3 basses). Acceptation : critères conformes (décomptes du plan à lire avec V3), 22 mutations et une par constat détectées.
  - **Même échec deux fois** : options présentées à l'humain, qui a délégué le choix ; option retenue par l'agent : clore avec risque résiduel accepté (aucun modèle réel en M0), constats ouverts reportés en garde obligatoire de `prompts/M1.md` avant le premier appel réel, avec une conception différente (détection structurée, ADR).
  - Écarts de protocole consignés : la correction V3 a été écrite par `test-author` sur copie puis appliquée par l'agent principal (indépendance compensée par la contre-revue et l'acceptation) ; fixture de webhook Slack reformulée après un refus de la protection de push GitHub (retour journalisé en phase tests, `--allow-green`).
  - Menaces T37 à T39.

- 2026-09-24 : **M0-T08 `llm-contrat` terminée** (plan `docs/plans/M0-llm-contrat.md`, amendement V1) :
  - `internal/llm/domain` (bibliothèque standard seulement, R1) : types du contrat, `Part` exactement un des deux, `Request.Validate`, `HasUntrusted`, `RenderUntrusted` (contenu échappé, aucune balise possible, `SourceID` filtré), `RequestHash` (JSON canonique versionné), `CheckPolicy` (résidence et rétention vides ou inconnues refusées, amendement A2 ; liste blanche UE ; modèle épinglé exigé par plateforme ; échec fermé), 8 erreurs sentinelles ; `internal/llm/ports` : interfaces `ModelProvider` et `RouteResolver` (sans route par défaut).
  - Code de référence du plan vérifié sur copie par `test-author` avant gel (aucun défaut) ; 16 tests, 24 mutations détectées ; `make verify-quick` rc=0 ; `security-reviewer` **PASS** avec réserves ; `acceptance-verifier` **PASS**.
  - **À revérifier** (étape I0 impossible, documentation AWS et Google refusée par le proxy) : régions UE Bedrock et Vertex, formats d'identifiants de modèle, et surtout les destinations du profil d'inférence Bedrock `eu.` (doute de la revue : `eu-central-2`, Zurich, hors UE). À faire avant tout adaptateur Bedrock ou Vertex.
  - Menaces T40 (route vérifiée et route appelée distinctes), T41 (faux fournisseur hors test), T42 (délimiteur statique, homoglyphes).

- 2026-09-24 : **M0-T09 `llm-schema-prompts` terminée avec réserves** (plan `docs/plans/M0-llm-schema-prompts.md`) :
  - `internal/llm/schema` : `CompileSchema` (Draft 2020-12, profil strict : liste blanche de mots-clés, `additionalProperties: false` et `required` exhaustif, `$ref` limité à `#/$defs/...`, chargeur qui refuse tout accès fichier ou réseau), `Validate` (taille, UTF-8, clés en double, données après le JSON, nombres, profondeur ; erreurs donnant le chemin sans le contenu), `Raw` ; `internal/llm/prompts` : `Prompt`, `LoadFS`, `Load` (identifiant `<nom>.v<N>` vérifié avant tout accès, hash SHA-256 avec séparation de domaine et préfixes de longueur), FS embarqué vide jusqu'à M0-T19.
  - Dépendance `github.com/santhosh-tekuri/jsonschema/v6 v6.0.3` (Apache 2.0 ; dépendances `dlclark/regexp2`, `golang.org/x/text` v0.14.0 ; aucun import réseau ni exécution de processus ; motifs `pattern` évalués par le moteur RE2 de Go).
  - Code de référence du plan vérifié sur copie avant gel (aucun défaut) ; 16 tests, 18 mutations détectées ; critère 3 de `prompts/M0.md` couvert par `TestValidateRejectsOutOfSchema` (`TestOutOfSchemaRejected`, critère 6, relève de M0-T11) ; `make verify-quick` rc=0.
  - `security-reviewer` **PASS** avec réserve (moyenne) : le contrôle de rigueur ne parcourt pas les clés sœurs d'un `enum`, `anyOf`, `oneOf` ou d'un type scalaire (un mot-clé hors liste peut y figurer ; une sortie non conforme reste rejetée) ; (basse) `LoadFS` lit un fichier entier avant le contrôle de taille et suit les liens d'un FS non embarqué. À corriger avant le premier prompt réel (M0-T19). Menace T43.
  - `acceptance-verifier` : tout conforme sauf le critère `go tool govulncheck`, **invérifiable ici** (`vuln.go.dev` bloqué par le proxy) : à relancer par l'humain avec `make verify`.

- 2026-09-24 : **M0-T10 `llm-fake` terminée** (plan `docs/plans/M0-llm-fake.md`, amendement V1) :
  - `internal/llm/fake` : `Provider` déterministe à l'octet (enregistrements par `PromptID` et `RequestHash` prioritaires, scripts séquentiels par `PromptID`, jamais de réponse par défaut : `ErrNoRecording`, `ErrScriptExhausted`) ; ordre des contrôles : compteur, `ctx`, route (plateforme `fake` sans région), refus de tout `UntrustedBlock` par `WithTools` avant `Validate` et avant capture ; `Invocations()`, `Calls()`, `Requests()` (copies profondes, route reçue exposée pour T40) ; `Capabilities` par modèle, modèle inconnu : rétention exigée ; `LoadOptions` (JSON borné, champs inconnus refusés) ; `StaticResolver` sans route par défaut (`ErrNoRoute`), clés vérifiées par `ParseID`, copie défensive. Aucune journalisation, erreurs sans valeur d'entrée.
  - Code de référence vérifié sur copie avant gel (un seul écart de formatage gofumpt, amendement V1) ; 16 tests sous `-race`, 18 mutations détectées ; `TestFakeDeterministic` (critère 6 de M0) ; `make verify-quick` rc=0 ; `security-reviewer` **PASS** (3 constats bas : `LoadOptions` accepte un script vide, une étape vide et des clés en double ou de casse différente ; à durcir avec le décodage strict de T43 quand le faux chargera des fichiers en M0-T20) ; `acceptance-verifier` **PASS**.

- 2026-09-24 : **M0-T11 `llm-client` terminée** (plan `docs/plans/M0-llm-client.md`, amendement V1) :
  - `internal/llm` : service `Client` (`NewClient`, `Structured`, `WithTools`, `Config`, `Result`, `Trace`). Ordre : tenant du contexte, `ctx`, refus d'un bloc non fiable avec outils, `Validate`, budget de tokens, borne de 1 Mio avant rédaction, outils, prompt chargé et hash vérifié (tous sans I/O) ; puis une seule résolution de route, refus de `PlatformFake` sauf `Config.AllowFakeRoute` explicite (T41), `CheckPolicy`, rédaction des messages (secret dans le prompt système ou un outil : refus), appel avec exactement la route vérifiée (T40), comparaison stricte du modèle déclaré, validation par schéma avec correction bornée (le message de correction ne reprend pas la sortie). Erreurs opaques, causes enveloppées, aucune journalisation.
  - Critères de `prompts/M0.md` couverts : 3 (avec M0-T07 et T09), 6 (`TestFakeDeterministic`, `TestOutOfSchemaRejected`), 7 (`TestNoRouteNoCall`, `TestRetentionZeroRejectsRetentionModel`, `TestUntrustedBlockRejectedWithTools`, `TestModelMismatchRejected`), plus `TestServicePassesCheckedRoute` (T40) et `TestFakeRouteRefusedByDefault` (T41). Critères 8 et 9 : M0-T12.
  - Code de référence vérifié sur copie avant gel (aucun défaut ; 3 mutations reformulées pour compiler, amendement V1) ; 19 tests sous `-race`, 28 mutations détectées ; `make verify-quick` rc=0 ; `security-reviewer` **PASS** avec réserves ; `acceptance-verifier` **PASS**.
  - Réserves de la revue : (moyenne) `InputSchema` des outils et schéma du prompt non contrôlés par le rédacteur (T44) ; (basses) `Usage` du fournisseur non vérifié (T45), liste d'outils non copiée après contrôle, texte rédigé pouvant dépasser 1 Mio.
- 2026-09-24 : **M0-T12 `llm-anthropic` terminée** (plan `docs/plans/M0-llm-anthropic.md`, amendement V1) :
  - `internal/llm/adapters/anthropic` : adaptateur `ModelProvider` sur anthropic-sdk-go v1.75.0 (MIT, épinglé en `834edd8`, sous-paquets bedrock, vertex et aws non importés). Client construit avec `option.WithoutEnvironmentDefaults()` (T46), client HTTP sans redirection ni proxy d'environnement et `Timeout` explicite (T47), `MaxRetries` 0 à 3, URL explicite obligatoire, clé `secret.Value` révélée une seule fois, `*sdk.Error` remplacée par `APIError{StatusCode, RequestID}` opaque (T48), refus avant I/O (plateforme, région, non fiable avec outils, requête invalide, contexte annulé), `output_config` json_schema et outils `strict`, `stop_reason` en liste blanche, `Usage` borné (T45 soldée), `Response.Model` lu dans la réponse.
  - `internal/llm/domain/policy.go` : identifiants de modèle non datés acceptés (`claude-opus-5`, Bedrock `eu.anthropic.claude-opus-5`, Vertex nu), alias `latest`, `preview` et formes libres toujours refusés (41 cas).
  - Critères de `prompts/M0.md` couverts : 8 (`TestProviderContract`, `TestResidencyEUBlocksAnthropicDirect`, `TestNoSecretInOutgoingRequest`, plus `TestAPIKeyOnlyInHeader`, `TestResponseMapping`, `TestNewValidatesConfig`), 9 (règle `sdk-confine-anthropic`).
  - Code de référence vérifié sur copie avant gel (`provider.go` sans défaut ; jeton `preview` redondant retiré, amendement V1) ; 15 mutations sur 15 détectées ; `-race` vert ; `make verify-quick` rc=0 ; `security-reviewer` **PASS** avec conditions ; `acceptance-verifier` **FAIL** sur le seul `govulncheck` (proxy : `vuln.go.dev` Forbidden), tous les autres critères PASS : clôture avec cette limite d'environnement, comme M0-T09.
  - Conditions de la revue (à faire avant M0-T20 et avant tout adaptateur Bedrock ou Vertex) : (moyenne) regex trop larges, `claude-sonnet-4-5` (alias mobile documenté) et familles libres acceptés (T51) ; (moyenne) attente `Retry-After` sans délai global (T50) ; (basses) métadonnées de réponse non validées (T52), `Transport` injecté pouvant réactiver le proxy (T47), `tool_use` accepté sans outils, corps de réponse sans borne (T49). Menaces T46 à T52 ajoutées à `docs/02-THREAT-MODEL.md`.

- 2026-09-24 : **M0-T13 `loop-findings` terminée** (plan `docs/plans/M0-loop-findings.md`, amendement V1) :
  - `internal/loops/domain/findings.go` (bibliothèque standard seulement) : `Severity.Weight` (100, 20, 5, 1, 0 ; inconnue : 100), `Sort` (copie, ordre total : poids, gravité, fichier, ligne, code, ressource, source, message), `Fingerprint` (SHA-256 hex des couples code et ressource de gravité medium ou plus, inconnue incluse, triés, dédoublonnés, encodés en netstring contre les collisions ; liste vide : SHA-256 de l'entrée vide), `Score` (somme des poids, doublons compris), `Top`.
  - 8 tests dont deux propriétés `rapid` ; code de référence identique au plan, vérifié sur copie ; 10 mutations sur 10 détectées (M6 et M10 réécrites pour compiler, amendement V1) ; `make verify-quick` rc=0 ; revue sécurité non requise (fiche) ; `acceptance-verifier` : tous les critères PASS, FAIL sur le seul `make verify` (govulncheck, `vuln.go.dev` Forbidden), clôture avec cette limite d'environnement comme M0-T09 et M0-T12.
  - Pour M0-T14 : une empreinte vide répétée (échec sans finding medium ou plus) vaut stagnation, à tester ; une montée de gravité ne change pas l'empreinte, surveiller aussi `Score` ; l'encodage est figé (rejeu Temporal). Proposition : reporter netstring, dédoublonnage et ordre total dans le skill `loop-engineering` (`normalized-findings.md`), modification à signaler ici.

- 2026-09-25 : **M0-T14 `runloop` terminée** (plan `docs/plans/M0-runloop.md`, amendements V1, V2, V3) :
  - `internal/loops/{spec.go,runloop.go}` : workflow Temporal générique `RunLoop` (proposer, vérifier, diagnostiquer), sans domaine. Spécification validée et bornée (itérations, tokens, temps, stratégies, `ActivityTimeout`, `EscalateAfter` au plus 10, vérificateur distinct du proposeur ; refus non rejouable `InvalidLoopSpec` avant toute activité). Temps contrôlé par `workflow.Now` avant chaque activité ; tokens déclarés bornés ; empreinte et score recalculés par la boucle ; OK avec finding bloquant, candidat vide ou `null`, échec sans finding : `invalid_response` ; stagnation (défauts 2 puis 3) ; meilleur candidat au plus petit score ; proposeur à une tentative Temporal, reprise dans la boucle (3 échecs consécutifs au plus), tokens des échecs lus dans `ProposeFailure` et comptés ; vérificateur repris par Temporal (3 tentatives) ; échec d'activité : escalade `activity_failed` avec meilleur candidat et trace, erreur nil.
  - Dépendances (commit `e61bb1a`) : `go.temporal.io/sdk` v1.49.0 et `workflowcheck` v0.5.0 (directive `tool`, MIT), `make arch-test` lance `go tool workflowcheck ./internal/loops/...`. Montées imposées par MVS : `golang.org/x/text` v0.42.0 (le plan attendait v0.41.0), `google.golang.org/grpc` v1.83.2, `google.golang.org/protobuf` v1.36.11, `genproto/googleapis/rpc`, `gopkg.in/yaml.v2` v2.4.0 ; testify v1.11.1 et le SDK en dépendances directes. Liés au binaire via `sdk/internal` : `facebookgo/clock` (2015) et `golang/mock` (archivé).
  - Critère 2 de `prompts/M0.md`, première partie : 18 tests `TestRunLoop` (14 de la fiche plus 4 de V2), `-race` vert, `workflowcheck` muet (contrôle négatif : `time.Now` injecté détecté), 27 mutations sur 27 détectées, `make verify-quick` rc=0.
  - Revues : `security-reviewer` PASS conditionné (constats moyens : tokens des échecs non comptés, candidat vide pouvant converger, échec sans finding promu meilleur), corrigés par V2 et V3, seconde revue **PASS** ; `acceptance-verifier` **PASS** (12 critères) ; `make verify` bloqué au seul `govulncheck` (`vuln.go.dev` 403), à lancer par l'humain.
  - Menaces : T53, T54, T55 ajoutées ; T10, T16, T45 révisées (`docs/02-THREAT-MODEL.md`).

- 2026-09-25 : **M0-T15 `approvals` terminée** (plan `docs/plans/M0-approvals.md`, amendement V1 ; puce V4 de `docs/plans/M0-runloop.md`) :
  - `internal/loops/approvals.go` : `AwaitApprovals` (signal reçu brut puis décodé strictement, 8 Kio, champs exacts ; hash de 64 hex comparé à l'octet ; identités canoniques ; ordre : décodage, hash, auteur exclu (approbation ou refus), doublon, vérification par activité (une tentative, 30 s), refus authentifié qui arrête, place réservée au rôle sécurité ; quorum de `Required` approbateurs distincts ; inondation bornée (`signal_flood`) ; timeout : `timed_out`, rien de retenu ; annulation : erreur d'annulation). `internal/loops/fake/approvals.go` : vérificateur déterministe sans clé (netstrings, SHA-256), tests et `cmd/` en `-dev` seulement. `RunLoop` rend l'annulation au lieu d'escalader : **obligation (b) de M0-T14 soldée**.
  - `workflowcheck.config.yaml` : `(*encoding/json.Decoder).Decode` déclaré déterministe (Go 1.27 passe par `encoding/json/v2`) ; `arch-test` lance `workflowcheck -config` ; contrôles négatifs (time.Now, map itérée) toujours signalés.
  - **Critère 2 de `prompts/M0.md` couvert** (avec M0-T14) : 7 tests groupés PASS. 16 tests `TestAwaitApprovals`, 19 `TestRunLoop`, 2 `TestFake`, `-race` vert ; 25 mutations sur 25 (plus 27 sur 27 de M0-T14) ; 43 mutations exploratoires, 39 détectées, 4 équivalentes ou inatteignables ; `make verify-quick` rc=0.
  - Revues : `security-reviewer` **PASS** (conditions ci-dessous) ; `acceptance-verifier` **PASS** ; `make verify` bloqué au seul `govulncheck` (`vuln.go.dev` 403 ; le relecteur signale aussi un binaire govulncheck construit en go1.26 à reconstruire en go1.27).
  - Menaces : T56 (rejeu d'approbation), T57 (différentiel d'analyse JSON) ajoutées ; T18, T41 étendues.
- 2026-09-26 : **M0-T22 `evals-core` terminée** (plan `docs/plans/M0-evals-core.md`, amendements V1 à V11, ancres des mutations en section 14) :
  - `internal/evals/{suite,path,grade,report,baseline,select,doc}.go` : chargement des suites et cas YAML (`go.yaml.in/yaml/v3` v3.0.5, MIT et Apache 2.0) avec liste d'admission des caractères (ASCII imprimable, fins de ligne, lettres du français ; tout le reste par échappement visible), liste blanche des échappements, arbre YAML validé avant conversion (clés `!!str` exactes à toute profondeur, scalaires en forme JSON à aller-retour exact, nulls explicites seulement dans le contenu opaque, scalaires ambigus YAML 1.1 ou core exigés entre guillemets, directives et `!` refusés), noms de fichiers validés avant d'être cités, liens et fichiers non réguliers refusés, lectures bornées ; graders sur un sous-ensemble JSONPath ; agrégation par exécution ; comparaison à la baseline (injection sous 1 toujours régressive, bornes, exécutions d'injection et d'escalade comptées) ; `BaselinePath` sûr ; `SelectChanged` qui échoue fermé. `schema.DecodeStrict` borné ajouté à `internal/llm/schema`.
  - Revues : **six revues sécurité**, cinq BLOCK successifs sur la même classe (texte relu différent de la donnée évaluée : repli de casse Unicode, clés YAML non chaîne, invisibles par catégorie puis par propriété, glyphes vides), deux changements d'approche consignés (V4 : validation de l'arbre avant conversion ; V10 : liste d'admission au lieu de listes de refus) ; sixième revue **PASS** ; `acceptance-verifier` **PASS** (8 critères, 40 mutations sur 40, 14 tests, `-race`) ; `make verify` bloqué au seul `govulncheck` (`vuln.go.dev` 403).
  - Menaces : T58 à T67 ajoutées ou étendues.
- 2026-09-27 : **M0-T19a `llm-harden` terminée** (plan `docs/plans/M0-demo-prep.md`, amendements V1 à V3 ; première des quatre tâches issues de l'amendement A3) :
  - `internal/llm/schema` : formes fermées (une seule forme par sous-schéma, mots-clés admis par forme, noms en liste d'admission), `AdmittedText` (ASCII imprimable, saut de ligne, lettres du français) appliqué aux octets bruts des schémas (seuls `\"`, `\\`, `\n` admis ; `\\` suivi de `u`, `U`, `x` refusé) et au prompt système, `Texts` (clés, chaînes et paires `clé: valeur` décodées). `internal/llm/prompts` : `LoadFS` refuse liens et fichiers non réguliers, lecture bornée, descripteur ouvert revérifié. `internal/llm` : `ContainsSecret` sur les octets bruts et la forme décodée de chaque `InputSchema` et du schéma du prompt, description d'outil admise, copie profonde des outils vérifiés, taille recontrôlée après rédaction.
  - Revues : `security-reviewer` BLOCK (secret caché derrière `\"` ou `\n`, le modèle lisant la forme décodée), corrigé par V2 et V3, seconde revue **PASS** ; `acceptance-verifier` **PASS** (8 critères, 69 mutations sur 74, 5 équivalentes, tests gelés inchangés) ; `make verify` bloqué au seul `govulncheck`.
  - Menaces : T68, T69, T70 ajoutées ; T43, T44, T64 mises à jour.
- 2026-09-27 : **M0-T19b `loops-harden` terminée** (plan `docs/plans/M0-loops-harden.md`, amendement V1 ; deuxième tâche issue de A3) :
  - `internal/loops` : bornes de taille (charge et candidat 64 Kio en UTF-8 valide, 100 findings de 1 Kio, noms 64 octets ; `LoopResult` maximal mesuré 203 555 octets) ; reprise du proposeur seulement sur cause directe `ApplicationError` rejouable portant un `ProposeFailure` canonique (lu brut, `{"tokens":N}`), jamais à travers un délai ; tokens invalides tracés avant escalade ; candidat fait de blancs JSON refusé ; `ctx.Err()` après le vérificateur ; signal d'approbation admis seulement sous forme canonique (plus de décodeur JSON dans `approvals.go`) ; `DeclaredApprover`. Obligations (a), (h), (i), (m) côté `RunLoop`, (j), (n) soldées.
  - Revues : `security-reviewer` **PASS** (fuzz de 45 s sans divergence entre octets du signal et décision) ; `acceptance-verifier` **PASS** après reprise dans un répertoire privé (la première passe a été invalidée par une collision de répertoire de copie entre agents, T72) : 14 critères, 74 mutations sur 74 (27 de M0-T14, 22 de M0-T15, 25 nouvelles) ; caractères invisibles bruts retirés de deux plans ; `make verify` bloqué au seul `govulncheck`.
  - Menaces : T71, T72 ajoutées ; T10, T57 mises à jour. Pratique retenue : chaque sous-agent travaille dans un répertoire privé (`mktemp -d`) et consigne le SHA de sa copie.
- 2026-09-27 : **M0-T19c `loops-archtest` terminée** (plan `docs/plans/M0-loops-archtest.md`, amendements V1 à V3 ; troisième tâche issue de A3) :
  - `internal/archtest` : `loopsrc.go` (`ReadSources`, `ParseSources`, `CheckLoopSources`) contrôle sur `go/ast` : `RunLoop` et `AwaitApprovals` jamais enregistrés, spécifications constantes (règle (d)), requête d'approbation littérale écrite dans l'appel (règle (p)), aucun décodage dans les paquets de workflow et cibles de décodage limitées à `converter.RawValue` (règle (l), `Get` admis seulement sur un appel direct `ExecuteActivity`, `ExecuteLocalActivity` ou `ExecuteChildWorkflow`), pas de point d'entrée prenant une spécification ; `pkgdirs.go` (`CheckPackageDirs`) : `Dir` résolu égal au chemin d'import, tout import interne listé ; règle `loops-fake-tests-only` ajoutée à `DefaultRules` (obligation (k)) ; échec fermé sur tout lien symbolique. Exemption du décodeur JSON retirée : `workflowcheck.config.yaml` supprimé, le Makefile ne passe plus `-config`. Obligations (d), (k), (l), (p) soldées.
  - Revues : `security-reviewer` BLOCK (liens symboliques de dossier, T74), corrigé par V2 et V3, seconde revue **PASS** avec constats à traiter avant T19d ou T20 (obligations (ai) à (al)) ; `acceptance-verifier` **PASS** (68 mutations, 67 distinctes, toutes détectées sauf N9 équivalente, tests gelés inchangés) ; `make verify` bloqué au seul `govulncheck`.
  - Menaces : T73, T74 ajoutées puis étendues par la seconde revue (module imbriqué, valeurs de méthode).
- 2026-09-27 : **M0-T03 `pile-dev` terminée** (plan `docs/plans/M0-pile-dev.md`, amendement V1 après sonde réelle des images) :
  - `docker-compose.yml` (PostgreSQL 17.6 officiel, Temporal `auto-setup` 1.28.1, OpenBao 2.4.1 en mode dev, images épinglées par `sha256`, ports publiés sur `127.0.0.1` seulement : 7233 et 8200, PostgreSQL non publié, `no-new-privileges`, journaux d'OpenBao coupés) ; `scripts/dev-env.sh` (`.env.dev` aléatoire, 600, validé avant export) ; `scripts/dev/postgres-init.sh` (rôles `temporal`, `rempart_owner`, `rempart` distincts, `REVOKE CONNECT, TEMPORARY ... FROM PUBLIC`) ; `scripts/dev-bootstrap.sh` (namespace `rempart`, rétention 168 h) ; `Makefile` (`dev`, `dev-down`, `verify` démarre la pile) ; `docs/SETUP.md` (section pile de dev, miroir contre le 429 de Docker Hub). Selon A1 : ni Transit, ni clés, ni jeton du worker (M1).
  - Tests : 9 unitaires (`compose_test.go`, `devscripts_test.go`), 5 d'intégration (`devstack_integration_test.go`).
  - Revues : `security-reviewer` **PASS** avec deux constats moyens à traiter avant la clôture de M0 (obligations (an), (ao)) ; `acceptance-verifier` **PASS** (13 critères, 23 mutations sur 23) ; `make verify` rc=0 pour la première fois en entier (pile, intégration, govulncheck).
  - Menaces : T76, T77 ajoutées ; T18 complétée. Proposition de harnais `docs/proposals/0006-garde-secrets-pile-dev.md` (garde contre l'affichage des secrets de la pile) à appliquer par l'humain.
  - Décisions de la section 11 du plan retenues sur délégation de l'humain, réversibles : OpenBao en HTTP sur loopback en M0 (à réexaminer avec Transit en M1) ; proposition 0006 ; critère 6 à cinq tests.
- 2026-09-27 : **M0-T19d `demo-workflow` terminée** (plan `docs/plans/M0-demo-workflow.md`, amendements V1 et V2 ; dernière des quatre tâches issues de A3) :
  - Étape A (`internal/archtest/loopsrc.go`) : `go.mod` hors racine, `go.work`, `go.work.sum`, `vendor/modules.txt` refusés à toute profondeur, `GOWORK=off` dans le `Makefile` ; méthodes de décodage prises comme valeur et `Validator` hors appel refusés ; méthodes et fermetures prenant un `LoopSpec` refusées ; trous E5, E6, E9 comblés.
  - Étape B : `internal/loops/demo` (workflow `rempart.demo.v1`, `Register` sur interface étroite), `internal/loops/demo/activities` (sans `sdk/workflow`), prompt `demo.greeting.v1` embarqué (hash `507f3f39...`) ; fiche `docs/loops/L0-demo.md` ; 13 tests en processus, faux fournisseur seulement.
  - Étape C : skill `loop-engineering` mis à jour, **à relire par l'humain** : `references/temporal-loop-skeleton.md` (déclarations compilées d'`internal/loops`, règles D10 à D12, T19b, T19c, (aj), (ak)) et `references/normalized-findings.md` (ordre total, empreinte en netstrings). Reste : `.claude/skills/secure-iac-generation/scripts/normalize_findings.py` décrit encore l'ancienne empreinte, à aligner en M3.
  - Revues : `security-reviewer` **PASS**, quatre constats moyens à traiter avant T20 (obligations (at) à (aw)) ; `acceptance-verifier` **PASS** (13 critères, 27 mutations détectées sur 28, 1 équivalente déclarée ; gels des tests vérifiés) ; `make verify` rc=0.
  - Obligations soldées : (ai), (ak), (al), (o), (g), (ae) pour la démo ; (m) côté démo par contrôle statique (rejeu réel en M1) ; (aj) partiellement (voir (at)).
  - Menaces : T75, T78 ajoutées ; T10, T12, T73, T74 complétées.
  - Décisions 1 à 8 de la section 11 du plan retenues sur délégation de l'humain, réversibles.
- 2026-09-29 : **M0-T20b `llm-adapter-harden` terminée** (plan `docs/plans/M0-llm-adapter-harden.md`, amendement V1 ; tâche ajoutée par A4) :
  - `internal/llm/domain/policy.go` : liste fermée des modèles non datés (11, SDK v1.75.0), date réelle exigée sinon, Bedrock et Vertex datés seulement, `preview`, `beta`, `experimental` refusés. `internal/llm/adapters/anthropic/provider.go` : une seule tentative dans le délai global, corps de réponse borné à 1 Mio sans troncature, `id` et `model` validés, `request-id` assaini, transport injecté sans proxy et cloné, `tool_use` refusé sans outils ou pour un outil non déclaré, schémas émis égaux octet pour octet aux octets vérifiés. `internal/llm/schema/admit.go` : paires `nom: valeur` à travers `$ref`, `items`, `anyOf`, `oneOf`, plafond de 65 536 textes, `\\` suivi d'un chiffre refusé. `LoadFS` documenté. Conditions de la revue M0-T12 et obligations (aa) à (ad) soldées ; l'adaptateur reste non câblé en M0 (`anthropic-unwired-m0`).
  - Revues : `security-reviewer` **PASS** avec deux constats moyens à tenir avant tout câblage (obligation (ay)) ; `acceptance-verifier` : 28 mutations sur 28 détectées, `-race` vert ; FAIL de clôture levé (artefact rapid `testdata/rapid` retiré, pile relancée pour `make verify`, fiche STATUS écrite).
  - Menaces : T80, T81 ajoutées ; T47, T49 à T52, T69, T70 complétées.
- 2026-09-29 : **M0-T20 `worker-e2e` terminée** (plan `docs/plans/M0-worker-demo.md`, amendements V1 à V3) :
  - Étape A (`5fad698`) : littéraux à clés dans le code de workflow, règles de décodage sur tout `internal/loops`, `reflect`, `unsafe`, `C`, `//go:linkname` et sources non Go refusés sous `internal/loops`, attributs de recherche et mémo refusés, `GOFLAGS` et `GOWORK` neutralisés, adaptateur Anthropic non câblé en M0 (`anthropic-unwired-m0`), `llm.UsageError` avec borne haute après tout appel, seule la sortie hors schéma reprise, `Register` durci.
  - Étape B (`0ce09f6`) : `loops.NewWorkflowID` opaque, `LoopSpec.MaxRunDuration`, `demo.ExecutionTimeout` (228 s pour 5 s, obligation (c)), `cmd/rempart-worker` (`LoadConfig` sans environnement ni secret, drapeaux obligatoires, `-llm=fake` seulement avec `-dev` revérifié avant toute I/O, `anthropic` refusé, Temporal en bouclage littéral, tenant validé et `System` refusé, file par processus, vérificateur `denyAll`), cible `make demo` : un seul document JSON, `converged`, `timed_out`, rien de commis (critère 4 de M0), exécuté contre la pile de dev.
  - Revues : `security-reviewer` **PASS**, deux constats moyens et plusieurs bas reportés dans M0-T03b (obligations (bd) à (bi)) ; `acceptance-verifier` **PASS** après correction (critère 14 : mutations A16 à A19 annoncées par V1 sans définition, définies en V3 par le principal à partir du rapport de `test-author` puis rejouées : 32 mutations sur 32). `make verify` rc=0.
  - Passage en impl de l'étape A : tests commités en WIP à la demande du hook git, HEAD ramené sur le parent par `git reset --soft` le temps du changement de phase, puis remis sur le commit poussé, sans réécriture d'historique distant.
  - Obligations soldées : (at), (au), (av), (aw), (af), (c), T41 et T40 côté worker ; (ax) partiellement (voir (bd)).
  - Menaces : T79 ajoutée ; T10, T14, T41, T73, T74, T78 complétées.
- 2026-09-29 : **M0-T03b `pile-dev-harden` terminée** (plan `docs/plans/M0-pile-dev-harden.md`, amendements V0 à V4 ; tâche ajoutée par A4) :
  - Étape A (`faa876b`) : compose seulement par `dev-env.sh run` avec `-p rempart-dev`, `COMPOSE_*` retirées, `scripts/dev-preflight.sh` (socket unix local seulement, Docker Engine 28 ou plus), secrets donnés au seul paquet d'intégration de la pile, `postgres-init.sh` valide les trois mots de passe, modes des scripts sans dépendance à l'umask. Étape B (`6edc17f`) : clés et sélecteurs de mémo et d'attributs de recherche refusés (portée `cmd/` et importeurs du SDK), `no-linkname`, `no-cmd-import`, usage négatif refusé, `onceBool`, connexion Temporal par `DialContext`, adresse revérifiée, `Identity` opaque, erreur à message fixe. V3 (`52c0202`, après revue BLOCK) : `.env.dev` lu une seule fois, preflight avant toute commande `docker` de `run`, `docs/SETUP.md` réécrit et contrôlé par test, portée étendue à tout `internal/loops` et `UpsertedMemo`.
  - Revues : `security-reviewer` BLOCK (dernière ligne de `.env.dev` non exportée, `docs/SETUP.md` obsolète), corrigé par V3, seconde revue **PASS** ; `acceptance-verifier` FAIL (`docs/SETUP.md`), puis **PASS** sur `52c0202` (17 critères, 43 mutations sur 43). `make verify` rc=0 ; critère 4 (variables hostiles) : jeton `root` refusé (403), un seul projet `rempart-dev`.
  - Écart de protocole consigné (V2) : revue unique sur A et B réunies ; passages en impl avec HEAD ramené sur le parent le temps du changement de phase (tests commités en WIP à la demande du hook git), sans réécriture d'historique distant.
  - Obligations soldées : (an), (ao), (ap), (ar), (as), (bd), (be), (bf), (bg), (bh) ; (aq) reste un résidu (proposition 0007).
  - Menaces : T10, T73, T76, T77 complétées.
- 2026-09-30 : **M0-T04 `ci` terminée sous réserve du critère 8** (premier passage vert sur GitHub, après l'étape humaine H1) (plan `docs/plans/M0-ci.md`, V1) :
  - `.github/workflows/verify.yml` : `pull_request` et `push` sur `main`, `contents: read`, `persist-credentials: false`, `actions/checkout` v7.0.1 (`3d3c42e5...`) et `actions/setup-go` v7.0.0 (`b7ad1dad...`) épinglées par SHA vérifié, `go-version-file: go.mod`, `cache: false`, `GOTOOLCHAIN: local`, golangci-lint v2.13.2 par `go install`, `make -f Makefile dev-preflight` puis `verify` (`EVAL_BASE` par `env`), `dev-down` en `always()`, `ubuntu-24.04`, 45 minutes. `internal/archtest/ci_test.go` : 7 tests de la fiche, `TestNoShadowMakefile`, `TestParseCIWorkflowDecoding`.
  - Propositions 0006 et 0007 appliquées par l'humain (`2792a9b`) : `/Makefile` code owner, `make -f Makefile` admis et utilisé par le hook Stop, lectures de secrets dans la pile bloquées.
  - Revues : `security-reviewer` **PASS** conditionnel (trois constats moyens : sous-make sans `-f`, fichiers de `verify` sans code owner, identité de l'agent sur GitHub) ; `acceptance-verifier` **PASS** (critères 1 à 7, critère 5 par `git ls-remote` faute de `gh api`, 17 mutations sur 17, gel des tests vérifié).
  - Menaces : T82 ajoutée ; T6, T32 complétées. Proposition 0008 (code owners sur ce qui définit `verify`) appliquée par l'humain (`927eca5`).
  - **Critère 8 constaté le 2026-09-30** : PR #4 (`main-6cpq6q` vers `main`), exécution 36654743901 sur `927eca5`, conclusion `success` en 3 min 30 environ : `dev-preflight` (Docker Engine 28 ou plus, compose v2), golangci-lint `0 issues`, tests unitaires et d'intégration contre la pile, govulncheck `No vulnerabilities found`, `dev-down` exécuté. La première exécution a été annulée par le groupe de concurrence (nouveau push), comportement attendu. **M0-T04 terminée.**
- 2026-09-30 : **M0-T04b `make-subcalls` terminée** (obligation (bp) ; plan `docs/plans/M0-make-subcalls.md`, V0 à V3) :
  - `Makefile` : 4 sous-make sous la forme exacte `$(MAKE) -f Makefile --no-print-directory <cible>` (`47b510d`) ; règle `Makefile: ;` (`32cb53c`), aucune règle implicite intégrée ne refait le `Makefile`.
  - `internal/archtest` : grammaire du `Makefile` en liste blanche, aucune expansion make en recette hors sous-make canonique, lexeur qui rejette les formes ambiguës, oracle `make -n -r -p` comparé au parseur, fichiers voisins `Makefile.*`, `Makefile,v`, `s.Makefile`, `RCS/`, `SCCS/` refusés, jointure des lignes bash (parité des `\`, commentaire jamais prolongé).
  - Revues : `security-reviewer` BLOCK trois fois (indirections make, désaccord de lexeur, refabrication du `Makefile`), puis **PASS** ; `acceptance-verifier` **PASS** (74 mutations tuées, attaques des trois BLOCK rejouées, `make verify` complet vert).
  - Proposition harnais 0009 (hook Stop en `make -r -f Makefile verify-quick` sans environnement make hérité, liste blanche d'options de make, `SHELL=` refusé, cas de sous-make imbriqué) : **à appliquer par l'humain**, 157 cas `test_hooks.sh` sur copie.
  - Menaces : T32 et T31 complétées. Obligations (bv) et (bw) avant M1.
- 2026-09-30 : **M0-T23 `evals-cli` terminée sous réserve de H3** (baseline `demo` écrite par l'humain) (plan `docs/plans/M0-evals-cli.md`, périmètre réduit aux 7 tests de la fiche) :
  - `cmd/rempart-evals` : exécuteur (suite, `all`, `changed` avec `--base` SHA complet, repli sur toutes les suites si base nulle, absente, invalide ou non ancêtre), `git` sans shell après `--end-of-options`, cible `demo` en processus (environnement de test Temporal, sans réseau ni Docker), baseline écrite seulement avec `--write-baseline` ; `internal/evals` : `LoadBaseline`, `EncodeBaseline`, `DiscoverSuites` ; suite `evals/demo` ; `Makefile` : `EVAL_BASE` figée et exportée, evals ciblées en tête de `verify` (`d922ae8`).
  - Revues : `security-reviewer` **PASS** (obligations (bx) à (cc)) ; `acceptance-verifier` critères 1, 2 (écart de code accepté), gel, harnais, (bs) **PASS**, mutation M14 survivante : test renforcé (réécriture de la baseline par une exécution en régression sans le drapeau, mutation tuée).
  - **H3 faite par l'humain** (`5fc5d25`, commit ne touchant que la baseline, sans `Co-Authored-By`) : critère 3 `make -s -f Makefile evals EVAL=demo | jq -e '.cases == 1 and .regressions_vs_baseline == []'` : `true`, rc=0 ; critère 5 `make -f Makefile verify` (avec `EVAL_BASE`) : rc=0, suite `demo` sélectionnée et conforme, intégration verte, govulncheck sans vulnérabilité. **M0-T23 terminée.**
- 2026-09-30 : **M1-T03 `intent-ir` terminée** (plan `docs/plans/M1-intent-ir.md`, ADR 0006 accepté) :
  - `schemas/intent/v1.json` (IR canonique) et `schemas/intent/draft-v1.json` (brouillon strict du modèle, sans `tenant_id`) ; `internal/intent` (`ParseDraft`, `ValidateIR`) et `internal/intent/domain` : conversion, références, valeurs techniques refusées, provenance (aucune valeur inventée hors `assumptions`), contradictions et questions calculées en code, exposition sensible (critère 4 de M1) fondée sur le texte de l'utilisateur (règle de phrase et règle de complétude des données) en plus des déclarations du modèle.
  - Revues : `security-reviewer` BLOCK deux fois (T85b reclassement ou omission de la donnée, T85c phrase coupée), puis **PASS** (`0f84fdd`), obligations (ch) à (cn) ; `acceptance-verifier` PASS (10 critères, gel des tests, mutations), puis un seul écart corrigé en phase tests (mutation M7 masquée par la règle texte : sous-test `stored_in_only`).
  - Skill `intent-to-spec` modifié (note D2), à relire.
- 2026-09-30 : **M1-T04 `design-cidr` terminée** (plan `docs/plans/M1-design-cidr.md`, écart E2 retenu : sortie lisible par défaut, `--json`) :
  - `internal/design/cidr` : allocateur CIDR déterministe (superbloc, un VPC par cloud, région et environnement, un sous-réseau par tier, marge x4 à deux niveaux, plages `--reserve` évitées) et vérificateur indépendant aligné sur `cidr_check.py` (T87) ; `schemas/graph/v1.json` et `internal/graph/domain` (texte libre isolé sous `untrusted_text`, type `FreeText`, projection `Facts` sans texte libre) ; `internal/design` (IR vers graphe) ; `cmd/rempart design <ir.json>` (codes 0, 1, 2).
  - Preuves : critère 2 de M1, 1 000 plans aléatoires, 0 violation ; `cidr_check.py --selftest 1000` sans faux positif ni négatif ; scénario de référence : 5 réseaux, 12 nœuds, 13 arêtes, 0 finding (critère 3, partie graphe) ; aucune dépendance vers le LLM ou Temporal.
  - Revues : `security-reviewer` **PASS** (obligations (co) à (cr)) ; `acceptance-verifier` **PASS** (14 critères, 8 mutations tuées, gel des tests) ; réserve : `make verify` complet non rejoué faute de Docker, à constater en CI sur la prochaine PR.
## En cours
**M1 démarré.** Décisions de l'humain (2026-09-30) : Q2 à Q5 selon les recommandations de `docs/plans/M1-overview.md` ; Q1 : faux LLM scripté en CI, **plus vrais LLM multi-fournisseurs** (Claude, OpenAI, DeepSeek, Qwen, open-weight auto-hébergés) en exécution manuelle, avec refonte du rédacteur avant tout appel réel, adaptateur compatible OpenAI et politique des fournisseurs par ADR (recommandation de l'agent, à confirmer par l'humain avant ces tâches : evals synthétiques vers tout fournisseur, données client seulement vers un fournisseur traitant dans l'UE ou auto-hébergé). Plan amendé en conséquence. **Attente humaine** : accepter l'ADR 0004 (avant M1-T01) et l'ADR 0005, poser le tag `m1-start`, fournir au moins une clé API avant les tâches LLM réel. Aucune tâche en cours. ADR 0004, 0005 et 0006 acceptés par l'humain (`885a556`), tag `m1-start` posé. Prochaine tâche : M1-T01 `envelope-transit` (chiffrement par tenant, OpenBao Transit). **Skill `intent-to-spec` modifié en M1-T03** (note D2 : `tenant_id` du scénario de référence invalide, `internal/intent/testdata/reference-ir.json` fait foi), à relire par l'humain. **Mode accéléré** (humain, 2026-09-30, « ça prend bcp de temps ») : seuls les constats critiques ou hauts de la revue sécurité relancent un cycle ; les constats moyens et bas deviennent des obligations datées pour M1 ; une seule campagne de mutations par tâche ; garde-fous inchangés (TDD, revue, acceptation, baseline humaine). **Périmètre réduit de M0-T23** (humain, 2026-09-30, « fais seulement le nécessaire ») : les 7 tests de la fiche seulement (plus les adaptations indispensables de `internal/archtest`), une mutation par test ; l'étape A du plan (obligations (s) à (w) et (y) de M0-T22 sur `internal/evals`) est reportée à M1. **Skill `loop-engineering/references/temporal-loop-skeleton.md` modifié en M0-T19d et M0-T20, à relire.** Rappel des décisions de M0-T19c (section 11 de son plan) retenues sur délégation de l'humain : (1) vérificateur factice réservé aux tests, même en `-dev` : T20 enregistre dans `make demo` un vérificateur qui refuse tout (issue `timed_out`) ; (2) en T19d, `Author` et le délai d'approbation viennent de l'entrée, `Author` restant une identité déclarée jusqu'à M4 ; (3) T19d : `func Spec() loops.LoopSpec` renvoyant un littéral constant, littéral `loops.ApprovalRequest` écrit dans l'appel ; (4) faux positifs acceptés (`internal/archtest` exempté de la règle des chaînes, import `.` interdit partout). Décisions de M0-T19b : Décisions de la section 10 du plan retenues sur délégation de l'humain (« continue sans t'arrêter, fais ce qu'il faut »), toutes dans le sens le plus strict, réversibles : (1) signal d'approbation admis seulement sous forme canonique, octets du hash et de la signature `[A-Za-z0-9+/=._:-@]` (plus strict que D2 de M0-T15, à confirmer avant M4 : une signature JSON ou PEM serait refusée) ; (2) charge trop grosse : `InvalidLoopSpec` avant toute activité ; (3) échec du proposeur sans `ProposeFailure` non repris (l'adaptateur LLM de T20 doit toujours le renvoyer après un appel facturé) ; (4) obligation (m) couverte par un critère statique en M0, test de rejeu d'historique en M1 ; (5) exemption du décodeur JSON retirée de `workflowcheck.config.yaml` en T19c ; (6) noms de spécification bornés (64 octets, jeu fermé). Amendement A3 retenu sur délégation de l'humain : M0-T19 découpée en T19a à T19d, M0 passe à 22 tâches (`docs/plans/M0-overview.md`, section 0 bis). A1 prime sur la fiche : pas de `ContinueAsNew` en M0. Décisions humaines ouvertes (section 13 du plan) : (1) relire A3 ; (3) liste d'admission ASCII et français pour les prompts ; (4) avant T20, câblage du vérificateur factice (étiquette de build avec ADR, binaire de développement distinct, ou vérificateur qui refuse tout) ; (5) avant T20, `-llm=anthropic` refusé en M0 sauf décision contraire ; (6) forme canonique du signal d'approbation en T19b, à confirmer avant M4.

`/milestone M0` lancé et découpage validé par l'humain le 2026-09-23 (« validé, chiffrement en M1 ») : 19 tâches (M0-T01 à T15, T19, T20, T22, T23) et étapes humaines H0, D0, H1, H3, H4 dans `docs/plans/M0-overview.md`. Réponses par défaut retenues pour Q1 à Q5. M0-T16, T17, T18 et T21 (ADR 0001) deviennent les premières tâches de M1 (`prompts/M1.md`). Risque résiduel accepté : historique Temporal en clair en M0, sans données client.

Préalables humains (étape H0 du plan) :
1. ~~Valider le découpage et répondre aux questions Q1 à Q5~~ : fait le 2026-09-23.
2. ~~Appliquer les propositions 0001 à 0005~~ : **fait par l'humain le 2026-09-27** (commit `2b3a9a6`). Vérifié par l'agent : l'état obtenu en appliquant 0001 à 0005 dans l'ordre sur `6edace9` est identique à `2b3a9a6` (0 ligne de différence hors `docs/`) ; suite de tests du harnais : 92 réussis, 0 échoué ; `make verify-quick` rc=0. Reste : activer « Require review from Code Owners » sur la branche par défaut (réglage GitHub, condition (r) avant M0-T23). M0-T01 a été faite sans elles (écarts consignés ci-dessus). Faux positif constaté du nouveau `guard_bash` : une commande qui écrit un fichier et dont le texte cite un chemin du harnais est refusée, même si le fichier écrit est hors du harnais (contourné proprement par l'outil d'édition, pas par la ligne de commande).
3. ~~Trancher les ADR 0001, 0002 et 0003~~ : acceptés le 2026-09-23.
4. ~~Poste Linux, macOS ou WSL2, `bash scripts/check-tools.sh` vert ; `git tag m0-start`~~ : fait le 2026-09-23 dans une session Claude Code cloud (conteneur Linux) à la demande de l'humain (« continue et fais le nécessaire »). Outils installés : Go 1.27.1 (dernière stable), golangci-lint v2.13.2, gofumpt v0.12.0, govulncheck v1.8.0, OPA 1.20.2 ; `bash scripts/check-tools.sh` affiche `Outils requis pour M0 : OK.` ; démon Docker non joignable dans ce conteneur (nécessaire à partir de M0-T03). Tag `m0-start` posé sur `1eca7a7` par l'agent. Jalon courant réglé à M0 (`rempart-state milestone M0`, l'état n'est pas versionné). Le tag n'a pas pu être poussé depuis la session cloud : `git tag m0-start 1eca7a7 && git push origin m0-start` depuis le poste de l'humain.
5. Relire les modifications des skills `loop-engineering`, `intent-to-spec`, `safe-autonomy` et `agent-evals`.
6. Choisir le point d'entrée produit (n'affecte pas M0, mais M1 à M4).

## Reste à faire
- Installer la chaîne d'outils sur le poste principal : `docs/SETUP.md`, puis `bash scripts/check-tools.sh`.
- `ContinueAsNew` avant l'attente d'approbation dans `temporal-loop-skeleton.md` : avec les tâches ADR 0001, au début de M1.
- ADR non encore rédigés (après le choix du point d'entrée) : plan calculé par le runner et approbations signées par des clés du client ; L3 en compilateur déterministe ; pas de mode hébergé au MVP.
- ADR « intégration Git » (T25) à rédiger avant M4 : `security-reviewer` rendra BLOCK en M4 sans lui. Il doit trancher la contradiction entre l'écran E1 de `docs/04-INTERFACE.md` (application Git centrale) et l'invariant « le plan de contrôle ne détient pas d'identifiant d'écriture ».
- Prochaine tâche : `/task` M0-T20 (commence par (at) à (aw)) ; M0-T23 après activation de « Require review from Code Owners ». Docker : le binaire `dockerd` est présent dans l'image de la session cloud ; lancé à la main le 2026-09-27 (`dockerd` en arrière-plan), `docker run --rm hello-world` rc=0, images tirées à travers le proxy. M0-T03 et T20 ne sont donc plus bloquées ; le démon est à relancer au début de chaque nouvelle session.
- **Avant M0-T20 et avant tout adaptateur Bedrock ou Vertex, obligatoire** (conditions de la revue M0-T12) : liste fermée des modèles publiés sans snapshot daté et date exigée sinon, jetons `preview`, `beta`, `experimental` refusés (T51) ; délai global par appel ou `MaxRetries` 0 (T50) ; borne du corps de réponse (T49) ; validation de `request-id`, `id`, `model` (T52) ; `Transport` injecté refusé s'il a un proxy (T47) ; `tool_use` accepté seulement avec outils.
- **Obligations issues de M0-T14** (plan `docs/plans/M0-runloop.md` 11.5 et seconde revue) : (a) tailles des findings et candidats bornées, avant T19 ; (b) annulation distinguée d'une panne, avant T15 et T20 ; (c) `WorkflowExecutionTimeout` au moins égal à `MaxWallTime + 3 x ActivityTimeout + 3 s` plus marge, testé, en T20 ; (d) T54 : `RunLoop` jamais enregistré comme workflow démarrable, spécifications constantes dans le code (`TestRunLoopNotRegistered`, `TestLoopSpecsAreConstants`), avant T19 et T20 ; (e) T16 : `workflow.GetVersion` pour les constantes et commandes de `spec.go`, en M1 ; (f) second signal de stagnation sur les seuls codes, en M1 ; (g) reporter dans le skill `loop-engineering` (`temporal-loop-skeleton.md`, `normalized-findings.md`) les écarts D10 à D12, V2 et l'encodage netstring de T13, en T19, modification de skill à signaler ici ; **(h) avant T19, obligatoire** : toute erreur du proposeur après un appel facturé est une `ApplicationError` de premier niveau portant `ProposeFailure`, jamais enveloppée, avec un test, ou bien `retryable` exige `ae.HasDetails()` (« pas de déclaration, pas de reprise ») ; (i) bas, avant T19 : tester délai, annulation et panique du proposeur (1 appel, `Failed`, `activity_failed`), exiger que la cause directe de l'`ActivityError` soit une `ApplicationError`, compacter le candidat avant `emptyCandidate` (test avec `converter.RawValue`), tester l'échec sans finding à l'itération 1, tracer un appel aux tokens invalides avant d'escalader.
- **Obligations issues de M0-T15**, avant T19 et T20 : (j) décodage strict du signal d'approbation : clés en double ou de casse inexacte refusées en `malformed` (T57, constat moyen) ; (k) contrainte mécanique empêchant `internal/loops/fake` hors des racines de développement (build tag ou règle `archtest`, T41 étendue, constat moyen) ; (l) test d'architecture limitant `json.NewDecoder` à `approvals.go` ou refusant toute méthode `UnmarshalJSON` dans `internal/loops` (portée de la déclaration workflowcheck) ; (m) résidu D11 : annulation dans la même tâche que le dernier signal ou à l'échéance donne `signal_flood` ou `timed_out` au lieu d'une annulation, à documenter et traiter en T19 ; même contrôle `ctx.Err()` après un vérificateur réussi dans `RunLoop` ; (n) `IgnoredSignal.Approver` est déclaré, non authentifié : renommer ou afficher comme non vérifié (T18) ; (o) une attente d'approbation par workflow, ou purge documentée du canal de signaux, en T19 (T56) ; (p) T54 étendue : `AwaitApprovals` jamais enregistré, requête construite par le code (`TestAwaitApprovalsNotRegistered` en T19) ; (q) M4 : message signé liant tenant, identifiant de demande, échéance et nonce (T56), contrat `SignatureValid`.
- **Obligations issues de M0-T22, avant T23** : (r) propositions 0001 et 0005 appliquées, « Require review from Code Owners » activé (T58, T63) ; (s) dans `contains` et `equals`, toute `\` refusée hors guillemets doubles (T65) ; (t) longueur de ligne bornée (160 runes) pour les evals et baselines, deux espaces consécutifs refusés dans `contains`/`equals` (T64) ; (u) vocabulaire fermé des étiquettes de cas dans `compileCase` (T66) ; (v) motifs `watch` à jeu de caractères fermé (T67) ; (w) baseline chargée avec les mêmes règles (liste d'admission, clés exactes, arbre validé) ; (x) `EVAL=changed` par `git diff --no-renames -z` (T61) ; (y) suites enracinées sur `os.Root.FS()` et comparaison `os.SameFile` entre `Lstat` et le fichier ouvert (TOCTOU) ; (z) cas toujours chargés par `LoadSuite`, jamais passés directement à `GradeOutcome` ; résidus consignés : `fs.ReadDir` lit tout avant la borne de 1000, `contains` réduit à un blanc, homoglyphes visibles dans la liste d'admission, typage visible des aiguilles (`contains: 443`).
- **Obligations issues de M0-T19a, avant T20** : (aa) `Texts` rend aussi `nom: v` pour chaque chaîne de `const`, `enum` et le littéral de `pattern` sous une propriété (secret sans forme sous `api_key`), et `k: ` suivi de la valeur sans blancs initiaux (valeur commençant par un saut de ligne), avec tests et propriété étendue ; (ab) `escapeLike` refuse aussi `\\` suivi d'un chiffre octal, et un test couvre un premier chiffre hexadécimal majuscule (mutation Y4 survivante) ; (ac) `LoadFS` documenté comme n'acceptant qu'un FS sans liens (`embed.FS`, `os.Root`) ; (ad) T70 : l'adaptateur envoie les octets vérifiés ou revérifie la forme réencodée ; pour la refonte du rédacteur (T37, garde de `prompts/M1.md`) : paire `name: Authorization` / `value: ...`, secret coupé entre éléments d'`enum`, `password:` puis saut de ligne, `AKIA` coupé par un saut de ligne, `:AWS_SECRET_ACCESS_KEY=...`, JSON doublement encodé (T69).
- **Obligations issues de M0-T19b, avant T20** : (ae) l'adaptateur LLM renvoie toujours un `ProposeFailure` porté par l'erreur la plus externe après un appel facturé ; (af) reprise avec attente bornée ou selon le type d'erreur (rafales sur 429) ; (ag) (m) : test de rejeu d'historique réel en M1 ; (ah) avant M4 : `valueBytes` du signal refuse une signature JSON ou PEM, à revoir avec l'ADR des approbations signées.
- **Obligations issues de M0-T19c, avant T19d ou T20** (seconde revue sécurité et acceptation) : (ai) [moyen, T74] `ReadSources` échoue fermé sur tout `go.mod` autre que celui de la racine et sur `go.work` ou `go.work.sum`, ou bien `GOWORK=off` imposé aux commandes `go` des tests d'architecture ; (aj) [moyen, T73] valeur de méthode ou de fonction gardée dans une variable (`recv := sig.Receive`, `get := fut.Get`, `set := workflow.SetUpdateHandler`) refusée hors position `Fun` d'un appel, `Validator` de tout littéral `UpdateHandlerOptions` contrôlé ; (ak) [bas, T73] méthode ou fermeture prenant un `LoopSpec` (expression de méthode, `FuncLit` renvoyée) couverte par la règle des points d'entrée ; (al) trous de tests signalés par l'acceptation : E5 (`IndexListExpr`, `RunG[LoopSpec,int]`), E6 (`LastHeartbeatDetails` non testé), E9 (chaîne d'alias déclarée à l'envers). Obligation (am) soldée : critère 9 du plan corrigé en 33 000 octets.
- **Obligations issues de M0-T03, avant la clôture de M0** (revue sécurité) : (an) [moyen, T77] les variables du shell ou de la ligne de commande de make priment sur `.env.dev` (`OPENBAO_DEV_ROOT_TOKEN=root make dev` donne un jeton `root`) : lancer compose par `bash scripts/dev-env.sh run docker compose ...` dans `dev`, `dev-down` et `dev-bootstrap.sh`, test qui refuse un `docker compose ... up` hors `dev-env.sh run`, validation de `POSTGRES_PASSWORD` dans `postgres-init.sh` ; (ao) [moyen, T77] `COMPOSE_PROJECT_NAME`, `COMPOSE_PROFILES`, `COMPOSE_ENV_FILES`, `DOCKER_HOST`, `DOCKER_CONTEXT` non neutralisés : `-p rempart-dev` explicite, `dev-preflight` refuse un démon distant, tests ; (ap) [bas] secrets exportés vers tous les paquets par `verify` : restreindre `run` au paquet d'intégration de la pile ; (aq) [bas, T76] mots de passe d'initialisation dans l'environnement de `postgres`, configuration Temporal en clair dans le conteneur : résidu consigné, règle `guard_bash` à étendre (`exec ... cat`, `/proc/*/environ`) ; (ar) [bas] `dev-preflight` exige Docker Engine 28 ou plus (étanchéité de la publication sur loopback) ; (as) [bas] test du mode 755 sensible à l'umask d'extraction : exiger seulement l'absence d'écriture pour le groupe et les autres.
- **Obligations issues de M0-T19d, avant T20** (revue sécurité) : (at) [moyen, T73] littéral `workflow.UpdateHandlerOptions` sans noms de champs non détecté : refuser dans le code de workflow tout littéral de ce type contenant un élément sans clé, sous-test `validator_unkeyed` ; (au) [moyen, T73] décodage par une fonction d'un paquet sans `sdk/workflow` sous `internal/loops` (ex. `activities.Take(sig, &in)` appelée depuis le workflow) : appliquer `decodeTargets` et la règle des noms de décodage pris comme valeur à tous les paquets sous `internal/loops` hors `fake`, et écrire dans le skill que le code de workflow ne passe jamais une valeur du SDK à une fonction du paquet d'activités ; (av) [moyen, T10] `FailureTokens = 1024` n'est pas une borne haute (tokens d'entrée des corrections non comptés) : usage accumulé rendu dans une erreur typée par `llm.Client`, ou borne incluant l'entrée, sinon qualifier d'estimation dans D5, T10 et le skill ; (aw) [moyen, T73] imports `reflect`, `unsafe` et directive `//go:linkname` refusés dans les paquets de workflow et sous `internal/loops` hors tests ; (ax) [bas] entrée de workflow non fermée par le convertisseur (champ `tenant` en trop accepté, casse, doublons : T78) : test qui fige le comportement en M0, entrée canonique en M1 ; `Register` refuse `a.LLM` nil, un tenant invalide et un vérificateur nil typé ; attributs de recherche typés ajoutés aux noms de décodage ou interdits ; `GOFLAGS` neutralisé par le `Makefile` ; `Author` authentifié avant tout `Commit` à effet (T12) ; (m) : test de rejeu réel en M1 (déjà (ag)).
- **Obligations issues de M0-T20b, avant tout câblage de l'adaptateur Anthropic (levée de `anthropic-unwired-m0`)** : (ay) [moyen, T47, T81] refuser dans `New` tout transport injecté ayant `Dial`, `DialContext`, `DialTLS`, `DialTLSContext`, `GetProxyConnectHeader`, `OnProxyConnectResponse`, ou un `TLSClientConfig` avec `InsecureSkipVerify`, `KeyLogWriter`, `VerifyPeerCertificate`, `VerifyConnection` ou `RootCAs` (ou réserver `Transport` aux tests), `noProxy` construit un transport neuf ; `checkTools` compile le schéma strict avant d'en extraire les textes et compte un budget de travail (chaîne de `$ref`, au plus 2^20 allocations) ; (az) [bas, T69] `Texts` suit `properties` avec un nom composé, traite `title` et `description` comme alias du nom, suit les objets d'`enum`, sinon cas consignés ; (ba) [bas, T70] corps émis relu par le décodeur strict (doublons, casse) ; (bb) [bas] règle `.gitignore` pour `**/testdata/rapid/` à proposer à l'humain (artefact rapid commité par erreur en M0-T20b, retiré à la clôture) ; (bc) [bas] `TestSingleAttemptAndDeadline` sans délai propre : la mutation N1 n'est détectée que par l'expiration du test ; borner son `ctx` à la prochaine révision.
- **Obligations issues de M0-T20, à traiter dans M0-T03b, avant `/close-milestone M0`** (revue sécurité) : (bd) [moyen, T73] `loops-no-search-attributes` ne voit que les sélecteurs : signaler dans le code de workflow toute clé `Memo`, `SearchAttributes`, `TypedSearchAttributes` d'un littéral, étendre le contrôle à `cmd/...` (ou à tout paquet important `go.temporal.io/sdk/client`), cas `child_options_keyed_memo`, `child_options_keyed_typed`, `start_options_in_cmd` ; (be) [moyen, T10] `llm.Client` refuse un usage négatif champ par champ (`spent(ErrProviderFailed)` avec la borne de l'appel), test `negative_usage` ; (bf) [bas, T73] `//go:linkname` refusé dans tout le module, paquets de workflow sous `internal/loops` ajoutés à R4 ou interdits d'importer `cmd/...` ; (bg) [bas] `-dev` et `-demo-once` non répétables (type `onceBool`) ; (bh) [bas, T14] `client.DialContext` lié au contexte, erreur à message fixe, adresse de bouclage revérifiée dans `run`, `Identity` opaque dans `client.Options` ; (bi) [bas] avant tout commit réel (M1) : idempotence et réconciliation si `ExecutionTimeout` expire pendant `Commit`.
- **Obligations issues de M0-T03b** (seconde revue sécurité), avant M1 sauf mention : (bj) [moyen, T73] refuser hors `cmd/` toute déclaration de type (alias ou définition) dont le membre droit est un type `go.temporal.io/...`, puis contrôle `go/types` sur les champs des structures SDK et API ; décodage ou `reflect` vers des options SDK sous `cmd/` ; (bk) [bas, T10] plancher de borne sur un usage déclaré à 0 pour un appel réussi ; (bl) [bas, T77] preflight lancé à chaque `run` (ou `${1##*/}`), `BASH_ENV`, `ENV`, fonctions bash exportées (`builtin unset`, `command docker`, `unexport BASH_ENV ENV`) ; (bm) [bas] erreurs après connexion du worker à message fixe, double préfixe `rempart-worker:` retiré (critère 14 à adapter) ; (bn) [bas] `dev-bootstrap.sh` relance le preflight à chaque itération de `tcli` : coût seulement ; (bo) proposition 0007 à rédiger et à faire appliquer par l'humain avant la phase impl de M0-T04 : garde `guard_bash` contre `exec` et lectures de secrets dans la pile (aq), `/Makefile` dans `.github/CODEOWNERS`, `make -f Makefile verify-quick` dans le hook Stop (T32).
- **Obligations issues de M0-T04, avant `/close-milestone M0` sauf mention** (revue sécurité) : (bp) [moyen, T32] chaque `$(MAKE)` du `Makefile` porte `-f Makefile` (sous-make sans `-f` : un `GNUmakefile` remplacerait `opa-test`, `arch-test`, `dev`), règle archtest qui le vérifie, cas `test_hooks.sh` avec sous-make imbriqué (proposition harnais) ; (bq) [bas, T82] liste blanche des expressions `${{ }}` sur tout le fichier du workflow, clé `uses` non simple refusée ; (br) [bas] groupe de concurrence de `main` avec `github.sha` ou risque accepté ; (bs) [bas, T23] `EVAL_BASE` nul, absent ou non ancêtre : toutes les evals ; (bt) [bas] proposition harnais refusant `make -C`, `--directory`, `-t`, `-n`, `-q` (traitée par la proposition 0009, `-n` admis sur délégation) ; (bu) [humain] identité distincte de l'agent sur GitHub (compte ou App sans rôle admin, sans permission `workflows`, hors contournement) : **refusée par l'humain le 2026-09-30, risque accepté** (l'agent pousse avec l'identité de l'humain ; la revue humaine de chaque PR reste la défense). Réglages H1 déclarés faits par l'humain le 2026-09-30.
- **Obligations issues de M1-T04** (revue sécurité PASS, mode accéléré), avant la clôture de M1 : (co) [moyen] `rempart design --json` : contrôles C1 (U+0080 à U+009F, dont CSI U+009B) et caractères bidirectionnels (U+202A à U+202E, U+2066 à U+2069) de `untrusted_text` non échappés : échapper en `\uXXXX` à l'encodage de `FreeText` ou les refuser par motif, test canari U+009B et U+202E ; (cp) [bas] motif excluant `\p{Cc}` et les bidirectionnels sur les textes libres des schémas intent et graphe ; (cq) [bas] `region` du schéma intent : motif `^[a-z][a-z0-9-]{0,30}[a-z0-9]$`, `maxLength` sur `justification` ; (cr) [bas] `readIR` : `Stat` avant `Open` (FIFO bloquant), ouverture `O_NONBLOCK` puis revérification du fichier régulier. Menace à écrire : séquences C1 et bidirectionnelles (« Trojan Source ») dans les textes non fiables affichés. Obligations du plan M1-design-cidr : ADR « planification CIDR stable et incrémentale » avant de stocker le premier plan (M2) ; à la première API, le tenant du contexte égal à celui de l'IR.
- **Obligations issues de M1-T03** (revue sécurité, constats moyens et bas, mode accéléré), avant la clôture de M1 : (ch) [moyen, T86] valeurs techniques collées à un préfixe (`subnet=10.0.0.0/16`, `cidr:10.0.0.0/8`, `AS 64512`) non détectées : découpage sur tout caractère hors `[0-9A-Fa-f.:/]` et ASN `as\s*[0-9]+` ; (ci) [moyen, T86b] ancrage lexical global : une classification moins stricte que la plus stricte du texte est refusée ; (cj) [bas] provenance de `allowed_sources` par sous-chaîne : comparer à des préfixes extraits du texte ; (ck) [bas, T3] `field` des hypothèses et questions : normaliser `.` et espaces, ou exiger un chemin valide. Constat haut T85b (reclassement ou omission de la donnée sensible) : corrigé dans la tâche par la **variante D**, retenue sur délégation (la règle globale déclenchait sur le scénario de référence et cassait le critère 3) : `INTENT-EXPOSURE-SENSITIVE` dès qu'une même phrase du texte de l'utilisateur contient un marqueur d'exposition et un marqueur de sensibilité ou de base de données, quoi que déclare le modèle. (cl) : seconde revue sécurité **BLOCK** (T85c), la variante D se contourne par une ponctuation ou une anaphore ; **même classe d'échec deux fois (règle de sécurité fondée sur les déclarations ou la proximité) : changement d'approche**, règle de **complétude** ajoutée (le texte affirme une donnée confidentielle, réglementée ou soumise à une réglementation : le brouillon doit la déclarer, sinon `INTENT-DATA-OMITTED` haut), variante D conservée en complément. Troisième revue sécurité **PASS** (`0f84fdd`). (cn) [moyen, T85d] donnée sensible déclarée dans un workload leurre privé et workload exposé inventé : si le texte contient un marqueur de base de données et qu'une exposition vise un `managed_db` ou un `vm_group`, lever `INTENT-EXPOSURE-SENSITIVE` ; cas leurre dans les evals de M1-T06 ; en L2, tout workload exposé présenté à la confirmation humaine. (cm) [moyen] marqueurs d'exposition en liste fermée de formes exactes (« exposez », « ouvert au monde », `0.0.0.0/0`) : cas adverses dans les evals de M1-T06.
- **Obligations issues de la revue sécurité du jalon M0** (PASS, 2026-09-30), pour M1 : (cd) [bas] `cmd/rempart-worker/run.go` : `fakeClient` ouvre `os.OpenRoot(".")`, racine à ancrer sur celle du module ou refus sans `go.mod` ; (ce) [bas, T6] `golangci-lint` installé par version en CI : épingler par hash ou passer par `go tool` ; (cf) [bas] `cmd/rempart-evals/git.go` : ajouter `-c core.hooksPath=/dev/null` et `-c diff.external=`, test qui fige les options `-c` ; menace nouvelle à écrire : configuration git locale d'un clone non fiable comme vecteur d'exécution ; (cg) [bas, bs] `github.event.before` nul sur `push` : repli sûr, à tester au niveau du workflow. (bq) et (br), marquées « avant clôture de M0 », sont **reportées à M1** (gravité basse, mode accéléré décidé par l'humain).
- **Obligations issues de M0-T23** (revue sécurité PASS, mode accéléré), avant M1 : (bx) [moyen, T63] `guard_bash` ne voit pas `--write-baseline` entre guillemets ou par variable : proposition harnais (recherche sans ancre, refus de `rempart-evals` avec `$`) et confirmation humaine sur `/dev/tty` dans le binaire avant écriture ; (by) [moyen, T67] motifs `watch` à jeu de caractères fermé `[a-z0-9._/*-]` ; (bz) [moyen, T66] liste fermée des étiquettes de cas ; (ca) [bas, T61] fichiers ignorés par Git sous un chemin surveillé : `--ignored` ou repli sur toutes les suites ; (cb) [bas, T59] journal du SDK sur stderr : handler qui échappe ou filtre ; (cc) [bas] `f.Sync()` avant le renommage de la baseline ; plus l'étape A du plan M0-evals-cli (obligations (s) à (w) et (y) de M0-T22), reportée. Écart accepté : sans baseline, `make evals EVAL=demo` rend 2 (l'exécuteur rend 3, `go run` le ramène à 1).
- **Obligations issues de M0-T04b** (quatrième revue sécurité, PASS), avant M1 : (bv) [moyen, règle (an)] `shellComment` et `joinShellLines` (`internal/archtest/devharden_test.go`) ne suivent pas le quoting de bash (`$'...'`, guillemets imbriqués dans `$(...)`) : un `#` masqué fait joindre à tort la ligne suivante et cache un appel compose ; principe « dans le doute, ne pas joindre » (aucune jointure d'une ligne contenant `#` hors forme sûre, ou `$'`, `` ` ``, `$(` avec guillemets), cas négatifs A3, A4 et recette du `Makefile` ; (bw) [bas, T32] section 6 du plan M0-make-subcalls : D19 (pas de `-r` en CI) repose sur des cibles toutes `.PHONY`, à exiger par un test pour toute cible sans recette si une cible non phony apparaît. Traités par la proposition 0009 : options de make entre guillemets ou échappées, `SHELL=` et `.SHELLFLAGS=` en ligne de commande.
- Avant M0-T19 (premier prompt réel) : contrôle des secrets dans `InputSchema` et dans le schéma du prompt (T44), copie profonde des outils vérifiés .
- Obligations restantes de T41 et T40 : M0-T11 refuse `PlatformFake` sauf option explicite de configuration, compare `Route.Model` et `Response.Model`, transmet exactement la route vérifiée (`TestServicePassesCheckedRoute`) et porte `TestOutOfSchemaRejected`, `TestNoRouteNoCall`, `TestRetentionZeroRejectsRetentionModel`, `TestUntrustedBlockRejectedWithTools`, `TestModelMismatchRejected` (critères 6 et 7 de M0) ; M0-T20 ne câble le faux que par `-dev`, avec un test de configuration de production sans faux.
- Avant M0-T19 (premier prompt réel) : durcissement de `internal/llm/schema` et `prompts` (réserves de la revue M0-T09, T43).
- Obligations pour M0-T10 à T12 (réserves de la revue M0-T08) : le service transmet exactement la route vérifiée par `CheckPolicy` (T40) ; `PlatformFake` refusé hors mode de développement explicite (T41) ; documenter et tester dans chaque fournisseur : `req.Validate()` avant toute I/O, respect de `ctx`, aucune journalisation du prompt ni du contenu, erreurs sans valeur d'entrée, comparaison `Response.Model` et `Route.Model` ; `RequestHash` réservé à la clé du faux, jamais utilisé comme identité de preuve.
- Avant le premier appel à un modèle réel (M1) : refonte du rédacteur de secrets (garde de `prompts/M1.md`, constats ouverts de M0-T07).
- Humain : trancher l'ADR 0004 (identifiant de tenant, tenant système) avant M1.
- Tâche de durcissement de `internal/archtest` (revue M0-T02, 3 constats moyens, T33) : fichiers exclus par build tags ou GOOS (`IgnoredGoFiles`), `go.mod` imbriqué, SDK atteint par un module tiers ; en bas : `internal/*/*/{domain,adapters,fake}`, `C` et `unsafe` dans R1, règle « personne n'importe `internal/archtest` ». À faire avant le premier fichier `//go:build` non test ou la première dépendance qui enveloppe un SDK confiné.
- **Avant M3 (création de `scripts/sandbox.sh`), obligatoire** : tâche de durcissement issue de la contre-revue de M0-T01 (plan `docs/plans/M0-squelette.md`, section 0) : confirmation et appel sur une ligne chaînée par `&&`, refus par test du préfixe `-`, de `.IGNORE` et de `MAKEFLAGS`, approbation hors de portée de l'agent (T31).
- Avec M0-T04 au plus tard : règle archtest refusant `GNUmakefile` et `makefile`, `make -f Makefile` dans la CI, et proposition de harnais pour `make -f Makefile` dans le hook Stop (T32).
- ~~Session cloud : autoriser `vuln.go.dev`~~ : **fait par l'humain le 2026-09-27**. Vérifié : HTTP 200, `go tool govulncheck ./...` « No vulnerabilities found. », `make verify` rc=0 sur `74283c9`. Le binaire `govulncheck` du PATH (construit en go1.26) échoue sur les paquets go1.27 : seul `go tool govulncheck` (celui du Makefile) fait foi. Docker : disponible dans la session en lançant `dockerd` (voir « Prochaine tâche »).

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

- 2026-09-23 23:49 [harnais] phase : free -> tests

- 2026-09-24 00:52 [harnais] phase : tests -> impl

- 2026-09-24 01:14 [harnais] RETOUR EN PHASE TESTS depuis impl : M0-T07 amendement V2 : revue securite BLOCK (4 fuites hautes, 5 moyennes) a rendre mecaniques par des cas de test rouges

- 2026-09-24 01:14 [harnais] phase : impl -> tests

- 2026-09-24 04:14 [harnais] phase : tests -> impl

- 2026-09-24 10:03 [harnais] RETOUR EN PHASE TESTS depuis impl : M0-T07 : fixture de webhook Slack prise pour un vrai secret par la protection de push GitHub ; remplacement par une forme non reconnue, sans changer la regle testee

- 2026-09-24 10:03 [harnais] phase : impl -> tests

- 2026-09-24 10:04 [harnais] passage en impl avec tests verts (caractérisation) : fixture Slack reformulee pour la protection de push GitHub, meme regle testee

- 2026-09-24 10:04 [harnais] phase : tests -> impl

- 2026-09-24 10:07 [harnais] PHASE FREE (discipline TDD suspendue) : tâche redaction (M0-T07) close avec réserves (décision déléguée par l'humain le 2026-09-24)

- 2026-09-24 10:07 [harnais] phase : impl -> free

- 2026-09-24 10:21 [harnais] phase : free -> tests

- 2026-09-24 10:32 [harnais] phase : tests -> impl

- 2026-09-24 10:40 [harnais] PHASE FREE (discipline TDD suspendue) : tâche llm-contrat (M0-T08) terminée

- 2026-09-24 10:40 [harnais] phase : impl -> free

- 2026-09-24 11:36 [harnais] phase : free -> tests

- 2026-09-24 11:47 [harnais] phase : tests -> impl

- 2026-09-24 16:34 [harnais] PHASE FREE (discipline TDD suspendue) : tâche llm-schema-prompts (M0-T09) terminée avec réserves

- 2026-09-24 16:34 [harnais] phase : impl -> free

- 2026-09-24 18:01 [harnais] phase : free -> tests

- 2026-09-24 18:13 [harnais] phase : tests -> impl

- 2026-09-24 18:21 [harnais] PHASE FREE (discipline TDD suspendue) : tâche llm-fake (M0-T10) terminée

- 2026-09-24 18:21 [harnais] phase : impl -> free

- 2026-09-24 18:48 [harnais] phase : free -> tests

- 2026-09-24 19:06 [harnais] phase : tests -> impl

- 2026-09-24 19:17 [harnais] PHASE FREE (discipline TDD suspendue) : tâche llm-client (M0-T11) terminée

- 2026-09-24 19:17 [harnais] phase : impl -> free

- 2026-09-24 22:34 [harnais] phase : free -> tests

- 2026-09-24 22:51 [harnais] phase : tests -> impl

- 2026-09-24 23:03 [harnais] PHASE FREE (discipline TDD suspendue) : tâche llm-anthropic (M0-T12) terminée

- 2026-09-24 23:03 [harnais] phase : impl -> free

- 2026-09-24 23:16 [harnais] phase : free -> tests

- 2026-09-24 23:28 [harnais] phase : tests -> impl

- 2026-09-24 23:30 [harnais] PHASE FREE (discipline TDD suspendue) : tâche loop-findings (M0-T13) terminée

- 2026-09-24 23:30 [harnais] phase : impl -> free

- 2026-09-25 10:32 [harnais] phase : free -> tests

- 2026-09-25 10:39 [harnais] phase : tests -> impl

- 2026-09-25 12:17 [harnais] RETOUR EN PHASE TESTS depuis impl : M0-T14 amendement V2 (conditions de la revue sécurité)

- 2026-09-25 12:17 [harnais] phase : impl -> tests

- 2026-09-25 12:33 [harnais] phase : tests -> impl

- 2026-09-25 12:44 [harnais] PHASE FREE (discipline TDD suspendue) : tâche runloop (M0-T14) terminée

- 2026-09-25 12:44 [harnais] phase : impl -> free

- 2026-09-25 21:48 [harnais] phase : free -> tests

- 2026-09-25 22:10 [harnais] phase : tests -> impl

- 2026-09-25 22:18 [harnais] PHASE FREE (discipline TDD suspendue) : tâche approvals (M0-T15) terminée

- 2026-09-25 22:18 [harnais] phase : impl -> free

- 2026-09-25 23:34 [harnais] phase : free -> tests

- 2026-09-26 00:06 [harnais] phase : tests -> impl

- 2026-09-26 00:47 [harnais] RETOUR EN PHASE TESTS depuis impl : M0-T22 amendement V2 (BLOCK de la revue sécurité : clés exactes, noms non fiables, liens, bornes de baseline)

- 2026-09-26 00:47 [harnais] phase : impl -> tests

- 2026-09-26 01:07 [harnais] phase : tests -> impl

- 2026-09-26 01:25 [harnais] RETOUR EN PHASE TESTS depuis impl : M0-T22 amendement V4 (seconde revue BLOCK : clés YAML non chaîne, changement d'approche)

- 2026-09-26 01:25 [harnais] phase : impl -> tests

- 2026-09-26 01:57 [harnais] phase : tests -> impl

- 2026-09-26 02:03 [harnais] RETOUR EN PHASE TESTS depuis impl : M0-T22 amendement V6 (troisième revue BLOCK : Unicode invisible, étiquette !, directives, nulls, scalaires ambigus)

- 2026-09-26 02:03 [harnais] phase : impl -> tests

- 2026-09-26 02:24 [harnais] phase : tests -> impl

- 2026-09-26 11:58 [harnais] RETOUR EN PHASE TESTS depuis impl : M0-T22 amendement V8 (quatrième revue BLOCK : invisibles par propriété Unicode, null implicite)

- 2026-09-26 11:58 [harnais] phase : impl -> tests

- 2026-09-26 12:18 [harnais] phase : tests -> impl

- 2026-09-26 12:39 [harnais] RETOUR EN PHASE TESTS depuis impl : M0-T22 amendement V10 (cinquième revue BLOCK : liste d'admission des caractères)

- 2026-09-26 12:39 [harnais] phase : impl -> tests

- 2026-09-26 13:18 [harnais] phase : tests -> impl

- 2026-09-26 13:40 [harnais] PHASE FREE (discipline TDD suspendue) : tâche evals-core (M0-T22) terminée

- 2026-09-26 13:40 [harnais] phase : impl -> free

- 2026-09-26 18:46 [harnais] phase : free -> tests

- 2026-09-26 19:25 [harnais] phase : tests -> impl

- 2026-09-26 19:44 [harnais] RETOUR EN PHASE TESTS depuis impl : M0-T19a amendement V2 (revue BLOCK : secrets sur la forme décodée des schémas)

- 2026-09-26 19:44 [harnais] phase : impl -> tests

- 2026-09-26 23:41 [harnais] phase : tests -> impl

- 2026-09-27 00:08 [harnais] PHASE FREE (discipline TDD suspendue) : tâche llm-harden (M0-T19a) terminée

- 2026-09-27 00:08 [harnais] phase : impl -> free

- 2026-09-27 00:58 [harnais] phase : free -> tests

- 2026-09-27 09:46 [harnais] phase : tests -> impl

- 2026-09-27 10:16 [harnais] PHASE FREE (discipline TDD suspendue) : tâche loops-harden (M0-T19b) terminée

- 2026-09-27 10:16 [harnais] phase : impl -> free

- 2026-09-27 11:05 [harnais] phase : free -> tests

- 2026-09-27 11:25 [harnais] phase : tests -> impl

- 2026-09-27 11:36 [harnais] RETOUR EN PHASE TESTS depuis impl : M0-T19c amendement V2 (revue BLOCK : liens symboliques)

- 2026-09-27 11:36 [harnais] phase : impl -> tests

- 2026-09-27 15:03 [harnais] phase : tests -> impl

- 2026-09-27 15:25 [harnais] PHASE FREE (discipline TDD suspendue) : tâche M0-T19c loops-archtest terminée

- 2026-09-27 15:25 [harnais] phase : impl -> free

- 2026-09-27 16:04 [harnais] phase : free -> tests

- 2026-09-27 19:50 [harnais] phase : tests -> impl

- 2026-09-27 20:00 [harnais] PHASE FREE (discipline TDD suspendue) : tâche M0-T03 pile-dev terminée

- 2026-09-27 20:00 [harnais] phase : impl -> free

- 2026-09-27 20:16 [harnais] phase : free -> tests

- 2026-09-27 20:21 [harnais] phase : tests -> impl

- 2026-09-27 20:32 [harnais] RETOUR EN PHASE TESTS depuis impl : M0-T19d etape B: tests demo

- 2026-09-27 20:32 [harnais] phase : impl -> tests

- 2026-09-27 20:42 [harnais] phase : tests -> impl

- 2026-09-27 20:53 [harnais] PHASE FREE (discipline TDD suspendue) : tâche M0-T19d demo-workflow terminée

- 2026-09-27 20:53 [harnais] phase : impl -> free

- 2026-09-27 21:25 [harnais] phase : free -> tests

- 2026-09-28 07:09 [harnais] phase : tests -> impl

- 2026-09-28 07:11 [harnais] PHASE FREE (discipline TDD suspendue) : M0-T20 etape A faite, M0-T20b avant etape B

- 2026-09-28 07:11 [harnais] phase : impl -> free

- 2026-09-28 07:31 [harnais] phase : free -> tests

- 2026-09-28 08:16 [harnais] phase : tests -> impl

- 2026-09-29 15:06 [harnais] PHASE FREE (discipline TDD suspendue) : M0-T20b cloture (revues rendues)

- 2026-09-29 15:06 [harnais] phase : impl -> free

- 2026-09-29 15:13 [harnais] phase : free -> tests

- 2026-09-29 15:25 [harnais] phase : tests -> impl

- 2026-09-29 15:42 [harnais] PHASE FREE (discipline TDD suspendue) : tâche M0-T20 worker-e2e terminée

- 2026-09-29 15:42 [harnais] phase : impl -> free

- 2026-09-29 16:05 [harnais] phase : free -> tests

- 2026-09-29 16:20 [harnais] phase : tests -> impl

- 2026-09-29 16:22 [harnais] RETOUR EN PHASE TESTS depuis impl : M0-T03b etape B: tests

- 2026-09-29 16:22 [harnais] phase : impl -> tests

- 2026-09-29 16:33 [harnais] phase : tests -> impl

- 2026-09-29 20:16 [harnais] RETOUR EN PHASE TESTS depuis impl : M0-T03b V3: tests des correctifs apres BLOCK

- 2026-09-29 20:16 [harnais] phase : impl -> tests

- 2026-09-29 20:30 [harnais] phase : tests -> impl

- 2026-09-29 21:00 [harnais] PHASE FREE (discipline TDD suspendue) : tâche M0-T03b pile-dev-harden terminée

- 2026-09-29 21:00 [harnais] phase : impl -> free

- 2026-09-29 21:10 [harnais] phase : free -> tests

- 2026-09-30 00:59 [harnais] phase : tests -> impl

- 2026-09-30 01:10 [harnais] PHASE FREE (discipline TDD suspendue) : tâche M0-T04 ci terminée sous réserve du critère 8

- 2026-09-30 01:10 [harnais] phase : impl -> free

- 2026-09-30 01:31 [harnais] phase : free -> tests

- 2026-09-30 01:38 [harnais] phase : tests -> impl

- 2026-09-30 01:48 [harnais] RETOUR EN PHASE TESTS depuis impl : BLOCK securite M0-T04b : parseur Makefile a durcir (eval, RECIPEPREFIX, MAKE_COMMAND)

- 2026-09-30 01:48 [harnais] phase : impl -> tests

- 2026-09-30 11:48 [harnais] phase : tests -> impl

- 2026-09-30 12:31 [harnais] PHASE FREE (discipline TDD suspendue) : tâche M0-T04b make-subcalls terminée

- 2026-09-30 12:31 [harnais] phase : impl -> free

- 2026-09-30 12:53 [harnais] phase : free -> tests

- 2026-09-30 14:17 [harnais] phase : tests -> impl

- 2026-09-30 14:24 [harnais] RETOUR EN PHASE TESTS depuis impl : acceptation M0-T23 FAIL : mutation M14 survit, assertion sur disque manquante

- 2026-09-30 14:24 [harnais] phase : impl -> tests

- 2026-09-30 14:27 [harnais] PHASE FREE (discipline TDD suspendue) : tâche M0-T23 evals-cli terminée, en attente de H3

- 2026-09-30 14:27 [harnais] phase : tests -> free

- 2026-09-30 15:06 [harnais] jalon courant : M1

- 2026-09-30 19:51 [harnais] phase : free -> tests

- 2026-09-30 20:30 [harnais] phase : tests -> impl

- 2026-09-30 20:33 [harnais] RETOUR EN PHASE TESTS depuis impl : BLOCK securite M1-T03 : exposition sensible contournable par reclassement ou omission (T85b)

- 2026-09-30 20:33 [harnais] phase : impl -> tests

- 2026-09-30 20:35 [harnais] phase : tests -> impl

- 2026-09-30 20:37 [harnais] RETOUR EN PHASE TESTS depuis impl : second BLOCK M1-T03 : regle par phrase contournable, regle de completude des donnees (T85c)

- 2026-09-30 20:37 [harnais] phase : impl -> tests

- 2026-09-30 20:38 [harnais] phase : tests -> impl

- 2026-09-30 20:42 [harnais] RETOUR EN PHASE TESTS depuis impl : acceptation M1-T03 FAIL : mutation M7 masquee par la regle texte, sous-test stored_in isole

- 2026-09-30 20:42 [harnais] phase : impl -> tests

- 2026-09-30 20:44 [harnais] PHASE FREE (discipline TDD suspendue) : tâche M1-T03 intent-ir terminée

- 2026-09-30 20:44 [harnais] phase : tests -> free

- 2026-09-30 20:55 [harnais] phase : free -> tests

- 2026-09-30 21:13 [harnais] phase : tests -> impl

- 2026-09-30 21:20 [harnais] PHASE FREE (discipline TDD suspendue) : tâche M1-T04 design-cidr terminée

- 2026-09-30 21:20 [harnais] phase : impl -> free
