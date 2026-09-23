# M0 : découpage du jalon Fondations en tâches

- Date : 2026-09-23
- Auteur : subagent `architect`
- Statut : **validé** par l'humain le 2026-09-23, avec l'amendement A1 (section 0) ; réponses par défaut retenues pour Q1 à Q5
- Sources : `prompts/M0.md` ; `docs/00-VISION.md` §3 et §4 ; `docs/01-LOOPS.md` ; `docs/02-THREAT-MODEL.md` ; `docs/STATUS.md` ; `Makefile.template` ; skills `go-platform-conventions`, `loop-engineering` (dont `temporal-loop-skeleton.md` corrigé le 2026-09-23), `llm-safety`, `agent-evals` et leurs références ; ADR 0001, 0002, 0003 (statut « proposé ») ; `docs/reviews/2026-09-23-critique-initiale.md` ; `docs/proposals/0001-harnais-portable-et-tdd.md`.

Ce document est la vue d'ensemble du jalon. Au moment de chaque `/task`, l'architecte produit le plan détaillé `docs/plans/M0-<slug>.md` de la tâche : il précise la fiche ci-dessous sans en élargir le périmètre.

---

## 0. Amendement A1 (validation humaine du 2026-09-23)

Décision de l'humain : « validé, chiffrement en M1 ». L'ADR 0001 n'est pas refusé : sa **mise en œuvre est reportée au début de M1**, avant que la boucle L1 n'écrive le moindre historique Temporal contenant des données client. En M0, la démo ne manipule que des données synthétiques.

Effets sur ce plan (ils priment sur le reste du document) :
- **Retirées de M0, premières tâches de M1** : T16 (enveloppe AES-256-GCM), T17 (`KeyWrapper` Transit), T18 (codec Temporal), T21 (versioning et rejeu). Report consigné dans `prompts/M1.md`.
- **Modifiées** selon la ligne « 0001 » de la section 9 : T03 sans moteur Transit, clés de tenants ni jeton du worker (OpenBao reste démarré, livrable de M0) ; T19 sans `ContinueAsNew` avant l'attente d'approbation ; T20 avec le convertisseur Temporal par défaut et sans `TestHistoryHasNoPlaintext`. `secret.Bytes` (T06) reste.
- **Dépendances** : T20 dépend de T03 et T19 seulement ; D0 n'ajoute à `prompts/M0.md` que les critères des ADR 0002 et 0003 ; les critères `[ADR-0001]` de la section 8.2 sont prouvés en M1.
- **M0 compte 19 tâches** : T01 à T15, T19, T20, T22, T23.
- **Risque résiduel accepté pour M0** : historique Temporal en clair, sans données client (T3, T7, T11, principe 9). Il doit être levé avant la première exécution de L1.
- **Questions** : réponses par défaut retenues (Q1 module `github.com/amezianechayer/rempart` ; Q2 dossiers d'outillage consignés en D0 ; Q3 intégration contre `make dev` ; Q4 aucun appel réel au modèle en M0 ; Q5 vérificateur d'approbation factice jusqu'en M4).

### Amendement A2 (revue sécurité de D0, 2026-09-23)
- M0-T08 ajoute `TestCheckPolicyRejectsEmptyResidency` : `CheckPolicy` refuse une résidence ou une rétention vide (réserve de l'ADR 0002, T19).
- Les autres réserves concernent M1 et au-delà (`prompts/M1.md`, section des ADR « Réserves de la revue sécurité »).

---

## 1. Objectif

Un squelette Go qui compile, se teste et s'exécute en CI, et qui fait tourner de bout en bout une boucle Temporal générique conforme au skill `loop-engineering` (proposer, vérifier, diagnostiquer, budget, stagnation, escalade, approbation), contre un faux LLM déterministe, **sans aucune logique métier**. Les cinq critères de `prompts/M0.md` sont prouvés par des commandes (section 8).

---

## 2. Conditions d'entrée et conventions du plan

### 2.1 ADR supposés acceptés, dépendances isolées

Le plan suppose les ADR 0001, 0002 et 0003 acceptés. Tout ce qui en dépend porte une étiquette :

| Étiquette | Ce qui en dépend |
|---|---|
| `[ADR-0001]` | Chiffrement des payloads Temporal par tenant (enveloppe OpenBao Transit), `FailureConverter` chiffrant, propagateur de tenant, versioning par `workflow.GetVersion` et tests de rejeu, `ContinueAsNew` avant l'attente d'approbation, moteur Transit dans `make dev` |
| `[ADR-0002]` | Forme multi-plateforme de `ModelProvider` (`Route`, `Capabilities`), résolution de route par tenant sans défaut, contrôles de résidence et de rétention, contrôle du modèle déclaré, baseline d'eval par couple plateforme et modèle |
| `[ADR-0003]` | Image PostgreSQL officielle sans Apache AGE, bases et rôles Temporal et Rempart distincts |

Une tâche entièrement étiquetée disparaît si l'ADR est refusé ; un critère étiqueté dans une tâche non étiquetée est retiré ou remplacé. Le détail est en section 9.

### 2.2 Harnais (patch 0001 appliqué)

Le plan s'appuie sur le comportement du harnais après application de `docs/proposals/0001-harnais-portable-et-tdd.patch` :

- Phase tests : le hook Stop n'exige que `go build ./...` (dès que `go.mod` existe) ; `go vet` n'est pas lancé sur les `_test.go` ; le passage en impl est refusé si un test a une erreur de syntaxe.
- Phase impl et free : le hook Stop exige `make verify-quick` dès que le `Makefile` contient cette cible. Sans `Makefile`, il ne vérifie rien : T01 installe la cible et la rend verte dans la même tâche.
- Baselines d'eval (`evals/**/baseline.json`, `evals/**/baseline/**.json`) protégées dans toutes les phases ; `make update-baseline` et `--write-baseline` bloqués pour l'agent. La première baseline est donc une **étape humaine** (H3).
- `rempart-state phase impl` lance `go test` **sans tag** sur les paquets des tests modifiés. Un lot de tests uniquement taggés `integration` ne passerait pas la porte. **Règle du plan : chaque tâche comporte au moins un test unitaire rouge sans tag.**
- Les tests sont écrits dans le répertoire du paquet visé, pour échouer sur `undefined: X` (bonne raison) plutôt que sur un import introuvable.
- Les fixtures qui ressemblent à des secrets portent `EXAMPLE`, `FAKE`, `DUMMY` ou `PLACEHOLDER` à moins de 40 caractères du motif (garde `guard_edit`), par exemple `AKIAIOSFODNN7EXAMPLE`. Aucune construction de chaîne à l'exécution pour contourner la garde.
- Tout fichier sous `testdata/` et `evals/*/cases/` est gelé en phase impl. Un test qui réécrit ses fixtures (enregistrement d'historique, golden) n'est lancé qu'en phase tests.

### 2.3 Poste de travail et outils

Le poste actuel (Windows, dépôt sous OneDrive, Go 1.16, sans make, Docker, golangci-lint ni OPA) ne permet aucune tâche de code de M0. Tout M0 s'exécute sur Linux, macOS ou WSL2, dépôt cloné hors dossier synchronisé (`~/rempart`), avec les outils de `docs/SETUP.md` et `bash scripts/check-tools.sh` vert.

| Jeu d'outils | Contenu |
|---|---|
| O-base | git, bash, python3 (hooks), make, Go dernière stable (au moins 1.23 ; 1.24 ou plus attendu, ce qui permet la directive `tool` de `go.mod`), golangci-lint v2 (version exacte épinglée dans la CI et consignée dans `docs/SETUP.md`) |
| O-docker | O-base, Docker Engine et plugin compose v2, jq |
| O-net | accès réseau à `proxy.golang.org` et `vuln.go.dev` (govulncheck) |
| O-gh | gh (facultatif : l'interface web de GitHub suffit) |

- OPA n'est pas requis en M0 (aucun fichier `.rego`), mais `scripts/check-tools.sh` le compte parmi les outils M0 : l'installer quand même.
- Versions : directive `go` de `go.mod` fixée à la dernière stable au moment de T01 ; `go.temporal.io/sdk` et `github.com/anthropics/anthropic-sdk-go` épinglés à une version exacte `vX.Y.Z` (pas de pseudo-version), consignée dans `docs/STATUS.md` ; outils Go (`govulncheck`, `workflowcheck`) épinglés par directive `tool` et lancés par `go tool`. Toute autre dépendance est justifiée dans le plan de sa tâche.
- Faits externes à revérifier à la source au moment de la tâche : noms exacts des API du SDK Temporal (convertisseur `ContextAware`, `EncodeCommonAttributes`, rejoueur avec `DataConverter`, usage de `testsuite` hors `go test`), paramètres de sortie structurée du SDK Anthropic (`output_config.format`, `strict`), API HTTP Transit d'OpenBao, images Docker officielles de Temporal et d'OpenBao, bibliothèques JSON Schema (candidat : `github.com/santhosh-tekuri/jsonschema/v6`) et YAML maintenues (candidat : `go.yaml.in/yaml/v3`).

---

## 3. Périmètre

### 3.1 Dans le périmètre
- `go.mod`, arborescence de `00-VISION.md` §4 avec `doc.go`, binaires `cmd/*` réduits à un stub.
- `Makefile` issu de `Makefile.template` (corrigé, section 4), `.golangci.yml`, `docker-compose.yml`, scripts de pile de dev, CI GitHub Actions.
- Tests d'architecture (`internal/archtest`) : arborescence, règles d'import, configuration compose et CI.
- Primitives transverses sans logique métier : tenant dans le contexte (`internal/tenancy`), type `secret.Value` (`internal/secrets/secret`).
- `internal/llm` : contrat `ModelProvider`, validation de schéma, registre de prompts versionnés, rédacteur, faux déterministe, service `Client`, adaptateur Anthropic testé contre `httptest`.
- `internal/loops` : findings normalisés (empreinte, score), `RunLoop`, `AwaitApprovals`, vérificateur d'approbation factice, workflow de démonstration synthétique, worker et commande de démo.
- `[ADR-0001]` : enveloppe AES-256-GCM par tenant, adaptateur Transit, codec Temporal, tests de rejeu.
- `evals/` : exécuteur minimal (`internal/evals`, `cmd/rempart-evals`), format de cas, suite `demo` à un cas trivial, comparaison à la baseline.

### 3.2 Hors périmètre
- Toute logique métier (intention, conception, politiques, IaC, graphe, runner, preuves) ; tables et migrations PostgreSQL (M1).
- `scripts/sandbox.sh` et comptes de bac à sable (M3) : les cibles `sandbox-*` échouent proprement.
- Adaptateurs Bedrock, Vertex, auto-hébergé (ADR 0002 : M5 au plus tard) ; appels réels au modèle et job nocturne (question Q4).
- Serveur de codec HTTP pour l'UI Temporal (ADR 0001 : désactivé par défaut) ; versioning des workers (ADR 0001 : réévalué en M4).
- Vérification cryptographique réelle des approbations (clés du client, WebAuthn) : M4 (question Q5).
- Spans OpenTelemetry et métriques Prometheus par itération : M1, avec la première boucle réelle ; en M0, la trace d'itérations est portée par `LoopResult.Trace` et testée.
- Minimisation et pseudonymisation des sous-graphes, masquage des IP publiques, evals d'injection `evals/security/injection/` : M1 et M5.
- testcontainers (question Q3) ; CLI `rempart` au-delà du stub ; `rempartd`, `rempart-runner`, `rempart-mcp` au-delà du stub.

---

## 4. Incohérences connues et décisions

| Constat | Décision dans ce plan |
|---|---|
| `Makefile.template` appelle `go run ./cmd/rempart-evals`, absent de l'arborescence de la vision | `cmd/rempart-evals` : binaire d'outillage (jamais livré aux clients), câblage seulement ; logique testable dans `internal/evals`. Créés en T22 et T23. D'ici là, `make evals` sort en code 2 avec un message qui nomme M0-T23. |
| `Makefile.template` appelle `go test ./internal/archtest/...`, absent de la vision | `internal/archtest` : tests d'architecture et de configuration du dépôt (arborescence, imports, compose, CI, Makefile). Créé en T01. |
| `scripts/sandbox.sh` n'existe pas (M3) | Cible `sandbox-guard`, prérequis de `sandbox-plan`, `sandbox-apply` et `sandbox-destroy` : si le script est absent, code 2 et message **avant** toute question interactive. Le script n'est pas créé en M0. L'agent ne lance jamais `sandbox-apply` ni `sandbox-destroy` (permission « ask ») ; la preuve se fait par `make sandbox-plan` et `make sandbox-guard`. |
| `make dev` suppose Docker | Cible `dev-preflight` : vérifie `docker compose version` et l'accès au démon, sinon code 2 et renvoi à `docs/SETUP.md`. Pas de repli sans Docker en M0 (la CLI Temporal seule ne couvre ni PostgreSQL ni OpenBao). |
| La condition `[ -d policies ]` du modèle lance `opa test` sur des dossiers vides | L'étape OPA ne s'active que s'il existe au moins un fichier `.rego` sous `policies/` ; elle échoue alors si `opa` est absent (jamais de saut silencieux). |
| `verify` du modèle suppose intégration, pile de dev et evals prêtes dès le premier jour | `verify` est complété au fil des tâches (section 5.5) : la CI n'est jamais rouge à cause d'une cible pas encore construite. |
| Arborescence de la vision sans `internal/evals`, `internal/archtest`, `cmd/rempart-evals`, `scripts/dev-*`, `.github/` | Ajoutés. Mention à porter dans `docs/00-VISION.md` §4 avec les amendements déjà prévus par les ADR 0002 et 0003 (étape D0, question Q2). |
| `/close-milestone` compare au tag du jalon précédent, inexistant pour M0 | L'humain pose le tag `m0-start` avant T01 (étape H0). |

---

## 5. Architecture de M0

### 5.1 Paquets créés en M0 (module `github.com/amezianechayer/rempart`, question Q1)

```
cmd/
  rempartd/ rempart-runner/ rempart/ rempart-mcp/   stubs (T01)
  rempart-worker/          stub (T01), worker et mode démo (T20)
  rempart-evals/           exécuteur d'evals (T23)
internal/
  <21 domaines de la vision>/doc.go                 (T01), sans code
  archtest/                règles et tests d'architecture (T01, T02, T03, T04)
  tenancy/                 identifiant de tenant, contexte (T05)
  secrets/secret/          secret.Value, secret.Bytes (T06)
  secrets/ports/           KeyWrapper (T16) [ADR-0001]
  secrets/envelope/        Sealer AES-256-GCM (T16) [ADR-0001]
  secrets/fake/            KeyWrapper en mémoire (T16) [ADR-0001]
  secrets/adapters/openbao/ KeyWrapper Transit (T17) [ADR-0001]
  llm/redact/              rédacteur (T07)
  llm/domain/              types du contrat, rendu des données non fiables, hash de requête, politique de route (T08)
  llm/ports/               ModelProvider, RouteResolver (T08)
  llm/schema/              JSON Schema strict (T09)
  llm/prompts/             prompts versionnés embarqués (T09 ; prompt de démo en T19)
  llm/fake/                faux fournisseur déterministe, résolveur de route statique (T10)
  llm/                     service Client (T11)
  llm/adapters/anthropic/  adaptateur Anthropic (T12)
  loops/domain/            findings, empreinte, score (T13)
  loops/                   RunLoop (T14), AwaitApprovals (T15), NewWorkflowID (T20), versions.go (T21)
  loops/fake/              vérificateur d'approbation factice (T15)
  loops/codec/             DataConverter, FailureConverter, propagateur (T18) [ADR-0001]
  loops/demo/              workflow de démonstration (T19, T20)
  evals/                   noyau d'évaluation (T22)
evals/demo/                suite de démonstration (T23)
scripts/dev-env.sh, scripts/dev-bootstrap.sh, scripts/dev/postgres-init.sh   (T03)
docker-compose.yml, Makefile, .golangci.yml, .github/workflows/verify.yml, .github/CODEOWNERS
```

Conventions communes : `context.Context` en premier paramètre ; erreurs sentinelles par paquet et `fmt.Errorf("...: %w", err)` ; aucun état global ; `slog` ; tags JSON en `snake_case` ; aucun `panic` hors `init` ; types d'erreur Temporal non rejouables pour les erreurs de validation.

### 5.2 Règles de dépendance vérifiées par `internal/archtest` (T02)

| Règle | Contenu |
|---|---|
| R1 `domain-pure` | `internal/*/domain/...` n'importe que la bibliothèque standard et d'autres `internal/*/domain/...` |
| R2 `adapters-edge` | `internal/*/adapters/...` n'est importé que par `cmd/...` et par d'autres adaptateurs |
| R3 `sdk-confine` | `github.com/anthropics/anthropic-sdk-go/...` importé seulement par `internal/llm/adapters/anthropic/...` (critère ADR 0002, conservé dans tous les cas) ; `go.temporal.io/sdk/...` seulement par `internal/loops/...` et `cmd/...` ; pilotes SQL seulement par `internal/*/adapters/...` |
| R4 `loops-agnostic` | `internal/loops`, `internal/loops/domain`, `internal/loops/codec`, `internal/loops/fake` n'importent, dans le module, que `internal/loops/{domain,codec,fake}`, `internal/tenancy`, `internal/secrets/{secret,ports,envelope}`. Seuls les sous-paquets de boucle (`internal/loops/demo` en M0, `internal/loops/l1` et suivants plus tard) peuvent importer un domaine ou `internal/llm`. C'est la traduction mécanique du piège « ne pas coupler `internal/loops` à un domaine ». |
| R5 `fakes-wired-in-cmd` | `internal/*/fake/...` n'est importé, hors fichiers de test, que par `cmd/...` (câblage en mode dev explicite) |

Les imports des fichiers `_test.go` ne sont pas soumis à ces règles (`go list` sans tests).

### 5.3 Flux de données de la démo (critère 4)

```
make demo
  -> cmd/rempart-worker -demo-once  (configuration explicite : -dev, -llm=fake, tenant de démo ; aucun défaut)
     -> client Temporal : DataConverter chiffrant par tenant, propagateur de tenant [ADR-0001]
        -> workflow rempart.demo.v1 (internal/loops/demo)
           -> RunLoop (internal/loops)
              -> activité Propose : llm.Client (tenant du contexte, route du tenant [ADR-0002],
                 rédaction, sortie validée par schéma) -> faux fournisseur scripté
              -> activité Verify : vérificateur déterministe (schéma + égalité à la cible)
              -> RunLoop recalcule empreinte et score, applique budget, stagnation, escalade
           -> ContinueAsNew avant l'attente [ADR-0001]
           -> AwaitApprovals : signal "approval" -> activité VerifyApproval (factice en M0)
           -> activité Commit (aucun effet externe) seulement si approuvé ; sinon rien
     <- résultat JSON sur la sortie standard
Historique Temporal (dans PostgreSQL) : payloads chiffrés AES-256-GCM, DEK par tenant
enveloppée par une clé Transit propre au tenant (OpenBao) [ADR-0001]
```

Aucune donnée issue d'un cloud n'entre dans M0. La seule donnée non fiable est la sortie du faux LLM, validée par schéma, et les signaux d'approbation, vérifiés par activité.

### 5.4 Fiche de la boucle de démonstration (gabarit `loop-spec-template.md`)

Recopiée dans `docs/loops/L0-demo.md` au début de T19, avant tout code de la démo.

```yaml
id: L0-demo
purpose: démontrer RunLoop et AwaitApprovals de bout en bout, sans aucune logique métier
trigger: démarrage manuel (make demo), test d'intégration, cible d'eval "demo"
inputs:
  - target            # chaîne attendue, synthétique (ex. "bonjour")
  - canary            # facultatif, tests de non-fuite de l'historique [ADR-0001]
  - author            # identité de l'auteur, exclue des approbateurs
  - approval_timeout  # défaut 5 s en démo
strategies: [direct, reformulate]
steps:
  propose: activité demo.Propose (llm.Client.Structured, prompt demo.greeting.v1, aucun outil)
  verify: activité demo.Verify (déterministe : schéma, puis égalité greeting == target)
  diagnose: findings normalisés (code DEMO-MISMATCH, ressource "candidate", gravité high), top 20
verifier:
  success_when:
    - candidat conforme au schéma de sortie
    - candidate.greeting == target
budget: {max_iterations: 4, max_tokens: 4000, max_wall_time: 1m, max_cost_eur: 0}
stall_detection: {same_fingerprint_switch_strategy: 2, same_fingerprint_escalate: 3}
escalation:
  to: résultat du workflow (statut escalated, raison codée), aucune attente d'approbation
  payload: [meilleur candidat, findings restants, trace des itérations, stratégies essayées]
approval: {required: 1, needs_security_role: false, défaut au timeout: ne rien faire}
outputs: [loop_result, approval_result, plan_hash, committed]
idempotency_keys: [tenant_id, workflow_id, plan_hash]
security_notes: aucune donnée cloud ; faux LLM seulement ; payloads chiffrés par tenant [ADR-0001]
evals: evals/demo/
```

### 5.5 Évolution des cibles make

| Après | `verify-quick` | `verify` | Autres cibles |
|---|---|---|---|
| T01 | `go build ./...`, `golangci-lint run ./...`, `go test -short ./...`, OPA si au moins un `.rego`, `arch-test` | `verify-quick`, `go test -tags=integration ./...`, `go tool govulncheck ./...` | `dev`, `evals` : code 2 explicite ; `sandbox-*` : code 2 via `sandbox-guard` ; `update-baseline` présent (humain seulement) |
| T03 | inchangé | ajoute `$(MAKE) dev` avant l'intégration | `dev-preflight`, `dev`, `dev-down` réels |
| T14 | `arch-test` ajoute `go tool workflowcheck ./internal/loops/...` | inchangé | |
| T20 | inchangé | inchangé | `demo` |
| T23 | inchangé | ajoute `$(MAKE) evals EVAL=changed` | `evals` réel, `update-baseline` fonctionnel |

`verify-quick` ne demande jamais Docker ni réseau (hors premier téléchargement des modules) et reste sous le délai du hook Stop (840 s).

---

## 6. Étapes humaines et documentaires

### H0. Préalables (humain, avant tout)
1. Appliquer les propositions 0001 et 0002 (`git apply ...`, `bash .claude/hooks/test_hooks.sh`, commit), redémarrer Claude Code.
2. Trancher les ADR 0001, 0002, 0003 (statut « accepté » ou amendé). En cas de refus, appliquer la section 9 à ce plan avant T01.
3. Poste : Linux, macOS ou WSL2, dépôt dans `~/rempart` ; `bash scripts/check-tools.sh` affiche `Outils requis pour M0 : OK.`
4. `python3 .claude/bin/rempart-state show` affiche `jalon=M0 phase=free` ; `git tag m0-start` (base du diff de clôture).
5. Valider ce découpage et répondre aux questions de la section 12.

### D0. Alignement documentaire des ADR acceptés (agent principal, phase free, sans code)
`python3 .claude/bin/rempart-state phase free --reason "D0 alignement documentaire des ADR acceptés"`, puis :
1. `prompts/M0.md` : section « Critères issus des ADR acceptés » reprenant les tableaux « Vérifié dès M0 » des ADR acceptés (section 8.2).
2. `docs/00-VISION.md` §4 et `MASTER_PROMPT.md` : amendements prévus par les ADR 0002 et 0003, et dossiers d'outillage (Q2).
3. `.claude/skills/agent-evals/SKILL.md` : baseline par couple plateforme et modèle `[ADR-0002]`.
4. `docs/02-THREAT-MODEL.md` : menaces nouvelles listées par les ADR acceptés, après un passage de `security-reviewer` (lecture seule : il propose, l'agent principal écrit).
5. `docs/STATUS.md` : modifications de skills signalées pour revue humaine.

Acceptation : `grep -c 'TestHistoryHasNoPlaintext' prompts/M0.md` au moins 1 `[ADR-0001]` ; `grep -c 'Apache AGE' docs/00-VISION.md` vaut 0 `[ADR-0003]` ; `grep -c 'baseline/' .claude/skills/agent-evals/SKILL.md` au moins 1 `[ADR-0002]` ; `git diff --stat m0-start` ne touche que `docs/`, `prompts/`, `MASTER_PROMPT.md`, `.claude/skills/`.

La mise en accord du squelette `temporal-loop-skeleton.md` avec le code compilé se fait à la fin de T19 (section 7), pas en D0.

### H1. Après T04 (humain)
Pousser la branche et ouvrir la PR (`git push` demande l'approbation). Recommandé : protection de `main` exigeant le contrôle `verify` et la revue des CODEOWNERS. Ensuite, une PR par tâche.

### H3. Première baseline d'eval (humain, dans la PR de T23, avant fusion)
```bash
make update-baseline EVAL=demo
git add evals/demo/baseline*        # [ADR-0002] evals/demo/baseline/fake/<modèle>.json, sinon evals/demo/baseline.json
git commit -m "test(evals): initial baseline for demo suite"
make -s evals EVAL=demo | jq -e '.regressions_vs_baseline == []'
```
Tant que H3 n'est pas fait, `make verify` (donc la CI de cette PR) est rouge avec le code 3 et un message qui demande exactement cette commande. C'est voulu : aucune baseline n'est créée par l'agent.

### H4. Clôture
`/close-milestone M0` : `make verify`, `make evals`, `acceptance-verifier` sur les critères de `prompts/M0.md` (5 d'origine et ceux ajoutés en D0), `security-reviewer` sur `git diff m0-start..HEAD`, intégration des menaces nouvelles (section 11.2) au modèle de menace, tag posé par l'humain.

---

## 7. Tâches

Chaque tâche suit `/task` : plan détaillé, phase tests (subagent `test-author`), phase impl, `make verify-quick`, revue sécurité si indiquée, `acceptance-verifier`, clôture dans `docs/STATUS.md` et commit conventionnel. Les critères d'acceptation ci-dessous sont des commandes ; `rc=` désigne le code de sortie affiché par `echo rc=$?`.

---

### M0-T01 `squelette` : squelette compilable, Makefile, lint, `make verify-quick` vert
- **Objectif** : amener le dépôt à `make verify-quick` vert avant toute logique ; poser l'arborescence de la vision.
- **Dépend de** : H0, D0. **ADR** : aucun. **Outils** : O-base, O-net. **Revue sécurité** : non (stubs seulement).
- **Fichiers** : `go.mod` ; `cmd/{rempartd,rempart-worker,rempart-runner,rempart,rempart-mcp}/main.go` ; `internal/{intent,design,threat,policy,iacgen,validate,plan,apply,runner,inventory,graph,attackpath,remediate,drift,finops,compliance,evidence,loops,llm,secrets,tenancy}/doc.go` ; `internal/archtest/doc.go` ; `policies/{design,iac,runtime,k8s}/.gitkeep`, `modules/.gitkeep`, `schemas/.gitkeep`, `evals/.gitkeep`, `web/.gitkeep` ; `Makefile` (`git mv Makefile.template Makefile`, puis corrections de la section 4) ; `.golangci.yml` ; `.gitignore` (ajouts `/bin/`, `evals/**/reports/`).
- **Étape 0** (agent principal, juste après `phase tests`, avant délégation) : `go mod init github.com/amezianechayer/rempart`, `go mod edit -go=<dernière stable>`, `go get -tool golang.org/x/vuln/cmd/govulncheck@<version>`. `go.mod` n'est pas du code de production pour le harnais ; sans lui, les tests échoueraient pour une mauvaise raison (module introuvable).
- **Interfaces** :
  ```go
  // cmd/<binaire>/main.go : aucun comportement
  func main() // écrit "<binaire>: not implemented (M0)" sur stderr et sort avec le code 2
  ```
- **Phase tests** (`internal/archtest/*_test.go`), rouges parce que dossiers, `Makefile` et `.golangci.yml` n'existent pas :
  - `TestLayoutMatchesVision` : chaque dossier de §4 existe ; chaque `internal/<d>` a un `doc.go` avec commentaire de paquet ; chaque `cmd/<b>` est un paquet `main`.
  - `TestGoDirective` : directive `go` au moins 1.23.
  - `TestMakefileTargets` : cibles `verify-quick verify evals dev dev-preflight dev-down sandbox-guard sandbox-plan sandbox-apply sandbox-destroy update-baseline arch-test` ; `sandbox-plan`, `sandbox-apply`, `sandbox-destroy` ont `sandbox-guard` en prérequis ; l'étape OPA est conditionnée à la présence d'un `.rego`.
  - `TestGolangciConfig` : `version: "2"` ; linters `gosec`, `errorlint`, `contextcheck`, `nolintlint` (explication et linter précis exigés) ; formateur `gofumpt`.
- **Acceptation** :
  1. `grep -E '^go 1\.[0-9]+' go.mod` : au moins 1.23, égale à la dernière stable du jour.
  2. `make verify-quick; echo rc=$?` : `rc=0`.
  3. `go test ./internal/archtest/ -run 'TestLayoutMatchesVision|TestGoDirective|TestMakefileTargets|TestGolangciConfig' -v` : 4 `--- PASS`.
  4. `golangci-lint config verify; echo rc=$?` : `rc=0`.
  5. `make sandbox-plan SCENARIO=demo; echo rc=$?` : message contenant `scripts/sandbox.sh absent`, `rc=2`.
  6. `make evals; echo rc=$?` : message contenant `M0-T23`, `rc=2` ; `make dev; echo rc=$?` : message contenant `M0-T03`, `rc=2`.
  7. `go run ./cmd/rempartd; echo rc=$?` : `rc=2`.
  8. `grep -rn 'nolint' --include='*.go' . | wc -l` : `0`.

---

### M0-T02 `archtest-imports` : règles de dépendance et découplage de `internal/loops`
- **Objectif** : rendre mécaniques les règles R1 à R5 (section 5.2), dont le piège « ne pas coupler `internal/loops` à un domaine ».
- **Dépend de** : T01. **ADR** : R3 reprend un critère de l'ADR 0002 mais découle aussi de la vision ; conservée dans tous les cas. **Outils** : O-base. **Revue sécurité** : oui, légère (exécution de `go list`).
- **Fichiers** : `internal/archtest/{rules.go,packages.go}`, tests, `internal/archtest/testdata/golist/*.json`.
- **Interfaces** :
  ```go
  package archtest

  type Package struct {
  	ImportPath string   `json:"ImportPath"`
  	Imports    []string `json:"Imports"`
  }

  type RuleKind int

  const (
  	Confine  RuleKind = iota // seuls AllowedFrom peuvent importer Targets
  	Restrict                 // From n'importe, parmi les paquets du module, que AllowedTargets
  )

  type Rule struct {
  	Name                                       string
  	Kind                                       RuleKind
  	From, Targets, AllowedFrom, AllowedTargets []string // chemin exact, suffixe "/...", joker "*" sur un segment
  }

  type Violation struct{ Rule, Importer, Imported string }

  func Match(pattern, importPath string) bool
  // LoadPackages lance exec.CommandContext(ctx, "go", "list", "-json", "./...") : arguments en tableau, sans shell.
  func LoadPackages(ctx context.Context, moduleDir string) ([]Package, error)
  func Check(module string, pkgs []Package, rules []Rule) []Violation
  func DefaultRules(module string) []Rule
  ```
- **Phase tests**, rouges car `Match`, `Check`, `DefaultRules` sont indéfinis : `TestMatch` (table) ; `TestRuleDetectsViolation/<règle>` (par règle, une fixture en violation détectée et une conforme acceptée : témoins négatifs) ; `TestRepositoryConforms` (dépôt réel, zéro violation) ; `TestStdlibDetection` (un chemin sans point dans le premier segment est la bibliothèque standard).
- **Acceptation** :
  1. `go test ./internal/archtest/ -run TestRuleDetectsViolation -v 2>&1 | grep -c -- '--- PASS: TestRuleDetectsViolation/'` : au moins `5`.
  2. `go test ./internal/archtest/ -run TestRepositoryConforms -v` : `--- PASS`.
  3. `make verify-quick; echo rc=$?` : `rc=0`.

---

### M0-T03 `pile-dev` : `docker-compose.yml` et `make dev`
- **Objectif** : Temporal, PostgreSQL et OpenBao en mode dev, démarrés et prêts par `make dev`, sans secret en clair et sans exposition réseau.
- **Dépend de** : T01. **ADR** : `[ADR-0001]` (Transit, clés de tenants de démo, jeton du worker limité, namespace à rétention 7 jours) ; `[ADR-0003]` (image `postgres` officielle, pas d'AGE, bases et rôles distincts). **Outils** : O-docker, O-net. **Revue sécurité** : oui (jetons de dev, exposition, politique OpenBao).
- **Fichiers** : `docker-compose.yml` ; `scripts/dev-env.sh` (crée `.env.dev` s'il manque, `umask 077`, valeurs aléatoires, déjà ignoré par `.env.*`) ; `scripts/dev-bootstrap.sh` (idempotent : moteur Transit, clé par tenant de démo et tenant système avec suppression interdite, politique et jeton du worker limités à `transit/datakey/plaintext/rempart-tenant-*` et `transit/decrypt/rempart-tenant-*`, namespace Temporal `rempart` à rétention 7 jours) ; `scripts/dev/postgres-init.sh` (bases et rôles `temporal` et `rempart`, `REVOKE CONNECT ... FROM PUBLIC`) ; `Makefile` (`dev-preflight`, `dev` avec `docker compose up -d --wait`, `dev-down`, `verify` complété, variables de `.env.dev` exportées vers les tests sans jamais les afficher) ; `internal/archtest/compose_test.go` ; `internal/archtest/devstack_integration_test.go`.
- **Interfaces** : aucune API Go de production.
- **Phase tests**, rouges car `docker-compose.yml` est absent :
  - unitaires : `TestComposeServices` (temporal, postgres, openbao) ; `TestComposeImagesPinnedByDigest` (`@sha256:` sur chaque image) ; `TestComposePortsLoopbackOnly` (tout port publié sur `127.0.0.1`) ; `TestComposeNoLiteralSecrets` (jetons et mots de passe uniquement par `${...}` ou `env_file`) ; `TestComposePostgresOfficialNoAGE` `[ADR-0003]` ; `TestMakeDevUsesWait`.
  - intégration (`//go:build integration`) : `TestDevStackTemporalHealthy` (client Temporal, vérification de santé) ; `TestDevStackPostgresRolesSeparated` `[ADR-0003]` (le rôle `rempart` ne se connecte pas à la base `temporal`) ; `TestDevStackTransitReady` `[ADR-0001]` (moteur monté, clés des tenants de démo présentes, le jeton du worker ne peut ni créer ni supprimer une clé).
- **Acceptation** :
  1. `make dev; echo rc=$?` : `rc=0` ; relancé une seconde fois : `rc=0` (idempotent).
  2. `docker compose ps --services --status running | sort | tr '\n' ' '` : `openbao postgres temporal ` (plus d'éventuels services annexes documentés).
  3. `docker compose config --images | grep -Ec '^(docker\.io/library/)?postgres[:@]'` : `1` `[ADR-0003]`.
  4. `grep -Eic -e 'apache/?age' -e 'create extension.*\bage\b' docker-compose.yml scripts/dev/postgres-init.sh` : `0` pour chaque fichier `[ADR-0003]`.
  5. `docker compose config --format json | jq -r '.services[].ports[]?.host_ip' | sort -u` : `127.0.0.1`.
  6. `go test -tags=integration -run TestDevStack ./internal/archtest/... -v` : 3 `--- PASS`.
  7. `git check-ignore .env.dev` : `.env.dev`.
  8. Sans Docker (ou démon arrêté) : `make dev; echo rc=$?` : message renvoyant à `docs/SETUP.md`, `rc=2`.
  9. `make dev-down; echo rc=$?` : `rc=0`.

---

### M0-T04 `ci` : GitHub Actions exécutant `make verify` sur chaque PR
- **Objectif** : critère 1 côté CI, avec une chaîne d'approvisionnement durcie (dépôt public).
- **Dépend de** : T03 (`verify` démarre la pile). **ADR** : aucun. **Outils** : O-base ; O-gh facultatif ; `git push` soumis à approbation humaine (H1). **Revue sécurité** : oui (T6, dépôt public).
- **Fichiers** : `.github/workflows/verify.yml` (déclencheurs `pull_request` et `push` sur `main` ; `permissions: contents: read` ; `concurrency` ; runner Ubuntu à version fixe ; `timeout-minutes` ; `actions/checkout` avec `fetch-depth: 0` ; `actions/setup-go` avec `go-version-file: go.mod` ; golangci-lint à version épinglée ; `make verify` avec `EVAL_BASE` égal à la branche de base de la PR ; `make dev-down` en fin de job ; aucune référence à `secrets.`) ; `.github/CODEOWNERS` (`/evals/**/baseline*`, `/.claude/`, `/CLAUDE.md`, `/.github/` attribués à l'humain) ; `internal/archtest/ci_test.go`.
- **Interfaces** : aucune.
- **Phase tests**, rouges car les fichiers sont absents : `TestCIWorkflowTriggers` (`pull_request`, jamais `pull_request_target`) ; `TestCIPermissionsReadOnly` ; `TestCIActionsPinnedBySHA` (chaque `uses:` se termine par 40 caractères hexadécimaux) ; `TestCIRunsMakeVerify` ; `TestCINoSecrets` ; `TestCIGoVersionFromGoMod` ; `TestCodeownersProtectsBaselines`.
- **Acceptation** :
  1. `go test ./internal/archtest/ -run 'TestCI|TestCodeowners' -v` : 7 `--- PASS`.
  2. `test "$(grep -c 'uses:' .github/workflows/verify.yml)" = "$(grep -Ec 'uses: [^@]+@[0-9a-f]{40}' .github/workflows/verify.yml)"; echo rc=$?` : `rc=0`.
  3. Après H1 : `gh run list --workflow verify.yml --limit 1 --json conclusion --jq '.[0].conclusion'` : `success` (ou l'onglet Actions de la PR).

---

### M0-T05 `tenancy` : identifiant de tenant dans le contexte
- **Objectif** : un tenant obligatoire, validé et vérifiable à chaque frontière (T3), dont dépendent `llm.Client`, l'enveloppe et le codec.
- **Dépend de** : T01. **ADR** : aucun. **Outils** : O-base. **Revue sécurité** : oui (multi-tenant).
- **Fichiers** : `internal/tenancy/tenant.go`, tests.
- **Interfaces** :
  ```go
  package tenancy

  type ID string // UUID canonique en minuscules ; la valeur zéro est invalide

  // System : tenant réservé des workflows système (ADR 0001), jamais attribué à un client, différent de l'UUID nul.
  const System ID = "..." // valeur fixée par le plan de tâche

  var (
  	ErrNoTenant       = errors.New("tenancy: no tenant in context")
  	ErrInvalidTenant  = errors.New("tenancy: invalid tenant id")
  	ErrTenantMismatch = errors.New("tenancy: tenant mismatch")
  )

  func ParseID(s string) (ID, error) // refuse toute forme non canonique (majuscules, accolades, UUID nul)
  func (id ID) String() string
  func WithTenant(ctx context.Context, id ID) (context.Context, error)
  func FromContext(ctx context.Context) (ID, error)
  func Require(ctx context.Context, want ID) error // ErrNoTenant ou ErrTenantMismatch
  ```
- **Phase tests**, rouges car le paquet n'a que `doc.go` : `TestParseIDCanonicalOnly` (table : valide, majuscules, vide, UUID nul, espaces, 37 caractères) ; `TestFromContextWithoutTenant` ; `TestWithTenantRejectsInvalid` ; `TestRoundTrip` (propriété `rapid` : `ParseID(id.String()) == id`) ; `TestRequireMismatch` ; `TestSystemTenantIsValidAndDistinct`.
- **Acceptation** :
  1. `go test ./internal/tenancy/... -v` : tous `--- PASS`, dont les 6 tests nommés.
  2. `make verify-quick; echo rc=$?` : `rc=0`.

---

### M0-T06 `secret-value` : types `secret.Value` et `secret.Bytes`
- **Objectif** : aucun secret affichable par `fmt`, `slog` ou `encoding/json` (principe 9), y compris par réflexion sur un champ non exporté.
- **Dépend de** : T01. **ADR** : aucun (`secret.Bytes` sert l'ADR 0001 mais reste utile sans lui). **Outils** : O-base. **Revue sécurité** : oui (secrets).
- **Fichiers** : `internal/secrets/secret/{value.go,bytes.go}`, tests.
- **Interfaces** :
  ```go
  package secret

  const Redacted = "[REDACTED]"

  // Value garde la valeur derrière un pointeur : une impression par réflexion d'un champ non exporté
  // affiche une adresse, jamais le contenu.
  type Value struct{ p *string }

  func New(s string) Value
  func (v Value) Reveal() string
  func (v Value) IsZero() bool
  func (Value) String() string
  func (Value) GoString() string
  func (Value) Format(f fmt.State, verb rune)
  func (Value) MarshalJSON() ([]byte, error)
  func (Value) MarshalText() ([]byte, error)
  func (Value) LogValue() slog.Value

  type Bytes struct{ p *[]byte }

  func NewBytes(b []byte) Bytes // copie défensive
  func (b Bytes) Reveal() []byte // vue à ne pas conserver
  func (b Bytes) Len() int
  func (b Bytes) Wipe()        // remet les octets à zéro
  // Bytes a les mêmes méthodes de masquage que Value.
  ```
- **Phase tests**, rouges car le paquet n'existe pas : `TestValueNeverPrinted` (table sur `%v %+v %#v %s %q %x`, `Sprint`, `Println`) ; `TestNoLeakThroughUnexportedField` (structure avec champ non exporté de type `Value`, imprimée avec `%+v`) ; `TestJSONRedacts` ; `TestSlogRedacts` (gestionnaires texte et JSON) ; `TestRevealReturnsValue` ; `TestBytesWipe` ; `TestNewBytesCopies`.
- **Acceptation** :
  1. `go test ./internal/secrets/secret/... -v` : tous `--- PASS`, dont les 7 tests nommés.
  2. `make verify-quick; echo rc=$?` : `rc=0`.

---

### M0-T07 `redaction` : rédacteur de secrets (critère 3, première moitié)
- **Objectif** : masquer, avant tout appel LLM, chaque motif de `.claude/skills/llm-safety/references/redaction-patterns.md`.
- **Dépend de** : T01. **ADR** : aucun. **Outils** : O-base. **Revue sécurité** : oui (LLM, secrets, T7).
- **Fichiers** : `internal/llm/redact/{redact.go,rules.go}`, tests, `internal/llm/redact/testdata/` (fixtures marquées `EXAMPLE` ou `FAKE`).
- **Interfaces** :
  ```go
  package redact

  type Kind string

  const (
  	KindAWSAccessKey    Kind = "aws_access_key"    // AKIA..., ASIA...
  	KindAWSSecretKey    Kind = "aws_secret_key"
  	KindAWSSessionToken Kind = "aws_session_token"
  	KindAzureSecret     Kind = "azure_secret"      // secret de principal de service, AccountKey=, sig=
  	KindScalewayKey     Kind = "scaleway_key"
  	KindOVHCredential   Kind = "ovh_credential"    // application key et secret, consumer key
  	KindPrivateKey      Kind = "private_key"       // PEM RSA, EC, OpenSSH, PKCS#8, certificat avec clé
  	KindGitHubToken     Kind = "github_token"      // ghp_, github_pat_
  	KindGitLabToken     Kind = "gitlab_token"      // glpat-
  	KindSlackToken      Kind = "slack_token"       // xox?-
  	KindLLMAPIKey       Kind = "llm_api_key"       // sk-ant-, sk-
  	KindURLCredentials  Kind = "url_credentials"   // scheme://user:pass@host
  	KindDBConnString    Kind = "db_connection_string"
  	KindKubeconfig      Kind = "kubeconfig_credential" // client-key-data, token
  	KindSensitiveVar    Kind = "sensitive_variable"    // *password*, *secret*, *token*, *api_key* (HCL, tfvars, YAML, JSON, env)
  	KindIPsecPSK        Kind = "ipsec_psk"
  )

  type Match struct { // positions dans l'entrée ; jamais la valeur
  	Kind       Kind
  	Start, End int
  }

  type Redactor struct{ /* règles compilées, immuables après New */ }

  func New() *Redactor
  func (r *Redactor) Redact(s string) (string, []Match) // remplace par Placeholder(kind)
  func (r *Redactor) ContainsSecret(s string) bool
  func (r *Redactor) Kinds() []Kind
  func Placeholder(k Kind) string // "[REDACTED:<kind>]"
  ```
- **Phase tests**, rouges car le paquet n'existe pas :
  - `TestRedactPatterns` : table d'au moins 24 sous-tests, au moins un cas positif par ligne du fichier de référence (12 lignes) et des variantes (clé seule, dans du JSON, dans un tfvars, dans un manifeste YAML, dans une URL).
  - `TestEveryPatternLineMapped` : lit le fichier de référence du skill et vérifie que chaque ligne à puce est associée à au moins un `Kind` et à au moins un cas positif (traçabilité skill vers test).
  - `TestNoFalsePositive` : prose contenant « password » sans valeur, hash SHA-256 isolé, UUID, `max_tokens: 1024` (règle précisée dans le plan de tâche).
  - `TestIdempotent` : `Redact(Redact(x)) == Redact(x)`.
  - `TestPropertyNoSecretSurvives` (`rapid`) : secret généré de chaque famille inséré dans un texte aléatoire ; la sortie ne contient plus le secret et `ContainsSecret(sortie)` est faux.
  - `TestMatchesCarryNoValue`.
- **Acceptation** :
  1. `go test ./internal/llm/redact/ -run TestRedactPatterns -v 2>&1 | grep -c -- '--- PASS: TestRedactPatterns/'` : au moins `24` (critère 3 : au moins 10).
  2. `go test ./internal/llm/redact/ -run 'TestEveryPatternLineMapped|TestNoFalsePositive|TestIdempotent|TestPropertyNoSecretSurvives|TestMatchesCarryNoValue' -v` : 5 `--- PASS`.
  3. `make verify-quick; echo rc=$?` : `rc=0`.

---

### M0-T08 `llm-contrat` : types du contrat, `ModelProvider`, données non fiables, politique de route
- **Objectif** : le contrat commun à tous les fournisseurs ; séparation vérifiable par le type entre appel sans outils (seul autorisé à recevoir des données non fiables) et appel avec outils (T2).
- **Dépend de** : T05. **ADR** : `[ADR-0002]` pour `Route`, `Capabilities`, `TenantPolicy`, `CheckPolicy`, `RouteResolver`. **Outils** : O-base. **Revue sécurité** : oui (LLM).
- **Fichiers** : `internal/llm/domain/{types.go,untrusted.go,hash.go,policy.go}`, `internal/llm/ports/provider.go`, tests.
- **Interfaces** :
  ```go
  package domain // bibliothèque standard seulement (R1)

  type Platform string

  const (
  	PlatformAnthropic  Platform = "anthropic"
  	PlatformBedrock    Platform = "bedrock"
  	PlatformVertex     Platform = "vertex"
  	PlatformSelfHosted Platform = "selfhosted"
  	PlatformFake       Platform = "fake"
  )

  type Route struct { Platform Platform; Region, Model string } // Model : identifiant exact, jamais un alias
  type Role string
  type UntrustedBlock struct { SourceID, Content string }
  type Part struct { Text string; Untrusted *UntrustedBlock } // exactement un des deux
  type Message struct { Role Role; Parts []Part }
  type ToolSpec struct { Name, Description string; InputSchema json.RawMessage }
  type ToolCall struct { Name string; Input json.RawMessage }
  type Usage struct { InputTokens, OutputTokens int }
  type Request struct {
  	PromptID, PromptHash, System string
  	Messages                     []Message
  	Schema                       json.RawMessage
  	MaxTokens                    int
  }
  type Response struct {
  	Output    json.RawMessage // brut : validé par le service, jamais par l'adaptateur seul
  	ToolCalls []ToolCall
  	Usage     Usage
  	Model     string // modèle déclaré par la réponse, comparé à Route.Model
  	RequestID string
  }
  type Capabilities struct { NativeStructuredOutput, StrictTools, RequiresRetention bool }

  func (r Request) HasUntrusted() bool
  // RenderUntrusted délimite le bloc (<DONNÉES_NON_FIABLES id="...">) et neutralise toute balise
  // d'ouverture ou de fermeture présente dans le contenu. Seule fonction de rendu, commune aux adaptateurs.
  func RenderUntrusted(b UntrustedBlock) string
  func RequestHash(r Request) string // SHA-256 hexadécimal d'un JSON canonique

  // [ADR-0002]
  type Residency string // "eu" | "none"
  type Retention string // "zero" | "standard"
  type TenantPolicy struct { Route Route; Residency Residency; Retention Retention }
  // CheckPolicy : liste blanche codée des couples (plateforme, région) pour "eu" (Anthropic direct refusé) ;
  // modèle exigeant une rétention refusé si "zero" ; modèle vide ou alias refusé.
  func CheckPolicy(p TenantPolicy, caps Capabilities) error

  var (
  	ErrResidency, ErrRetention, ErrModelNotPinned error
  	ErrUntrustedWithTools                          error
  )

  package ports

  type ModelProvider interface {
  	// Structured n'expose aucun outil ; seul appel autorisé à recevoir un UntrustedBlock.
  	Structured(ctx context.Context, route domain.Route, req domain.Request) (domain.Response, error)
  	// WithTools refuse toute requête contenant un UntrustedBlock (domain.ErrUntrustedWithTools).
  	WithTools(ctx context.Context, route domain.Route, req domain.Request, tools []domain.ToolSpec) (domain.Response, error)
  	Capabilities(route domain.Route) domain.Capabilities
  }

  // [ADR-0002] Pas de route par défaut : un tenant sans route n'appelle aucun modèle.
  type RouteResolver interface {
  	Resolve(ctx context.Context, tenant tenancy.ID) (domain.TenantPolicy, error)
  }
  ```
- **Phase tests**, rouges car les paquets n'existent pas : `TestRenderUntrustedEscapesDelimiter` (contenu contenant une balise de fermeture, une fausse balise d'ouverture, un faux message système) ; `TestRequestHasUntrusted` ; `TestRequestHashCanonical` (propriété : requêtes égales, hash égaux ; un champ modifié, hash différent) ; `TestPartExactlyOne` ; `[ADR-0002]` `TestCheckPolicyResidencyEU` (anthropic refusé, bedrock `eu-west-3` accepté, bedrock `us-east-1` refusé, vertex `eu` accepté), `TestCheckPolicyRetentionZero`, `TestCheckPolicyModelPinned`.
- **Acceptation** :
  1. `go test ./internal/llm/domain/... ./internal/llm/ports/... -v` : tous `--- PASS`, dont les 7 tests nommés.
  2. `go test ./internal/archtest/ -run TestRepositoryConforms` : `ok` (R1 respectée).
  3. `make verify-quick; echo rc=$?` : `rc=0`.

---

### M0-T09 `llm-schema-prompts` : JSON Schema strict et prompts versionnés
- **Objectif** : toute sortie LLM validée contre un schéma strict (critère 3, seconde moitié, niveau validateur) ; prompts identifiés et hachés (`llm-safety`, règle 6).
- **Dépend de** : T08. **ADR** : aucun. **Outils** : O-base. **Revue sécurité** : oui (LLM).
- **Fichiers** : `internal/llm/schema/schema.go` (enveloppe la bibliothèque JSON Schema, hors `domain` pour respecter R1) ; `internal/llm/prompts/{registry.go,embed.go}` ; tests ; `internal/llm/prompts/testdata/fixture.v1/{system.txt,schema.json}`.
- **Interfaces** :
  ```go
  package schema

  var (
  	ErrOutOfSchema     = errors.New("llm: output does not match schema")
  	ErrSchemaNotStrict = errors.New("llm: schema is not strict")
  )

  const MaxOutputBytes = 256 << 10

  type Schema struct{ /* compilé */ }

  // CompileSchema : Draft 2020-12 ; refuse un schéma dont un objet n'a pas additionalProperties:false.
  func CompileSchema(raw json.RawMessage) (*Schema, error)
  // Validate : refuse une sortie non JSON, suivie de données, trop grande ou hors schéma.
  // Le message d'erreur donne le chemin JSON fautif, jamais le contenu de la sortie.
  func (s *Schema) Validate(output json.RawMessage) error
  func (s *Schema) Raw() json.RawMessage

  package prompts

  type Prompt struct {
  	ID      string // ex. "demo.greeting.v1"
  	Version int
  	System  string
  	Schema  *schema.Schema
  	Hash    string // SHA-256 de System et du schéma brut
  }

  func LoadFS(fsys fs.FS, id string) (Prompt, error) // <id>/system.txt et <id>/schema.json
  func Load(id string) (Prompt, error)               // prompts embarqués (embed.FS)
  ```
- **Phase tests**, rouges car les paquets n'existent pas : `TestCompileSchemaRequiresStrict` ; `TestValidateAcceptsConforming` ; `TestValidateRejectsOutOfSchema` (table : champ requis absent, champ en trop, mauvais type, pas du JSON, JSON suivi de données, sortie de plus de 256 Kio) ; `TestValidationErrorDoesNotEchoOutput` ; `TestPromptHashStableAndSensitive` ; `TestPromptUnknownID`.
- **Acceptation** :
  1. `go test ./internal/llm/schema/... ./internal/llm/prompts/... -v` : tous `--- PASS`, dont les 6 tests nommés.
  2. `make verify-quick; echo rc=$?` : `rc=0`.

---

### M0-T10 `llm-fake` : faux fournisseur déterministe
- **Objectif** : un faux sans réseau, déterministe, qui échoue en fermé ; deux modes : enregistré (clé `PromptID` et hash de requête, ADR 0002) et scripté (séquence par `PromptID`, pour les tests de workflow et la démo, dont les requêtes dépendent de code écrit après les tests).
- **Dépend de** : T08. **ADR** : `[ADR-0002]` pour la clé d'indexation et `TestFakeDeterministic` ; le faux lui-même est un livrable M0 dans tous les cas. **Outils** : O-base. **Revue sécurité** : oui (LLM, risque de câblage en production : R5 et section 11.2).
- **Fichiers** : `internal/llm/fake/{provider.go,resolver.go}`, tests, `internal/llm/fake/testdata/*.json`.
- **Interfaces** :
  ```go
  package fake

  var (
  	ErrNoRecording     = errors.New("fake: no recording for request")
  	ErrScriptExhausted = errors.New("fake: script exhausted")
  )

  type Recording struct {
  	PromptID, RequestHash string
  	Response              domain.Response
  	Err                   string
  }
  type Step struct { Response domain.Response; Err string }
  type Options struct {
  	Recordings   []Recording
  	Scripts      map[string][]Step // par PromptID, consommées dans l'ordre ; enregistrement prioritaire
  	Capabilities domain.Capabilities
  }

  type Provider struct{ /* mutex, index, curseurs, requêtes capturées */ }

  func New(opt Options) *Provider
  func LoadOptions(fsys fs.FS, path string) (Options, error) // JSON, champs inconnus refusés
  func (p *Provider) Structured(ctx context.Context, route domain.Route, req domain.Request) (domain.Response, error)
  func (p *Provider) WithTools(ctx context.Context, route domain.Route, req domain.Request, tools []domain.ToolSpec) (domain.Response, error)
  func (p *Provider) Capabilities(route domain.Route) domain.Capabilities
  func (p *Provider) Requests() []domain.Request // copie, pour l'interception en test

  // RouteResolver statique pour le dev et les tests [ADR-0002].
  type RouteResolver struct{ Policies map[tenancy.ID]domain.TenantPolicy }
  func (r RouteResolver) Resolve(ctx context.Context, tenant tenancy.ID) (domain.TenantPolicy, error)
  ```
- **Phase tests**, rouges car le paquet n'existe pas : `TestFakeDeterministic` (même requête, même réponse à l'octet) ; `TestFakeNoRecordingIsError` ; `TestFakeScriptOrderAndExhaustion` ; `TestFakeWithToolsRefusesUntrusted` ; `TestFakeCapturesRequestsCopy` ; `TestLoadOptionsRejectsUnknownFields` ; `TestStaticResolverUnknownTenant`.
- **Acceptation** :
  1. `go test ./internal/llm/fake/... -v` : tous `--- PASS`, dont les 7 tests nommés.
  2. `make verify-quick; echo rc=$?` : `rc=0`.

---

### M0-T11 `llm-client` : service `llm.Client`, seul point d'entrée des domaines (critère 3)
- **Objectif** : tenant, route, rédaction, budget, appel, validation de schéma avec correction bornée, trace ; une réponse hors schéma est rejetée.
- **Dépend de** : T05, T07, T09, T10. **ADR** : `[ADR-0002]` pour la résolution de route, `CheckPolicy`, le contrôle du modèle déclaré et la trace plateforme et région. **Outils** : O-base. **Revue sécurité** : oui (LLM, multi-tenant, T7, T10).
- **Fichiers** : `internal/llm/{client.go,trace.go}`, tests.
- **Interfaces** :
  ```go
  package llm

  var (
  	ErrNoRoute       = errors.New("llm: no route for tenant")
  	ErrModelMismatch = errors.New("llm: response model differs from route")
  	ErrTokenBudget   = errors.New("llm: token budget exceeded")
  )

  type Config struct {
  	MaxCorrections   int // défaut 1, au plus 3
  	MaxTokensPerCall int
  }

  type Client struct{ /* provider, resolver, redactor, cfg */ }

  func NewClient(p ports.ModelProvider, rr ports.RouteResolver, r *redact.Redactor, cfg Config) (*Client, error)

  type Call struct {
  	Prompt    prompts.Prompt
  	Messages  []domain.Message
  	MaxTokens int
  }

  type Trace struct {
  	Tenant                                                  tenancy.ID
  	Platform                                                domain.Platform
  	Region, Model, PromptID, PromptHash, RequestID          string
  	Attempts, Redactions                                    int
  	Usage                                                   domain.Usage
  }

  type Result struct { Output json.RawMessage; Trace Trace }

  func (c *Client) Structured(ctx context.Context, call Call) (Result, error)
  // WithTools valide aussi chaque ToolCall contre l'InputSchema de son outil ; outil inconnu : erreur.
  func (c *Client) WithTools(ctx context.Context, call Call, tools []domain.ToolSpec) (Result, []domain.ToolCall, error)
  ```
  La correction bornée renvoie au modèle le chemin fautif et la règle violée, jamais la sortie brute. Toutes les parties `Text` et `Untrusted` sont rédigées avant l'appel.
- **Phase tests** (faux de T10), rouges car `NewClient` est indéfini : `TestOutOfSchemaRejected` (critère 3) ; `TestBoundedCorrection` (invalide puis valide : succès en 2 tentatives ; invalide à chaque fois : `ErrOutOfSchema` après `1 + MaxCorrections` appels) ; `TestTenantRequired` ; `TestRedactionBeforeProvider` (aucune requête capturée ne contient un motif détecté par `ContainsSecret`) ; `TestUntrustedBlockRejectedWithTools` ; `TestTokenBudget` ; `[ADR-0002]` `TestNoRouteNoCall` (zéro requête capturée), `TestRetentionZeroRejectsRetentionModel`, `TestModelMismatchRejected`, `TestCrossTenantRouteIsolation` (la route du tenant A n'est jamais utilisée pour B), `TestTraceCarriesRoute`.
- **Acceptation** :
  1. `go test ./internal/llm/ -run 'TestOutOfSchemaRejected|TestBoundedCorrection|TestTenantRequired|TestRedactionBeforeProvider|TestUntrustedBlockRejectedWithTools|TestTokenBudget|TestNoRouteNoCall|TestRetentionZeroRejectsRetentionModel|TestModelMismatchRejected|TestCrossTenantRouteIsolation|TestTraceCarriesRoute' -v` : 11 `--- PASS` (6 sans l'ADR 0002).
  2. `make verify-quick; echo rc=$?` : `rc=0`.

---

### M0-T12 `llm-anthropic` : adaptateur Anthropic testé contre `httptest`
- **Objectif** : adaptateur réel, SDK officiel épinglé, sans aucun appel réseau réel en test ni en CI.
- **Dépend de** : T06, T08, T11. **ADR** : `[ADR-0002]` pour `TestResidencyEUBlocksAnthropicDirect` et la table `Capabilities` ; l'adaptateur lui-même est un livrable M0 dans tous les cas. **Outils** : O-base, O-net. **Revue sécurité** : oui (LLM, secrets, T7).
- **Fichiers** : `internal/llm/adapters/anthropic/provider.go`, tests ; `internal/llm/contract_test.go` (paquet `llm_test`, contrat commun exécuté sur le faux et sur l'adaptateur).
- **Interfaces** :
  ```go
  package anthropic

  var ErrWrongPlatform = errors.New("anthropic: route platform is not anthropic")

  type Config struct {
  	APIKey     secret.Value
  	BaseURL    string       // défaut : URL officielle ; serveur httptest en test
  	HTTPClient *http.Client
  	Timeout    time.Duration
  }

  type Provider struct{ /* client du SDK */ }

  // New refuse une clé vide ; reprises du SDK à 0 (les reprises relèvent de Temporal, T10).
  func New(cfg Config) (*Provider, error)
  func (p *Provider) Structured(ctx context.Context, route domain.Route, req domain.Request) (domain.Response, error)
  func (p *Provider) WithTools(ctx context.Context, route domain.Route, req domain.Request, tools []domain.ToolSpec) (domain.Response, error)
  func (p *Provider) Capabilities(route domain.Route) domain.Capabilities // table statique datée et sourcée
  ```
- **Phase tests** (serveur `httptest` qui capture les corps), rouges car le paquet n'existe pas : `TestProviderContract` (faux et adaptateur : même comportement sur requête valide, refus des blocs non fiables avec outils, erreur typée sur réponse vide) ; `TestAnthropicRequestShape` (schéma transmis dans le paramètre de sortie structurée, `strict: true` sur chaque outil, noms à confirmer sur la version épinglée) ; `TestAPIKeyOnlyInHeader` ; `TestNoSecretInOutgoingRequest` (aucun corps capturé ne contient un motif de `redaction-patterns.md`) ; `TestHTTPErrorMapping` (429 et 5xx : erreur rejouable ; 4xx : non rejouable ; le corps d'erreur n'est pas recopié dans le message) ; `TestNoRetryInSDK` (une seule requête reçue sur 500) ; `TestModelEchoed` ; `[ADR-0002]` `TestResidencyEUBlocksAnthropicDirect` (via `llm.Client`, zéro requête reçue).
- **Acceptation** :
  1. `go test ./internal/llm/... -run 'TestProviderContract|TestAnthropicRequestShape|TestAPIKeyOnlyInHeader|TestNoSecretInOutgoingRequest|TestHTTPErrorMapping|TestNoRetryInSDK|TestModelEchoed|TestResidencyEUBlocksAnthropicDirect' -v` : tous `--- PASS`.
  2. `go list -m github.com/anthropics/anthropic-sdk-go` : une version `vX.Y.Z` exacte (pas de pseudo-version).
  3. `go test ./internal/archtest/ -run TestRepositoryConforms` : `ok` (R3).
  4. `go tool govulncheck ./...; echo rc=$?` : `rc=0`.

---

### M0-T13 `loop-findings` : findings normalisés, empreinte, score
- **Objectif** : fonctions pures de `normalized-findings.md`, base de la détection de stagnation, indépendantes de Temporal.
- **Dépend de** : T01. **ADR** : aucun. **Outils** : O-base. **Revue sécurité** : non.
- **Fichiers** : `internal/loops/domain/findings.go`, tests.
- **Interfaces** :
  ```go
  package domain

  type Severity string

  const (
  	SeverityCritical Severity = "critical"
  	SeverityHigh     Severity = "high"
  	SeverityMedium   Severity = "medium"
  	SeverityLow      Severity = "low"
  	SeverityInfo     Severity = "info"
  )

  type Finding struct {
  	Code     string   `json:"code"`
  	Source   string   `json:"source"`
  	Severity Severity `json:"severity"`
  	Resource string   `json:"resource"`
  	File     string   `json:"file"`
  	Line     int      `json:"line"`
  	Message  string   `json:"message"`
  }

  func (s Severity) Weight() int         // 100, 20, 5, 1, 0 ; gravité inconnue : 100 (échec sûr)
  func Sort(f []Finding) []Finding        // copie : gravité décroissante, fichier, ligne
  func Fingerprint(f []Finding) string    // SHA-256 hex des couples "code|resource" triés, gravité >= medium
  func Score(f []Finding) int
  func Top(f []Finding, n int) []Finding  // après Sort
  ```
- **Phase tests**, rouges car le paquet n'existe pas : `TestFingerprintOrderIndependent` (`rapid`) ; `TestFingerprintIgnoresLowAndInfo` ; `TestFingerprintChangesWithCodeOrResource` ; `TestFingerprintFormat` (64 caractères hexadécimaux) ; `TestScoreWeights` ; `TestUnknownSeverityCountsAsCritical` ; `TestSortOrder` ; `TestTopN`.
- **Acceptation** :
  1. `go test ./internal/loops/domain/... -v` : 8 `--- PASS`.
  2. `make verify-quick; echo rc=$?` : `rc=0`.

---

### M0-T14 `runloop` : workflow générique `RunLoop` (critère 2, première partie)
- **Objectif** : proposer, vérifier, diagnostiquer, budget (itérations, tokens, temps), stagnation, escalade, meilleur candidat conservé, sans aucun domaine.
- **Dépend de** : T13. **ADR** : aucun. **Outils** : O-base. **Revue sécurité** : oui (budgets T10, échec sûr).
- **Écarts assumés par rapport au squelette du skill** (reportés dans le skill en fin de T19) : le vérificateur reçoit aussi la charge utile (`VerifyRequest`), car un vérificateur réel en a besoin (équivalence graphe et plan en L3) ; `RunLoop` **recalcule** empreinte et score à partir des findings (un vérificateur ou un proposeur ne peut pas maquiller la stagnation) ; raisons d'escalade codées ; spécification validée (une boucle sans budget est refusée) ; échec d'activité après reprises : escalade documentée avec le meilleur candidat.
- **Fichiers** : `internal/loops/{runloop.go,spec.go}`, tests ; `Makefile` (`arch-test` ajoute `go tool workflowcheck ./internal/loops/...`, outil épinglé par directive `tool`, compatibilité à vérifier).
- **Interfaces** :
  ```go
  package loops

  type Budget struct {
  	MaxIterations, MaxTokens int
  	MaxWallTime              time.Duration
  }

  type LoopSpec struct {
  	ID, ProposeActivity, VerifyActivity string
  	Strategies                          []string
  	Budget                              Budget
  	SwitchAfter, EscalateAfter          int           // défauts 2 et 3
  	ActivityTimeout                     time.Duration // défaut 5 min
  }

  // Validate : budgets strictement positifs, au moins une stratégie, activités nommées,
  // SwitchAfter < EscalateAfter. Erreur applicative non rejouable "InvalidLoopSpec".
  func (s LoopSpec) Validate() error

  type ProposeRequest struct {
  	Payload   json.RawMessage  `json:"payload"`
  	Strategy  string           `json:"strategy"`
  	Best      json.RawMessage  `json:"best,omitempty"`
  	Findings  []domain.Finding `json:"findings,omitempty"` // top 20
  	Iteration int              `json:"iteration"`
  }
  type ProposeResponse struct {
  	Candidate json.RawMessage `json:"candidate"`
  	Tokens    int             `json:"tokens"`
  }
  type VerifyRequest struct {
  	Payload   json.RawMessage `json:"payload"`
  	Candidate json.RawMessage `json:"candidate"`
  	Iteration int             `json:"iteration"`
  }
  type VerifyResult struct {
  	OK       bool             `json:"ok"`
  	Findings []domain.Finding `json:"findings"`
  }

  type Status string

  const (
  	StatusConverged Status = "converged"
  	StatusEscalated Status = "escalated"
  )

  type Reason string

  const (
  	ReasonBudgetIterations    Reason = "budget_iterations"
  	ReasonBudgetTokens        Reason = "budget_tokens"
  	ReasonBudgetTime          Reason = "budget_time"
  	ReasonStagnation          Reason = "stagnation"
  	ReasonStrategiesExhausted Reason = "strategies_exhausted"
  	ReasonActivityFailed      Reason = "activity_failed"
  )

  type IterationTrace struct {
  	Iteration         int    `json:"iteration"`
  	Strategy          string `json:"strategy"`
  	Fingerprint       string `json:"fingerprint"`
  	Findings, Tokens  int
  }

  type LoopResult struct {
  	Status            Status           `json:"status"`
  	Reason            Reason           `json:"reason,omitempty"`
  	Best              json.RawMessage  `json:"best,omitempty"`
  	Remaining         []domain.Finding `json:"remaining,omitempty"`
  	Iterations, Tokens int
  	Trace             []IterationTrace `json:"trace"`
  }

  func RunLoop(ctx workflow.Context, spec LoopSpec, payload json.RawMessage) (LoopResult, error)
  ```
- **Phase tests** (`go.temporal.io/sdk/testsuite`, activités factices enregistrées sous les noms de la spécification), rouges car `RunLoop` est indéfini :
  - `TestRunLoopConverges` ; `TestRunLoopStagnationSwitchesStrategy` (même empreinte aux itérations 1 et 2 : l'itération 3 utilise la stratégie 2) ; `TestRunLoopStagnationEscalates` (même empreinte trois fois de suite : `escalated`, `stagnation`) ; `TestRunLoopStrategiesExhausted` ; `TestRunLoopFingerprintChangeResetsCount` ;
  - `TestRunLoopBudgetIterations` ; `TestRunLoopBudgetTokens` ; `TestRunLoopBudgetWallTime` (activité retardée dans l'horloge du testsuite) ;
  - `TestRunLoopKeepsBestCandidate` ; `TestRunLoopSendsTop20Findings` ; `TestRunLoopRecomputesFingerprint` ; `TestRunLoopInvalidSpecRejected` ; `TestRunLoopValidationErrorNotRetried` (une seule tentative) ; `TestRunLoopActivityFailureEscalates`.
- **Acceptation** :
  1. `go test ./internal/loops/ -run TestRunLoop -v 2>&1 | grep -c -- '^--- PASS: TestRunLoop'` : `14`.
  2. `go tool workflowcheck ./internal/loops/...; echo rc=$?` : `rc=0` (si l'outil est retenu au plan de tâche ; sinon, justification consignée).
  3. `go test ./internal/archtest/ -run TestRepositoryConforms` : `ok` (R3, R4).
  4. `make verify-quick; echo rc=$?` : `rc=0`.

---

### M0-T15 `approvals` : `AwaitApprovals` et vérificateur factice (critère 2, seconde partie)
- **Objectif** : attente d'approbation liée à un hash exact, signature vérifiée par activité, quorum, rôle sécurité, exclusion de l'auteur, signal invalide ignoré sans interrompre l'attente, timeout : ne rien faire.
- **Dépend de** : T14. **ADR** : aucun. **Outils** : O-base. **Revue sécurité** : oui (T12, échec sûr).
- **Écarts assumés par rapport au squelette** : issue explicite au lieu d'un booléen ; requête validée (`Required` au moins 1, timeout positif) ; signal mal formé ignoré (réception brute puis décodage contrôlé) ; refus non authentifié ignoré ; plafond de signaux ignorés contre l'inondation.
- **Fichiers** : `internal/loops/approvals.go`, `internal/loops/fake/approvals.go`, tests.
- **Interfaces** :
  ```go
  package loops

  const ApprovalSignal = "approval"

  type ApprovalRequest struct {
  	PlanHash, Author  string
  	Required          int    // au moins 1 ; 2 pour un risque critique
  	NeedsSecurityRole bool
  	VerifyActivity    string // nom de l'activité de vérification enregistrée par l'appelant
  	MaxIgnored        int    // défaut 100
  }
  func (r ApprovalRequest) Validate() error

  type Approval struct {
  	Approved  bool   `json:"approved"`
  	PlanHash  string `json:"plan_hash"`
  	Approver  string `json:"approver"`
  	Signature string `json:"signature"`
  }
  type ApprovalCheck struct {
  	SignatureValid bool `json:"signature_valid"`
  	SecurityRole   bool `json:"security_role"`
  }

  type ApprovalOutcome string

  const (
  	OutcomeApproved    ApprovalOutcome = "approved"
  	OutcomeRejected    ApprovalOutcome = "rejected"
  	OutcomeTimedOut    ApprovalOutcome = "timed_out"
  	OutcomeSignalFlood ApprovalOutcome = "signal_flood"
  )

  type IgnoredReason string // wrong_hash, self_approval, duplicate, invalid_signature, verify_error, malformed

  type IgnoredSignal struct {
  	Approver string        `json:"approver"`
  	Reason   IgnoredReason `json:"reason"`
  }

  type ApprovalResult struct {
  	Outcome   ApprovalOutcome `json:"outcome"`
  	Approvals []Approval      `json:"approvals,omitempty"`
  	Ignored   []IgnoredSignal `json:"ignored,omitempty"`
  }

  func AwaitApprovals(ctx workflow.Context, req ApprovalRequest, timeout time.Duration) (ApprovalResult, error)

  package fake

  // ApprovalVerifier : signature valide si et seulement si elle vaut ExpectedSignature(a).
  // Déterministe, sans clé ; la cryptographie réelle arrive en M4 (Q5).
  type ApprovalVerifier struct{ SecurityRoles map[string]bool }

  func ExpectedSignature(a loops.Approval) string // SHA-256 de "fake|approver|plan_hash|approved"
  func (v *ApprovalVerifier) VerifyApproval(ctx context.Context, a loops.Approval) (loops.ApprovalCheck, error)
  ```
- **Phase tests** (testsuite, signaux par `env.RegisterDelayedCallback`), rouges car `AwaitApprovals` est indéfini : `TestAwaitApprovalsTimeoutDoesNothing` (critère 2 : `timed_out`, aucune approbation retenue) ; `TestAwaitApprovalsWrongHashIgnored` (l'attente continue et aboutit sur un signal valide ultérieur) ; `TestAwaitApprovalsInvalidSignatureIgnored` ; `TestAwaitApprovalsSelfApprovalIgnored` ; `TestAwaitApprovalsDuplicateApproverIgnored` ; `TestAwaitApprovalsQuorumWithSecurityRole` ; `TestAwaitApprovalsQuorumWithoutSecurityRoleKeepsWaiting` ; `TestAwaitApprovalsAuthenticatedRefusalStops` ; `TestAwaitApprovalsUnauthenticatedRefusalIgnored` ; `TestAwaitApprovalsMalformedSignalIgnored` ; `TestAwaitApprovalsVerifierErrorIgnored` ; `TestAwaitApprovalsSignalFlood` ; `TestAwaitApprovalsInvalidRequest`.
- **Acceptation** :
  1. `go test ./internal/loops/... -run TestAwaitApprovals -v 2>&1 | grep -c -- '^--- PASS: TestAwaitApprovals'` : `13`.
  2. `go test ./internal/loops/... -run 'TestRunLoopConverges|TestRunLoopStagnationSwitchesStrategy|TestRunLoopStagnationEscalates|TestRunLoopBudget|TestAwaitApprovalsTimeoutDoesNothing' -v` : 7 `--- PASS` (preuve groupée du critère 2).
  3. `make verify-quick; echo rc=$?` : `rc=0`.

---

### M0-T16 `envelope` : enveloppe AES-256-GCM par tenant `[ADR-0001]`
- **Objectif** : sceller et ouvrir des octets avec une DEK propre au tenant, enveloppée par un `KeyWrapper` ; aucune confusion de tenant possible.
- **Dépend de** : T05, T06. **ADR** : `[ADR-0001]`, tâche entière. **Outils** : O-base. **Revue sécurité** : oui (cryptographie, T3).
- **Fichiers** : `internal/secrets/ports/keywrapper.go`, `internal/secrets/envelope/{sealer.go,format.go,cache.go}`, `internal/secrets/fake/keywrapper.go`, tests.
- **Interfaces** :
  ```go
  package ports

  type KeyWrapper interface {
  	GenerateDataKey(ctx context.Context, tenant tenancy.ID) (plain secret.Bytes, wrapped []byte, err error)
  	UnwrapDataKey(ctx context.Context, tenant tenancy.ID, wrapped []byte) (secret.Bytes, error)
  }

  package envelope

  const FormatV1 byte = 1 // version | tenant | id de DEK | DEK enveloppée | nonce 96 bits | chiffré et tag

  var (
  	ErrTenantMismatch = errors.New("envelope: tenant mismatch")
  	ErrMalformed      = errors.New("envelope: malformed payload")
  	ErrAuth           = errors.New("envelope: authentication failed")
  )

  type Options struct {
  	MaxDEKAge     time.Duration // défaut 15 min
  	MaxDEKUses    uint64        // défaut 1 << 20
  	MaxCachedDEKs int
  	Now           func() time.Time
  	Rand          io.Reader
  }

  type Sealer struct{ /* KeyWrapper, cache borné de DEK */ }

  func NewSealer(kw ports.KeyWrapper, opt Options) (*Sealer, error)
  // Seal : tenant du contexte obligatoire (tenancy.ErrNoTenant sinon) ; données associées :
  // version, tenant, id de DEK.
  func (s *Sealer) Seal(ctx context.Context, plaintext []byte) ([]byte, error)
  // Open : le tenant scellé doit égaler celui du contexte (ErrTenantMismatch).
  func (s *Sealer) Open(ctx context.Context, sealed []byte) ([]byte, error)

  package fake

  // KeyWrapper : clé d'enveloppe par tenant dérivée d'une graine fixe, en mémoire. Tests et historiques de référence.
  func NewKeyWrapper(seed [32]byte) *KeyWrapper
  ```
- **Phase tests**, rouges car les paquets n'existent pas : `TestSealOpenRoundTrip` ; `TestOpenTamperedByteFails` (un octet modifié dans chaque zone du format) ; `TestOpenOtherTenantFails` ; `TestSealWithoutTenantFails` ; `TestSealedContainsNoPlaintext` ; `TestNoncesUnique` (10 000 scellements, aucun nonce répété) ; `TestDEKRotatesAfterMaxUses` ; `TestDEKRotatesAfterMaxAge` (horloge injectée) ; `TestDEKCacheBounded` ; `TestUnwrapErrorFailsClosed` ; `TestFakeKeyWrapperTenantIsolation`.
- **Acceptation** :
  1. `go test ./internal/secrets/envelope/... ./internal/secrets/fake/... -v` : 11 `--- PASS`.
  2. `make verify-quick; echo rc=$?` : `rc=0`.

---

### M0-T17 `openbao-transit` : `KeyWrapper` OpenBao Transit `[ADR-0001]`
- **Objectif** : DEK générées et déballées par Transit, clé par tenant, jeton du worker au moindre privilège.
- **Dépend de** : T03, T16. **ADR** : `[ADR-0001]`, tâche entière. **Outils** : O-docker pour l'intégration. **Revue sécurité** : oui (secrets, T3).
- **Fichiers** : `internal/secrets/adapters/openbao/keywrapper.go` (client HTTP de la bibliothèque standard : dépendance évitée, décision à confirmer au plan de tâche), tests unitaires `httptest`, `keywrapper_integration_test.go`.
- **Interfaces** :
  ```go
  package openbao

  type Config struct {
  	Addr       string
  	Token      secret.Value
  	Mount      string // défaut "transit"
  	KeyPrefix  string // défaut "rempart-tenant-"
  	HTTPClient *http.Client
  }

  type KeyWrapper struct{ /* ... */ }

  func New(cfg Config) (*KeyWrapper, error)
  // Le nom de clé n'est formé qu'à partir d'un tenancy.ID valide : aucune donnée libre dans l'URL.
  func (k *KeyWrapper) GenerateDataKey(ctx context.Context, tenant tenancy.ID) (secret.Bytes, []byte, error)
  func (k *KeyWrapper) UnwrapDataKey(ctx context.Context, tenant tenancy.ID, wrapped []byte) (secret.Bytes, error)
  ```
- **Phase tests** : unitaires, rouges car le paquet n'existe pas : `TestGenerateDataKeyRequest` (chemin, en-tête de jeton, 256 bits) ; `TestUnwrapRequest` ; `TestTenantKeyNameFromValidatedID` ; `TestErrorsDoNotLeakToken` ; `TestHTTPErrorMapping`. Intégration : `TestTransitRotation` (payload scellé avant rotation de la clé Transit, ouvert après) ; `TestTransitTenantKeysDistinct` (une DEK enveloppée pour A ne se déballe pas avec la clé de B).
- **Acceptation** :
  1. `go test ./internal/secrets/adapters/openbao/... -v` : 5 `--- PASS`.
  2. `make dev && go test -tags=integration -run 'TestTransitRotation|TestTransitTenantKeysDistinct' ./internal/secrets/... -v` : 2 `--- PASS`.
  3. `make verify-quick; echo rc=$?` : `rc=0`.

---

### M0-T18 `temporal-codec` : convertisseur Temporal chiffrant par tenant `[ADR-0001]`
- **Objectif** : tout payload, message d'erreur et pile chiffrés par le tenant du contexte, sans repli en clair.
- **Dépend de** : T14, T16. **ADR** : `[ADR-0001]`, tâche entière. **Outils** : O-base. **Revue sécurité** : oui (T3, T7, T11).
- **Fichiers** : `internal/loops/codec/{converter.go,failure.go,propagator.go}`, tests.
- **Interfaces** (noms du SDK à confirmer sur la version épinglée) :
  ```go
  package codec

  const (
  	MaxPayloadBytes = 256 << 10
  	EncodingV1      = "binary/rempart-aesgcm-v1"
  )

  // NewDataConverter implémente workflow.ContextAware : la clé suit le tenant du contexte.
  // Sans tenant, l'encodage échoue. Erreurs non rejouables "TenantMismatch" et "PayloadTooLarge".
  func NewDataConverter(s *envelope.Sealer) converter.DataConverter
  // NewFailureConverter chiffre message et pile (EncodeCommonAttributes).
  func NewFailureConverter(s *envelope.Sealer) converter.FailureConverter
  // NewTenantPropagator : en-tête limité à l'identifiant de tenant.
  func NewTenantPropagator() workflow.ContextPropagator
  // ClientOptions pré-remplit DataConverter, FailureConverter et ContextPropagators.
  func ClientOptions(s *envelope.Sealer, base client.Options) client.Options
  ```
- **Phase tests** (testsuite avec le convertisseur et le `KeyWrapper` factice), rouges car le paquet n'existe pas : `TestCodecRoundTripThroughWorkflow` ; `TestEncodeWithoutTenantFails` (démarrage refusé, rien en clair) ; `TestEncodedPayloadHasNoPlaintext` (données et métadonnées) ; `TestDecodeOtherTenantFailsNonRetryable` ; `TestPayloadTooLarge` ; `TestFailureAttributesEncrypted` ; `TestPropagatorHeaderOnlyTenant`.
- **Acceptation** :
  1. `go test ./internal/loops/codec/... -v` : 7 `--- PASS`.
  2. `go test ./internal/archtest/ -run TestRepositoryConforms` : `ok` (R4 : le codec n'importe que les paquets autorisés).
  3. `make verify-quick; echo rc=$?` : `rc=0`.

---

### M0-T19 `demo-workflow` : workflow de démonstration synthétique
- **Objectif** : une boucle complète selon la fiche 5.4, sans logique métier, prouvée par testsuite.
- **Dépend de** : T11, T14, T15. **ADR** : `[ADR-0001]` pour `ContinueAsNew` avant l'attente et `TestDemoContinueAsNewBeforeApproval`. **Outils** : O-base. **Revue sécurité** : oui (appel LLM).
- **Fichiers** : `docs/loops/L0-demo.md` (fiche 5.4, avant tout code) ; `internal/loops/demo/{workflow.go,activities.go,register.go}` ; `internal/llm/prompts/demo.greeting.v1/{system.txt,schema.json}` ; tests ; `internal/loops/demo/testdata/scripts/*.json` (scripts du faux LLM : convergence, stagnation). En fin de tâche : mise en accord de `.claude/skills/loop-engineering/references/temporal-loop-skeleton.md` avec le code compilé de T14, T15 et T19, signalée dans `docs/STATUS.md`.
- **Interfaces** :
  ```go
  package demo

  const (
  	WorkflowName = "rempart.demo.v1"
  	PromptID     = "demo.greeting.v1"
  	TaskQueue    = "rempart-demo"
  )

  type Phase string // "loop" | "approval" (reprise après ContinueAsNew [ADR-0001])

  type Input struct {
  	Target          string            `json:"target"`
  	Canary          string            `json:"canary,omitempty"`
  	Author          string            `json:"author"`
  	ApprovalTimeout time.Duration     `json:"approval_timeout"`
  	Phase           Phase             `json:"phase,omitempty"`
  	Loop            *loops.LoopResult `json:"loop,omitempty"`
  }

  type Output struct {
  	Loop      loops.LoopResult     `json:"loop"`
  	Approval  loops.ApprovalResult `json:"approval"`
  	PlanHash  string               `json:"plan_hash,omitempty"`
  	Committed bool                 `json:"committed"`
  }

  func Spec() loops.LoopSpec
  func Workflow(ctx workflow.Context, in Input) (Output, error)

  type Activities struct {
  	LLM    *llm.Client
  	Prompt prompts.Prompt
  }

  func (a *Activities) Propose(ctx context.Context, req loops.ProposeRequest) (loops.ProposeResponse, error)
  // Verify : déterministe, n'appelle jamais le LLM.
  func (a *Activities) Verify(ctx context.Context, req loops.VerifyRequest) (loops.VerifyResult, error)
  // Commit : aucun effet externe ; idempotent sur (tenant, workflow, plan_hash).
  func (a *Activities) Commit(ctx context.Context, planHash string) error

  type ApprovalVerifier interface {
  	VerifyApproval(ctx context.Context, a loops.Approval) (loops.ApprovalCheck, error)
  }

  func Register(r worker.Registry, a *Activities, v ApprovalVerifier)
  ```
- **Phase tests** (testsuite, `llm.Client` sur faux scripté, vérificateur d'approbation factice), rouges car le paquet n'existe pas : `TestDemoConverges` ; `TestDemoStagnationEscalatesWithoutApprovalWait` ; `TestDemoApprovalTimeoutNoCommit` (principe 7) ; `TestDemoApprovedCommitsOnce` ; `TestDemoApprovalOnOtherHashIgnored` ; `TestDemoVerifyDeterministic` ; `TestDemoPromptStrict` ; `[ADR-0001]` `TestDemoContinueAsNewBeforeApproval`.
- **Acceptation** :
  1. `go test ./internal/loops/demo/... -v` : 8 `--- PASS` (7 sans l'ADR 0001).
  2. `test -f docs/loops/L0-demo.md; echo rc=$?` : `rc=0`.
  3. `go test ./internal/archtest/ -run TestRepositoryConforms` : `ok` (R4 : seul `internal/loops/demo` importe `internal/llm`).
  4. `make verify-quick; echo rc=$?` : `rc=0`.

---

### M0-T20 `worker-e2e` : worker, `make demo`, bout en bout sur la pile de dev (critère 4)
- **Objectif** : le workflow de démo s'exécute contre Temporal, PostgreSQL et OpenBao démarrés par `make dev`, avec le faux LLM ; configuration explicite, sans défaut dangereux.
- **Dépend de** : T03, T17, T18, T19. **ADR** : `[ADR-0001]` pour le câblage du codec et `TestHistoryHasNoPlaintext`. **Outils** : O-docker. **Revue sécurité** : oui (configuration des secrets, tenant, câblage des faux).
- **Fichiers** : `cmd/rempart-worker/{main.go,config.go,run.go}`, tests ; `internal/loops/workflowid.go`, test ; `internal/loops/demo/e2e_integration_test.go` ; `Makefile` (cible `demo`).
- **Interfaces** :
  ```go
  // cmd/rempart-worker
  type Config struct {
  	TemporalAddress, Namespace, TaskQueue string
  	LLMProvider                           string // "fake" | "anthropic" ; aucun défaut
  	Dev                                   bool   // requis pour "fake" et pour le vérificateur d'approbation factice
  	FakeScript                            string
  	BaoAddr                               string
  	BaoToken                              secret.Value
  	AnthropicKey                          secret.Value
  	DemoOnce                              bool
  	DemoTenant                            tenancy.ID
  }

  func LoadConfig(args []string, getenv func(string) string) (Config, error)
  func run(ctx context.Context, cfg Config, stdout io.Writer) error

  // internal/loops
  // NewWorkflowID : "<loopID>-<uuid v4>" (crypto/rand) ; loopID en liste blanche [a-z0-9-] ;
  // aucun identifiant de tenant ni contenu client (ADR 0001, métadonnées en clair).
  func NewWorkflowID(loopID string) (string, error)
  ```
  `make demo` : `$(MAKE) dev` puis `go run ./cmd/rempart-worker -dev -demo-once -llm=fake -fake-script=internal/loops/demo/testdata/scripts/converge.json -tenant=$(DEMO_TENANT)`, résultat JSON (`demo.Output` et identifiant de workflow) sur la sortie standard.
- **Phase tests** : unitaires, rouges car `LoadConfig` et `NewWorkflowID` sont indéfinis : `TestLoadConfigRequiresLLMProvider` ; `TestLoadConfigFakeRequiresDev` ; `TestLoadConfigDemoTenantValidated` ; `TestConfigNeverPrintsSecrets` ; `TestNewWorkflowIDOpaque`. Intégration : `TestDemoEndToEnd` (worker en processus, codec avec Transit `[ADR-0001]` : `converged`, `timed_out`, rien de commis) ; `TestDemoApprovedEndToEnd` (signal signé par le faux vérificateur : `approved`, commis une fois) ; `[ADR-0001]` `TestHistoryHasNoPlaintext` (canari en entrée, en résultat d'activité, en signal et dans un message d'erreur ; historique brut sérialisé sans le canari ; décodé avec le codec, le canari est présent, preuve que le test n'est pas vide).
- **Acceptation** :
  1. `go test ./cmd/rempart-worker/... ./internal/loops/ -run 'TestLoadConfig|TestConfigNeverPrintsSecrets|TestNewWorkflowIDOpaque' -v` : 5 `--- PASS`.
  2. `make dev && make -s demo | jq -e '.loop.status == "converged" and .approval.outcome == "timed_out" and .committed == false'` : `true`, code 0 (critère 4).
  3. `go test -tags=integration -run 'TestDemoEndToEnd|TestDemoApprovedEndToEnd|TestHistoryHasNoPlaintext' ./internal/loops/demo/... -v` : 3 `--- PASS` (2 sans l'ADR 0001).
  4. `go run ./cmd/rempart-worker -demo-once -llm=fake; echo rc=$?` (sans `-dev`) : refus explicite, `rc=2`.
  5. `make verify; echo rc=$?` : `rc=0`.

---

### M0-T21 `replay` : versioning des workflows et tests de rejeu `[ADR-0001]`
- **Objectif** : un déploiement ne casse pas les exécutions en vol ; tout changement de séquence de commandes passe par `workflow.GetVersion`.
- **Dépend de** : T20. **ADR** : `[ADR-0001]`, tâche entière. **Outils** : O-docker pour l'enregistrement ; O-base pour le rejeu. **Revue sécurité** : non (vérifier seulement que la graine du `KeyWrapper` factice n'est câblée que dans les tests).
- **Fichiers** : `internal/loops/versions.go` ; tests ; `internal/loops/testdata/histories/*.json` (enregistrés en phase tests, chiffrés avec la clé du faux).
- **Enregistrement** (phase tests uniquement) : après `make dev`, `go test -tags=integration,record -run TestRecordDemoHistory ./internal/loops/demo/...` avec le `KeyWrapper` factice ; le test d'enregistrement n'existe que sous le tag `record`. En phase impl, `acceptance-verifier` vérifie que `internal/loops/testdata/histories/` n'a pas changé.
- **Interfaces** :
  ```go
  package loops

  // Identifiants de changement déclarés ; chaque appel workflow.GetVersion utilise l'une de ces constantes.
  const ChangeDemoContinueAsNew = "demo-continue-as-new-v1"

  var ChangeIDs = []string{ChangeDemoContinueAsNew}
  ```
- **Phase tests**, rouges car `versions.go` n'existe pas : `TestChangeIDsDeclared` (analyse `go/ast` : chaque `workflow.GetVersion` du module utilise une constante de `ChangeIDs`) ; `TestReplay` (chaque historique se rejoue avec le code courant et le convertisseur de Rempart ; non sauté en `-short`) ; `TestReplayNegativeControl` (variante incompatible sans `GetVersion` : erreur de non-déterminisme ; même variante avec `GetVersion` : rejeu réussi).
- **Acceptation** :
  1. `go test -short -run 'TestReplay|TestChangeIDsDeclared' ./internal/loops/... -v 2>&1 | grep -Ec -- '--- (PASS|SKIP): (TestReplay|TestReplayNegativeControl|TestChangeIDsDeclared)'` : `3`, et `grep -c SKIP` sur la même sortie : `0`.
  2. `ls internal/loops/testdata/histories/*.json | wc -l` : au moins `1`.
  3. `make verify-quick; echo rc=$?` : `rc=0` (le rejeu tourne à chaque `verify-quick`).

---

### M0-T22 `evals-core` : noyau d'évaluation
- **Objectif** : format de cas du skill `agent-evals`, graders déterministes, agrégation, comparaison à une baseline dont les tolérances sont dans le fichier protégé.
- **Dépend de** : T01 (peut être avancée juste après T02). **ADR** : `[ADR-0002]` pour `BaselinePath` par couple plateforme et modèle et les champs `platform`, `region` du rapport. **Outils** : O-base. **Revue sécurité** : non.
- **Fichiers** : `internal/evals/{suite.go,grade.go,path.go,report.go,baseline.go,select.go}`, tests, `internal/evals/testdata/` (dont une copie de l'exemple de `references/case-format.md`).
- **Interfaces** :
  ```go
  package evals

  type Suite struct {
  	Name, Loop, Target string
  	Watch              []string // motifs de chemins pour EVAL=changed
  	Cases              []Case
  }
  type Case struct {
  	ID, Loop string
  	Tags     []string
  	Input    json.RawMessage
  	Expect   Expect
  	Runs     int
  }
  type Expect struct {
  	SchemaValid, Escalation       *bool
  	Status                        string
  	MaxIterations, MaxOpenQuestions *int
  	MustInclude, MustNotInclude   []PathCheck
  }
  type PathCheck struct {
  	Path             string // sous-ensemble JSONPath : $.a.b, $.a[*].b ; toute autre syntaxe est une erreur
  	Contains, Equals json.RawMessage
  }
  type Outcome struct {
  	Output             json.RawMessage
  	SchemaValid        bool
  	Status             string
  	Escalated          bool
  	Iterations, Tokens int
  	Duration           time.Duration
  	Err                string
  }
  type Target interface {
  	Run(ctx context.Context, c Case, run int) (Outcome, error)
  }
  type Grade struct {
  	CaseID                        string
  	Run                           int
  	Pass, Injection               bool
  	ExpectedEscalation, Escalated bool
  	Failures                      []string
  }
  type Report struct {
  	Loop, Platform, Region, Model                                               string
  	Cases, Runs                                                                 int
  	SuccessRate, CorrectEscalationRate, InjectionResistance, AvgIterations, AvgTokens float64
  	RegressionsVsBaseline                                                       []Regression `json:"regressions_vs_baseline"`
  }
  type Tolerances struct{ SuccessRateDrop, CorrectEscalationDrop, AvgIterationsRise, AvgTokensRisePct float64 }
  type Baseline struct { Report Report; Tolerances Tolerances }
  type Regression struct { Metric string; Baseline, Current float64 }

  func LoadSuite(fsys fs.FS, dir string) (Suite, error) // suite.yaml et cases/*.yaml ; champs inconnus refusés
  func GradeOutcome(c Case, o Outcome) (Grade, error)
  func Aggregate(s Suite, grades []Grade, outcomes []Outcome) Report
  // Compare : InjectionResistance < 1 est toujours une régression, quelle que soit la baseline.
  func Compare(b Baseline, r Report) []Regression
  func SelectChanged(suites []Suite, changed []string) []Suite
  func BaselinePath(suite, platform, model string) string // [ADR-0002] evals/<suite>/baseline/<plateforme>/<modèle>.json
  ```
- **Phase tests**, rouges car le paquet n'existe pas : `TestLoadSuiteCaseFormatExample` ; `TestLoadSuiteRejectsUnknownFields` ; `TestGradeChecks` (table : `must_include`, `must_not_include`, `schema_valid`, `escalation`, `status`, `max_iterations`) ; `TestPathSubsetUnsupportedIsError` ; `TestAggregateRuns` ; `TestCompareDetectsSuccessDrop` ; `TestCompareEqualIsNoRegression` ; `TestCompareImprovementIsNoRegression` ; `TestInjectionResistanceBelowOneIsRegression` ; `TestSelectChanged` ; `TestBaselinePath`.
- **Acceptation** :
  1. `go test ./internal/evals/... -v` : 11 `--- PASS`.
  2. `make verify-quick; echo rc=$?` : `rc=0`.

---

### M0-T23 `evals-cli` : `cmd/rempart-evals`, suite `demo`, `make evals` (critère 5)
- **Objectif** : `make evals` exécute un cas trivial et le compare à la baseline ; `verify` exécute les evals ciblées.
- **Dépend de** : T19, T22. **ADR** : `[ADR-0002]` pour l'emplacement de la baseline. **Outils** : O-base, git ; O-docker pour `make verify`. **Revue sécurité** : oui (exécution de `git`).
- **Fichiers** : `cmd/rempart-evals/{main.go,targets.go}`, tests, `cmd/rempart-evals/testdata/` (suite, baseline conforme, baseline en régression : fixtures hors `evals/`, donc non protégées) ; `evals/demo/cases/demo-converge-001.yaml` (phase tests) ; `evals/demo/suite.yaml` ; `Makefile` (`evals`, `update-baseline`, `verify` complété, `EVAL_BASE`) ; `.gitignore` (`evals/**/reports/`).
- **Interfaces** :
  ```go
  // cmd/rempart-evals
  // run : 0 conforme, 1 régression, 2 usage ou configuration, 3 baseline absente, 4 erreur d'exécution.
  // --suite <nom|all|changed> ; --write-baseline (écrit la baseline : bloqué pour l'agent par le hook) ;
  // --base <réf git> pour changed : validée (liste blanche de caractères, pas de "-" initial),
  // passée après "--end-of-options" à exec.CommandContext("git", "diff", "--name-only", ...) ;
  // base introuvable : toutes les suites (échec sûr : plus d'evals, jamais moins).
  func run(ctx context.Context, args []string, stdout, stderr io.Writer) int

  // targets.go : cible "demo" : exécute le workflow de démo en processus (environnement de test Temporal,
  // faisabilité hors go test à confirmer ; repli : pile make dev), faux LLM scripté par l'entrée du cas.
  ```
- **Phase tests**, rouges car `run` est indéfini : `TestRunOKAgainstBaseline` (code 0, JSON avec `"regressions_vs_baseline": []`) ; `TestRegressionDetected` (code 1) ; `TestMissingBaselineAsksHuman` (code 3, message contenant `make update-baseline EVAL=`) ; `TestWriteBaselineOnlyWithFlag` (écriture dans un répertoire temporaire, jamais sans le drapeau) ; `TestSuiteChangedSelection` ; `TestRejectsUnsafeGitRef` (`--base=--output=x`, `--base='a;b'`) ; `TestDemoTargetRunsWorkflow` (le cas trivial converge).
- **Acceptation** :
  1. `go test ./cmd/rempart-evals/... -v` : 7 `--- PASS`.
  2. Avant H3 : `make -s evals EVAL=demo; echo rc=$?` : message contenant `make update-baseline EVAL=demo`, `rc=3`.
  3. Après H3 : `make -s evals EVAL=demo | jq -e '.cases == 1 and .regressions_vs_baseline == []'` : `true`, code 0 (critère 5).
  4. `git log --format='%an | %s' -- evals/demo/baseline*` : commit de l'humain.
  5. `make verify; echo rc=$?` : `rc=0` (critère 1, local).

---

## 8. Matrices de preuve

### 8.1 Critères de `prompts/M0.md`

| Critère M0 | Tâches qui le prouvent | Commande de preuve finale |
|---|---|---|
| 1. `make verify` vert en local et en CI | T01 (cible et `verify-quick`), T02, T03 (pile dans `verify`), T04 (CI), T23 (evals dans `verify`), H3 (baseline) ; toutes les tâches le maintiennent vert | `make verify; echo rc=$?` : `rc=0` ; `gh run list --workflow verify.yml --branch main --limit 1 --json conclusion --jq '.[0].conclusion'` : `success` |
| 2. `go test ./internal/loops/...` : convergence, stagnation (2 : stratégie, 3 : escalade), budget, timeout d'approbation | T13 (empreinte), T14, T15, T19 (`TestDemoApprovalTimeoutNoCommit`) | `go test ./internal/loops/... -run 'TestRunLoopConverges|TestRunLoopStagnationSwitchesStrategy|TestRunLoopStagnationEscalates|TestRunLoopBudget|TestAwaitApprovalsTimeoutDoesNothing' -v` : 7 `--- PASS` |
| 3. `go test ./internal/llm/...` : au moins 10 cas de rédaction ; réponse hors schéma rejetée | T07, T09, T11 (T08 et T10 en support) | `go test ./internal/llm/... -run 'TestRedactPatterns|TestOutOfSchemaRejected|TestValidateRejectsOutOfSchema' -v 2>&1 | grep -c -- '--- PASS: TestRedactPatterns/'` : au moins 24 ; `TestOutOfSchemaRejected` et `TestValidateRejectsOutOfSchema` en `--- PASS` |
| 4. `make dev` démarre Temporal, PostgreSQL, OpenBao ; démo de bout en bout contre le faux LLM | T03, T10, T19, T20 (et T16 à T18 avec l'ADR 0001) | `make dev && make -s demo | jq -e '.loop.status == "converged" and .approval.outcome == "timed_out" and .committed == false'` ; `go test -tags=integration -run TestDemoEndToEnd ./internal/loops/demo/...` |
| 5. `make evals` exécute un cas trivial et compare à la baseline | T22, T23, H3 | `make -s evals EVAL=demo | jq -e '.cases == 1 and .regressions_vs_baseline == []'` ; témoin : `go test ./cmd/rempart-evals/ -run TestRegressionDetected` |

### 8.2 Critères issus des ADR (ajoutés à `prompts/M0.md` en D0)

| Critère | Tâches |
|---|---|
| `[ADR-0001]` enveloppe et codec : aller-retour, octet modifié, autre tenant, tenant absent, plus de 256 Kio, métadonnées sans clair, nonces distincts sur 10 000 | T16, T18 |
| `[ADR-0001]` `TestReplay` et témoin négatif | T21 |
| `[ADR-0001]` `TestHistoryHasNoPlaintext` | T20 |
| `[ADR-0001]` `TestTransitRotation` | T17 |
| `[ADR-0002]` `TestFakeDeterministic` | T10 |
| `[ADR-0002]` `TestOutOfSchemaRejected`, `TestNoRouteNoCall`, `TestRetentionZeroRejectsRetentionModel`, `TestUntrustedBlockRejectedWithTools`, `TestModelMismatchRejected` | T11 |
| `[ADR-0002]` `TestProviderContract`, `TestResidencyEUBlocksAnthropicDirect`, `TestNoSecretInOutgoingRequest` | T12 |
| `[ADR-0002]` confinement du SDK Anthropic | T02 (R3), vérifié à nouveau en T12 |
| `[ADR-0003]` `docker compose config --images` : image `postgres` officielle ; `grep` AGE : 0 | T03 |

---

## 9. Ce qui change si un ADR est refusé

| ADR refusé | Tâches supprimées | Tâches modifiées | Conséquence à consigner |
|---|---|---|---|
| 0001 | T16, T17, T18, T21 | T03 : sans Transit, sans clés de tenants, sans jeton du worker (OpenBao reste démarré : livrable M0) ; T19 : sans `ContinueAsNew` ; T20 : convertisseur par défaut, sans `TestHistoryHasNoPlaintext` ; T06 : `secret.Bytes` reste | Historique Temporal en clair : risque résiduel sur T3, T7, T11 et le principe 9, à couvrir par un autre ADR avant M1. M0 passe de 23 à 19 tâches. |
| 0002, au profit de l'option (c) « Anthropic direct seulement » | aucune | T08 : sans `Route`, `Platform`, `Capabilities`, `TenantPolicy`, `CheckPolicy`, `RouteResolver` (l'interface devient `Structured(ctx, req)` et `WithTools(ctx, req, tools)`) ; T10 : clé du faux libre, résolveur retiré ; T11 : 6 tests au lieu de 11 ; T12 : sans test de résidence ni table de capacités ; T22 et T23 : baseline `evals/<suite>/baseline.json` | A6 (option UE) non tenu ; à noter dans le modèle de menace (T7). R3 reste. |
| 0002, au profit de l'option (b) « passerelle » | T12 | nouvel adaptateur de passerelle, plan de tâche à refaire | nouvel actif sur la frontière LLM (T7, T6) |
| 0003 | aucune | T03 : image AGE épinglée par empreinte, `CREATE EXTENSION age` dans la base `rempart` ; critères 3 et 4 de T03 inversés | aucune autre incidence en M0 (aucune table de graphe) |

---

## 10. Risques du jalon

| # | Risque | Atténuation |
|---|---|---|
| R1 | Ampleur : 23 tâches, dont 4 entièrement liées à l'ADR 0001 | L'ordre livre les critères 2, 3 et 5 sans dépendre de l'ADR 0001 ; T16 à T18 et T21 peuvent glisser sans toucher le reste (section 9). Budget du protocole : plus de 6 cycles sans progrès sur une tâche, arrêt et deux options. |
| R2 | API des SDK différentes de l'esquisse (convertisseur `ContextAware`, `EncodeCommonAttributes`, rejoueur avec convertisseur, `testsuite` hors `go test`, sortie structurée et `strict` du SDK Anthropic) | Premier incrément de chaque tâche concernée : vérification sur la version épinglée, écart consigné dans le plan de tâche ; tests de contrat ; replis nommés (T23 : pile `make dev`). |
| R3 | Frictions du harnais : porte TDD aveugle aux tests `integration` ; fixtures gelées (scripts, historiques) qui dépendent du code ; CI rouge sur la PR de T23 jusqu'à H3 | Règles de la section 2.2 ; mode scripté du faux ; enregistrement des historiques en phase tests seulement ; H3 dans la même PR que T23. |
| R4 | Docker sous WSL2 : lenteur, `--wait`, empreintes d'images à tenir à jour ; dépôt actuel sous OneDrive | `dev-preflight` explicite ; empreintes vérifiées par test ; clone dans `~/rempart` (H0). |
| R5 | Non-déterminisme du code de workflow (horloge, aléa, itération de map) | `workflowcheck` dans `arch-test` ; `TestReplay` dans `verify-quick` ; slices plutôt que maps pour tout ordre observable. |
| R6 | Tests d'intégration instables (délais Temporal, démarrage de la pile) | Attentes bornées avec sondes de santé, jamais de pause fixe ; horloge du testsuite pour les tests unitaires. |
| R7 | Faux positifs de `gosec` et tentation du `//nolint` | `nolintlint` exige linter précis et explication ; `acceptance-verifier` compte les `nolint` à chaque tâche. |
| R8 | Fixtures ressemblant à des secrets dans un dépôt public (protection de push de GitHub, confusion avec un vrai secret) | Marqueurs `EXAMPLE` ou `FAKE` imposés par la garde ; jetons factices sans somme de contrôle valide ; revue sécurité de T07. |
| R9 | Dérive de version de Go entre poste et CI | `go-version-file: go.mod` dans la CI ; directive `toolchain` si nécessaire. |
| R10 | `govulncheck` dépend du réseau et une vulnérabilité publiée pendant M0 rend `verify` rouge sans changement de code | Tâche corrective dédiée (montée de version), jamais d'exclusion silencieuse. |
| R11 | La démo glisse vers de la logique métier | Vérificateur d'égalité synthétique ; règle R4 ; revue de T19. |
| R12 | Coût ou fuite par appel réel au modèle | Aucun appel réel en M0 (Q4) ; reprises du SDK à 0 ; `MaxTokensPerCall`. |

---

## 11. Impact sur le modèle de menace (`docs/02-THREAT-MODEL.md`)

### 11.1 Menaces existantes traitées ou préparées par M0

| Menace | Apport de M0 | Preuve |
|---|---|---|
| T1 Vol d'identifiants | Aucun identifiant cloud en M0 ; `secret.Value` ; historique Temporal chiffré `[ADR-0001]` | `TestValueNeverPrinted`, `TestNoLeakThroughUnexportedField`, `TestHistoryHasNoPlaintext` |
| T2 Injection de prompt | Séparation `Structured` et `WithTools` ; refus des blocs non fiables avec outils ; délimitation qui neutralise les balises ; sorties validées par schéma ; vérificateur de démo déterministe | `TestUntrustedBlockRejectedWithTools`, `TestRenderUntrustedEscapesDelimiter`, `TestOutOfSchemaRejected`, `TestDemoVerifyDeterministic` |
| T3 Accès inter-tenant | Tenant obligatoire et vérifié (`llm.Client`, enveloppe, codec) ; clé Transit par tenant `[ADR-0001]` ; route par tenant `[ADR-0002]` | `TestTenantRequired`, `TestOpenOtherTenantFails`, `TestDecodeOtherTenantFailsNonRetryable`, `TestTransitTenantKeysDistinct`, `TestCrossTenantRouteIsolation` |
| T6 Dépendance piégée | Modules épinglés (`go.sum`, directive `tool`), images par empreinte, actions par SHA, `govulncheck` dans `verify` | `TestComposeImagesPinnedByDigest`, `TestCIActionsPinnedBySHA`, `go tool govulncheck ./...` |
| T7 Fuite vers le fournisseur LLM | Rédacteur ; interception des requêtes sortantes ; aucun appel réel en CI ; résidence `[ADR-0002]` | `TestRedactPatterns`, `TestRedactionBeforeProvider`, `TestNoSecretInOutgoingRequest`, `TestResidencyEUBlocksAnthropicDirect` |
| T8 Exécution de commandes | Seules exécutions : `go list` (archtest) et `git diff` (evals), arguments en tableau, référence validée, `--end-of-options` | `TestRejectsUnsafeGitRef`, revue de T02 et T23 |
| T10 Épuisement de coût | Budgets d'itérations, de tokens et de temps dans `RunLoop` ; correction bornée ; reprises du SDK à 0 | `TestRunLoopBudget*`, `TestBoundedCorrection`, `TestNoRetryInSDK` |
| T11 Initié malveillant | Accès à la base ou à l'UI Temporal insuffisant pour lire les données `[ADR-0001]` | `TestHistoryHasNoPlaintext` |
| T12 Approbation usurpée | Hash exact, signature vérifiée par activité, quorum, rôle sécurité, exclusion de l'auteur, refus non authentifié ignoré | `TestAwaitApprovals*` (13 tests) |
| Principe 7 (échec sûr) | Timeout d'approbation, escalade et erreur d'activité ne commettent rien | `TestAwaitApprovalsTimeoutDoesNothing`, `TestDemoApprovalTimeoutNoCommit`, `TestRunLoopActivityFailureEscalates` |

### 11.2 Menaces nouvelles à faire intégrer par `security-reviewer` à la clôture (H4)
En plus des menaces listées par les ADR acceptés (intégrées en D0) :
- **N1 CI d'un dépôt public** (T, E) : PR de forks, action compromise, empoisonnement de cache. Atténuation : `pull_request` seulement, `permissions: contents: read`, actions épinglées par SHA, aucun secret dans les jobs de PR, CODEOWNERS sur `.github/`. Vérification : `TestCI*`.
- **N2 Pile de développement exposée** (I, E) : ports, jeton racine OpenBao, mots de passe PostgreSQL. Atténuation : écoute sur `127.0.0.1`, valeurs aléatoires dans `.env.dev` ignoré par Git, jeton du worker limité à Transit. Vérification : `TestComposePortsLoopbackOnly`, `TestComposeNoLiteralSecrets`, `TestDevStackTransitReady`.
- **N3 Faux câblé en production** (E, T) : faux fournisseur LLM ou vérificateur d'approbation factice (qui accepterait une signature calculable). Atténuation : `-dev` obligatoire, aucun fournisseur par défaut, R5 limite les faux à `cmd/`. Vérification : `TestLoadConfigFakeRequiresDev`, `TestRepositoryConforms`.
- **N4 Falsification de baseline ou de seuils d'eval** pour masquer une régression (T, R). Atténuation : baseline et tolérances dans le fichier protégé par le hook, CODEOWNERS, résistance aux injections inférieure à 1 toujours bloquante. Vérification : `TestInjectionResistanceBelowOneIsRegression`, `TestCodeownersProtectsBaselines`, `git log` de la baseline.
- **N5 Inondation de signaux d'approbation invalides** (D) : croissance de l'historique, attente bloquée. Atténuation : plafond `MaxIgnored`, issue `signal_flood`, rien n'est appliqué. Vérification : `TestAwaitApprovalsSignalFlood`.
- **N6 Vérificateur contourné par une empreinte fournie** (T) : un vérificateur ou une sortie LLM qui maquillerait la stagnation. Atténuation : `RunLoop` recalcule empreinte et score. Vérification : `TestRunLoopRecomputesFingerprint`.

---

## 12. Questions ouvertes pour l'humain

| # | Question | Réponse par défaut proposée |
|---|---|---|
| Q1 | Chemin du module Go ? | `github.com/amezianechayer/rempart` (dépôt public existant). |
| Q2 | Accepter les dossiers d'outillage hors vision (`cmd/rempart-evals`, `internal/evals`, `internal/archtest`, `scripts/dev-*`, `.github/`) et les consigner dans `docs/00-VISION.md` §4 lors de l'amendement déjà prévu par les ADR 0002 et 0003, sans ADR dédié ? | Oui, en D0. |
| Q3 | Tests d'intégration de M0 contre la pile `make dev` (que `make verify` démarre lui-même, en local et en CI) plutôt que testcontainers, recommandé par `go-platform-conventions` ? | Oui en M0 : le critère 4 impose déjà cette pile ; testcontainers arrive en M1 avec les premières tables PostgreSQL et leurs tests d'accès croisé. |
| Q4 | Appels réels à l'API Anthropic en M0 (clé dans les secrets GitHub, job nocturne) ? | Non : adaptateur testé contre `httptest` seulement, aucun secret dans la CI ; job nocturne et secret en M1, avec la première boucle LLM. |
| Q5 | Vérification cryptographique réelle des signatures d'approbation dès M0 ? | Non : vérificateur factice déterministe derrière une activité (le contrat de `AwaitApprovals` est complet et testé) ; cryptographie réelle avec l'ADR « approbations signées par des clés du client », en M4. |

---

## 13. Récapitulatif ordonné

| Ordre | Id | Titre | Dépend de | ADR | Revue sécurité |
|---|---|---|---|---|---|
| 0 | H0 | Préalables humains (patchs, ADR, poste, tag `m0-start`) | | | |
| 1 | D0 | Alignement documentaire des ADR acceptés | H0 | 0001, 0002, 0003 | passage pour le modèle de menace |
| 2 | T01 | Squelette, Makefile, lint, `verify-quick` vert | D0 | | non |
| 3 | T02 | Règles d'architecture et découplage de `loops` | T01 | | oui |
| 4 | T03 | Pile de dev et `make dev` | T01 | 0001, 0003 (parties) | oui |
| 5 | T04 | CI GitHub Actions ; puis H1 | T03 | | oui |
| 6 | T05 | Tenant dans le contexte | T01 | | oui |
| 7 | T06 | `secret.Value` et `secret.Bytes` | T01 | | oui |
| 8 | T07 | Rédacteur de secrets | T01 | | oui |
| 9 | T08 | Contrat LLM et `ModelProvider` | T05 | 0002 (parties) | oui |
| 10 | T09 | JSON Schema strict et prompts versionnés | T08 | | oui |
| 11 | T10 | Faux fournisseur déterministe | T08 | 0002 (parties) | oui |
| 12 | T11 | Service `llm.Client` | T05, T07, T09, T10 | 0002 (parties) | oui |
| 13 | T12 | Adaptateur Anthropic | T06, T08, T11 | 0002 (parties) | oui |
| 14 | T13 | Findings, empreinte, score | T01 | | non |
| 15 | T14 | `RunLoop` | T13 | | oui |
| 16 | T15 | `AwaitApprovals` | T14 | | oui |
| 17 | T16 | Enveloppe AES-256-GCM | T05, T06 | 0001 | oui |
| 18 | T17 | `KeyWrapper` Transit | T03, T16 | 0001 | oui |
| 19 | T18 | Codec Temporal | T14, T16 | 0001 | oui |
| 20 | T19 | Workflow de démonstration | T11, T14, T15 | 0001 (partie) | oui |
| 21 | T20 | Worker, `make demo`, bout en bout | T03, T17, T18, T19 | 0001 (partie) | oui |
| 22 | T21 | Versioning et rejeu | T20 | 0001 | non |
| 23 | T22 | Noyau d'évaluation | T01 | 0002 (partie) | non |
| 24 | T23 | `rempart-evals`, suite `demo` ; puis H3 | T19, T22 | 0002 (partie) | oui |
| 25 | H4 | Clôture `/close-milestone M0` | tout | | revue du diff complet |

Parallélisables après T01 (si plusieurs sessions) : T05, T06, T07, T13, T22. L'ordre ci-dessus reste la référence pour une exécution séquentielle.
