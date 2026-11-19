# M2 : découpage du jalon « Conception sécurisée »

- Date : 2026-11-18 (tête `845b449`, M1 accepté sur `810c15e`)
- Auteur : subagent `architect`
- Statut : **proposé**. Questions Q1 à Q8 à trancher par l'humain (section 9) ; ADR 0010, 0011 et 0012 à écrire au début des tâches indiquées et à faire accepter.
- Sources : `prompts/M2.md` ; `docs/00-VISION.md` ; `docs/01-LOOPS.md` (L2) ; `docs/02-THREAT-MODEL.md` (T2, T3, T6, T8, T10, T12, T16, T18, T24, T56, T86, T98, T102 à T104) ; `docs/STATUS.md` (« M1 ACCEPTÉ », « Fait » depuis le 2026-11-17, « En cours », « Reste à faire ») ; `docs/plans/M1-overview.md`, `docs/plans/M1-design-cidr.md` ; ADR 0003, 0006 (A2), 0008 (A1.2) ; skills `policy-as-code` (et ses exemples Rego), `security-graph-attack-paths` (et `graph-schema.md`), `multicloud-networking`, `kubernetes-gitops` (`k8s-baseline.md`), `loop-engineering` (gabarit de fiche), `agent-evals` ; code : `internal/graph/{schema.go,domain}`, `internal/design/{build.go,placement.go,cidr}`, `schemas/graph/v1.json`, `schemas/intent/v1.json`, `internal/threat` et `internal/policy` (vides), `policies/{design,iac,k8s,runtime}` (vides), `internal/loops/{spec.go,runloop.go,l1}`, `internal/evals`, `cmd/rempart-evals`, `evals/baselines.go`, `Makefile` (cible `opa-test`).
- Contraintes de l'humain (mode allégé, 2026-10-13) : par tâche, plan court, tests essentiels (critères et cas adverses de sécurité) et code d'une traite, phases TDD conservées ; pas d'`architect` (sauf ADR), de `test-author` ni d'`acceptance-verifier` par tâche ; `security-reviewer` une passe sur les tâches sensibles, seuls les constats critiques ou hauts relancent un cycle ; une acceptation unique à `/close-milestone M2` ; peu de tâches.

Convention des commandes (reprise de M1) : `go test -v` écrit `--- PASS: TestNom (0.00s)` ; les motifs se terminent par une espace après le nom, jamais par `$`. `rc=` est le code affiché par `echo rc=$?`. Les commandes marquées « pile » supposent `make -f Makefile dev` lancé.

---

## 0. Synthèse

Sept tâches, dans cet ordre :

| Ordre | N° | Titre | Taille | Dépend de | Critère servi | Revue sécurité |
|---|---|---|---|---|---|---|
| 1 | M2-T01 | `pre-m2` : obligations datées « avant M2 » | M | ADR 0006 A2 accepté | aucun (dette, préalable) | oui |
| 2 | M2-T02 | `graph-reach` : graphe v1 étendu, `internal/graph/reach` | M | T01, ADR 0010 | C3 | non |
| 3 | M2-T03 | `policy-design` : moteur OPA embarqué, pack `policies/design/` (45 règles) | L | T02, ADR 0011 | C1 | oui |
| 4 | M2-T04 | `threat-stride` : STRIDE par nœud et par flux, révision, delta | M | T02, T03 | C4 | non |
| 5 | M2-T05 | `l2-loop` : fiche L2, réviseur, confirmation, workflow, `make l2-demo` | L | T03, T04, ADR 0012 | C2 (boucle), vérificateur de L2 | oui |
| 6 | M2-T06 | `harden-batch` : M1-T07 reportée (obligations moyennes de M0) | M | aucune | aucun (dette, à solder avant clôture) | oui |
| 7 | M2-T07 | `evals-design` : 15 architectures piégées, cible `design` | M | T05, T06 | C2 | non |

Hors décompte, facultative selon Q7 : M2-T08 `intent-draft-v2` (section 9).

---

## 1. Objectif et critères

Boucle L2 : depuis une IR confirmée (ou un graphe candidat), graphe d'architecture, atteignabilité déterministe, politiques de conception OPA, STRIDE versionné, révision par un réviseur déterministe jusqu'à conformité, sinon escalade expliquée. Aucune décision de sécurité par un LLM ; aucun appel de modèle dans L2 en M2.

| Critère (`prompts/M2.md`) | Tâche |
|---|---|
| C1 `opa test policies/ -v` vert, chaque règle a au moins un cas conforme et un non conforme | T03 |
| C2 15 architectures piégées corrigées ou escaladées avec explication, aucune ne passe en l'état | T07 (avec T05) |
| C3 propriété : ajouter une règle deny ne crée jamais de chemin | T02 |
| C4 delta de menace calculé et sérialisé entre deux versions d'un graphe | T04 |
| Livrable `internal/graph/reach` | T02 |
| Livrable `internal/threat` | T04 |
| Livrable `policies/design/` (au moins 40 règles, métadonnées, tests) | T03 |
| Livrable `docs/loops/L2.md`, workflow L2 | T05 |
| Livrable `evals/design/` (15 architectures piégées) | T07 |
| Vérificateur de L2 (`docs/01-LOOPS.md`) : zéro critique ou haute, aucun chemin Internet vers donnée sensible, CIDR sans conflit, override justifié par un humain | T05 |

## 2. Périmètre

**Dans** : extension en place du schéma `schemas/graph/v1.json` (identités, permissions abstraites, attributs de cluster) et de `internal/design.Build` (défauts sûrs) ; `internal/graph/reach` ; `internal/policy` (domaine, entrée de conception, table de juridiction) et `internal/policy/adapters/opa` ; `policies/embed.go` et `policies/design/*.rego` ; `internal/threat` et `schemas/threat/v1.json` ; `internal/design/revise`, `internal/design/confirm` ; `internal/loops/l2` ; sous-commandes `rempart design --digest`, `rempart threat model|diff` ; enregistrement de L2 dans `rempart-worker` (`-l2-once`) et `make l2-demo` ; suite `evals/design` et cible `design` ; obligations des sections 8.1.

**Hors** : appel de modèle dans L2 (Q1) ; persistance PostgreSQL, `Store`, RLS (Q6) ; API `rempartd` ; confirmation authentifiée et exceptions humaines avec expiration (M4) ; `policies/k8s/` au niveau manifeste, `policies/iac/`, `policies/runtime/` (M3, M5) ; correspondance avec les référentiels (`frameworks` vides tant que `compliance/catalog/` n'existe pas, skill `policy-as-code` : aucun article inventé) ; chemins d'attaque multi-sauts avec compromission supposée (M6) ; relocalisation automatique de région et nouvelle allocation CIDR par le réviseur (escalade en M2) ; v2 du schéma du brouillon (Q7).

---

## 3. Décisions de conception (réversibles, reprises dans l'ADR indiqué)

| # | Décision |
|---|---|
| D1 (ADR 0012) | **Proposeur déterministe** (Q1) : le réviseur applique un catalogue fermé de remédiations qui ne font que restreindre ; aucun LLM dans L2 en M2. Une stratégie LLM pourra s'ajouter plus tard derrière le même vérificateur. |
| D2 (ADR 0012) | **Deux formes d'entrée**, exactement une par exécution : IR confirmée (chemin produit, `Build` puis boucle) ou graphe candidat `source: design` (import futur, cas d'evals que l'IR ne sait pas exprimer : IAM `*`, API de cluster publique). Même vérificateur ; la sortie porte `subject` (`ir` ou `graph`). |
| D3 (ADR 0012) | **Confirmation à l'entrée de L2** (décision Q3 de M1, Q5) : objet `Confirmation` lié à l'empreinte SHA-256 du sujet et à la liste **complète** des expositions (charge (cn), (ev)) ; empreinte ou liste différente : refus avant la boucle (`InvalidL2Input`, non rejouable). Identité du confirmant déclarée, non authentifiée jusqu'à M4 (T107). |
| D4 (ADR 0012) | **Vérificateur** (activité `l2.Verify`) : schéma et invariants du graphe, tenant égal à celui du worker, CIDR (`cidr.Check` sur le plan tiré du graphe), atteignabilité (`reach`), **invariant Go indépendant du pack** « aucun saut direct Internet vers un DataStore confidentiel ou réglementé » (`L2-INTERNET-TO-SENSITIVE`, critique, T108), puis pack OPA. Findings critiques et hauts : rendus à `RunLoop` ; moyens et bas : `advisories` de la sortie, jamais bloquants (cohérent avec `docs/01-LOOPS.md` ; `RunLoop` refuse un OK accompagné d'un finding moyen). Plus de 100 findings : les 100 plus graves. |
| D5 (ADR 0012) | **Remédiations** : vocabulaire fermé lu dans `custom.remediation` de chaque règle (`make_private`, `remove_exposure`, `https_only`, `encrypt_transit`, `move_to_data_tier`, `enable_encryption`, `least_privilege`, `dedicated_identity`, `use_workload_identity`, `enable_audit_log`, `enable_secrets_encryption`, `enable_admission`, `default_deny_netpol`, `escalate`, `advisory`). Un correctif impossible (ex. pas de sous-réseau data dans le VPC) n'applique rien : la stagnation mène à l'escalade. |
| D6 (ADR 0012) | **Escalade** : explication par gabarits codés en français (code fermé, `control_id`, ressource à grammaire fermée, contraintes en cause), jamais de texte non fiable ni de modèle ; aucune sortie de graphe à l'escalade (analogue de T98). Codes : `incompatible_constraints`, `relocation_required`, `exposure_unconfirmed`, `sources_unresolved`, `manual_fix_required`, `cidr_conflict`. |
| D7 (ADR 0012) | **Dérogations** (`explicit_overrides`) jamais appliquées automatiquement ; affichées échappées dans le récapitulatif de confirmation ; (ey) : fait `sources_unresolved` calculé en Go (exposition sans source et dérogation qui cite une adresse, avec la lecture d'adresses de L1 après (ez)), règle NET-005. |
| D8 (ADR 0010) | **Atteignabilité** : graphe dirigé de sauts ; un saut `(src, dst, proto)` porte l'union des plages de ports des règles allow moins l'union des règles deny (deny l'emporte) ; sources Internet en attribut (vide ou `/0` : tout Internet) ; chemins depuis Internet par parcours en largeur borné (`Limits`). Monotonie par construction, prouvée par propriété (C3) ; deuxième propriété : retirer une allow ne crée aucun chemin. Une seule implémentation pour L2, L5 et L6 (skill `multicloud-networking`). |
| D9 (ADR 0010) | **Graphe v1 étendu en place** (aucun graphe persisté ni lecteur externe) : nœuds `Identity` et `Account`, arêtes `RUNS_AS` et `HAS_PERMISSION` (`actions` dans `read`, `write`, `admin`, `*`), attributs de cluster (`api_allowed_sources`, `audit_log`, `secrets_encryption`, `network_policy_default_deny`, `admission_policy`, `workload_identity`), `public_ip`, `credential` ; préfixes d'identifiant `id:` et `acct:` ; description « `allowed_sources` vide : tout Internet » (ADR 0006 A2.3, au niveau du graphe). Toute modification après le premier graphe persisté change `version`. `Build` pose les défauts sûrs et une identité par workload, permissions `read` et `write` sur les seuls DataStore qu'il héberge ou atteint. |
| D10 (ADR 0010) | **STRIDE** : catalogue codé `stride-v1` (catégorie, cible nœud ou flux, contrôles qui l'atténuent) ; statut `mitigated` si aucun de ces contrôles n'a de finding sur la cible, sinon `open` (`accepted` réservé aux exceptions humaines, M4). Révision du graphe = SHA-256 des `Facts` triés ; modèle et delta en JSON à ordre total, schéma `schemas/threat/v1.json`, décodage strict. Le delta initial vers final de L2 entre dans la sortie (futur dossier de preuves, A3). |
| D11 (ADR 0011) | **OPA embarqué** (Q2) : bibliothèque `github.com/open-policy-agent/opa/v1/rego` à version épinglée, seule importée par `internal/policy/adapters/opa` (règle archtest) ; capacités en liste blanche (aucun `http.send`, `net.*`, `opa.runtime`, `time.now_ns`, `rand.*`, `print`) ; Rego v1 strict ; pack embarqué par `policies/embed.go` (fichiers `_test.rego` exclus), compilé une fois au démarrage du worker, métadonnées vérifiées (échec fermé). CLI par `go tool opa` (directive `tool` de `go.mod`) : même version que la bibliothèque, aucun changement de la CI (`make verify` appelle déjà la cible `opa-test`). |
| D12 (ADR 0011) | **Juridiction** : table codée et datée (cloud, région) vers `fr`, `eu`, `non_eu`, chaque ligne vérifiée à la source du fournisseur ; région absente : `unknown`, échec fermé pour un hôte de données sensibles (RES-005). |
| D13 | `frameworks` vide dans toutes les règles en M2 ; contrôles K8s de conception (`K8S-xxx`) dans `policies/design/`, avec le `control_id` que reprendra `policies/k8s/` en M3. |
| D14 (ADR 0012) | Budget L2 : 5 itérations, `max_tokens` 1 (aucun modèle), 2 minutes ; stagnation aux seuils par défaut (2, 3) avec une seule stratégie `catalog`. Graphe candidat limité à `loops.MaxCandidateBytes` (64 Kio) : au-delà, escalade `payload_too_large` (R2). |

### 3.1 Interfaces principales (Go)

```go
package reach // internal/graph/reach : bibliothèque standard et internal/graph/domain seulement
type Proto string                        // tcp, udp (http et https lus comme tcp)
type PortRange struct{ From, To uint16 }
type PortSet []PortRange                 // trié, fusionné
type Rule struct {
	Action   string        // allow, deny
	Src, Dst string        // identifiant de nœud, "internet", "*" (deny seulement)
	Proto    Proto
	Ports    PortRange
	Sources  []netip.Prefix // allow depuis internet ; vide : tout Internet
}
type Model struct{ Nodes []string; Rules []Rule }
type Limits struct{ MaxNodes, MaxRules, MaxDepth, MaxPaths int }
type Hop struct{ Src, Dst string; Proto Proto; Ports PortSet; World bool; Sources []netip.Prefix }
type Path struct{ Target string; Nodes []string }
type Result struct{ Hops []Hop; FromInternet []Path }
var ErrGraphTooLarge, ErrInvalidModel error
func FromGraph(g domain.Graph) (Model, error)       // EXPOSES, CAN_REACH, public_access, api_public, public_ip ; deny Internet vers tiers data et mgmt
func Compute(m Model, l Limits) (Result, error)     // déterministe ; deny l'emporte
func (r Result) SubsetOf(o Result) bool             // sauts, ports, sources et chemins inclus

package threat // internal/threat
const CatalogVersion = "stride-v1"
type Threat struct{ ID, Rule, Category, Target, TargetType, Severity, Status string; Controls []string }
type Model struct{ SchemaVersion, Catalog, TenantID, GraphRevision string; Threats []Threat }
type Change struct{ ID string; From, To Threat }
type Delta struct{ SchemaVersion, Catalog, TenantID, From, To string; Added, Removed []Threat; Changed []Change }
var ErrTenantMismatch, ErrCatalogMismatch error
func Revision(g graphdomain.Graph) (string, error)
func Analyze(g graphdomain.Graph, findings []loopsdomain.Finding) (Model, error)
func Diff(a, b Model) (Delta, error)
func DecodeModel(raw []byte) (Model, error) // strict
func DecodeDelta(raw []byte) (Delta, error) // strict

package domain // internal/policy/domain
type Remediation string // vocabulaire fermé de D5
type Control struct{ ID, Title string; Severity loopsdomain.Severity; Remediation Remediation }
type Derived struct{ /* juridiction par nœud, expositions confirmées, sources non résolues, contraintes et observabilité de l'IR */ }
type DesignInput struct{ Graph graphdomain.FactsGraph; Reach reach.Result; Derived Derived } // aucun FreeText

package policy // internal/policy
type Evaluator interface {
	Evaluate(ctx context.Context, in domain.DesignInput) ([]loopsdomain.Finding, error) // Code = control_id, Source = "policy:design"
	Controls() []domain.Control
}
func Jurisdiction(cloud, region string) string // fr, eu, non_eu, unknown

package opa // internal/policy/adapters/opa : seul importeur d'OPA
func NewDesign() (*Engine, error) // pack embarqué, capacités en liste blanche, métadonnées vérifiées

package revise // internal/design/revise
type Applied struct{ ControlID, Resource string; Remediation policydomain.Remediation }
func Revise(g graphdomain.Graph, f []loopsdomain.Finding, c []policydomain.Control) (graphdomain.Graph, []Applied, error)

package confirm // internal/design/confirm
type ExposureKey struct{ Target, Protocol string; Port int; Sources []string }
type Confirmation struct{ Subject, SubjectSHA256 string; Exposures []ExposureKey; ConfirmedBy string } // ConfirmedBy déclaré (T107)
type Digest struct{ /* empreinte, expositions (sans source : « tout Internet »), dérogations échappées, données sensibles et régions */ }
func DigestOfIR(ir intentdomain.IR) (Digest, error)
func DigestOfGraph(g graphdomain.Graph) (Digest, error)
func Check(d Digest, c Confirmation) error // ErrNotConfirmed : empreinte ou liste d'expositions différente

package l2 // internal/loops/l2
const WorkflowName = "rempart.l2.v1"
type Input struct{ IR *intentdomain.IR; Graph *graphdomain.Graph; Confirmation confirm.Confirmation } // aucun tenant : celui du worker
type Explanation struct{ Code, ControlID, Resource, Text string } // Text : gabarit codé
type Output struct {
	Status, Reason, Subject string // converged, escalated
	Graph           *graphdomain.Graph // converged seulement
	Applied         []revise.Applied
	InitialFindings []loopsdomain.Finding
	Advisories      []loopsdomain.Finding
	Threats         *threat.Model // converged seulement
	ThreatDelta     *threat.Delta // initial vers final, converged seulement
	Explanation     []Explanation // escalated seulement
	Loop            loops.LoopResult // Best vidé
}
func Spec() loops.LoopSpec // littéral constant
```

## 4. Fiche de la boucle L2 (recopiée dans `docs/loops/L2.md` au début de T05, avant le code)

```yaml
id: L2-design
purpose: produire un graphe d'architecture conforme aux politiques de conception, ou escalader en expliquant les contraintes incompatibles
trigger: démarrage explicite (make l2-demo, cible d'eval design, tests) ; à terme, IR confirmée sortie de L1 (API en M4)
inputs:
  - ir              # Intent IR v1 confirmée (chemin produit), ou
  - graph           # graphe candidat source design (import, evals) ; exactement un des deux
  - confirmation    # empreinte du sujet et liste complète des expositions (D3)
  # tenant : celui du worker ; tenant de l'IR ou du graphe différent : refus avant la boucle
strategies: [catalog]
steps:
  prepare: activité l2.Prepare (confirmation, tenant, Build ou validation du graphe, faits dérivés de l'IR dont (ey))
  propose: activité l2.Propose (itération 1 : candidat initial ; ensuite revise.Revise sur les findings, restreindre seulement)
  verify: activité l2.Verify (D4 : schéma, tenant, CIDR, reach, invariant Go, pack OPA)
  diagnose: findings normalisés (control_id, ressource), 20 premiers par gravité
  finalize: activité l2.Finalize (advisories, STRIDE initial et final, delta, explication si escalade)
verifier:
  success_when:
    - aucun finding critique ou haut (pack, invariant Go, CIDR)
    - aucun saut direct Internet vers une donnée confidentielle ou réglementée
    - toute exposition du graphe final figure dans la confirmation humaine
budget: {max_iterations: 5, max_tokens: 1, max_wall_time: 2m, max_cost_eur: 0}   # aucun modèle en M2
stall_detection: {same_fingerprint_switch_strategy: 2, same_fingerprint_escalate: 3}
escalation:
  to: résultat du workflow (statut escalated), aucun graphe rendu
  payload: [findings restants, explication codée par contrainte, révisions appliquées, trace]
outputs: [status, subject, graph (converged), applied, initial_findings, advisories, threats, threat_delta, explanation (escalated), loop_trace]
idempotency_keys: [tenant_id, workflow_id]
security_notes: aucun texte libre dans l'entrée des politiques (Facts) ; dérogations jamais appliquées ; réviseur qui ne fait que restreindre ; confirmation déclarée jusqu'à M4 ; historique chiffré (ADR 0001)
evals: evals/design/
```

---

## 5. Tâches

### M2-T01 `pre-m2` : obligations datées « avant M2 »

- **Objectif** : solder ce qui doit précéder tout code de M2 : confinement par contrainte de build (avant l'arrivée d'OPA), sorties de L1 consommées par L2, dépendances.
- **Dépend de** : ADR 0006 A2 accepté par l'humain (T01 en étend la règle).
- **Livrables** : (er) `internal/archtest` : contrainte de build (`//go:build`, suffixe GOOS ou GOARCH) refusée dans tout fichier non test lu par `ReadSources`, sauf l'étiquette `integration`, cas `build_variant` par règle de confinement ; (es) et (ck) `internal/intent/domain` : `resource` de `INTENT-BLOCKING-ASSUMED` fixe, grammaire fermée de `assumptions[].field` et `open_questions[].field` (chemin `[a-z_]+(\[[0-9]+\])?` séparé par `.`, 64 octets), test sur toute la sortie sérialisée de L1 (aucun texte du brouillon) ; (ez) lecture des adresses : séparateurs d'apparence de point non ASCII (U+2024, U+FF0E, U+00B7, U+3002, U+FE52) et notations désarmées (`[.]`, `(.)`, `[:]`, points espacés) relus, sinon échec fermé du jeton (A2.1 bis), tests de l'échec fermé ; (ev) cas `evals/intent/cases/intent-exposure-negated.yaml` (réponse scriptée sûre ; mesure réelle en H-real) ; (ex) `golang.org/x/net` v0.62.0 ; (dx) `fresh()` construit un transport explicite, transport injecté cloné.
- **Tests clés (7)** : `TestBuildVariantCannotHideImports`, `TestBlockingAssumedResourceFixed`, `TestFieldGrammar`, `TestL1OutputHasNoDraftText`, `TestExposureSourcesNonASCIISeparators`, `TestExposureSourcesDefanged`, `TestFreshTransportExplicit`.
- **Acceptation** :
  1. `go test ./internal/archtest/ ./internal/intent/... ./internal/loops/l1/... ./internal/llm/... -v 2>&1 | grep -Ec -- '^--- PASS: Test(BuildVariantCannotHideImports|BlockingAssumedResourceFixed|FieldGrammar|L1OutputHasNoDraftText|ExposureSourcesNonASCIISeparators|ExposureSourcesDefanged|FreshTransportExplicit) '` : `7`.
  2. `go list -m golang.org/x/net` : `golang.org/x/net v0.62.0` ; `go tool govulncheck ./...; echo rc=$?` : `rc=0`.
  3. `test -f evals/intent/cases/intent-exposure-negated.yaml && echo ok` : `ok` ; après H3-intent-bis : `make -s -f Makefile evals EVAL=intent | jq -e '.cases == 31 and .injection_resistance == 1 and .regressions_vs_baseline == []'` : `true`.
  4. `make -f Makefile verify-quick; echo rc=$?` : `rc=0`.
- **Sécurité** : oui (confinement T103, sortie de L1 T104, T102).

### M2-T02 `graph-reach` : graphe v1 étendu et atteignabilité

- **Objectif** : modèle d'atteignabilité unique, monotone et borné ; graphe capable de représenter les pièges du jalon (IAM, API de cluster).
- **Dépend de** : T01 ; ADR 0010 écrit au début de la tâche et accepté avant la phase tests.
- **Livrables** : `schemas/graph/v1.json` et `internal/graph/domain` étendus (D9), avec (cp) : motif excluant `\p{Cc}` et les bidirectionnels sur `free_text` ; `internal/design/build.go` (défauts sûrs, identités) ; `internal/graph/reach/{model.go,compute.go,fromgraph.go}` ; golden du scénario de référence mis à jour en phase tests ; `security-graph-attack-paths/references/graph-schema.md` aligné (modification de skill signalée dans `docs/STATUS.md`).
- **Tests clés (10)** : `TestDenyNeverAddsPath` (C3, rapid), `TestRemoveAllowNeverAddsPath`, `TestReachDenyOverridesAllow`, `TestReachDeterministic`, `TestReachFromGraphReference` (Internet atteint seulement le LB ; aucun saut direct vers la base), `TestReachLimits` (T24, `ErrGraphTooLarge`), `TestGraphSchemaExtension` (nouveaux nœuds et arêtes, `*`, contrôles C1 et bidi refusés), `TestBuildIdentitiesLeastPrivilege`, `TestReferenceScenarioGraphValid` (mis à jour), `TestFactsBlockHasNoFreeText` (inchangé, vert).
- **Acceptation** :
  1. C3 : `go test ./internal/graph/reach/ -run TestDenyNeverAddsPath -rapid.checks=1000 -v` : `--- PASS: TestDenyNeverAddsPath `.
  2. `go test ./internal/graph/... ./internal/design/... -v 2>&1 | grep -Ec -- '^--- PASS: Test(DenyNeverAddsPath|RemoveAllowNeverAddsPath|ReachDenyOverridesAllow|ReachDeterministic|ReachFromGraphReference|ReachLimits|GraphSchemaExtension|BuildIdentitiesLeastPrivilege|ReferenceScenarioGraphValid|FactsBlockHasNoFreeText) '` : `10`.
  3. `go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./internal/graph/reach | grep -v '^github.com/amezianechayer/rempart/internal/graph/' | wc -l` : `0`.
  4. `go run ./cmd/rempart design internal/intent/testdata/reference-ir.json | jq -e '([.graph.nodes[] | select(.kind == "Identity")] | length) > 0 and ([.graph.edges[] | select(.type == "HAS_PERMISSION" and (.attrs.actions | index("*")))] | length) == 0'` : `true`.
  5. `make -f Makefile verify-quick; echo rc=$?` : `rc=0`.
- **Sécurité** : non par tâche (code pur, couvert par la revue de T05 qui le consomme et par la revue de clôture).
- **Écarts reportés (ADR 0010, section « Écarts au plan M2 »)** : (1) section 3.1 : aucune règle deny implicite dans `FromGraph` ; (2) section 3.1 : `FromGraph`, `Revision` et `Analyze` prennent un `FactsGraph`, `domain.FactsOf` ajouté, `Analyze` reçoit un `Pack`, `pack_digest` et `ErrPackMismatch`, `Limits` sans défaut implicite et `DefaultLimits` exporté ; (3) D10 : `accepted` hors du schéma v1 de menace ; (4) critère 4 de cette fiche : la commande porte `--json` (vérification 4 de l'ADR) ; (5) sous-cas ajoutés à des tests existants sans en changer le nombre. Écarts de mise en oeuvre (`World` sur les deux familles, ordre total des sauts, `*` qui couvre `internet`, `ErrAttrKind`, faits illisibles refusés) : `docs/STATUS.md`, entrée M2-T02, à valider par l'humain.

### M2-T03 `policy-design` : moteur OPA embarqué et pack de conception

- **Objectif** : C1 ; au moins 40 règles de conception avec métadonnées, cas conformes et non conformes, évaluées depuis Go sur les seuls faits.
- **Dépend de** : T02 ; ADR 0011 écrit au début de la tâche et accepté avant la phase tests (dépendance nouvelle, T6).
- **Livrables** : `go.mod` (bibliothèque OPA et directive `tool` pour la CLI, même version) ; `Makefile` (`OPA` par `go tool opa`, `opa check --strict` dans `opa-test`) et `internal/archtest/makefile_test.go` ; `policies/embed.go` ; `policies/design/{network,data,residency,iam,k8s,resilience}.rego`, leurs `_test.rego` et `lib_test.rego` (aides `ok(control, input)` et `ko(control, input)`) ; `internal/policy/{domain,design.go,jurisdiction.go}` ; `internal/policy/adapters/opa/engine.go` ; règle archtest `opa-confined` ; proposition de harnais `CODEOWNERS` sur `/policies/` (T108).
- **Catalogue (45 contrôles ; sévérité ; remédiation)** :
  - Réseau : NET-001 donnée confidentielle ou réglementée atteignable directement depuis Internet (critique ; `make_private`) ; NET-002 exposition non confirmée par un humain, (cn) (haute ; `escalate`) ; NET-003 port d'administration 22, 3389, 5985, 5986 atteignable depuis Internet (critique ; `remove_exposure`) ; NET-004 port de base ou de cache (1433, 1521, 3306, 5432, 6379, 9042, 9200, 11211, 27017) atteignable depuis Internet (critique ; `remove_exposure`) ; NET-005 exposition sans source et dérogation citant une adresse, (ey) (haute ; `escalate`) ; NET-006 tcp ou udp brut ouvert à tout Internet (haute ; `escalate`) ; NET-007 exposition `http` en clair (haute ; `https_only`) ; NET-008 LB vers DataStore sans tier applicatif (haute ; `escalate`) ; NET-009 flux de plus de 100 ports (haute ; `escalate`) ; NET-010 `public_ip` hors tier public (haute ; `make_private`) ; NET-011 flux inter-cloud hors `vpn_site_to_site` ou `private_link` (haute ; `encrypt_transit`) ; NET-012 hôte de donnée sensible hors tier data (haute ; `move_to_data_tier`) ; NET-013 exposition vers un chemin de donnée sensible sans WAF (moyenne ; `advisory`) ; NET-014 tier mgmt atteignable depuis Internet (haute ; `remove_exposure`) ; NET-015 exposition d'un hôte de donnée sensible (haute ; `escalate`).
  - Données : DATA-001 `public_access` sur une donnée non publique (critique ; `make_private`) ; DATA-002 donnée confidentielle ou réglementée non chiffrée (haute ; `enable_encryption`) ; DATA-003 donnée interne non chiffrée (moyenne ; `advisory`) ; DATA-004 classification de l'hôte inférieure à celle de la donnée stockée (haute ; `escalate`).
  - Résidence : RES-001 donnée `eu` ou réglementée sur un hôte `non_eu` (critique ; `escalate`, code `relocation_required`) ; RES-002 donnée `fr` hors France (critique ; `escalate`) ; RES-003 région hors `constraints.allowed_regions` (haute ; `escalate`) ; RES-004 cloud dans `forbidden_clouds` (haute ; `escalate`) ; RES-005 juridiction `unknown` pour un hôte de donnée sensible (haute ; `escalate`) ; RES-006 flux d'un workload `non_eu` vers une donnée `eu` réglementée (haute ; `escalate`) ; RES-007 juridiction `unknown` sans donnée sensible (moyenne ; `advisory`).
  - Identités : IAM-001 action `*` (critique ; `least_privilege`) ; IAM-002 permission d'écriture ou d'administration sur un `Account` entier (critique ; `least_privilege`) ; IAM-003 identité partagée entre tiers (haute ; `dedicated_identity`) ; IAM-004 workload exposé avec action `admin` (haute ; `least_privilege`) ; IAM-005 identifiant statique (`credential: static_key`) (haute ; `use_workload_identity`) ; IAM-006 workload sans identité dédiée (moyenne ; `advisory`) ; IAM-007 permission sur un DataStore ni hébergé ni atteint (haute ; `least_privilege`).
  - Kubernetes (conception) : K8S-001 API publique sans source (critique ; `make_private`) ; K8S-002 journal d'audit désactivé (haute ; `enable_audit_log`) ; K8S-003 Secrets non chiffrés par KMS (haute ; `enable_secrets_encryption`) ; K8S-004 API publique restreinte (moyenne ; `advisory`) ; K8S-010 politique d'admission absente (haute ; `enable_admission`) ; K8S-020 NetworkPolicy deny par défaut absente (haute ; `default_deny_netpol`) ; K8S-030 compte de service à droits `admin` ou `*` hors système (critique ; `least_privilege`) ; K8S-040 identités de workload désactivées (haute ; `use_workload_identity`) ; K8S-050 contrôleur GitOps exposé à Internet (haute ; `remove_exposure`).
  - Résilience : OBS-001 prod sans métriques ni journaux (moyenne ; `advisory`) ; AVL-001 base de prod à un nœud (moyenne ; `advisory`) ; AVL-002 cluster de prod à moins de 3 nœuds (basse ; `advisory`).
- **Tests clés Go (8)** : `TestEveryControlHasOkAndKo` (lecture AST des `_test.rego` : pour chaque `control_id`, au moins un test `ok("<id>", ...)` et un `ko("<id>", ...)`), `TestPolicyMetadataComplete` (titre, `control_id` unique `^[A-Z0-9]{2,5}-[0-9]{3}$`, sévérité fermée, `remediation` du vocabulaire, `frameworks` vide), `TestEngineCapabilitiesDenyIO` (règle avec `http.send`, `opa.runtime`, `time.now_ns`, `rand.intn`, `print` : refus à la compilation), `TestEngineDeterministic`, `TestEngineFailsClosed` (métadonnée manquante, sévérité inconnue lue critique, erreur d'évaluation rendue en erreur, jamais en liste vide), `TestEngineInputHasNoFreeText`, `TestJurisdictionTableClosed`, `TestOPAConfined`.
- **Acceptation** :
  1. C1 : `make -f Makefile opa-test; echo rc=$?` : `rc=0` ; `go tool opa test policies/ -v; echo rc=$?` : `rc=0`.
  2. `go tool opa check --strict policies/; echo rc=$?` : `rc=0`.
  3. `ls policies/design/*.rego | grep -v '_test\.rego$' | xargs grep -h '^#[[:space:]]*control_id:' | sort -u | wc -l` : au moins `40`.
  4. `go test ./internal/policy/... ./internal/archtest/ -v 2>&1 | grep -Ec -- '^--- PASS: Test(EveryControlHasOkAndKo|PolicyMetadataComplete|EngineCapabilitiesDenyIO|EngineDeterministic|EngineFailsClosed|EngineInputHasNoFreeText|JurisdictionTableClosed|OPAConfined) '` : `8`.
  5. `go list -deps ./internal/graph/... ./internal/design/... ./internal/threat/... ./internal/intent/... | grep -c open-policy-agent` : `0`.
  6. `go tool govulncheck ./...; echo rc=$?` : `rc=0`.
  7. `make -f Makefile verify-quick; echo rc=$?` : `rc=0`.
- **Sécurité** : oui (T6, T8, T108, T109, T114).
- **Garde de taille** : au-delà de 6 cycles, couper en T03a (moteur, archtest, 15 règles réseau et données) et T03b (30 autres), sans changer les critères.

### M2-T04 `threat-stride` : STRIDE versionné et delta

- **Objectif** : C4 ; menaces par nœud et par flux, statut dérivé des contrôles, delta sérialisé et reproductible.
- **Dépend de** : T02, T03 (identifiants de contrôle).
- **Livrables** : `internal/threat/{catalog.go,model.go,delta.go,decode.go}` ; `schemas/threat/v1.json` (`$defs` `model` et `delta`) ; `cmd/rempart` sous-commandes `threat model <graphe>` et `threat diff <graphe A> <graphe B>` (findings calculés par le même vérificateur que L2, sans boucle) ; `internal/threat/testdata/{reference.graph.json,reference-ssh.graph.json,delta.golden.json}`.
- **Tests clés (9)** : `TestStrideCoversEveryNodeAndFlow`, `TestThreatStatusFromControls`, `TestGraphRevisionStable` (nœuds et arêtes permutés : même révision), `TestDeltaBetweenVersions` (C4), `TestDeltaSerializationGolden` (octet pour octet, conforme au schéma), `TestDeltaStrictDecode` (clé inconnue, doublon, casse), `TestDeltaRefusesCrossTenant` (T3), `TestThreatModelHasNoFreeText`, `TestThreatDiffCommand`.
- **Acceptation** :
  1. `go test ./internal/threat/... ./cmd/rempart/... -v 2>&1 | grep -Ec -- '^--- PASS: Test(StrideCoversEveryNodeAndFlow|ThreatStatusFromControls|GraphRevisionStable|DeltaBetweenVersions|DeltaSerializationGolden|DeltaStrictDecode|DeltaRefusesCrossTenant|ThreatModelHasNoFreeText|ThreatDiffCommand) '` : `9`.
  2. C4 : `go run ./cmd/rempart threat diff internal/threat/testdata/reference.graph.json internal/threat/testdata/reference-ssh.graph.json | jq -e '.schema_version == "1" and .catalog == "stride-v1" and .from != .to and (.added | length) > 0'` : `true`.
  3. Reproductibilité : `for i in 1 2; do go run ./cmd/rempart threat diff internal/threat/testdata/reference.graph.json internal/threat/testdata/reference-ssh.graph.json | sha256sum; done | uniq | wc -l` : `1`.
  4. `make -f Makefile verify-quick; echo rc=$?` : `rc=0`.
- **Sécurité** : non par tâche (code pur ; T113 couverte par les tests ; revue de clôture).

### M2-T05 `l2-loop` : fiche L2, réviseur, confirmation, workflow

- **Objectif** : boucle L2 de bout en bout sur l'historique chiffré ; vérificateur de `docs/01-LOOPS.md` ; (cn), (ey), affichage de (ev).
- **Dépend de** : T03, T04 ; ADR 0012 écrit au début de la tâche et accepté avant la phase tests.
- **Livrables** : `docs/loops/L2.md` (fiche de la section 4, avant le code) ; `internal/design/revise` ; `internal/design/confirm` (récapitulatif, (co) : C1 et bidirectionnels des dérogations échappés en `\uXXXX`) ; `internal/loops/l2/{workflow.go,register.go}` et `internal/loops/l2/activities/{prepare,propose,verify,finalize}.go` ; `internal/loops/versions.go` ; `cmd/rempart` (`design --digest`), `cmd/rempart-worker` (`-l2-once`, `-l2-input`, enregistrement derrière `codec.Check`, moteur OPA compilé au démarrage, échec fermé) ; lecteurs de fichiers nouveaux avec `Stat` avant `Open` et refus d'un non régulier ((cr)) ; `Makefile` (cible `l2-demo` sur le scénario de référence et une confirmation de test liée au tenant de démo) et `internal/archtest/makefile_test.go` ; mise à jour de T98 et T18 si besoin dans le modèle de menace (T107, T110 ajoutées).
- **Tests clés (13)** : `TestL2ReferenceConvergesUnchanged`, `TestL2RevisesTrap` (SSH ouvert : exposition retirée, NET-003 appliqué), `TestL2EscalatesIncompatibleConstraints` (explication codée), `TestL2RefusesUnconfirmed` (empreinte ou exposition manquante : refus avant toute activité de boucle), `TestL2EveryExposureInDigest` ((cn), (ev) : toute exposition, y compris sans source, apparaît dans le récapitulatif et la confirmation), `TestL2UnresolvedSourceEscalates` ((ey)), `TestL2TenantMismatchRefused` (IR et graphe d'un autre tenant ; obligation du plan M1-design-cidr appliquée au worker), `TestRevisionNeverWidens` (propriété rapid : sauts, sources, permissions, drapeaux publics et chiffrement ne s'élargissent jamais, T110), `TestL2EscalationHasNoGraph`, `TestL2CoreInvariantWithoutPack` (pack vide : la donnée sensible exposée reste refusée, T108), `TestL2FreeTextHasNoEffect` (texte non fiable injecté : sortie identique, T2), `TestDigestEscapesUntrusted` ((co), canaris U+009B et U+202E), `TestWorkerRequiresRempartConverterL2`.
- **Acceptation** :
  1. `go test -race ./internal/loops/l2/... ./internal/design/... ./cmd/rempart-worker/... -v 2>&1 | grep -Ec -- '^--- PASS: Test(L2ReferenceConvergesUnchanged|L2RevisesTrap|L2EscalatesIncompatibleConstraints|L2RefusesUnconfirmed|L2EveryExposureInDigest|L2UnresolvedSourceEscalates|L2TenantMismatchRefused|RevisionNeverWidens|L2EscalationHasNoGraph|L2CoreInvariantWithoutPack|L2FreeTextHasNoEffect|DigestEscapesUntrusted|WorkerRequiresRempartConverterL2) '` : `13`.
  2. `go test ./internal/design/revise/ -run TestRevisionNeverWidens -rapid.checks=1000 -v` : `--- PASS: TestRevisionNeverWidens `.
  3. Aucun modèle : `go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./internal/loops/l2/... | grep -c '/internal/llm'` : `0`.
  4. `grep -c '^budget:' docs/loops/L2.md` : `1`.
  5. Pile : `make -s -f Makefile l2-demo | jq -e '.status == "converged" and .subject == "ir" and (.applied | length) == 0 and (.threats.threats | length) > 0 and .threat_delta.from == .threat_delta.to'` : `true` (vérifiable par l'humain sur son poste si le démon Docker manque, comme `l1-demo`).
  6. `make -f Makefile verify; echo rc=$?` : `rc=0` (dont `workflowcheck` et les règles `loopsrc` sur `internal/loops/l2`).
- **Sécurité** : oui (multi-tenant, confirmation, réviseur, T2, T3, T12, T18, T98, T107, T110).

### M2-T06 `harden-batch` : M1-T07 reportée

- **Objectif** : solder avant la clôture de M2 les obligations moyennes de M0 reportées par l'humain ; placée avant T07 pour que la nouvelle suite soit chargée par le chargeur durci.
- **Dépend de** : aucune.
- **Livrables** : (bj) `internal/archtest` : hors `cmd/`, toute déclaration de type (alias ou définition) dont le membre droit est un type `go.temporal.io/...` refusée ; (bv) `shellComment` et `joinShellLines` : « dans le doute, ne pas joindre » (`$'`, accent grave, `$(` avec guillemets) ; (v) et (by) motifs `watch` au jeu fermé `[a-z0-9._/*-]` ; (s) `\` refusée hors guillemets doubles dans `contains` et `equals` ; (t) lignes de 160 runes au plus, deux espaces consécutives refusées dans `contains` et `equals` ; (w) baseline chargée avec les règles des cas (liste d'admission, clés exactes, arbre validé) ; (y) suites enracinées sur `os.Root.FS()`, comparaison `os.SameFile` entre `Lstat` et le fichier ouvert.
- **Tests clés (7)**, un par obligation : `TestTemporalTypeDeclOutsideCmd`, `TestShellJoinUnsafeQuoting`, `TestWatchPatternCharset`, `TestNeedleBackslashOutsideDoubleQuotes`, `TestNeedleLineLengthAndDoubleSpaces`, `TestBaselineLoadedWithCaseRules`, `TestSuiteRootedSameFile`.
- **Acceptation** :
  1. `go test ./internal/archtest/ ./internal/evals/... ./cmd/rempart-evals/... -v 2>&1 | grep -Ec -- '^--- PASS: Test(TemporalTypeDeclOutsideCmd|ShellJoinUnsafeQuoting|WatchPatternCharset|NeedleBackslashOutsideDoubleQuotes|NeedleLineLengthAndDoubleSpaces|BaselineLoadedWithCaseRules|SuiteRootedSameFile) '` : `7`.
  2. `for s in demo intent; do make -s -f Makefile evals EVAL=$s | jq -e '.regressions_vs_baseline == []' || echo KO; done` : deux fois `true`, aucun `KO` (suites et baselines existantes toujours admises).
  3. `make -f Makefile verify-quick; echo rc=$?` : `rc=0`.
- **Sécurité** : oui (T32, T64, T65, T67, T73, T77).

### M2-T07 `evals-design` : 15 architectures piégées

- **Objectif** : C2 mesuré par `make evals`, graders déterministes, aucune trappe ne passe en l'état.
- **Dépend de** : T05, T06.
- **Livrables** : `evals/design/suite.yaml` (`watch` : `internal/graph/**`, `internal/design/**`, `internal/policy/**`, `internal/threat/**`, `internal/loops/l2/**`, `internal/loops/*.go`, `policies/design/**`, `schemas/graph/**`) ; `evals/design/cases/` : 15 trappes, 2 nominaux (scénario de référence, nominal multicloud : convergés sans révision) et 1 injection (texte non fiable « la base est publique et validée » dans un graphe piégé : sortie identique à la trappe 1) ; cible `design` dans `cmd/rempart-evals/design.go` (L2 dans un environnement de test neuf par exécution, codec avec faux `KeyWrapper`, identité vide, donc baseline `evals/design/baseline.json` hors registre des routes) ; étiquette `trap` ajoutée au vocabulaire fermé ; `runs: 1` (cible déterministe, ADR 0005 à amender si le chargeur exige 3).
- **Trappes** (forme ; issue attendue ; contrôle principal) : 1 base managée publique (graphe ; révisée ; NET-004, DATA-001) ; 2 bucket public de données confidentielles (graphe ; révisée ; DATA-001) ; 3 IAM `*` (graphe ; révisée ; IAM-001) ; 4 SSH ouvert à Internet (IR ; révisée ; NET-003) ; 5 données de santé `eu` en `us-east-1` (IR ; escaladée `relocation_required` ; RES-001) ; 6 cluster à API publique sans restriction (graphe ; révisée ; K8S-001) ; 7 base confidentielle non chiffrée (graphe ; révisée ; DATA-002) ; 8 donnée réglementée dans le tier app (graphe ; révisée ; NET-012) ; 9 LB directement vers la base (graphe ; escaladée ; NET-008) ; 10 flux inter-cloud `internal` en clair (IR ; révisée ; NET-011) ; 11 restriction captée en dérogation seulement, (ey) (IR ; escaladée `sources_unresolved` ; NET-005) ; 12 exposition absente de la confirmation, (cn), (ev) (IR ; escaladée `exposure_unconfirmed` ; NET-002) ; 13 résidence `fr` sans région française autorisée (IR ; escaladée `incompatible_constraints` ; RES-002, RES-003) ; 14 compte de service `cluster-admin` à clé statique (graphe ; révisée ; K8S-030, IAM-005) ; 15 sous-réseaux qui se chevauchent (graphe ; escaladée `cidr_conflict` ; `CIDR_OVERLAP`).
- **Graders** (par cas) : `status` exact ; `must_include` `$.initial_findings[*].code` contient le contrôle principal (la trappe est vue pour la bonne raison) ; révisée : `must_include` `$.applied[*].control_id` le contient ; escaladée : `must_include` `$.explanation[*].code` contient le code attendu et `must_not_include` `$.graph`.
- **Tests clés (4)** : `TestDesignSuiteComposition` (15 trappes, chacune rejetée par le vérificateur sur son candidat initial exactement pour son contrôle principal, chacune de la forme « révisée avec ce contrôle appliqué » ou « escaladée avec code »), `TestDesignTargetRunsCase`, `TestDesignInputClosed` (entrée fermée : `ir` ou `graph`, `confirmation`, 64 Kio), `TestDesignTrapsDetectedForTheirReason` (pack vidé par recouvrement en test : les trappes révisées échouent).
- **Étape humaine H3-design** : `make update-baseline EVAL=design`, commit de `evals/design/baseline.json`.
- **Acceptation** :
  1. C2 : `make -s -f Makefile evals EVAL=design | jq -e '.cases == 18 and .success_rate == 1 and .injection_resistance == 1 and .regressions_vs_baseline == []'` : `true`.
  2. `grep -lE '^tags:.*[[ ,]trap[],]' evals/design/cases/*.yaml | wc -l` : `15`.
  3. `go test ./cmd/rempart-evals/... -v 2>&1 | grep -Ec -- '^--- PASS: Test(DesignSuiteComposition|DesignTargetRunsCase|DesignInputClosed|DesignTrapsDetectedForTheirReason) '` : `4`.
  4. `git log --format=%ae -- evals/design/baseline.json | sort -u` : la seule adresse de l'humain.
  5. `make -f Makefile verify; echo rc=$?` : `rc=0`.
- **Sécurité** : non par tâche (revue de clôture ; T88 atténuée par la composition et la baseline humaine).

---

## 6. Étapes humaines

| Étape | Quand | Action |
|---|---|---|
| H0-M2.1 | avant T01 | Valider le découpage, répondre à Q1 à Q8 (section 9). |
| H0-M2.2 | avant T01 | Poser `m1-done` sur `810c15e` et `m2-start` sur la tête ; accepter l'amendement A2 de l'ADR 0006 (T01 l'étend) ; ADR 0007 et 0008 A1 restent à accepter (non bloquants pour M2). |
| H0-M2.3 | début de T02, T03, T05 | Accepter respectivement les ADR 0010, 0011, 0012 avant la phase tests. |
| H-CODEOWNERS | fin de T03 | Appliquer la proposition `CODEOWNERS` sur `/policies/` et `/schemas/` (pack de politiques, T6, T108). |
| H3-intent-bis | fin de T01 | `make update-baseline EVAL=intent` (31 cas), commit. |
| H-demo | fin de T05 | Si la session n'a pas de démon Docker : `make l2-demo` sur le poste de l'humain (critère 5 de T05). |
| H3-design | fin de T07 | `make update-baseline EVAL=design`, commit. |
| H-skills | avant la clôture | Relire `graph-schema.md` (T02) et toute autre modification de skill signalée. |
| H-real (M1) | hors M2 | Calibration et mesure réelles de la suite `intent` après achat de crédit ; le cas (ev) y est mesuré. |

## 7. ADR à écrire

| ADR | Quand | Options et recommandation |
|---|---|---|
| **0010 « Graphe de conception étendu, atteignabilité et STRIDE versionné »** | début de T02 | Atteignabilité : (a) fermeture de sauts allow moins deny, deny prioritaire, recommandée ; (b) énumération de chemins sur règles ordonnées (premier qui correspond), monotonie non garantie ; (c) calcul en Rego, contraire à la règle 2 du skill. Schéma : (a) v1 étendu en place, recommandé tant que rien n'est persisté ; (b) v2. Permissions abstraites (`read`, `write`, `admin`, `*`), jamais d'action IAM concrète avant L3. STRIDE dérivé des contrôles, révision par empreinte des `Facts`, delta (D8 à D10). |
| **0011 « Moteur de politiques OPA embarqué »** | début de T03 | (a) bibliothèque Go épinglée, capacités en liste blanche, CLI par `go tool opa`, recommandée ; (b) binaire `opa eval` lancé par le worker (exécution de commande T8, version hors `go.mod`, coût de processus) ; (c) Rego compilé en Wasm et moteur Wasm (deuxième dépendance lourde, builtins partiels). Mesure du nombre de modules avant et après, `govulncheck`, règle `opa-confined`, table de juridiction datée et sourcée (D11, D12). |
| **0012 « Boucle L2 : réviseur déterministe, confirmation, dérogations »** | début de T05 | Proposeur (Q1) ; deux formes d'entrée (D2) ; confirmation déclarée liée à l'empreinte et aux expositions (Q5) ; findings moyens en `advisories` ; dérogations jamais appliquées ; explication codée ; budget (D1 à D7, D14). |
| « Planification CIDR stable et incrémentale » (plan M1-design-cidr) | reportée (Q6) | Avant le premier plan CIDR stocké. M2 ne stocke rien ; le réviseur ne réalloue pas (escalade). |
| Amendement de l'ADR 0003 | avec Q6 | Tests Store et RLS déplacés de M2 vers la première table. |
| Amendement de l'ADR 0005 | T07, si besoin | `runs: 1` pour une cible déterministe ; identité vide et `baseline.json`. |

## 8. Obligations héritées : place de chacune

### 8.1 Soldées dans M2

| Obligation | Gravité | Tâche | Note |
|---|---|---|---|
| (er) confinement contournable par contrainte de build (T103) | moyen | T01 | avant l'arrivée d'OPA (T03) |
| (es) texte du modèle dans `remaining[].resource` (T104) et (ck) grammaire de `field` | moyen, bas | T01 | (ck) soldée avec (es) |
| (ez) séparateurs non ASCII et notation désarmée | bas | T01 | sert aussi (ey) en L2 |
| (ev) négation d'exposition | moyen | T01 (cas `evals/intent`), T05 (récapitulatif), T07 (trappe 12) | |
| (ex) `golang.org/x/net` v0.62.0 | bas | T01 | |
| (dx) `fresh()` et transport injecté cloné | bas | T01 | |
| (ey) restriction captée en dérogation seulement | moyen | T03 (NET-005), T05 (fait et test), T07 (trappe 11) | datée « avant M2 », mais c'est un comportement de L2 : soldée avec L2 |
| (cn) tout workload exposé présenté à la confirmation | moyen | T05 (NET-002, récapitulatif), T07 (trappe 12) | |
| (bj), (bv), (v), (by), (s), (t), (w), (y) (M1-T07) | moyen | T06 | avant la clôture de M2, décision humaine |
| Tenant du contexte égal à celui de l'IR (plan M1-design-cidr) | moyen | T05 (`TestL2TenantMismatchRefused`, frontière du worker) | reste exigible à la première API |
| (co) C1 et bidirectionnels non échappés | moyen | T05 (récapitulatif de confirmation) | `rempart design --json` aussi |
| (cp) motif de texte libre du schéma du graphe | bas | T02 | schéma modifié de toute façon |
| (cr) lecteur de fichier qui bloque sur un FIFO | bas | T05 (nouveaux lecteurs) | `readIR` existant repris au passage |
| ADR 0006 A2.3 (sens de `allowed_sources` vide) | bas | T02 (schéma du graphe) | le schéma intent attend sa v2 (Q7) |
| T24 `Limits` du calcul de graphe | moyen | T02 (`TestReachLimits`) | |

### 8.2 Redatation proposée à l'humain (Q8)

| Obligation | Gravité | Proposition | Justification |
|---|---|---|---|
| (ch) partielle, (cj) provenance de L1 | moyen, bas | avec la v2 du schéma du brouillon (Q7), au plus tard M4 avant toute donnée client | même code et mêmes evals ; aucun critère de M2 |
| (cq) motif de `region`, `maxLength` de `justification` | bas | v2 du schéma intent | changement de schéma, nouvelle baseline |
| (cd) racine de `fakeClient` | bas | M4 (worker de production) | chemin de développement |
| (ce), (cg), (bq), (br) CI | bas | lot CI avant M3 (création de `scripts/sandbox.sh`, déjà daté) | `.github/` sous CODEOWNERS, changement par l'humain |
| (cf) options `-c` de git dans `rempart-evals` | bas | même lot avant M3 | faible coût, hors périmètre de L2 |
| Tests Store et RLS de l'ADR 0003 | moyen | première table PostgreSQL (Q6) | aucune table en M2 |
| ADR « planification CIDR stable et incrémentale » | | avant le premier plan stocké (Q6) | |
| v2 du schéma du brouillon (ADR 0008 A1.2, ADR 0006 A2.3) | | Q7 : avant la première calibration d'une route Claude (M5, Bedrock UE) | |
| (ef) contexte du tenant fourni par l'entrée | moyen | inchangé (avant M4) ; L2 reprend la forme de L1, les contraintes viennent de l'IR confirmée | |

---

## 9. Questions ouvertes (une recommandation par question)

- **Q1. Proposeur de L2.** (A) déterministe : catalogue fermé de remédiations qui ne font que restreindre ; (B) LLM en périphérie qui propose des révisions en schéma strict, vérifiées par le même code ; (C) mélange : A d'abord, B en seconde stratégie après stagnation. **Recommandation : A en M2**, C plus tard. Aucune décision de sécurité ne bouge (le vérificateur décide dans les trois cas), mais A n'ajoute ni prompt, ni route à calibrer (le crédit OpenRouter manque encore), ni sortie de données d'architecture vers un fournisseur (T7), et rend les evals de conception déterministes, donc sans baseline par modèle. Prix : les trappes sans correctif sûr sont escaladées plutôt que corrigées, ce que C2 admet.
- **Q2. Évaluation OPA.** (A) bibliothèque `opa/v1/rego` embarquée ; (B) binaire `opa eval` ; (C) Wasm. **Recommandation : A**, capacités en liste blanche (aucune entrée-sortie, aucun non-déterminisme), confinée à un adaptateur par règle archtest, pack embarqué dans le binaire, CLI par `go tool opa` à la même version (parité `opa test` et moteur, aucun changement de CI). Coût : dépendance lourde (T6) mesurée dans l'ADR 0011, `govulncheck` à chaque montée. B ajoute une exécution de commande dans le worker (T8) et une version hors `go.mod`.
- **Q3. Atteignabilité, monotonie, STRIDE.** **Recommandation** : D8 à D10. Sauts allow moins deny (deny prioritaire), sources Internet en attribut, parcours borné ; C3 par `TestDenyNeverAddsPath` (rapid, 1 000 tirages) plus la propriété « retirer une allow » ; invariant L2 sur le saut direct seulement, les chemins transitifs devenant des menaces STRIDE et des hypothèses pour L6 ; graphe v1 étendu en place ; STRIDE dérivé des contrôles, delta `{from, to, added, removed, changed}` à ordre total, schéma `schemas/threat/v1.json`.
- **Q4. Evals de conception.** **Recommandation** : suite `evals/design`, cible nouvelle `design`, 15 trappes plus 2 nominaux et 1 injection, entrées en IR quand l'IR sait exprimer le piège, en graphe candidat sinon (IAM `*`, API de cluster) ; graders déterministes sur la raison (contrôle vu, correctif appliqué ou code d'escalade) ; `runs: 1` ; baseline `evals/design/baseline.json` écrite et commitée par l'humain (H3-design), hors registre des routes.
- **Q5. Confirmation humaine à l'entrée de L2.** (A) objet de confirmation déclaré, lié à l'empreinte du sujet et à la liste complète des expositions, refus avant la boucle ; (B) signal Temporal et `AwaitApprovals` (vérificateur d'approbation encore factice, T12, T56) ; (C) pas de confirmation en M2, toute exposition escaladée. **Recommandation : A**, authentification reportée à M4 avec les approbations signées (T107 consignée).
- **Q6. Persistance en M2.** **Recommandation : aucune table** : graphe, menaces et delta sérialisés en JSON, révision par empreinte ; tests Store et RLS de l'ADR 0003 et ADR CIDR redatés à la première table et au premier plan stocké.
- **Q7. Version 2 du schéma du brouillon** (ADR 0008 A1.2 la classait en M2). **Recommandation : hors M2**, redatée avant la première calibration d'une route Claude (M5, Bedrock UE, ADR 0002) : aucun critère de M2 n'en dépend, elle impose prompt, hash et baselines nouveaux (coût humain), et la route OpenAI marche avec la v1. Si l'humain la veut en M2 : tâche facultative M2-T08 `intent-draft-v2` (16 paramètres nullables ou unions au plus, sens de `allowed_sources` vide écrit dans le schéma, (cq), (ch), (cj)) après T07.
- **Q8. Obligations « avant la clôture de M1 » restées ouvertes.** **Recommandation** : accepter la redatation de la section 8.2 ; (ck), (cn), (co), (cp), (cr) sont soldées dans M2 (section 8.1).

## 10. Menaces nouvelles proposées (à faire valider par `security-reviewer`)

| # | Menace | Cat. | Atténuation | Vérification |
|---|---|---|---|---|
| T107 | Confirmation de L2 forgée ou rejouée : identité déclarée, objet produit par quiconque démarre le workflow (T18) | S, E | Liée à l'empreinte du sujet et à la liste complète des expositions ; M4 : confirmation signée (T12, T56) | `TestL2RefusesUnconfirmed` ; test signé à créer en M4 |
| T108 | Pack de politiques affaibli : règle retirée, sévérité abaissée, métadonnée manquante, paquet non chargé, test `ko` vidé | T | Pack embarqué, CODEOWNERS sur `/policies/`, métadonnées vérifiées en échec fermé, `ok` et `ko` par contrôle, invariant Go indépendant du pack | `TestPolicyMetadataComplete`, `TestEveryControlHasOkAndKo`, `TestL2CoreInvariantWithoutPack` |
| T109 | OPA vecteur d'entrée-sortie ou de non-déterminisme (`http.send`, `net.*`, `opa.runtime` qui lit l'environnement, `time.now_ns`, `rand`) | I, T | Capacités en liste blanche, `print` désactivé, entrée bornée, délai par évaluation | `TestEngineCapabilitiesDenyIO`, `TestEngineDeterministic` |
| T110 | Réviseur qui élargit : correctif qui ouvre un flux, une source ou une permission, ou déplace hors juridiction | E, T | Catalogue fermé, propriété « restreindre seulement », vérificateur rejoué après chaque révision | `TestRevisionNeverWidens` |
| T111 | Texte non fiable du graphe (justification, notes, identifiants) qui influe sur une décision de L2 | T | Entrée des politiques = `Facts` sans `FreeText`, identifiants à grammaire fermée, explications par gabarits | `TestEngineInputHasNoFreeText`, `TestL2FreeTextHasNoEffect`, cas d'injection de `evals/design` |
| T112 | Graphe candidat hostile (chemin d'import) qui épuise le worker par l'atteignabilité ou l'évaluation Rego | D | `reach.Limits`, `ErrGraphTooLarge`, 64 Kio par candidat, 100 findings au plus, délai d'activité | `TestReachLimits`, `TestDesignInputClosed` |
| T113 | Delta de menace non reproductible ou altéré, preuve contestable | T, R | Révision par empreinte des `Facts` triés, ordre total, schéma et décodage stricts ; signature avec le dossier de preuves (M4) | `TestGraphRevisionStable`, `TestDeltaSerializationGolden`, `TestDeltaStrictDecode` |
| T114 | Table de juridiction fausse ou incomplète : donnée réglementée placée hors UE sans finding | I | Table codée, datée, sourcée ; région inconnue en échec fermé pour une donnée sensible | `TestJurisdictionTableClosed`, RES-005 |
| T115 | Graphe candidat accepté sans IR : architecture qui n'est pas l'intention confirmée | T | Sortie marquée `subject: graph`, confirmation liée à l'empreinte du graphe ; L3 (M3) n'acceptera qu'un sujet `ir`, sauf décision par ADR | `TestDesignInputClosed` ; garde de L3 à créer en M3 |

## 11. Risques

| # | Risque | Parade |
|---|---|---|
| R1 | Poids de la dépendance OPA (modules, vulnérabilités, version de Go exigée, temps de build) | Mesure dans l'ADR 0011 ; `govulncheck` ; repli B de Q2 si l'arbre est inacceptable |
| R2 | Graphe candidat au-delà de 64 Kio (`MaxCandidateBytes`) | Escalade `payload_too_large` ; taille du scénario de référence consignée en T05 ; graphe par référence avec le `Store` (première table) |
| R3 | 45 règles et leurs cas : coût | Règles mécaniques sur faits précalculés, aides `ok` et `ko` ; garde de taille T03a et T03b |
| R4 | L'extension du graphe change les sorties de M1 (`make l1-demo`, golden du scénario de référence) | Golden mis à jour en phase tests de T02 ; critère 3 de M1 rejoué à la clôture |
| R5 | Faux positifs sur le scénario de référence : la chaîne L1 vers L2 n'aboutit plus | `TestL2ReferenceConvergesUnchanged`, deux cas nominaux dans `evals/design` |
| R6 | Le réviseur déterministe corrige peu | C2 admet l'escalade expliquée ; Q1 option C plus tard |
| R7 | Faits de juridiction faux (régions des quatre clouds) | Vérification à la source au début de T03, date et source par ligne (ADR 0011), RES-005 en échec fermé |
| R8 | Grammaire stricte du `Makefile` (`go tool opa`, `l2-demo`) | Prévu en T03 et T05, précédent de `l1-demo`, CODEOWNERS |
| R9 | Rejeu Temporal de L2 sans historique de référence (comme L1) | `GetVersion` dès le premier changement de séquence ; historique de référence de L2 à enregistrer s'il est peu coûteux, sinon écart consigné |
| R10 | Étapes humaines de baseline (H3-intent-bis, H3-design) qui bloquent `make verify` | Signalées en fin de T01 et T07 ; aucune autre tâche n'en dépend |
| R11 | Chargeur durci (T06) qui refuse un cas ou une baseline existants | Critère 2 de T06 ; correction des fichiers en phase tests, baseline par l'humain si sa forme change |
