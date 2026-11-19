# 0012. Boucle L2 : réviseur déterministe, confirmation, dérogations

- Statut : proposé (à accepter par l'humain avant la phase tests de M2-T05, étape H0-M2.3)
- Date : 2026-11-19
- Jalon : M2. M2-T05 `l2-loop` met en oeuvre D1 à D8 ; M2-T07 `evals-design` consomme D2, D3 et D5 (graders sur `status`, `initial_findings`, `applied`, `explanation`).
- Base : M2-T04 livrée ; obligations (fe) à (fi) et (fm) soldées (`920e3b8`) : `DesignInput.Check()` revalide l'entrée dans `Evaluate` (recalcul par `NewDesignInput`, schéma à l'exécution), `NewDesignInput` refuse une atteignabilité qui nomme un nœud hors du graphe, `Derived.WorldSources` est calculé en Go, une règle `deny` n'est admise que sous la forme `deny contains <var>` à sortie `{control_id: <m>.custom.control_id, resource}`.
- Sources : `docs/plans/M2-overview.md` (D1 à D7, D14, section 3.1, fiche L2, fiche M2-T05, section 7, Q1, Q5, Q6, T107 à T115, R2, R5, R6, R9) ; ADR 0010 (D2 à D4, D8 à D12) et 0011 (D3 à D5, D8) ; `docs/01-LOOPS.md` (L2) ; `docs/02-THREAT-MODEL.md` (T2, T3, T12, T16, T18, T24, T102, T119, T120) ; `docs/STATUS.md` (M2-T02 à M2-T04 ; (cn), (co), (cr), (ev), (ey), (fb)) ; skills `loop-engineering`, `policy-as-code`, `security-graph-attack-paths` ; code : `internal/loops/{runloop.go,spec.go,versions.go,l1}`, `internal/design/{build.go,cidr}`, `internal/graph/reach`, `internal/policy`, `internal/threat`, `internal/intent/domain/sources.go`, `cmd/rempart/{design.go,threat.go}`, `cmd/rempart-worker/{l1.go,config.go}`.

## Contexte

Tous les calculs de L2 existent sauf la boucle : `design.Build` (IR vers graphe, défauts sûrs), `reach` (monotone, `SubsetOf` exact), le moteur OPA et ses 45 contrôles (`policy.Evaluator`), `threat.Analyze` et `Diff`. Manquent le proposeur, la confirmation humaine, le vérificateur composé, l'explication d'une escalade, le workflow et son enregistrement.

Faits du code qui contraignent : `RunLoop` refuse un `OK` accompagné d'un finding moyen ou plus et calcule l'empreinte de stagnation sur ces findings ; `ProposeResponse` ne porte que `Candidate` et `Tokens` ; le premier `Propose` reçoit `Best` vide, le candidat initial doit donc venir de la charge ; charge et candidat sont bornés à 64 Kio et un dépassement de la charge est une erreur de `RunLoop`, pas une escalade ; `Budget.MaxTokens` vaut au moins 1. Le lecteur d'adresses de L1 (`readAddresses`, après (ez)) n'est pas exporté. `stride-v1` ne cite pas `L2-INTERNET-TO-SENSITIVE`, qui n'existe pas encore (STRIDE-I-004 sans contrôle, écart 2 de M2-T04).

Difficile à inverser : forme de la confirmation (contrat avec l'humain, futur objet signé de M4) ; codes d'escalade (graders et baseline humaine de `evals/design`) ; forme de la sortie (entrée de L3) ; nom et séquence du workflow (rejeu, T16). Contraintes : aucune décision de sécurité par un LLM et aucun appel de modèle dans L2 en M2 (Q1) ; aucune table (Q6) ; texte libre non fiable (T2, T111) ; tenant du worker (T3) ; calcul borné (T24, T112).

## Options envisagées

1. **Proposeur (Q1).** (1a) Catalogue fermé de remédiations qui ne font que restreindre, en Go (retenue). (1b) LLM en périphérie en schéma strict, vérifié par le même code : prompt et route à calibrer, architecture envoyée à un fournisseur (T7), evals non déterministes. (1c) (1a) puis (1b) après stagnation : plus tard, par amendement, derrière le même vérificateur.
2. **Formes d'entrée (D2).** (2a) IR ou graphe candidat `source: design`, exactement un (retenue). (2b) IR seule : trappes IAM `*`, API de cluster, compte de service inexprimables. (2c) Graphe seul : l'humain confirmerait un objet qu'il n'a pas écrit.
3. **Confirmation (Q5).** (3a) Objet déclaré lié à l'empreinte du sujet et à la liste exhaustive de ses expositions, vérifié avant la boucle (retenue). (3b) Signal Temporal et `AwaitApprovals` : vérificateur d'approbation encore factice (T12, T56), aucune authenticité gagnée. (3c) Aucune confirmation, toute exposition escaladée : le scénario de référence ne converge plus (R5).
4. **Liste des expositions.** (4a) Arêtes `EXPOSES` seules : manquent `public_access`, `api_public`, `public_ip` et `CAN_REACH` depuis Internet (une API de cluster restreinte ne lève que K8S-004, `advisory`). (4b) Projection des sauts depuis `internet` de `reach` (retenue) : une seule sémantique, exhaustive par construction (ADR 0010 D2), inclusion jugée par `SubsetOf`.
5. **Exposition du sujet absente de la confirmation.** (5a) Refus avant la boucle (D3 du plan) : NET-002 ne se déclencherait jamais et la trappe 12 (`exposure_unconfirmed`) serait impossible. (5b) Fait non confirmé, NET-002 et invariant Go, escalade expliquée (retenue) ; le refus reste pour une confirmation qui ne porte pas sur ce sujet.
6. **Invariant du cœur et STRIDE-I-004.** (6a) Invariant Go hors catalogue, I-004 sans contrôle, toujours `open` (retenue). (6b) `stride-v2` rattachant l'invariant à I-004 : l'invariant juge le saut direct, I-004 le chemin de plus d'un saut ; il n'aurait jamais de finding sur ces cibles et I-004 deviendrait `mitigated` sans atténuation (risque 7 de l'ADR 0010). (6c) `stride-v2` le rattachant à I-002 et T-005 : sans gain (NET-001 y est cité, un contrôle absent du pack rouvre déjà la menace), version et golden nouveaux.
7. **Lieu des refus d'entrée.** (7a) Code du workflow, sans activité : il ignore le tenant du worker, importerait `confirm` et `design`, et tout changement du contrôle toucherait le code rejoué (T16). (7b) Première activité `l2.Prepare`, déterministe et sans effet, erreur non rejouable (retenue) : aucune activité de boucle (`Propose`, `Verify`, `Finalize`) n'est appelée.

## Décision

### D1. Proposeur et réviseur déterministes (1a)
- Stratégie unique `catalog`. Itération 1 : `l2.Propose` rend le candidat initial de la charge. Ensuite : `revise.Revise(Best, Findings, Controls)` ; les findings sont ceux du dernier candidat (contrat de `RunLoop`) et, appliqués à `Best`, ne peuvent que restreindre ; le vérificateur rejuge tout.
- Remédiation lue dans `Controls()` du pack ou dans `verify.CoreControls()`, jamais dans `Message` ; ressource absente ou de type non prévu : rien. Table fermée en M2 :

| Remédiation | Ressource | Effet |
|---|---|---|
| `make_private` | `DataStore`, `Compute`, `K8sCluster` | `public_access`, `public_ip`, `api_public` à faux (`api_allowed_sources` retirées avec `api_public`) |
| `remove_exposure` | source d'`EXPOSES` ; `DataStore` | `EXPOSES` de la ressource retirées ; équilibreur : `public` faux, écouteurs vides ; `public_ip` ou `public_access` à faux |
| `https_only` | `EXPOSES` ou son équilibreur | `http` devient `https` sur le même port (n-uplet `tcp` inchangé ; changer de port ouvrirait un n-uplet) |
| `encrypt_transit` | `CAN_REACH` | `via` à `vpn_site_to_site` (attribut hors `reach`) |
| `move_to_data_tier` | hôte de donnée | `MEMBER_OF` vers le sous-réseau `data` du même VPC s'il existe, sinon rien |
| `enable_encryption` | `DataStore` | `encrypted` vrai |
| `least_privilege` | `HAS_PERMISSION`, ou `Identity` | vers un `Account` ou un `DataStore` ni hébergé ni atteint : arête retirée ; sinon `actions` = fermeture (ADR 0010 D8) inter {`read`, `write`} |
| `use_workload_identity` | `Identity`, `K8sCluster` | `credential` à `workload_identity` ; `workload_identity` vrai |
| `enable_audit_log`, `enable_secrets_encryption`, `enable_admission`, `default_deny_netpol` | `K8sCluster` | booléen correspondant à vrai |
| `dedicated_identity`, `escalate`, `advisory` | | jamais appliquées en M2 |

- `dedicated_identity` n'est pas appliquée en M2 : créer des identités ajoute des nœuds dont il faudrait prouver, workload par workload, le non-élargissement ; aucune trappe ne l'exige ; IAM-003 mène à l'escalade.
- Jamais fait par le réviseur (escalade) : relocalisation de région ou de cloud, allocation CIDR, changement de classification, de résidence ou de port, ajout de nœud ou d'arête. Un correctif impossible n'applique rien : l'empreinte se répète et `RunLoop` escalade (une seule stratégie : au deuxième passage identique, raison `strategies_exhausted`).
- **Non-élargissement (T110)**, `TestRevisionNeverWidens` (rapid, 1 000 tirages ; graphes valides tirés, findings de tout contrôle sur toute ressource) : (1) `reach(g').SubsetOf(reach(g))` (sauts, ports, sources, chemins) ; (2) aucune `HAS_PERMISSION` ni `RUNS_AS` ajoutée, fermeture des actions jamais agrandie ; (3) drapeaux publics (`public_access`, `public_ip`, `api_public`, `public`) jamais de faux à vrai, aucune liste de sources vidée ni modifiée hors retrait de l'arête ; (4) `encrypted`, `audit_log`, `secrets_encryption`, `network_policy_default_deny`, `admission_policy`, `workload_identity` jamais de vrai à faux, `credential` jamais vers `static_key` ; (5) `cloud`, `region`, `cidr`, classification, résidence, réglementation inchangés, aucun nœud ajouté ; (6) `g'` valide (schéma, `domain.Validate`) et une entrée `Applied` seulement si le graphe a changé pour ce couple (contrôle, ressource).

### D2. Deux formes d'entrée, refus et escalades avant la boucle (2a, 7b)
- `Input{IR, Graph, Confirmation}`, sans tenant. `l2.Prepare` refuse par une erreur non rejouable de type `InvalidL2Input` (message fixe, aucune donnée citée) ; le workflow se termine en erreur, aucune activité de boucle n'est appelée : zéro ou deux formes ; tenant de l'IR ou du graphe différent de celui du worker (`TestL2TenantMismatchRefused`) ; IR hors `ValidateIR` ; graphe hors schéma, hors `domain.Validate` ou `source` autre que `design` ; confirmation refusée par `confirm.Check` (D3).
- Escalade dans `Prepare`, sortie `escalated` sans graphe : `Build` refusé (`cidr_conflict` pour une erreur du planificateur, `manual_fix_required` sinon, ressource `ir`) ; charge au-delà de `MaxPayloadBytes`, candidat au-delà de `MaxCandidateBytes` ou `reach.ErrGraphTooLarge` : `payload_too_large` (R2, ADR 0010 D4). Une révision ne fait que restreindre : ces bornes valent ensuite.
- Charge construite par `Prepare` seule et décodée strictement par chaque activité : sujet, candidat initial, clés confirmées, contexte de D7. Candidat : enveloppe `{graph, applied}` (`applied` doit traverser les itérations) ; `Verify` ne lit que `graph`.
- Sortie marquée `subject` (`ir` ou `graph`) ; L3 n'acceptera qu'un sujet `ir` sauf ADR (T115).

### D3. Confirmation déclarée (3a, 4b, 5b)
- **Empreinte** : SHA-256 hexadécimal de la netstring du type de sujet suivie de l'encodage `encoding/json` de la valeur décodée (ordre des structures, aucune carte). Elle couvre tout le document, texte libre et dérogations compris : un octet changé après confirmation fait refuser. Ni révision des `Facts` (ADR 0010 D10) ni `content_sha256`.
- **Expositions** : `ExposureKey{target, proto, ports, world, sources}`, projection d'un saut depuis `internet` du graphe du sujet (IR : `Build` aux options par défaut) ; `sources` vide si et seulement si `world` (« tout Internet »). Liste exhaustive par construction : `EXPOSES`, `public_access`, `api_public`, `public_ip`, `CAN_REACH` depuis Internet ((cn)) ; une exposition niée par l'utilisateur mais présente dans l'IR y figure ((ev)).
- `confirm.Check(d, c)` refuse (`ErrNotConfirmed`) si sujet ou empreinte diffèrent, si une clé confirmée n'est pas une clé du sujet (forgée, ports ou sources changés), si une clé est en double, si `confirmed_by` sort de `^[a-z0-9._@-]{1,64}$`. Il rend les clés du sujet non confirmées : un fait, pas un refus (5b).
- **Couverture**, à chaque vérification : tout saut depuis Internet du candidat doit être inclus, n-uplet par n-uplet, dans l'union des clés confirmées (`SubsetOf` restreint à ces sauts, invariant de D4). Les `EXPOSES` non couvertes du candidat forment `UnconfirmedExposures` (NET-002), recalculé par candidat.
- **Récapitulatif** : `rempart design --digest <ir.json>` écrit le JSON de `confirm.Digest` (sujet, empreinte, toutes les clés avec « tout Internet » pour `world`, dérogations, données sensibles avec hôtes et régions) ; `--superblock`, `--reserve`, `--growth` refusés avec `--digest` (L2 construit aux défauts). **(co)** : `confirm.Escape` écrit en `\uXXXX` toute rune `\p{Cc}`, `\p{Cf}` (bidirectionnels compris), U+2028 et U+2029, avant l'encodage, pour les dérogations du récapitulatif et le texte libre du récapitulatif textuel de `rempart design`.
- `confirmed_by` : déclaré, jamais authentifié ni lu par une décision, absent de la sortie (T107) ; signature en M4 (T12, T56).

### D4. Vérificateur `l2.Verify`, indépendant du proposeur
- Ordre, sur le candidat décodé strictement : schéma, `domain.Validate`, tenant égal à celui du worker ; `cidr.Check(design.PlanOf(facts))` (super-bloc 10.0.0.0/8, défaut de `Build`) ; `reach.FromGraph` et `Compute(DefaultLimits)` sur le candidat, jamais lus dans la charge ; invariants du cœur ; `policy.NewDesignInput` puis `Evaluate`, qui rappelle `DesignInput.Check()`.
- **Invariants du cœur** (`internal/design/verify`, source `l2:core`, indépendants du pack, T108) : `L2-INTERNET-TO-SENSITIVE` (critique, `make_private`) pour un saut depuis `internet` vers un `DataStore` de classification autre que `public` et `internal` (absente : sensible) ou vers un hôte (`STORES`) d'un tel `DataStore` ; `L2-EXPOSURE-UNCONFIRMED` (haute, `escalate`) pour un saut non couvert (D3). Les chemins de plus d'un saut restent des hypothèses (STRIDE-I-004, L6).
- `TestL2CoreInvariantWithoutPack` : évaluateur vide (aucun contrôle, aucun finding) ; une base exposée a `L2-INTERNET-TO-SENSITIVE` dans `initial_findings` et aucune sortie ne contient ce saut.
- Rendu à `RunLoop` : critiques et hauts seulement, les 100 plus graves (`OK` si aucun) ; moyens et bas jamais bloquants, en `advisories` (D5). Toute erreur (évaluation, délai, décodage, borne) est non rejouable et mène à `evaluation_failed`, jamais à une liste vide.
- **Dérogations jamais appliquées** : aucune activité ne lit `explicit_overrides` pour relâcher quoi que ce soit. Seule lecture : `intentdomain.CitesAddress(statement)` (lecteur de L1 après (ez), exporté), qui ne peut qu'ajouter un fait bloquant. **(ey)** : si une dérogation cite une adresse, toute `EXPOSES` du candidat présente dans `Derived.WorldSources` entre dans `SourcesUnresolved` (NET-005, `sources_unresolved`) ; un faux positif ((fb)) coûte une escalade, jamais un élargissement.

### D5. Sortie de la boucle
- `Output{status, reason, subject, graph, applied, initial_findings, advisories, threats, threat_delta, explanation, loop}` ; `loop.best` toujours vidé ; `graph`, `threats`, `threat_delta` seulement si `converged`, `explanation` seulement si `escalated` ; aucune liste `null`.
- `l2.Finalize` rejoue le vérificateur (déterministe) sur le candidat initial (`initial_findings`, toutes gravités ; modèle initial) et, si convergé, sur le candidat final : finding critique ou haut, refus (jamais un graphe non vérifié) ; `advisories` = ses moyens et bas ; `threats` = `Analyze(final)` ; `threat_delta` = `Diff(initial, final)`. `Pack` : empreinte du moteur, contrôles du pack, codes du cœur et `CIDR_*`.
- **STRIDE-I-004** (6a) : `stride-v1` inchangé, I-004 sans contrôle, toujours `open` ; aucune entrée ne cite un code du cœur, le modèle ne dépend que du pack. Un contrôle de chemin transitif viendra avec L6 (`stride-v2`).
- **Escalade sans graphe** (analogue de la règle T98 de L1) : ni `graph`, ni `best`, ni `threats` (`TestL2EscalationHasNoGraph` cherche ces clés dans la sortie sérialisée).
- **Explication codée** : une entrée par finding restant critique ou haut (doublons (code, ressource) retirés, 20 premiers par gravité), `{code, control_id, resource, text}`. `text` : gabarit français fixe par code, paramétré seulement par `control_id` et `resource` vérifiés par grammaire (motif du pack ou code du cœur ; identifiant du schéma ou nom de réseau `[a-z0-9-]+`), sinon libellé fixe ; jamais `Message`, texte libre ni modèle. Codes fermés :

| Code | Cause |
|---|---|
| `exposure_unconfirmed` | NET-002, `L2-EXPOSURE-UNCONFIRMED` |
| `sources_unresolved` | NET-005 |
| `cidr_conflict` | `CIDR_*` ; erreur du planificateur dans `Build` |
| `relocation_required` | RES-001, 002, 005, 006 si une région permise satisfait la zone exigée ; RES-003, RES-004 |
| `incompatible_constraints` | RES-001, 002, 005, 006 si aucune région permise ne la satisfait |
| `manual_fix_required` | tout autre finding restant (remédiation `escalate` ou correctif sans effet) ; `Build` refusé |
| `payload_too_large` | bornes de D2 |
| `evaluation_failed` | activité en échec ou réponse invalide, sans finding restant |

- Faisabilité (Go) : zone exigée `fr` si une donnée de l'hôte a la résidence `fr`, `eu` si `eu` ou réglementée ; faisable si `allowed_regions` est vide, ou si une région permise, sur un cloud non interdit, a dans la table de juridiction une zone incluse dans la zone exigée. Les gabarits parlent de localisation (T118).

### D6. Budget, stagnation, versions, worker
- `Spec()` littéral : `L2-design`, `l2.Propose`, `l2.Verify`, stratégies `[catalog]`, 5 itérations, `MaxTokens` 1 (minimum de `Validate` ; `Propose` déclare 0 jeton), 2 minutes, seuils 2 et 3, `ActivityTimeout` 30 s. `WorkflowName` `rempart.l2.v1`, file `rempart-l2`, préfixe `l2-design` ; `Prepare` et `Finalize` : 30 s, trois tentatives, types non rejouables de `loops`.
- **Versions** : aucun identifiant de changement à la création ; tout changement ultérieur de séquence passe par `workflow.GetVersion` avec un identifiant `l2-<objet>` déclaré dans `internal/loops/versions.go`. Historique de référence (R9) enregistré en M2-T05 si la pile de dev est disponible, sinon obligation « avant le premier changement de séquence de L2 ».
- **Aucun import de `internal/llm`** sous `internal/loops/l2/...` (critère 3) : `Activities{Tenant tenancy.ID; Policy policy.Evaluator}`, sans client de modèle ; ni l'adaptateur OPA (interface seulement).
- **Worker** : `-l2-once` (exclusif de `-demo-once` et `-l1-once`), `-l2-input <chemin relatif .json>` (`{ir|graph, confirmation}`, strict, 256 Kio au plus). `opa.NewDesign()` avant toute connexion à Temporal : un échec arrête le processus sans enregistrement. `registerL2` appelle `codec.Check` avant `l2.Register`, qui exige un tenant client et un évaluateur non nul.
- **(cr)** : lecteur commun `internal/fsread` pour `--digest`, `-l2-input` et `readIR` repris : `os.Stat` (régulier, taille bornée), ouverture `O_RDONLY|O_NONBLOCK`, `Stat` du descripteur (régulier, `os.SameFile`), lecture bornée.
- `make l2-demo` : scénario de référence et confirmation de test liée au tenant de démo, sur le modèle de `l1-demo`.

### D7. Contexte de conception passé au pack (`DesignContext`)

| Champ | Forme IR | Forme graphe |
|---|---|---|
| `UnconfirmedExposures` | `EXPOSES` du candidat non couvertes (D3), recalculées par `Verify` | idem |
| `SourcesUnresolved` | `EXPOSES` du candidat dans `WorldSources` si une dérogation cite une adresse, sinon vide | vide |
| `Constraints` | `ir.constraints.allowed_regions` et `forbidden_clouds` | vides |
| `Environment` | `ir.environment` (vide : réseaux, sinon `prod`) | vide (réseaux, sinon `prod`) |
| `Observability` | `metrics`, `logs` présents et différents de `none` | faux (OBS-001 `advisory`) |
| `WorkloadRoles` | `wl:<id>` des workloads `gitops_controller` ou `observability_stack` | vide (K8S-050 muet : limite) |

Jamais le contexte du tenant porté par l'entrée ((ef) inchangée) ni un texte libre ; `Jurisdiction` et `WorldSources` sont calculés par `NewDesignInput` depuis le graphe.

### D8. Interfaces Go (écarts à la section 3.1 du plan)

```go
package confirm // internal/design/confirm ; étiquettes json en snake_case
type ExposureKey struct{ Target string; Proto reach.Proto; Ports reach.PortSet; World bool; Sources []string }
type Confirmation struct{ Subject, SubjectSHA256 string; Exposures []ExposureKey; ConfirmedBy string }
type Digest struct{ Subject, SubjectSHA256 string; Exposures []ExposureKey; Overrides []string; Sensitive []SensitiveData }
func DigestOfIR(ir intentdomain.IR) (Digest, error)
func DigestOfGraph(g graphdomain.Graph) (Digest, error)
func Check(d Digest, c Confirmation) (unconfirmed []ExposureKey, err error) // ErrNotConfirmed
func Uncovered(hops []reach.Hop, confirmed []ExposureKey) []reach.Hop
func Escape(s string) string

package verify // internal/design/verify
const CodeInternetToSensitive, CodeExposureUnconfirmed = "L2-INTERNET-TO-SENSITIVE", "L2-EXPOSURE-UNCONFIRMED"
func CoreControls() []policydomain.Control
type Context struct{ Confirmed []confirm.ExposureKey; OverridesCiteAddress bool; Base policy.DesignContext }
func Candidate(ctx context.Context, ev policy.Evaluator, g graphdomain.Graph, tenant string, c Context) ([]loopsdomain.Finding, error)

func PlanOf(g graphdomain.FactsGraph) (cidr.Plan, error) // internal/design
func CitesAddress(s string) bool                         // internal/intent/domain
type Candidate struct{ Graph graphdomain.Graph; Applied []revise.Applied } // internal/loops/l2/activities
const ErrTypeInvalidL2Input = "InvalidL2Input"                             // internal/loops/l2
```
`revise.Revise`, `revise.Applied`, `l2.Input`, `l2.Output`, `l2.Explanation`, `l2.Spec` : section 3.1, inchangés.

## Conséquences
- Positives : aucune décision ni texte de modèle dans L2 ; evals de conception déterministes ; une sémantique d'exposition (celle de `reach`) pour la confirmation, l'invariant et les politiques ; NET-002 et NET-005 vivants ; aucune escalade ne rend de graphe ; pack affaibli sans effet sur les deux invariants.
- Négatives : peu de corrections (relocalisation, CIDR, identité dédiée escaladées, R6) ; empreinte du document entier, donc une retouche de texte libre exige une nouvelle confirmation ; vérificateur rejoué deux fois par `Finalize` ; un faux positif de lecture d'adresse escalade.
- Difficile à changer : `ExposureKey` et l'empreinte (confirmations de M4) ; codes d'escalade (baseline) ; forme de `Output` (L3) ; séquence du workflow.

## Impact sur le modèle de menace
- À insérer en M2-T05 : **T107** (confirmation liée à l'empreinte et aux sauts depuis Internet, identité déclarée ; `TestL2RefusesUnconfirmed`) ; **T110** (table fermée, propriété (1) à (6) ; `TestRevisionNeverWidens`).
- **T108** : deux invariants Go indépendants du pack (`TestL2CoreInvariantWithoutPack`). **T111** et **T2** : vérificateur sur `FactsGraph`, dérogations lues par le seul lecteur d'adresses et seulement pour bloquer, gabarits fixes (`TestL2FreeTextHasNoEffect`). **T112** et **T24** : `payload_too_large`, 100 findings, délai d'activité. **T115** : `subject`. **T3** : tenant du worker, refus avant la boucle (`TestL2TenantMismatchRefused`). **T12**, **T18** : confirmation forgeable par quiconque démarre le workflow jusqu'à M4 (résidu, comme `Author`). **T16** : D6.
- Nouvelle proposée (numéro provisoire, à confirmer par `security-reviewer`) : **T121** récapitulatif de confirmation incomplet ou maquillé (exposition implicite omise, texte bidirectionnel ou C1 qui masque une ligne) : l'humain confirme ce qu'il n'a pas vu (S, T) ; atténuation : clés tirées de `reach`, couverture rejouée à chaque vérification, `Escape` ; vérification : `TestL2EveryExposureInDigest`, `TestDigestEscapesUntrusted`.

## Ordre de mise en oeuvre (M2-T05, tests puis impl à chaque pas)
1. `docs/loops/L2.md` (fiche de la section 4 du plan, amendée par cet ADR).
2. `internal/fsread` et `CitesAddress` (`TestRegularRefusesFIFO`).
3. `internal/design/confirm` (`TestL2EveryExposureInDigest`, `TestDigestEscapesUntrusted`), puis `rempart design --digest`.
4. `PlanOf` et `internal/design/verify` (`TestL2CoreInvariantWithoutPack`, au niveau du paquet).
5. `internal/design/revise` (`TestRevisionNeverWidens`, `TestL2RevisesTrap` au niveau du réviseur).
6. `internal/loops/l2` et ses activités (`TestL2ReferenceConvergesUnchanged`, `TestL2RefusesUnconfirmed`, `TestL2TenantMismatchRefused`, `TestL2UnresolvedSourceEscalates`, `TestL2EscalatesIncompatibleConstraints`, `TestL2EscalationHasNoGraph`, `TestL2FreeTextHasNoEffect`).
7. Worker et `make l2-demo` (`TestWorkerRequiresRempartConverterL2`, `makefile_test.go`) ; T107, T110 et T121 soumises à `security-reviewer`.

## Vérifications
1. Critère 1 de la fiche M2-T05 (treize tests nommés) : `13`.
2. `go test ./internal/design/revise/ -run TestRevisionNeverWidens -rapid.checks=1000 -v` : `--- PASS: TestRevisionNeverWidens `.
3. `go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./internal/loops/l2/... | grep -c '/internal/llm'` : `0`.
4. `go list -deps ./internal/loops/l2/... ./internal/design/... | grep -c open-policy-agent` : `0`.
5. `grep -c '^budget:' docs/loops/L2.md` : `1`.
6. `go run ./cmd/rempart design --digest internal/intent/testdata/reference-ir.json | jq -e '.subject == "ir" and (.subject_sha256 | test("^[0-9a-f]{64}$")) and .exposures == [{"target":"lb:app-cluster-443","proto":"tcp","ports":[{"from":443,"to":443}],"world":true,"sources":[]}]'` : `true`.
7. `go run ./cmd/rempart design --digest --superblock 10.0.0.0/8 internal/intent/testdata/reference-ir.json; echo rc=$?` : `rc=2`.
8. `go test ./internal/fsread/ -run TestRegularRefusesFIFO -v 2>&1 | grep -c '^--- PASS: TestRegularRefusesFIFO '` : `1`.
9. `stride-v1` inchangé : `go test ./internal/threat/ -run TestDeltaSerializationGolden -v 2>&1 | grep -c '^--- PASS: TestDeltaSerializationGolden '` : `1`.
10. Pile, critère 5 de la fiche : `make -s -f Makefile l2-demo | jq -e '.status == "converged" and .subject == "ir" and (.applied | length) == 0 and (.threats.threats | length) > 0 and .threat_delta.from == .threat_delta.to and (has("explanation") | not) and (.loop | has("best") | not)'` : `true`.
11. Critère 6 : `make -f Makefile verify; echo rc=$?` : `rc=0`.

## Questions à l'humain
1. Exposition du sujet non confirmée : escalade `exposure_unconfirmed` (NET-002 et invariant) plutôt que refus avant la boucle (oui).
2. Second invariant Go `L2-EXPOSURE-UNCONFIRMED`, couvrant les expositions implicites que NET-002 ne voit pas (oui).
3. STRIDE-I-004 laissé sans contrôle, `stride-v1` inchangé, `L2-INTERNET-TO-SENSITIVE` hors catalogue (oui).
4. `dedicated_identity` non appliquée en M2, IAM-003 escaladé (oui).
5. Historique de référence de L2 : obligation datée si la pile de dev manque en M2-T05 (oui).

## Écarts au plan M2, à reporter au début de M2-T05
1. D3 : seule une clé confirmée hors du sujet fait refuser ; une exposition du sujet non confirmée mène à l'escalade `exposure_unconfirmed` (trappe 12, NET-002 vivant).
2. Section 3.1 : `ExposureKey` est la projection d'un saut (`ports` en plages, `world`) ; `confirm.Check` rend les clés non confirmées ; `Uncovered`, `Escape`, paquet `internal/design/verify`, `PlanOf`, `CitesAddress`, `activities.Candidate`, `internal/fsread` ajoutés.
3. D4 et D6 du plan : invariant `L2-EXPOSURE-UNCONFIRMED` ajouté ; codes `payload_too_large` (déjà en D14) et `evaluation_failed` ajoutés à la liste fermée.
4. D5 du plan : `dedicated_identity` non appliquée en M2.
5. ADR 0010 D9 : `stride-v1` ne cite pas `L2-INTERNET-TO-SENSITIVE` (option 6a).
6. Fiche M2-T05 : `TestRegularRefusesFIFO` hors des treize tests ; compte du critère 1 inchangé.
