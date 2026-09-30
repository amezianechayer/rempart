# M1-T04 `design-cidr` : graphe d'architecture, allocateur CIDR déterministe, `rempart design`

2026-09-30, `architect`, proposé. Fiche M1-T04 de `docs/plans/M1-overview.md`. Mode accéléré (humain, 2026-09-30) : les 8 tests de la fiche, une mutation par test, une seule campagne de mutations ; seuls les constats critiques ou hauts de la revue sécurité relancent un cycle. Décisions humaines appliquées : Q2 (aucune table PostgreSQL, graphe calculé à la demande, jamais stocké), Q4 (pas d'API ; point d'entrée `rempart design <ir.json>`).

## 0. Amendements

Aucun.

## 1. Objectif

Transformer une Intent IR v1 validée en un graphe d'architecture valide, avec un plan CIDR calculé par un allocateur déterministe en code pur, vérifié par un vérificateur indépendant. Le LLM ne choisit jamais un CIDR : il n'intervient nulle part dans cette tâche. `rempart design ir.json` est la première fonctionnalité visible par l'humain.

Critères de `prompts/M1.md` servis :
- **C2** : test de propriété, 1 000 plans CIDR aléatoires, zéro chevauchement, zéro sous-réseau hors parent, marge respectée (`TestAllocatorProperty`).
- **C3, seconde moitié** : le scénario de référence produit un graphe valide (`TestReferenceScenarioGraphValid`, critères 4 à 6 de la section 11).
- **Garde** de `prompts/M1.md` et de la réserve de l'ADR 0003 : `schemas/graph/v1.json` marque chaque champ texte libre (`TestGraphSchemaMarksFreeText`) ; `TestFactsBlockHasNoFreeText`.

## 2. Périmètre

### 2.1 Dans le périmètre
- `schemas/graph/v1.json` ; `schemas/embed.go` (embarquement du schéma de graphe, fonction `Compile` partagée).
- `internal/graph/domain/{graph.go,freetext.go,facts.go,validate.go}` : modèle de graphe commun au conçu et au réel (skill `security-graph-attack-paths`, `references/graph-schema.md`), type `FreeText`, projection `Facts`, invariants structurels.
- `internal/graph/schema.go` : validation d'un graphe contre `schemas/graph/v1.json`.
- `internal/design/cidr/{types.go,allocate.go,check.go,reference.go}` : allocateur, vérificateur (portage de `cidr_check.py`), lecture et écriture du format de `cidr_check.py`.
- `internal/design/{build.go,placement.go}` : IR vers graphe et plan, table fermée de placement.
- `internal/intent/parse.go` : ajout de `ParseIR` (décodage strict d'une IR puis `ValidateIR`).
- `cmd/rempart/{main.go,design.go,summary.go}` : sous-commande `design`.

### 2.2 Hors périmètre
- Stockage du graphe, `internal/graph/ports.Store`, migrations, RLS (Q2 : M2).
- Allocation incrémentale et stable par rapport à un plan précédent (un ajout de workload peut renuméroter) : M2, avec ADR (section 4, D-ADR).
- IPv6, découpage par zone de disponibilité, `GatewaySubnet` et `AzureBastionSubnet` nommés, agrégation de routes par cloud : L2 et L3 (M2, M3), dans la marge du VPC.
- Plages découvertes par l'inventaire (M5, M6) : en M1, les plages externes sont déclarées à la main par `--reserve`.
- Atteignabilité (`internal/graph/reach`), STRIDE, politiques `policies/design/` (M2).
- Noeuds `Account`, `Identity`, `Policy`, `SecurityRule`, `Secret`, `K8sNamespace` et arêtes `CAN_ASSUME`, `HAS_PERMISSION`, `RUNS_AS`, `MANAGED_BY_IAC` : absents du graphe conçu en M1 ; ajoutés à `schemas/graph/v1.json` par amendement tant qu'aucun graphe n'est persisté (Q2).
- `rempart plan`, API, confirmation de l'IR (M2, M4).

### 2.3 Écarts à la fiche (précisions, sans élargissement)
- **E1** : `Graph`, `Node`, `Edge`, `FreeText`, `Facts` vont dans `internal/graph/domain` et non `internal/design/domain` : le skill impose un seul modèle pour le graphe conçu (L2) et le graphe réel (L6), et l'ADR 0003 place le port `Store` dans `internal/graph`. `internal/design` ne garde que la construction.
- **E2** : sortie lisible par défaut et `--json`, conformément à `docs/04-INTERFACE.md` §8 (« Sortie lisible par défaut, `--json` sur toutes les commandes, codes retour stables ») ; toute autre forme exigerait un ADR. Le critère 4 de la fiche prend donc `--json`. `--cidr-only` rend exactement le format d'entrée de `cidr_check.py` (fiche, critère 3).
- **E3** : `intent.ParseIR` ajouté (la CLI lit une IR depuis un fichier, sans passer par L1). `schemas.Compile` factorise le compilateur de `intent.ValidateIR` (réutilisé par `internal/graph`), sans changement de comportement (tests de M1-T03 inchangés).
- **E4** : `cidr.CheckReference(raw []byte)` lit le format de `cidr_check.py`, y compris des CIDR invalides (code `CIDR_INVALID`), ce que `netip.Prefix` ne peut pas représenter ; exigé par `TestCheckMatchesReference`.

## 3. Décisions propres à ce plan

| # | Décision |
|---|---|
| P1 | **Hiérarchie** : superbloc (défaut `10.0.0.0/8`), puis un VPC ou VNet par triplet (cloud, région, environnement), puis un sous-réseau par tier (`public`, `app`, `data`, `mgmt`). Le découpage cloud, région, environnement, tier du skill est conservé, aplati en deux niveaux réels (VPC, sous-réseau) ; aucun bloc intermédiaire matérialisé en M1 (pas d'agrégation de routes). |
| P2 | **Taille d'un sous-réseau** : `2^ceil(log2(Hosts * Growth + 5))` adresses, au moins `/28` ; 5 adresses réservées par sous-réseau (AWS et Azure en réservent 5 : valeur la plus prudente, appliquée à tous les clouds). Marge : `usable = taille - 5 >= Hosts * Growth`. |
| P3 | **Taille d'un VPC** : `Growth * 2^ceil(log2(somme des tailles de ses sous-réseaux))`, au plus `/16` (limite d'un bloc de VPC AWS), sinon `ErrInvalidRequest`. La marge du VPC loge plus tard zones de disponibilité, `GatewaySubnet` (au moins `/27`) et `AzureBastionSubnet`. |
| P4 | **Placement** : VPC triés par (taille décroissante, nom croissant), chacun au premier emplacement aligné du superbloc qui ne chevauche ni une plage réservée ni un VPC déjà placé (saut à l'alignement suivant la fin du bloc en conflit : coût quadratique dans le nombre de blocs, borné). Aucun emplacement : `ErrExhausted`. Dans un VPC, sous-réseaux triés par (taille décroissante, ordre `public`, `app`, `data`, `mgmt`) et empilés depuis le début du VPC (empilement parfait de blocs alignés en puissances de deux décroissantes). |
| P5 | **Déterminisme** : le plan ne dépend que de l'ensemble des besoins, pas de leur ordre (tri canonique en entrée) ; aucune horloge, aucun aléa, aucune map itérée ; `Plan.Networks` trié par (adresse, longueur de préfixe) : un parent précède ses enfants. |
| P6 | **Validation de la requête** (`ErrInvalidRequest`, message fixe) : superbloc IPv4, canonique (`p == p.Masked()`), inclus dans une plage RFC 1918, longueur de 8 à 24 ; plages réservées IPv4 canoniques, 64 au plus ; 1 à 64 besoins, triplet unique ; cloud dans `aws`, `azure`, `scaleway`, `ovhcloud` ; région au motif `^[a-z][a-z0-9-]{0,30}[a-z0-9]$` ; environnement dans `dev`, `staging`, `prod` ; 1 à 4 tiers distincts du jeu fermé ; `Hosts` de 1 à 16 384 ; `Growth` 0 (vaut 4) ou de 1 à 16. |
| P7 | **Vérificateur indépendant** (T87) : `Check` ne partage aucune fonction avec `Allocate` (fichier distinct, seules les structures de `types.go` sont communes) et reprend exactement les règles, codes, gravités et ressources de `cidr_check.py`. `Build` appelle `Check` sur chaque plan produit ; un finding refuse la conception. **Divergence voulue** : Go est plus strict que Python sur `CIDR_NOT_PRIVATE` (RFC 1918 seulement, alors que `ipaddress.is_private` accepte aussi des plages spéciales comme `192.0.2.0/24`) et refuse l'IPv6 en `CIDR_INVALID` ; ces deux cas sont testés à part (section 9, test 3). |
| P8 | **Placement des workloads** (table fermée, `placement.go`) : voir section 6.2. Un workload cité dans `stored_in` d'une donnée `internal`, `confidential` ou `regulated` est placé dans le tier `data`, quel que soit son type. Une exposition qui vise un workload du tier `data` refuse la conception (`ErrDesignRefused`) : le tier `data` n'a aucune route vers Internet (skill). |
| P9 | **Texte libre** : seules quatre valeurs de l'IR entrent dans le graphe comme texte libre, sous `untrusted_text` : `summary` (graphe), `workloads[].notes` (noeud), `connectivity[].purpose` (arêtes `CAN_REACH`), `exposure[].justification` (noeud `LoadBalancer` et arête `EXPOSES`). Hypothèses, questions et overrides restent dans l'IR. Tout autre champ de graphe est fermé (`enum`, `const`) ou contraint par un motif. |
| P10 | **Tenant** : le graphe porte le `tenant_id` de l'IR, validé par `ValidateIR` (UUID v4, `System` refusé). Aucun état global, aucun cache : `Build` est une fonction pure. À la première API, le tenant du contexte authentifié devra être égal à celui de l'IR (obligation reportée, section 12). |

**D-ADR, pas d'ADR dans cette tâche** : en M1, aucun plan n'est persisté ni déployé (Q2) ; l'algorithme et le schéma sont réversibles sans coût. La décision devient difficile à inverser dès qu'un plan est persisté ou appliqué (renumérotation d'un VPC = destruction). Obligation : ADR « planification CIDR stable et incrémentale » (plan précédent en entrée, blocs jamais déplacés, plages de l'inventaire) **avant** la première persistance d'un plan CIDR (M2) ; consignée dans `docs/STATUS.md` à la clôture.

## 4. Interfaces

```go
// schemas/embed.go
package schemas

//go:embed intent/v1.json intent/draft-v1.json graph/v1.json
var FS embed.FS

const (
	IntentIR    = "intent/v1.json"
	IntentDraft = "intent/draft-v1.json"
	Graph       = "graph/v1.json"
)

// Compile compiles an embedded schema (Draft 2020-12, loader that denies any
// access), once per path. Used by intent.ValidateIR and graph.ValidateSchema.
func Compile(path string) (*jsonschema.Schema, error)
```

```go
package cidr // internal/design/cidr : bibliothèque standard et internal/loops/domain seulement

type Tier string

const (
	TierPublic Tier = "public"
	TierApp    Tier = "app"
	TierData   Tier = "data"
	TierMgmt   Tier = "mgmt"
)

const (
	DefaultGrowth     = 4
	ReservedPerSubnet = 5
	MinSubnetBits     = 28 // longueur maximale d'un sous-réseau
	MaxVPCBits        = 16 // longueur minimale d'un VPC
	MaxNeeds          = 64
	MaxReserved       = 64
	MaxHosts          = 16384
)

type TierNeed struct {
	Tier  Tier
	Hosts int
}

type Need struct {
	Cloud, Region, Env string
	Tiers              []TierNeed
}

type Request struct {
	Superblock netip.Prefix
	Reserved   []netip.Prefix
	Needs      []Need
	Growth     int // 0 : DefaultGrowth
}

// Network : VPC (Parent vide, Tier vide, Hosts = somme des besoins) ou sous-réseau.
// Name : "<cloud>-<region>-<env>" pour un VPC, "<vpc>-<tier>" pour un sous-réseau.
type Network struct {
	Name, Parent string
	Tier         Tier
	Prefix       netip.Prefix
	Hosts        int
}

type Plan struct {
	Superblock netip.Prefix
	Growth     int
	Networks   []Network      // trié par (adresse, longueur) : parent avant enfants
	External   []netip.Prefix // plages réservées, triées
}

var (
	ErrInvalidRequest = errors.New("cidr: invalid request")
	ErrExhausted      = errors.New("cidr: superblock exhausted")
)

// Allocate : P1 à P6. Même ensemble de besoins, même plan, à l'octet.
func Allocate(r Request) (Plan, error)

// Check : règles de cidr_check.py (P7). Findings triés par loopsdomain.Sort, Source "cidr_check".
// Codes : CIDR_INVALID, CIDR_NOT_PRIVATE, CIDR_OUTSIDE_SUPERBLOCK, CIDR_UNKNOWN_PARENT,
// CIDR_OUTSIDE_PARENT, CIDR_OVERLAP, CIDR_OVERLAP_EXTERNAL (mêmes gravités et ressources que le script).
func Check(p Plan) []loopsdomain.Finding

// ReferenceJSON rend le plan au format d'entrée de cidr_check.py : clé "parent" absente pour
// un VPC, plages externes nommées "reserved-1", "reserved-2", ... dans l'ordre de External.
func ReferenceJSON(p Plan) ([]byte, error)

// CheckReference décode le format de cidr_check.py (1 Mio au plus, décodage strict) et applique Check ;
// un CIDR non analysable ou non canonique donne CIDR_INVALID (E4).
func CheckReference(raw []byte) ([]loopsdomain.Finding, error)
```

```go
package domain // internal/graph/domain : bibliothèque standard seulement (R1)

const GraphVersion = "1"

type NodeKind string // Internet, Network, Compute, K8sCluster, K8sWorkload, LoadBalancer, DataStore
type EdgeType string // MEMBER_OF, EXPOSES, CAN_REACH, STORES

// FreeText : texte libre non fiable. Structure à champ non exporté : aucune conversion
// possible vers string ; String() et Format rendent "[free text]" ; seul Untrusted() rend le contenu.
type FreeText struct{ s string }

func NewFreeText(s string) FreeText
func (t FreeText) Untrusted() string
func (t FreeText) String() string
func (t FreeText) MarshalJSON() ([]byte, error)

type Graph struct {
	Version  string    `json:"version"`
	TenantID string    `json:"tenant_id"`
	Source   string    `json:"source"` // design (M1), observed (M5)
	Nodes    []Node    `json:"nodes"`
	Edges    []Edge    `json:"edges"`
	Text     GraphText `json:"untrusted_text"`
}

type Node struct {
	ID    string    `json:"id"`
	Kind  NodeKind  `json:"kind"`
	Attrs NodeAttrs `json:"attrs"`
	Text  NodeText  `json:"untrusted_text"`
}

type Edge struct {
	ID    string    `json:"id"`
	Type  EdgeType  `json:"type"`
	Src   string    `json:"src"`
	Dst   string    `json:"dst"`
	Attrs EdgeAttrs `json:"attrs"`
	Text  EdgeText  `json:"untrusted_text"`
}

// NodeAttrs, EdgeAttrs : champs fermés de la section 6.1, pointeurs avec omitempty, aucun FreeText.
// GraphText{Summary *FreeText}, NodeText{Notes, Justification *FreeText}, EdgeText{Purpose, Justification *FreeText}.

// Facts : projection JSON du graphe sans aucun untrusted_text, seule vue destinée aux politiques
// et au LLM. Construite sur des types dédiés (FactsGraph, FactNode, FactEdge) qui ne contiennent
// aucun FreeText à aucune profondeur.
func Facts(g Graph) ([]byte, error)

// Validate : identifiants uniques, arêtes vers des noeuds existants, types et genres fermés,
// CAN_REACH avec chemin non vide de noeuds Network, aucune arête EXPOSES depuis un noeud
// membre d'un sous-réseau de tier data. Erreurs à message fixe.
func Validate(g Graph) error
```

```go
package graph // internal/graph

var ErrGraphInvalid = errors.New("graph: invalid graph")

// ValidateSchema : schemas/graph/v1.json (schemas.Compile), puis domain.Validate.
func ValidateSchema(g domain.Graph) error
```

```go
package design // internal/design

type Options struct {
	Superblock netip.Prefix   // zéro : 10.0.0.0/8
	Reserved   []netip.Prefix
	Growth     int            // 0 : 4
}

var ErrDesignRefused = errors.New("design: refused") // enveloppe une cause à message fixe

// Build : intent.ValidateIR, besoins par la table 6.2, cidr.Allocate, cidr.Check (vide exigé),
// graphe, graph.ValidateSchema. Aucun LLM, aucune entrée-sortie, aucun état global.
func Build(ir intentdomain.IR, o Options) (graphdomain.Graph, cidr.Plan, error)
```

```go
package intent

// ParseIR : 1 Mio au plus, schema.DecodeStrict (clés en double, profondeur), décodage
// avec DisallowUnknownFields vers domain.IR, puis ValidateIR. ErrIRInvalid, message fixe.
func ParseIR(raw []byte) (domain.IR, error)
```

```go
package main // cmd/rempart

// run : point d'entrée testable ; main() fait os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)).
// Codes : 0 succès ; 1 conception refusée (IR invalide, fichier illisible ou trop gros,
// ErrInvalidRequest, ErrExhausted, ErrDesignRefused) ; 2 usage (commande inconnue, option
// inconnue, --json avec --cidr-only, zéro ou plusieurs fichiers).
func run(args []string, stdout, stderr io.Writer) int
```

Usage : `rempart design [--json | --cidr-only] [--superblock CIDR] [--reserve CIDR]... [--growth N] <ir.json>` (options avant le fichier, paquet `flag`). `--reserve` est répétable. Messages d'erreur sur stderr, fixes, préfixés `rempart design:`, sans contenu du fichier.

## 5. Flux de données

```
ir.json (fichier local) -> lecture bornée (1 Mio, fichier régulier) -> intent.ParseIR -> IR validée
IR -> design.Build
        |- placement (table 6.2) -> []cidr.Need   (aucune valeur technique ne vient de l'IR)
        |- cidr.Allocate(Request{superbloc, --reserve, besoins, croissance}) -> Plan
        |- cidr.Check(Plan) == []                  (vérificateur indépendant, T87)
        |- graphe : noeuds, arêtes, attrs fermés ; summary, notes, purpose, justification -> FreeText
        |- graph.ValidateSchema(graphe)            (schéma v1 puis invariants)
     -> (Graph, Plan)
sortie : texte (faits seulement, jamais de untrusted_text) | --json {version, graph, cidr_plan, cidr_findings}
        | --cidr-only (format cidr_check.py)
```

La seule entrée non fiable est l'IR (texte libre de l'utilisateur, éventuellement produit par un modèle en L1). Elle n'atteint le plan CIDR que par des nombres (`size.count`) et des identifiants à motif ; ses chaînes libres ne sont jamais interprétées, seulement transportées en `FreeText`.

## 6. Graphe v1

### 6.1 `schemas/graph/v1.json` (Draft 2020-12, `additionalProperties: false` partout)
- Racine : `version` (`const "1"`), `tenant_id` (motif UUID v4 de `schemas/intent/v1.json`), `source` (`enum design, observed`), `nodes` (`maxItems` 10 000), `edges` (`maxItems` 50 000), `untrusted_text` (`{summary}`).
- `$defs/free_text` : `{"type": "string", "maxLength": 500}`. C'est la **seule** chaîne non fermée du schéma.
- Noeud : `id` (motif `^(internet|(net|wl|lb|data):[a-z0-9][a-z0-9.-]{0,80})$`), `kind` (`enum`), `attrs`, `untrusted_text` (`{notes, justification}`, chacun `$ref: #/$defs/free_text`).
- `attrs` de noeud (tous facultatifs dans l'objet, requis par genre via `allOf` et `if`/`then`) : `cloud` (`enum`), `region` (motif P6), `env` (`enum`), `subtype` (`enum vpc, subnet, vm, managed_db, object_storage, dataset`), `cidr` (motif CIDR IPv4), `tier` (`enum`), `count` (entier 1 à 500), `os` (`enum`), `public` (booléen), `listeners` (tableau de `{protocol enum, port 1..65535}`), `behind` (`enum` de l'IR), `classification`, `regulation`, `residency` (`enum` de l'IR), `encrypted`, `public_access`, `api_public` (booléens).
- Requis par genre : `Network` : `subtype`, `cidr`, `cloud`, `region`, `env` (et `tier` pour `subnet`) ; `Compute` : `subtype`, `cloud`, `region`, `count` ; `K8sCluster` : `cloud`, `region`, `count`, `api_public` ; `LoadBalancer` : `public`, `listeners` ; `DataStore` : `subtype`, `classification`, `encrypted`, `public_access` ; `K8sWorkload`, `Internet` : aucun.
- Arête : `id` (motif `^[a-z_]+\|[a-z0-9:.-]+\|[a-z0-9:.-]+(\|(tcp|udp|https|http)/[0-9]{1,5}(-[0-9]{1,5})?)?$`), `type` (`enum`), `src`, `dst` (motif d'identifiant de noeud), `attrs` (`protocol` `enum tcp, udp, https, http` ; `port_from`, `port_to` entiers ; `via` `enum vpn_site_to_site, peering, private_link, internal, load_balancer` ; `path` tableau d'identifiants de noeud, `minItems` 1 ; `allowed_sources` tableau de CIDR à motif), `untrusted_text` (`{purpose, justification}`).

### 6.2 Table de placement (fermée, `placement.go`)

| `kind` de l'IR | Noeud | Tier | Hosts |
|---|---|---|---|
| `k8s_cluster` | `K8sCluster` (`api_public: false`) | `app` | `count` (défaut 3) x 32 (une adresse par pod avec le CNI VPC d'EKS, skill) |
| `vm_group` | `Compute` `vm` | `app` | `count` (défaut 1) |
| `managed_db` | `DataStore` `managed_db` | `data` | `count` (défaut 2) |
| `object_storage` | `DataStore` `object_storage` | aucun sous-réseau | 0 |
| `load_balancer` | `LoadBalancer` | `public` | 8 |
| `observability_stack`, `gitops_controller` avec `runs_on` | `K8sWorkload`, `MEMBER_OF` le cluster | aucun | 0 |
| les mêmes sans `runs_on` | `Compute` `vm` | `app` | `count` (défaut 1) |

- Hôte d'une donnée `internal`, `confidential` ou `regulated` (`stored_in`) : tier `data` (P8). Chaque donnée donne un noeud `DataStore` `dataset` (`encrypted: true`, `public_access: false`) et une arête `STORES` depuis chacun de ses hôtes.
- Exposition : noeud `lb:<workload>-<port>` (`public: true`, `listeners`, `behind`), 8 hôtes dans le tier `public` du VPC du workload exposé, arête `EXPOSES` du répartiteur vers `internet` (`port`, `allowed_sources`), arête `CAN_REACH` du répartiteur vers le workload (chemin : sous-réseau public, sous-réseau du workload). Port absent : 443 pour `https`, 80 pour `http`, refus pour `tcp` et `udp`. Workload exposé du tier `data` ou `object_storage` exposé : `ErrDesignRefused`.
- Liaison : une arête `CAN_REACH` par port déclaré (dans les deux sens si `bidirectional`), `via` = `kind` de la liaison, chemin : sous-réseau source, VPC source, VPC cible, sous-réseau cible (un `K8sWorkload` prend le sous-réseau de son cluster). Liaison sans port : aucune arête (refus par défaut).
- Environnement absent de l'IR : `dev` (défaut du schéma de l'IR). Noeud `internet` toujours présent.

## 7. Sortie attendue sur le scénario de référence

Calcul (P2 à P4, croissance 4) : `public` 8 x 4 + 5 = 37, donc `/26` ; `app` 96 x 4 + 5 = 389, donc `/23` ; `data` 3 x 4 + 5 = 17, donc `/27`. VPC AWS : 4 x 2^ceil(log2(576)) = 4 096, donc `/20` ; VNet Azure : 4 x 32 = 128, donc `/25`.

```
$ go run ./cmd/rempart design internal/intent/testdata/reference-ir.json
rempart design: deterministic plan, no LLM
tenant       3f6c2a9e-8b1d-4c7a-9e2f-5d4b3a2c1e0f
environment  staging
superblock   10.0.0.0/8 (growth x4)
reserved     none: declare on-premise and existing ranges with --reserve

NETWORK                           CIDR          TIER    HOSTS  USABLE
aws-eu-west-3-staging             10.0.0.0/20   vpc         -       -
aws-eu-west-3-staging-app         10.0.0.0/23   app        96     507
aws-eu-west-3-staging-public      10.0.2.0/26   public      8      59
azure-francecentral-staging       10.0.16.0/25  vpc         -       -
azure-francecentral-staging-data  10.0.16.0/27  data        3      27

WORKLOAD     KIND                 PLACEMENT
app-cluster  k8s_cluster          aws-eu-west-3-staging-app
gitops       gitops_controller    runs on app-cluster
legacy-vms   vm_group             azure-francecentral-staging-data
obs          observability_stack  runs on app-cluster

exposure     internet -> lb:app-cluster-443 https/443 -> app-cluster
flow         app-cluster -> legacy-vms tcp/5432 via vpn_site_to_site
flow         app-cluster -> legacy-vms tcp/9100 via vpn_site_to_site
data         customer-db confidential on legacy-vms (tier data)
graph        12 nodes, 13 edges
cidr check   0 findings
```

Le résumé n'imprime que des faits (valeurs fermées ou à motif) : aucun `untrusted_text`, donc aucune séquence d'échappement de terminal venue de l'IR. Alignement par `text/tabwriter` (remplissage 2) ; les tests vérifient les lignes par expressions régulières, pas les espaces.

```
$ go run ./cmd/rempart design --json internal/intent/testdata/reference-ir.json | jq '{nodes: (.graph.nodes | length), edges: (.graph.edges | length), cidr_findings, first: .graph.edges[0].id}'
{
  "nodes": 12,
  "edges": 13,
  "cidr_findings": [],
  "first": "can_reach|lb:app-cluster-443|wl:app-cluster|https/443"
}
```

Forme de `--json` : `{"version": "1", "graph": {version, tenant_id, source: "design", nodes, edges, untrusted_text}, "cidr_plan": {superblock, growth, networks: [{name, cidr, parent?, tier?, hosts, usable}], external: [{name, cidr}]}, "cidr_findings": []}`. Arêtes triées par (type, src, dst, protocole, port), noeuds par identifiant.

Noeuds (12) : `internet` ; `net:` x 5 (2 VPC, 3 sous-réseaux) ; `wl:app-cluster`, `wl:legacy-vms`, `wl:obs`, `wl:gitops` ; `lb:app-cluster-443` ; `data:customer-db`. Arêtes (13) : 8 `MEMBER_OF` (3 sous-réseau vers VPC, `app-cluster`, `legacy-vms`, `lb`, `obs`, `gitops`), 1 `EXPOSES`, 3 `CAN_REACH` (répartiteur vers cluster, 5432, 9100), 1 `STORES`.

```
$ go run ./cmd/rempart design --cidr-only internal/intent/testdata/reference-ir.json | jq -c '[.networks[] | [.name, .cidr, .parent]]'
[["aws-eu-west-3-staging","10.0.0.0/20",null],["aws-eu-west-3-staging-app","10.0.0.0/23","aws-eu-west-3-staging"],["aws-eu-west-3-staging-public","10.0.2.0/26","aws-eu-west-3-staging"],["azure-francecentral-staging","10.0.16.0/25",null],["azure-francecentral-staging-data","10.0.16.0/27","azure-francecentral-staging"]]
```

## 8. Spécification de boucle

Sans objet : aucune boucle dans cette tâche. `Build` fournira l'étape « IR vers graphe et allocation CIDR » de L2 (M2) et est appelé par `make l1-demo` (M1-T05) ; son critère « CIDR sans conflit » de `docs/01-LOOPS.md` (L2) est `cidr.Check(plan) == []`.

## 9. Tests (écrits par `test-author` en phase tests)

Données :
- `internal/design/cidr/testdata/golden/<cas>.plan.json` et `<cas>.want.json` : `want` produit **par le script de référence**, commande consignée dans le test : `python3 .claude/skills/multicloud-networking/scripts/cidr_check.py <cas>.plan.json > <cas>.want.json` (code 0 ou 1). Cas : `valid_reference` (sortie `--cidr-only` attendue en section 7), `valid_nested`, `overlap_siblings`, `duplicate_sibling`, `child_overlaps_parent_only` (aucun finding), `outside_parent`, `unknown_parent`, `outside_superblock`, `not_private` (`8.8.8.0/24`), `overlap_external`, `invalid_host_bits` (`10.0.0.1/16`).
- `internal/design/testdata/reference-canaries.json` : IR de référence dont `summary`, `notes`, `purpose`, `justification` portent chacun un canari distinct (`CANARY-SUMMARY-7f3a`, ...).
- `internal/design/testdata/exposed-data-tier.json` : IR de référence avec une exposition `https` de `legacy-vms`.

| # | Test (paquet) | Preuve | Mutation (une par test) |
|---|---|---|---|
| 1 | `TestAllocatorProperty` (`cidr`, C2) | `rapid` ; générateur : superbloc RFC 1918 de `/8` à `/12`, 0 à 4 plages réservées de `/16` à `/24` (chevauchant ou non le superbloc), 1 à 8 besoins distincts, 1 à 4 tiers, `Hosts` de 1 à 256, `Growth` 0 à 4 (faisable par construction) ; pour chaque plan : `Allocate` réussit ; `Check(plan)` vide ; contrôles propres au test, sans `Check` : aucun chevauchement entre deux réseaux de même parent, aucun réseau (tout niveau) chevauchant une plage réservée, tout sous-réseau inclus dans son parent, tout VPC inclus dans le superbloc, `usable >= Hosts * Growth` pour chaque sous-réseau, `taille(VPC) >= Growth * somme(tailles des enfants)`, chaque tier demandé présent une fois. Compteurs dans la fermeture, puis `t.Logf("plans=%d allocated=%d violations=%d", ...)` ; échec si `allocated != plans` | M1 : `Allocate` ignore `Reserved` |
| 2 | `TestAllocatorDeterministic` (`cidr`) | requête de référence (besoins de la section 7) : plan égal à la table de la section 7 ; deux appels : `ReferenceJSON` identiques à l'octet ; 20 permutations (graine fixe) de `Needs` et de `Tiers` : plan identique | M2 : tri canonique des besoins retiré (ordre d'entrée) |
| 3 | `TestCheckMatchesReference` (`cidr`) | pour chaque cas doré : `CheckReference(plan)` égal à `want` sur le multiensemble (code, gravité, ressource, source) ; sous-test `divergence` (P7, attendus écrits à la main) : `192.0.2.0/24` donne `CIDR_NOT_PRIVATE`, `fd00::/8` donne `CIDR_INVALID` | M3 : règle `CIDR_OVERLAP_EXTERNAL` retirée |
| 4 | `TestAllocatorExhausted` (`cidr`) | superbloc `/20` et un besoin dont le VPC fait exactement `/20` : succès (borne) ; plus un second besoin : `ErrExhausted` ; plage réservée égale au superbloc : `ErrExhausted` ; sous-tests `invalid_*` (`ErrInvalidRequest`) : superbloc public `8.0.0.0/8`, non canonique `10.0.0.1/8`, IPv6, besoin en double, `Hosts` 0 et 16 385, VPC au-delà de `/16`, région `EU_WEST` | M4 : contrôle « bloc dans le superbloc » retiré du placement |
| 5 | `TestReferenceScenarioGraphValid` (`design`, C3) | `intent.ParseIR(reference-ir.json)` sans erreur ; `Build` sans erreur ; `graph.ValidateSchema` nil ; 12 noeuds, 13 arêtes, dénombrement par type de la section 7 ; `wl:legacy-vms` membre de `net:azure-francecentral-staging-data` (tier `data`) ; aucune arête `EXPOSES` depuis un membre du tier `data` ; `cidr.Check(plan)` vide ; `tenant_id` du graphe égal à celui de l'IR ; sous-tests `exposed_data_tier_refused` (`errors.Is(err, ErrDesignRefused)`) et `system_tenant_refused` (`ErrIRInvalid`) | M5 : `stored_in` ignoré par le placement |
| 6 | `TestGraphSchemaMarksFreeText` (`graph`) | parcours récursif de `schemas/graph/v1.json` : tout sous-schéma `"type": "string"` a `enum`, `const` ou `pattern`, sauf `$defs/free_text` ; toute référence à `#/$defs/free_text` est une propriété directe d'un objet valeur d'une clé `untrusted_text` ; `$defs/free_text` a un `maxLength` ; `additionalProperties` faux dans chaque objet ; au moins une référence par champ de P9 | M6 : `pattern` retiré de `attrs.region` dans le schéma |
| 7 | `TestFactsBlockHasNoFreeText` (`design`) | `Build(reference-canaries)` : le JSON complet du graphe contient les 4 canaris (témoin : ils ont traversé), `Facts(g)` n'en contient aucun ; parcours `reflect` des types de `Facts` : aucun champ de type `FreeText` à aucune profondeur ; `fmt.Sprintf("%v %+v %s", ft, ft, ft)` sur un `FreeText` canari ne contient pas le canari | M7 : `Facts` recopie `untrusted_text` des noeuds |
| 8 | `TestDesignCommand` (`cmd/rempart`, via `run`) | texte : code 0, les 5 lignes de réseau, `^exposure\s+internet -> lb:app-cluster-443 https/443 -> app-cluster$`, `^graph\s+12 nodes, 13 edges$`, `^cidr check\s+0 findings$`, aucun canari avec l'IR à canaris ; `--json` : code 0, décodable, graphe valide par `graph.ValidateSchema` après décodage, deux exécutions identiques à l'octet ; `--cidr-only` : clés exactes du format de référence, `parent` absent des VPC ; `--reserve 10.0.0.0/9` : premier VPC `10.128.0.0/20` ; IR invalide (tenant `System`, champ inconnu, clé en double) : code 1, stdout vide, stderr fixe sans contenu du fichier ; usage (aucun fichier, deux fichiers, option inconnue, `--json --cidr-only`, commande `frobnicate`) : code 2 | M8 : `--reserve` non transmis à `Options` |

Les mutations sont appliquées une à une (M6 sur le schéma, les autres sur l'implémentation) ; chacune fait échouer au moins son test ; aucune ne touche un test.

## 10. Revue sécurité

Oui, légère (fiche). Points : indépendance réelle de `Check` et `Allocate` (P7) ; aucune valeur technique de l'IR dans le plan ; plages réservées et absence de défaut silencieux (avertissement « reserved none ») ; complétude du marquage du texte libre (P9, test 6) ; `Facts` sans texte libre ; bornes (fichier 1 Mio, besoins 64, réservées 64, noeuds et arêtes) et coût quadratique borné du placement ; codes de sortie et messages sans contenu ; résumé texte sans `untrusted_text` ; aucune dépendance vers un paquet LLM ou Temporal (critère 10).

## 11. Critères d'acceptation

1. C2 : `go test ./internal/design/cidr/ -run 'TestAllocatorProperty$' -rapid.checks=1000 -v 2>&1 | grep -Ec -- '^--- PASS: TestAllocatorProperty |plans=1000 allocated=1000 violations=0'` : `2`.
2. `python3 .claude/skills/multicloud-networking/scripts/cidr_check.py --selftest 1000; echo rc=$?` : `{"cases": 1000, "false_positives": 0, "false_negatives": 0}` puis `rc=0`.
3. `p="$(mktemp)"; go run ./cmd/rempart design --cidr-only internal/intent/testdata/reference-ir.json > "$p" && python3 .claude/skills/multicloud-networking/scripts/cidr_check.py "$p"; echo rc=$?` : `[]` puis `rc=0`.
4. C3 : `go run ./cmd/rempart design --json internal/intent/testdata/reference-ir.json | jq -e '(.graph.nodes | length) == 12 and (.graph.edges | length) == 13 and .cidr_findings == [] and .graph.tenant_id == "3f6c2a9e-8b1d-4c7a-9e2f-5d4b3a2c1e0f" and .graph.source == "design"'` : `true`.
5. `go run ./cmd/rempart design --cidr-only internal/intent/testdata/reference-ir.json | jq -c '[.networks[] | [.name, .cidr, .parent]]'` : la ligne exacte de la section 7.
6. `go run ./cmd/rempart design internal/intent/testdata/reference-ir.json | grep -Ec '^(aws-eu-west-3-staging|aws-eu-west-3-staging-app|aws-eu-west-3-staging-public|azure-francecentral-staging|azure-francecentral-staging-data) +10\.0\.'` : `5`.
7. Déterminisme : `a=$(go run ./cmd/rempart design --json internal/intent/testdata/reference-ir.json | sha256sum); b=$(go run ./cmd/rempart design --json internal/intent/testdata/reference-ir.json | sha256sum); [ "$a" = "$b" ] && echo same` : `same`.
8. `go test ./internal/design/... ./internal/graph/... ./cmd/rempart/... -v 2>&1 | grep -Ec -- '^--- PASS: Test(AllocatorProperty|AllocatorDeterministic|CheckMatchesReference|AllocatorExhausted|ReferenceScenarioGraphValid|GraphSchemaMarksFreeText|FactsBlockHasNoFreeText|DesignCommand) '` : `8`.
9. `jq -e '."$defs".free_text.type == "string" and ."$defs".free_text.maxLength > 0 and .additionalProperties == false' schemas/graph/v1.json` : `true`.
10. Aucun LLM ni Temporal : `go list -deps ./internal/design/... ./internal/graph/... ./cmd/rempart | grep -Ec 'rempart/internal/llm($|/adapters|/fake|/prompts)|anthropic-sdk-go|go\.temporal\.io'` : `0`.
11. Codes de sortie : `d="$(mktemp -d)"; go build -o "$d/rempart" ./cmd/rempart && { "$d/rempart" design; echo rc=$?; "$d/rempart" design --growth 99 internal/intent/testdata/reference-ir.json; echo rc=$?; }` : `rc=2` puis `rc=1`.
12. Mutations M1 à M8 (section 9) : chacune fait échouer `go test ./internal/design/... ./internal/graph/... ./cmd/rempart/...` (compte rendu de `acceptance-verifier`, une exécution par mutation, code non nul).
13. `go test ./internal/intent/... ./internal/archtest/ -run 'Test' ; echo rc=$?` : `rc=0` (tests de M1-T03 inchangés après la factorisation `schemas.Compile` ; arborescence et règles d'import, dont R1 sur `internal/graph/domain`).
14. `make -f Makefile verify-quick; echo rc=$?` : `rc=0`.

## 12. Risques

| # | Risque | Parade |
|---|---|---|
| R1 | Renumérotation : un workload ajouté peut déplacer un VPC (plan recalculé de zéro) | Sans effet en M1 (rien de persisté ni déployé) ; ADR « planification stable et incrémentale » exigé avant la première persistance d'un plan (D-ADR, M2) |
| R2 | Divergence `is_private` entre Python et Go, et entre versions de Python | Go plus strict (P7), cas dorés hors plages spéciales, divergence testée à part ; version de Python consignée dans le test à la génération |
| R3 | Dimensionnement Kubernetes (32 adresses par noeud) insuffisant ou excessif selon le CNI | Constante nommée, marge du VPC ; dimensionnement fin et délégation de préfixes en L2 (M2) |
| R4 | Plages on-premise non déclarées : plan en conflit avec l'existant (T87) | `--reserve`, avertissement explicite quand aucune plage n'est déclarée, plages de l'inventaire en M5 et M6, vérification post-déploiement en L5 |
| R5 | Schéma de graphe v1 incomplet pour L2 et L6 | Amendements admis tant qu'aucun graphe n'est persisté (Q2) ; test 6 garde la règle du texte libre à chaque ajout |
| R6 | Nouveaux paquets (`internal/graph/domain`, `internal/design/cidr`) refusés par l'arborescence ou R1 | Critère 13 ; adaptation de `internal/archtest` en phase tests si besoin |
| R7 | Temps de `TestAllocatorProperty` à 1 000 cas dans `verify-quick` | `verify-quick` garde le défaut de `rapid` (100 cas) ; 1 000 cas par le critère 1 ; générateur borné |

## 13. Impact sur le modèle de menace (`docs/02-THREAT-MODEL.md`)

- **T87** (proposée par `docs/plans/M1-overview.md`, à écrire par `security-reviewer` à la clôture) : plan CIDR qui chevauche des réseaux non déclarés (on-premise, VPC existants, plages d'un partenaire), provoquant coupure ou routage vers le mauvais réseau après interconnexion (D, T). Atténuations : plages réservées explicites (`--reserve`), avertissement quand aucune n'est déclarée, `Check` indépendant d'`Allocate` et appelé par `Build`, conformité au script de référence ; en M5 et M6, plages de l'inventaire ; en L5, vérification post-déploiement (routes apprises, connectivité interdite bloquée). Vérifications : `TestAllocatorProperty`, `TestCheckMatchesReference`, `TestAllocatorExhausted`. Résidu : plages non déclarées et non encore inventoriées.
- **T2** : vérification complétée : `TestGraphSchemaMarksFreeText`, `TestFactsBlockHasNoFreeText` (texte libre confiné à `untrusted_text`, absent de `Facts`, type `FreeText` sans conversion).
- **T10** : bornes de `Allocate` (P6), de `ParseIR` (1 Mio) et du schéma de graphe (noeuds, arêtes).
- **T3** : graphe porteur du tenant de l'IR validée (`System` refusé) ; aucun état global. Obligation pour la première API : tenant du contexte égal à celui de l'IR (avec `ParseCustomerID`, ADR 0004).
- Aucune nouvelle frontière de confiance : outil local, sans réseau ni LLM (critère 10).

## 14. Tâches ordonnées

1. `python3 .claude/bin/rempart-state phase tests`. **Tests (`test-author`)** : données de la section 9 (cas dorés produits par `cidr_check.py`, commandes consignées), les 8 tests ; rouges pour la bonne raison (`undefined:` ou schéma absent) ; adaptation de `internal/archtest` si R6. Passage en impl.
2. **Schéma** : `schemas/graph/v1.json`, embarquement, `schemas.Compile`, bascule de `intent.ValidateIR` sur `Compile`. Verts : test 6, critère 13 (tests de M1-T03).
3. **Modèle de graphe** : `internal/graph/domain` (types, `FreeText`, `Facts`, `Validate`), `internal/graph/schema.go`.
4. **Allocateur** : `internal/design/cidr/{types.go,allocate.go}`, `ReferenceJSON`. Verts : tests 1, 2, 4.
5. **Vérificateur** : `check.go`, `reference.go` (`CheckReference`), sans aucun appel à `allocate.go`. Vert : test 3.
6. **Construction** : `intent.ParseIR`, `internal/design/{placement.go,build.go}`. Verts : tests 5 et 7.
7. **CLI** : `cmd/rempart/{main.go,design.go,summary.go}`. Vert : test 8 ; critères 3 à 7 et 11 exécutés à la main.
8. `make -f Makefile verify-quick` ; campagne de mutations M1 à M8 ; `security-reviewer` (section 10) ; `acceptance-verifier` (section 11) ; clôture dans `docs/STATUS.md` avec l'obligation D-ADR et l'obligation « tenant du contexte égal à celui de l'IR » ; commit conventionnel.
