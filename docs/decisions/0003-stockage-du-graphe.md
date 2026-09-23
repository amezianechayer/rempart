# 0003. Stockage du graphe sans Apache AGE

- Statut : accepté le 2026-09-23 (décision humaine)
- Date : 2026-09-23
- Jalon : M0

## Contexte
La vision (§4) prévoit « PostgreSQL + Apache AGE pour le graphe (derrière une interface) ». Le graphe (`.claude/skills/security-graph-attack-paths/references/graph-schema.md`) porte le graphe conçu (L2), le graphe réel (L6), le diff conçu et réel, les chemins d'attaque et l'explorateur de l'interface (E7). M0 livre un `docker-compose.yml` avec PostgreSQL : le choix de l'image dépend de cette décision. La critique initiale (§5) propose des tables PostgreSQL classiques avec RLS.

Faits :
- Le skill `policy-as-code` impose que l'atteignabilité et les permissions effectives soient calculées en Go et injectées dans `input` ; Rego ne parcourt pas de graphe. Les chemins d'attaque sont validés saut par saut en Go. Le langage Cypher d'AGE ne servirait donc qu'à la lecture et à l'exploration.
- AGE, à notre connaissance, n'est pas proposé sur Amazon RDS ni Aurora ; un support récent existe côté Azure Database for PostgreSQL (à vérifier) ; Cloud SQL et les PostgreSQL managés d'OVHcloud et de Scaleway : non vérifiés. Or Rempart doit être auto-hébergeable (A6) et servir des clients sur clouds souverains (A4) : une extension absente des offres managées impose d'exploiter PostgreSQL soi-même.
- AGE stocke chaque label dans des tables internes interrogées par la fonction `cypher()`. L'efficacité du row-level security sur ces tables et son interaction avec les requêtes Cypher ne sont, à notre connaissance, ni documentées ni garanties. L'alternative (un graphe AGE par tenant) isole par schéma et non par RLS, et multiplie les schémas à migrer.
- T3 exige RLS PostgreSQL et tests d'accès croisé ; `go-platform-conventions` impose RLS par `tenant_id`, tenant positionné par transaction.
- Chaque version d'AGE cible des versions majeures précises de PostgreSQL (à vérifier), ce qui peut retarder les montées de version.

## Options envisagées
1. **(a) PostgreSQL + AGE** (vision actuelle). Avantages : Cypher pour l'exploration, un seul moteur. Inconvénients : absent des offres managées visées ; RLS incertain, précisément sur le mécanisme d'isolation exigé par T3 ; Cypher inutile pour les calculs, déjà en Go ; requêtes Cypher composées en texte (risque d'injection si mal paramétrées) ; extension au cycle de version propre.
2. **(b) PostgreSQL relationnel et graphe en mémoire.** Tables d'instantanés, de nœuds et d'arêtes avec `tenant_id`, attributs typés en JSONB, `untrusted_text` en colonne séparée, RLS forcé. Les calculs chargent un instantané complet en mémoire (listes d'adjacence en Go) ; l'exploration de voisinage (1 ou 2 sauts) se fait en SQL. Avantages : fonctionne sur toute offre PostgreSQL managée ; RLS standard, compris et testable ; un seul modèle pour calcul, preuve et affichage ; aucune dépendance nouvelle. Inconvénients : pas de parcours profond ad hoc en SQL (CTE récursives réservées aux petits cas) ; mémoire des workers dimensionnée sur le plus gros tenant ; instantanés complets coûteux pour un graphe réel scanné souvent.
3. **(c) Base graphe dédiée** (Neo4j ou équivalent : Memgraph, Neptune). Avantages : parcours natifs, outils de visualisation. Inconvénients : un composant à état de plus à exploiter, sécuriser, sauvegarder et livrer en auto-hébergé ; pas d'équivalent du RLS (isolation par un filtre dans chaque requête, ou une base par tenant, réservée à l'édition commerciale de Neo4j, à vérifier) ; Neptune limité à AWS ; données dupliquées entre PostgreSQL et la base graphe.

## Décision
Option **(b)**, derrière le port `internal/graph/ports.Store` que la vision prévoyait déjà.

Schéma (migration versionnée, livrée en M1 avec `schemas/graph/v1.json`) :
- `graph_snapshots(tenant_id, snapshot_id, environment_id, source, version, content_sha256, created_at)` : instantanés immuables, `source` vaut `design` ou `observed` ; le hash du contenu canonicalisé entre dans le dossier de preuves.
- `graph_nodes(tenant_id, snapshot_id, node_id, kind, attrs jsonb, untrusted_text jsonb, observed_at)`, clé primaire `(tenant_id, snapshot_id, node_id)`, index GIN sur `attrs` pour les filtres de E7.
- `graph_edges(tenant_id, snapshot_id, edge_id, type, src, dst, attrs jsonb)`, clés étrangères vers les nœuds du même tenant et du même instantané, index `(tenant_id, snapshot_id, src)` et `(tenant_id, snapshot_id, dst)`.
- Chaque table : `ENABLE` et `FORCE ROW LEVEL SECURITY`, politique `tenant_id = current_setting('rempart.tenant_id')::uuid` en `USING` et en `WITH CHECK` ; rôle applicatif non propriétaire, sans `BYPASSRLS` ; requêtes paramétrées uniquement.

Port (esquisse) :
```go
// internal/graph/ports
type Store interface {
	SaveSnapshot(ctx context.Context, g domain.Graph) (domain.SnapshotRef, error)
	LoadSnapshot(ctx context.Context, ref domain.SnapshotRef, lim domain.Limits) (domain.Graph, error)
	Latest(ctx context.Context, env domain.EnvironmentID, src domain.Source) (domain.SnapshotRef, error)
	// Neighborhood sert l'interface ; depth vaut au plus 2.
	Neighborhood(ctx context.Context, ref domain.SnapshotRef, node domain.NodeID, depth int) (domain.Graph, error)
}
```
Chaque méthode vérifie que le tenant du contexte est présent et égal à `ref.TenantID`. `LoadSnapshot` refuse au-delà de `Limits` (nœuds, arêtes) avec `ErrGraphTooLarge`, qui mène à une escalade et non à l'épuisement mémoire d'un worker partagé. Pas de cache entre appels en M1 ; s'il est ajouté plus tard, sa clé est `(tenant_id, snapshot_id)`.

Critères de réévaluation (un seul suffit ; seuils initiaux, à ajuster après les mesures de M5) :
- plus gros graphe de tenant au-delà de 250 000 nœuds ou de 2 500 000 arêtes ;
- chargement d'instantané au-delà de 2 s au 95e centile en production (histogramme `rempart_graph_load_seconds`) ;
- besoin produit avéré de parcours interactifs de plus de 2 sauts avec un 95e centile au-delà de 1 s, non servi par des résultats précalculés.
Si l'un est atteint : nouvel ADR comparant stockage différentiel, graphe en mémoire persistant par tenant et base graphe dédiée, derrière le même port.

Impact M0 : `docker-compose.yml` utilise l'image PostgreSQL officielle standard, épinglée (version majeure et empreinte), sans extension ; base et rôle de Temporal distincts de ceux de Rempart. Aucune table de graphe en M0.

Vérification :

| Jalon | Commande | Attendu |
|---|---|---|
| M0 | `docker compose config --images` | l'image PostgreSQL est une image officielle `postgres` |
| M0 | `grep -Eic -e 'apache/?age' -e 'create extension.*\bage\b' docker-compose.yml` | affiche `0` |
| M1 | `go test -tags=integration -run TestGraphStoreCrossTenant ./internal/graph/...` | le tenant B ne lit, n'écrit ni ne référence (clé étrangère) aucun nœud ou arête du tenant A, y compris par une requête SQL sans filtre |
| M1 | `go test -tags=integration -run TestTenantTablesForceRLS ./internal/tenancy/...` | toute table ayant une colonne `tenant_id` a `relrowsecurity` et `relforcerowsecurity` vrais dans `pg_class` ; le rôle applicatif n'a pas `BYPASSRLS` |
| M1 | `go test -run TestLoadSnapshotLimits ./internal/graph/...` | au-delà des limites : `ErrGraphTooLarge` |
| M2 | `go test -tags=integration -run '^$' -bench BenchmarkLoadSnapshot ./internal/graph/...` | graphe synthétique de 100 000 nœuds et 1 000 000 d'arêtes chargé en moins de 2 s ; mesure consignée comme référence |

## Conséquences
- Positives : portabilité sur toute offre PostgreSQL managée, en auto-hébergé et sur clouds souverains ; isolation par un mécanisme standard, vérifiable par une requête sur le catalogue ; une dépendance de moins ; image standard en développement.
- Négatives : pas de Cypher pour l'exploration ; parcours profonds uniquement en Go ; stockage des instantanés complets du graphe réel (stockage différentiel à trancher en M5) ; code de chargement et d'indexation à écrire.
- Difficile à changer : schéma des tables (migrations) ; sémantique d'instantané immuable, car les dossiers de preuves référencent des hash d'instantanés.
- Point ouvert pour M5 : chiffrement applicatif par tenant de `attrs` et `untrusted_text` (T3 exige des clés par tenant), incompatible avec les index GIN ; réutiliser l'enveloppe de l'ADR 0001 au moins pour `untrusted_text` ; a minima, chiffrement du stockage.
- Après acceptation : amender `docs/00-VISION.md` §4 et `MASTER_PROMPT.md` (« PostgreSQL + Apache AGE » devient « PostgreSQL relationnel sous RLS, calculs de graphe en Go »).

## Impact sécurité
- **T3** : RLS standard et forcé, contrôle par requête sur le catalogue, tests d'accès croisé ; l'incertitude sur le RLS des tables internes d'AGE disparaît.
- **Actif « graphe de sécurité des clients »** (§1) : présent en mémoire des workers le temps d'un calcul ; pas de vidage mémoire en production.
- **T2** : `untrusted_text` reste dans une colonne séparée, jamais lue par les calculs ni par Rego ; seuls des faits typés, extraits de façon déterministe, entrent dans `attrs`.
- **T10** (par analogie) : un tenant qui gonfle son graphe ne peut pas épuiser la mémoire d'un worker partagé, grâce aux limites de chargement.

Menaces nouvelles, à intégrer au modèle de menace par `security-reviewer` après acceptation :
- Mélange de données entre tenants dans la mémoire d'un worker, par un cache ou un état global (I). Atténuation : pas d'état global (`go-platform-conventions`), graphe chargé par calcul, contrôle du tenant au chargement, clé de cache incluant le tenant.
- Épuisement mémoire par un graphe surdimensionné, volontaire ou non (D). Atténuation : `Limits` au chargement, `ErrGraphTooLarge`, escalade.

## Réserves de la revue sécurité (D0, 2026-09-23)
Verdict de `security-reviewer` sur les ADR 0001 à 0003 : PASS avec réserves. Les réserves ci-dessous font partie de la décision acceptée ; les menaces citées sont dans `docs/02-THREAT-MODEL.md`.
- Porte de chiffrement du graphe réel, en remplacement de « a minima, chiffrement du stockage » : aucun instantané `observed` d'un client réel n'est enregistré tant que `untrusted_text` et les attributs sensibles (documents de politique, ARN) ne sont pas scellés par tenant avec l'enveloppe de l'ADR 0001, sauf ADR d'acceptation de risque signé par l'humain. Test `TestObservedSnapshotSealedPerTenant` (M5).
- L'affirmation « seuls des faits typés entrent dans `attrs` » est inexacte : `Policy.document`, les ARN, chemins et modules de `MANAGED_BY_IAC` sont des chaînes contrôlables par un attaquant et nécessaires aux calculs. `schemas/graph/v1.json` (M1) marque chaque champ texte libre, porté en Go par un type distinct sans conversion implicite ; son rendu vers le LLM passe uniquement par `UntrustedBlock`. Test `TestFactsBlockHasNoFreeText` (M1), ajouté à la vérification de T2.
- Le tenant est positionné par transaction seulement, jamais pour la session (T23). Test `TestTenantSettingIsTransactionLocal` (M1, avec les premières tables).
- `Neighborhood` plafonne aussi le nombre de nœuds renvoyés, en plus de la profondeur 2 (T24). Test `TestNeighborhoodLimits`.
