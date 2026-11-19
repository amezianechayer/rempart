# 0010. Graphe de conception étendu, atteignabilité et STRIDE versionné

- Statut : proposé le 2026-11-19 par `architect`, à accepter par l'humain avant la phase tests de M2-T02 (remplacer cette ligne par « Statut : accepté le <date> (décision humaine) »).
- Date : 2026-11-19
- Jalon : M2 (étape humaine H0-M2.3). M2-T02 `graph-reach` met en oeuvre D1 à D8 ; M2-T04 `threat-stride` met en oeuvre D9 à D12 ; M2-T05 `l2-loop` consomme D3 (monotonie de `FromGraph`, `SubsetOf`) et D11 (delta dans la sortie de L2).
- Base : branche `main-6cpq6q`, tête `c79d1f0`.
- Sources : `prompts/M2.md` (critères 3 et 4, livrables `internal/graph/reach` et `internal/threat`) ; `docs/plans/M2-overview.md` (décisions D8 à D10, section 3.1, fiches M2-T02 et M2-T04, section 7 ligne 0010, Q3, menaces T107 à T115 de la section 10, risques R2, R4, R5 de la section 11) ; skills `security-graph-attack-paths` (et `references/graph-schema.md`, `references/effective-permissions.md`), `multicloud-networking` (section atteignabilité), `policy-as-code` (règle 2) ; ADR 0003 (`Limits`, `content_sha256`), ADR 0006 (D2, A2.3) ; `docs/02-THREAT-MODEL.md` (T2, T3, T5, T24) ; code : `schemas/graph/v1.json`, `internal/graph/{schema.go,domain}`, `internal/design/{build.go,placement.go}`, `internal/threat` (vide), `cmd/rempart/design.go`, `cmd/rempart-worker/l1.go`, `internal/loops/domain/findings.go`, `internal/llm/schema/decode.go`.

## Contexte

L2 refuse ou révise une architecture d'après des faits calculés en Go (skill `policy-as-code`, règle 2 : Rego décide sur des faits, il ne recalcule pas un graphe). Trois de ces faits manquent :

1. **L'atteignabilité.** `internal/graph/reach` n'existe pas. Le skill `multicloud-networking` exige une seule implémentation pour L2 (conception), L5 (vérification après déploiement) et L6 (chemins d'attaque), et deux propriétés : ajouter une règle deny ne crée jamais de chemin (critère 3 de `prompts/M2.md`), retirer une autorisation non plus.
2. **Un graphe capable de porter les pièges du jalon.** `schemas/graph/v1.json` connaît 7 types de nœuds et 4 types d'arêtes, sans identité, permission, attribut de sécurité de cluster ni IP publique de calcul. Les trappes IAM `*` (3), API de cluster publique (6) et compte de service `cluster-admin` à clé statique (14) de `evals/design` ne sont pas représentables.
3. **Un modèle STRIDE versionné et son delta** (critère 4) : `internal/threat` est vide.

État constaté à `c79d1f0` : aucun graphe n'est persisté. Aucune table n'existe (Q6 : aucune en M2) ; le graphe est construit par `cmd/rempart` et par `cmd/rempart-worker` (`l1.go`) après la boucle L1, hors de tout historique Temporal ; seuls des fichiers de test et des sorties de commande contiennent des graphes. Le scénario de référence donne 12 nœuds et 13 arêtes (`TestReferenceScenarioGraphValid`).

Ces choix sont difficiles à inverser : la sémantique de l'atteignabilité sera reprise par L5, L6 et les golden ; le schéma du graphe deviendra l'entrée de L3 et une pièce du dossier de preuves (A3) ; le vocabulaire des permissions fixe ce que L3 devra traduire ; identifiants de menace, révision du graphe et forme du delta entreront dans les preuves (T5, T113 proposée).

Contraintes : cœur déterministe, aucune décision de sécurité par un LLM (aucun appel de modèle dans L2 en M2, Q1) ; texte libre non fiable et exclu des calculs (T2, T111 proposée) ; calcul borné (T24, T112 proposée) ; tenant vérifié aux frontières (T3) ; `internal/graph/reach` n'importe que la bibliothèque standard et `internal/graph/...` (critère 3 de M2-T02) ; rien dans la chaîne de L2 n'importe `internal/llm` (critère 3 de M2-T05).

## Options envisagées

### Question 1 : modèle d'atteignabilité

1. **(1a) Ensemble de sauts « allow moins deny », deny prioritaire, chemins par parcours en largeur borné (retenue).** Règles sans ordre ; un saut existe pour les ports autorisés par au moins une règle allow et refusés par aucune règle deny. Avantages : monotonie par construction (D3) ; coût quasi linéaire ; un chemin canonique par cible, donc aucune énumération exponentielle ; résultat indépendant de l'ordre des entrées. Inconvénients : l'ordre propre à certains pare-feu (NACL AWS, priorités NSG Azure) doit être résolu avant `reach` (L6) ; sur-approximations assumées (D2).
2. **(1b) Énumération de chemins sur règles ordonnées (premier qui correspond).** Fidèle aux NACL et aux NSG. Refusée : le graphe de conception n'a pas d'ordre entre ses arêtes, il faudrait en inventer un ; le résultat dépend de la position d'insertion, donc C3 doit être énoncé pour chaque position, et un deny placé après un allow est sans effet, ce qui trompe le relecteur ; surtout, l'énumération de tous les chemins est exponentielle et doit être tronquée : une troncature masque des chemins (échec ouvert, T24) et rend la liste rendue non monotone (retirer une règle fait apparaître un chemin que la borne coupait).
3. **(1c) Calcul en Rego.** Refusée : contraire à la règle 2 du skill `policy-as-code` ; deuxième implémentation non partagée avec L5 et L6 ; coût non borné dans l'évaluateur ; monotonie à prouver dans un autre langage.

### Question 2 : forme du schéma

1. **(2a) Extension en place de `schemas/graph/v1.json` (retenue).** Aucun graphe persisté ni lu par une autre version du code : rien à migrer ; golden et fichiers de test mis à jour en phase tests de M2-T02. Inconvénient : deux formes auront porté `version: "1"`, sans effet tant qu'aucune n'a quitté le dépôt.
2. **(2b) Nouvelle version `v2`.** Refusée en M2 : deux schémas, deux lecteurs et un convertisseur pour des graphes que personne n'a stockés ; aucun gain de sûreté.

### Question 3 : permissions

1. **(3a) Actions IAM concrètes du fournisseur** (`s3:GetObject`, `Microsoft.Storage/...`). Refusée : L2 est indépendant du fournisseur ; vocabulaire ouvert de milliers d'actions par cloud, que les politiques ne jugent pas de façon fermée ; canal de valeurs techniques que le LLM ne doit jamais produire (`prompts/M1.md`, ADR 0006 D2) ; ces noms appartiennent à la traduction de L3.
2. **(3b) Aucune permission en M2.** Refusée : les trappes 3 et 14, les contrôles IAM-001 à IAM-007 et K8S-030 ne sont pas exprimables.
3. **(3c) Vocabulaire abstrait fermé `read`, `write`, `admin`, `*` (retenue).**

### Question 4 : STRIDE, révision et delta

1. **(4a) Catalogue codé, statut dérivé des findings des contrôles, révision par empreinte des `Facts`, delta en JSON à ordre total (retenue).**
2. **(4b) Menaces rédigées ou classées par un LLM.** Refusée : décision de sécurité par un modèle (`llm-safety`, règle 1), résultat non reproductible, delta inutilisable comme preuve.
3. **(4c) Statut déclaré dans le graphe ou à la main.** Refusée : un `mitigated` sans lien avec un contrôle vérifié n'atteste rien, et un graphe candidat pourrait le forger (T111).
4. **(4d) Révision par compteur ou horodatage de stockage.** Refusée : dépend d'un stockage absent en M2 (Q6) ; deux calculs du même graphe donneraient deux révisions ; non recalculable par un auditeur.

## Décision

### D1. Atteignabilité : ensemble de sauts « allow moins deny » (option 1a)

- **Modèle.** `Model{Nodes, Rules}`. Le nœud `internet` est implicite, jamais listé dans `Nodes`. Règle `Rule{Action, Src, Dst, Proto, Ports, Sources}` :
  - `Action` : `allow` ou `deny` ; `Proto` : `tcp` ou `udp` ; `Ports` : une plage de `From` à `To`, avec `1 <= From <= To <= 65535`.
  - allow : `Src` est un nœud ou `internet`, `Dst` un nœud, jamais `*` ; `Sources` permis seulement si `Src` vaut `internet` : préfixes canoniques (bits d'hôte nuls, sans zone, pas d'IPv4 encapsulée en IPv6) ; liste vide : tout Internet.
  - deny : `Src` est un nœud, `internet` ou `*` ; `Dst` un nœud ou `*` ; jamais de `Sources` en M2 (un deny vaut pour toute source ; un deny restreint à des sources viendra par amendement, avec sa preuve de monotonie, pour L6).
  - `ErrInvalidModel` (message fixe, aucune donnée citée) : action, protocole ou plage hors domaine ; extrémité inconnue ; `Dst` égal à `internet` (sortie vers Internet hors modèle en M2) ; `Src` égal à `Dst` ; sources hors des cas permis ou non canoniques ; identifiant de nœud vide, dupliqué, `internet` ou `*` dans `Nodes`.
- **Sémantique.** Le modèle définit un ensemble de tuples (source, destination, protocole, port, adresse d'origine) ; l'adresse ne compte que pour les sauts depuis `internet`. Un tuple est permis s'il est couvert par au moins une règle allow et par aucune règle deny (`*` correspond à tout nœud). **Aucun ordre** entre règles : deny l'emporte toujours.
- **Sauts (`Hop`)**, forme canonique unique, indépendante de l'ordre de `Nodes` et de `Rules` :
  - saut interne : un `Hop` par triplet (`Src`, `Dst`, `Proto`) dont l'ensemble de ports permis est non vide ; `Ports` triés et fusionnés (plages adjacentes réunies) ; `World` faux, `Sources` vide ;
  - saut depuis `internet` : pour chaque clé de source (tout Internet, ou un préfixe cité par une règle allow), ports permis = union des plages des règles allow qui citent cette clé (règle sans source : clé « tout Internet »), moins les plages deny ; les clés de même ensemble de ports non vide forment un `Hop` ; `Sources` est l'agrégation canonique de leurs préfixes (sans doublon, préfixes inclus retirés, voisins fusionnés) ; `World` est vrai si la clé « tout Internet » en fait partie ou si l'agrégation couvre tout l'espace IPv4 ou tout l'espace IPv6, et `Sources` est alors vide ;
  - tri total : `Src`, `Dst`, `Proto`, `World` vrai d'abord, première source, premier port.
- **Chemins.** Depuis `internet` seulement en M2 (identité ou workload compromis supposés : M6). Parcours en largeur sur les sauts, quels que soient protocole et source ; un `Path{Target, Nodes}` par nœud atteint : le plus court, chaque prédécesseur choisi au plus petit identifiant parmi ceux de profondeur minimale. Un chemin suppose que chaque nœud intermédiaire peut initier les flux qui en partent (pivot) : sur-approximation voulue ; un chemin de plus d'un saut est une **hypothèse** (skill `security-graph-attack-paths`, point 4), jamais un fait de compromission. Un chemin ne porte pas de source : son premier saut la porte.
- **Déterminisme.** Aucune sortie ne dépend de l'ordre d'itération d'une `map` ; `TestReachDeterministic` permute les entrées et compare les octets JSON du résultat.
- **Une seule implémentation** pour L2, L5 et L6 : L5 et L6 étendent `FromGraph` (D2) par amendement, sans toucher à `Compute` ; toute évolution de `Compute` garde les tests de D3. L'ordre propre à un fournisseur (NACL, priorités NSG) sera résolu par le collecteur de L6 en règles sans ordre ; un cas impossible à résoudre sans perte est marqué `ambiguous` et lu comme allow (sur-approximation), jamais tranché par un LLM.

### D2. Correspondance graphe vers modèle : table fermée de `FromGraph`

`FromGraph` lit un `graphdomain.FactsGraph`, jamais un `Graph` : le texte libre ne peut pas y entrer (T111). Les nœuds du modèle sont tous les nœuds sauf `Internet`, `Network`, `Identity` et `Account`. Seules les lignes suivantes produisent des règles, **toutes allow** :

| # | Fait du graphe | Règle produite |
|---|---|---|
| R1 | arête `EXPOSES` de `s` vers `internet` | allow `internet` vers `s`, protocole et ports de l'arête, `Sources` = `allowed_sources` |
| R2 | arête `CAN_REACH` de `s` vers `d`, `d` différent de `internet` | allow `s` vers `d`, protocole et ports de l'arête ; si `s` vaut `internet`, comme R1 |
| R3 | `DataStore` à `public_access: true` | allow `internet` vers le nœud, tout Internet ; tcp/443 pour `object_storage` et `dataset`, tcp/1-65535 pour `managed_db` (port du moteur inconnu à la conception) |
| R4 | `K8sCluster` à `api_public: true` | allow `internet` vers le cluster, tcp/443 (API des services managés), `Sources` = `api_allowed_sources` |
| R5 | `Compute` à `public_ip: true` | allow `internet` vers le nœud, tcp/1-65535 et udp/1-65535, tout Internet (le graphe de conception n'a pas de règle de pare-feu) |
| R6 | arête `MEMBER_OF` d'un `K8sWorkload` `w` vers un `K8sCluster` `c` dont `network_policy_default_deny` n'est pas vrai | allow `c` vers `w` et `w` vers `c`, tcp et udp, 1-65535 (les pods se voient) |

- `http` et `https` sont lus comme `tcp`. Attribut absent : valeur la plus large (protocole absent : tcp et udp ; ports absents : 1-65535), défense en profondeur puisque D6 les rend requis.
- **Aucune règle deny implicite en M2.** Écart à la section 3.1 du plan (« deny Internet vers tiers data et mgmt ») : dans le graphe de conception, un allow direct depuis Internet vers un membre du tier data ou mgmt est toujours une violation (refusée par `domain.Validate` pour `EXPOSES`, jugée par DATA-001, NET-012, NET-014) ; un deny implicite ne ferait que la cacher à l'invariant Go de L2 (`L2-INTERNET-TO-SENSITIVE`), qui doit rester indépendant du pack (T108). L'absence de route vers Internet du tier data est une garantie que L3 construira et que L5 vérifiera (« connectivité interdite effectivement bloquée »), pas un fait du graphe de conception.
- **Faits non réseau** : `STORES`, `RUNS_AS`, `HAS_PERMISSION` et `MEMBER_OF` hors R6 ne produisent aucun saut. Une donnée est atteinte quand l'un de ses hôtes (source d'une arête `STORES`) ou elle-même est la cible d'un chemin : jointure faite par les consommateurs (faits dérivés de M2-T03, STRIDE de M2-T04), pas par `reach`, qui reste un calcul de flux.
- `CAN_REACH` vers `internet` (sortie) n'ouvre aucun chemin entrant : ignorée en M2, consignée pour la menace I (exfiltration) de M6.
- Un attribut contradictoire ne retire jamais un saut ; les contradictions sont refusées par `domain.Validate` (D6).
- R3 et R5 sont des sur-approximations monotones. Une règle « exposé seulement par ses arêtes » ferait d'un retrait d'`EXPOSES` un élargissement (R5 reviendrait), ce qui casserait D3 et T110. Conséquence assumée : un calcul à IP publique ou une base publique est jugé ouvert sur tous ses ports ; le correctif est l'équilibreur de charge ou `make_private` (skill `multicloud-networking` : pas de `0.0.0.0/0` en entrée hors LB ou WAF déclarés).
- Garde contre l'oubli : `TestGraphSchemaExtension` vérifie que chaque type d'arête et chaque attribut booléen du schéma figure dans la table de classement de `FromGraph` (lu par une ligne R1 à R6, ou déclaré non réseau) ; un fait nouveau non classé fait échouer le test (T116 proposée).

### D3. Monotonie (critère 3)

- **Lemme.** Soit `A(m)` et `D(m)` les ensembles de tuples couverts par les règles allow et deny de `m`. Si `A(m')` est inclus dans `A(m)` et `D(m')` contient `D(m)`, les sauts de `m'` sont inclus (tuple par tuple) dans ceux de `m` ; tout nœud atteint dans `m'` l'est dans `m`, à une profondeur au plus égale dans `m` ; chaque pas d'un chemin de `m'` est un saut de `m`. Cas particuliers : ajouter une règle deny (P1), retirer une règle allow (P2), rétrécir une règle allow en ports ou en sources (P3).
- **`SubsetOf`.** `r.SubsetOf(o)` est vrai si et seulement si (1) les tuples de `r` sont inclus dans ceux de `o`, calcul par intervalles de ports et d'adresses, exact (correct et complet, y compris quand une adresse de `r` n'est couverte que par l'union de préfixes de `o` portés par des sauts différents) ; (2) toute cible de `r` est cible de `o` et chaque pas de son chemin est un saut de `o`, protocole quelconque.
- **Bornes.** La propriété porte sur les résultats rendus. Si `Compute(m)` réussit, `Compute(m')` ne peut échouer que par `ErrGraphTooLarge` sur `MaxRules` (une règle de plus) ou `MaxDepth` (chemin plus long), jamais par une troncature, qui n'existe pas (D4). Une erreur mène à l'escalade ; elle n'est jamais une preuve d'absence de chemin.
- **Monotonie de `FromGraph`.** Toute restriction du graphe rétrécit `A` : `public_access`, `api_public` ou `public_ip` passés à faux ; `network_policy_default_deny` passé à vrai ; sources ajoutées à une liste vide, ou retirées d'une liste qui reste non vide ; arête `EXPOSES` ou `CAN_REACH` retirée ou réduite en ports. Vider une liste de sources est un élargissement. `FromGraph` ne produit aucun deny en M2. C'est la base de `TestRevisionNeverWidens` (M2-T05, T110), qui compare les résultats par `SubsetOf`.
- **Tests de M2-T02.** `TestDenyNeverAddsPath` (P1) et `TestRemoveAllowNeverAddsPath` (P2, P3), propriétés `pgregory.net/rapid`, 1 000 tirages au critère : modèles de 2 à 12 nœuds et de 0 à 40 règles, deux protocoles, `*` dans les deny, plages chevauchantes tirées dans 1 à 64, sources emboîtées, voisines et `0.0.0.0/0` ; `MaxDepth` au moins égal au nombre de nœuds, pour que le générateur n'atteigne aucune borne. Chaque tirage compare `Compute` à un **oracle naïf** écrit dans le fichier de test (énumération des ports 1 à 64 et des clés de source, point fixe d'atteignabilité) sur `m` et sur `m'`, vérifie l'inclusion sur l'oracle, puis l'accord de `SubsetOf` : la propriété ne repose pas sur `SubsetOf` seul. `TestReachDenyOverridesAllow` couvre les cas fixes (deny avant ou après l'allow dans la liste, deny `*`, deny d'une partie de plage).

### D4. Bornes du calcul (T24, T112 proposée)

- `Limits{MaxNodes, MaxRules, MaxDepth, MaxPaths}`, toutes strictement positives : une valeur nulle ou négative donne `ErrInvalidModel`, aucun défaut implicite. `reach.DefaultLimits` : `MaxNodes` 10 000 et `MaxRules` 50 000 (maxima du schéma), `MaxDepth` 32, `MaxPaths` 10 000.
- `MaxNodes` porte sur `Nodes`. `MaxRules` compte les couples (règle, source), une règle sans source comptant pour un : il borne aussi le nombre de préfixes. Ces deux contrôles précèdent toute allocation proportionnelle à l'entrée. `MaxPaths` borne le nombre de cibles atteintes (un chemin par cible), `MaxDepth` la longueur d'un chemin.
- Au-delà d'une borne : `ErrGraphTooLarge` (message fixe), **jamais un résultat partiel ni tronqué**. Dans L2, cette erreur mène à l'escalade ; le code est fixé par l'ADR 0012 (`payload_too_large` de D14 du plan proposé).
- Coût : tri des règles par triplet en `O(R log R)`, parcours en `O(N + H)`, chemins en `O(N x MaxDepth)` identifiants partagés. Mesure consignée dans `docs/STATUS.md` en fin de M2-T02 (temps et mémoire aux limites par défaut) ; au-delà de 2 s ou de 256 Mio sur le poste de développement, les défauts sont abaissés par amendement.
- Bornes en amont inchangées : `maxItems` du schéma (10 000 nœuds, 50 000 arêtes), graphe candidat de 64 Kio au plus (D14 du plan).

### D5. Schéma : v1 étendu en place (option 2a) et règle de version

- L'extension de D6 est faite dans `schemas/graph/v1.json` ; `version` reste `"1"`, `$id` inchangé. Golden, `internal/design/testdata` et sorties attendues sont mis à jour en phase tests de M2-T02 (R4).
- **Règle de version.** Dès qu'un graphe est persisté ou publié (table PostgreSQL, dossier de preuves, artefact lu par une autre version du code), toute modification du schéma crée une nouvelle version et un lecteur de la précédente. Un historique Temporal n'est pas un stockage durable au sens de cette règle ; mais, à partir de M2-T05, la sortie de L2 contient un graphe et une sortie d'activité enregistrée doit rester décodable au rejeu (T16) : tout changement de forme du graphe passe alors par `workflow.GetVersion`.

### D6. Contenu de l'extension

| Élément | Ajout |
|---|---|
| Types de nœuds | `Identity`, `Account` |
| Types d'arêtes | `RUNS_AS` (`Compute`, `K8sCluster` ou `K8sWorkload` vers `Identity`) ; `HAS_PERMISSION` (`Identity` vers `DataStore`, `Account` ou `K8sCluster`) |
| Identifiants | préfixes `id:` (exactement les `Identity`) et `acct:` (exactement les `Account`) ; motif `^(internet\|(net\|wl\|lb\|data\|id\|acct):[a-z0-9][a-z0-9.-]{0,80})$` |
| `subtype` | `role` (identité de workload au niveau du cloud, traduite par L3) et `k8s_service_account` |
| Attributs de nœud | `credential` (`workload_identity`, `static_key`) ; `public_ip` (booléen) ; pour un cluster : `api_allowed_sources` (au plus 64 `source_cidr`), `audit_log`, `secrets_encryption`, `network_policy_default_deny`, `admission_policy`, `workload_identity` (booléens) |
| Attribut d'arête | `actions` : ensemble non vide et sans doublon de `read`, `write`, `admin`, `*` |
| Attributs requis | `Identity` : `subtype` (`role` ou `k8s_service_account`), `cloud`, `credential` ; `Account` : `cloud` ; `Compute` : `public_ip` en plus ; `K8sCluster` : les cinq booléens de cluster en plus d'`api_public` ; `HAS_PERMISSION` : `actions` ; `EXPOSES` et `CAN_REACH` : `protocol`, `port_from`, `port_to` |
| Sources | `$defs/source_cidr` : préfixe IPv4 canonique de longueur 1 à 32 ; « tout Internet » s'écrit **seulement** par une liste vide ou absente, ce que dit la description du schéma (ADR 0006 A2.3, au niveau du graphe) ; `Build` réécrit une source `0.0.0.0/0` de l'IR en liste vide (équivalence, pas élargissement) |
| Texte libre | obligation (cp) : `$defs/free_text` exclut par motif `\p{Cc}` et les bidirectionnels (U+061C, U+200E, U+200F, U+202A à U+202E, U+2066 à U+2069) |

`domain.Validate` ajoute, avec des erreurs à message fixe : types des extrémités de `RUNS_AS` et `HAS_PERMISSION` ; préfixe `id:` si et seulement si `Identity`, `acct:` si et seulement si `Account` ; `port_from` au plus égal à `port_to` ; `EXPOSES` partant seulement d'un `LoadBalancer` ou d'un `Compute` ; cohérence d'un équilibreur : `public` vrai si et seulement si une arête `EXPOSES` en part, chaque écouteur a son `EXPOSES` de même protocole et port et réciproquement (sinon un équilibreur public sans `EXPOSES` échapperait à R1) ; `api_allowed_sources` non vide seulement si `api_public` est vrai. Aucun attribut de sécurité n'a trois états : il est requis là où il s'applique.

Hors extension : `Policy`, `Secret`, `SecurityRule`, `CAN_ASSUME`, `MANAGED_BY_IAC`, `ambiguous` sur `HAS_PERMISSION` (L3, L6, par amendement ou version suivante) ; sources IPv6 : le graphe v1 reste IPv4 et `Build` refuse une IR à source IPv6 (échec fermé), `reach` accepte déjà les deux familles.

### D7. Défauts sûrs et identités posés par `Build`

- Cluster : `api_public` faux, `api_allowed_sources` absent, les cinq booléens de cluster à vrai. `Compute` : `public_ip` faux. Le placement est inchangé.
- Une `Identity` par workload qui exécute du code (`K8sCluster`, `Compute`, `K8sWorkload`) : identifiant `id:<id du workload>`, `subtype` `k8s_service_account` pour un `K8sWorkload` et `role` sinon, `cloud` du workload (du cluster pour un `K8sWorkload`), `credential` `workload_identity`, une arête `RUNS_AS`. `DataStore` et `LoadBalancer` n'ont pas d'identité.
- `HAS_PERMISSION` `[read, write]` de l'identité d'un workload vers chaque `DataStore` qu'il héberge (arête `STORES` dont il est la source) ou qu'il atteint (arête `CAN_REACH` vers un `DataStore`), et vers aucun autre. Jamais `admin`, jamais `*`, jamais un `Account` ; `Build` ne crée aucun `Account` en M2.
- Scénario de référence : 4 identités (`id:app-cluster`, `id:gitops`, `id:legacy-vms`, `id:obs`), 4 `RUNS_AS`, 1 `HAS_PERMISSION` (`id:legacy-vms` vers `data:customer-db`) ; le graphe passe de 12 nœuds et 13 arêtes à **16 nœuds et 18 arêtes**. `FromGraph` en tire : Internet vers `lb:app-cluster-443` (tcp/443, tout Internet), ce LB vers `wl:app-cluster` (tcp/443), `wl:app-cluster` vers `wl:legacy-vms` (tcp, 5432 et 9100) ; aucun saut direct depuis Internet hors du LB.

### D8. Permissions abstraites (option 3c)

- `read` : lecture du plan de données de la ressource. `write` : écriture et suppression dans le plan de données. `admin` : gestion du plan de contrôle de la ressource (configuration, politique d'accès, suppression de la ressource, attribution de droits). `*` : toute action présente ou future ; représentable pour décrire un piège (IAM-001, critique), jamais produit par `Build`.
- **Élargissement.** Fermeture : `read` vaut {read}, `write` vaut {write}, `admin` vaut {read, write, admin} (un administrateur peut s'accorder le reste), `*` vaut tout. Un ensemble `A'` élargit `A` si la fermeture de `A'` n'est pas incluse dans celle de `A`. Cette définition sert à `TestRevisionNeverWidens` (T110) et aux menaces E de D9.
- **Aucune action IAM concrète avant L3** : ni ARN, ni nom de rôle, ni nom d'action dans le graphe de conception ; le LLM n'en produit jamais (ADR 0006 D2). La traduction vers les actions d'un fournisseur sera une table fermée, versionnée et testée par fournisseur, fixée par l'ADR de L3 : aucun joker (`s3:*`, `*`), aucune action d'une autre catégorie, échec de L3 pour une permission sans traduction connue (T117 proposée).

### D9. STRIDE : catalogue `stride-v1`, statut dérivé des contrôles

- **Entrée du catalogue** (code Go, `internal/threat/catalog.go`) : identifiant `STRIDE-<S|T|R|I|D|E>-<nnn>` ; catégorie (`spoofing`, `tampering`, `repudiation`, `information_disclosure`, `denial_of_service`, `elevation_of_privilege`) ; type de cible (`node` ou `flow`) ; prédicat déterministe sur les faits (type, attributs, faits tirés de `reach`) ; gravité fixe (`critical`, `high`, `medium`, `low`) ; liste triée des contrôles qui l'atténuent (`control_id` du pack, `L2-INTERNET-TO-SENSITIVE`, codes `CIDR_*`).
- **Couverture, STRIDE par élément.** Processus (`Compute`, `K8sCluster`, `K8sWorkload`, `LoadBalancer`) : S, T, R, I, D, E ; `DataStore` : T, R, I, D ; `Identity` : S, R, E ; `Account` : R, E ; flux (`EXPOSES`, `CAN_REACH`) : T, I, D. `Internet` (source) et `Network` (conteneur) n'en reçoivent pas. Chaque élément reçoit au moins une menace par catégorie applicable (`TestStrideCoversEveryNodeAndFlow`), donc chaque couple (type, catégorie) a une entrée générique. Les chemins transitifs depuis Internet vers une donnée sensible deviennent des menaces `information_disclosure` dont la règle les marque comme hypothèses (Q3 du plan).
- **Menace** : identifiant `<règle>@<cible>` (cible : identifiant de nœud ou d'arête, grammaires fermées du schéma), stable d'une version du graphe à l'autre tant que la cible garde son identifiant ; aucun champ de texte libre.
- **Statut.** Ressources d'une cible : le nœud ; pour un flux, l'arête et ses deux extrémités. `mitigated` si et seulement si (1) l'entrée cite au moins un contrôle, (2) tous ses contrôles ont été évalués (`Pack.Controls`, D12), (3) aucun finding de ces contrôles, de gravité quelconque, ne porte sur ces ressources (`Finding.Resource`). Sinon `open`. Une entrée sans contrôle donne une menace toujours ouverte ; un contrôle retiré du pack rouvre la menace au lieu de la laisser atténuée (T108).
- `accepted` est hors de `stride-v1` et du schéma v1 de menace : il arrivera avec les exceptions humaines datées et signées (M4).
- Toute modification d'une entrée change `CatalogVersion` (`stride-v2`) ; l'empreinte du catalogue est figée par un test à côté de la constante. Un seul catalogue dans le binaire.

### D10. Révision du graphe

- `Revision` = SHA-256, en 64 caractères hexadécimaux minuscules, de la forme canonique RFC 8785 (JCS) du `FactsGraph` : nœuds triés par `id`, arêtes triées par `id`, ensembles d'attributs (`behind`, `regulation`, `allowed_sources`, `api_allowed_sources`, `actions`, et `listeners` par protocole puis port) triés et sans doublon, `path` gardé dans son ordre. Sur ce sous-ensemble (chaînes ASCII à grammaire fermée, entiers, booléens), JCS s'obtient avec la bibliothèque standard ; un vecteur figé dans `TestGraphRevisionStable` protège l'encodage. Un auditeur la recalcule avec toute implémentation de JCS (T5, T113).
- La révision inclut `version`, `tenant_id` et `source` et **exclut** tout texte libre : deux graphes qui ne diffèrent que par une justification ont la même révision, ce qui est voulu (T111). Ce n'est pas l'empreinte du document : `content_sha256` de l'ADR 0003 (graphe entier) reste l'empreinte de stockage et de preuve.

### D11. Modèle et delta : JSON à ordre total, `schemas/threat/v1.json`, décodage strict

- Modèle : `{schema_version: "1", catalog, tenant_id, graph_revision, pack_digest, threats}` ; menace : `{id, rule, category, target, target_type, severity, status, controls}` ; menaces triées par `id`, `controls` triés ; tableau vide écrit `[]`, jamais `null`.
- Delta : `{schema_version, catalog, tenant_id, pack_digest, from, to, added, removed, changed}` ; appariement par `id` ; `changed` : `{id, from, to}` pour un même `id` dont un champ diffère ; chaque liste triée par `id`. Deux modèles égaux : listes vides et `from` égal à `to`.
- `Diff` refuse un tenant différent (`ErrTenantMismatch`, T3), un catalogue différent (`ErrCatalogMismatch`), une empreinte de pack différente (`ErrPackMismatch`) : un delta n'attribue au graphe que des changements du graphe ; pour comparer à un modèle ancien, on le recalcule depuis son graphe.
- Sérialisation par `encoding/json` sur des structures à champs ordonnés : sortie identique à l'octet d'une exécution à l'autre (`TestDeltaSerializationGolden`) ; la canonicalisation RFC 8785 avant signature revient au dossier de preuves (M4, T5).
- `schemas/threat/v1.json` : un fichier, `$defs` `model` et `delta` compilés séparément, `additionalProperties: false` partout, identifiants, révisions et empreintes contraints par motif, `status` limité à `open` et `mitigated`.
- `DecodeModel` et `DecodeDelta` : taille bornée (16 Mio), UTF-8 valide, clé en double refusée par une lecture des jetons, validation contre le schéma (qui refuse une clé de casse inexacte, que `encoding/json` accepterait), décodage avec `DisallowUnknownFields` ; erreurs à message fixe. Le contrôle des doublons est une copie locale de celui de `internal/llm/schema/decode.go`, car `internal/threat` n'importe pas `internal/llm` (critère 3 de M2-T05).
- `Analyze` refuse un graphe au-delà de `reach.DefaultLimits` et un modèle de plus de 20 000 menaces (`reach.ErrGraphTooLarge`).
- Le delta du graphe initial au graphe final entre dans la sortie de L2 (`ThreatDelta`), futur élément du dossier de preuves (A3).

### D12. Interfaces Go (écarts à la section 3.1 du plan)

```go
package domain // internal/graph/domain
func FactsOf(g Graph) FactsGraph // Facts(g) devient json.Marshal(FactsOf(g))

package reach // internal/graph/reach
var DefaultLimits = Limits{MaxNodes: 10000, MaxRules: 50000, MaxDepth: 32, MaxPaths: 10000}
func FromGraph(g domain.FactsGraph) (Model, error) // table de D2, allow seulement en M2
func Compute(m Model, l Limits) (Result, error)     // D1, D4 : ErrInvalidModel, ErrGraphTooLarge
func (r Result) SubsetOf(o Result) bool             // D3, exact

package threat // internal/threat
type Pack struct{ Digest string; Controls []string } // empreinte du pack embarqué et contrôles évalués (invariant Go et codes CIDR compris)
type Model struct{ SchemaVersion, Catalog, TenantID, GraphRevision, PackDigest string; Threats []Threat }
type Delta struct{ SchemaVersion, Catalog, TenantID, PackDigest, From, To string; Added, Removed []Threat; Changed []Change }
var ErrTenantMismatch, ErrCatalogMismatch, ErrPackMismatch error
func Revision(g graphdomain.FactsGraph) (string, error)
func Analyze(g graphdomain.FactsGraph, findings []loopsdomain.Finding, p Pack) (Model, error)
```

Les autres signatures de la section 3.1 sont inchangées. L'empreinte du pack (SHA-256 des fichiers `.rego` embarqués hors `_test.rego`, triés par chemin) est calculée par l'adaptateur OPA de M2-T03 ; l'ADR 0011 la reprend.

## Conséquences

- Positives : C3 est une propriété du calcul, testée contre un oracle indépendant ; aucun résultat tronqué ; une seule sémantique pour L2, L5 et L6 ; pièges IAM et Kubernetes représentables sans vocabulaire de fournisseur ; aucune décision n'emprunte au texte libre (entrées typées `FactsGraph`) ; delta reproductible, recalculable, lié au tenant, au catalogue et au pack ; aucune migration.
- Négatives : sur-approximations (R3, R5, R6, pivot) qui ajoutent findings et menaces ouvertes sur les graphes candidats ; nombreuses menaces génériques toujours ouvertes ; un texte libre de l'IR à caractère de contrôle (saut de ligne compris) ou bidirectionnel fait désormais refuser `Build` (risque 4) ; golden, `make l1-demo` et `TestReferenceScenarioGraphValid` changent (16 nœuds, 18 arêtes, R4) ; copie locale du contrôle des clés JSON en double.
- Difficile à changer : sémantique « allow moins deny sans ordre » et table de `FromGraph` (L5, L6, golden) ; vocabulaire `read`, `write`, `admin`, `*` (traduction de L3) ; identifiants `STRIDE-x-nnn@cible` et forme du delta (preuves) ; algorithme de révision (recalcul par un auditeur).

## Risques résiduels

1. **Faits absents.** Le graphe de conception ne porte ni routes, ni NACL, ni groupes de sécurité : `reach` dit ce que la conception autorise, pas ce que le cloud fera. Parade : L3 génère les règles depuis les arêtes, L5 vérifie la connectivité interdite, L6 reprend `reach` avec une table étendue.
2. **Fait non lu** (T116 proposée) : attribut ou type ajouté plus tard sans ligne dans D2. Parade : classement exhaustif testé, aucun deny implicite.
3. **Faux positifs des sur-approximations** sur les graphes candidats (R5 du plan) : révision ou escalade en plus, jamais un passage silencieux.
4. **(cp) et L1.** Un modèle réel qui écrit un saut de ligne dans `purpose` ou `justification` fait échouer la chaîne L1 vers L2 (`Build` refusé). À mesurer en phase tests de M2-T02 sur les cas de `evals/intent` ; si un cas casse, deux options pour l'humain : refuser ces caractères dès le brouillon en L1 (correction ciblée), ou admettre `\t` et `\n` dans le motif, C1 et bidirectionnels restant refusés.
5. **IPv6** : une restriction de source IPv6 légitime fait refuser `Build` jusqu'à la version suivante du schéma (échec fermé).
6. **Permissions abstraites** : perte de précision (un `read` sur tout un bucket) et traduction élargie possible en L3 (T117 proposée).
7. **Qualité du catalogue STRIDE** : prédicats et contrôles écrits à la main ; une liste de contrôles trop large rendrait `mitigated` trop facile. Parade : statut ouvert par défaut, empreinte figée, relecture humaine du catalogue avec les skills (étape H-skills).
8. **Deny restreint à des sources** non pris en charge : nécessaire à L6, par amendement avec sa preuve.

## Impact sur le modèle de menace

Menaces existantes :
- **T24** : `Limits` en nœuds, couples (règle, source), profondeur et cibles ; contrôle avant allocation ; `ErrGraphTooLarge` puis escalade, jamais de troncature. Ajouter `TestReachLimits` à la colonne « Vérification ».
- **T3** : tenant dans la révision, le modèle et le delta ; `Diff` refuse deux tenants (`TestDeltaRefusesCrossTenant`).
- **T2** : `FromGraph`, `Revision` et `Analyze` ne lisent que `FactsGraph` ; motif (cp) du texte libre (`TestGraphSchemaExtension`, `TestFactsBlockHasNoFreeText`, `TestThreatModelHasNoFreeText`).
- **T5** : révision JCS recalculable ; signature avec le dossier de preuves (M4).

Menaces proposées par le plan (section 10) qui relèvent de cet ADR :
- **T111** (texte non fiable qui influe sur L2) : entrées typées `FactsGraph`, révision sans texte libre.
- **T112** (graphe candidat hostile) : D4, en plus des 64 Kio par candidat et des 100 findings au plus (ADR 0012).
- **T113** (delta non reproductible ou altéré) : D10, D11 ; `TestGraphRevisionStable`, `TestDeltaSerializationGolden`, `TestDeltaStrictDecode`.
- **T108** (pack affaibli), en partie : aucun deny implicite qui cacherait une violation à l'invariant Go ; contrôle non évalué, menace `open`.
- **T110** (réviseur qui élargit), en partie : monotonie de `FromGraph`, `SubsetOf` exact, fermeture des actions (D8).

Menaces nouvelles proposées (numéros provisoires, confirmés par `security-reviewer` à l'insertion dans `docs/02-THREAT-MODEL.md`) :

| # | Menace | Cat. | Atténuation | Vérification |
|---|---|---|---|---|
| T116 | Sous-approximation de l'atteignabilité : fait du graphe qui ouvre un flux sans être lu par `FromGraph` (attribut ou type d'arête nouveau, attribut contradictoire), ou deny implicite qui cache une violation ; l'invariant de L2 et les politiques ne voient pas le chemin | I, E | Table fermée D2, aucun deny implicite, attribut absent lu au plus large, contradictions refusées par `domain.Validate`, classement exhaustif testé | `TestGraphSchemaExtension` (classement), `TestReachFromGraphReference` (sous-cas : base à `public_access` dans le tier data atteinte depuis Internet) |
| T117 | Traduction élargie d'une permission abstraite en L3 (joker, action d'une autre catégorie, `read` traduit avec écriture) : l'IaC accorde plus que le graphe vérifié | E | Table fermée par fournisseur, sans joker, échec fermé sans traduction ; équivalence graphe et plan dans le vérificateur de L3 | à créer avec l'ADR de L3 (M3) |

## Écarts au plan M2, à reporter dans `docs/plans/M2-overview.md` au début de M2-T02

1. Section 3.1 : aucune règle deny implicite dans `FromGraph` (D2).
2. Section 3.1 : `FromGraph`, `Revision` et `Analyze` prennent un `FactsGraph` ; `domain.FactsOf` ajouté ; `Analyze` reçoit un `Pack` ; `pack_digest` et `ErrPackMismatch` ; `Limits` sans défaut implicite et `DefaultLimits` exporté (D4, D11, D12).
3. D10 du plan : `accepted` hors du schéma v1 de menace (D9).
4. Fiche M2-T02, critère 4 : `rempart design` écrit par défaut un récapitulatif textuel (`cmd/rempart/design.go`), la commande doit porter `--json` (vérification 4 ci-dessous).
5. Sous-cas ajoutés à des tests existants, sans changer leur nombre : classement de `FromGraph` dans `TestGraphSchemaExtension` ; base publique du tier data et absence de deny dans `TestReachFromGraphReference` ; contrôle non évalué dans `TestThreatStatusFromControls` ; empreinte du catalogue dans `TestDeltaSerializationGolden`.

## Vérification

M2-T02 :
1. C3 et P2 : `go test ./internal/graph/reach/ -run 'TestDenyNeverAddsPath|TestRemoveAllowNeverAddsPath' -rapid.checks=1000 -v 2>&1 | grep -Ec -- '^--- PASS: Test(DenyNeverAddsPath|RemoveAllowNeverAddsPath) '` : `2`.
2. Critère 2 de la fiche M2-T02 (dix tests nommés) : `10`.
3. Critère 3 de la fiche M2-T02 (dépendances de `reach`) : `0`.
4. `go run ./cmd/rempart design --json internal/intent/testdata/reference-ir.json | jq -e '([.graph.nodes[] | select(.kind == "Identity") | .id] == ["id:app-cluster","id:gitops","id:legacy-vms","id:obs"]) and ([.graph.edges[] | select(.type == "HAS_PERMISSION" and (.attrs.actions | any(. == "*" or . == "admin")))] | length) == 0 and (.graph.nodes | length) == 16 and (.graph.edges | length) == 18'` : `true`.
5. `jq -e '.properties.version.const == "1" and (."$defs".node.properties.kind.enum | index("Identity") != null) and (."$defs".edge.properties.type.enum | index("HAS_PERMISSION") != null)' schemas/graph/v1.json` : `true`.
6. `make -f Makefile verify-quick; echo rc=$?` : `rc=0`.
7. Mesure (consignée, sans seuil bloquant) : `go test ./internal/graph/reach/ -run '^$' -bench BenchmarkReachAtLimits -benchmem`.

M2-T04 :
8. Critère 1 de la fiche M2-T04 (neuf tests nommés) : `9`.
9. C4 : `go run ./cmd/rempart threat diff internal/threat/testdata/reference.graph.json internal/threat/testdata/reference-ssh.graph.json | jq -e '.schema_version == "1" and .catalog == "stride-v1" and .from != .to and (.added | length) > 0 and (.pack_digest | test("^[0-9a-f]{64}$"))'` : `true`.
10. Critère 3 de la fiche M2-T04 (reproductibilité) : `1`.
11. `go run ./cmd/rempart threat model internal/threat/testdata/reference.graph.json | jq -e '(.graph_revision | test("^[0-9a-f]{64}$")) and (([.threats[].status] - ["open","mitigated"]) | length) == 0 and ([.threats[].id] == ([.threats[].id] | sort))'` : `true`.
12. `jq -e '[."$defs".model, ."$defs".delta] | all(.additionalProperties == false)' schemas/threat/v1.json` : `true`.
13. `go list -deps ./internal/threat/... | grep -c '/internal/llm'` : `0`.

## Ordre de mise en oeuvre

M2-T02 (phase tests puis impl) :
1. Schéma étendu, types du domaine, `domain.Validate`, `FactsOf` (`TestGraphSchemaExtension`).
2. Défauts sûrs et identités de `Build` ; golden à 16 nœuds et 18 arêtes (`TestBuildIdentitiesLeastPrivilege`, `TestReferenceScenarioGraphValid`, `TestFactsBlockHasNoFreeText`).
3. `Model`, `Compute`, `Limits` (`TestReachDenyOverridesAllow`, `TestReachDeterministic`, `TestReachLimits`).
4. Propriétés avec oracle et `SubsetOf` (`TestDenyNeverAddsPath`, `TestRemoveAllowNeverAddsPath`).
5. `FromGraph` (`TestReachFromGraphReference`).
6. `security-graph-attack-paths/references/graph-schema.md` aligné et signalé dans `docs/STATUS.md` ; mesure de D4 consignée.

M2-T04 (après M2-T03) :
7. `Revision`, catalogue, `Analyze` (`TestGraphRevisionStable`, `TestStrideCoversEveryNodeAndFlow`, `TestThreatStatusFromControls`, `TestThreatModelHasNoFreeText`).
8. `Diff`, sérialisation, schéma, décodage strict (`TestDeltaBetweenVersions`, `TestDeltaSerializationGolden`, `TestDeltaStrictDecode`, `TestDeltaRefusesCrossTenant`).
9. Sous-commandes `rempart threat model` et `threat diff` (`TestThreatDiffCommand`).
