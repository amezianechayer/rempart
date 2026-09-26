# 0004. Forme canonique de l'identifiant de tenant et valeur du tenant système

- Statut : proposé
- Date : 2026-09-23
- Jalon : décision en M0 (M0-T05, plan `docs/plans/M0-tenancy.md`). Réversible sans coût tant qu'aucun identifiant n'est persisté (M0 : données synthétiques, pas de clé Transit, amendement A1). **Acceptation exigée avant la première tâche de M1 qui persiste un identifiant de tenant** (clés Transit `rempart-tenant-<id>` de M0-T16 et M0-T17 reportées, migrations PostgreSQL, historiques Temporal chiffrés).

## Contexte
`internal/tenancy.ID` (fiche M0-T05) porte le tenant dans le contexte et sera vérifié à chaque frontière (T3). Il deviendra :
- la valeur de `rempart.tenant_id` des politiques RLS de l'ADR 0003 (`current_setting('rempart.tenant_id')::uuid`), donc une colonne PostgreSQL de type `uuid` ;
- une partie du nom des clés Transit par tenant (ADR 0001 : `rempart-tenant-<id>`) et des données associées AES-GCM ;
- l'attribut de recherche Temporal `TenantId`, en clair dans les métadonnées (T14).

L'ADR 0001 exige un « tenant système explicite » pour les workflows système, qui ne traitent jamais de données client. Deux choix sont donc à figer : la forme acceptée par `ParseID` et la valeur de `System`. Après M1, les changer demande une migration des données, des clés Transit et des historiques.

Contraintes : en M1, les identifiants de tenant sont générés par PostgreSQL `gen_random_uuid()` (UUID version 4, variante RFC 9562, 122 bits aléatoires, sortie textuelle canonique en minuscules) ; aucune valeur par défaut ne doit pouvoir devenir silencieusement un tenant valide (valeur zéro Go `""`, UUID nul, valeur sentinelle) ; l'identifiant n'est pas un secret mais doit rester imprévisible (défense en profondeur contre les références directes à l'objet d'un autre tenant, T3) et opaque (T14).

## Options envisagées

### Forme acceptée par `ParseID`
1. **(F1) Tout UUID canonique en minuscules**, sans contrainte de version ni de variante, UUID nul refusé. Avantages : accepte tout générateur. Inconvénients : accepte des versions à horodatage (1, 6, 7) qui exposent la date de création dans les métadonnées en clair (T14) et réduisent l'imprévisibilité ; le tenant système n'est pas structurellement distinct d'un tenant client ; la valeur « max » (`ffffffff-...`), sentinelle « tous » dans certains systèmes, reste acceptée.
2. **(F2) UUID version 4, variante RFC 9562, en minuscules ; plus le seul identifiant réservé `System`** (retenue). Avantages : correspond exactement à la sortie de `gen_random_uuid()` ; tout identifiant client porte 122 bits aléatoires ; UUID nul et max refusés (versions 0 et f) ; les identifiants réservés vivent dans un espace (version 8) qu'aucun générateur standard ne produit, donc aucune collision possible par construction. Inconvénients : un identifiant importé d'un autre système (version 1 ou 7) est refusé ; élargir plus tard à la version 7 est compatible (on accepte davantage), resserrer ne l'est pas : c'est pourquoi on part strict.
3. **(F3) Identifiant préfixé non UUID** (`tnt_<base32>`, `sys`). Avantages : auto-descriptif. Inconvénients : incompatible avec le type `uuid` et la politique RLS de l'ADR 0003 ; comparaison et index plus coûteux ; aucun gain de sécurité.

### Valeur de `System`
1. **(S1) UUID nul.** Refusée : la valeur par défaut d'une colonne ou d'un champ non renseigné deviendrait le tenant système, l'échec ouvert le plus probable.
2. **(S2) UUID max.** Refusée : sentinelle « tous les tenants » dans d'autres outils, confusion possible dans un filtre.
3. **(S3) UUID version 4 tiré une fois et figé.** Valide mais indiscernable d'un tenant client ; la réservation ne repose que sur une liste.
4. **(S4) UUID version 8 (RFC 9562 section 5.8, format propre à l'application), variante RFC, valeur lisible `00000000-0000-8000-8000-000000000001`** (retenue). Reconnaissable à l'œil (journaux, nom de clé Transit), distinct de tout identifiant client par sa version, différent du nul et du max.

### Type Go
1. **(T1) `type ID string`** (fiche M0-T05, retenue) : clé de map, comparaison `==`, conversions SQL et JSON triviales. Inconvénient : `tenancy.ID("x")` compile ; la validité n'est garantie qu'aux frontières (`WithTenant`, `FromContext`, `Require`), qui revalident.
2. **(T2) `type ID struct{ s string }`** : infalsifiable hors du paquet. Inconvénients : contredit les signatures déjà planifiées (M0-T08, T11, T16, T17, T20), exige des méthodes de sérialisation pour chaque usage. Réévaluable par un ADR si une fausse valeur franchit une frontière malgré la revalidation.

## Décision
- **F2** : `ParseID` accepte exactement 36 octets, tirets aux positions 8, 13, 18 et 23, chiffres hexadécimaux minuscules ailleurs, UUID nul et max refusés ; hors `System`, version `4` (position 14) et variante RFC 9562 (position 19 dans `8`, `9`, `a`, `b`). Aucune normalisation (ni passage en minuscules, ni retrait d'espaces, d'accolades ou de préfixe `urn:uuid:`) : une forme non canonique est refusée, jamais corrigée.
- **S4** : `const System ID = "00000000-0000-8000-8000-000000000001"`. La liste des identifiants réservés est fermée : tout autre UUID version 8 est refusé ; ajouter un identifiant réservé exige un amendement de cet ADR.
- **T1** : `type ID string`, revalidé à chaque frontière.

## Conséquences
- Positives : un identifiant accepté est toujours la forme textuelle exacte que PostgreSQL renvoie pour une colonne `uuid` ; la comparaison par `==` est sûre (une seule forme par identifiant) ; aucune valeur par défaut ne devient un tenant ; le tenant système est structurellement impossible à attribuer à un client.
- Négatives : identifiants de version 7 ou 1 refusés (élargissement possible par amendement, compatible) ; tout générateur Go de tenant (tests, M1) doit poser la version et la variante.
- M1 : colonne `tenant_id uuid` avec contrainte `CHECK` équivalente à F2 sur la table des tenants ; l'API et tout point d'entrée externe refusent `System` comme tenant fourni par un appelant ; clé Transit du tenant système `rempart-tenant-00000000-0000-8000-8000-000000000001`, couverte par le motif `rempart-tenant-*` du jeton du worker (T17).
- Plus difficile à changer après M1 : la valeur de `System` et la forme canonique (migrations, clés Transit, historiques).

## Impact sécurité
- T3 : forme unique, comparaison exacte, aucune valeur par défaut acceptée, tenant système hors de l'espace des tenants clients.
- T14 : identifiant opaque sans horodatage (version 4) dans les métadonnées Temporal en clair.
- T23 : aucune normalisation implicite qui ferait correspondre deux écritures d'un même identifiant à des lignes différentes.
- Menace nouvelle proposée à `security-reviewer` pour la clôture de M0 (H4) : usurpation du tenant système (un appelant externe fournit `System` et obtient le périmètre des workflows système). Atténuation : tenant toujours fixé par l'authentification, jamais lu d'une requête ; refus explicite de `System` aux points d'entrée externes ; test à créer en M1 (`TestAPIRejectsSystemTenant`).

## Réserves de la revue sécurité (M0-T05, 2026-09-23, verdict PASS)
- **Condition d'acceptation proposée (moyen)** : `ParseID` accepte le littéral de `System`. Avant la première frontière externe (M1), séparer `ParseCustomerID` (refuse `System`, seule fonction permise dans les gestionnaires d'API et de runner) de `ParseID` (usage interne) ; règle archtest interdisant `ParseID` et `System` dans les paquets d'API ; `TestAPIRejectsSystemTenant`. Menace T34.
- (bas) `FromContext(nil)` satisfait `errors.Is(err, ErrNoTenant)` : `ErrNoTenant` n'ouvre jamais de droit (aucun appelant ne doit le traiter comme « anonyme, continuer »).
- (bas) Un contexte non nil mais nil typé fait paniquer `ctx.Value` : risque accepté en M0, à documenter.
- (bas) `pgregory.net/rapid` est sous MPL-2.0 : acceptée pour les tests seulement (absente des binaires, `go list -deps ./cmd/...`) ; règle archtest « rapid interdit hors tests » à ajouter au durcissement.
- Menace T35 : contournement de la revalidation par conversion directe `tenancy.ID(x)` dans les requêtes SQL ou Transit (atténuation M1 : revalidation dans le Store, contrainte `CHECK` SQL sur la forme).
