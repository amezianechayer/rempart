# 0001. Chiffrement des payloads Temporal par tenant et versioning des workflows

- Statut : proposé
- Date : 2026-09-23
- Jalon : M0

## Contexte
Temporal persiste l'historique de chaque exécution : entrées et sorties des workflows et des activités, signaux, marqueurs (`SideEffect`, versions), messages d'erreur et piles d'appel. Par défaut, tout est en clair dans la base de Temporal et lisible dans l'UI et la CLI Temporal. Pour Rempart, cela signifie : Intent IR, graphe conçu ou réel (la « carte des faiblesses » du client), JSON de plan (qui peut contenir des valeurs `sensitive`), prompts et réponses LLM, findings. Cela contredit T3 (clés par tenant), T7 (les prompts et contextes sont un actif), T11 (un opérateur qui ouvre l'UI Temporal voit tous les clients) et le principe 9 (pas de secret dans un état en clair). La critique initiale (§2) demande de régler ce point en M0, avant que la première boucle n'écrive d'historique.

Seconde contrainte : une attente d'approbation (L4) dure des jours. Une exécution en attente est rejouée depuis son historique par le code du worker déployé à ce moment ; un changement qui modifie la séquence des commandes provoque une erreur de non-déterminisme et bloque les exécutions en vol. Il faut une stratégie de versioning avant le premier déploiement.

Ce que le SDK Go offre (noms à vérifier sur la version retenue) : `DataConverter` composé d'un `PayloadCodec` (chiffrement côté client, le serveur ne voit que du chiffré) ; interface `ContextAware` pour choisir la clé selon le contexte ; `FailureConverter` avec `EncodeCommonAttributes` pour chiffrer message et pile d'erreur ; gestionnaire HTTP de serveur de codec, appelé par l'UI et la CLI pour déchiffrer à l'affichage ; `workflow.GetVersion` et rejeu hors ligne (`worker.NewWorkflowReplayer`) ; versioning des workers (exécutions épinglées sur une version de worker), dont la disponibilité sur un serveur auto-hébergé est à confirmer.

Restent en clair quel que soit le codec : identifiants de workflow, types de workflow et d'activité, files de tâches, attributs de recherche, en-têtes de propagation, horodatages, tailles.

## Options envisagées

### Chiffrement
1. **(a) Payload Codec AES-256-GCM, clé par tenant.** Chaque payload (métadonnées et données d'origine) est chiffré par une clé de données (DEK) propre au tenant, enveloppée par une clé Transit OpenBao dédiée au tenant. La DEK en clair vit dans un cache mémoire borné. Le tenant circule dans un propagateur de contexte ; le convertisseur `ContextAware` choisit la clé. Avantages : couverture mécanique de tous les payloads, y compris ceux qu'un développeur oublierait ; effacement cryptographique d'un tenant par destruction de sa clé ; une confusion de tenant devient une erreur de déchiffrement. Inconvénients : OpenBao sur le chemin critique ; historique plus lourd (DEK enveloppée en métadonnée) ; métadonnées Temporal toujours en clair ; UI Temporal illisible sans serveur de codec.
2. **(b) Références seules, sans codec.** Les workflows ne transportent que des références (`tenant_id`, type, identifiant, SHA-256) ; les contenus sont stockés hors Temporal, chiffrés par tenant, dans PostgreSQL sous RLS. Avantages : historique petit et sans contenu ; pas de dépendance OpenBao dans Temporal ; évite la limite de taille des payloads pour graphes et plans. Inconvénients : repose sur la discipline (un champ oublié, un message d'erreur ou une sortie LLM suffit à écrire du clair) ; chaque lecture de contenu devient une activité ; cycle de vie des objets à gérer.
3. **(c) Combinaison.** Codec (a) sur tout, en échec fermé ; références (b) pour les objets volumineux ou durables (graphe, JSON de plan, IaC, dossier de preuves), chiffrés par la même enveloppe.

Variante écartée : un namespace Temporal par tenant. Il cloisonne la visibilité mais ne chiffre rien, et multiplie workers et configuration.

### Versioning
1. **(v1) API de versioning du SDK** (`workflow.GetVersion`) et tests de rejeu d'historiques enregistrés. Fin, sans infrastructure ; exige de la discipline, d'où les tests.
2. **(v2) Versioning des workers.** Pas de branches dans le code, mais plusieurs versions de workers en parallèle pendant des jours, et un prérequis serveur à confirmer.
3. **(v3) Nouveau type de workflow à chaque changement incompatible.** Simple, mais duplique le code et oblige à router les démarrages.

## Décision
**(c)** pour le chiffrement ; **(v1)** pour le versioning, (v2) réévalué en M4 quand les workers seront déployés sur Kubernetes et le support serveur confirmé.

Chiffrement :
- Client et workers utilisent exclusivement le convertisseur de Rempart. Sans tenant dans le contexte, l'encodage échoue : jamais de repli en clair. Les workflows système utilisent un tenant système explicite.
- AES-256-GCM, nonce aléatoire de 96 bits, données associées : version du format, `tenant_id`, identifiant de DEK. Au décodage, le tenant du payload doit égaler celui du contexte, sinon erreur non rejouable `TenantMismatch`.
- DEK renouvelée toutes les 15 minutes ou après 2^20 chiffrements ; DEK déchiffrées mises en cache avec la même borne. Clés Transit : rotation planifiée, suppression interdite (`deletion_allowed` à faux) hors procédure de suppression de tenant.
- `FailureConverter` avec `EncodeCommonAttributes` ; en plus, les erreurs portent des codes et des références, pas de contenu client.
- Payload de plus de 256 Kio refusé (erreur non rejouable `PayloadTooLarge`) : l'usage des références devient obligatoire pour les gros objets.
- Identifiants de workflow opaques (`<boucle>-<uuid>`), attributs de recherche en liste blanche (`TenantId` opaque, `LoopId`, `Status`), en-têtes limités à l'identifiant de tenant et au contexte de trace.
- Serveur de codec absent en production par défaut. S'il est activé : SSO, accès juste-à-temps, vérification que l'utilisateur appartient au tenant de chaque payload, journal d'accès visible par le client.
- Rétention du namespace : 7 jours après clôture. Temporal n'est pas un système d'enregistrement ; les preuves vivent dans `internal/evidence`. Base de Temporal chiffrée au repos, en complément et non en remplacement.

Versioning :
- Tout changement de code de workflow qui modifie la séquence des commandes passe par `workflow.GetVersion`, avec un identifiant de changement déclaré dans `internal/loops/versions.go`.
- Historiques de référence dans `internal/loops/testdata/histories/` (chiffrés avec la clé du faux), rejoués par un test non sauté en `-short`, donc à chaque `make verify-quick`.
- `ContinueAsNew` juste avant l'attente d'approbation : l'historique rejoué pendant l'attente ne contient que l'attente, ce qui protège les exécutions en vol des changements du code amont.

Interfaces (esquisse) :
```go
// internal/secrets/ports
type KeyWrapper interface {
	GenerateDataKey(ctx context.Context, tenantID string) (plain secret.Bytes, wrapped []byte, err error)
	UnwrapDataKey(ctx context.Context, tenantID string, wrapped []byte) (secret.Bytes, error)
}

// internal/secrets/envelope : Seal et Open en AES-GCM, cache de DEK borné, ne dépend que de KeyWrapper.
// internal/loops/codec
func NewDataConverter(s *envelope.Sealer) converter.DataConverter // implémente ContextAware
func NewFailureConverter(s *envelope.Sealer) converter.FailureConverter
func NewTenantPropagator() workflow.ContextPropagator
func NewCodecHandler(s *envelope.Sealer, authz TenantAuthorizer) http.Handler
```
Adaptateurs : `internal/secrets/adapters/openbao` (Transit), `internal/secrets/fake` (clés en mémoire). `secret.Bytes` est la variante octets de `secret.Value` (`go-platform-conventions`).

Vérifié dès M0 :

| Commande | Attendu |
|---|---|
| `go test ./internal/secrets/envelope/... ./internal/loops/codec/...` | aller-retour ; un octet modifié échoue ; tenant différent échoue ; tenant absent : l'encodage échoue ; payload de plus de 256 Kio refusé ; aucune métadonnée ne contient le texte d'origine ; nonces distincts sur 10 000 chiffrements (test de propriété) |
| `go test -run TestReplay ./internal/loops/...` | chaque historique de `testdata/histories/` se rejoue avec le code courant ; témoin négatif : une variante incompatible sans `GetVersion` échoue en non-déterminisme, la même avec `GetVersion` passe |
| `go test -tags=integration -run TestHistoryHasNoPlaintext ./internal/loops/...` (après `make dev`) | le workflow de démo reçoit un canari en entrée, en résultat d'activité, en signal et dans un message d'erreur ; la sérialisation protobuf de l'historique brut (sans codec) ne contient pas le canari ; décodé avec le codec, il le contient (le test n'est pas vide) |
| `go test -tags=integration -run TestTransitRotation ./internal/secrets/...` | un payload chiffré avant rotation de la clé Transit se déchiffre après |

Points à confirmer au prototype : tous les chemins (démarrage, activités, signaux, requêtes, mises à jour, memo, workflows enfants, erreurs) passent par le convertisseur lié au contexte. Le test canari le prouve ; un chemin non couvert échoue en fermé au lieu d'écrire du clair.

## Conséquences
- Positives : historiques chiffrés dès le premier workflow ; confusion de tenant détectée au déchiffrement ; suppression d'un tenant par effacement cryptographique ; historiques petits grâce aux références ; approbations longues protégées des déploiements. L'enveloppe `internal/secrets/envelope` sert aussi au stockage des objets référencés.
- Négatives : OpenBao devient une dépendance de disponibilité des boucles (un appel Transit par DEK, amorti par le cache) ; débogage plus lent sans serveur de codec ; discipline `GetVersion`, historiques de référence à entretenir, branches à retirer quand plus aucune ancienne exécution n'existe ; `make dev` doit activer le moteur Transit d'OpenBao.
- Difficile à changer : format des payloads chiffrés (version en métadonnée, tout changement impose une double lecture pendant la rétention) ; Transit comme gestionnaire d'enveloppe (remplaçable derrière `KeyWrapper` par un KMS cloud).
- Après acceptation : ajouter les critères ci-dessus à `prompts/M0.md` ; mettre à jour `.claude/skills/loop-engineering/references/temporal-loop-skeleton.md` (`ContinueAsNew` avant l'attente, convertisseur de Rempart), modification à signaler dans `docs/STATUS.md`.

## Impact sécurité
- **T3** : clé par tenant, décodage lié au tenant du contexte, effacement cryptographique.
- **T7** : prompts et réponses LLM persistés uniquement chiffrés.
- **T11** : un accès à la base ou à l'UI Temporal ne suffit plus à lire les données ; le serveur de codec est contrôlé et journalisé.
- **T1** : la vérification « aucune donnée persistée ne contient d'identifiant » s'étend à l'historique Temporal (test canari).
- **Principe 9** : plus d'état Temporal en clair.

Menaces nouvelles, à intégrer au modèle de menace par `security-reviewer` après acceptation :
- Serveur de codec utilisé comme oracle de déchiffrement (I, E). Atténuation : désactivé par défaut, SSO, juste-à-temps, contrôle du tenant par payload, journal.
- Fuite par métadonnées non chiffrées : identifiants, attributs de recherche, noms d'activités, tailles, horaires (I). Atténuation : identifiants opaques, liste blanche d'attributs, test d'architecture sur les noms.
- Indisponibilité ou destruction d'une clé Transit, qui bloque ou rend illisibles les workflows d'un tenant (D). Atténuation : échec fermé, suppression interdite par défaut, sauvegarde d'OpenBao, alerte.
- Déploiement qui casse le rejeu et gèle les approbations en vol (D). Atténuation : tests de rejeu dans `make verify-quick`.
- DEK en clair dans la mémoire des workers (I). Atténuation : cache borné en durée et en usages, pas de vidage mémoire en production.
