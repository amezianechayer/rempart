# M1-T01 `envelope-transit` : enveloppe AES-256-GCM par tenant et OpenBao Transit (M0-T16 et M0-T17)

- Date : 2026-09-30
- Auteur : subagent `architect`
- Statut : proposé ; aucune question bloquante (ADR 0004 accepté, préalable H0-M1 point 2 levé)
- Sources : fiche M1-T01 de `docs/plans/M1-overview.md` (sections 6, 7.1, 9, 10) ; fiches M0-T16 et M0-T17 de `docs/plans/M0-overview.md` (amendement A1) ; `prompts/M1.md` (prérequis reporté de M0) ; ADR 0001 (tableau « Vérifié dès M0 », réserves de la revue D0) ; ADR 0004 (forme canonique, `System`, clés `rempart-tenant-<id>`) ; skill `secrets-and-identity` (règle 4) ; `docker-compose.yml`, `scripts/dev-bootstrap.sh`, `scripts/dev-env.sh` ; `internal/archtest/{compose_test.go,devscripts_test.go,devharden_test.go,devharden_v3_test.go,devstack_integration_test.go,rules.go}` ; `internal/secrets/secret`, `internal/tenancy` ; `docs/02-THREAT-MODEL.md` (T3, T15, T17, T18, T35) ; `docs/STATUS.md` (obligations (an), (ap), (bn)).
- Contraintes de l'humain : **mode accéléré, périmètre minimal** : le moins de tests possible, ceux qui prouvent les critères de la fiche et de l'ADR 0001 relevant de T01 ; une mutation par test ; revue sécurité oui (secrets, clés, multi-tenant).

---

## 1. Objectif

Chiffrer tout octet persistant d'un tenant avec une DEK propre au tenant, enveloppée par une clé OpenBao Transit propre au tenant (`rempart-tenant-<id>`), sans repli en clair, et doter la pile de dev du moteur Transit, des clés du tenant de démo et de `System`, et d'une politique du worker limitée à `datakey` et `decrypt`. Prérequis bloquant de M1-T02 (codec Temporal).

## 2. Périmètre

### 2.1 Dans le périmètre
- `internal/secrets/ports/keywrapper.go` : port `KeyWrapper`, erreur `ErrWrappedKeyRejected`.
- `internal/secrets/envelope/{sealer.go,format.go,cache.go}` : `Sealer` (Seal, Open), format v1, cache borné des DEK.
- `internal/secrets/fake/keywrapper.go` : faux `KeyWrapper` déterministe par graine (tests, historiques de référence et cible `demo` de T02).
- `internal/secrets/adapters/openbao/{client.go,transit.go}` : client HTTP durci (bibliothèque standard, réutilisé par la lecture KV de T09) et `KeyWrapper` Transit.
- `scripts/dev-bootstrap.sh` : moteur Transit, clés du tenant de démo et de `System`, politique `rempart-worker` ; `scripts/dev/openbao-worker.hcl` (texte de la politique, versionné).
- `internal/archtest/transit_integration_test.go` (nouveau) et amendement de `TestDevStackOpenBaoReady` (liste des montages).
- `internal/secrets/doc.go` (commentaire de paquet à jour) ; `docs/SETUP.md` (une phrase : ce que `make dev` crée dans OpenBao).

### 2.2 Hors périmètre
- Codec Temporal, propagateur, `FailureConverter`, identifiant de workflow dans les données associées, câblage dans `cmd/rempart-worker` et `cmd/rempart-evals` : M1-T02.
- **Remise d'un jeton du worker au processus `rempart-worker`** (fichier, variable, AppRole) : M1-T02 (voir 3, D6).
- Lecture KV d'une clé de fournisseur (`kv.go`, `SecretReader`) : M1-T09.
- Serveur de codec HTTP : M4 (ADR 0001).
- Création des clés Transit à l'onboarding d'un tenant, procédure de suppression de tenant, sauvegarde d'OpenBao : M4 et suivants (T15).
- TLS d'OpenBao dans la pile de dev (reste en HTTP sur 127.0.0.1, voir D5).
- Jeton de courte durée par identité de charge de travail (T17) : déploiement Kubernetes, M4.

### 2.3 Écarts à la fiche (précisions, sans élargissement)
- **E1. Tests d'intégration Transit dans `internal/archtest`.** La fiche place `TestTransitRotation`, `TestTransitTenantKeysDistinct` et `TestWorkerTokenScope` sous `./internal/secrets/...`. Ils exigent le jeton root de la pile (créer une clé de test, la tourner, émettre un jeton du worker). Or la décision D4 de `M0-pile-dev-harden`, figée par `TestMakeDevUsesWait` et `checkDocComposeLines`, ne donne les secrets de `.env.dev` qu'à `./internal/archtest` (seconde passe de `make verify`). Élargir cette passe à un second paquet affaiblirait (ap) et imposerait la réécriture de sept cas négatifs figés. Les trois tests vont donc dans `internal/archtest/transit_integration_test.go`, à côté de `TestDevStackTransitReady` ; ils importent l'adaptateur depuis un fichier `_test.go` (les règles d'import ne portent que sur les imports hors tests). Les commandes d'acceptation sont adaptées (section 11).
- **E2. Commande de `TestDevStackTransitReady`.** La commande 3 de la fiche (`go test -tags=integration ... ./internal/archtest/...` sans `dev-env.sh run`) échouerait faute de jeton (D7 : jamais de saut). Elle passe par `bash scripts/dev-env.sh run`, forme autorisée.
- **E3. Jeton du worker.** La fiche fait créer au bootstrap « politique et jeton du worker ». Un jeton créé sans consommateur ni lieu de dépôt ne prouve rien et devrait être stocké quelque part : T01 installe la **politique** seule ; les tests émettent des jetons éphémères de cette politique avec le jeton root. La remise du jeton au worker est une obligation de T02 (D6).
- **E4. Deux ajouts d'interface** : `ports.ErrWrappedKeyRejected` (distinguer « DEK enveloppée refusée », définitif, de « Transit indisponible », transitoire : T02 en a besoin pour classer les erreurs rejouables) et `envelope.ParseHeader` (lecture du tenant et des champs publics sans déchiffrer : tests de format, et contrôle `TenantMismatch` du codec de T02 avant tout appel au `KeyWrapper`).

## 3. Décisions propres à ce plan (réversibles, sans ADR)

| # | Décision | Justification |
|---|---|---|
| D1 | **Format v1** binaire, version en premier octet, en-tête entier authentifié (section 6). | ADR 0001 fixe le contenu minimal des données associées (version, tenant, identifiant de DEK) ; authentifier tout l'en-tête (DEK enveloppée comprise) est un sur-ensemble, nécessaire car une ouverture servie par le cache ne relit pas la DEK enveloppée (sinon un octet modifié dans la DEK enveloppée passerait). Un format v2 reste possible par double lecture (ADR 0001, « Difficile à changer »). |
| D2 | **Point d'extension pour T02** : les données associées valent `en-tête || extra`, `extra` vide en T01, non stocké. Si T02 lie l'identifiant de workflow (réserve D0 de l'ADR 0001), il ajoute `SealWithAAD` et `OpenWithAAD` sans changer le format. | Évite une v2 prématurée ; aucune API supplémentaire en T01. |
| D3 | **Le cache garde des `cipher.AEAD`, pas des DEK** : la DEK en clair (`secret.Bytes`) est effacée (`Wipe`) juste après `aes.NewCipher`. Bornes : 15 min et 2^20 usages (scellement comme ouverture), `CacheEntries` entrées (LRU), clé du cache `(tenant, identifiant de DEK)`. Insertion dans le cache d'ouverture seulement après une authentification GCM réussie. | T17 : la DEK brute ne vit que le temps de l'expansion de clé ; le programme de clés AES reste en mémoire jusqu'à l'éviction (résidu, déjà accepté par l'ADR 0001). T23 : clé de cache incluant le tenant. |
| D4 | **Client OpenBao en bibliothèque standard** (`net/http`, `encoding/json`), aucun SDK OpenBao ni Vault. Transport neuf sans proxy (`Proxy: nil`), aucune redirection suivie, délai obligatoire (10 s par défaut, 60 s au plus), corps de réponse borné à 64 Kio, erreurs à message fixe (opération et code HTTP seulement, jamais le corps ni le jeton), jeton en `secret.Value` placé dans `X-Vault-Token` seulement. | Décision laissée au plan par M0-T17 ; T6 (dépendances), T47 et T49 (même famille que l'obligation (ay) de T09). |
| D5 | **Adresse** : `https://` obligatoire, `http://` admis seulement vers un littéral de bouclage (`127.0.0.1`, `[::1]`) ; ni utilisateur, ni chemin, ni requête, ni fragment. La pile de dev reste en HTTP sur 127.0.0.1 (réexamen D11 de M0-T03 demandé « avec Transit en M1 » : conclu, résidu T18 inchangé). | Pas de certificat à gérer en dev ; aucune configuration de production possible en HTTP non local. |
| D6 | **Jeton du worker** : politique `rempart-worker` (fichier `scripts/dev/openbao-worker.hcl`, deux chemins, capacité `update` seule) installée par le bootstrap. Aucun jeton persistant en T01. **Obligation T02** : choisir la remise du jeton à `rempart-worker` (options à comparer dans le plan de T02 : jeton éphémère émis par le bootstrap dans un fichier ignoré par Git en droits 600 ; AppRole ; ajout d'une clé à `.env.dev`, qui casse les `.env.dev` existants et impose une migration). | Minimalité (E3) ; la politique porte seule la garantie de T17 et elle est testée. |
| D7 | **Bootstrap** : toute commande `bao` passe par le tableau `compose` existant (seule ligne nommant `docker`, règle (an)) : `"${compose[@]}" exec -T -e OPENBAO_DEV_ROOT_TOKEN openbao sh -c 'BAO_TOKEN="$OPENBAO_DEV_ROOT_TOKEN" BAO_ADDR=http://127.0.0.1:8200 exec bao "$@"' bao <arguments>`. Le jeton n'apparaît jamais en argument (même forme que `-e PGPASSWORD` de `psqlAs`, déjà prouvée). La politique entre par l'entrée standard (`bao policy write rempart-worker - < scripts/dev/openbao-worker.hcl`). Sorties de `bao` redirigées vers `/dev/null`. Idempotence : montage `transit/` créé s'il manque, clé créée si `bao read transit/keys/<nom>` échoue, configuration (`deletion_allowed=false`, `exportable` jamais posé) et politique réécrites à chaque passage. | Critère 4 (deux `make dev` de suite) ; aucune donnée sensible dans les journaux (OpenBao a déjà `logging.driver: none`). |
| D8 | **Clés créées par le bootstrap** : `rempart-tenant-0d3e0000-0000-4000-8000-000000000001` (tenant de démo, constante de `cmd/rempart-evals/targets.go` et de `cmd/rempart-worker`) et `rempart-tenant-00000000-0000-8000-8000-000000000001` (`System`, ADR 0004), type `aes256-gcm96`. | Fiche ; ADR 0004 (conséquence M1). |

**Pas d'ADR** : aucune décision de ce plan n'est à la fois structurante et coûteuse à inverser au-delà de ce que l'ADR 0001 a déjà tranché. Le format est versionné (D1), le client HTTP est caché derrière `KeyWrapper` (D4), la remise du jeton est différée à T02 (D6). Si T02 retient une remise du jeton qui touche `.env.dev` ou la grammaire du `Makefile`, c'est ce plan-là qui décidera s'il faut un ADR.

## 4. Interfaces (signatures Go)

```go
// internal/secrets/ports/keywrapper.go
package ports

// ErrWrappedKeyRejected : le gestionnaire de clés refuse la DEK enveloppée (clé d'un autre tenant,
// octets altérés). Définitif : jamais rejoué. Toute autre erreur est réputée transitoire.
var ErrWrappedKeyRejected = errors.New("secrets: wrapped data key rejected")

// KeyWrapper enveloppe les DEK par une clé propre au tenant. Contrat : plain fait 32 octets ;
// wrapped fait de 1 à 1024 octets, opaque ; l'implémentation revalide tenant (tenancy.ParseID)
// avant toute entrée-sortie (T35) ; aucune journalisation ; erreurs sans contenu.
type KeyWrapper interface {
	GenerateDataKey(ctx context.Context, tenant tenancy.ID) (plain secret.Bytes, wrapped []byte, err error)
	UnwrapDataKey(ctx context.Context, tenant tenancy.ID, wrapped []byte) (secret.Bytes, error)
}
```

```go
// internal/secrets/envelope
package envelope

const (
	MaxPlaintext      = 256 << 10 // ADR 0001
	FormatV1     byte = 1
	DefaultDEKMaxAge  = 15 * time.Minute // borne haute acceptée
	DefaultDEKMaxUses = 1 << 20          // borne haute acceptée
	DefaultCacheEntries = 1024           // borne haute acceptée : 65536
)

var (
	ErrNoTenant        = errors.New("envelope: no tenant in context")   // enveloppe l'erreur de tenancy
	ErrTenantMismatch  = errors.New("envelope: tenant mismatch")
	ErrPayloadTooLarge = errors.New("envelope: payload too large")
	ErrCorrupt         = errors.New("envelope: corrupt or unauthenticated payload")
	ErrInvalidOptions  = errors.New("envelope: invalid options")
)

type Options struct {
	DEKMaxAge    time.Duration    // 0 : défaut ; au-delà de 15 min : ErrInvalidOptions
	DEKMaxUses   uint64           // 0 : défaut ; au-delà de 2^20 : ErrInvalidOptions
	CacheEntries int              // 0 : défaut ; négatif ou au-delà de 65536 : ErrInvalidOptions
	Now          func() time.Time // nil : time.Now
}

type Sealer struct{ /* KeyWrapper, DEK courante par tenant, cache LRU d'AEAD, verrou */ }

// NewSealer : kw nil ou options hors bornes : ErrInvalidOptions.
func NewSealer(kw ports.KeyWrapper, o Options) (*Sealer, error)

// Seal : tenant du contexte (sinon ErrNoTenant, aucun appel au KeyWrapper) ; plaintext de plus de
// MaxPlaintext : ErrPayloadTooLarge (aucun appel) ; DEK courante renouvelée à l'âge ou au nombre
// d'usages ; nonce aléatoire de 96 bits (crypto/rand) ; données associées : en-tête entier (D1, D2).
// Sûr en concurrence.
func (s *Sealer) Seal(ctx context.Context, plaintext []byte) ([]byte, error)

// Open : en-tête analysé et borné (ErrCorrupt) ; tenant de l'en-tête différent de celui du contexte :
// ErrTenantMismatch avant tout appel au KeyWrapper ; ports.ErrWrappedKeyRejected ou échec GCM :
// ErrCorrupt ; autre erreur du KeyWrapper : renvoyée enveloppée (transitoire), jamais ErrCorrupt ;
// aucun octet de clair rendu en cas d'erreur.
func (s *Sealer) Open(ctx context.Context, sealed []byte) ([]byte, error)

// Header : champs publics d'un payload scellé, lus sans déchiffrer.
type Header struct {
	Version byte
	Tenant  tenancy.ID // revalidé par tenancy.ParseID
	DEKID   [16]byte
	Wrapped []byte     // copie
	Nonce   [12]byte
}
func ParseHeader(sealed []byte) (Header, error) // ErrCorrupt si mal formé
```

```go
// internal/secrets/fake/keywrapper.go (R5 : importé hors tests par cmd/ seulement)
package fake

// NewKeyWrapper : KEK par tenant = HMAC-SHA256(seed, "rempart-fake-kek/" + tenant) ; DEK aléatoire ;
// wrapped = AES-256-GCM(KEK, DEK, données associées = tenant) ; refus : ports.ErrWrappedKeyRejected.
func NewKeyWrapper(seed [32]byte) *KeyWrapper
func (k *KeyWrapper) GenerateDataKey(ctx context.Context, tenant tenancy.ID) (secret.Bytes, []byte, error)
func (k *KeyWrapper) UnwrapDataKey(ctx context.Context, tenant tenancy.ID, wrapped []byte) (secret.Bytes, error)
// Calls : nombre d'appels, pour les tests (« aucun appel au KeyWrapper »).
func (k *KeyWrapper) Calls() (generate, unwrap int)
```

```go
// internal/secrets/adapters/openbao
package openbao

var (
	ErrConfig = errors.New("openbao: invalid configuration")
	ErrStatus = errors.New("openbao: unexpected response") // message : opération et code HTTP seulement
)

type Config struct {
	Addr    string        // D5
	Token   secret.Value  // obligatoire
	Timeout time.Duration // 0 : 10 s ; au-delà de 60 s : ErrConfig
}

// client.go : transport neuf (Proxy nil), CheckRedirect qui refuse toute redirection, corps borné
// à 64 Kio, décodage JSON du seul champ utile. Aucun champ Transport injectable (tests en boîte blanche).
type Client struct{ /* ... */ }
func NewClient(cfg Config) (*Client, error)

// transit.go : implémente ports.KeyWrapper.
// GenerateDataKey : POST /v1/<mount>/datakey/plaintext/rempart-tenant-<id> {"bits":256} ;
//   plaintext décodé (base64, 32 octets exigés) en secret.Bytes, tampons effacés ; ciphertext rendu tel quel.
// UnwrapDataKey : POST /v1/<mount>/decrypt/rempart-tenant-<id> {"ciphertext": "<wrapped>"} ;
//   400 : ports.ErrWrappedKeyRejected ; autre code non 200 : ErrStatus.
// Nom de clé construit seulement après tenancy.ParseID(string(tenant)) ; invalide : erreur sans requête.
type Transit struct{ /* ... */ }
func NewTransit(c *Client, mount string) (*Transit, error) // "" : "transit" ; motif ^[a-z0-9-]{1,64}$
```

## 5. Flux de données

```
Seal(ctx, clair)
  tenant := tenancy.FromContext(ctx)            -> ErrNoTenant
  len(clair) > MaxPlaintext                     -> ErrPayloadTooLarge
  DEK courante du tenant (âge < MaxAge, usages < MaxUses) sinon :
      KeyWrapper.GenerateDataKey(tenant) -> (DEK, wrapped) ; AEAD := AES-GCM(DEK) ; DEK.Wipe()
      identifiant de DEK aléatoire (128 bits) ; AEAD inséré aussi dans le cache d'ouverture
  en-tête := v1 | tenant | id DEK | len(wrapped) | wrapped
  nonce := crypto/rand (12 octets)
  sortie := en-tête | nonce | AEAD.Seal(clair, données associées = en-tête)

Open(ctx, scellé)
  ParseHeader(scellé)                           -> ErrCorrupt
  tenant du contexte                            -> ErrNoTenant
  en-tête.Tenant != tenant du contexte          -> ErrTenantMismatch (zéro appel au KeyWrapper)
  AEAD := cache(tenant, id DEK) sinon KeyWrapper.UnwrapDataKey(tenant, wrapped)
      ErrWrappedKeyRejected -> ErrCorrupt ; autre erreur -> renvoyée (transitoire)
  AEAD.Open(nonce, chiffré, données associées = en-tête) -> ErrCorrupt
  insertion dans le cache après succès seulement

Transit (dev) : Sealer -> openbao.Transit -> http://127.0.0.1:8200/v1/transit/{datakey/plaintext,decrypt}/rempart-tenant-<id>
                jeton de politique rempart-worker : update sur ces deux chemins, rien d'autre
```

## 6. Format v1 (`format.go`)

| Décalage | Taille | Champ |
|---|---|---|
| 0 | 1 | version `0x01` |
| 1 | 36 | tenant, forme canonique ASCII (ADR 0004), revalidé à la lecture |
| 37 | 16 | identifiant de DEK (aléatoire) |
| 53 | 2 | longueur `L` de la DEK enveloppée, gros-boutiste, 1 à 1024 |
| 55 | `L` | DEK enveloppée (opaque ; pour Transit, le chiffré `vault:vN:...` qui porte la version de clé) |
| 55+L | 12 | nonce |
| 67+L | n+16 | chiffré AES-256-GCM et étiquette |

Données associées : octets `[0, 55+L)` (plus `extra`, vide en T01, D2). Longueur totale bornée : `67 + 1024 + MaxPlaintext + 16` ; au-delà, `ErrCorrupt`.

## 7. Pile de dev

- `docker-compose.yml` : **inchangé** (le mode dev d'OpenBao monte déjà ce qu'il faut ; `TestCompose*` restent verts).
- `scripts/dev-env.sh` et `.env.dev` : **inchangés** (aucune clé nouvelle ; les `.env.dev` existants restent valides).
- `scripts/dev-bootstrap.sh` : après le contrôle `bao status` existant, étapes idempotentes D7 et D8 ; message final inchangé. Commentaire de la ligne 2 mis à jour (plus de « A1 : ni Transit »).
- `scripts/dev/openbao-worker.hcl` :
  ```hcl
  path "transit/datakey/plaintext/rempart-tenant-*" {
    capabilities = ["update"]
  }
  path "transit/decrypt/rempart-tenant-*" {
    capabilities = ["update"]
  }
  ```
  Ni `create` (Transit `encrypt` créerait la clé à la volée ; ce chemin n'est d'ailleurs pas ouvert), ni `read`, `list`, `delete`, `sudo`.
- **Stockage en mémoire** du mode dev : un redémarrage du conteneur OpenBao perd les clés ; `make dev` les recrée (nouvelles clés), mais les historiques Temporal scellés avant deviennent illisibles (risque R1, dev seulement).

## 8. Spécification de boucle

Sans objet : aucune boucle dans cette tâche. `Sealer` sera le chiffrement de tout payload des boucles via le codec de T02.

## 9. Tests (écrits par `test-author` en phase tests)

**Sans Docker** (`go test`, dans `make verify-quick`), faux `KeyWrapper` de `internal/secrets/fake` ou espion local au test qui l'enveloppe (compte les appels, retient la DEK en clair, injecte une erreur transitoire) :

| # | Test (paquet) | Preuve | Mutation (une par test) |
|---|---|---|---|
| U1 | `TestSealOpenRoundTrip` (`envelope`) | tailles 0, 1, 1 Kio et `MaxPlaintext` exactement ; tenants démo et `System` ; sous-test `concurrent` (8 goroutines, 200 scellements chacune, sous `-race`) ; ouverture par le même `Sealer` et par un `Sealer` neuf sur le même faux (cache froid) | `Open` lit le nonce à l'offset `53+L` au lieu de `55+L` |
| U2 | `TestTamperedByteFails` (`envelope`, propriété `rapid`) | pour tout clair (0 à 4 Kio), tout indice d'octet et tout masque non nul : `Open` échoue, `errors.Is` sur `ErrCorrupt` ou `ErrTenantMismatch`, clair rendu `nil`, **avec cache chaud et cache froid** ; toute troncature : `ErrCorrupt` ; sous-test `unwrap_unavailable` : l'espion rend une erreur transitoire, `Open` échoue sans `ErrCorrupt` et sans clair (échec fermé, T15) | données associées réduites aux octets `[0, 53)` (DEK enveloppée non authentifiée) |
| U3 | `TestOpenOtherTenantFails` (`envelope`) | scellé sous A, ouvert sous B : `ErrTenantMismatch` et **zéro** appel à `UnwrapDataKey` ; en-tête réécrit de A vers B puis ouvert sous B : `ErrCorrupt` (liaison cryptographique, pas seulement le contrôle) | comparaison du tenant de l'en-tête et du contexte retirée |
| U4 | `TestSealWithoutTenantFails` (`envelope`) | contexte sans tenant, puis contexte à tenant invalide : `ErrNoTenant`, sortie `nil`, zéro appel au `KeyWrapper` ; `Open` sans tenant : `ErrNoTenant` | repli sur `tenancy.System` quand le contexte n'a pas de tenant |
| U5 | `TestPayloadTooLarge` (`envelope`) | `MaxPlaintext+1` : `ErrPayloadTooLarge`, zéro appel à `GenerateDataKey` ; `MaxPlaintext == 256<<10` | contrôle de taille retiré de `Seal` |
| U6 | `TestNoncesDistinct` (`envelope`) | 10 000 scellements d'un tenant (une seule DEK, `DEKMaxUses` par défaut) : 10 000 nonces distincts lus par `ParseHeader` | nonce laissé à zéro |
| U7 | `TestDEKRotation` (`envelope`, horloge injectée) | `max_age` : à 14 min 59 s, 1 génération ; à 15 min, 2 ; `max_uses` (`DEKMaxUses: 3`) : 4e scellement, 2 générations ; `cache_bounded` (`CacheEntries: 2`) : payloads de 3 DEK ouverts par un `Sealer` neuf, puis le premier rouvert : un déballage de plus (éviction LRU) ; entrée d'ouverture expirée à 15 min : nouveau déballage ; `options_bounds` : 16 min, `1<<20+1` usages, `CacheEntries` 65537 et `kw` nil : `ErrInvalidOptions` | condition d'âge retirée du renouvellement |
| U8 | `TestNoPlaintextInSealedMetadata` (`envelope`) | clair canari de 1 Kio : le scellé ne contient ni le canari ni aucune fenêtre de 16 octets de celui-ci, ni la DEK en clair retenue par l'espion ; longueur égale à `67 + L + len(clair) + 16` ; `ParseHeader` rend exactement tenant, identifiant, DEK enveloppée et nonce | l'en-tête porte la DEK en clair au lieu de la DEK enveloppée |
| U9 | `TestTransitClientHardened` (`openbao`, boîte blanche, contre `httptest` sur 127.0.0.1) | `request_shape` : méthode, chemin `/v1/transit/datakey/plaintext/rempart-tenant-<id>` puis `/decrypt/...`, corps `{"bits":256}`, jeton dans `X-Vault-Token` seulement (absent de l'URL et du corps) ; `redirect_not_followed` : 307 vers un second gestionnaire, zéro visite, erreur ; `no_env_proxy` : `Proxy == nil` sur le transport construit ; `error_without_body_or_token` : 500 avec corps canari et jeton en écho, `err.Error()` ne contient ni l'un ni l'autre, `fmt.Sprintf("%+v", cfg)` sans jeton ; `body_bounded` : réponse de 2 Mio refusée ; `unwrap_400` : `errors.Is(err, ports.ErrWrappedKeyRejected)` ; `plaintext_length` : DEK de 16 octets refusée ; `invalid_tenant_no_request` : `tenancy.ID("x")` et `System` mal formé, zéro requête (T35) ; `address_rules` : `http://10.0.0.1:8200`, `http://localhost:8200`, `https://u:p@h`, chemin ou requête refusés, `https://h:8200` et `http://127.0.0.1:8200` acceptés | `CheckRedirect` retiré (redirections suivies) |

**Avec la pile** (`-tags=integration`, `internal/archtest/transit_integration_test.go`, lancé par `bash scripts/dev-env.sh run`, jamais sauté : D7). Jeton root lu par `devStackSecrets` ; clés de test `rempart-tenant-<uuid v4 aléatoire>` créées par le jeton root ; jetons du worker émis par le jeton root (`policies: ["rempart-worker"]`, `no_default_policy: true`, `ttl: 5m`), tenus en `secret.Value`, jamais journalisés ; toute sortie passe par `redactSecrets`.

| # | Test | Preuve | Mutation (une par test) |
|---|---|---|---|
| I1 | `TestTransitRotation` | clé de test neuve ; `Sealer` sur `openbao.Transit` avec un jeton du worker ; P1 scellé ; rotation par le jeton root ; P2 scellé après rotation par un `Sealer` neuf ; un troisième `Sealer` neuf (cache vide, donc déballage réel) ouvre P1 et P2 ; `latest_version` de la clé égal à 2 | l'adaptateur réécrit la version de clé du chiffré enveloppé en `v1` avant `decrypt` |
| I2 | `TestTransitTenantKeysDistinct` | clés de test A et B ; DEK enveloppée pour A, `UnwrapDataKey(B, ...)` : `ports.ErrWrappedKeyRejected` ; scellé sous A, en-tête réécrit vers B, ouvert sous B : `ErrCorrupt` ; les clés de démo et de `System` ont des noms distincts et existent | nom de clé construit sans le tenant (toujours la clé de `System`) |
| I3 | `TestWorkerTokenScope` | jeton du worker : `datakey/plaintext` et `decrypt` sur la clé de démo : 200 ; 403 sur : création de clé (`POST transit/keys/rempart-tenant-<neuf>`), lecture (`GET transit/keys/<démo>`), liste, suppression, `config` (`deletion_allowed=true`), `rotate`, `export`, `trim`, `datakey/wrapped`, `encrypt`, `sys/policies/acl/rempart-worker`, `secret/data/x` ; `datakey` sur une clé inexistante : erreur **et** clé toujours absente (constaté par le jeton root : 404) | le fichier de politique ajoute `read` sur `transit/keys/rempart-tenant-*` |
| I4 | `TestDevStackTransitReady` | par le jeton root : montage `transit/` de type `transit` ; clés de démo et de `System` présentes, `type` `aes256-gcm96`, `deletion_allowed`, `exportable` et `allow_plaintext_backup` à `false` ; politique `rempart-worker` lue dans OpenBao égale à l'octet près à `scripts/dev/openbao-worker.hcl` | le bootstrap ne crée plus la clé de `System` |

Amendement d'un test existant (même phase) : `TestDevStackOpenBaoReady` attend désormais les montages `cubbyhole/`, `identity/`, `secret/`, `sys/`, `transit/` et ne signale plus le montage Transit comme une erreur.

Les mutations sont appliquées une à une (U1 à U9, I1, I2 sur le code ; I3 sur `openbao-worker.hcl` ; I4 sur `dev-bootstrap.sh`, suivie de `make -f Makefile dev-down` puis `make -f Makefile dev` pour repartir d'un OpenBao vierge) ; chacune fait échouer au moins son test ; aucune ne touche un test.

## 10. Revue sécurité

Oui (fiche : cryptographie, jetons, T3, T17). Points : nonce aléatoire et bornes de DEK (limite GCM par clé) ; en-tête entier authentifié (D1) ; ordre des contrôles d'`Open` (tenant avant tout appel au `KeyWrapper`) ; insertion au cache après authentification ; effacement des DEK (D3) et résidu du programme de clés ; distinction définitif et transitoire (`ErrWrappedKeyRejected`) ; aucun repli en clair, aucune donnée rendue en erreur ; client HTTP (D4, D5) ; revalidation du tenant avant construction du nom de clé (T35) ; politique du worker (fichier et test I3) ; jeton root jamais en argument dans le bootstrap (D7) ; sorties des tests expurgées. Mode accéléré : seuls les constats critiques ou hauts relancent un cycle.

## 11. Critères d'acceptation

Les critères 1, 5, 6, 7 et 9 tournent **sans Docker**. Les critères 2, 3, 4 et 8 exigent la pile (`dockerd` lancé, `make -f Makefile dev`).

1. `go test -race ./internal/secrets/... -v 2>&1 | grep -Ec -- '^--- PASS: Test(SealOpenRoundTrip|TamperedByteFails|OpenOtherTenantFails|SealWithoutTenantFails|PayloadTooLarge|NoncesDistinct|DEKRotation|NoPlaintextInSealedMetadata|TransitClientHardened) '` : `9`.
2. `make -f Makefile dev && bash scripts/dev-env.sh run go test -count=1 -tags=integration -run='^Test(TransitRotation|TransitTenantKeysDistinct|WorkerTokenScope|DevStackTransitReady|DevStackOpenBaoReady)$' -v ./internal/archtest 2>&1 | grep -Ec -- '^--- PASS: Test(TransitRotation|TransitTenantKeysDistinct|WorkerTokenScope|DevStackTransitReady|DevStackOpenBaoReady) '` : `5`.
3. `make -f Makefile dev; echo rc=$?` deux fois de suite : `rc=0` puis `rc=0` (bootstrap idempotent).
4. `make -f Makefile verify; echo rc=$?` : `rc=0` (dont les deux passes d'intégration de D4 et `govulncheck`).
5. Aucun SDK : `go list -deps ./internal/secrets/... | grep -Ec '^github\.com/(openbao|hashicorp)/'` : `0`.
6. Politique minimale : `grep -c 'capabilities = \["update"\]' scripts/dev/openbao-worker.hcl` : `2`, et `grep -Ec '"(create|read|list|delete|sudo|patch)"' scripts/dev/openbao-worker.hcl` : `0`.
7. Arborescence et règles d'import (R2 `adapters-edge`, R5 `fakes-wired-in-cmd`, R4 inchangée) : `go test ./internal/archtest/ -run 'TestRepositoryConforms|TestLayoutMatchesVision|TestComposeOnlyThroughDevEnv|TestDevBootstrapScript|TestMakeDevUsesWait'; echo rc=$?` : `rc=0`.
8. Mutations U1 à U9 et I1 à I4 (section 9) : chacune fait échouer la commande 1 (U) ou 2 (I) ; compte rendu de `acceptance-verifier`, une exécution par mutation, code non nul.
9. `make -f Makefile verify-quick; echo rc=$?` : `rc=0`.

## 12. Risques

| # | Risque | Parade |
|---|---|---|
| R1 | Mode dev d'OpenBao en mémoire : clés perdues au redémarrage du conteneur, historiques Temporal scellés avant illisibles | Dev seulement ; `make dev` recrée les clés ; T02 écrit ses tests sur des exécutions neuves ; production : stockage persistant et sauvegarde (T15) |
| R2 | Tests Transit hors de `internal/secrets` (E1) : lecteur surpris | Écart consigné ici et dans `docs/STATUS.md` ; paquet d'intégration de la pile = seul destinataire des secrets (D4, (ap)) |
| R3 | `compose exec -e VAR` sans valeur ne transmet pas la variable | Forme déjà prouvée par `psqlAs` ; repli : jeton passé par l'entrée standard de `sh -c 'read -r BAO_TOKEN; ...'` |
| R4 | Forme des réponses Transit d'OpenBao 2.4.1 (préfixe du chiffré, champs de `datakey`) différente de Vault | Aucune hypothèse sur le préfixe (D1 : opaque) ; forme vérifiée par I1 et I2 dès la phase tests ; `ParseHeader` borne `L` à 1024 |
| R5 | Verrou du `Sealer` tenu pendant l'appel Transit : latence sous charge | Acceptable en M1 (un appel par DEK, amorti 15 min) ; libre à l'implémentation d'appeler hors verrou si U1 `concurrent` reste vert |
| R6 | Remise du jeton du worker non décidée (E3, D6) | Obligation T02 datée ; T02 ne peut pas câbler Transit sans elle |
| R7 | `rapid` et 10 000 scellements alourdissent `verify-quick` | Défaut de `rapid` (100 cas) ; U6 mesuré, attendu sous la seconde |
| R8 | La mutation I4 laisse un OpenBao sans clé `System` | Consigne de la section 9 : `dev-down` puis `dev` après restauration |

## 13. Impact sur le modèle de menace (`docs/02-THREAT-MODEL.md`)

À reporter par `security-reviewer` à la clôture ; aucune menace nouvelle.
- **T3** : `TestOpenOtherTenantFails` et `TestTransitTenantKeysDistinct` créés (déjà cités, statut « M1 » à marquer fait).
- **T15** : `TestUnwrapErrorFailsClosed` (nom de M0-T16) remplacé par le sous-test `TestTamperedByteFails/unwrap_unavailable` ; `TestDevStackTransitReady` créé (`deletion_allowed`, `exportable`, `allow_plaintext_backup` à faux) ; jeton du worker sans création, lecture, configuration ni suppression de clé : `TestWorkerTokenScope` ; création implicite de clé par `encrypt` fermée par la politique.
- **T17** : `TestDEKCacheBounded`, `TestDEKRotatesAfterMaxUses`, `TestDEKRotatesAfterMaxAge` (noms de M0-T16) remplacés par les sous-tests de `TestDEKRotation` ; DEK brute effacée après expansion (D3) ; politique limitée à `datakey/plaintext` et `decrypt` testée ; résidu inchangé : un jeton du worker couvre `rempart-tenant-*` (tous les tenants) ; jeton de courte durée par identité de charge de travail en M4.
- **T18** : réexamen « OpenBao en HTTP, à réexaminer avec Transit en M1 » conclu (D5) : HTTP limité au bouclage par l'adaptateur, résidu dev inchangé.
- **T35** : revalidation du tenant avant construction du nom de clé Transit : sous-test `TestTransitClientHardened/invalid_tenant_no_request`.
- **§4.1** : inchangé en T01 (levé par T02 avec `TestHistoryHasNoPlaintext`).

## 14. Ce que l'humain doit faire

- **Session cloud** : relancer `dockerd` avant la phase tests (critères 2 à 4 et 8) ; sans Docker, seuls les critères 1, 5, 6, 7 et 9 sont constatables et la tâche ne peut pas être close.
- **Rien sur `.env.dev`** : aucune clé nouvelle, les fichiers existants restent valides ; un `make -f Makefile dev` suffit (OpenBao reçoit Transit à chaud).
- **Facultatif** : placer `scripts/dev/openbao-worker.hcl` sous CODEOWNERS (proposition de harnais à rédiger à la clôture si l'humain le souhaite), la politique étant une garde de T17.
- **Avant T02** : relire l'obligation D6 (remise du jeton au worker) ; le plan de T02 proposera les options.

## 15. Tâches ordonnées

1. `python3 .claude/bin/rempart-state phase tests`. **Tests unitaires (`test-author`)** : U1 à U8 (`internal/secrets/envelope/*_test.go`, espion local), U9 (`internal/secrets/adapters/openbao/transit_internal_test.go`, paquet `openbao`). Rouges pour la bonne raison (`undefined:`).
2. **Tests d'intégration (`test-author`, même phase)** : `internal/archtest/transit_integration_test.go` (I1 à I4, aides `openBaoDo` et `newTenantID` locales au fichier) ; amendement de `TestDevStackOpenBaoReady`. Constat rouge contre la pile (montage absent, paquets absents). Passage en impl (`rempart-state phase impl`).
3. **Port et faux** : `internal/secrets/ports/keywrapper.go`, `internal/secrets/fake/keywrapper.go`. Compilation des tests.
4. **Format** : `envelope/format.go` (`FormatV1`, `ParseHeader`, construction de l'en-tête). Vert : aucun encore, compile.
5. **Sealer sans cache** : `envelope/sealer.go` (Seal, Open, erreurs, bornes, options). Verts : U1, U3, U4, U5, U6, U8 ; U2 partiel.
6. **Cache** : `envelope/cache.go` (DEK courante par tenant, LRU d'AEAD, âge et usages, insertion après authentification). Verts : U2, U7 ; `go test -race ./internal/secrets/...` (critère 1).
7. **Client et Transit** : `adapters/openbao/client.go`, `transit.go`. Vert : U9 (critère 1 complet : 9).
8. **Pile** : `scripts/dev/openbao-worker.hcl`, `scripts/dev-bootstrap.sh` (D7, D8) ; `make -f Makefile dev` deux fois (critère 3) ; critère 2 (5 PASS) ; critères 5 à 7.
9. **Documentation** : `internal/secrets/doc.go`, phrase de `docs/SETUP.md` (sans toucher aux énoncés exigés par `checkSetupContent`).
10. `make -f Makefile verify-quick` puis `make -f Makefile verify` ; campagne de mutations U1 à U9, I1 à I4 ; `security-reviewer` (section 10) ; `acceptance-verifier` (section 11) ; clôture dans `docs/STATUS.md` (écarts E1 à E4, obligation D6 pour T02, résidus T17 et R1) ; commit conventionnel.
