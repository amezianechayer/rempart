# M1-T02 `codec-replay` : codec Temporal, versioning, rejeu, `ContinueAsNew`

- Jalon : M1 ; fiche `docs/plans/M1-overview.md` (M1-T02, reprend M0-T18 et M0-T21 plus `ContinueAsNew`).
- Dépend de : M1-T01 (`internal/secrets/envelope`, `ports`, `fake`, `adapters/openbao`), **ADR 0009 accepté par l'humain** (`docs/decisions/0009-convertisseur-temporal-lie-au-tenant-du-processus.md`, statut proposé).
- Mode : accéléré et périmètre minimal (décision humaine du 2026-09-30) : le moins de tests possible, ceux qui prouvent les critères ; une mutation par test ; revue sécurité oui ; une campagne de mutations.
- Pile : le démon Docker est disponible dans la session ; les tests d'intégration tournent contre `make -f Makefile dev`.

## 1. Objectif

1. Aucun payload Temporal en clair : entrées, résultats, signaux, messages, piles et détails d'erreur scellés par l'enveloppe de M1-T01 sous la clé du tenant. Lève le risque résiduel §4.1 du modèle de menace.
2. Exécutions en vol protégées des changements de code : historiques de référence rejoués à chaque `make verify-quick`, témoin négatif, `ContinueAsNew` juste avant l'attente d'approbation, phase d'approbation acceptée seulement en continuation.
3. Obligation (ct) de `docs/STATUS.md`, bloquante avant cette tâche : `Sealer.Seal` ne tient plus le verrou global pendant `GenerateDataKey` ; DEK générée hors verrou, vol unique par tenant.
4. Obligation D6 de M1-T01 : remise du jeton Transit au processus `rempart-worker`.

## 2. Périmètre

### 2.1 Dans le périmètre
- `internal/secrets/envelope/sealer.go` : vol unique par tenant, génération hors verrou (D1).
- `internal/loops/codec/{dataconverter.go,failure.go,propagator.go,check.go,doc.go}` (nouveau paquet).
- `internal/loops/versions.go` : registre des identifiants de changement, vide en T02 (D8).
- `internal/loops/demo/workflow.go` : `ContinueAsNew` avant `AwaitApprovals`, phase d'approbation en continuation seulement (D7).
- `internal/loops/testdata/histories/demo-run1.json`, `demo-run2.json` (enregistrés contre la pile, D10).
- `cmd/rempart-worker` : `-openbao-addr`, jeton d'emballage lu sur l'entrée standard, `Sealer` sur Transit, codec et propagateur sur le client et le worker, refus d'enregistrer sans les convertisseurs de Rempart.
- `internal/secrets/adapters/openbao/wrapping.go` : `UnwrapWorkerToken` (D9).
- `scripts/dev-bootstrap.sh` : sous-commande `worker-token` (D9).
- `Makefile`, cible `demo` seulement : jeton d'emballage passé au worker par un tube.
- `cmd/rempart-evals/targets.go` : cible `demo` avec codec sur faux `KeyWrapper` et conduite de la continuation.
- `internal/archtest` : règles du paquet `codec` (D11) ; règle `secrets-fake-dev-only` (obligation (cw)).
- `docs/loops/L0-demo.md` (section 6) ; skill `loop-engineering/references/temporal-loop-skeleton.md` (convertisseur, `ContinueAsNew`, `GetVersion`), modification signalée dans `docs/STATUS.md`.
- `docs/02-THREAT-MODEL.md` : section 10.

### 2.2 Hors périmètre
- Serveur de codec HTTP (`NewCodecHandler`) : M4 (ADR 0001).
- Identifiant de workflow dans les données associées : refusé en T02, limite consignée (D12).
- `TestSystemWorkflowsFrozen` : aucun workflow système n'existe ; reporté au premier workflow du tenant `System` (obligation (cz), section 12).
- Constante `ChangeLoopSpecV1` et `TestChangeIDsDeclared` : aucun changement de séquence n'a d'exécution en vol à protéger ; reportés au premier `GetVersion` de production (obligation (da)).
- Obligations (cu), (cv), (cx), (cy) de M1-T01 : inchangées (section 12).
- Workers partagés entre tenants, jeton par identité de charge de travail : M4 (ADR 0009, T17).

### 2.3 Écarts à la fiche (précisions, sans élargissement)
- **E1. Signatures du codec** : tenant du processus en paramètre (ADR 0009). La fiche prévoyait `NewDataConverter(s)` avec un tenant pris au seul contexte ; le `FailureConverter` du SDK v1.49.0 n'a pas de contexte et panique si l'encodage échoue (lu dans `internal/failure_converter.go` et `internal/error.go` du module).
- **E2. `TestStrictInputDecoding`** vit dans `internal/loops/demo` et **remplace** `TestDemoInputDecodingFrozen`, qui annonçait l'inversion en M1 (obligation (ax)). Il prouve la propriété de bout en bout (entrée de workflow), là où un test unitaire du codec ne prouverait que la fonction.
- **E3. Tests fusionnés** (mode minimal) : `TestDecodeOtherTenantFailsNonRetryable` (T18) est `TestCodecTenantMismatch` ; `TestReplayNegativeControl` (T16) est un sous-test de `TestReplay` ; `TestDemoContinueAsNewBeforeApproval` (T16) est un sous-test de `TestDemoApprovalPhaseRequiresContinuation` ; `TestPropagatorHeaderOnlyTenant` (T14) est une assertion de `TestHistoryHasNoPlaintext`.
- **E4. Reports** : `TestSystemWorkflowsFrozen`, `ChangeLoopSpecV1` (2.2).
- **E5. Ajouts** : obligation (ct) (deux tests) et obligation D6 (sous-tests dans un test existant).
- **E6. Tenant visible dans l'historique** : en-tête `rempart-tenant` et en-tête d'enveloppe (format v1 de M1-T01) le portent en clair, ce que l'ADR 0001 admet (« restent en clair : en-têtes de propagation »). Les assertions de M0 « l'historique ne porte jamais le tenant » (`TestDemoEndToEnd`, `TestRunDemoOnceEndToEnd`) deviennent « l'historique ne porte la valeur du tenant que dans l'en-tête `rempart-tenant` et dans les en-têtes d'enveloppe » ; T14 mise à jour.

## 3. Décisions propres à ce plan

| # | Décision | Justification |
|---|---|---|
| D1 | **(ct) Vol unique par tenant.** `Sealer` gagne `inflight map[tenancy.ID]*dekFlight` (sous `mu`). `Seal` : sous verrou, DEK courante valide : un usage, sortie ; vol en cours pour ce tenant : relâche le verrou, attend `done` ou `ctx.Done()`, puis recommence ; sinon crée le vol, relâche le verrou, appelle `GenerateDataKey` **hors verrou**, reprend le verrou pour installer la DEK (ou noter l'erreur), retire le vol (par `defer`, même en cas de panique), ferme `done`, recommence pour prendre un usage sous verrou. L'erreur du meneur est rendue aux attentes de ce vol, jamais mise en cache. `Open` inchangé (déjà hors verrou). | Un tenant lent (Transit jusqu'à 10 s) ne bloque plus les autres ; un seul appel Transit par rotation et par tenant. Sémantique de `singleflight` : l'annulation du contexte du meneur atteint ses attentes, l'appel suivant recommence. |
| D2 | **Tenant lié au processus** (ADR 0009). Convertisseur non lié : tenant du processus. Lié par `WithContext` ou `WithWorkflowContext` : tenant du contexte absent, refus `ErrNoTenant` ; différent, `TenantMismatch` non rejouable. Ces deux méthodes ne pouvant rendre d'erreur, elles rendent un convertisseur qui refuse chaque appel. | Seul choix sans chemin en clair ni panique. |
| D3 | **Format du payload** : métadonnée unique `encoding` = `binary/rempart-envelope-v1` ; données = `Sealer.Seal(proto.Marshal(payload interne))`, le payload interne étant celui du convertisseur JSON du SDK (métadonnées d'origine comprises, donc cachées). `converter.RawValue` : le payload interne est rendu tel quel, sans décodage (la boucle lit ses octets bruts, M0-T19b). `ToString` et `ToStrings` rendent `[sealed]`. | ADR 0001 ; aucune métadonnée d'origine visible. |
| D4 | **Décodage canonique** (obligation (ax)) : après décodage JSON vers la cible, `json.Marshal(cible)` doit égaler octet pour octet les données internes ; sinon `ErrNotCanonical`. Refuse champ inconnu, clé en double, casse inexacte, ordre différent, blancs. Sans `reflect` (règle `loops-no-reflection`). `encoding/json/v2` écarté : expérimental en Go 1.27.1 (`//go:build goexperiment.jsonv2`). | Tous les payloads légitimes sont produits par `json.Marshal` du même convertisseur, donc canoniques ; différentiel d'analyse fermé (T57). |
| D5 | **Propagateur** : un seul en-tête, `rempart-tenant`, payload d'encodage `binary/rempart-tenant`, données = les 36 octets de l'UUID (pas de `json/plain`), relu par `tenancy.ParseID`. `Inject` et `InjectFromWorkflow` sans tenant : erreur. `Extract` : `tenancy.WithTenant` ; `ExtractToWorkflow` : `workflow.WithValue` sous une clé non exportée. Toute autre clé d'en-tête est ignorée. | T14 : en-têtes limités au tenant ; T35 : validation à la frontière. |
| D6 | **`FailureConverter`** : `temporal.NewDefaultFailureConverter` avec le convertisseur non lié et `EncodeCommonAttributes: true`, enveloppé ; un `recover` autour de `ErrorToFailure` rend, si l'encodage échoue, une défaillance au message fixe `rempart: failure not encodable`, type `RempartFailureNotEncodable`, rejouable, sans pile ni détail. Jamais de panique, jamais de clair. | ADR 0009 ; T96. |
| D7 | **`ContinueAsNew`** : run 1 = `RunLoop` ; convergé : `workflow.NewContinueAsNewError(ctx, WorkflowName, Input{..., Phase: &ApprovalPhase{Loop: loop}})`. Run 2 : phase admise seulement si `workflow.GetInfo(ctx).ContinuedExecutionRunID != ""`, `Phase.Loop.Status == converged` et `Best` non vide, sinon `InvalidDemoInput` non rejouable, avant toute activité. `PlanHash` **recalculé** dans le run 2 depuis `Phase.Loop.Best`, jamais lu dans l'entrée (T54). Les signaux reçus par le run 1 sont perdus (journal d'avertissement du SDK) : une approbation ne vaut que pendant l'attente. `ExecutionTimeout` inchangé : le délai d'exécution couvre toute la chaîne, la continuation tient dans `ExecutionMargin`. | ADR 0001 et sa réserve T18 ; taille : `LoopResult` maximal mesuré 203 555 octets, sous `MaxPlaintext` (256 Kio). |
| D8 | **Versioning** : `internal/loops/versions.go` porte la règle (tout changement de séquence de commandes d'un workflow ayant des exécutions possibles en vol passe par `workflow.GetVersion` avec un identifiant déclaré ici) et une liste vide. Le passage à `ContinueAsNew` n'en a pas besoin : aucune exécution de démo ne survit plus de 228 s et la pile de dev est jetable. | Obligation (e) : `TestReplay` en est la garde mécanique (fiche, ligne « Condition de `TestReplay` ») ; une constante sans usage serait une fausse garantie. |
| D9 | **Remise du jeton au worker (D6 de M1-T01)** : options en section 3.1 ; retenue **O5** : jeton d'emballage à usage unique (60 s) d'un jeton orphelin `rempart-worker` (10 min), émis à chaque `make demo`, passé au worker par un tube, déballé par le worker, politiques vérifiées. | La plus stricte et réversible (section 3.1). |
| D10 | **Historiques de référence** : enregistrés contre la pile par `TestRecordHistories` (étiquette de build `recordhistories`, jamais lancée par `make verify`), faux `KeyWrapper` de graine fixe `replaySeed` (fichier de test partagé), tenant de démo ; deux fichiers : run 1 (boucle convergée puis continuation) et run 2 (attente, `timed_out`). Enregistrés après l'implémentation, par un retour journalisé en phase tests (tâche 10). | ADR 0001 : « chiffrés avec la clé du faux » ; un historique ne peut être produit que par le code qui l'exécute. |
| D11 | **`internal/archtest`** : le paquet `codec` sort des classes « code de workflow » (`wf`) et « décodage » (`dec`) de `loopsrc.go` (c'est le décodeur lui-même) ; règle nouvelle `loops-codec-confined` : dans `codec`, seuls les identifiants `workflow.Context`, `ContextPropagator`, `HeaderReader`, `HeaderWriter`, `ContextAware` et `workflow.WithValue` du paquet `workflow` sont admis ; `reflect`, `unsafe`, `//go:linkname` restent interdits. Règle `secrets-fake-dev-only` : `internal/secrets/fake/...` importable par `cmd/rempart-evals` seulement (tests exclus, comme toute règle d'import). | Sans D11, `loops-no-json-decoding` refuse tout usage de `converter` dans le codec ; (cw). |
| D12 | **Identifiant de workflow dans les données associées** : non en T02. Le `FailureConverter` ne le connaît que par `SerializationContext`, les autres chemins par des voies différentes ; limite acceptée et consignée dans `docs/STATUS.md` (réserve D0 de l'ADR 0001) : un acteur qui écrit dans la base Temporal peut déplacer un payload entre exécutions d'un même tenant. À réexaminer en M4 avec `SerializationContext`. | Réserve D0 de l'ADR 0001 (« sinon, limite acceptée et consignée »). |

### 3.1 Remise du jeton du worker (D6 de M1-T01)

| Option | Description | Pour | Contre |
|---|---|---|---|
| O1 | Le bootstrap émet un jeton `rempart-worker` dans un fichier ignoré par Git (600), lu par le worker | Simple | Jeton sur disque, durée longue, lisible par tout processus de l'utilisateur et par l'agent |
| O2 | AppRole : `role_id` versionné, `secret_id` émis par le bootstrap | Proche d'un mode serveur | Le `secret_id` pose le même problème de remise ; configuration et surface plus grandes |
| O3 | Clé ajoutée à `.env.dev` | Réutilise `dev-env.sh` | Casse les `.env.dev` existants (clés exactes), jeton longue durée, exporté à tout le paquet d'intégration (contraire à (ap)) |
| O4 | Jeton éphémère par exécution, émis par `make demo`, passé sur l'entrée standard | Jamais sur disque, ni en argument, ni dans l'environnement ; TTL court | Un jeton lu en clair par qui intercepte le tube ou lance la commande seule |
| **O5** | O4 avec emballage de réponse : `bao token create -orphan -policy=rempart-worker -no-default-policy -ttl=10m -explicit-max-ttl=10m -wrap-ttl=60s -field=wrapping_token` ; le worker appelle `sys/wrapping/unwrap` et refuse un jeton dont `policies` ou `token_policies` diffère de `["rempart-worker"]` ou dont la durée dépasse 900 s | Usage unique : une interception consomme le jeton et fait échouer le worker (détection) ; un jeton root emballé est refusé ; mêmes propriétés que O4 | Un appel OpenBao de plus ; option `-field=wrapping_token` à confirmer sur OpenBao 2.4.1 (repli : O4 avec la même vérification par `auth/token/lookup-self`) |

**Retenue : O5.** Réversible (un drapeau, une sous-commande, une fonction d'adaptateur) ; ne touche ni `.env.dev` ni la grammaire du `Makefile` (une recette changée, forme déjà admise : tube dans `verify`), donc pas d'ADR (règle posée par le plan de M1-T01). En production, le jeton viendra d'une identité de charge de travail (M4, T17).

## 4. Interfaces (signatures Go)

```go
// internal/secrets/envelope (D1) : API inchangée.
type dekFlight struct {
	done chan struct{}
	err  error
}
// Sealer : champ ajouté inflight map[tenancy.ID]*dekFlight, protégé par mu.
```

```go
// internal/loops/codec
package codec

const (
	EncodingEnvelope      = "binary/rempart-envelope-v1"
	EncodingTenant        = "binary/rempart-tenant"
	TenantHeader          = "rempart-tenant"
	ErrTypeTenantMismatch = "TenantMismatch"             // erreur non rejouable
	ErrTypeNotEncodable   = "RempartFailureNotEncodable" // D6, rejouable
	SealedString          = "[sealed]"
)

var (
	ErrInvalid          = errors.New("codec: nil sealer or invalid tenant")
	ErrNoTenant         = errors.New("codec: no tenant in context")
	ErrPlaintextPayload = errors.New("codec: payload is not sealed")
	ErrNotCanonical     = errors.New("codec: payload is not canonical JSON")
	ErrNotRempart       = errors.New("codec: Temporal options without the Rempart converters")
)

// NewDataConverter rend un convertisseur lié au tenant du processus (ADR 0009) ;
// implémente workflow.ContextAware (D2), jamais de repli en clair.
func NewDataConverter(s *envelope.Sealer, tenant tenancy.ID) (converter.DataConverter, error)

// NewFailureConverter : dc doit venir de NewDataConverter (sinon ErrNotRempart) ; D6.
func NewFailureConverter(dc converter.DataConverter) (converter.FailureConverter, error)

func NewTenantPropagator() workflow.ContextPropagator

// Check : dc et fc de Rempart, fc construit sur ce dc, ps contient exactement
// le propagateur de Rempart ; sinon ErrNotRempart.
func Check(dc converter.DataConverter, fc converter.FailureConverter, ps []workflow.ContextPropagator) error
```

```go
// internal/loops/versions.go
package loops

// ChangeIDs liste les identifiants passés à workflow.GetVersion (D8) ; vide en M1-T02.
var ChangeIDs = []string{}
```

```go
// internal/loops/demo
type ApprovalPhase struct {
	Loop loops.LoopResult `json:"loop"`
}

type Input struct {
	Target          string         `json:"target"`
	Author          string         `json:"author"`
	ApprovalTimeout time.Duration  `json:"approval_timeout"`
	Phase           *ApprovalPhase `json:"approval_phase,omitempty"` // D7 : posé par le workflow seulement
}
```

```go
// internal/secrets/adapters/openbao/wrapping.go
const WorkerPolicy = "rempart-worker"

var ErrTokenPolicy = errors.New("openbao: token is not a rempart-worker token")

// UnwrapWorkerToken échange un jeton d'emballage contre le jeton du worker (D9) :
// politiques exactement [WorkerPolicy], durée de 1 à 900 s, corps effacé.
func UnwrapWorkerToken(ctx context.Context, addr string, wrapping secret.Value) (secret.Value, error)
```

```go
// cmd/rempart-worker
var ErrConverterRequired = errors.New("rempart-worker: Temporal options without the Rempart converters")

// Config : champ OpenBaoAddress (drapeau -openbao-addr, http://127.0.0.1:<port> ou http://[::1]:<port>).
func readWrappingToken(r io.Reader) (secret.Value, error) // 256 octets au plus, [A-Za-z0-9._-], fin de ligne admise
func run(ctx context.Context, cfg Config, s *envelope.Sealer, stdout io.Writer) error
func clientOptions(cfg Config, s *envelope.Sealer) (client.Options, error) // + DataConverter, FailureConverter, ContextPropagators
// registerDemo : codec.Check sur o, sinon ErrConverterRequired sans aucun enregistrement.
func registerDemo(r demo.Registry, o client.Options, a *activities.Activities, v demo.ApprovalVerifier) error
```

## 5. Flux de données

```
make demo
  bash scripts/dev-bootstrap.sh worker-token          (jeton root dans le conteneur seulement)
    | go run ./cmd/rempart-worker ... -openbao-addr=http://127.0.0.1:8200
        realMain : LoadConfig -> readWrappingToken(stdin) -> UnwrapWorkerToken
                   -> openbao.NewClient -> NewTransit -> envelope.NewSealer -> run
        run : codec.NewDataConverter(s, cfg.Tenant), NewFailureConverter, NewTenantPropagator
              -> clientOptions -> DialContext -> registerDemo (codec.Check)
              -> ExecuteWorkflow(tenancy.WithTenant(ctx, cfg.Tenant), ...)

client  : entrée -> JSON -> payload interne -> Seal(tenant) -> payload binary/rempart-envelope-v1
          en-tête rempart-tenant = UUID (propagateur)
worker  : ExtractToWorkflow -> tenant dans le contexte de workflow
          décodage : ParseHeader (tenant = processus, sinon TenantMismatch, sans appel Transit)
                     -> Open -> payload interne -> json -> contrôle canonique (D4)
run 1   : RunLoop (activités scellées) -> ContinueAsNew(Input + Phase), scellé
run 2   : ContinuedExecutionRunID non vide -> AwaitApprovals -> Commit éventuel -> Output scellé
erreurs : FailureConverter -> message, pile, détails scellés (tenant du processus) ; échec d'encodage : message fixe (D6)
```

## 6. Spécification de boucle (delta de `docs/loops/L0-demo.md`)

Boucle, budget, stratégies, vérificateur, empreintes : inchangés. Seuls changent :

```yaml
approval:
  phase: exécution continuée (ContinueAsNew juste avant l'attente) ; admise seulement si ContinuedExecutionRunID non vide [ADR-0001, T18]
  plan_hash: recalculé dans l'exécution continuée depuis loop.best, jamais lu dans l'entrée (T54)
  signals_before_wait: perdus avec l'exécution 1 ; seule l'attente compte
outputs: [loop_result, approval_result, plan_hash, committed]   # inchangés, document unique de make demo
idempotency_keys: [tenant_id, workflow_id, plan_hash]
security_notes: aucune donnée cloud ; faux fournisseur LLM ; historique scellé par tenant (ADR 0001, 0009) ; tenant visible seulement dans l'en-tête rempart-tenant et les en-têtes d'enveloppe
replay: internal/loops/testdata/histories/demo-run1.json et demo-run2.json rejoués à chaque make verify-quick
```

## 7. Tests

Écrits par `test-author` en phase tests ; rouges pour la bonne raison (`undefined:` ou assertion) avant l'implémentation. Une mutation par test (mode accéléré), appliquée sur copie privée (`mktemp -d`, SHA consigné). Quinze mutations au total : douze tests nouveaux (7.1) et trois sous-tests ajoutés.

### 7.1 Tests nouveaux

| # | Test (paquet) | Ce qu'il prouve | Mutation unique (doit faire échouer) |
|---|---|---|---|
| N1 | `TestSealSlowTenantDoesNotBlockOthers` (`internal/secrets/envelope`) | Faux `KeyWrapper` de test dont `GenerateDataKey` bloque le tenant A sur un canal ; une fois A entré, `Seal` du tenant B rend en moins de 2 s ; A libéré, les deux scellés s'ouvrent. Sous `-race`. | `newDEK` appelé sous `s.mu` (code de M1-T01) |
| N2 | `TestSealSingleFlightPerTenant` (`internal/secrets/envelope`) | 32 `Seal` concurrents du tenant A pendant le blocage : un seul `GenerateDataKey` ; les 32 scellés portent le même identifiant de DEK (`ParseHeader`) et s'ouvrent. | attente du vol en cours supprimée (chaque appelant génère) |
| N3 | `TestCodecRoundTrip` (`internal/loops/codec`) | Lié au contexte du tenant A : `ToPayload` d'une structure contenant un canari ; une seule métadonnée, `encoding` = `binary/rempart-envelope-v1` ; `proto.Marshal` du payload ne contient pas le canari ; `FromPayload` rend la valeur ; `RawValue` rend le payload interne. | payload interne rendu sans `Seal` |
| N4 | `TestCodecNoTenantFails` (`internal/loops/codec`) | Lié à un contexte sans tenant : `ToPayload` rend `ErrNoTenant`, aucun appel `GenerateDataKey` (compteur du faux). | repli sur le tenant du processus quand le contexte n'a pas de tenant |
| N5 | `TestCodecRejectsPlaintextPayload` (`internal/loops/codec`) | Payload `json/plain` du convertisseur par défaut, et payload `binary/rempart-envelope-v1` aux données altérées : refus (`ErrPlaintextPayload`, erreur d'ouverture), jamais la valeur. | encodage inconnu délégué au convertisseur JSON par défaut |
| N6 | `TestCodecTenantMismatch` (`internal/loops/codec`) | Payload scellé par un convertisseur du tenant B, ouvert par celui du tenant A : `ApplicationError` de type `TenantMismatch`, non rejouable, **aucun** `UnwrapDataKey` ; lié au contexte du tenant B, le convertisseur de A refuse d'encoder (`TenantMismatch`). | erreur rendue rejouable |
| N7 | `TestFailureMessageEncrypted` (`internal/loops/codec`) | `ApplicationError` (message, cause et détail `{"tokens":3}` porteurs d'un canari) : `proto.Marshal` de la défaillance sans canari, message du SDK `Encoded failure` ; `FailureToError` rend message, cause et détail. Sous-test `keywrapper_down` : `KeyWrapper` en échec, aucune panique, message `rempart: failure not encodable`, type `RempartFailureNotEncodable`, pas de canari. | `EncodeCommonAttributes: false` |
| N8 | `TestStrictInputDecoding` (`internal/loops/demo`, remplace `TestDemoInputDecodingFrozen`) | Entrée brute avec `tenant` en trop, clé `TARGET`, clé en double, clés réordonnées : erreur de workflow, zéro appel au fournisseur, zéro activité ; témoin : l'entrée canonique converge. | contrôle canonique (D4) retiré |
| N9 | `TestDemoApprovalPhaseRequiresContinuation` (`internal/loops/demo`) | Sous-tests : `first_run_continues_before_wait` (run 1 convergé finit en `*workflow.ContinueAsNewError` vers `rempart.demo.v1`, entrée décodée avec `Phase` non nul, zéro `demo.VerifyApproval`) ; `phase_without_continuation_refused` (entrée avec `Phase`, sans `SetContinuedExecutionRunID` : `InvalidDemoInput` non rejouable, zéro activité, signal valide ignoré) ; `phase_in_continuation_waits` (même entrée avec `SetContinuedExecutionRunID("run-1")` : `timed_out`). | contrôle de `ContinuedExecutionRunID` retiré |
| N10 | `TestWorkerRequiresRempartConverter` (`cmd/rempart-worker`) | `registerDemo` avec options sans convertisseur, avec le convertisseur par défaut, avec le `DataConverter` de Rempart mais le `FailureConverter` par défaut, sans propagateur : `ErrConverterRequired` et aucun enregistrement (registre factice) ; options de `clientOptions` : enregistrement des 5 éléments de la démo. | appel à `codec.Check` retiré de `registerDemo` |
| N11 | `TestReplay` (`internal/loops`, `-short`, jamais sauté) | Sous-tests `replay_demo_run1`, `replay_demo_run2` (rejeu par `worker.NewWorkflowReplayerWithOptions` avec codec sur faux `KeyWrapper` de graine `replaySeed`, propagateur, `FailureConverter`) ; `incompatible_without_getversion` (variante enregistrée sous `rempart.demo.v1` qui ajoute un `workflow.Sleep` avant `demo.Workflow` : erreur contenant `[TMPRL1100]`) ; `compatible_with_getversion` (même ajout derrière `workflow.GetVersion(ctx, <id de test>, workflow.DefaultVersion, 1)` : rejeu réussi). Exige exactement les deux fichiers d'historique. | `workflow.Sleep(ctx, time.Millisecond)` ajouté en tête de `demo.Workflow` |
| I1 | `TestHistoryHasNoPlaintext` (`internal/loops/demo`, `-tags=integration`) | Contre la pile : worker en processus avec codec (faux `KeyWrapper`), vérificateur de test qui rend une erreur porteuse du canari au premier signal ; canari dans l'entrée (`Target`), le résultat d'activité (réponse scriptée), le signal (`Approver`), un message d'erreur. Les historiques bruts des deux runs (`proto.Marshal` de chaque événement) ne contiennent pas le canari ; décodés par le codec, ils le contiennent aux quatre endroits (le test n'est pas vide) ; chaque en-tête ne porte que la clé `rempart-tenant` ; aucun payload hors en-tête n'a un encodage autre que `binary/rempart-envelope-v1`. | convertisseur du client remplacé par le convertisseur par défaut |

Sous-tests ajoutés à un test existant (sans nouvelle fonction) :
- `TestTransitClientHardened` (`internal/secrets/adapters/openbao`, `httptest`) : `unwrap_worker_token` (jeton d'emballage dans `X-Vault-Token` seulement, jeton rendu en `secret.Value`) et `unwrap_foreign_policy_refused` (`policies` `["root"]` : `ErrTokenPolicy`, aucun jeton rendu). Mutation : vérification des politiques retirée.
- `TestRuleDetectsViolation` (`internal/archtest`) : `v("secrets-fake-dev-only", m+"/cmd/rempart-worker", m+"/internal/secrets/fake")`. Mutation : règle retirée de `DefaultRules`.
- `TestSourceRulesHardening` (`internal/archtest`) : `codec_executes_activity` (un fichier de `internal/loops/codec` qui appelle `workflow.ExecuteActivity` : `loops-codec-confined`). Mutation : règle retirée.

### 7.2 Tests existants à adapter (phase tests, sans nouvelle propriété)
- `internal/loops/demo/demo_test.go` : `newHarnessWith` pose sur l'environnement le codec (faux `KeyWrapper`, graine fixe), le `FailureConverter`, le propagateur et l'en-tête `rempart-tenant` (`SetHeader`) ; `run` conduit la continuation (`ContinueAsNewError` : entrée décodée par le codec, environnement neuf, mêmes enregistrements et écouteur, `SetContinuedExecutionRunID`, signaux de `signalAt` posés sur l'environnement du run 2) ; tous les tests de démo passent ainsi par le codec.
- `internal/loops/demo/e2e_integration_test.go` : client et worker avec codec ; historique des deux runs ; « la cible apparaît dans l'historique » devient « n'apparaît pas » ; tenant admis dans les seuls en-têtes (E6) ; `TestDemoApprovedEndToEnd` signale après la continuation (attente d'un `RunId` différent par `DescribeWorkflowExecution`), plus avant.
- `cmd/rempart-worker` : `run_test.go`, `harden_test.go`, `config_test.go`, `main_test.go` (signature de `run`, drapeau `-openbao-addr`, ordre jeton puis Temporal) ; `run_integration_test.go` : jeton obtenu par `exec.Command("bash", "scripts/dev-bootstrap.sh", "worker-token")` (sans shell, jamais affiché), assertions d'historique comme ci-dessus sur les deux runs.
- `cmd/rempart-evals/run_test.go` si une assertion dépend du déroulé de la cible `demo`.
- `internal/archtest` : `TestDefaultRules` (liste des règles), cas de `loopsrc` qui supposaient `codec` dans `wf`, contrôle de la recette `demo` du `Makefile` s'il existe.

## 8. Critères d'acceptation (commandes)

`rc=` désigne le code affiché par `echo rc=$?`. Les commandes 6 à 9 et 13 supposent `make -f Makefile dev` lancé.

1. `go test -race -count=1 -run 'TestSealSlowTenantDoesNotBlockOthers|TestSealSingleFlightPerTenant' ./internal/secrets/envelope/ -v 2>&1 | grep -c -- '^--- PASS'` : `2`.
2. `go test -race -count=1 ./internal/loops/codec/ -v 2>&1 | grep -Ec -- '^--- PASS: Test(CodecRoundTrip|CodecNoTenantFails|CodecRejectsPlaintextPayload|CodecTenantMismatch|FailureMessageEncrypted) '` : `5`.
3. `go test -short -count=1 -run TestReplay ./internal/loops/ -v 2>&1 | grep -Ec -- '--- PASS: TestReplay(/(replay_demo_run1|replay_demo_run2|incompatible_without_getversion|compatible_with_getversion))? '` : `5` ; même commande avec `grep -c -- '--- SKIP'` : `0`.
4. `go test -count=1 -run 'TestStrictInputDecoding|TestDemoApprovalPhaseRequiresContinuation' ./internal/loops/demo/ -v 2>&1 | grep -c -- '^--- PASS'` : `2`.
5. `go test -count=1 -run TestWorkerRequiresRempartConverter ./cmd/rempart-worker/ -v 2>&1 | grep -c -- '^--- PASS'` : `1`.
6. `go test -count=1 -tags=integration -run 'TestHistoryHasNoPlaintext|TestDemoEndToEnd|TestDemoApprovedEndToEnd' ./internal/loops/demo/ -v 2>&1 | grep -c -- '^--- PASS'` : `3`.
7. `go test -count=1 -tags=integration -run TestRunDemoOnceEndToEnd ./cmd/rempart-worker/ -v 2>&1 | grep -c -- '^--- PASS'` : `1`.
8. `make -s -f Makefile demo | jq -e '.loop.status == "converged" and .approval.outcome == "timed_out" and .committed == false'` : `true`.
9. `bash scripts/dev-bootstrap.sh worker-token | wc -c` : une valeur supérieure à 10 (le jeton d'emballage n'est jamais affiché, seulement compté ; il expire en 60 s).
10. `make -s -f Makefile evals EVAL=demo | jq -e '.regressions_vs_baseline == []'` : `true` (sinon R1 : nouvelle baseline écrite par l'humain).
11. `go test -count=1 -run 'TestTransitClientHardened|TestRuleDetectsViolation|TestSourceRulesHardening|TestRepositoryConforms|TestLoopSourcesConform' ./internal/secrets/adapters/openbao/ ./internal/archtest/ 2>&1 | grep -c '^ok'` : `2`.
12. `grep -c 'TestDemoInputDecodingFrozen' internal/loops/demo/demo_test.go` : `0`.
13. `make -f Makefile verify-quick; echo rc=$?` : `rc=0` ; `make -f Makefile verify; echo rc=$?` : `rc=0`.
14. Campagne de mutations (section 7, 15 mutations) : chaque mutation fait échouer son test ; tests gelés inchangés entre le SHA de gel (fin de la tâche 10) et la clôture : `git diff --stat <sha de gel>..HEAD -- '*_test.go' internal/loops/testdata/` vide.

## 9. Risques

| # | Risque | Parade |
|---|---|---|
| R1 | La cible `demo` de `rempart-evals` change de déroulé (continuation) : baseline `demo` à refaire | Projection identique attendue (mêmes champs) ; sinon baseline réécrite par l'humain (H3) |
| R2 | Un chemin du SDK décode vers `*any` ou une `map` : le contrôle canonique (D4) le refuse (clés triées) | Échec fermé visible dans les tests de démo et I1 ; repli : contrôle canonique limité aux cibles de structure par un `switch` de type, sans `reflect` |
| R3 | Un chemin du SDK encode sans contexte ailleurs que les erreurs (requêtes, détails de heartbeat) | Tenant du processus (ADR 0009) : jamais de clair ; I1 couvre entrée, résultat, signal, erreur |
| R4 | `workflowcheck` analyse `ExtractToWorkflow`, `InjectFromWorkflow`, `WithWorkflowContext` (paramètre `workflow.Context`) | Ces méthodes ne font qu'une lecture de valeur et un `ParseID` ; aucune horloge, aucune `map` itérée |
| R5 | Taille de l'entrée continuée (`LoopResult` jusqu'à 203 555 octets) proche de `MaxPlaintext` | Marge de 58 Kio ; `ErrPayloadTooLarge` échoue fermé ; L1 passera par des références (ADR 0001) |
| R6 | `-field=wrapping_token` ou `sys/wrapping/unwrap` diffèrent sur OpenBao 2.4.1 | Sonde en tâche 7 ; repli O4 avec vérification des politiques par `auth/token/lookup-self` |
| R7 | L'agent lance `dev-bootstrap.sh worker-token` seul et affiche un jeton d'emballage | Usage unique, 60 s, pile locale : l'affichage le consomme ou expire ; critère 9 ne compte que les octets ; obligation (db) |
| R8 | Signaux d'approbation perdus avec le run 1 (D7) | Voulu ; documenté dans la fiche de boucle ; tests e2e adaptés |
| R9 | L'environnement de test du SDK ne propage pas l'en-tête ou le convertisseur au run 2 | `SetHeader`, `SetDataConverter`, `SetFailureConverter`, `SetContextPropagators`, `SetContinuedExecutionRunID` présents dans `internal/workflow_testsuite.go` v1.49.0 ; posés sur chaque environnement |
| R10 | `DescribeWorkflowExecution` du run 2 n'affiche pas 228 s comme délai d'exécution (assertion de `TestRunDemoOnceEndToEnd`) | Assertion portée sur l'événement de démarrage du run 1 ; le délai de la chaîne est celui du démarrage |

## 10. Impact sur le modèle de menace (`docs/02-THREAT-MODEL.md`)

- **§4.1 levé** : « Historique Temporal en clair en M0 » : garde `TestWorkerRequiresRempartConverter` et `TestHistoryHasNoPlaintext`.
- **T1, T3, T7, T11** : vérification M1 renseignée (`TestHistoryHasNoPlaintext`, `TestCodecTenantMismatch`, `TestFailureMessageEncrypted`).
- **T14** : en-têtes limités à `rempart-tenant` (assertion de I1, remplace `TestPropagatorHeaderOnlyTenant`) ; le tenant est visible en clair dans l'en-tête et les en-têtes d'enveloppe (E6, admis par l'ADR 0001).
- **T16** : `TestReplay` (avec témoins), `ContinueAsNew` avant l'attente ; `TestChangeIDsDeclared` reporté (obligation (da)).
- **T17** : jeton du worker emballé, usage unique, 10 min, politiques vérifiées par le worker (O5) ; résidu inchangé (portée `rempart-tenant-*`).
- **T18** : `TestDemoApprovalPhaseRequiresContinuation` ; `TestCodecTenantMismatch` remplace `TestDecodeOtherTenantFailsNonRetryable`. Résidu : un autre workflow enregistré sur le même worker pourrait continuer vers `rempart.demo.v1` avec une phase forgée ; seule la démo est enregistrée.
- **T54** : `PlanHash` recalculé dans le run 2.
- **T57** : décodage canonique des payloads (D4).
- **Ajoutées** (proposées à `security-reviewer`) : **T94** contention inter-tenant au gestionnaire de clés (un tenant lent ou un Transit lent bloque les autres) (D) : vol unique par tenant hors verrou global, N1, N2 ; **T95** interception du jeton du worker pendant sa remise (I, E) : emballage à usage unique, TTL courts, politiques vérifiées, jamais sur disque ni en argument ; **T96** perte de diagnostic quand Transit est indisponible (ADR 0009, D6).

## 11. Revue sécurité (points à examiner)

Codec (aucun chemin en clair, refus du clair, `TenantMismatch` avant tout appel Transit, `RawValue`, `ToString`), `FailureConverter` (récupération de panique sans clair), contrôle canonique, propagateur (une clé, validation), continuation (T18, T54), remise du jeton (O5 : bornes de lecture, politiques, effacement, aucune trace dans les erreurs), (ct) (course, vol retiré même si `GenerateDataKey` panique), règles d'architecture D11. Seuls les constats critiques ou hauts relancent un cycle ; les autres deviennent des obligations datées.

## 12. Obligations

Soldées par ce plan : (ct), D6 de M1-T01, (e) (par `TestReplay` et `versions.go`), (m) et (ag) (rejeu réel), (ax) (entrée canonique), (cw), réserve D0 de l'ADR 0001 sur l'identifiant de workflow (limite consignée), garde §4.1.

Créées :
- **(cz)** [moyen, T18, ADR 0001] `TestSystemWorkflowsFrozen` au premier workflow du tenant `System`, au plus tard à la clôture de M1.
- **(da)** [bas, T16] `TestChangeIDsDeclared` (tout premier argument de `workflow.GetVersion` hors tests est un élément de `loops.ChangeIDs`) au premier `GetVersion` de production.
- **(db)** [bas, R7] proposition de garde `guard_bash` refusant `dev-bootstrap.sh worker-token` hors d'un tube vers `rempart-worker` ou `wc`, à soumettre à l'humain.
- ADR 0009 à réexaminer en M4 (workers partagés).

Inchangées : (cu), (cv) (aucun appelant du codec ne supprime ni ne met en quarantaine sur `ErrCorrupt`), (cx), (cy).

## 13. Tâches ordonnées

Phase journalisée par `python3 .claude/bin/rempart-state phase ...`. Chaque tâche est assez petite pour un cycle tests puis impl.

1. **Préalable** : ADR 0009 accepté par l'humain ; `dockerd` lancé ; `make -f Makefile dev` rc=0.
2. **(ct), phase tests** : N1, N2 dans `internal/secrets/envelope/sealer_test.go` ; N1 rouge (B bloqué), N2 vert (caractérisation consignée).
3. **(ct), phase impl** : D1 dans `sealer.go` ; critère 1 ; `make -f Makefile verify-quick` ; commit `fix(envelope): generate data keys outside the global lock`.
4. **Codec, phase tests** : N3 à N7 (`internal/loops/codec/*_test.go`) ; sous-cas archtest D11 et `secrets-fake-dev-only` ; adaptation de `TestDefaultRules`. Rouges sur `undefined:`.
5. **Codec, phase impl** : `internal/loops/codec`, `versions.go`, `loopsrc.go` et `rules.go` (D11) ; critères 2 et 11 (partie archtest) ; commit.
6. **Démo et rejeu, phase tests** : N8 (remplace `TestDemoInputDecodingFrozen`), N9, adaptation du harnais `demo_test.go` (7.2) ; N11 `internal/loops/replay_test.go` et `replay_seed_test.go` (graine, tenant) ; `internal/loops/record_histories_test.go` (étiquette `recordhistories`) ; I1 et adaptation de `e2e_integration_test.go`.
7. **Worker et jeton, phase tests** : sonde manuelle de R6 (`-wrap-ttl`, `sys/wrapping/unwrap` sur la pile, sans afficher de jeton) ; N10 ; sous-tests de `TestTransitClientHardened` ; adaptation des tests de `cmd/rempart-worker` et, si besoin, de `cmd/rempart-evals` (7.2). Tests des tâches 6 et 7 rouges pour la bonne raison ; `git add` des tests.
8. **Démo, phase impl** : `demo/workflow.go` (D7), `cmd/rempart-evals/targets.go` (codec, continuation) ; critères 4 et 10.
9. **Worker et jeton, phase impl** : `openbao/wrapping.go`, `cmd/rempart-worker`, `dev-bootstrap.sh worker-token`, recette `demo` du `Makefile` ; critères 5 à 9 et 11.
10. **Historiques, retour journalisé en phase tests** (« M1-T02 : enregistrement des historiques de référence par le code implémenté ») : `go test -count=1 -tags=recordhistories -run TestRecordHistories ./internal/loops/` ; `demo-run1.json` et `demo-run2.json` commités ; critère 3 vert ; SHA de gel consigné ; passage en `free`.
11. **Documents** : `docs/loops/L0-demo.md` (section 6) ; `temporal-loop-skeleton.md` (modification de skill signalée dans `docs/STATUS.md`) ; menaces T94 à T96 et mises à jour de la section 10 dans `docs/02-THREAT-MODEL.md` ; limite D12 consignée dans `docs/STATUS.md`.
12. **Vérification** : critères 12 et 13 ; campagne de mutations (15) sur copie privée (critère 14) ; `security-reviewer` (section 11) ; `acceptance-verifier` (section 8).
13. **Clôture** : `docs/STATUS.md` (écarts E1 à E6, décisions D1 à D12, obligations (cz) à (db), skill modifié à relire) ; commit conventionnel `feat(loops): seal Temporal payloads per tenant, replay histories, continue before approval`.
