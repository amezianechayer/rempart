# 0009. Convertisseur Temporal lié au tenant du processus

- Statut : accepté le 2026-10-02 (décision humaine)
- Date : 2026-10-02
- Jalon : M1 (tâche M1-T02 `codec-replay`, plan `docs/plans/M1-codec-replay.md`)

## Contexte
L'ADR 0001 décide un codec AES-256-GCM par tenant dont le convertisseur, `ContextAware`, choisit la clé selon le tenant du contexte, et un `FailureConverter` avec `EncodeCommonAttributes` pour chiffrer messages et piles d'erreur.

Lecture du SDK épinglé (`go.temporal.io/sdk` v1.49.0, `internal/failure_converter.go` et `internal/error.go`) :
- `FailureConverter` n'a pas de contexte Go ni de contexte de workflow. Il reçoit seulement un `SerializationContext` (espace de noms, identifiant de workflow, type d'activité), sans tenant.
- `DefaultFailureConverter.ErrorToFailure` encode le message, la pile (`EncodeCommonAttributes`) et les détails d'une `ApplicationError` avec son `DataConverter` **non lié** au contexte, et **panique** si l'encodage échoue (`panic(err)` dans `ErrorToFailure` et dans `convertErrDetailsToPayloads`).
- `RunLoop` dépend des détails d'erreur : `ProposeFailure` (`{"tokens":N}`) voyage dans les détails d'une `ApplicationError` (M0-T19b).

Un convertisseur qui choisit la clé par le seul contexte ne peut donc pas chiffrer les erreurs : soit les erreurs restent en clair, soit le worker panique à chaque erreur. Il faut décider d'où vient le tenant quand aucun contexte n'est disponible.

## Options envisagées
1. **Option A : tenant du contexte seulement (lecture littérale de l'ADR 0001).** Sans contexte, le convertisseur refuse. Avantage : un worker sert plusieurs tenants. Inconvénient : toute erreur d'activité ou de workflow fait paniquer le `FailureConverter` ; ou bien les erreurs sont laissées en clair, ce qui contredit l'ADR 0001 et T7.
2. **Option B : tenant fixé au processus.** Chaque client et chaque worker Temporal est construit pour un seul tenant (`NewDataConverter(sealer, tenant)`). Le convertisseur lié à un contexte exige que le tenant du contexte égale celui du processus (sinon `TenantMismatch`, non rejouable), et refuse un contexte sans tenant ; les chemins sans contexte (erreurs) scellent sous le tenant du processus. Avantages : aucun chemin en clair, aucune panique, aucun état partagé ; un worker compromis ou mal configuré ne scelle jamais pour un autre tenant ; le jeton du worker reste le seul pont inter-tenant (T17). Inconvénients : un processus worker par tenant (coût en mémoire et en connexions quand le nombre de tenants grandit) ; le futur mode de workers partagés exige de revenir sur cette décision.
3. **Option C : registre identifiant de workflow vers tenant.** Le propagateur alimente une table en mémoire (identifiant de workflow, tenant) ; le `FailureConverter` la lit par le `SerializationContext`. Avantage : workers partagés. Inconvénients : état global mutable dans le worker (T23), entrée absente après redémarrage ou éviction (échec fermé, donc erreurs perdues), course entre l'extraction de l'en-tête et la première erreur, surface de test bien plus large.
4. **Option D : erreurs sans contenu.** Le `FailureConverter` remplace message et pile par un texte fixe et refuse les détails. Avantage : rien à chiffrer. Inconvénients : casse `ProposeFailure` (comptage des tokens des échecs, T10) ; diagnostic perdu ; des détails scellés sous le tenant système feraient lire des contenus clients par la clé `System` (contraire à l'ADR 0004).

## Décision
**Option B** pour M1 et jusqu'au déploiement des workers en M4. Raison principale : c'est la seule option sans chemin en clair, sans panique et sans état partagé, avec la garantie d'isolation la plus forte (un processus ne scelle que pour son tenant).

Règles :
- `codec.NewDataConverter(s, tenant)` : tenant validé par `tenancy.ParseID` ; `System` admis pour les futurs workflows système, refusé par l'enregistrement des workflows clients (déjà le cas de `demo.Register`).
- Convertisseur lié (`WithContext`, `WithWorkflowContext`) : tenant du contexte absent, refus ; différent du tenant du processus, `TenantMismatch` non rejouable.
- Convertisseur non lié (chemins du SDK sans contexte, dont le `FailureConverter`) : tenant du processus.
- Au décodage, le tenant lu dans l'en-tête de l'enveloppe doit égaler celui du processus, avant tout appel au `KeyWrapper`.
- Le `FailureConverter` de Rempart ne panique jamais : si l'encodage échoue (Transit indisponible, taille), la défaillance rendue porte un message fixe, sans pile ni détail.

À réexaminer en M4 avec l'ADR de déploiement des workers : option C, ou workers partagés avec un `FailureConverter` lié par `SerializationContext`, si le SDK fournit alors un moyen sûr d'y porter le tenant.

## Conséquences
- Positives : couverture complète des erreurs (message, pile, détails) ; `ProposeFailure` continue de fonctionner ; une confusion de tenant devient une erreur explicite ; aucune donnée de tenant dans un état global du worker.
- Négatives : un processus `rempart-worker` par tenant (la démo l'est déjà : `-tenant` obligatoire) ; L1 (M1-T05) suit la même topologie ; montée en charge par processus, pas par tenant multiplexé.
- Facile à inverser : le format des payloads (enveloppe v1 de M1-T01) ne dépend pas de l'option ; passer à C ou à un autre mode ne change que le choix de la clé, pas les données déjà écrites.
- Plus difficile : les plans de déploiement M4 doivent prévoir un pool de workers par tenant ou réviser cet ADR.

## Impact sécurité
- **T3** renforcée : un processus ne scelle ni n'ouvre jamais pour un autre tenant ; `TestCodecTenantMismatch`.
- **T7, T11** : messages, piles et détails d'erreur chiffrés ; `TestFailureMessageEncrypted`, `TestHistoryHasNoPlaintext` (canari dans un message d'erreur).
- **T17** inchangée : le jeton Transit du worker couvre toujours `rempart-tenant-*` ; la politique par tenant reste une réserve de M4.
- **T23** évitée : pas de registre mémoire identifiant vers tenant (option C écartée).
- Menace nouvelle proposée : **T96** perte de diagnostic d'erreur quand Transit est indisponible (message fixe), confondue avec une erreur métier (D, R). Atténuation : type d'erreur dédié `RempartFailureNotEncodable`, rejouable ; alerte sur ce type en M4.
