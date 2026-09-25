# M0-T15 `approvals` : attente d'approbation `AwaitApprovals` et vérificateur factice

2026-09-25, `architect`, proposé. Fiche `docs/plans/M0-overview.md` (M0-T15, lignes 906 à 975). Aucun ADR : contrat interne réversible avant T19 ; format signé, clés et identités réelles relèvent de l'ADR des approbations signées (M4, Q5). Revue sécurité : oui (T12, T18, échec sûr).

## 0. Amendements

- V1 (2026-09-25, `test-author`, étape A2) : point non vérifié 1 infirmé : sous Go 1.27.1, `(*encoding/json.Decoder).Decode` passe par `encoding/json/v2` (cache et `marshalObjectAny` itèrent des maps, goroutines du GC) et `workflowcheck` rend rc=3 jusqu'à `AwaitApprovals`. Parade prévue en section 9 appliquée : `workflowcheck.config.yaml` à la racine (`decls: (*encoding/json.Decoder).Decode: false`, motif en commentaire) et `-config workflowcheck.config.yaml` dans la recette `arch-test` ; contrôle négatif : map itérée et `time.Now` injectés dans `decodeApproval` restent signalés. Code de 4.1 à 4.3 identique. Tests renforcés (mutations exploratoires X1 à X43 : 39 détectées, 4 équivalentes ou inatteignables) : sous-tests dans `WrongHashIgnored` (hash avant auteur), `DuplicateApproverIgnored`, `QuorumWithSecurityRole` (le rôle libère la dernière place), `AuthenticatedRefusalStops` (refus sans rôle sécurité), `MalformedSignalIgnored` (chaque champ absent ou `null`, encodage `json/protobuf`), `SignalFlood` (borne par défaut), `Canceled` ; `fake/approvals_test.go` reformaté par gofumpt. 25 mutations sur 25 et 27 sur 27 (M0-T14) détectées. Observation pour la revue : signal puis annulation dans le même rappel peut finir en `signal_flood` (contexte pas encore annulé).

## 1. Objet et périmètre
Critère 2 de `prompts/M0.md`, seconde partie : attente d'approbation liée au hash exact du plan, signature vérifiée par activité, quorum, rôle sécurité, auteur exclu, signal invalide ignoré sans interrompre l'attente, timeout : ne rien faire. Solde aussi l'obligation (b) de M0-T14 (annulation distinguée d'une panne) dans `AwaitApprovals` et `RunLoop` (D11).

Dans : `internal/loops/{approvals.go,doc.go}`, diff de `internal/loops/runloop.go`, nouveau paquet `internal/loops/fake` (`approvals.go`), tests `internal/loops/approvals_test.go`, `internal/loops/fake/approvals_test.go`, un test ajouté à `runloop_test.go` ; `docs/STATUS.md` ; ligne V4 en section 0 de `docs/plans/M0-runloop.md`.
Hors : cryptographie réelle, message signé, réauthentification `high`, format des identités (M4) ; `ContinueAsNew` avant l'attente, `workflow.GetVersion`, convertisseur chiffrant (M1) ; câblage worker et mode `-dev` (T19, T20) ; classification du risque (M4) ; workflow produit L4.

## 2. Étape 0
Aucune. `go.temporal.io/sdk/converter` est dans le module SDK, déjà direct ; les tests fabriquent un payload arbitraire par accès au champ `Data` du `*commonpb.Payload` rendu par `converter.GetDefaultDataConverter().ToPayload`, sans importer `go.temporal.io/api` (qui deviendrait direct). Contrôle : critère 12.

## 3. Décisions
| # | Décision |
|---|---|
| D1 | **Réception brute** : `converter.RawValue` lue par `ReceiveAsync` dans le rappel du `Selector`. Réception typée écartée : le SDK jette en silence un signal indécodable (`assignValue`, métrique `CorruptedSignalsCounter`, `internal_workflow.go` l. 836 à 851), ni compté ni tracé, et `encoding/json` tolère champs absents et inconnus. `Receive` écarté : il boucle sur un payload indécodable jusqu'au suivant, sans voir l'échéance ; `ReceiveAsync` rend `false`. |
| D2 | **Décodage contrôlé** (`decodeApproval`) : encodage `json/plain`, au plus 8 Kio, un seul objet (`DisallowUnknownFields`, second `Decode` égal à `io.EOF`), quatre champs présents et non `null` (structure à pointeurs), types stricts, approbateur canonique (D4), signature non vide. Sinon `malformed`, approbateur vide : aucun octet non fiable recopié. Acceptés sans risque : clés en casse libre et clés dupliquées (la dernière gagne) : la signature est vérifiée sur les valeurs décodées, pas sur les octets. |
| D3 | **Hash** : `Validate` exige 64 chiffres hexadécimaux minuscules ; le signal est comparé octet par octet, sans normalisation (majuscules : `wrong_hash`). Temps constant inutile : le hash est public (PR, demande), sa comparaison n'authentifie rien (la signature le fait, par activité) et la durée d'une tâche de workflow n'est pas observable par l'émetteur (asynchrone, rejouée). |
| D4 | **Identités** : forme canonique imposée, jamais normalisée : 1 à 128 octets parmi `a-z0-9._-@`, pour `Author` (`Validate`) et `Approver` (sinon `malformed`) ; égalité exacte ; vide refusé. Normaliser (casse, blancs, Unicode) crée des équivalences qui divergent entre IdP, interface et workflow : on refuse. |
| D5 | **Ordre par signal**, contrôles sans activité d'abord : (1) décodage, `malformed` ; (2) hash, `wrong_hash` ; (3) auteur, `self_approval`, approbation **ou refus** (l'auteur ne décide pas ; il peut annuler le workflow, action journalisée) ; (4) approbation d'un approbateur déjà retenu, `duplicate` (un refus n'est jamais un doublon) ; (5) activité : erreur, `verify_error` ; signature invalide, `invalid_signature` ; (6) refus authentifié : `rejected`, y compris d'un approbateur qui avait approuvé (retrait, échec sûr) ; (7) place réservée au rôle sécurité, `needs_security_role` ; (8) retenue, quorum. Refus non authentifié ignoré : sinon tout émetteur de signal bloquerait l'approbation. |
| D6 | **Quorum** : exactement `Required` approbateurs distincts à signature valide ; si `NeedsSecurityRole`, la dernière place est réservée à un rôle sécurité. Donc `approved` implique `len(Approvals) == Required` avec un rôle sécurité ; résultat borné. Bornes : `Required` 1 à 5 ; `MaxIgnored` 0 (défaut 100) ou 1 à 1000 ; `timeout` dans ]0, 7 j]. Refus : `ApplicationError` non rejouable `InvalidApprovalRequest`, message fixe, avant toute commande (ni minuteur ni activité). |
| D7 | **Vérification** : `ScheduleToCloseTimeout` et `StartToCloseTimeout` 30 s (file comprise, T10), une tentative : erreur (délai, panique, activité absente) donne `verify_error`, approbateur non retenu, il peut renvoyer. Séquentielle, ordre d'arrivée, déterministe ; les signaux reçus entre-temps restent en tampon. Contrat pour M4 : `SignatureValid` signifie « signature valide d'un approbateur autorisé pour ce plan et ce tenant ». |
| D8 | **Échéance** : un minuteur de `timeout`, sur un contexte fils annulé au retour (pas de minuteur pendant chez l'appelant ; non observable au testsuite, dont la boucle s'arrête à la complétion : ni test ni mutation). Minuteur échu après une vérification : `timed_out` sans retenir le résultat (échéance absolue, dépassement au plus 30 s). |
| D9 | **Inondation** : tout signal ignoré est tracé et compté ; au-delà de `MaxIgnored`, `signal_flood` (fin, rien d'approuvé). `Ignored` : au plus `MaxIgnored + 1` entrées d'au plus 128 octets ; activités par attente : au plus `MaxIgnored + Required + 1`. Un émetteur de signaux peut forcer `signal_flood` : déni sûr, borné par T18. |
| D10 | **Issues** : `approved`, `rejected`, `timed_out`, `signal_flood`, erreur nil ; `Approvals` non vide si et seulement si `approved` (critère 2 : rien de retenu au timeout) ; `Ignored` conservé pour la preuve. |
| D11 | **Annulation, obligation (b) de M0-T14** : `AwaitApprovals` rend `ctx.Err()` (`*temporal.CanceledError`) dès que le contexte du workflow est annulé, contrôlé avant toute issue, jamais `timed_out`. `RunLoop` aussi, **dans cette tâche** : après chaque activité, contexte annulé : `LoopResult{}, ctx.Err()` au lieu de `activity_failed`. Motifs : `docs/STATUS.md` exige (b) avant T15 ; T19 enchaîne les deux et une annulation ne doit pas notifier d'escalade ; diff de six lignes, ancres des 27 mutations de M0-T14 intactes (critère 14). |
| D12 | **Faux** : `ExpectedSignature` = SHA-256 hexadécimal des netstrings (comme `domain/findings.go`) de `fake`, approbateur, hash, `strconv.FormatBool(approved)`. Sans clé, calculable par tous : tests et `cmd/` en `-dev` seulement (R5 : `internal/*/fake/...` importable par `cmd/...` seul, imports de test hors règles). Rôle sécurité seulement si signature valide ; `subtle` par hygiène (rien de secret) ; jamais d'erreur. |
| D13 | **Écarts d'interface** : `IgnoredNeedsSecurityRole` ; constantes exportées (bornes, raisons, issues, `ErrTypeInvalidApprovalRequest`) ; tests d'`AwaitApprovals` en `package loops_test` (le faux importe `loops` : un test interne qui l'importerait ferait un cycle) ; `AwaitApprovals` jamais enregistré comme workflow, requête construite par le code (T54 étendue, test en T19 avec `TestRunLoopNotRegistered`). |

## 4. Code de référence (normatif ; ancres de la section 7 au caractère près)
### 4.1 `internal/loops/approvals.go`
```go
package loops

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// ApprovalSignal is the name of the signal that carries one Approval.
const ApprovalSignal = "approval"

// ErrTypeInvalidApprovalRequest types the refusal of a request or a timeout.
const ErrTypeInvalidApprovalRequest = "InvalidApprovalRequest"

// Defaults and bounds of an approval wait (threats T10, T12, T18).
const (
	DefaultMaxIgnored      = 100
	MaxIgnoredLimit        = 1000
	MaxRequiredApprovals   = 5
	MaxApprovalTimeout     = 7 * 24 * time.Hour
	VerifyApprovalTimeout  = 30 * time.Second
	MaxApprovalSignalBytes = 8 << 10
	MaxIdentityBytes       = 128
)

const (
	hexDigits     = "0123456789abcdef"
	identityBytes = "abcdefghijklmnopqrstuvwxyz0123456789._-@"
)

// ApprovalRequest says what to gather before applying one plan. The calling
// workflow builds it from constants and the deterministic risk
// classification, never from an input (threat T54).
type ApprovalRequest struct {
	PlanHash          string // SHA-256 of the plan, 64 lower-case hex digits
	Author            string // canonical identity; none of its signals counts
	Required          int    // distinct approvers, 1 to MaxRequiredApprovals
	NeedsSecurityRole bool   // one of them at least has the security role
	VerifyActivity    string // registered verification activity
	MaxIgnored        int    // 0 means DefaultMaxIgnored
}

// Approval is one decision on a plan hash. A signal is not authenticated:
// only the signature, checked by the verification activity, counts.
type Approval struct {
	Approved  bool   `json:"approved"`
	PlanHash  string `json:"plan_hash"`
	Approver  string `json:"approver"`
	Signature string `json:"signature"`
}

// ApprovalCheck is the result of the verification activity. SignatureValid
// means a valid signature of an approver allowed to decide on this plan.
type ApprovalCheck struct {
	SignatureValid bool `json:"signature_valid"`
	SecurityRole   bool `json:"security_role"`
}

// ApprovalOutcome ends a wait.
type ApprovalOutcome string

const (
	OutcomeApproved    ApprovalOutcome = "approved"
	OutcomeRejected    ApprovalOutcome = "rejected"
	OutcomeTimedOut    ApprovalOutcome = "timed_out"
	OutcomeSignalFlood ApprovalOutcome = "signal_flood"
)

// IgnoredReason says why a signal did not count.
type IgnoredReason string

const (
	IgnoredMalformed         IgnoredReason = "malformed"
	IgnoredWrongHash         IgnoredReason = "wrong_hash"
	IgnoredSelfApproval      IgnoredReason = "self_approval"
	IgnoredDuplicate         IgnoredReason = "duplicate"
	IgnoredVerifyError       IgnoredReason = "verify_error"
	IgnoredInvalidSignature  IgnoredReason = "invalid_signature"
	IgnoredNeedsSecurityRole IgnoredReason = "needs_security_role"
)

// IgnoredSignal records one ignored signal; Approver is empty if malformed.
type IgnoredSignal struct {
	Approver string        `json:"approver"`
	Reason   IgnoredReason `json:"reason"`
}

// ApprovalResult holds Approvals only for OutcomeApproved: exactly Required
// distinct approvals, in arrival order.
type ApprovalResult struct {
	Outcome   ApprovalOutcome `json:"outcome"`
	Approvals []Approval      `json:"approvals,omitempty"`
	Ignored   []IgnoredSignal `json:"ignored,omitempty"`
}

// Validate checks r once defaults are applied. The error is a non-retryable
// application error of type ErrTypeInvalidApprovalRequest that never quotes r.
func (r ApprovalRequest) Validate() error {
	r = r.withDefaults()
	switch {
	case !validPlanHash(r.PlanHash):
		return invalidApproval("plan hash")
	case !validIdentity(r.Author):
		return invalidApproval("author")
	case r.Required < 1 || r.Required > MaxRequiredApprovals:
		return invalidApproval("required approvals")
	case r.VerifyActivity == "":
		return invalidApproval("verify activity")
	case r.MaxIgnored < 1 || r.MaxIgnored > MaxIgnoredLimit:
		return invalidApproval("ignored signals bound")
	}
	return nil
}

func (r ApprovalRequest) withDefaults() ApprovalRequest {
	if r.MaxIgnored == 0 {
		r.MaxIgnored = DefaultMaxIgnored
	}
	return r
}

// AwaitApprovals waits until req.Required distinct approvers approve
// req.PlanHash, one of them with the security role if required, or until one
// authenticated refusal. An invalid signal is recorded and ignored without
// ending the wait, unless more than req.MaxIgnored were. Timeout: nothing is
// approved. The error is an invalid request or the cancellation of ctx,
// never an outcome.
func AwaitApprovals(ctx workflow.Context, req ApprovalRequest, timeout time.Duration) (ApprovalResult, error) {
	if err := req.Validate(); err != nil {
		return ApprovalResult{}, err
	}
	if timeout <= 0 || timeout > MaxApprovalTimeout {
		return ApprovalResult{}, invalidApproval("timeout")
	}
	req = req.withDefaults()
	actx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		ScheduleToCloseTimeout: VerifyApprovalTimeout,
		StartToCloseTimeout:    VerifyApprovalTimeout,
		RetryPolicy:            &temporal.RetryPolicy{MaximumAttempts: 1},
	})
	tctx, cancelTimer := workflow.WithCancel(ctx)
	defer cancelTimer()
	deadline := workflow.NewTimer(tctx, timeout)
	signals := workflow.GetSignalChannel(ctx, ApprovalSignal)

	var (
		res      ApprovalResult
		security bool
	)
	end := func(o ApprovalOutcome) (ApprovalResult, error) {
		if err := ctx.Err(); err != nil { // a cancellation is never an outcome
			return ApprovalResult{}, err
		}
		if o != OutcomeApproved {
			res.Approvals = nil // nothing retained unless approved
		}
		res.Outcome = o
		return res, nil
	}
	for {
		var (
			raw converter.RawValue
			got bool
		)
		workflow.NewSelector(ctx).
			AddFuture(deadline, func(workflow.Future) {}).
			AddReceive(signals, func(c workflow.ReceiveChannel, _ bool) { got = c.ReceiveAsync(&raw) }).
			Select(ctx)
		if deadline.IsReady() {
			return end(OutcomeTimedOut)
		}
		if !got {
			continue // dropped by the SDK: not decodable by the data converter
		}
		a, reason := screen(raw, req, res.Approvals)
		if reason == "" {
			var check ApprovalCheck
			err := workflow.ExecuteActivity(actx, req.VerifyActivity, a).Get(ctx, &check)
			if ctx.Err() != nil || deadline.IsReady() { // late verification: nothing retained
				return end(OutcomeTimedOut)
			}
			switch {
			case err != nil:
				reason = IgnoredVerifyError
			case !check.SignatureValid:
				reason = IgnoredInvalidSignature
			case !a.Approved:
				return end(OutcomeRejected)
			case req.NeedsSecurityRole && !security && !check.SecurityRole && len(res.Approvals) == req.Required-1:
				reason = IgnoredNeedsSecurityRole
			default:
				res.Approvals = append(res.Approvals, a)
				security = security || check.SecurityRole
				if len(res.Approvals) == req.Required {
					return end(OutcomeApproved)
				}
				continue
			}
		}
		res.Ignored = append(res.Ignored, IgnoredSignal{Approver: a.Approver, Reason: reason})
		if len(res.Ignored) > req.MaxIgnored {
			return end(OutcomeSignalFlood)
		}
	}
}

// screen decodes raw and applies, in order, the checks that need no activity.
func screen(raw converter.RawValue, req ApprovalRequest, kept []Approval) (Approval, IgnoredReason) {
	a, ok := decodeApproval(raw)
	dup := slices.ContainsFunc(kept, func(k Approval) bool { return k.Approver == a.Approver })
	switch {
	case !ok:
		return a, IgnoredMalformed
	case a.PlanHash != req.PlanHash: // exact bytes: the hash is public, nothing to time
		return a, IgnoredWrongHash
	case a.Approver == req.Author:
		return a, IgnoredSelfApproval
	case a.Approved && dup:
		return a, IgnoredDuplicate
	}
	return a, ""
}

// approvalWire tells absent and null fields apart from zero values.
type approvalWire struct {
	Approved  *bool   `json:"approved"`
	PlanHash  *string `json:"plan_hash"`
	Approver  *string `json:"approver"`
	Signature *string `json:"signature"`
}

// decodeApproval accepts one bounded json/plain object with exactly the four
// fields, none null, a canonical approver and a non-empty signature.
func decodeApproval(raw converter.RawValue) (Approval, bool) {
	p := raw.Payload()
	if string(p.GetMetadata()[converter.MetadataEncoding]) != converter.MetadataEncodingJSON {
		return Approval{}, false
	}
	data := p.GetData()
	var w approvalWire
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if len(data) > MaxApprovalSignalBytes || dec.Decode(&w) != nil || !errors.Is(dec.Decode(new(json.RawMessage)), io.EOF) {
		return Approval{}, false
	}
	if w.Approved == nil || w.PlanHash == nil || w.Approver == nil || w.Signature == nil ||
		!validIdentity(*w.Approver) || *w.Signature == "" {
		return Approval{}, false
	}
	return Approval{Approved: *w.Approved, PlanHash: *w.PlanHash, Approver: *w.Approver, Signature: *w.Signature}, true
}

// validPlanHash: 64 lower-case hex digits (Trim leaves any other byte).
func validPlanHash(s string) bool {
	return len(s) == 64 && strings.Trim(s, hexDigits) == ""
}

// validIdentity: 1 to MaxIdentityBytes bytes of identityBytes; identities are
// compared byte for byte, never normalized.
func validIdentity(s string) bool {
	return s != "" && len(s) <= MaxIdentityBytes && strings.Trim(s, identityBytes) == ""
}

func invalidApproval(what string) error {
	return temporal.NewNonRetryableApplicationError("invalid approval request: "+what, ErrTypeInvalidApprovalRequest, nil)
}
```

### 4.2 `internal/loops/fake/approvals.go`
```go
// Package fake holds deterministic fakes of the loop engine: tests and the
// -dev composition root only (rule R5). Its approval verifier has no key:
// anyone can compute a valid signature (threats T12, T41).
package fake

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strconv"

	"github.com/amezianechayer/rempart/internal/loops"
)

// ApprovalVerifier accepts a signature if and only if it equals
// ExpectedSignature; SecurityRoles lists the approvers with the security role.
type ApprovalVerifier struct{ SecurityRoles map[string]bool }

// ExpectedSignature returns the hex SHA-256 of the netstrings of "fake", the
// approver, the plan hash and the decision ("true" or "false").
func ExpectedSignature(a loops.Approval) string {
	var buf []byte
	for _, s := range []string{"fake", a.Approver, a.PlanHash, strconv.FormatBool(a.Approved)} {
		buf = strconv.AppendInt(buf, int64(len(s)), 10)
		buf = append(buf, ':')
		buf = append(buf, s...)
		buf = append(buf, ',')
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}

// VerifyApproval is the verification activity; it never fails. The role
// counts only with a valid signature.
func (v *ApprovalVerifier) VerifyApproval(_ context.Context, a loops.Approval) (loops.ApprovalCheck, error) {
	ok := subtle.ConstantTimeCompare([]byte(a.Signature), []byte(ExpectedSignature(a))) == 1
	return loops.ApprovalCheck{SignatureValid: ok, SecurityRole: ok && v.SecurityRoles[a.Approver]}, nil
}
```

### 4.3 `runloop.go` (diff) et `doc.go`
```diff
@@ commentaire de RunLoop
-// result, not an error: only an invalid spec fails the workflow.
+// result, not an error: only an invalid spec or a cancellation ends in error.
@@
 		perr := workflow.ExecuteActivity(pctx, spec.ProposeActivity, req).Get(ctx, &prop)
+		if ctx.Err() != nil { // cancellation is no proposer failure (obligation b)
+			return LoopResult{}, ctx.Err()
+		}
 		if perr != nil {
@@
 		if err := workflow.ExecuteActivity(ctx, spec.VerifyActivity, vreq).Get(ctx, &vr); err != nil {
+			if ctx.Err() != nil { // cancellation is no verifier failure (obligation b)
+				return LoopResult{}, ctx.Err()
+			}
 			return escalate(ReasonActivityFailed) // Temporal retries only
```
`doc.go` : « Package loops holds the generic loop workflow RunLoop, the approval wait AwaitApprovals and, later, one workflow per product loop. Neither knows a domain: payloads and candidates are opaque JSON, findings are normalized by package domain, approvals bind an opaque plan hash. »

## 5. Tests (`test-author`)
Signaux par `env.RegisterDelayedCallback` (le signal i arrive à la minute i+1 de l'horloge du workflow) ; durées de vérification par `OnActivity(...).After(d)`.

### 5.1 `internal/loops/approvals_test.go` (`package loops_test`, 16 tests)
```go
package loops_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"

	"github.com/amezianechayer/rempart/internal/loops"
	"github.com/amezianechayer/rempart/internal/loops/fake"
)

const verifyApprovalName = "VerifyApproval"

func plan() string { return strings.Repeat("ab", 32) }

func request(required int, security bool) loops.ApprovalRequest {
	return loops.ApprovalRequest{
		PlanHash: plan(), Author: "alice", Required: required,
		NeedsSecurityRole: security, VerifyActivity: verifyApprovalName,
	}
}

func sign(a loops.Approval) loops.Approval {
	a.Signature = fake.ExpectedSignature(a)
	return a
}

// signed passes the fake verifier; forged carries the signature of another approver.
func signed(approver string, approved bool) loops.Approval {
	return sign(loops.Approval{Approved: approved, PlanHash: plan(), Approver: approver})
}

func forged(approver string, approved bool) loops.Approval {
	a := signed(approver, approved)
	a.Signature = signed("mallory", approved).Signature
	return a
}

func onHash(h string, approved bool) loops.Approval {
	return sign(loops.Approval{Approved: approved, PlanHash: h, Approver: "bob"})
}

func ign(approver string, r loops.IgnoredReason) loops.IgnoredSignal {
	return loops.IgnoredSignal{Approver: approver, Reason: r}
}

// rawJSON is a json/plain payload holding exactly data.
func rawJSON(t *testing.T, data string) converter.RawValue {
	t.Helper()
	p, err := converter.GetDefaultDataConverter().ToPayload("")
	if err != nil {
		t.Fatal(err)
	}
	p.Data = []byte(data)
	return converter.NewRawValue(p)
}

// verifier wraps the fake: it records every call and fails the first failFirst.
type verifier struct {
	mu        sync.Mutex
	fake      fake.ApprovalVerifier
	failFirst int
	seen      []string
}

func newVerifier(security ...string) *verifier {
	roles := map[string]bool{}
	for _, s := range security {
		roles[s] = true
	}
	return &verifier{fake: fake.ApprovalVerifier{SecurityRoles: roles}}
}

func (v *verifier) verify(ctx context.Context, a loops.Approval) (loops.ApprovalCheck, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.seen = append(v.seen, a.Approver)
	if len(v.seen) <= v.failFirst {
		return loops.ApprovalCheck{}, temporal.NewApplicationError("verifier unavailable", "Transient")
	}
	return v.fake.VerifyApproval(ctx, a)
}

func wantVerified(t *testing.T, v *verifier, approvers ...string) {
	t.Helper()
	v.mu.Lock()
	defer v.mu.Unlock()
	if !slices.Equal(v.seen, approvers) {
		t.Errorf("verified %v, want %v", v.seen, approvers)
	}
}

type outcome struct {
	res    loops.ApprovalResult
	err    error
	timers []time.Duration
}

func await(t *testing.T, req loops.ApprovalRequest, timeout time.Duration, v *verifier, setup func(*testsuite.TestWorkflowEnvironment), signals ...any) outcome {
	t.Helper()
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	env.RegisterActivityWithOptions(v.verify, activity.RegisterOptions{Name: verifyApprovalName})
	var out outcome
	env.SetOnTimerScheduledListener(func(_ string, d time.Duration) { out.timers = append(out.timers, d) })
	for i, s := range signals {
		env.RegisterDelayedCallback(func() { env.SignalWorkflow(loops.ApprovalSignal, s) }, time.Duration(i+1)*time.Minute)
	}
	if setup != nil {
		setup(env)
	}
	env.ExecuteWorkflow(loops.AwaitApprovals, req, timeout)
	if !env.IsWorkflowCompleted() {
		t.Fatal("workflow not completed")
	}
	if out.err = env.GetWorkflowError(); out.err == nil {
		if err := env.GetWorkflowResult(&out.res); err != nil {
			t.Fatalf("GetWorkflowResult: %v", err)
		}
	}
	return out
}

func wantOutcome(t *testing.T, out outcome, o loops.ApprovalOutcome, approvers []string, ignored ...loops.IgnoredSignal) {
	t.Helper()
	if out.err != nil {
		t.Fatalf("AwaitApprovals failed: %v", out.err)
	}
	var got []string
	for _, a := range out.res.Approvals {
		got = append(got, a.Approver)
	}
	if out.res.Outcome != o || !slices.Equal(got, approvers) || !slices.Equal(out.res.Ignored, ignored) {
		t.Fatalf("got %q %v, ignored %v; want %q %v, ignored %v", out.res.Outcome, got, out.res.Ignored, o, approvers, ignored)
	}
}

func TestAwaitApprovalsTimeoutDoesNothing(t *testing.T) {
	v := newVerifier()
	out := await(t, request(1, false), time.Hour, v, nil)
	wantOutcome(t, out, loops.OutcomeTimedOut, nil)
	wantVerified(t, v)
	if !slices.Equal(out.timers, []time.Duration{time.Hour}) {
		t.Errorf("timers %v, want the timeout only", out.timers)
	}
	t.Run("partial quorum not retained", func(t *testing.T) {
		v := newVerifier()
		wantOutcome(t, await(t, request(2, false), time.Hour, v, nil, signed("bob", true)), loops.OutcomeTimedOut, nil)
		wantVerified(t, v, "bob")
	})
	t.Run("signal after the deadline", func(t *testing.T) {
		v := newVerifier()
		wantOutcome(t, await(t, request(1, false), 30*time.Second, v, nil, signed("bob", true)), loops.OutcomeTimedOut, nil)
		wantVerified(t, v)
	})
}

func TestAwaitApprovalsWrongHashIgnored(t *testing.T) {
	v, other := newVerifier(), strings.Repeat("cd", 32)
	out := await(t, request(1, false), time.Hour, v, nil, onHash(other, true), onHash(strings.ToUpper(plan()), true),
		onHash(plan()[:63], true), onHash(other, false), signed("bob", true))
	w := ign("bob", loops.IgnoredWrongHash)
	wantOutcome(t, out, loops.OutcomeApproved, []string{"bob"}, w, w, w, w)
	wantVerified(t, v, "bob")
	if out.res.Approvals[0] != signed("bob", true) {
		t.Errorf("approval %+v", out.res.Approvals[0])
	}
}

func TestAwaitApprovalsInvalidSignatureIgnored(t *testing.T) {
	v, upper := newVerifier(), signed("bob", true)
	upper.Signature = strings.ToUpper(upper.Signature)
	out := await(t, request(1, false), time.Hour, v, nil, forged("bob", true), upper, signed("bob", true))
	w := ign("bob", loops.IgnoredInvalidSignature)
	wantOutcome(t, out, loops.OutcomeApproved, []string{"bob"}, w, w)
	wantVerified(t, v, "bob", "bob", "bob")
}

func TestAwaitApprovalsSelfApprovalIgnored(t *testing.T) {
	v := newVerifier()
	out := await(t, request(1, false), time.Hour, v, nil, signed("alice", true), signed("alice", false), signed("bob", true))
	w := ign("alice", loops.IgnoredSelfApproval)
	wantOutcome(t, out, loops.OutcomeApproved, []string{"bob"}, w, w)
	wantVerified(t, v, "bob")
}

func TestAwaitApprovalsDuplicateApproverIgnored(t *testing.T) {
	v := newVerifier()
	out := await(t, request(2, false), time.Hour, v, nil, signed("bob", true), signed("bob", true), forged("bob", true), signed("carol", true))
	w := ign("bob", loops.IgnoredDuplicate)
	wantOutcome(t, out, loops.OutcomeApproved, []string{"bob", "carol"}, w, w)
	wantVerified(t, v, "bob", "carol")
}

func TestAwaitApprovalsQuorumWithSecurityRole(t *testing.T) {
	v := newVerifier("carol")
	out := await(t, request(2, true), time.Hour, v, nil, signed("bob", true), signed("carol", true), signed("dave", true))
	wantOutcome(t, out, loops.OutcomeApproved, []string{"bob", "carol"})
	wantVerified(t, v, "bob", "carol")
	t.Run("one approver with the role", func(t *testing.T) {
		out := await(t, request(1, true), time.Hour, newVerifier("carol"), nil, signed("bob", true), signed("carol", true))
		wantOutcome(t, out, loops.OutcomeApproved, []string{"carol"}, ign("bob", loops.IgnoredNeedsSecurityRole))
	})
}

func TestAwaitApprovalsQuorumWithoutSecurityRoleKeepsWaiting(t *testing.T) {
	w := ign("carol", loops.IgnoredNeedsSecurityRole)
	out := await(t, request(2, true), time.Hour, newVerifier("dave"), nil, signed("bob", true), signed("carol", true))
	wantOutcome(t, out, loops.OutcomeTimedOut, nil, w)
	out = await(t, request(2, true), time.Hour, newVerifier("dave"), nil, signed("bob", true), signed("carol", true), signed("dave", true))
	wantOutcome(t, out, loops.OutcomeApproved, []string{"bob", "dave"}, w)
}

func TestAwaitApprovalsAuthenticatedRefusalStops(t *testing.T) {
	v := newVerifier()
	out := await(t, request(2, false), time.Hour, v, nil, signed("bob", true), signed("carol", false), signed("dave", true))
	wantOutcome(t, out, loops.OutcomeRejected, nil)
	wantVerified(t, v, "bob", "carol")
	t.Run("an approver withdraws", func(t *testing.T) {
		out := await(t, request(2, false), time.Hour, newVerifier(), nil, signed("bob", true), signed("bob", false), signed("carol", true))
		wantOutcome(t, out, loops.OutcomeRejected, nil)
	})
}

func TestAwaitApprovalsUnauthenticatedRefusalIgnored(t *testing.T) {
	out := await(t, request(1, false), time.Hour, newVerifier(), nil, forged("bob", false), forged("carol", false), signed("dave", true))
	wantOutcome(t, out, loops.OutcomeApproved, []string{"dave"},
		ign("bob", loops.IgnoredInvalidSignature), ign("carol", loops.IgnoredInvalidSignature))
}

func TestAwaitApprovalsMalformedSignalIgnored(t *testing.T) {
	valid := signed("bob", true)
	body, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	j := string(body)
	noApproved, err := json.Marshal(map[string]string{"plan_hash": plan(), "approver": "bob", "signature": valid.Signature})
	if err != nil {
		t.Fatal(err)
	}
	huge, unsigned := valid, valid
	huge.Signature, unsigned.Signature = strings.Repeat("a", loops.MaxApprovalSignalBytes), ""
	malformed := []any{
		rawJSON(t, j[:len(j)-1]), rawJSON(t, j+" {}"), rawJSON(t, strings.Replace(j, "{", `{"scope":"all",`, 1)),
		rawJSON(t, string(noApproved)), rawJSON(t, strings.Replace(j, "true", `"true"`, 1)),
		rawJSON(t, strings.Replace(j, `"`+valid.Signature+`"`, "null", 1)),
		rawJSON(t, "null"), rawJSON(t, "[]"), rawJSON(t, `"approved"`), body, nil, huge, unsigned,
		signed("Bob", true), signed(" bob", true), signed("", true), signed(strings.Repeat("b", loops.MaxIdentityBytes+1), true),
	}
	req, v := request(1, false), newVerifier()
	req.MaxIgnored = len(malformed)
	out := await(t, req, time.Hour, v, nil, append(malformed, valid)...)
	wantOutcome(t, out, loops.OutcomeApproved, []string{"bob"}, slices.Repeat([]loops.IgnoredSignal{ign("", loops.IgnoredMalformed)}, len(malformed))...)
	wantVerified(t, v, "bob")
	t.Run("size bound", func(t *testing.T) {
		pad := func(n int) converter.RawValue { return rawJSON(t, j+strings.Repeat(" ", n-len(j))) }
		out := await(t, request(1, false), time.Hour, newVerifier(), nil, pad(loops.MaxApprovalSignalBytes+1), pad(loops.MaxApprovalSignalBytes))
		wantOutcome(t, out, loops.OutcomeApproved, []string{"bob"}, ign("", loops.IgnoredMalformed))
	})
}

func TestAwaitApprovalsVerifierErrorIgnored(t *testing.T) {
	v := newVerifier()
	v.failFirst = 1
	out := await(t, request(1, false), time.Hour, v, nil, signed("bob", true), signed("bob", true))
	wantOutcome(t, out, loops.OutcomeApproved, []string{"bob"}, ign("bob", loops.IgnoredVerifyError))
	wantVerified(t, v, "bob", "bob") // one attempt per signal
}

func TestAwaitApprovalsSignalFlood(t *testing.T) {
	wrong, w := onHash(strings.Repeat("cd", 32), true), ign("bob", loops.IgnoredWrongHash)
	req, v := request(1, false), newVerifier()
	req.MaxIgnored = 3
	out := await(t, req, time.Hour, v, nil, wrong, wrong, rawJSON(t, "{}"), wrong, signed("bob", true))
	wantOutcome(t, out, loops.OutcomeSignalFlood, nil, w, w, ign("", loops.IgnoredMalformed), w)
	wantVerified(t, v)
	t.Run("at the bound the wait goes on", func(t *testing.T) {
		out := await(t, req, time.Hour, newVerifier(), nil, wrong, wrong, wrong, signed("bob", true))
		wantOutcome(t, out, loops.OutcomeApproved, []string{"bob"}, w, w, w)
	})
	t.Run("default bound", func(t *testing.T) {
		flood := slices.Repeat([]any{wrong}, loops.DefaultMaxIgnored)
		out := await(t, request(1, false), 3*time.Hour, newVerifier(), nil, append(flood, signed("bob", true))...)
		wantOutcome(t, out, loops.OutcomeApproved, []string{"bob"}, slices.Repeat([]loops.IgnoredSignal{w}, loops.DefaultMaxIgnored)...)
	})
}

func TestAwaitApprovalsInvalidRequest(t *testing.T) {
	valid := request(1, false)
	valid.Author = "canary-author"
	with := func(f func(*loops.ApprovalRequest)) loops.ApprovalRequest {
		r := valid
		f(&r)
		return r
	}
	invalid := []loops.ApprovalRequest{
		with(func(r *loops.ApprovalRequest) { r.PlanHash = "" }),
		with(func(r *loops.ApprovalRequest) { r.PlanHash = strings.ToUpper(plan()) }),
		with(func(r *loops.ApprovalRequest) { r.PlanHash = plan()[:63] }),
		with(func(r *loops.ApprovalRequest) { r.PlanHash = plan() + "a" }),
		with(func(r *loops.ApprovalRequest) { r.PlanHash = strings.Repeat("g", 64) }),
		with(func(r *loops.ApprovalRequest) { r.Author = "" }),
		with(func(r *loops.ApprovalRequest) { r.Author = "Canary-author" }),
		with(func(r *loops.ApprovalRequest) { r.Author = "canary author" }),
		with(func(r *loops.ApprovalRequest) { r.Author = strings.Repeat("c", loops.MaxIdentityBytes+1) }),
		with(func(r *loops.ApprovalRequest) { r.Required = 0 }),
		with(func(r *loops.ApprovalRequest) { r.Required = loops.MaxRequiredApprovals + 1 }),
		with(func(r *loops.ApprovalRequest) { r.VerifyActivity = "" }),
		with(func(r *loops.ApprovalRequest) { r.MaxIgnored = -1 }),
		with(func(r *loops.ApprovalRequest) { r.MaxIgnored = loops.MaxIgnoredLimit + 1 }),
	}
	isInvalid := func(err error) bool {
		var ae *temporal.ApplicationError
		return errors.As(err, &ae) && ae.Type() == loops.ErrTypeInvalidApprovalRequest && ae.NonRetryable() &&
			!strings.Contains(strings.ToLower(err.Error()), "canary")
	}
	for i, r := range invalid {
		if err := r.Validate(); !isInvalid(err) {
			t.Errorf("case %d: Validate() = %v", i, err)
		}
	}
	for i, r := range []loops.ApprovalRequest{
		valid,
		with(func(r *loops.ApprovalRequest) { r.Author = "0.9_-@z" }),
		with(func(r *loops.ApprovalRequest) {
			r.Author, r.Required, r.MaxIgnored = strings.Repeat("c", loops.MaxIdentityBytes), loops.MaxRequiredApprovals, loops.MaxIgnoredLimit
		}),
	} {
		if err := r.Validate(); err != nil {
			t.Errorf("valid case %d refused: %v", i, err)
		}
	}
	for i, c := range []struct {
		req     loops.ApprovalRequest
		timeout time.Duration
	}{{invalid[0], time.Hour}, {invalid[9], time.Hour}, {valid, 0}, {valid, -time.Second}, {valid, loops.MaxApprovalTimeout + time.Second}} {
		v := newVerifier()
		out := await(t, c.req, c.timeout, v, nil, signed("bob", true))
		if !isInvalid(out.err) || len(out.timers) != 0 {
			t.Errorf("case %d: error %v, timers %v", i, out.err, out.timers)
		}
		wantVerified(t, v)
	}
	wantOutcome(t, await(t, valid, loops.MaxApprovalTimeout, newVerifier(), nil, signed("bob", true)), loops.OutcomeApproved, []string{"bob"})
}

func TestAwaitApprovalsCanceled(t *testing.T) {
	canceled := func(t *testing.T, out outcome) {
		t.Helper()
		if !temporal.IsCanceledError(out.err) {
			t.Fatalf("error %v, outcome %q: want the cancellation, never an outcome", out.err, out.res.Outcome)
		}
	}
	t.Run("while waiting", func(t *testing.T) {
		v := newVerifier()
		canceled(t, await(t, request(1, false), time.Hour, v, func(env *testsuite.TestWorkflowEnvironment) {
			env.RegisterDelayedCallback(env.CancelWorkflow, 30*time.Minute)
		}, forged("bob", true)))
		wantVerified(t, v, "bob")
	})
	t.Run("during a verification", func(t *testing.T) {
		v := newVerifier()
		canceled(t, await(t, request(1, false), time.Hour, v, func(env *testsuite.TestWorkflowEnvironment) {
			env.OnActivity(verifyApprovalName, mock.Anything, mock.Anything).Return(v.verify).After(20 * time.Minute)
			env.RegisterDelayedCallback(env.CancelWorkflow, 10*time.Minute)
		}, signed("bob", true)))
	})
}

func TestAwaitApprovalsDeadlineDuringVerification(t *testing.T) {
	v := newVerifier()
	out := await(t, request(1, false), time.Hour, v, func(env *testsuite.TestWorkflowEnvironment) {
		env.OnActivity(verifyApprovalName, mock.Anything, mock.Anything).Return(v.verify).After(time.Hour)
	}, signed("bob", true))
	wantOutcome(t, out, loops.OutcomeTimedOut, nil)
	wantVerified(t, v, "bob")
}

func TestAwaitApprovalsLimitsFrozen(t *testing.T) {
	got := []any{
		loops.ApprovalSignal, loops.ErrTypeInvalidApprovalRequest, loops.DefaultMaxIgnored, loops.MaxIgnoredLimit, loops.MaxRequiredApprovals,
		loops.MaxApprovalTimeout, loops.VerifyApprovalTimeout, loops.MaxApprovalSignalBytes, loops.MaxIdentityBytes,
	}
	frozen := []any{"approval", "InvalidApprovalRequest", 100, 1000, 5, 7 * 24 * time.Hour, 30 * time.Second, 8192, 128}
	if !slices.Equal(got, frozen) {
		t.Errorf("limits %v, want %v", got, frozen)
	}
	codes := []string{
		string(loops.OutcomeApproved), string(loops.OutcomeRejected), string(loops.OutcomeTimedOut), string(loops.OutcomeSignalFlood),
		string(loops.IgnoredMalformed), string(loops.IgnoredWrongHash), string(loops.IgnoredSelfApproval), string(loops.IgnoredDuplicate),
		string(loops.IgnoredVerifyError), string(loops.IgnoredInvalidSignature), string(loops.IgnoredNeedsSecurityRole),
	}
	want := []string{
		"approved", "rejected", "timed_out", "signal_flood", "malformed", "wrong_hash",
		"self_approval", "duplicate", "verify_error", "invalid_signature", "needs_security_role",
	}
	if !slices.Equal(codes, want) {
		t.Errorf("codes %v, want %v", codes, want)
	}
}
```
Indices 0 et 9 de `invalid` : hash vide, `Required` nul.

### 5.2 `internal/loops/fake/approvals_test.go` (`package fake_test`)
```go
package fake_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/amezianechayer/rempart/internal/loops"
	"github.com/amezianechayer/rempart/internal/loops/fake"
)

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func sign(approver string) loops.Approval {
	a := loops.Approval{Approved: true, PlanHash: strings.Repeat("ab", 32), Approver: approver}
	a.Signature = fake.ExpectedSignature(a)
	return a
}

func TestFakeExpectedSignature(t *testing.T) {
	h := strings.Repeat("ab", 32)
	a := loops.Approval{Approved: true, PlanHash: h, Approver: "bob", Signature: "not covered"}
	if got := fake.ExpectedSignature(a); got != sum("4:fake,3:bob,64:"+h+",4:true,") {
		t.Errorf("approval: %s", got)
	}
	a.Approved = false
	if got := fake.ExpectedSignature(a); got != sum("4:fake,3:bob,64:"+h+",5:false,") {
		t.Errorf("refusal: %s", got)
	}
	if fake.ExpectedSignature(loops.Approval{Approver: "a|b", PlanHash: "c"}) == fake.ExpectedSignature(loops.Approval{Approver: "a", PlanHash: "b|c"}) {
		t.Error("ambiguous encoding")
	}
}

func TestFakeApprovalVerifier(t *testing.T) {
	v := &fake.ApprovalVerifier{SecurityRoles: map[string]bool{"carol": true, "mallory": true}}
	stolen, upper, empty := sign("mallory"), sign("carol"), sign("carol")
	stolen.Signature, upper.Signature, empty.Signature = sign("bob").Signature, strings.ToUpper(upper.Signature), ""
	for i, c := range []struct {
		a    loops.Approval
		want loops.ApprovalCheck
	}{
		{sign("bob"), loops.ApprovalCheck{SignatureValid: true}},
		{sign("carol"), loops.ApprovalCheck{SignatureValid: true, SecurityRole: true}},
		{stolen, loops.ApprovalCheck{}}, {upper, loops.ApprovalCheck{}}, {empty, loops.ApprovalCheck{}},
	} {
		if got, err := v.VerifyApproval(t.Context(), c.a); err != nil || got != c.want {
			t.Errorf("case %d: %+v, %v; want %+v", i, got, err, c.want)
		}
	}
	if got, err := (&fake.ApprovalVerifier{}).VerifyApproval(t.Context(), sign("carol")); err != nil || got != (loops.ApprovalCheck{SignatureValid: true}) {
		t.Errorf("without roles: %+v, %v", got, err)
	}
}
```

### 5.3 `runloop_test.go` (ajout en fin de fichier, `package loops`)
```go
func TestRunLoopCanceled(t *testing.T) {
	for _, name := range []string{proposeName, verifyName} {
		t.Run(name, func(t *testing.T) {
			s := newScript(fail(high("A")), pass())
			var fn any = s.propose
			if name == verifyName {
				fn = s.verify
			}
			_, err := execute(t, testSpec(), s, func(env *testsuite.TestWorkflowEnvironment) {
				env.OnActivity(name, mock.Anything, mock.Anything).Return(fn).After(30 * time.Minute)
				env.RegisterDelayedCallback(env.CancelWorkflow, 10*time.Minute)
			})
			if !temporal.IsCanceledError(err) {
				t.Fatalf("error %v: a cancellation is neither an escalation nor a failure", err)
			}
		})
	}
}
```

## 6. Critères d'acceptation (racine)
| # | Commande | Attendu |
|---|---|---|
| 1 | `go test ./internal/loops/... -count=1 -run TestAwaitApprovals -v 2>&1 \| grep -c -- '^--- PASS: TestAwaitApprovals'` ; idem `grep -cE -- '--- (FAIL\|SKIP)'` | `16` ; `0` |
| 2 | `go test ./internal/loops/... -count=1 -run 'TestRunLoopConverges\|TestRunLoopStagnationSwitchesStrategy\|TestRunLoopStagnationEscalates\|TestRunLoopBudget\|TestAwaitApprovalsTimeoutDoesNothing' -v 2>&1 \| grep -c -- '^--- PASS'` | `7` (critère 2 de M0) |
| 3 | `go test ./internal/loops/ -count=1 -run TestRunLoop -v 2>&1 \| grep -c -- '^--- PASS: TestRunLoop'` | `19` |
| 4 | `go test ./internal/loops/fake/ -count=1 -run TestFake -v 2>&1 \| grep -c -- '^--- PASS: TestFake'` | `2` |
| 5 | `go test ./internal/loops/... -count=1 -race; echo rc=$?` | `rc=0` |
| 6 | `go tool workflowcheck ./internal/loops/...; echo rc=$?` | aucun diagnostic, `rc=0` |
| 7 | `go list -f '{{join .Imports " "}}' ./internal/loops ./internal/loops/fake \| sed 's#github.com/amezianechayer/rempart/##g'` | `bytes encoding/json errors internal/loops/domain go.temporal.io/sdk/converter go.temporal.io/sdk/temporal go.temporal.io/sdk/workflow io slices strings time` puis `context crypto/sha256 crypto/subtle encoding/hex internal/loops strconv` |
| 8 | `go test ./internal/archtest/ -count=1 -run TestRepositoryConforms; echo rc=$?` | `rc=0` (R3, R4, R5) |
| 9 | `grep -nE 'time\.(Now\|Sleep)\|math/rand\|"os"\|"log\|go func\|<-' internal/loops/*.go internal/loops/fake/*.go \| grep -v _test.go \| wc -l` ; `grep -c 'range' internal/loops/approvals.go` | `0` ; `0` |
| 10 | `grep -rnE '//[[:space:]]*(nolint\|#nosec)\|workflowcheck:ignore\|panic\(' --include='*.go' internal/loops \| wc -l` | `0` |
| 11 | `golangci-lint run ./internal/loops/...; echo rc=$?` ; `gofumpt -l internal/loops \| wc -l` | `rc=0` ; `0` |
| 12 | `go mod tidy -diff; echo rc=$?` | `rc=0` |
| 13 | M1 à M25 (section 7) sur copie | 25 détectées |
| 14 | M1 à M27 de `docs/plans/M0-runloop.md` (sections 7 et 11.4, V3) sur copie du code final | 27 détectées |
| 15 | `make verify-quick; echo rc=$?` | `rc=0` |

Effet sur M0-T14 (ligne V4 de `M0-runloop.md`) : critère 1 : `19` ; critère 4 : première ligne du critère 7 ci-dessus.

## 7. Mutations sur copie
Script de `docs/plans/M0-tenancy.md` 8.3 avec le fichier en premier argument (`A` : `internal/loops/approvals.go`, `F` : `internal/loops/fake/approvals.go`, `R` : `internal/loops/runloop.go`), `OLD` présent une fois ; `go test ./internal/loops/... -count=1 2>&1 | grep -cE -- "--- FAIL: ($EXPECTED)"` au moins `1` (préfixe `TestAwaitApprovals` omis ci-dessous sauf pour `F` et `R`). « faux » : `case false:` ou `if false {`.

| # | | `OLD` | `NEW` | `EXPECTED` |
|---|---|---|---|---|
| M1 | A | `case !validPlanHash(r.PlanHash):` | `case r.PlanHash == "":` | InvalidRequest |
| M2 | A | `case r.Required < 1 \|\| r.Required > MaxRequiredApprovals:` | `case r.Required < 1:` | InvalidRequest |
| M3 | A | `if timeout <= 0 \|\| timeout > MaxApprovalTimeout {` | `if timeout < 0 {` | InvalidRequest |
| M4 | A | `&temporal.RetryPolicy{MaximumAttempts: 1}` | `&temporal.RetryPolicy{MaximumAttempts: 3}` | VerifierErrorIgnored |
| M5 | A | `deadline := workflow.NewTimer(tctx, timeout)` | `deadline := workflow.NewTimer(tctx, 2*timeout)` | TimeoutDoesNothing |
| M6 | A | `if o != OutcomeApproved {` | faux | TimeoutDoesNothing |
| M7 | A | `if err := ctx.Err(); err != nil {` | `if err := ctx.Err(); errors.Is(err, io.EOF) {` | Canceled |
| M8 | A | `if ctx.Err() != nil \|\| deadline.IsReady() {` | `if ctx.Err() != nil {` | DeadlineDuringVerification |
| M9 | A | `case err != nil:` | `case errors.Is(err, io.EOF):` | VerifierErrorIgnored |
| M10 | A | `case !check.SignatureValid:` | faux | InvalidSignatureIgnored |
| M11 | A | `case !a.Approved:` | faux | AuthenticatedRefusalStops |
| M12 | A | `case req.NeedsSecurityRole && !security && !check.SecurityRole && len(res.Approvals) == req.Required-1:` | faux | QuorumWithoutSecurityRoleKeepsWaiting |
| M13 | A | `if len(res.Ignored) > req.MaxIgnored {` | `>=` au lieu de `>` | SignalFlood |
| M14 | A | `case a.PlanHash != req.PlanHash:` | faux | WrongHashIgnored |
| M15 | A | `case a.Approver == req.Author:` | faux | SelfApprovalIgnored |
| M16 | A | `return k.Approver == a.Approver` | `return false` | DuplicateApproverIgnored |
| M17 | A | `dec.DisallowUnknownFields()` | `dec.UseNumber()` | MalformedSignalIgnored |
| M18 | A | `!errors.Is(dec.Decode(new(json.RawMessage)), io.EOF)` | `errors.Is(dec.Decode(new(json.RawMessage)), io.ErrUnexpectedEOF)` | MalformedSignalIgnored |
| M19 | A | `if string(p.GetMetadata()[converter.MetadataEncoding]) != converter.MetadataEncodingJSON {` | faux | MalformedSignalIgnored |
| M20 | A | `strings.Trim(s, identityBytes) == ""` | `true` | InvalidRequest |
| M21 | A | `w.Approved == nil \|\|` | `false \|\|` | MalformedSignalIgnored |
| M22 | F | `[]byte(ExpectedSignature(a))` | `[]byte(a.Signature)` | TestFakeApprovalVerifier |
| M23 | F | `SecurityRole: ok && v.SecurityRoles[a.Approver]` | `SecurityRole: v.SecurityRoles[a.Approver]` | TestFakeApprovalVerifier |
| M24 | R | `if ctx.Err() != nil { // cancellation is no proposer failure (obligation b)` | faux | TestRunLoopCanceled |
| M25 | R | `if ctx.Err() != nil { // cancellation is no verifier failure (obligation b)` | faux | TestRunLoopCanceled |

Non mutée : `if deadline.IsReady() {` (sa suppression boucle sans céder : détection par le détecteur d'interblocage, lente) ; annulation du minuteur au retour (D8).

## 8. Boucle (gabarit `loop-engineering`, règle 8)
```yaml
id: attente-approbation   # brique de L4, appelée par le workflow de démonstration (T19)
purpose: réunir un quorum d'approbations signées liées au hash exact d'un plan, sinon ne rien faire
trigger: appel par un workflow produit, plan calculé et risque classé
inputs: [ApprovalRequest (constantes et classification, jamais une entrée), signaux "approval" non fiables]
strategies: []            # sans proposeur
steps: {receive: signal brut et décodage strict (D1, D2), verify: activité déterministe, 1 tentative, 30 s (D7), decide: ordre D5, quorum D6}
budget: {timeout: "<= 7 j", max_ignored: "100, <= 1000", activites: "<= MaxIgnored + Required + 1"}
stall_detection: sans objet
escalation: {to: workflow appelant, payload: [issue, approbations si approved, signaux ignorés]}
outputs: [ApprovalResult]
idempotency_keys: sans objet (aucun effet externe, vérification en lecture)
security_notes: aucune décision par un LLM ; le runner revérifie hash, signatures et quorum (M4)
evals: sans objet (pas de LLM)
```

## 9. Risques, menaces, points non vérifiés
Risques : déni par inondation (D9, sûr) ; approbation reçue juste avant l'échéance perdue si sa vérification finit après (D8) ; forme canonique des identités peut-être incompatible avec l'IdP (M4) ; signatures dans l'historique Temporal en clair (risque accepté M0) ; un refus authentifié de tout approbateur reconnu arrête l'attente (droit de veto : l'autorisation relève du vérificateur, D7).

Menaces (`security-reviewer`, `docs/02-THREAT-MODEL.md`) : **T12** renforcée (D3 à D7, tests 2 à 9, M10 à M16) ; **T18** : signaux forgés via le frontend ignorés, comptés, bornés (D9) ; **T10** : activités par attente bornées, 30 s chacune ; **T16** : bornes d'`approvals.go` dans le contrat de rejeu (`GetVersion`, M1) ; **T41 étendue** : vérificateur factice sans clé câblé hors `-dev` : toute approbation forgeable ; test de configuration de production sans faux en T20 ; **T54 étendue** : un `VerifyActivity` issu d'une entrée désignerait toute activité rendant `signature_valid: true` ; **T55 étendue** (M1) : le convertisseur de Rempart doit laisser passer `RawValue`, et un signal que le codec ne déchiffre pas est jeté par le SDK sans être compté ; test avec le vrai convertisseur. Menace proposée **T56** : rejeu d'approbation : la signature ne couvre qu'approbateur, hash et décision : une approbation d'une demande expirée ou refusée vaut pour une nouvelle demande du même plan, voire pour un autre tenant à hash égal ; M4 : message signé avec tenant, identifiant de demande et échéance, revérifié par le runner.

Points non vérifiés (A2 sur copie, sinon amendement V1) :
1. `workflowcheck` muet sous `json.Decoder`, `bytes.Reader`, `strings.Trim`, `converter.RawValue`. Parade : `workflowcheck.config.yaml` et `-config` dans `arch-test`, jamais `//workflowcheck:ignore`.
2. Testsuite : `SignalWorkflow` transmet une `RawValue` telle quelle (`ToPayloads`, l. 43) ; `p.Data = ...` compile sans importer `go.temporal.io/api` ; `nil` donne `binary/null` et `[]byte` `binary/plain`.
3. Chronologie : échéance tirée pendant une activité `.After` (minuteur antérieur tiré d'abord, `autoFireNextTimer`), `IsReady` vrai au retour de `Get` ; écouteur de minuteur sans course sous `-race`.
4. Annulation : `temporal.IsCanceledError` sur `GetWorkflowError` (`Unwrap`, `error.go` l. 1064) ; goroutine du mock `.After` bloquée après annulation, sans effet ; `Return(fn)` avec `fn` de type `any`.
5. M4 : reprise effective sous horloge simulée (`ScheduleToClose` 30 s, intervalle 1 s).
6. Lints : staticcheck (dont QF), `govet` `unusedwrite`, `nilerr` après la vérification.
7. Serveur réel (pas de Docker) : annulation du minuteur, ordre des signaux, `ScheduleToClose`, plafond de signaux par exécution.

`docs/STATUS.md` (F3) : obligation (b) soldée ; nouvelles obligations : T41 étendue (T20), T54 étendue et `TestAwaitApprovalsNotRegistered` (T19), T55 étendue (M1), T56 et contrat `SignatureValid` (M4, ADR des approbations signées) ; écarts D1, D5, D6, D13 à reporter dans `temporal-loop-skeleton.md` en T19 (obligation (g)).

## 10. Tâches ordonnées (après validation humaine)
| # | Tâche | Qui | Vérification |
|---|---|---|---|
| A1 | `phase tests` ; section 5 (deux fichiers neufs, `TestRunLoopCanceled` en fin de `runloop_test.go`) | `test-author` | `go vet ./internal/loops/...` : erreurs seulement sur des identifiants de `loops` et `fake` à créer |
| A2 | Copie : sections 4 et 5, critères 1 à 14, points non vérifiés ; sur copie sans `approvals_test.go` ni diff de `runloop.go`, `TestRunLoopCanceled` échoue (escalade, erreur nil) | `test-author` | vert, 25 et 27 détectées ; sinon amendement V1 |
| A3 | `phase impl` | principal | `Phase : tests -> impl` |
| I1 | `approvals.go`, `fake/approvals.go`, diff de `runloop.go`, `doc.go` | principal | critères 1 à 12, 15 |
| F1 | Critères 13 et 14 sur copie du code final | principal | 25 et 27 détectées |
| F2 | `security-reviewer` (section 9), puis `acceptance-verifier` | subagents | PASS |
| F3 | `docs/STATUS.md` (section 9), ligne V4 de `M0-runloop.md` (section 6), `phase free`, commit `feat(loops): await plan-hash-bound approvals with quorum, security role and fake verifier (M0-T15)` | principal | `git status --porcelain` vide |
