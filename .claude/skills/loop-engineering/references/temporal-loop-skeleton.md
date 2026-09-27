# Squelette Go/Temporal de RunLoop

Référence : le moteur générique est implémenté dans `internal/loops` (M0-T14, T15, T19b, T19c). Ce fichier n'est plus un point de départ à copier : il résume les déclarations compilées et les règles qui les entourent. En cas d'écart, le code et ses tests font foi. Exemple complet de boucle : `internal/loops/demo` (M0-T19d, fiche `docs/loops/L0-demo.md`).

## Déclarations (paquet `loops`, sans corps de fonction)

Types, constantes et signatures exportés, extraits du code à M0-T19d. `domain.Finding` vient de `internal/loops/domain` (voir `normalized-findings.md`).

```go
package loops

import (
	"encoding/json"
	"time"

	"github.com/amezianechayer/rempart/internal/loops/domain"
	"go.temporal.io/sdk/workflow"
)

const ApprovalSignal = "approval"

const ErrTypeInvalidApprovalRequest = "InvalidApprovalRequest"

const (
	DefaultMaxIgnored      = 100
	MaxIgnoredLimit        = 1000
	MaxRequiredApprovals   = 5
	MaxApprovalTimeout     = 7 * 24 * time.Hour
	VerifyApprovalTimeout  = 30 * time.Second
	MaxApprovalSignalBytes = 8 << 10
	MaxIdentityBytes       = 128
)

type ApprovalRequest struct {
	PlanHash          string // SHA-256 of the plan, 64 lower-case hex digits
	Author            string // canonical identity; none of its signals counts
	Required          int    // distinct approvers, 1 to MaxRequiredApprovals
	NeedsSecurityRole bool   // one of them at least has the security role
	VerifyActivity    string // registered verification activity
	MaxIgnored        int    // 0 means DefaultMaxIgnored
}

type Approval struct {
	Approved  bool   `json:"approved"`
	PlanHash  string `json:"plan_hash"`
	Approver  string `json:"approver"`
	Signature string `json:"signature"`
}

type ApprovalCheck struct {
	SignatureValid bool `json:"signature_valid"`
	SecurityRole   bool `json:"security_role"`
}

type ApprovalOutcome string

const (
	OutcomeApproved    ApprovalOutcome = "approved"
	OutcomeRejected    ApprovalOutcome = "rejected"
	OutcomeTimedOut    ApprovalOutcome = "timed_out"
	OutcomeSignalFlood ApprovalOutcome = "signal_flood"
)

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

type IgnoredSignal struct {
	DeclaredApprover string        `json:"declared_approver"`
	Reason           IgnoredReason `json:"reason"`
}

type ApprovalResult struct {
	Outcome   ApprovalOutcome `json:"outcome"`
	Approvals []Approval      `json:"approvals,omitempty"`
	Ignored   []IgnoredSignal `json:"ignored,omitempty"`
}

// Validate checks r once defaults are applied. The error is a non-retryable
// application error of type ErrTypeInvalidApprovalRequest that never quotes r.
func (r ApprovalRequest) Validate() error

// AwaitApprovals waits until req.Required distinct approvers approve
// req.PlanHash, one of them with the security role if required, or until one
// authenticated refusal. An invalid signal is recorded and ignored without
// ending the wait, unless more than req.MaxIgnored were. Timeout: nothing is
// approved. The error is an invalid request or the cancellation of ctx,
// never an outcome.
func AwaitApprovals(ctx workflow.Context, req ApprovalRequest, timeout time.Duration) (ApprovalResult, error)

type ProposeRequest struct {
	Payload   json.RawMessage  `json:"payload"`
	Strategy  string           `json:"strategy"`
	Best      json.RawMessage  `json:"best,omitempty"`
	Findings  []domain.Finding `json:"findings,omitempty"`
	Iteration int              `json:"iteration"`
}

type ProposeResponse struct {
	Candidate json.RawMessage `json:"candidate"`
	Tokens    int             `json:"tokens"`
}

type ProposeFailure struct {
	Tokens int `json:"tokens"`
}

type VerifyRequest struct {
	Payload   json.RawMessage `json:"payload"`
	Candidate json.RawMessage `json:"candidate"`
	Iteration int             `json:"iteration"`
}

type VerifyResult struct {
	OK       bool             `json:"ok"`
	Findings []domain.Finding `json:"findings"`
}

type Status string

const (
	StatusConverged Status = "converged"
	StatusEscalated Status = "escalated"
)

type Reason string

const (
	ReasonBudgetIterations    Reason = "budget_iterations"
	ReasonBudgetTokens        Reason = "budget_tokens"
	ReasonBudgetTime          Reason = "budget_time"
	ReasonStagnation          Reason = "stagnation"
	ReasonStrategiesExhausted Reason = "strategies_exhausted"
	ReasonActivityFailed      Reason = "activity_failed"
	ReasonInvalidResponse     Reason = "invalid_response"
)

type IterationTrace struct {
	Iteration   int    `json:"iteration"`
	Strategy    string `json:"strategy"`
	Failed      bool   `json:"failed"`
	Verified    bool   `json:"verified"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Score       int    `json:"score"`
	Findings    int    `json:"findings"`
	Tokens      int    `json:"tokens"`
}

type LoopResult struct {
	Status     Status           `json:"status"`
	Reason     Reason           `json:"reason,omitempty"`
	Best       json.RawMessage  `json:"best,omitempty"`
	Remaining  []domain.Finding `json:"remaining,omitempty"`
	Iterations int              `json:"iterations"`
	Tokens     int              `json:"tokens"`
	Trace      []IterationTrace `json:"trace"`
}

// RunLoop proposes and verifies until the verifier accepts a candidate, or a
// budget, a stagnation, a failed activity or an invalid response escalates. An
// escalation is a result, not an error: only an invalid spec or payload or a
// cancellation ends in error.
func RunLoop(ctx workflow.Context, spec LoopSpec, payload json.RawMessage) (LoopResult, error)

const (
	ErrTypeInvalidLoopSpec = "InvalidLoopSpec"
	ErrTypeValidation      = "ValidationError"
	ErrTypePolicyViolation = "PolicyViolation"
	ErrTypeBudgetExceeded  = "BudgetExceeded"
)

const (
	DefaultSwitchAfter     = 2
	DefaultEscalateAfter   = 3
	DefaultActivityTimeout = 5 * time.Minute

	MaxIterationsLimit   = 100
	MaxTokensLimit       = 10_000_000
	MaxWallTimeLimit     = 24 * time.Hour
	MinActivityTimeout   = time.Second
	MaxActivityTimeout   = 30 * time.Minute
	MaxStrategies        = 10
	MaxFindingsToPropose = 20
	MaxActivityAttempts  = 3
	MaxEscalateAfter     = 10
)

const (
	MaxPayloadBytes   = 64 << 10
	MaxCandidateBytes = 64 << 10
	MaxFindings       = 100
	MaxFindingBytes   = 1 << 10
	MaxNameBytes      = 64
)

type Budget struct {
	MaxIterations int
	MaxTokens     int
	MaxWallTime   time.Duration
}

type LoopSpec struct {
	ID              string
	ProposeActivity string
	VerifyActivity  string
	Strategies      []string
	Budget          Budget
	SwitchAfter     int
	EscalateAfter   int
	ActivityTimeout time.Duration
}

// NonRetryableErrorTypes returns the activity error types never retried.
func NonRetryableErrorTypes() []string

// Validate checks s once defaults are applied. The error is a non-retryable
// application error of type ErrTypeInvalidLoopSpec that never quotes s.
func (s LoopSpec) Validate() error
```

## Règles de conception retenues (écarts au squelette initial)

- D10 à D12 de M0-T14 : l'empreinte et le score sont calculés dans le workflow à partir des findings (jamais fournis par le vérificateur : pas de champ `fingerprint` dans `VerifyResult`) ; les compteurs d'empreinte identique courent sur des itérations consécutives, toutes stratégies confondues ; une escalade est un résultat (`StatusEscalated` avec une `Reason` codée), jamais une erreur. V2 de M0-T14 : une itération dont l'activité échoue est tracée (`Failed`) et escalade en `activity_failed`.
- Proposeur (T19b) : reprise seulement si la cause directe de l'échec est une `ApplicationError` rejouable portant un `ProposeFailure` canonique (`{"tokens":N}`), dont les tokens sont comptés ; sans cette déclaration, pas de reprise. Un adaptateur LLM renvoie toujours un `ProposeFailure` après un appel facturé (la démo compte 1024 tokens par échec facturable).
- Bornes (T19b) : charge et candidat 64 Kio en UTF-8 valide, 100 findings de 1 Kio, noms de 64 octets ; tout dépassement est une `InvalidLoopSpec` ou une réponse invalide, avant ou pendant la boucle.
- Approbation : `AwaitApprovals` renvoie un `ApprovalResult` (issue, approbations retenues, signaux ignorés avec raison codée) ; signal admis seulement sous forme canonique ; `DeclaredApprover` est une identité déclarée, jamais authentifiée avant M4 ; une seule attente d'approbation par workflow (obligation (o)) ; `ctx.Err()` contrôlé entre l'approbation et tout effet (obligation (m)).
- Règles d'architecture (T19c, T19d, `internal/archtest/loopsrc.go`) : `RunLoop` et `AwaitApprovals` jamais enregistrés comme workflows ; `LoopSpec` et `ApprovalRequest` écrits en littéraux constants dans le code ; aucun décodage dans un paquet de workflow (cibles limitées à `converter.RawValue`, `Get` seulement sur un appel direct `ExecuteActivity`, `ExecuteLocalActivity` ou `ExecuteChildWorkflow`) ; méthode de décodage prise comme valeur et `Validator` hors appel refusés (aj) ; méthode ou fermeture prenant un `LoopSpec` refusée (ak) ; `internal/loops/fake` réservé aux tests ; `go.mod` imbriqué, `go.work` et liens symboliques refusés.
- Activités d'une boucle concrète dans un paquet distinct sans `sdk/workflow` (ex. `internal/loops/demo/activities`) : le décodage y est permis.

## Points d'attention
- Le code de workflow reste déterministe : pas de `time.Now()`, pas d'aléatoire, pas d'appel réseau ; tout passe par `workflow.Now`, les activités, `workflow.SideEffect`. Vérifié par `go tool workflowcheck ./internal/loops/...`.
- `ContinueAsNew` avant l'attente d'approbation et au-delà de quelques centaines d'itérations cumulées : reporté en M1 (amendement A1, tâches de l'ADR 0001), avec `workflow.GetVersion` pour les constantes de `spec.go`.
- Une approbation doit aussi être revérifiée côté runner (hash et signature) : le workflow n'est pas la seule barrière.
