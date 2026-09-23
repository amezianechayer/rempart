# Squelette Go/Temporal de RunLoop

Point de départ pour `internal/loops`. À adapter, pas à copier aveuglément. Les types de domaine concrets restent dans leurs modules ; la boucle manipule des `json.RawMessage`.

```go
package loops

import (
	"encoding/json"
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

type Budget struct {
	MaxIterations int
	MaxTokens     int
	MaxWallTime   time.Duration
}

type Finding struct {
	Code     string `json:"code"`
	Source   string `json:"source"`
	Severity string `json:"severity"`
	Resource string `json:"resource"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Message  string `json:"message"`
}

type VerifyResult struct {
	OK          bool      `json:"ok"`
	Findings    []Finding `json:"findings"`
	Fingerprint string    `json:"fingerprint"`
	Score       int       `json:"score"` // plus bas = meilleur (somme pondérée des gravités)
}

type LoopSpec struct {
	ID              string
	ProposeActivity string
	VerifyActivity  string
	Strategies      []string
	Budget          Budget
	SwitchAfter     int // empreinte identique N fois : stratégie suivante (défaut 2)
	EscalateAfter   int // empreinte identique N fois : escalade (défaut 3)
}

type ProposeRequest struct {
	Payload   json.RawMessage `json:"payload"`
	Strategy  string          `json:"strategy"`
	Best      json.RawMessage `json:"best,omitempty"`
	Findings  []Finding       `json:"findings,omitempty"`
	Iteration int             `json:"iteration"`
}

type ProposeResponse struct {
	Candidate json.RawMessage `json:"candidate"`
	Tokens    int             `json:"tokens"`
}

type IterationTrace struct {
	Iteration   int
	Strategy    string
	Fingerprint string
	Findings    int
	Tokens      int
}

type LoopResult struct {
	Status     string // "converged" | "escalated"
	Reason     string
	Best       json.RawMessage
	Remaining  []Finding
	Iterations int
	Tokens     int
	Trace      []IterationTrace
}

func RunLoop(ctx workflow.Context, spec LoopSpec, payload json.RawMessage) (LoopResult, error) {
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 5 * time.Minute,
		RetryPolicy: &temporal.RetryPolicy{
			MaximumAttempts: 3,
			// Une erreur de validation n'est pas transitoire : pas de retry automatique.
			NonRetryableErrorTypes: []string{"ValidationError", "PolicyViolation", "BudgetExceeded"},
		},
	})
	if spec.SwitchAfter == 0 {
		spec.SwitchAfter = 2
	}
	if spec.EscalateAfter == 0 {
		spec.EscalateAfter = 3
	}

	start := workflow.Now(ctx)
	res := LoopResult{}
	var best json.RawMessage
	bestScore := int(^uint(0) >> 1)
	var lastFindings []Finding
	lastFP, sameFP, strat := "", 0, 0

	escalate := func(reason string) (LoopResult, error) {
		res.Status, res.Reason, res.Best, res.Remaining = "escalated", reason, best, lastFindings
		return res, nil
	}

	for it := 1; it <= spec.Budget.MaxIterations; it++ {
		if workflow.Now(ctx).Sub(start) > spec.Budget.MaxWallTime {
			return escalate("budget temps dépassé")
		}
		req := ProposeRequest{Payload: payload, Strategy: spec.Strategies[strat], Best: best, Findings: top(lastFindings, 20), Iteration: it}
		var prop ProposeResponse
		if err := workflow.ExecuteActivity(ctx, spec.ProposeActivity, req).Get(ctx, &prop); err != nil {
			return res, err
		}
		res.Tokens += prop.Tokens
		if res.Tokens > spec.Budget.MaxTokens {
			return escalate("budget tokens dépassé")
		}

		var vr VerifyResult
		if err := workflow.ExecuteActivity(ctx, spec.VerifyActivity, prop.Candidate).Get(ctx, &vr); err != nil {
			return res, err
		}
		res.Iterations = it
		res.Trace = append(res.Trace, IterationTrace{it, spec.Strategies[strat], vr.Fingerprint, len(vr.Findings), prop.Tokens})

		if vr.Score < bestScore {
			best, bestScore = prop.Candidate, vr.Score
		}
		lastFindings = vr.Findings
		if vr.OK {
			res.Status, res.Best = "converged", prop.Candidate
			return res, nil
		}

		// Empreintes identiques comptées sur des itérations consécutives, toutes stratégies confondues
		// (le compteur n'est pas remis à zéro au changement de stratégie). Avec les défauts 2 et 3 :
		// la stratégie suivante n'a qu'un essai pour faire changer l'erreur, et une troisième stratégie
		// n'est atteinte que si l'empreinte a changé entre-temps. Conforme au critère 2 de prompts/M0.md.
		if vr.Fingerprint == lastFP {
			sameFP++
		} else {
			lastFP, sameFP = vr.Fingerprint, 1
		}
		switch {
		case sameFP >= spec.EscalateAfter:
			return escalate("stagnation : même empreinte d'erreur répétée")
		case sameFP >= spec.SwitchAfter:
			if strat+1 >= len(spec.Strategies) {
				return escalate("stagnation : stratégies épuisées")
			}
			strat++
		}
	}
	return escalate("budget itérations épuisé")
}

// ApprovalRequest : ce qu'il faut réunir avant d'appliquer un plan précis (règles du skill safe-autonomy).
type ApprovalRequest struct {
	PlanHash          string
	Author            string // l'auteur du changement ne peut pas l'approuver
	Required          int    // 1 ; 2 approbateurs distincts pour un risque critique
	NeedsSecurityRole bool   // risque critique : au moins un approbateur de rôle sécurité
}

// Approval : décision humaine sur un hash de plan précis, signée par la clé de l'approbateur
// (clé du client, ex. WebAuthn). Un signal Temporal n'est pas authentifié : seule la signature fait foi.
type Approval struct {
	Approved  bool   `json:"approved"`
	PlanHash  string `json:"plan_hash"`
	Approver  string `json:"approver"`
	Signature string `json:"signature"`
}

// ApprovalCheck : résultat de l'activité déterministe VerifyApproval (signature, identité, rôle).
type ApprovalCheck struct {
	SignatureValid bool `json:"signature_valid"`
	SecurityRole   bool `json:"security_role"`
}

// AwaitApprovals attend le quorum jusqu'au timeout. Un signal invalide (mauvais hash, auto-approbation,
// signature invalide, doublon) est ignoré : il n'interrompt pas l'attente, sinon n'importe qui pourrait
// bloquer une approbation. Un refus authentifié arrête l'attente. Timeout : ok=false, ne rien faire.
// ctx doit porter des ActivityOptions (VerifyApproval est une activité).
func AwaitApprovals(ctx workflow.Context, req ApprovalRequest, timeout time.Duration) ([]Approval, bool) {
	ch := workflow.GetSignalChannel(ctx, "approval")
	timer := workflow.NewTimer(ctx, timeout)
	var approvals []Approval  // slice et non map : l'ordre d'itération d'une map n'est pas déterministe
	seen := map[string]bool{} // lookups seulement, jamais d'itération
	hasSecurity := false
	for {
		var got Approval
		timedOut := false
		sel := workflow.NewSelector(ctx)
		sel.AddReceive(ch, func(c workflow.ReceiveChannel, _ bool) { c.Receive(ctx, &got) })
		sel.AddFuture(timer, func(workflow.Future) { timedOut = true })
		sel.Select(ctx)
		if timedOut {
			return nil, false
		}
		if got.PlanHash != req.PlanHash || got.Approver == req.Author || seen[got.Approver] {
			continue
		}
		var check ApprovalCheck
		if err := workflow.ExecuteActivity(ctx, "VerifyApproval", got).Get(ctx, &check); err != nil || !check.SignatureValid {
			continue // l'activité journalise le rejet
		}
		if !got.Approved {
			return nil, false
		}
		seen[got.Approver] = true
		approvals = append(approvals, got)
		hasSecurity = hasSecurity || check.SecurityRole
		if len(approvals) >= req.Required && (!req.NeedsSecurityRole || hasSecurity) {
			return approvals, true
		}
	}
}

func top(f []Finding, n int) []Finding {
	if len(f) <= n {
		return f
	}
	return f[:n] // les findings arrivent déjà triés par gravité depuis le vérificateur
}
```

## Points d'attention
- Le code de workflow doit rester déterministe : pas de `time.Now()`, pas d'aléatoire, pas d'appel réseau ; tout passe par `workflow.Now`, activités, `workflow.SideEffect`.
- Au-delà de quelques centaines d'itérations cumulées, utiliser `ContinueAsNew` pour borner l'historique.
- Une approbation doit aussi être revérifiée côté runner (hash et signature) : le workflow n'est pas la seule barrière.
