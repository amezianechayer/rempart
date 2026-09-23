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

// Approval : décision humaine liée à un hash de plan précis.
type Approval struct {
	Approved bool   `json:"approved"`
	PlanHash string `json:"plan_hash"`
	Approver string `json:"approver"`
}

// AwaitApproval renvoie false au timeout (échec sûr) ou si le hash ne correspond pas.
func AwaitApproval(ctx workflow.Context, planHash string, timeout time.Duration) (Approval, bool) {
	var got Approval
	ok := false
	sel := workflow.NewSelector(ctx)
	sel.AddReceive(workflow.GetSignalChannel(ctx, "approval"), func(c workflow.ReceiveChannel, _ bool) {
		c.Receive(ctx, &got)
		ok = got.Approved && got.PlanHash == planHash
	})
	sel.AddFuture(workflow.NewTimer(ctx, timeout), func(workflow.Future) { ok = false })
	sel.Select(ctx)
	return got, ok
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
