# M0-T14 `runloop` : workflow générique `RunLoop`

2026-09-24, `architect`, proposé. Fiche `docs/plans/M0-overview.md` (M0-T14). Aucun ADR (Temporal est déjà la pile de la vision). Revue sécurité : oui (T10, T45, échec sûr).

## 0. Amendements

- V1 (2026-09-25, `test-author`, étape A2) : mutation M13 réécrite pour compiler, même sens (findings de la dernière itération au lieu de ceux du meilleur) : `NEW` = `res.Status, res.Reason, res.Best, res.Remaining = StatusEscalated, r, best, domain.Sort(append(remaining[:0:0], last...))`, détectée par T9. Code de référence et tests inchangés ; 15 mutations sur 15 détectées ; points non vérifiés 1 à 4 levés (workflowcheck sans faux positif, frontière d'horloge exacte, testify indirect compilable) ; `go mod tidy` exige le réseau (proxy de modules), testify et le SDK Temporal passent en dépendances directes.
- V2 (2026-09-25, `architect`, revue `security-reviewer` : PASS conditionné par les constats moyens 1 à 3 ; constats bas 4 à 6 inclus) : le proposeur n'est plus repris par Temporal (`MaximumAttempts: 1`) ; chaque appel, réussi ou non, est une itération comptée (tokens d'échec lus dans le détail `ProposeFailure`, trace `Failed`) ; un échec rejouable est repris par la boucle, au plus `MaxActivityAttempts` fois d'affilée ; candidat sans contenu et échec sans finding mènent à `invalid_response` ; bornes de `spec.go` figées (T18) ; `EscalateAfter <= 10` ; escalade sur échec du vérificateur figée (T14). T3, T12, T13, T14 modifiés, T15 à T18 ajoutés (18 tests), mutations M16 à M21 ; D2 à D5, D8, D10 à D12 amendés. Détail en section 11, qui prime sur les sections 3 à 7 et 9.
- V3 (2026-09-25, `test-author`, étape V2-A2) : 11.2 inchangé. Tests renforcés au-delà de 11.3 (mutations exploratoires qui survivaient) : T15 gagne `consecutive failures only, request and stagnation kept` (A, échec, A, échec, échec, succès : convergence en 6, stratégies s1 s1 s1 s2 s2 s2, 33 tokens, meilleur et findings renvoyés) et `failed calls spend the token budget` (budget 15, 10 puis échec à 6 : `budget_tokens`, 16 tokens) ; T16 gagne le candidat absent (proposeur réenregistré sans clé `candidate`) ; messages d'échec de T13, T14, T16 alignés sur les conditions contrôlées. Mutations ajoutées au critère 12 : M22 ligne `failures = 0` supprimée (T15) ; M23 `""` retiré de `emptyCandidate` (T16) ; M24 `if perr == nil && res.Tokens > spec.Budget.MaxTokens {` (T15) ; M25, M26, M27 `same = 0`, `last = nil`, `strat = 0` insérés après `failures++` (T15). 27 mutations sur 27 détectées sur copie.

## 1. Objet et périmètre
`RunLoop` : proposer, vérifier, diagnostiquer ; budgets itérations, tokens, temps ; stagnation ; escalade ; meilleur candidat ; sans domaine. Critère 2 de `prompts/M0.md`, première partie. Dans : `internal/loops/{doc.go,spec.go,runloop.go,runloop_test.go}`, `go.mod`, `go.sum`, `Makefile` (étape 0), `docs/STATUS.md`. Hors : approbations (T15), workflow de démonstration et câblage worker (T19, T20), annulation du workflow (traitée comme un échec d'activité), `ContinueAsNew` et chiffrement des payloads (M1, ADR 0001), spans OpenTelemetry et métriques (M1).

## 2. Étape 0 (phase free, principal, avant `phase tests`)
Le `Makefile` n'est protégé ni par `guard_edit.py` (`PROTECTED` : `CLAUDE.md`, `.claude/...`) ni par la discipline TDD (hors `SOURCE_FILE`) : modifiable par l'agent. `go.mod` aussi. Le module `go.temporal.io/sdk` n'a pas de paquet racine : on nomme les paquets pour que `go.sum` couvre leur compilation.
```bash
go get go.temporal.io/sdk/workflow@v1.49.0 go.temporal.io/sdk/temporal@v1.49.0 \
  go.temporal.io/sdk/activity@v1.49.0 go.temporal.io/sdk/testsuite@v1.49.0
go get -tool go.temporal.io/sdk/contrib/tools/workflowcheck@v0.5.0
```
`Makefile`, cible `arch-test` (seule modification) :
```make
arch-test:
	go test -count=1 ./internal/archtest/...
	go tool workflowcheck ./internal/loops/...
```
Compatible avec `TestMakefileTargets` (recette contenant `./internal/archtest/...`, ni `go get`, ni réseau). Contrôles : `go list -m go.temporal.io/sdk go.temporal.io/sdk/contrib/tools/workflowcheck` rend `v1.49.0` et `v0.5.0` ; `go list -m github.com/stretchr/testify` rend une version (dépendance de `sdk/internal`, requise par le test du temps) ; `go tool workflowcheck ./internal/loops/...; echo rc=$?` : `rc=0` ; `make verify-quick` : `rc=0` ; `git status --porcelain` : `go.mod`, `go.sum`, `Makefile`. Montées de version imposées par MVS (attendu : `golang.org/x/text` vers v0.41.0, grpc, protobuf) consignées dans `docs/STATUS.md`. Commit `build(deps): add Temporal Go SDK v1.49.0 and workflowcheck v0.5.0 (M0-T14)`. Licences : SDK et workflowcheck MIT (lues dans le cache).

## 3. Décisions
| # | Décision |
|---|---|
| D1 | **Défauts** (`withDefaults`, non exportée) appliqués dans `Validate` **et** dans `RunLoop` : 0 vaut `SwitchAfter` 2, `EscalateAfter` 3, `ActivityTimeout` 5 min. Budgets sans défaut : 0 refusé. |
| D2 | **Bornes** (T10) : itérations 1 à 100 ; tokens 1 à 10 000 000 ; temps 0 exclu à 24 h ; stratégies 1 à 10, non vides ; `ActivityTimeout` 1 s à 30 min ; `1 <= SwitchAfter < EscalateAfter` ; `ID`, activités non vides ; **vérificateur distinct du proposeur** (règle 1). Refus : `ApplicationError` non rejouable `InvalidLoopSpec`, message fixe sans valeur de la spécification ; le workflow échoue avant toute activité. |
| D3 | **Ordre par itération `it`** : (1) temps, (2) proposeur, (3) tokens de la réponse dans `[0, MaxTokensLimit]` sinon `invalid_response`, (4) cumul (itération qui dépasse **incluse**) puis `> MaxTokens` : `budget_tokens`, candidat non vérifié, (5) temps, (6) vérificateur, (7) empreinte et score recalculés, (8) OK, (9) meilleur, (10) stagnation. Après la dernière itération : `budget_iterations`. |
| D4 | **Temps** : `workflow.Now(ctx) - start >= MaxWallTime`, contrôlé **avant chaque activité** ; aucune activité ne démarre budget épuisé. Dépassement maximal : une activité, soit `3 x ActivityTimeout + 3 s` (reprises). Pas de `ScheduleToCloseTimeout` : un timeout d'activité se confondrait avec `activity_failed`. Le timeout d'exécution du workflow (posé par l'appelant, T20) n'est qu'un filet, sans résultat d'escalade. |
| D5 | **Itérations et trace** : `Iterations` = propositions reçues ; une entrée de trace par proposition (`len(Trace) == Iterations`), `Verified` faux si non vérifiée. `Tokens` = somme des tokens déclarés et bornés. |
| D6 | **Recalcul** : `Fingerprint` et `Score` de `domain` sur `VerifyResult.Findings` ; le vérificateur ne fournit ni empreinte ni score. |
| D7 | **Convergence** : `OK` sans finding de poids `>= 5` (gravité inconnue comprise) : `converged`, `Best` = ce candidat, `Remaining` = ses findings triés (low, info). `OK` avec un finding bloquant : vérificateur incohérent, `escalated` `invalid_response` (échec sûr). |
| D8 | **Meilleur** : plus petit `Score` parmi les candidats vérifiés non OK ; ex aequo, le premier. `Remaining` = findings triés **du meilleur** (cohérents avec `Best`, pas ceux de la dernière itération). Une montée de gravité à empreinte égale ne remplace donc pas le meilleur. |
| D9 | **Proposeur** : `Findings` = `domain.Top(derniers findings vérifiés, 20)`, `Best` = meilleur courant (absent à l'itération 1), `Payload`, `Strategy`, `Iteration`. |
| D10 | **Stagnation** (règle 5 du skill) : empreintes égales consécutives, **toutes stratégies confondues** ; changement d'empreinte : compteur à 1 ; changement de stratégie : pas de remise à zéro. `same >= EscalateAfter` : `stagnation` ; sinon `same >= SwitchAfter` : stratégie suivante, ou `strategies_exhausted` s'il n'y en a plus. Empreinte vide répétée (aucun finding medium ou plus, échec sans finding) : stagnation. Stagnation sur l'empreinte seule, le score ne sert qu'au meilleur. |
| D11 | **Activités** : `StartToCloseTimeout` = `ActivityTimeout` ; `RetryPolicy` : 1 s, coefficient 2, max 1 min, **3 tentatives**, `NonRetryableErrorTypes` = `ValidationError`, `PolicyViolation`, `BudgetExceeded`. Échec après reprises ou non rejouable : `LoopResult` `escalated` `activity_failed`, **erreur nil** (escalade documentée avec meilleur candidat et trace) ; seule une spécification invalide rend une erreur. |
| D12 | **Écarts d'interface** (fiche) : `ReasonInvalidResponse` ajoutée ; `IterationTrace` gagne `Verified` et `Score` ; étiquettes JSON en minuscules partout ; constantes exportées (défauts, bornes, types d'erreur), `NonRetryableErrorTypes()`. |

## 4. Code de référence (normatif ; ancres de la section 7 au caractère près)
`doc.go` (remplace l'actuel) :
```go
// Package loops holds the generic loop workflow RunLoop and, later, one
// workflow per product loop. RunLoop knows no domain: payload and candidates
// are opaque JSON, findings are normalized by package domain.
package loops
```
`spec.go` :
```go
package loops

import (
	"slices"
	"time"

	"go.temporal.io/sdk/temporal"
)

// Error types. Activities report a non-transient failure with one of the last
// three: RunLoop never retries them.
const (
	ErrTypeInvalidLoopSpec = "InvalidLoopSpec"
	ErrTypeValidation      = "ValidationError"
	ErrTypePolicyViolation = "PolicyViolation"
	ErrTypeBudgetExceeded  = "BudgetExceeded"
)

// Defaults and bounds of a LoopSpec (threat T10).
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
)

// Budget bounds one run; every field is required.
type Budget struct {
	MaxIterations int
	MaxTokens     int
	MaxWallTime   time.Duration
}

// LoopSpec describes one loop. Zero SwitchAfter, EscalateAfter and
// ActivityTimeout take their defaults; a zero budget is refused.
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
func NonRetryableErrorTypes() []string {
	return []string{ErrTypeValidation, ErrTypePolicyViolation, ErrTypeBudgetExceeded}
}

// Validate checks s once defaults are applied. The error is a non-retryable
// application error of type ErrTypeInvalidLoopSpec that never quotes s.
func (s LoopSpec) Validate() error {
	s = s.withDefaults()
	b := s.Budget
	switch {
	case s.ID == "" || s.ProposeActivity == "" || s.VerifyActivity == "":
		return invalidSpec("missing name")
	case s.ProposeActivity == s.VerifyActivity:
		return invalidSpec("the verifier must not be the proposer")
	case len(s.Strategies) == 0 || len(s.Strategies) > MaxStrategies || slices.Contains(s.Strategies, ""):
		return invalidSpec("strategies")
	case b.MaxIterations < 1 || b.MaxIterations > MaxIterationsLimit:
		return invalidSpec("iteration budget")
	case b.MaxTokens < 1 || b.MaxTokens > MaxTokensLimit:
		return invalidSpec("token budget")
	case b.MaxWallTime <= 0 || b.MaxWallTime > MaxWallTimeLimit:
		return invalidSpec("wall time budget")
	case s.SwitchAfter < 1 || s.SwitchAfter >= s.EscalateAfter:
		return invalidSpec("stagnation thresholds")
	case s.ActivityTimeout < MinActivityTimeout || s.ActivityTimeout > MaxActivityTimeout:
		return invalidSpec("activity timeout")
	}
	return nil
}

func (s LoopSpec) withDefaults() LoopSpec {
	if s.SwitchAfter == 0 {
		s.SwitchAfter = DefaultSwitchAfter
	}
	if s.EscalateAfter == 0 {
		s.EscalateAfter = DefaultEscalateAfter
	}
	if s.ActivityTimeout == 0 {
		s.ActivityTimeout = DefaultActivityTimeout
	}
	return s
}

func invalidSpec(what string) error {
	return temporal.NewNonRetryableApplicationError("invalid loop spec: "+what, ErrTypeInvalidLoopSpec, nil)
}
```
`runloop.go` :
```go
package loops

import (
	"encoding/json"
	"slices"
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	"github.com/amezianechayer/rempart/internal/loops/domain"
)

// ProposeRequest is the input of the proposer activity.
type ProposeRequest struct {
	Payload   json.RawMessage  `json:"payload"`
	Strategy  string           `json:"strategy"`
	Best      json.RawMessage  `json:"best,omitempty"`
	Findings  []domain.Finding `json:"findings,omitempty"`
	Iteration int              `json:"iteration"`
}

// ProposeResponse is untrusted: RunLoop bounds Tokens (threats T10, T45).
type ProposeResponse struct {
	Candidate json.RawMessage `json:"candidate"`
	Tokens    int             `json:"tokens"`
}

// VerifyRequest is the input of the verifier activity.
type VerifyRequest struct {
	Payload   json.RawMessage `json:"payload"`
	Candidate json.RawMessage `json:"candidate"`
	Iteration int             `json:"iteration"`
}

// VerifyResult carries no fingerprint nor score: RunLoop computes them.
type VerifyResult struct {
	OK       bool             `json:"ok"`
	Findings []domain.Finding `json:"findings"`
}

// Status is the outcome of a run.
type Status string

const (
	StatusConverged Status = "converged"
	StatusEscalated Status = "escalated"
)

// Reason codes an escalation.
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

// IterationTrace records one proposal; Verified is false when the run
// stopped before its verification.
type IterationTrace struct {
	Iteration   int    `json:"iteration"`
	Strategy    string `json:"strategy"`
	Verified    bool   `json:"verified"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Score       int    `json:"score"`
	Findings    int    `json:"findings"`
	Tokens      int    `json:"tokens"`
}

// LoopResult is the outcome of a run. Remaining holds the sorted findings of
// Best.
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
// budget, a stagnation or a failed activity escalates. An escalation is a
// result, not an error: only an invalid spec fails the workflow.
func RunLoop(ctx workflow.Context, spec LoopSpec, payload json.RawMessage) (LoopResult, error) {
	if err := spec.Validate(); err != nil {
		return LoopResult{}, err
	}
	spec = spec.withDefaults()
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: spec.ActivityTimeout,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:        time.Second,
			BackoffCoefficient:     2,
			MaximumInterval:        time.Minute,
			MaximumAttempts:        MaxActivityAttempts,
			NonRetryableErrorTypes: NonRetryableErrorTypes(),
		},
	})
	start := workflow.Now(ctx)
	timeUp := func() bool { return workflow.Now(ctx).Sub(start) >= spec.Budget.MaxWallTime }

	var (
		res             LoopResult
		best            json.RawMessage
		remaining, last []domain.Finding
		bestScore       int
		haveBest        bool
		lastFP          string
		same, strat     int
	)
	escalate := func(r Reason) (LoopResult, error) {
		res.Status, res.Reason, res.Best, res.Remaining = StatusEscalated, r, best, remaining
		return res, nil
	}

	for it := 1; it <= spec.Budget.MaxIterations; it++ {
		if timeUp() { // T10: no proposal past the wall time budget
			return escalate(ReasonBudgetTime)
		}
		req := ProposeRequest{
			Payload: payload, Strategy: spec.Strategies[strat], Best: best,
			Findings: domain.Top(last, MaxFindingsToPropose), Iteration: it,
		}
		var prop ProposeResponse
		if err := workflow.ExecuteActivity(ctx, spec.ProposeActivity, req).Get(ctx, &prop); err != nil {
			return escalate(ReasonActivityFailed)
		}
		if prop.Tokens < 0 || prop.Tokens > MaxTokensLimit {
			return escalate(ReasonInvalidResponse)
		}
		res.Iterations, res.Tokens = it, res.Tokens+prop.Tokens
		res.Trace = append(res.Trace, IterationTrace{Iteration: it, Strategy: req.Strategy, Tokens: prop.Tokens})
		if res.Tokens > spec.Budget.MaxTokens {
			return escalate(ReasonBudgetTokens)
		}
		if timeUp() { // T10: no verification past the wall time budget
			return escalate(ReasonBudgetTime)
		}
		var vr VerifyResult
		vreq := VerifyRequest{Payload: payload, Candidate: prop.Candidate, Iteration: it}
		if err := workflow.ExecuteActivity(ctx, spec.VerifyActivity, vreq).Get(ctx, &vr); err != nil {
			return escalate(ReasonActivityFailed)
		}
		fp, score := domain.Fingerprint(vr.Findings), domain.Score(vr.Findings)
		tr := &res.Trace[len(res.Trace)-1]
		tr.Verified, tr.Fingerprint, tr.Score, tr.Findings = true, fp, score, len(vr.Findings)
		if vr.OK {
			if blocking(vr.Findings) {
				return escalate(ReasonInvalidResponse)
			}
			res.Status, res.Best, res.Remaining = StatusConverged, prop.Candidate, domain.Sort(vr.Findings)
			return res, nil
		}
		if !haveBest || score < bestScore {
			best, bestScore, remaining, haveBest = prop.Candidate, score, domain.Sort(vr.Findings), true
		}
		last = vr.Findings
		if fp == lastFP {
			same++
		} else {
			lastFP, same = fp, 1
		}
		switch {
		case same >= spec.EscalateAfter:
			return escalate(ReasonStagnation)
		case same >= spec.SwitchAfter:
			if strat+1 >= len(spec.Strategies) {
				return escalate(ReasonStrategiesExhausted)
			}
			strat++
		}
	}
	return escalate(ReasonBudgetIterations)
}

// blocking reports a finding at the fingerprint threshold (medium or more,
// unknown severities included): such a result cannot converge.
func blocking(f []domain.Finding) bool {
	return slices.ContainsFunc(f, func(x domain.Finding) bool {
		return x.Severity.Weight() >= domain.SeverityMedium.Weight()
	})
}
```

## 5. Tests (`test-author`, `runloop_test.go`, `package loops`, T1 à T14 dans l'ordre)
Activités factices enregistrées par `RegisterActivityWithOptions` sous les noms de la spécification ; le temps (T8) passe par `OnActivity(...).After(d)` du testsuite (horloge du workflow ; le contrôle `StartToClose` du testsuite est en temps réel, non déclenché).
```go
package loops

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"

	"github.com/amezianechayer/rempart/internal/loops/domain"
)

const (
	proposeName = "Propose"
	verifyName  = "Verify"
)

func payload() json.RawMessage { return json.RawMessage(`{"goal":"demo"}`) }

func candidate(it int) json.RawMessage { return json.RawMessage(`{"n":` + strconv.Itoa(it) + `}`) }

func fnd(sev domain.Severity, code string) domain.Finding {
	return domain.Finding{Code: code, Source: "fake", Severity: sev, Resource: "aws_s3_bucket.logs", File: "main.tf", Line: 1, Message: "m"}
}

func high(code string) domain.Finding { return fnd(domain.SeverityHigh, code) }

type step struct {
	tokens                int
	ok                    bool
	findings              []domain.Finding
	proposeErr, verifyErr error
}

func fail(f ...domain.Finding) step { return step{tokens: 10, findings: f} }

func pass(f ...domain.Finding) step { return step{tokens: 10, ok: true, findings: f} }

// script answers by iteration; every attempt is recorded.
type script struct {
	mu        sync.Mutex
	steps     []step
	proposals []ProposeRequest
	verifies  []VerifyRequest
}

func newScript(steps ...step) *script { return &script{steps: steps} }

func (s *script) at(it int) (step, error) {
	if it < 1 || it > len(s.steps) {
		return step{}, temporal.NewNonRetryableApplicationError("script exhausted", "ScriptExhausted", nil)
	}
	return s.steps[it-1], nil
}

func (s *script) propose(_ context.Context, req ProposeRequest) (ProposeResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.proposals = append(s.proposals, req)
	st, err := s.at(req.Iteration)
	if err != nil {
		return ProposeResponse{}, err
	}
	if st.proposeErr != nil {
		return ProposeResponse{}, st.proposeErr
	}
	return ProposeResponse{Candidate: candidate(req.Iteration), Tokens: st.tokens}, nil
}

func (s *script) verify(_ context.Context, req VerifyRequest) (VerifyResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifies = append(s.verifies, req)
	st, err := s.at(req.Iteration)
	if err != nil {
		return VerifyResult{}, err
	}
	if st.verifyErr != nil {
		return VerifyResult{}, st.verifyErr
	}
	return VerifyResult{OK: st.ok, Findings: st.findings}, nil
}

func (s *script) calls() (proposals, verifies int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.proposals), len(s.verifies)
}

func (s *script) sent() []ProposeRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.proposals)
}

func (s *script) verified() []VerifyRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.verifies)
}

func testSpec(strategies ...string) LoopSpec {
	if len(strategies) == 0 {
		strategies = []string{"s1", "s2", "s3"}
	}
	return LoopSpec{
		ID: "test-loop", ProposeActivity: proposeName, VerifyActivity: verifyName, Strategies: strategies,
		Budget: Budget{MaxIterations: 8, MaxTokens: 1_000_000, MaxWallTime: time.Hour},
	}
}

func execute(t *testing.T, spec LoopSpec, s *script, setup func(*testsuite.TestWorkflowEnvironment)) (LoopResult, error) {
	t.Helper()
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	env.RegisterActivityWithOptions(s.propose, activity.RegisterOptions{Name: proposeName})
	env.RegisterActivityWithOptions(s.verify, activity.RegisterOptions{Name: verifyName})
	if setup != nil {
		setup(env)
	}
	env.ExecuteWorkflow(RunLoop, spec, payload())
	if !env.IsWorkflowCompleted() {
		t.Fatal("workflow not completed")
	}
	if err := env.GetWorkflowError(); err != nil {
		return LoopResult{}, err
	}
	var res LoopResult
	if err := env.GetWorkflowResult(&res); err != nil {
		t.Fatalf("GetWorkflowResult: %v", err)
	}
	return res, nil
}

func run(t *testing.T, spec LoopSpec, s *script, setup func(*testsuite.TestWorkflowEnvironment)) LoopResult {
	t.Helper()
	res, err := execute(t, spec, s, setup)
	if err != nil {
		t.Fatalf("RunLoop failed: %v", err)
	}
	return res
}

func want(t *testing.T, res LoopResult, st Status, r Reason, iterations int) {
	t.Helper()
	if res.Status != st || res.Reason != r || res.Iterations != iterations || len(res.Trace) != iterations {
		t.Fatalf("got %q %q after %d iterations (%d traced), want %q %q after %d",
			res.Status, res.Reason, res.Iterations, len(res.Trace), st, r, iterations)
	}
}

func strategiesOf(reqs []ProposeRequest) []string {
	out := make([]string, len(reqs))
	for i, r := range reqs {
		out[i] = r.Strategy
	}
	return out
}

func TestRunLoopConverges(t *testing.T) {
	low := fnd(domain.SeverityLow, "L")
	s := newScript(fail(high("A")), pass(low))
	res := run(t, testSpec(), s, nil)
	want(t, res, StatusConverged, "", 2)
	if string(res.Best) != `{"n":2}` || res.Tokens != 20 || !slices.Equal(res.Remaining, []domain.Finding{low}) {
		t.Fatalf("best %s, tokens %d, remaining %v", res.Best, res.Tokens, res.Remaining)
	}
	if tr := res.Trace[1]; !tr.Verified || tr.Fingerprint != domain.Fingerprint(nil) || tr.Score != 1 || tr.Findings != 1 || tr.Strategy != "s1" {
		t.Errorf("trace %+v", tr)
	}
	v := s.verified()
	if len(v) != 2 || string(v[1].Candidate) != `{"n":2}` || string(v[1].Payload) != string(payload()) || v[1].Iteration != 2 {
		t.Errorf("verify requests %+v", v)
	}
	t.Run("ok with a blocking finding is incoherent", func(t *testing.T) {
		res := run(t, testSpec(), newScript(pass(fnd(domain.SeverityMedium, "M"))), nil)
		want(t, res, StatusEscalated, ReasonInvalidResponse, 1)
		if res.Best != nil {
			t.Errorf("best %s, want none", res.Best)
		}
	})
}

func TestRunLoopStagnationSwitchesStrategy(t *testing.T) {
	s := newScript(fail(high("A")), fail(high("A")), pass())
	res := run(t, testSpec(), s, nil)
	want(t, res, StatusConverged, "", 3)
	if got := strategiesOf(s.sent()); !slices.Equal(got, []string{"s1", "s1", "s2"}) || res.Trace[2].Strategy != "s2" {
		t.Errorf("strategies %v", got)
	}
}

func TestRunLoopStagnationEscalates(t *testing.T) {
	cases := []struct {
		name  string
		steps []step
	}{
		{"same findings", []step{fail(high("A")), fail(high("A")), fail(high("A")), pass()}},
		{"no blocking finding", []step{fail(), fail(fnd(domain.SeverityLow, "L")), fail(fnd(domain.SeverityInfo, "I")), pass()}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newScript(c.steps...)
			res := run(t, testSpec(), s, nil)
			want(t, res, StatusEscalated, ReasonStagnation, 3)
			if got := strategiesOf(s.sent()); !slices.Equal(got, []string{"s1", "s1", "s2"}) {
				t.Errorf("strategies %v", got)
			}
			if string(res.Best) != `{"n":1}` {
				t.Errorf("best %s, want the first of equal scores", res.Best)
			}
		})
	}
}

func TestRunLoopStrategiesExhausted(t *testing.T) {
	one := newScript(fail(high("A")), fail(high("A")), pass())
	want(t, run(t, testSpec("s1"), one, nil), StatusEscalated, ReasonStrategiesExhausted, 2)
	two := newScript(fail(high("A")), fail(high("A")), fail(high("B")), fail(high("B")), pass())
	want(t, run(t, testSpec("s1", "s2"), two, nil), StatusEscalated, ReasonStrategiesExhausted, 4)
	if got := strategiesOf(two.sent()); !slices.Equal(got, []string{"s1", "s1", "s2", "s2"}) {
		t.Errorf("strategies %v", got)
	}
}

func TestRunLoopFingerprintChangeResetsCount(t *testing.T) {
	s := newScript(fail(high("A")), fail(high("A")), fail(high("B")), fail(high("B")), pass())
	want(t, run(t, testSpec(), s, nil), StatusConverged, "", 5)
	if got := strategiesOf(s.sent()); !slices.Equal(got, []string{"s1", "s1", "s2", "s2", "s3"}) {
		t.Errorf("strategies %v", got)
	}
}

func TestRunLoopBudgetIterations(t *testing.T) {
	spec := testSpec()
	spec.Budget.MaxIterations = 3
	s := newScript(fail(high("A")), fail(high("B")), fail(high("C")), pass())
	res := run(t, spec, s, nil)
	want(t, res, StatusEscalated, ReasonBudgetIterations, 3)
	if p, v := s.calls(); p != 3 || v != 3 || res.Tokens != 30 || string(res.Best) != `{"n":1}` {
		t.Errorf("calls %d %d, tokens %d, best %s", p, v, res.Tokens, res.Best)
	}
}

func TestRunLoopBudgetTokens(t *testing.T) {
	distinct := func() *script {
		var steps []step
		for i := range 6 {
			steps = append(steps, step{tokens: 100, findings: []domain.Finding{high("C" + strconv.Itoa(i))}})
		}
		return newScript(steps...)
	}
	for _, c := range []struct{ max, iterations, tokens, verifies int }{{250, 3, 300, 2}, {300, 4, 400, 3}} {
		spec := testSpec()
		spec.Budget.MaxTokens = c.max
		s := distinct()
		res := run(t, spec, s, nil)
		want(t, res, StatusEscalated, ReasonBudgetTokens, c.iterations)
		if _, v := s.calls(); v != c.verifies || res.Tokens != c.tokens || res.Trace[c.iterations-1].Verified {
			t.Errorf("max %d: verifies %d, tokens %d", c.max, v, res.Tokens)
		}
	}
	for _, n := range []int{-1, MaxTokensLimit + 1} {
		s := newScript(step{tokens: n})
		res := run(t, testSpec(), s, nil)
		want(t, res, StatusEscalated, ReasonInvalidResponse, 0)
		if _, v := s.calls(); v != 0 || res.Tokens != 0 {
			t.Errorf("tokens %d accepted", n)
		}
	}
}

func TestRunLoopBudgetWallTime(t *testing.T) {
	distinct := func() *script { return newScript(fail(high("A")), fail(high("B")), fail(high("C"))) }
	t.Run("no verification past the budget", func(t *testing.T) {
		s := distinct()
		res := run(t, testSpec(), s, func(env *testsuite.TestWorkflowEnvironment) {
			env.OnActivity(proposeName, mock.Anything, mock.Anything).Return(s.propose).After(30 * time.Minute)
		})
		want(t, res, StatusEscalated, ReasonBudgetTime, 2)
		if p, v := s.calls(); p != 2 || v != 1 || res.Trace[1].Verified || string(res.Best) != `{"n":1}` {
			t.Errorf("calls %d %d, best %s", p, v, res.Best)
		}
	})
	t.Run("no proposal past the budget", func(t *testing.T) {
		s := distinct()
		res := run(t, testSpec(), s, func(env *testsuite.TestWorkflowEnvironment) {
			env.OnActivity(verifyName, mock.Anything, mock.Anything).Return(s.verify).After(time.Hour)
		})
		want(t, res, StatusEscalated, ReasonBudgetTime, 1)
		if p, v := s.calls(); p != 1 || v != 1 {
			t.Errorf("calls %d %d", p, v)
		}
	})
}

func TestRunLoopKeepsBestCandidate(t *testing.T) {
	spec := testSpec()
	spec.Budget.MaxIterations = 4
	b := high("B")
	crit := func(c string) domain.Finding { return fnd(domain.SeverityCritical, c) }
	s := newScript(fail(crit("A")), fail(b), fail(high("C")), fail(crit("D"), crit("E")))
	res := run(t, spec, s, nil)
	want(t, res, StatusEscalated, ReasonBudgetIterations, 4)
	if string(res.Best) != `{"n":2}` || !slices.Equal(res.Remaining, []domain.Finding{b}) {
		t.Fatalf("best %s, remaining %v", res.Best, res.Remaining)
	}
	sent := s.sent()
	for i, w := range []string{"", `{"n":1}`, `{"n":2}`, `{"n":2}`} {
		if i >= len(sent) || string(sent[i].Best) != w {
			t.Fatalf("proposal %d: best sent %v, want %q", i+1, sent, w)
		}
	}
}

func TestRunLoopSendsTop20Findings(t *testing.T) {
	sevs := []domain.Severity{domain.SeverityInfo, domain.SeverityLow, domain.SeverityMedium, domain.SeverityHigh, domain.SeverityCritical}
	var many []domain.Finding
	for i := range 25 {
		f := fnd(sevs[i%5], "C"+strconv.Itoa(i))
		f.Line = 25 - i
		many = append(many, f)
	}
	s := newScript(fail(many...), pass())
	want(t, run(t, testSpec(), s, nil), StatusConverged, "", 2)
	sent := s.sent()
	if len(sent) != 2 || len(sent[0].Findings) != 0 {
		t.Fatalf("proposals %d, first with %d findings", len(sent), len(sent[0].Findings))
	}
	got := sent[1]
	if len(got.Findings) != 20 || !slices.Equal(got.Findings, domain.Top(many, 20)) {
		t.Errorf("findings sent %v", got.Findings)
	}
	if string(got.Payload) != string(payload()) || got.Iteration != 2 || got.Strategy != "s1" || string(got.Best) != `{"n":1}` {
		t.Errorf("request %+v", got)
	}
}

func TestRunLoopRecomputesFingerprint(t *testing.T) {
	a, b := high("A"), fnd(domain.SeverityMedium, "B")
	a2, b2 := a, b
	a2.Message, a2.Line, a2.Source = "other wording", 9, "trivy"
	b2.File = "other.tf"
	rounds := [][]domain.Finding{{a, b}, {b2, a2, fnd(domain.SeverityLow, "N")}, {a, b, a, fnd(domain.SeverityInfo, "I")}}
	s := newScript(fail(rounds[0]...), fail(rounds[1]...), fail(rounds[2]...), pass())
	res := run(t, testSpec(), s, nil)
	want(t, res, StatusEscalated, ReasonStagnation, 3)
	for i, tr := range res.Trace {
		r := rounds[i]
		if !tr.Verified || tr.Fingerprint != domain.Fingerprint(r) || tr.Score != domain.Score(r) || tr.Findings != len(r) {
			t.Errorf("trace %d: %+v", i+1, tr)
		}
	}
	if res.Trace[0].Fingerprint == domain.Fingerprint(nil) {
		t.Error("blocking findings ignored")
	}
}

func TestRunLoopInvalidSpecRejected(t *testing.T) {
	valid := testSpec()
	valid.ID = "canary-loop"
	with := func(f func(*LoopSpec)) LoopSpec {
		s := valid
		s.Strategies = slices.Clone(valid.Strategies)
		f(&s)
		return s
	}
	invalid := []LoopSpec{
		with(func(s *LoopSpec) { s.Budget.MaxIterations = 0 }),
		with(func(s *LoopSpec) { s.Budget.MaxIterations = MaxIterationsLimit + 1 }),
		with(func(s *LoopSpec) { s.Budget.MaxTokens = 0 }),
		with(func(s *LoopSpec) { s.Budget.MaxTokens = MaxTokensLimit + 1 }),
		with(func(s *LoopSpec) { s.Budget.MaxWallTime = 0 }),
		with(func(s *LoopSpec) { s.Budget.MaxWallTime = -time.Second }),
		with(func(s *LoopSpec) { s.Budget.MaxWallTime = MaxWallTimeLimit + time.Second }),
		with(func(s *LoopSpec) { s.Strategies = nil }),
		with(func(s *LoopSpec) { s.Strategies = []string{"s1", ""} }),
		with(func(s *LoopSpec) { s.Strategies = slices.Repeat([]string{"s"}, MaxStrategies+1) }),
		with(func(s *LoopSpec) { s.ID = "" }),
		with(func(s *LoopSpec) { s.ProposeActivity = "" }),
		with(func(s *LoopSpec) { s.VerifyActivity = "" }),
		with(func(s *LoopSpec) { s.VerifyActivity = proposeName }),
		with(func(s *LoopSpec) { s.SwitchAfter = 3 }),
		with(func(s *LoopSpec) { s.EscalateAfter = 2 }),
		with(func(s *LoopSpec) { s.SwitchAfter = -1 }),
		with(func(s *LoopSpec) { s.EscalateAfter = -1 }),
		with(func(s *LoopSpec) { s.ActivityTimeout = -time.Second }),
		with(func(s *LoopSpec) { s.ActivityTimeout = MinActivityTimeout - time.Millisecond }),
		with(func(s *LoopSpec) { s.ActivityTimeout = MaxActivityTimeout + time.Second }),
	}
	isInvalidSpec := func(err error) bool {
		var ae *temporal.ApplicationError
		return errors.As(err, &ae) && ae.Type() == ErrTypeInvalidLoopSpec && ae.NonRetryable() &&
			!strings.Contains(strings.ToLower(err.Error()), "canary")
	}
	for i, s := range invalid {
		if err := s.Validate(); !isInvalidSpec(err) {
			t.Errorf("case %d: Validate() = %v", i, err)
		}
	}
	for i, s := range []LoopSpec{
		valid,
		with(func(s *LoopSpec) {
			s.Budget = Budget{MaxIterations: MaxIterationsLimit, MaxTokens: MaxTokensLimit, MaxWallTime: MaxWallTimeLimit}
			s.ActivityTimeout = MaxActivityTimeout
		}),
		with(func(s *LoopSpec) {
			s.Budget = Budget{MaxIterations: 1, MaxTokens: 1, MaxWallTime: time.Second}
			s.Strategies = slices.Repeat([]string{"s"}, MaxStrategies)
			s.SwitchAfter, s.EscalateAfter, s.ActivityTimeout = 1, 2, MinActivityTimeout
		}),
	} {
		if err := s.Validate(); err != nil {
			t.Errorf("valid case %d refused: %v", i, err)
		}
	}
	for _, i := range []int{0, 13} {
		s := newScript(pass())
		if _, err := execute(t, invalid[i], s, nil); !isInvalidSpec(err) {
			t.Errorf("case %d: workflow error %v", i, err)
		}
		if p, v := s.calls(); p+v != 0 {
			t.Errorf("case %d: %d activities ran", i, p+v)
		}
	}
}

func TestRunLoopValidationErrorNotRetried(t *testing.T) {
	for _, typ := range NonRetryableErrorTypes() {
		s := newScript(step{proposeErr: temporal.NewApplicationError("rejected", typ)})
		want(t, run(t, testSpec(), s, nil), StatusEscalated, ReasonActivityFailed, 0)
		if p, _ := s.calls(); p != 1 {
			t.Errorf("%s: %d attempts, want 1", typ, p)
		}
	}
	s := newScript(step{tokens: 10, verifyErr: temporal.NewApplicationError("rejected", ErrTypeValidation)})
	res := run(t, testSpec(), s, nil)
	want(t, res, StatusEscalated, ReasonActivityFailed, 1)
	if _, v := s.calls(); v != 1 || res.Trace[0].Verified || res.Tokens != 10 {
		t.Errorf("verifier: %d attempts, trace %+v", v, res.Trace)
	}
	if !slices.Equal(NonRetryableErrorTypes(), []string{ErrTypeValidation, ErrTypePolicyViolation, ErrTypeBudgetExceeded}) {
		t.Error("non retryable error types changed")
	}
}

func TestRunLoopActivityFailureEscalates(t *testing.T) {
	transient := errors.New("transient")
	s := newScript(fail(high("A")), step{proposeErr: transient})
	res := run(t, testSpec(), s, nil)
	want(t, res, StatusEscalated, ReasonActivityFailed, 1)
	if p, _ := s.calls(); p != 1+MaxActivityAttempts {
		t.Errorf("proposer attempts %d", p)
	}
	if string(res.Best) != `{"n":1}` || !slices.Equal(res.Remaining, []domain.Finding{high("A")}) {
		t.Errorf("best %s, remaining %v", res.Best, res.Remaining)
	}
	s = newScript(step{tokens: 10, verifyErr: transient})
	res = run(t, testSpec(), s, nil)
	want(t, res, StatusEscalated, ReasonActivityFailed, 1)
	if _, v := s.calls(); v != MaxActivityAttempts || res.Best != nil {
		t.Errorf("verifier attempts %d, best %s", v, res.Best)
	}
}
```
Indices 0 et 13 de `invalid` : budget d'itérations nul, vérificateur égal au proposeur.

## 6. Critères d'acceptation (racine)
| # | Commande | Attendu |
|---|---|---|
| 1 | `go test ./internal/loops/ -count=1 -run TestRunLoop -v 2>&1 \| grep -c -- '^--- PASS: TestRunLoop'` ; idem `grep -cE -- '--- (FAIL\|SKIP)'` | `14` ; `0` |
| 2 | `go test ./internal/loops/... -count=1 -race; echo rc=$?` | `rc=0` |
| 3 | `go tool workflowcheck ./internal/loops/...; echo rc=$?` | aucune ligne de diagnostic, `rc=0` |
| 4 | `go list -f '{{join .Imports " "}}' ./internal/loops \| sed 's#github.com/amezianechayer/rempart/##g'` | `encoding/json internal/loops/domain go.temporal.io/sdk/temporal go.temporal.io/sdk/workflow slices time` |
| 5 | `go test ./internal/archtest/ -count=1 -run TestRepositoryConforms; echo rc=$?` | `rc=0` (R3, R4) |
| 6 | `grep -nE 'time\.(Now\|Sleep)\|math/rand\|"os"\|"log\|go func\|<-' internal/loops/*.go \| grep -v _test.go \| wc -l` | `0` |
| 7 | `grep -rnE '//[[:space:]]*(nolint\|#nosec)\|workflowcheck:ignore\|panic\(' --include='*.go' internal/loops \| wc -l` | `0` |
| 8 | `golangci-lint run ./internal/loops/...; echo rc=$?` | `rc=0` |
| 9 | `grep -A2 '^arch-test:' Makefile \| grep -c 'go tool workflowcheck ./internal/loops/...'` ; `go list -m go.temporal.io/sdk go.temporal.io/sdk/contrib/tools/workflowcheck` | `1` ; `v1.49.0` et `v0.5.0` |
| 10 | `go mod tidy -diff; echo rc=$?` | `rc=0` |
| 11 | `make verify-quick; echo rc=$?` | `rc=0` |

## 7. Mutations sur copie
Script de `docs/plans/M0-tenancy.md` 8.3, fichier `internal/loops/spec.go` pour M1 à M3, `runloop.go` sinon ; `OLD` présent une fois ; `go test ./internal/loops/ -count=1 2>&1 | grep -cE -- "--- FAIL: ($EXPECTED)"` au moins `1`. « faux » : `if false {` (ou `case false:`).

| # | `OLD` | `NEW` | `EXPECTED` |
|---|---|---|---|
| M1 | `case s.ProposeActivity == s.VerifyActivity:` | `case false:` | T12 |
| M2 | `case b.MaxIterations < 1 \|\| b.MaxIterations > MaxIterationsLimit:` | `case b.MaxIterations < 1:` | T12 |
| M3 | `return []string{ErrTypeValidation, ErrTypePolicyViolation, ErrTypeBudgetExceeded}` | `return []string{ErrTypePolicyViolation, ErrTypeBudgetExceeded}` | T13 |
| M4 | `return workflow.Now(ctx).Sub(start) >= spec.Budget.MaxWallTime` | `>` au lieu de `>=` | T8 |
| M5 | `if timeUp() { // T10: no proposal past the wall time budget` | faux | T8 |
| M6 | `if timeUp() { // T10: no verification past the wall time budget` | faux | T8 |
| M7 | `if prop.Tokens < 0 \|\| prop.Tokens > MaxTokensLimit {` | `if prop.Tokens > MaxTokensLimit {` | T7 |
| M8 | `if res.Tokens > spec.Budget.MaxTokens {` | `>=` au lieu de `>` | T7 |
| M9 | `Findings: domain.Top(last, MaxFindingsToPropose), Iteration: it,` | `Findings: last, Iteration: it,` | T10 |
| M10 | `fp, score := domain.Fingerprint(vr.Findings), domain.Score(vr.Findings)` | `fp, score := domain.Fingerprint(domain.Top(vr.Findings, 1)), domain.Score(vr.Findings)` | T11 |
| M11 | `if blocking(vr.Findings) {` | faux | T1 |
| M12 | `if !haveBest \|\| score < bestScore {` | `<=` au lieu de `<` | T9 |
| M13 | `res.Status, res.Reason, res.Best, res.Remaining = StatusEscalated, r, best, remaining` | `..., best, last` | T9 |
| M14 | `lastFP, same = fp, 1` | `lastFP, same = fp, same+1` | T5 |
| M15 | `case same >= spec.EscalateAfter:` | `case same > spec.EscalateAfter:` | T3 |

## 8. Boucle (gabarit `loop-engineering`, générique)
Proposeur et vérificateur : activités nommées par la spécification, distinctes ; signal : top 20 des findings normalisés triés ; budget : itérations, tokens, temps (coût : M1) ; stagnation : 2 puis 3 par défaut ; escalade : `LoopResult` (meilleur candidat, findings restants, trace des empreintes et stratégies) ; idempotence : à la charge des activités (T19) ; traçabilité : `Trace` (spans en M1).

## 9. Risques, menaces, points non vérifiés
Risques : oscillation d'empreintes A, B, A non détectée (bornée par les budgets) ; candidats volumineux dans l'historique Temporal en clair (limite de payload du serveur, références chiffrées en M1, risque accepté M0) ; payload non JSON refusé par le convertisseur avant le workflow ; candidat vide transmis tel quel au vérificateur (qui le rejette).

Menaces (`security-reviewer`) : T10 renforcé (bornes D2, tokens non fiables D3, contrôle du temps avant chaque activité D4 ; dépassement borné à `3 x ActivityTimeout + 3 s`) ; T45 soldée côté boucle ; menace proposée **T53** : activité qui maquille la stagnation ou la convergence (empreinte fournie, OK incohérent, tokens négatifs), mitigée par D6, D7, D3, tests T1, T7, T11, mutations M7, M10, M11.

Points non vérifiés (à lever en A2 sur copie, sinon amendement V1) :
1. `workflowcheck` peut signaler un faux positif sous `domain.Fingerprint` (SHA-256) ou `temporal.NewNonRetryableApplicationError`. Parade : fichier `workflowcheck.config.yaml` à la racine (`decls: <fonction>: false`, motif justifié) et `-config` dans la recette ; jamais `//workflowcheck:ignore` (critère 7).
2. Égalité exacte de l'horloge simulée à la frontière (T8, 60 min pile) et `OnActivity(...).Return(s.propose)` avec une valeur de méthode.
3. Import de `testify/mock` alors que `go.mod` le marque indirect avant `go mod tidy` (`-mod=readonly`).
4. `nilerr` et `contextcheck` sur la fermeture `escalate` ; `go mod tidy` sans réseau.
5. Comportement du vrai serveur (timeouts, reprises) : non testé, pas de Docker ; testsuite seulement.

`docs/STATUS.md` : écarts D10 à D12 et netstring de T13 à reporter dans le skill en T19 (`temporal-loop-skeleton.md`, `normalized-findings.md`), modification de skill signalée ; T53 ; montées de version MVS.

## 10. Tâches ordonnées (après validation humaine ; A1 à I1 en un seul tour)
| # | Tâche | Qui | Vérification |
|---|---|---|---|
| E0 | Étape 0 (section 2), commit `build(deps)` | principal | contrôles section 2, arbre propre |
| A1 | `phase tests`, `runloop_test.go` (section 5) | `test-author` | `go vet ./internal/loops` : `undefined:` seulement |
| A2 | Copie : sections 4 et 5, critères 1 à 8, M1 à M15, points non vérifiés | `test-author` | vert, 15 détectées ; sinon amendement V1 |
| A3 | `phase impl` | principal | `Phase : tests -> impl` |
| I1 | `doc.go`, `spec.go`, `runloop.go` ; `go mod tidy` | principal | critères 1 à 11 |
| F1 | M1 à M15 sur copie finale | principal | 15 détectées |
| F2 | `security-reviewer`, puis `acceptance-verifier` | subagents | PASS |
| F3 | `docs/STATUS.md`, `phase free`, commit `feat(loops): generic RunLoop workflow with budgets, stagnation and escalation (M0-T14)` | principal | `git status --porcelain` vide |

## 11. Amendement V2

Prime sur les sections 3 à 7 et 9 ; pas d'ADR (contrat interne, réversible avant T19).

### 11.1 Décisions
**Constat 1.** Proposeur à une tentative (`MaximumAttempts: 1`). Chaque appel est une itération ; en échec, ses tokens viennent du détail `ProposeFailure` de l'`ApplicationError` (0 sans détail, -1 si indécodable), bornés comme D3, comptés et tracés (`Failed`) avant toute escalade. **Reprise dans la boucle** : une `ApplicationError` rejouable (ni `NonRetryable()`, ni type de `NonRetryableErrorTypes()`) est reprise à l'itération suivante, même requête ; un échec non rejouable, ou le `MaxActivityAttempts`-ième consécutif, escalade `activity_failed`. Motif : la robustesse de V1 (3 appels) sans reprise invisible, chaque appel étant compté et soumis aux budgets, temps compris ; escalader au premier échec enverrait toute panne brève à l'humain. Délai, annulation, panique : escalade sans reprise. Sans attente : le client LLM reprend les pannes de transport (T50).

**Constat 2.** Candidat absent, `null`, `""`, `{}` ou `[]` : tokens comptés, `invalid_response`, sans vérification. Blancs : `encoding/json` compacte la sortie de `RawMessage.MarshalJSON` (T16 : `" [ ] "`).

**Constat 3.** Échec sans finding : `invalid_response`, symétrique de D7 ; l'exclure du meilleur laisserait le proposeur sans signal et masquerait l'anomalie. T3 : `fail()` du cas `no blocking finding` devient `fail(fnd(domain.SeverityInfo, "I0"))` (empreinte vide répétée, scores 0, 1, 0, meilleur `{"n":1}`).

**Constats 4 à 6.** T18 ; T14 (itération 2 valide, une seule proposition) ; `MaxEscalateAfter = 10` (T12).

**Remplacements.** D2 : plus `EscalateAfter <= MaxEscalateAfter`. D3 : (3) vaut aussi pour les tokens d'échec ; après (4), échec : escalade ou itération suivante (succès : compteur à 0), puis candidat vide : `invalid_response` ; après (8), échec sans finding : `invalid_response`. D4 : proposeur au plus `ActivityTimeout`, dépassement maximal inchangé. D5 : `Iterations` et `Tokens` incluent les échecs. D8 : meilleur parmi les vérifiés non OK avec finding. D10 : « échec sans finding » retiré ; un échec du proposeur ne touche pas la stagnation. D11 : `RetryPolicy` de la section 4 pour le vérificateur seul. D12 : plus `ProposeFailure`, `IterationTrace.Failed`, `MaxEscalateAfter`.

### 11.2 Diffs de `spec.go` et `runloop.go`
```diff
--- spec.go
 	MaxActivityAttempts  = 3
+	MaxEscalateAfter     = 10
 )
@@ Validate
-	case s.SwitchAfter < 1 || s.SwitchAfter >= s.EscalateAfter:
+	case s.SwitchAfter < 1 || s.SwitchAfter >= s.EscalateAfter || s.EscalateAfter > MaxEscalateAfter:
--- runloop.go
 	"encoding/json"
+	"errors"
 	"slices"
@@ après ProposeResponse
+// ProposeFailure is the detail of a proposer ApplicationError that spent
+// tokens; untrusted, bounded like ProposeResponse.Tokens (T10, T45).
+type ProposeFailure struct {
+	Tokens int `json:"tokens"`
+}
+
@@ IterationTrace
 	Strategy    string `json:"strategy"`
+	Failed      bool   `json:"failed"`
@@ RunLoop
+	// T10: one attempt per paid call; RunLoop retries within the budgets.
+	pctx := workflow.WithRetryPolicy(ctx, temporal.RetryPolicy{MaximumAttempts: 1})
 	start := workflow.Now(ctx)
@@
 		same, strat     int
+		failures        int
 	)
@@
 		var prop ProposeResponse
-		if err := workflow.ExecuteActivity(ctx, spec.ProposeActivity, req).Get(ctx, &prop); err != nil {
-			return escalate(ReasonActivityFailed)
-		}
+		perr := workflow.ExecuteActivity(pctx, spec.ProposeActivity, req).Get(ctx, &prop)
+		if perr != nil {
+			prop.Tokens = failedTokens(perr)
+		}
 		if prop.Tokens < 0 || prop.Tokens > MaxTokensLimit {
@@
-		res.Trace = append(res.Trace, IterationTrace{Iteration: it, Strategy: req.Strategy, Tokens: prop.Tokens})
+		res.Trace = append(res.Trace, IterationTrace{Iteration: it, Strategy: req.Strategy, Failed: perr != nil, Tokens: prop.Tokens})
@@
 			return escalate(ReasonBudgetTokens)
 		}
+		if perr != nil {
+			failures++
+			if !retryable(perr) || failures >= MaxActivityAttempts {
+				return escalate(ReasonActivityFailed)
+			}
+			continue // same request; time checked first
+		}
+		failures = 0
+		if emptyCandidate(prop.Candidate) { // T53: empty desired state
+			return escalate(ReasonInvalidResponse)
+		}
 		if timeUp() { // T10: no verification past the wall time budget
@@
 		if err := workflow.ExecuteActivity(ctx, spec.VerifyActivity, vreq).Get(ctx, &vr); err != nil {
-			return escalate(ReasonActivityFailed)
+			return escalate(ReasonActivityFailed) // Temporal retries only
@@
 			return res, nil
 		}
+		if len(vr.Findings) == 0 { // T53: failure without finding
+			return escalate(ReasonInvalidResponse)
+		}
 		if !haveBest || score < bestScore {
@@ fin
+
+// failedTokens reads the ProposeFailure detail: 0 if absent, -1 if undecodable.
+func failedTokens(err error) int {
+	var ae *temporal.ApplicationError
+	var f ProposeFailure
+	if errors.As(err, &ae) && ae.HasDetails() && ae.Details(&f) != nil {
+		return -1
+	}
+	return f.Tokens
+}
+
+// retryable reports a retryable application error (no timeout, cancellation or panic).
+func retryable(err error) bool {
+	var ae *temporal.ApplicationError
+	return errors.As(err, &ae) && !ae.NonRetryable() && !slices.Contains(NonRetryableErrorTypes(), ae.Type())
+}
+
+// emptyCandidate reports a candidate without content (encoding/json compacted it).
+func emptyCandidate(c json.RawMessage) bool {
+	return slices.Contains([]string{"", "null", `""`, "{}", "[]"}, string(c))
+}
```

### 11.3 Tests
T15 à T18 : fonctions ci-dessous, après T14. T3 : section 11.1. T12 : `with(func(s *LoopSpec) { s.EscalateAfter = MaxEscalateAfter + 1 }),` en fin de `invalid` ; `s.SwitchAfter, s.EscalateAfter = MaxEscalateAfter-1, MaxEscalateAfter` dans le cas valide 1. Assistants, T13, T14 : diff exact.
```diff
@@ type step struct
 	ok                    bool
+	cand                  json.RawMessage
@@ func (s *script) propose
-	return ProposeResponse{Candidate: candidate(req.Iteration), Tokens: st.tokens}, nil
+	c := candidate(req.Iteration)
+	if st.cand != nil {
+		c = st.cand
+	}
+	return ProposeResponse{Candidate: c, Tokens: st.tokens}, nil
@@ T13
-		s := newScript(step{proposeErr: temporal.NewApplicationError("rejected", typ)})
-		want(t, run(t, testSpec(), s, nil), StatusEscalated, ReasonActivityFailed, 0)
-		if p, _ := s.calls(); p != 1 {
+		s := newScript(step{proposeErr: temporal.NewApplicationError("rejected", typ, ProposeFailure{Tokens: 40})}, pass())
+		res := run(t, testSpec(), s, nil)
+		want(t, res, StatusEscalated, ReasonActivityFailed, 1)
+		if p, _ := s.calls(); p != 1 || res.Tokens != 40 || !res.Trace[0].Failed {
@@ T14
-	s := newScript(fail(high("A")), step{proposeErr: transient})
+	e := step{proposeErr: transient}
+	s := newScript(fail(high("A")), e, e, e, pass())
 	res := run(t, testSpec(), s, nil)
-	want(t, res, StatusEscalated, ReasonActivityFailed, 1)
+	want(t, res, StatusEscalated, ReasonActivityFailed, 1+MaxActivityAttempts)
@@
-	s = newScript(step{tokens: 10, verifyErr: transient})
+	s = newScript(step{tokens: 10, verifyErr: transient}, pass())
@@
-	if _, v := s.calls(); v != MaxActivityAttempts || res.Best != nil {
+	if p, v := s.calls(); p != 1 || v != MaxActivityAttempts || res.Best != nil {
```
```go
func TestRunLoopProposerFailuresCounted(t *testing.T) {
	failed := func(detail any) step {
		return step{proposeErr: temporal.NewApplicationError("llm call failed", "Transient", detail)}
	}
	s := newScript(fail(high("A")), failed(ProposeFailure{Tokens: 7}), failed(ProposeFailure{Tokens: 5}), pass())
	res := run(t, testSpec(), s, nil)
	want(t, res, StatusConverged, "", 4)
	tr := res.Trace
	if p, v := s.calls(); p != 4 || v != 2 || res.Tokens != 32 || tr[1].Tokens != 7 || !tr[2].Failed || tr[2].Verified || tr[3].Failed {
		t.Errorf("calls %d %d, tokens %d, trace %+v", p, v, res.Tokens, tr)
	}
	other := step{proposeErr: temporal.NewNonRetryableApplicationError("llm", "Other", nil)}
	want(t, run(t, testSpec(), newScript(other, pass()), nil), StatusEscalated, ReasonActivityFailed, 1)
	for _, d := range []any{ProposeFailure{Tokens: -1}, ProposeFailure{Tokens: MaxTokensLimit + 1}, "tokens"} {
		s := newScript(failed(d), pass())
		res := run(t, testSpec(), s, nil)
		want(t, res, StatusEscalated, ReasonInvalidResponse, 0)
		if p, _ := s.calls(); p != 1 || res.Tokens != 0 {
			t.Errorf("detail %v: calls %d, tokens %d", d, p, res.Tokens)
		}
	}
}

func TestRunLoopEmptyCandidateRejected(t *testing.T) {
	for _, c := range []string{"null", `""`, "{}", " [ ] "} {
		s := newScript(step{tokens: 10, ok: true, cand: json.RawMessage(c)}, pass())
		res := run(t, testSpec(), s, nil)
		want(t, res, StatusEscalated, ReasonInvalidResponse, 1)
		if _, v := s.calls(); v != 0 || res.Tokens != 10 || res.Best != nil {
			t.Errorf("candidate %q: %d verifies, best %s", c, v, res.Best)
		}
	}
}

func TestRunLoopFailureWithoutFindingRejected(t *testing.T) {
	res := run(t, testSpec(), newScript(fail(high("A")), fail(), pass()), nil)
	want(t, res, StatusEscalated, ReasonInvalidResponse, 2)
	if !res.Trace[1].Verified || string(res.Best) != `{"n":1}` || !slices.Equal(res.Remaining, []domain.Finding{high("A")}) {
		t.Errorf("best %s, remaining %v", res.Best, res.Remaining)
	}
}

func TestRunLoopLimitsFrozen(t *testing.T) {
	got := []any{
		DefaultSwitchAfter, DefaultEscalateAfter, DefaultActivityTimeout, MaxIterationsLimit, MaxTokensLimit, MaxWallTimeLimit,
		MinActivityTimeout, MaxActivityTimeout, MaxStrategies, MaxFindingsToPropose, MaxActivityAttempts, MaxEscalateAfter,
	}
	frozen := []any{2, 3, 5 * time.Minute, 100, 10_000_000, 24 * time.Hour, time.Second, 30 * time.Minute, 10, 20, 3, 10}
	if !slices.Equal(got, frozen) {
		t.Errorf("limits %v, want %v", got, frozen)
	}
}
```

### 11.4 Critères et mutations
Critère 1 : `18` ; `0`. Critère 4 : `encoding/json errors internal/loops/domain go.temporal.io/sdk/temporal go.temporal.io/sdk/workflow slices time`. Critère 12 (nouveau) : M1 à M21 détectées (script de la section 7). Autres inchangés. Mutations (`spec.go` pour M21, sinon `runloop.go`) :

| # | `OLD` | `NEW` | `EXPECTED` |
|---|---|---|---|
| M16 | `pctx := workflow.WithRetryPolicy(ctx, temporal.RetryPolicy{MaximumAttempts: 1})` | `pctx := ctx` | T14, T15 |
| M17 | `prop.Tokens = failedTokens(perr)` | `prop.Tokens = 0` | T15 |
| M18 | `if emptyCandidate(prop.Candidate) { // T53: empty desired state` | faux | T16 |
| M19 | `if len(vr.Findings) == 0 { // T53: failure without finding` | faux | T17 |
| M20 | `return escalate(ReasonActivityFailed) // Temporal retries only` | `continue` | T14 |
| M21 | `MaxIterationsLimit   = 100` | `MaxIterationsLimit   = 1_000_000` | T18 |

### 11.5 Menaces, obligations, tâches
T10 renforcé ; résidu à reporter au modèle : tokens d'un appel interrompu par délai ou panique inconnus, comptés 0. T45 : détail d'échec borné. T53 : candidat vide et échec sans finding refusés.

Obligations hors V2 : (a) tailles des findings et candidats bornées, avant T19 ; (b) annulation distinguée d'une panne, avant T20 ; (c) `WorkflowExecutionTimeout >= MaxWallTime + 3 x ActivityTimeout + 3 s` plus marge, T20 ; (d) T54 (non enregistré, spécifications constantes), avant T19 et T20 ; (e) T16 : `workflow.GetVersion` pour constantes et commandes, M1 ; (f) stagnation sur les seuls codes, M1 ; (g) skill `loop-engineering` en T19, signalé dans `docs/STATUS.md`.

Tâches : (1) `test-author`, `phase tests`, 11.3 ; `go vet ./internal/loops` : erreurs sur `ProposeFailure`, `MaxEscalateAfter`, `Failed` seulement. (2) `test-author`, sur copie : 11.2, 11.3, critères 1 à 12, `workflowcheck` muet sous `errors.As` et `Details` ; sinon V3. (3) Principal : `phase impl`, 11.2. (4) `security-reviewer`, puis `acceptance-verifier` : PASS. (5) `docs/STATUS.md` (V2, résidu T10, (g)), `phase free`, commit `fix(loops): count failed proposer calls, refuse empty candidates and findingless failures (M0-T14)`.
