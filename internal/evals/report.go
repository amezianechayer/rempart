package evals

import (
	"errors"
	"fmt"
	"slices"
)

var ErrIncompleteRuns = errors.New("evals: incomplete runs")

type Report struct {
	Loop                  string       `json:"loop"`
	Platform              string       `json:"platform"`
	Region                string       `json:"region"`
	Model                 string       `json:"model"`
	Cases                 int          `json:"cases"`
	Runs                  int          `json:"runs"`
	InjectionRuns         int          `json:"injection_runs"`
	EscalationRuns        int          `json:"escalation_runs"`
	SuccessRate           float64      `json:"success_rate"`
	CorrectEscalationRate float64      `json:"correct_escalation_rate"`
	InjectionResistance   float64      `json:"injection_resistance"`
	AvgIterations         float64      `json:"avg_iterations"`
	AvgTokens             float64      `json:"avg_tokens"`
	RegressionsVsBaseline []Regression `json:"regressions_vs_baseline"`
}

func Aggregate(s Suite, grades []Grade, outcomes []Outcome) (Report, error) {
	if len(grades) != len(outcomes) {
		return Report{}, ErrIncompleteRuns
	}
	cases, total := make(map[string]Case, len(s.Cases)), 0
	for _, c := range s.Cases {
		cases[c.ID] = c
		total += c.Runs
	}
	seen := map[string]bool{}
	var pass, escRuns, escOK, injRuns, injOK int
	var iterations, tokens float64
	for i, g := range grades {
		c, known := cases[g.CaseID]
		k, o := fmt.Sprint(g.CaseID, "/", g.Run), outcomes[i]
		if !known || seen[k] || g.Run < 0 || g.Run >= c.Runs || o.Iterations < 0 || o.Tokens < 0 {
			return Report{}, fmt.Errorf("%w: grade %d", ErrIncompleteRuns, i)
		}
		seen[k] = true
		if g.Pass {
			pass++
		}
		if e := c.Expect.Escalation; e != nil {
			escRuns++
			if o.Escalated == *e {
				escOK++
			}
		}
		if slices.Contains(c.Tags, InjectionTag) {
			injRuns++
			if g.Pass {
				injOK++
			}
		}
		iterations += float64(o.Iterations)
		tokens += float64(o.Tokens)
	}
	if total == 0 || len(seen) != total {
		return Report{}, ErrIncompleteRuns
	}
	return Report{
		Loop: s.Loop, Cases: len(s.Cases), Runs: total,
		InjectionRuns: injRuns, EscalationRuns: escRuns,
		SuccessRate: ratio(pass, total), CorrectEscalationRate: ratio(escOK, escRuns),
		InjectionResistance: ratio(injOK, injRuns),
		AvgIterations:       iterations / float64(total), AvgTokens: tokens / float64(total),
		RegressionsVsBaseline: []Regression{},
	}, nil
}

func ratio(k, n int) float64 {
	if n == 0 {
		return 1
	}
	return float64(k) / float64(n)
}
