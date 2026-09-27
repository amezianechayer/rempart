package evals

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/amezianechayer/rempart/internal/llm/schema"
)

type Outcome struct {
	Output             json.RawMessage
	SchemaValid        bool
	Status             string
	Escalated          bool
	Iterations, Tokens int
	Duration           time.Duration
	Err                string
}

type Grade struct {
	CaseID                        string
	Run                           int
	Pass, Injection               bool
	ExpectedEscalation, Escalated bool
	Failures                      []string
}

type check struct {
	steps []string
	match func(any) bool
}

func GradeOutcome(c Case, run int, o Outcome) (Grade, error) {
	inc, exc, err := compileCase(c)
	if err == nil && (run < 0 || run >= c.Runs) {
		err = fmt.Errorf("%w: run", ErrInvalidCase)
	}
	if err != nil {
		return Grade{}, err
	}
	e := c.Expect
	g := Grade{CaseID: c.ID, Run: run, Injection: slices.Contains(c.Tags, InjectionTag), Escalated: o.Escalated}
	g.ExpectedEscalation = e.Escalation != nil && *e.Escalation
	fail := func(ok bool, code string) {
		if !ok {
			g.Failures = append(g.Failures, code)
		}
	}
	fail(o.Err == "", "error")
	fail(o.Iterations >= 0 && o.Tokens >= 0 && o.Duration >= 0, "outcome")
	fail(e.SchemaValid == nil || o.SchemaValid == *e.SchemaValid, "schema_valid")
	fail(e.Escalation == nil || o.Escalated == *e.Escalation, "escalation")
	fail(e.Status == "" || o.Status == e.Status, "status")
	fail(e.MaxIterations == nil || o.Iterations <= *e.MaxIterations, "max_iterations")
	if e.MaxOpenQuestions != nil || len(inc)+len(exc) > 0 {
		out, err := decodeJSON(o.Output)
		fail(err == nil, "output")
		m, isObject := out.(map[string]any)
		q, present := m["open_questions"]
		a, isArray := q.([]any)
		fail(err != nil || e.MaxOpenQuestions == nil || (isObject && (!present || isArray) && len(a) <= *e.MaxOpenQuestions), "max_open_questions")
		for i, ch := range inc {
			fail(err != nil || slices.ContainsFunc(selectPath(out, ch.steps), ch.match), fmt.Sprintf("must_include[%d]", i))
		}
		for i, ch := range exc {
			fail(err != nil || !slices.ContainsFunc(selectPath(out, ch.steps), ch.match), fmt.Sprintf("must_not_include[%d]", i))
		}
	}
	g.Pass = len(g.Failures) == 0
	return g, nil
}

func compileCase(c Case) (inc, exc []check, err error) {
	e := c.Expect
	checks := len(e.MustInclude) + len(e.MustNotInclude)
	_, jerr := decodeJSON(c.Input)
	if !token(c.ID, 64, lower+"0123456789-") || !token(c.Loop, 32, loopSet) || jerr != nil || c.Runs < 1 || c.Runs > 10 ||
		slices.ContainsFunc(c.Tags, func(t string) bool { return !tagToken.MatchString(t) }) ||
		checks > 32 || (e.MaxIterations != nil && *e.MaxIterations < 1) || (e.MaxOpenQuestions != nil && *e.MaxOpenQuestions < 0) ||
		(checks == 0 && e.SchemaValid == nil && e.Escalation == nil && e.Status == "" && e.MaxIterations == nil && e.MaxOpenQuestions == nil) {
		return nil, nil, fmt.Errorf("%w: fields", ErrInvalidCase)
	}
	if inc, err = compileChecks(e.MustInclude); err == nil {
		exc, err = compileChecks(e.MustNotInclude)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInvalidCase, err)
	}
	return inc, exc, nil
}

func compileChecks(list []PathCheck) ([]check, error) {
	out := make([]check, 0, len(list))
	for _, pc := range list {
		steps, err := parsePath(pc.Path)
		if err != nil {
			return nil, err
		}
		if pc.Contains != nil && pc.Equals != nil {
			return nil, errors.New("path check value")
		}
		raw, match := pc.Equals, equalJSON
		if pc.Contains != nil {
			raw, match = pc.Contains, containsJSON
		}
		ch := check{steps: steps, match: func(any) bool { return true }}
		if raw != nil {
			want, err := decodeJSON(raw)
			if err != nil || (pc.Contains != nil && want == "") {
				return nil, errors.New("path check value")
			}
			ch.match = func(v any) bool { return match(v, want) }
		}
		out = append(out, ch)
	}
	return out, nil
}

func decodeJSON(data []byte) (any, error) {
	return schema.DecodeStrict(data)
}

func equalJSON(a, b any) bool {
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, xv := range x {
			if yv, ok := y[k]; !ok || !equalJSON(xv, yv) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		return ok && slices.EqualFunc(x, y, equalJSON)
	case json.Number:
		y, ok := b.(json.Number)
		rx, okx := new(big.Rat).SetString(string(x))
		ry, oky := new(big.Rat).SetString(string(y))
		return ok && okx && oky && rx.Cmp(ry) == 0
	}
	return a == b
}

func containsJSON(v, needle any) bool {
	if equalJSON(v, needle) {
		return true
	}
	switch x := v.(type) {
	case string:
		s, ok := needle.(string)
		return ok && strings.Contains(x, s)
	case []any:
		return slices.ContainsFunc(x, func(e any) bool { return containsJSON(e, needle) })
	}
	return false
}
