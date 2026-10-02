package intent_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/amezianechayer/rempart/internal/intent"
	"github.com/amezianechayer/rempart/internal/intent/domain"
)

// TestAtMostThreeQuestionsWithDefaults: rule 4 of the intent-to-spec skill,
// ADR 0006 decision 3. At most three questions per turn, each with a non-empty
// safe default; contradictions come first and the ones not asked are returned
// for the next turn.
func TestAtMostThreeQuestionsWithDefaults(t *testing.T) {
	for _, tc := range []struct{ name, fixture string }{
		{"four_questions", "drafts/four-questions.json"},
		{"empty_default", "drafts/empty-default.json"},
	} {
		t.Run("parse_refuses_"+tc.name, func(t *testing.T) {
			if _, err := intent.ParseDraft(readFixture(t, tc.fixture)); !errors.Is(err, intent.ErrDraftInvalid) {
				t.Errorf("want ErrDraftInvalid, got %v", err)
			}
		})
	}

	withModelQuestions := func(t *testing.T) domain.IR {
		t.Helper()
		var ir domain.IR
		if err := json.Unmarshal(readFixture(t, "reference-ir.json"), &ir); err != nil {
			t.Fatalf("decode reference-ir.json: %v", err)
		}
		ir.OpenQuestions = []domain.Question{
			{Field: "environment", Question: "Quel environnement ?", Default: "staging"},
			{Field: "observability.retention_days", Question: "Quelle rétention ?", Default: "90"},
		}
		return ir
	}
	contradictions := []domain.Contradiction{
		{Code: "CONTRA-FORBIDDEN-CLOUD", Field: "workloads[legacy-vms].cloud", Default: "retirer"},
		{Code: "CONTRA-REGION-NOT-ALLOWED", Field: "workloads[obs].region", Default: "eu-west-3"},
		{Code: "CONTRA-RUNS-ON-NOT-CLUSTER", Field: "workloads[gitops].runs_on", Default: "aucun"},
		{Code: "CONTRA-RESIDENCY", Field: "workloads[legacy-vms].region", Default: "eu-west-3"},
	}

	check := func(t *testing.T, ir domain.IR, asked []domain.Contradiction) {
		t.Helper()
		if len(ir.OpenQuestions) != 3 {
			t.Fatalf("want 3 open questions, got %d: %+v", len(ir.OpenQuestions), ir.OpenQuestions)
		}
		for i, q := range ir.OpenQuestions {
			if q.Default == "" || q.Question == "" {
				t.Errorf("question %d without text or default: %+v", i, q)
			}
			if q.Field != asked[i].Field || q.Default != asked[i].Default {
				t.Errorf("question %d = %+v, want contradiction %+v first", i, q, asked[i])
			}
		}
		if err := intent.ValidateIR(ir); err != nil {
			t.Errorf("ValidateIR: %v", err)
		}
	}

	t.Run("three_contradictions_before_model_questions", func(t *testing.T) {
		ir, rest := domain.WithContradictions(withModelQuestions(t), contradictions[:3], domain.LangFR)
		check(t, ir, contradictions[:3])
		if len(rest) != 0 {
			t.Errorf("want no contradiction left, got %+v", rest)
		}
	})

	t.Run("four_contradictions_one_deferred", func(t *testing.T) {
		ir, rest := domain.WithContradictions(withModelQuestions(t), contradictions, domain.LangFR)
		check(t, ir, contradictions[:3])
		if len(rest) != 1 || rest[0] != contradictions[3] {
			t.Errorf("want the fourth contradiction returned, got %+v", rest)
		}
	})
}
