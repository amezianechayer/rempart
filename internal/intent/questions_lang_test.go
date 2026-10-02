package intent_test

import (
	"encoding/json"
	"testing"

	"github.com/amezianechayer/rempart/internal/intent"
	"github.com/amezianechayer/rempart/internal/intent/domain"
)

// TestQuestionsInRequestLanguage: ADR 0006 amendment A1.3 (plan
// M1-intent-multilingual, P8, section 6.4, test 5). The questions computed in
// code are written in the language of the request; the path and the symbolic
// safe default stay English identifiers (remove, none) and do not depend on
// the language; the IR stays valid in both languages.
func TestQuestionsInRequestLanguage(t *testing.T) {
	var ir domain.IR
	if err := json.Unmarshal(readFixture(t, "reference-ir.json"), &ir); err != nil {
		t.Fatalf("decode reference-ir.json: %v", err)
	}
	found := false
	for i := range ir.Workloads {
		if ir.Workloads[i].ID == "obs" {
			target := "legacy-vms"
			ir.Workloads[i].RunsOn = &target
			found = true
		}
	}
	if !found {
		t.Fatal("fixture: workload obs not found")
	}
	ctx := domain.TenantContext{ForbiddenClouds: []string{"azure"}}

	cs := domain.Contradictions(ir, ctx)
	wantDefaults := map[string]struct{ field, def string }{
		domain.ContraForbiddenCloud:   {"workloads[legacy-vms].cloud", "remove"},
		domain.ContraRunsOnNotCluster: {"workloads[obs].runs_on", "none"},
	}
	if len(cs) != len(wantDefaults) {
		t.Fatalf("want %d contradictions, got %+v", len(wantDefaults), cs)
	}
	for _, c := range cs {
		w, ok := wantDefaults[c.Code]
		if !ok || c.Field != w.field || c.Default != w.def {
			t.Errorf("contradiction %+v, want field %q and default %q", c, w.field, w.def)
		}
	}

	text := map[domain.Lang]map[string]string{
		domain.LangFR: {
			domain.ContraForbiddenCloud:   "Ce cloud est interdit pour ce tenant. Retirer ce composant ?",
			domain.ContraRunsOnNotCluster: "Ce composant doit être déployé dans un cluster Kubernetes. Le déployer sans cluster ?",
		},
		domain.LangEN: {
			domain.ContraForbiddenCloud:   "This cloud is forbidden for this tenant. Remove this component?",
			domain.ContraRunsOnNotCluster: "This component must be deployed in a Kubernetes cluster. Deploy it without a cluster?",
		},
	}
	asked := map[domain.Lang]domain.IR{}
	for _, lang := range []domain.Lang{domain.LangEN, domain.LangFR} {
		got, rest := domain.WithContradictions(ir, cs, lang)
		if len(rest) != 0 {
			t.Errorf("%s: want no contradiction left, got %+v", lang, rest)
		}
		if len(got.OpenQuestions) != len(cs) {
			t.Fatalf("%s: want %d questions, got %+v", lang, len(cs), got.OpenQuestions)
		}
		for i, q := range got.OpenQuestions {
			if want := text[lang][cs[i].Code]; q.Question != want {
				t.Errorf("%s: question %d = %q, want %q", lang, i, q.Question, want)
			}
		}
		if err := intent.ValidateIR(got); err != nil {
			t.Errorf("%s: ValidateIR: %v", lang, err)
		}
		asked[lang] = got
	}
	en, fr := asked[domain.LangEN].OpenQuestions, asked[domain.LangFR].OpenQuestions
	for i := range en {
		if en[i].Field != fr[i].Field || en[i].Default != fr[i].Default {
			t.Errorf("question %d: field or default differ between languages: en %+v, fr %+v", i, en[i], fr[i])
		}
	}
}
