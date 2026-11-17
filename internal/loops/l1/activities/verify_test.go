package activities_test

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/amezianechayer/rempart/internal/intent/domain"
	"github.com/amezianechayer/rempart/internal/loops"
	"github.com/amezianechayer/rempart/internal/loops/l1/activities"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

const tenantA tenancy.ID = "0f8fad5b-d9cb-469f-a165-70867728950e"

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := fs.ReadFile(os.DirFS(filepath.Join("..", "..", "..", "intent", "testdata")), name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func prepared(t *testing.T, a *activities.Activities, text string) json.RawMessage {
	t.Helper()
	p, err := a.Prepare(context.Background(), activities.Input{RequestText: text, Context: domain.TenantContext{AllowedRegions: []string{"eu-west-3", "francecentral"}}, Round: 1})
	if err != nil || p.Unsupported {
		t.Fatalf("Prepare: %+v, %v", p, err)
	}
	return p.Payload
}

// TestVerifyTenantFromModel (rule 9, T3): a draft that names a tenant, at any
// depth, is a critical finding, never accepted, even if the output schema of
// the client were relaxed.
func TestVerifyTenantFromModel(t *testing.T) {
	a := &activities.Activities{Tenant: tenantA}
	pl := prepared(t, a, string(fixture(t, "reference-request.txt")))
	for _, name := range []string{"tenant-top-level.json", "tenant-nested-in-workload.json", "tenant-camel-case.json"} {
		res, err := a.Verify(context.Background(), loops.VerifyRequest{Payload: pl, Candidate: fixture(t, "drafts/"+name), Iteration: 1})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.OK || len(res.Findings) != 1 || res.Findings[0].Code != activities.CodeTenantFromModel {
			t.Errorf("%s: %+v, want one %s finding", name, res, activities.CodeTenantFromModel)
		}
	}
	res, err := a.Verify(context.Background(), loops.VerifyRequest{Payload: pl, Candidate: fixture(t, "reference-draft.json"), Iteration: 1})
	if err != nil || !res.OK {
		t.Errorf("reference draft: %+v, %v; want OK", res, err)
	}
}

// TestFinalizeRefusesUnverifiedDraft: Finalize checks the draft again and
// never builds an IR from a draft with a blocking finding.
func TestFinalizeRefusesUnverifiedDraft(t *testing.T) {
	a := &activities.Activities{Tenant: tenantA}
	pl := prepared(t, a, string(fixture(t, "c4-request.txt")))
	if _, err := a.Finalize(context.Background(), activities.FinalizeRequest{Payload: pl, Candidate: fixture(t, "drafts/c4-obey-managed-db.json")}); err == nil {
		t.Error("Finalize built an IR from a draft exposing the database")
	}
	if _, err := (&activities.Activities{Tenant: tenancy.System}).Finalize(context.Background(), activities.FinalizeRequest{Payload: pl, Candidate: fixture(t, "drafts/c4-override.json")}); err == nil {
		t.Error("Finalize accepted the system tenant")
	}
}

// TestPrepareRefusesBadPayloads: a payload that Prepare did not build is
// refused by the other activities before any check.
func TestPrepareRefusesBadPayloads(t *testing.T) {
	a := &activities.Activities{Tenant: tenantA}
	for name, raw := range map[string]string{
		"extra_key":   `{"request_text":"Je veux un cluster.","answers":[],"context":{"allowed_regions":null,"forbidden_clouds":null,"compliance":null},"language":"fr","tenant_id":"x"}`,
		"bad_lang":    `{"request_text":"Je veux un cluster.","answers":[],"context":{"allowed_regions":null,"forbidden_clouds":null,"compliance":null},"language":"de"}`,
		"duplicate":   `{"request_text":"a","request_text":"Je veux un cluster.","answers":[],"context":{"allowed_regions":null,"forbidden_clouds":null,"compliance":null},"language":"fr"}`,
		"long_text":   `{"request_text":"` + strings.Repeat("a", activities.MaxRequestBytes+1) + `","answers":[],"context":{"allowed_regions":null,"forbidden_clouds":null,"compliance":null},"language":"fr"}`,
		"not_object":  `[]`,
		"empty":       ``,
		"bad_context": `{"request_text":"Je veux un cluster.","answers":[],"context":{"allowed_regions":["EU WEST"],"forbidden_clouds":null,"compliance":null},"language":"fr"}`,
	} {
		if !utf8.ValidString(raw) {
			t.Fatal(name)
		}
		if _, err := a.Verify(context.Background(), loops.VerifyRequest{Payload: json.RawMessage(raw), Candidate: fixture(t, "reference-draft.json")}); err == nil {
			t.Errorf("%s: Verify accepted the payload", name)
		}
	}
}
