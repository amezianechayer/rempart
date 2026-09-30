package intent_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/amezianechayer/rempart/internal/intent"
	"github.com/amezianechayer/rempart/internal/intent/domain"
)

const referenceTenant = "3f6c2a9e-8b1d-4c7a-9e2f-5d4b3a2c1e0f"

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return b
}

// referenceDraft parses testdata/reference-draft.json with the production parser.
func referenceDraft(t *testing.T) domain.Draft {
	t.Helper()
	d, err := intent.ParseDraft(readFixture(t, "reference-draft.json"))
	if err != nil {
		t.Fatalf("ParseDraft(reference-draft.json): %v", err)
	}
	return d
}

// asTree returns the generic JSON tree of v.
func asTree(t *testing.T, v any) any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("encode %T: %v", v, err)
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

// decodeTree decodes raw into a generic JSON tree.
func decodeTree(t *testing.T, raw []byte) any {
	t.Helper()
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}
