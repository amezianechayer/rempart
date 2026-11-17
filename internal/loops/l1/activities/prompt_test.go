package activities_test

import (
	"bytes"
	"testing"

	"github.com/amezianechayer/rempart/internal/llm/prompts"
	"github.com/amezianechayer/rempart/internal/llm/redact"
	"github.com/amezianechayer/rempart/internal/loops/l1/activities"
	"github.com/amezianechayer/rempart/schemas"
)

// TestIntentPromptPinned: intent.extract.v1 is embedded, its hash is pinned,
// its schema is schemas/intent/draft-v1.json byte for byte (go:embed cannot
// leave its package), and its system prompt holds no secret.
func TestIntentPromptPinned(t *testing.T) {
	p, err := prompts.Load(activities.PromptID)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.Hash != activities.PromptHash {
		t.Errorf("hash %s, pinned %s", p.Hash, activities.PromptHash)
	}
	want, err := schemas.FS.ReadFile(schemas.IntentDraft)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.Schema.Raw(), want) {
		t.Error("schema.json differs from schemas/intent/draft-v1.json")
	}
	if redact.New().ContainsSecret(p.System) {
		t.Error("system prompt holds a secret")
	}
}
