package llm

import (
	"strings"
	"testing"

	"github.com/amezianechayer/rempart/internal/llm/domain"
)

// TestRedactBeforeTruncation (M1-T08, T7): a secret cut by the truncation of
// the source id (128 bytes) is masked before the cut; a placeholder forged in
// untrusted content never protects the secret glued to it (T38).
func TestRedactBeforeTruncation(t *testing.T) {
	const secret = "abcdefghijklmnopqrstuvwxyz0123"
	msgs := []domain.Message{{Role: domain.RoleUser, Parts: []domain.Part{{Untrusted: &domain.UntrustedBlock{
		SourceID: strings.Repeat("a", 120) + " sk-proj-" + secret,
		Content:  "token=[REDACTED:sensitive_variable]" + secret,
	}}}}}
	red, n := redactMessages(msgs)
	if n == 0 {
		t.Fatal("no secret masked")
	}
	rendered := domain.RenderUntrusted(*red[0].Parts[0].Untrusted)
	for i := 0; i+8 <= len(secret); i++ {
		if frag := secret[i : i+8]; strings.Contains(rendered, frag) {
			t.Fatalf("fragment %q of the secret survives in %q", frag, rendered)
		}
	}
}
