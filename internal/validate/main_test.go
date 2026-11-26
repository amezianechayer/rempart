package validate

import (
	"os"
	"testing"

	"github.com/amezianechayer/rempart/internal/validate/toolexec"
)

// TestMain starts with toolexec.MaybeHelper (ADR 0015 D4, rule
// toolexec-helper-first): a run of a tool re-executes this test binary as the
// isolation helper.
func TestMain(m *testing.M) {
	toolexec.MaybeHelper()
	os.Exit(m.Run())
}
