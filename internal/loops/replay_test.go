package loops_test

import (
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	tlog "go.temporal.io/sdk/log"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"

	"github.com/amezianechayer/rempart/internal/loops/demo"
)

// TestReplay (ADR 0001, table of the checks since M0, line 2; obligations
// (e), (m), (ag); D8 and D10 of M1-codec-replay): every reference history of
// testdata/histories replays with the current code through the converters
// of Rempart; witness: a variant that adds a command without
// workflow.GetVersion fails in nondeterminism, the same behind GetVersion
// replays. Never skipped.
func TestReplay(t *testing.T) {
	histories := []string{"demo-run1.json", "demo-run2.json"}
	got, err := fs.Glob(os.DirFS("testdata/histories"), "*.json")
	if err != nil || !slices.Equal(got, histories) {
		t.Fatalf("testdata/histories holds %v, %v; want exactly %v", got, err, histories)
	}
	logger := tlog.NewStructuredLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
	replay := func(t *testing.T, wf any, file string) error {
		t.Helper()
		dc, fc, ps := replayConverters(t)
		r, err := worker.NewWorkflowReplayerWithOptions(worker.WorkflowReplayerOptions{
			DataConverter: dc, FailureConverter: fc, ContextPropagators: ps,
		})
		if err != nil {
			t.Fatal(err)
		}
		r.RegisterWorkflowWithOptions(wf, workflow.RegisterOptions{Name: demo.WorkflowName})
		return r.ReplayWorkflowHistoryFromJSONFile(logger, filepath.Join("testdata", "histories", file))
	}

	for _, f := range histories {
		t.Run("replay_"+strings.ReplaceAll(strings.TrimSuffix(f, ".json"), "-", "_"), func(t *testing.T) {
			if err := replay(t, demo.Workflow, f); err != nil {
				t.Errorf("replay of %s: %v", f, err)
			}
		})
	}

	t.Run("incompatible_without_getversion", func(t *testing.T) {
		variant := func(ctx workflow.Context, in demo.Input) (demo.Output, error) {
			if err := workflow.Sleep(ctx, time.Millisecond); err != nil {
				return demo.Output{}, err
			}
			return demo.Workflow(ctx, in)
		}
		err := replay(t, variant, histories[0])
		if err == nil || !strings.Contains(err.Error(), "[TMPRL1100]") {
			t.Errorf("replay of an incompatible variant: %v, want a nondeterminism error [TMPRL1100]", err)
		}
	})

	t.Run("compatible_with_getversion", func(t *testing.T) {
		variant := func(ctx workflow.Context, in demo.Input) (demo.Output, error) {
			if workflow.GetVersion(ctx, "test-replay-witness", workflow.DefaultVersion, 1) == 1 {
				if err := workflow.Sleep(ctx, time.Millisecond); err != nil {
					return demo.Output{}, err
				}
			}
			return demo.Workflow(ctx, in)
		}
		for _, f := range histories {
			if err := replay(t, variant, f); err != nil {
				t.Errorf("replay of %s behind GetVersion: %v", f, err)
			}
		}
	})
}
