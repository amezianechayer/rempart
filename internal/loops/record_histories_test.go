//go:build recordhistories

package loops_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	historypb "go.temporal.io/api/history/v1"
	"go.temporal.io/sdk/client"
	tlog "go.temporal.io/sdk/log"
	"go.temporal.io/sdk/worker"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/amezianechayer/rempart/internal/llm"
	lldomain "github.com/amezianechayer/rempart/internal/llm/domain"
	llmfake "github.com/amezianechayer/rempart/internal/llm/fake"
	"github.com/amezianechayer/rempart/internal/loops"
	"github.com/amezianechayer/rempart/internal/loops/demo"
	"github.com/amezianechayer/rempart/internal/loops/demo/activities"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

// TestRecordHistories (D10 of M1-codec-replay) records the reference
// histories of TestReplay against the Temporal server of make dev, with the
// converters of Rempart on the replay key: run 1 (the loop converges, then
// continues as new) and run 2 (the approval wait times out). Never run by
// make verify: go test -count=1 -tags=recordhistories -run TestRecordHistories ./internal/loops/
func TestRecordHistories(t *testing.T) {
	dc, fc, ps := replayConverters(t)
	c, err := client.Dial(client.Options{
		HostPort: "127.0.0.1:7233", Namespace: "rempart", Identity: "rempart-record-histories",
		DataConverter: dc, FailureConverter: fc, ContextPropagators: ps,
		Logger: tlog.NewStructuredLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
	})
	if err != nil {
		t.Fatalf("Temporal of make dev unreachable: %v (run make dev)", err)
	}
	defer c.Close()

	const model = "fake-model-v1"
	step := func(s string) llmfake.Step {
		return llmfake.Step{Response: lldomain.Response{Output: json.RawMessage(s), Model: model, Usage: lldomain.Usage{InputTokens: 10, OutputTokens: 5}}}
	}
	prov, err := llmfake.New(llmfake.Options{
		Models:  map[string]lldomain.Capabilities{model: {NativeStructuredOutput: true}},
		Scripts: map[string][]llmfake.Step{activities.PromptID: {step(`{"greeting":"salut"}`), step(`{"greeting":"bonjour"}`)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := llmfake.NewStaticResolver(map[tenancy.ID]lldomain.TenantPolicy{replayTenant: {
		Route: lldomain.Route{Platform: lldomain.PlatformFake, Model: model}, Residency: lldomain.ResidencyEU, Retention: lldomain.RetentionZero,
	}})
	if err != nil {
		t.Fatal(err)
	}
	cl, err := llm.NewClient(prov, res, nil, llm.Config{MaxTokensPerCall: activities.MaxTokensPerCall, AllowFakeRoute: true})
	if err != nil {
		t.Fatal(err)
	}
	queue, err := loops.NewWorkflowID("rempart-record")
	if err != nil {
		t.Fatal(err)
	}
	w := worker.New(c, queue, worker.Options{Identity: "rempart-record-histories"})
	if err := demo.Register(w, &activities.Activities{LLM: cl, Tenant: replayTenant}, refuseAllApprovals{}); err != nil {
		t.Fatal(err)
	}
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	in := demo.Input{Target: "bonjour", Author: "alice", ApprovalTimeout: demo.MinApprovalTimeout}
	timeout := demo.ExecutionTimeout(in.ApprovalTimeout)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if ctx, err = tenancy.WithTenant(ctx, replayTenant); err != nil {
		t.Fatal(err)
	}
	id, err := loops.NewWorkflowID(demo.IDPrefix)
	if err != nil {
		t.Fatal(err)
	}
	wr, err := c.ExecuteWorkflow(ctx, client.StartWorkflowOptions{ID: id, TaskQueue: queue, WorkflowExecutionTimeout: timeout}, demo.WorkflowName, in)
	if err != nil {
		t.Fatal(err)
	}
	run1 := wr.GetRunID() // Get follows the continuation and moves GetRunID to the last run
	var out demo.Output
	if err := wr.Get(ctx, &out); err != nil {
		t.Fatal(err)
	}
	if out.Loop.Status != loops.StatusConverged || out.Loop.Iterations != 2 || out.Approval.Outcome != loops.OutcomeTimedOut {
		t.Fatalf("output %+v, want converged in 2 iterations, timed_out", out)
	}
	d, err := c.DescribeWorkflowExecution(ctx, id, "")
	if err != nil {
		t.Fatal(err)
	}
	run2 := d.GetWorkflowExecutionInfo().GetExecution().GetRunId()
	if run2 == run1 {
		t.Fatal("no continuation recorded")
	}
	for name, run := range map[string]string{"demo-run1.json": run1, "demo-run2.json": run2} {
		var h historypb.History
		it := c.GetWorkflowHistory(ctx, id, run, false, 1) // HISTORY_EVENT_FILTER_TYPE_ALL_EVENT
		for it.HasNext() {
			ev, err := it.Next()
			if err != nil {
				t.Fatal(err)
			}
			h.Events = append(h.Events, ev)
		}
		b, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(&h)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join("testdata", "histories", name), append(b, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

type refuseAllApprovals struct{}

func (refuseAllApprovals) VerifyApproval(context.Context, loops.Approval) (loops.ApprovalCheck, error) {
	return loops.ApprovalCheck{}, nil
}
