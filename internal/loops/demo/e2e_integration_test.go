//go:build integration

package demo_test

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"go.temporal.io/sdk/client"
	tlog "go.temporal.io/sdk/log"
	"go.temporal.io/sdk/worker"

	llmfake "github.com/amezianechayer/rempart/internal/llm/fake"
	"github.com/amezianechayer/rempart/internal/loops"
	"github.com/amezianechayer/rempart/internal/loops/demo"
	"github.com/amezianechayer/rempart/internal/loops/demo/activities"
	loopsfake "github.com/amezianechayer/rempart/internal/loops/fake"
)

// Integration tests against the Temporal server of make dev (loopback, no TLS,
// namespace rempart). They read no environment variable and are never
// skipped: an unreachable server fails them (D7 of M0-pile-dev).
const (
	devTemporal  = "127.0.0.1:7233"
	devNamespace = "rempart"
	// historyAllEvents is HISTORY_EVENT_FILTER_TYPE_ALL_EVENT of the Temporal API.
	historyAllEvents = 1
)

// refuseAll is a local approval verifier that refuses every signature.
type refuseAll struct{}

func (refuseAll) VerifyApproval(context.Context, loops.Approval) (loops.ApprovalCheck, error) {
	return loops.ApprovalCheck{}, nil
}

func dialDev(t *testing.T) client.Client {
	t.Helper()
	c, err := client.Dial(client.Options{
		HostPort: devTemporal, Namespace: devNamespace,
		Logger: tlog.NewStructuredLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
	})
	if err != nil {
		t.Fatalf("Temporal of make dev unreachable on %s: %v (run make dev)", devTemporal, err)
	}
	t.Cleanup(c.Close)
	return c
}

// e2eRun is one demo execution on the dev server, with an in-process worker
// on a task queue of its own.
type e2eRun struct {
	c     client.Client
	prov  *llmfake.Provider
	id    string
	runID string
	queue string
	took  time.Duration
}

func runOnDev(t *testing.T, v demo.ApprovalVerifier, in demo.Input, signal *loops.Approval) (*e2eRun, demo.Output) {
	t.Helper()
	c := dialDev(t)
	cl, prov := newClient(t, []llmfake.Step{answer(greetSalut), answer(greetBonjour)})
	queue, err := loops.NewWorkflowID("rempart-demo-it")
	if err != nil {
		t.Fatal(err)
	}
	id, err := loops.NewWorkflowID(demo.IDPrefix)
	if err != nil {
		t.Fatal(err)
	}
	w := worker.New(c, queue, worker.Options{})
	if err := demo.Register(w, &activities.Activities{LLM: cl, Tenant: tenantA}, v); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := w.Start(); err != nil {
		t.Fatalf("worker start: %v", err)
	}
	t.Cleanup(w.Stop)

	timeout := demo.ExecutionTimeout(in.ApprovalTimeout)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	wr, err := c.ExecuteWorkflow(ctx, client.StartWorkflowOptions{ID: id, TaskQueue: queue, WorkflowExecutionTimeout: timeout},
		demo.WorkflowName, in)
	if err != nil {
		t.Fatalf("ExecuteWorkflow: %v", err)
	}
	if signal != nil { // before the approval wait starts: buffered by the server (risk 4)
		if err := c.SignalWorkflow(ctx, id, wr.GetRunID(), loops.ApprovalSignal, *signal); err != nil {
			t.Fatalf("SignalWorkflow: %v", err)
		}
	}
	var out demo.Output
	if err := wr.Get(ctx, &out); err != nil {
		t.Fatalf("workflow failed: %v", err)
	}
	return &e2eRun{c: c, prov: prov, id: id, runID: wr.GetRunID(), queue: queue, took: time.Since(start)}, out
}

// history returns the scheduled activity names, the execution timeout of the
// started event and the text of every event.
func (r *e2eRun) history(t *testing.T) (scheduled []string, timeout time.Duration, text string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var b strings.Builder
	it := r.c.GetWorkflowHistory(ctx, r.id, r.runID, false, historyAllEvents)
	for it.HasNext() {
		ev, err := it.Next()
		if err != nil {
			t.Fatalf("history: %v", err)
		}
		if a := ev.GetActivityTaskScheduledEventAttributes(); a != nil {
			scheduled = append(scheduled, a.GetActivityType().GetName())
		}
		if s := ev.GetWorkflowExecutionStartedEventAttributes(); s != nil {
			timeout = s.GetWorkflowExecutionTimeout().AsDuration()
		}
		b.WriteString(ev.String())
		b.WriteByte('\n')
	}
	if b.Len() == 0 {
		t.Fatal("empty history")
	}
	return scheduled, timeout, b.String()
}

func count(names []string, name string) int {
	n := 0
	for _, s := range names {
		if s == name {
			n++
		}
	}
	return n
}

// TestDemoEndToEnd (M0 criterion 4): on the dev server, the demo converges in
// two iterations, nobody can approve (local verifier refusing all), the wait
// times out and nothing is committed; the history never schedules a commit,
// bounds the execution to 228 s and never carries the tenant (A1, T14).
func TestDemoEndToEnd(t *testing.T) {
	in := demo.Input{Target: target, Author: "alice", ApprovalTimeout: 5 * time.Second}
	r, out := runOnDev(t, refuseAll{}, in, nil)
	if out.Loop.Status != loops.StatusConverged || out.Loop.Iterations != 2 {
		t.Errorf("loop = %s, %d iterations; want converged, 2", out.Loop.Status, out.Loop.Iterations)
	}
	if string(out.Loop.Best) != string(greetBonjour) || out.PlanHash != expectedHash(greetBonjour) {
		t.Errorf("best %s, plan hash %q; want %s, %q", out.Loop.Best, out.PlanHash, greetBonjour, expectedHash(greetBonjour))
	}
	if out.Approval.Outcome != loops.OutcomeTimedOut || len(out.Approval.Approvals) != 0 || out.Committed {
		t.Errorf("approval %+v, committed %v; want timed_out, none, false", out.Approval, out.Committed)
	}
	if n := r.prov.Invocations(); n != 2 {
		t.Errorf("%d provider calls, want 2", n)
	}
	scheduled, timeout, text := r.history(t)
	if count(scheduled, demo.CommitActivity) != 0 {
		t.Errorf("history schedules %s: %q", demo.CommitActivity, scheduled)
	}
	if count(scheduled, demo.ProposeActivity) != 2 || count(scheduled, demo.VerifyActivity) != 2 {
		t.Errorf("scheduled activities %q, want 2 proposals and 2 verifications", scheduled)
	}
	if timeout != 228*time.Second {
		t.Errorf("execution timeout %v, want 228s", timeout)
	}
	if strings.Contains(text, string(tenantA)) {
		t.Errorf("history carries the tenant %s", tenantA)
	}
	if !strings.Contains(text, target) {
		t.Error("history text does not show the target: the tenant check would prove nothing")
	}
	if strings.Contains(r.id, string(tenantA)) || strings.Contains(r.queue, string(tenantA)) {
		t.Errorf("workflow id %q or task queue %q carries the tenant", r.id, r.queue)
	}
}

// TestDemoApprovedEndToEnd: on the dev server, with the fake verifier, a valid
// signature of bob sent right after the start (buffered before the wait)
// approves the plan: exactly one commit, well before the 30 s wait ends.
func TestDemoApprovedEndToEnd(t *testing.T) {
	in := demo.Input{Target: target, Author: "alice", ApprovalTimeout: 30 * time.Second}
	sig := signedBy("bob", expectedHash(greetBonjour))
	r, out := runOnDev(t, &loopsfake.ApprovalVerifier{}, in, &sig)
	if out.Loop.Status != loops.StatusConverged || out.Loop.Iterations != 2 {
		t.Errorf("loop = %s, %d iterations; want converged, 2", out.Loop.Status, out.Loop.Iterations)
	}
	if out.Approval.Outcome != loops.OutcomeApproved || len(out.Approval.Approvals) != 1 ||
		out.Approval.Approvals[0].Approver != "bob" || !out.Committed {
		t.Errorf("approval %+v, committed %v; want approved by bob, committed", out.Approval, out.Committed)
	}
	scheduled, timeout, _ := r.history(t)
	if count(scheduled, demo.CommitActivity) != 1 {
		t.Errorf("history schedules %s %d times, want 1: %q", demo.CommitActivity, count(scheduled, demo.CommitActivity), scheduled)
	}
	if timeout != demo.ExecutionTimeout(30*time.Second) {
		t.Errorf("execution timeout %v, want %v", timeout, demo.ExecutionTimeout(30*time.Second))
	}
	if r.took >= 30*time.Second {
		t.Errorf("run took %v: the buffered approval did not end the wait", r.took)
	}
}
