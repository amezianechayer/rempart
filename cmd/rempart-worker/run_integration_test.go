//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"go.temporal.io/sdk/client"
	tlog "go.temporal.io/sdk/log"
)

var (
	demoWorkflowIDRe = regexp.MustCompile(`^l0-demo-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	demoQueueRe      = regexp.MustCompile(`^rempart-demo-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// captureStdout runs f with os.Stdout redirected and returns what was written
// there: the SDK or a logger must never write on the process stdout.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	done := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(r)
		done <- b
	}()
	defer func() { os.Stdout = saved }()
	f()
	os.Stdout = saved
	_ = w.Close()
	return string(<-done)
}

// TestRunDemoOnceEndToEnd (M0 criterion 4, risks 2 and 4): run with the
// configuration of make demo, against the dev server, from the repository
// root. TEMPORAL_* variables pointing elsewhere are ignored (D1). Output: one
// JSON document, converged, timed_out, not committed, opaque workflow id; the
// execution runs on a task queue of its own (D7, T79), bounded to 228 s (c),
// and its history never carries the tenant.
func TestRunDemoOnceEndToEnd(t *testing.T) {
	t.Chdir("../..")
	t.Setenv("TEMPORAL_ADDRESS", "10.255.255.1:1")
	t.Setenv("TEMPORAL_NAMESPACE", "absent-namespace")
	cfg, err := LoadConfig(demoArgs())
	if err != nil {
		t.Fatalf("LoadConfig(make demo): %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var out bytes.Buffer
	var runErr error
	leaked := captureStdout(t, func() { runErr = run(ctx, cfg, &out) })
	if runErr != nil {
		t.Fatalf("run: %v", runErr)
	}
	if leaked != "" {
		t.Errorf("process stdout received %q, want nothing (only the writer given to run)", leaked)
	}

	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	var doc struct {
		WorkflowID string `json:"workflow_id"`
		Loop       struct {
			Status     string `json:"status"`
			Iterations int    `json:"iterations"`
		} `json:"loop"`
		Approval struct {
			Outcome string `json:"outcome"`
		} `json:"approval"`
		Committed *bool `json:"committed"`
	}
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("stdout %q is not a JSON document: %v", out.String(), err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		t.Errorf("stdout %q holds more than one JSON document", out.String())
	}
	if strings.Count(out.String(), "\n") != 1 || !strings.HasSuffix(out.String(), "\n") {
		t.Errorf("stdout %q, want exactly one line", out.String())
	}
	if doc.Loop.Status != "converged" || doc.Loop.Iterations != 2 || doc.Approval.Outcome != "timed_out" ||
		doc.Committed == nil || *doc.Committed {
		t.Errorf("result %+v, want converged in 2 iterations, timed_out, committed false", doc)
	}
	if !demoWorkflowIDRe.MatchString(doc.WorkflowID) {
		t.Fatalf("workflow_id %q is not l0-demo-<uuid v4>", doc.WorkflowID)
	}

	c, err := client.Dial(client.Options{
		HostPort: demoAddress, Namespace: demoNS,
		Logger: tlog.NewStructuredLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
	})
	if err != nil {
		t.Fatalf("Temporal of make dev unreachable: %v", err)
	}
	defer c.Close()
	desc, err := c.DescribeWorkflowExecution(ctx, doc.WorkflowID, "")
	if err != nil {
		t.Fatalf("DescribeWorkflowExecution: %v", err)
	}
	ec := desc.GetExecutionConfig()
	if q := ec.GetTaskQueue().GetName(); !demoQueueRe.MatchString(q) {
		t.Errorf("task queue %q, want rempart-demo-<uuid v4> (one queue per process, T79)", q)
	}
	if d := ec.GetWorkflowExecutionTimeout().AsDuration(); d != 228*time.Second {
		t.Errorf("execution timeout %v, want 228s", d)
	}
	var b strings.Builder
	it := c.GetWorkflowHistory(ctx, doc.WorkflowID, "", false, 1) // HISTORY_EVENT_FILTER_TYPE_ALL_EVENT
	for it.HasNext() {
		ev, err := it.Next()
		if err != nil {
			t.Fatalf("history: %v", err)
		}
		b.WriteString(ev.String())
	}
	if !strings.Contains(b.String(), "bonjour") {
		t.Fatal("history text does not show the target: the tenant check would prove nothing")
	}
	if strings.Contains(b.String(), demoTenant) {
		t.Errorf("history carries the tenant %s", demoTenant)
	}
}
