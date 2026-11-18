//go:build integration

package codec_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	commonpb "go.temporal.io/api/common/v1"
	historypb "go.temporal.io/api/history/v1"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
	tlog "go.temporal.io/sdk/log"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/amezianechayer/rempart/internal/llm"
	lldomain "github.com/amezianechayer/rempart/internal/llm/domain"
	llmfake "github.com/amezianechayer/rempart/internal/llm/fake"
	"github.com/amezianechayer/rempart/internal/loops"
	"github.com/amezianechayer/rempart/internal/loops/codec"
	"github.com/amezianechayer/rempart/internal/loops/demo"
	demoactivities "github.com/amezianechayer/rempart/internal/loops/demo/activities"
	"github.com/amezianechayer/rempart/internal/loops/l1"
	l1activities "github.com/amezianechayer/rempart/internal/loops/l1/activities"
	"github.com/amezianechayer/rempart/internal/secrets/envelope"
	secretsfake "github.com/amezianechayer/rempart/internal/secrets/fake"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

// TestHistoryHasNoPlaintext (ADR 0001, table "Vérifié dès M0", line 3;
// prompts/M1.md, guard of D0; §4.1 of the threat model): on the Temporal
// server of make dev, with the converters of Rempart, a canary written in a
// workflow input, an activity result, a signal and an error message never
// shows in the raw protobuf serialization of the history (fetched without
// codec), while the history decoded with the codec holds it (the test is not
// empty). Subtests: a canary workflow for the four channels, the demo, L1.

const (
	histTemporal  = "127.0.0.1:7233"
	histNamespace = "rempart"
	histAllEvents = 1 // HISTORY_EVENT_FILTER_TYPE_ALL_EVENT
	histTenant    = tenancy.ID("0f8fad5b-d9cb-469f-a165-70867728950e")
	histModel     = "fake-model-v1"

	canaryWorkflowName = "rempart.test.canary.v1"
	canaryEcho         = "canary.echo"
	canaryFail         = "canary.fail"
	canarySignal       = "canary.signal"
)

func newCanary(t *testing.T, channel string) string {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return "canary-" + channel + "-" + hex.EncodeToString(b[:])
}

// sealedOptions are client options with the converters of Rempart for the
// tenant of the test, over an in-process key wrapper.
func sealedOptions(t *testing.T) (client.Options, converter.DataConverter) {
	t.Helper()
	s, err := envelope.NewSealer(secretsfake.NewKeyWrapper([32]byte{0x48, 0x31}), envelope.Options{})
	if err != nil {
		t.Fatal(err)
	}
	dc, err := codec.NewDataConverter(s, histTenant)
	if err != nil {
		t.Fatal(err)
	}
	fc, err := codec.NewFailureConverter(dc)
	if err != nil {
		t.Fatal(err)
	}
	return client.Options{
		HostPort: histTemporal, Namespace: histNamespace,
		DataConverter: dc, FailureConverter: fc,
		ContextPropagators: []workflow.ContextPropagator{codec.NewTenantPropagator()},
		Logger:             tlog.NewStructuredLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
	}, dc
}

func dialHist(t *testing.T, o client.Options) client.Client {
	t.Helper()
	c, err := client.Dial(o)
	if err != nil {
		t.Fatalf("Temporal of make dev unreachable on %s: %v (run make dev)", histTemporal, err)
	}
	t.Cleanup(c.Close)
	return c
}

// startWorker starts a worker on a queue of its own, registered by reg.
func startWorker(t *testing.T, c client.Client, reg func(worker.Worker)) string {
	t.Helper()
	queue, err := loops.NewWorkflowID("rempart-hist-it")
	if err != nil {
		t.Fatal(err)
	}
	w := worker.New(c, queue, worker.Options{})
	reg(w)
	if err := w.Start(); err != nil {
		t.Fatalf("worker start: %v", err)
	}
	t.Cleanup(w.Stop)
	return queue
}

func histCtx(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	ctx, err := tenancy.WithTenant(ctx, histTenant)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func fakeLLM(t *testing.T, tokens int, steps ...json.RawMessage) *llm.Client {
	t.Helper()
	opt := llmfake.Options{Models: map[string]lldomain.Capabilities{histModel: {NativeStructuredOutput: true}}}
	script := make([]llmfake.Step, 0, len(steps))
	for _, s := range steps {
		script = append(script, llmfake.Step{Response: lldomain.Response{Output: s, Model: histModel, Usage: lldomain.Usage{InputTokens: 100, OutputTokens: 50}}})
	}
	if len(script) > 0 {
		opt.Scripts = map[string][]llmfake.Step{demoactivities.PromptID: script, l1activities.PromptID: script}
	}
	prov, err := llmfake.New(opt)
	if err != nil {
		t.Fatal(err)
	}
	res, err := llmfake.NewStaticResolver(map[tenancy.ID]lldomain.TenantPolicy{histTenant: {
		Route: lldomain.Route{Platform: lldomain.PlatformFake, Model: histModel}, Residency: lldomain.ResidencyEU, Retention: lldomain.RetentionZero,
	}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := llm.NewClient(prov, res, nil, llm.Config{MaxTokensPerCall: tokens, AllowFakeRoute: true})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// canaryWorkflow carries a canary through the four channels of the ADR: its
// input, the result of an activity, a signal and the message of an activity
// error; its own result joins them.
func canaryWorkflow(ctx workflow.Context, in string) (string, error) {
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 10 * time.Second,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 1},
	})
	var echoed string
	if err := workflow.ExecuteActivity(ctx, canaryEcho, in).Get(ctx, &echoed); err != nil {
		return "", err
	}
	var sig string
	workflow.GetSignalChannel(ctx, canarySignal).Receive(ctx, &sig)
	err := workflow.ExecuteActivity(ctx, canaryFail, sig).Get(ctx, nil)
	if err == nil {
		return "", errors.New("the failing activity succeeded")
	}
	return echoed + " " + sig, nil
}

// historyOf fetches the history of the run first and of its continuation, if
// any, with a client without codec: the raw events as the server stores them.
func historyOf(t *testing.T, id, first string) [][]byte {
	t.Helper()
	plain := dialHist(t, client.Options{
		HostPort: histTemporal, Namespace: histNamespace,
		Logger: tlog.NewStructuredLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runs := []string{first}
	d, err := plain.DescribeWorkflowExecution(ctx, id, "")
	if err != nil {
		t.Fatalf("DescribeWorkflowExecution: %v", err)
	}
	if last := d.GetWorkflowExecutionInfo().GetExecution().GetRunId(); last != first {
		runs = append(runs, last)
	}
	var out [][]byte
	for _, run := range runs {
		it := plain.GetWorkflowHistory(ctx, id, run, false, histAllEvents)
		for it.HasNext() {
			ev, err := it.Next()
			if err != nil {
				t.Fatalf("history: %v", err)
			}
			raw, err := proto.Marshal(ev)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, raw)
		}
	}
	if len(out) == 0 {
		t.Fatal("empty history")
	}
	return out
}

// payloadsOf returns every payload of the raw history of a run.
func payloadsOf(t *testing.T, events [][]byte) []*commonpb.Payload {
	t.Helper()
	var all []*commonpb.Payload
	for _, raw := range events {
		var ev historypb.HistoryEvent
		if err := proto.Unmarshal(raw, &ev); err != nil {
			t.Fatal(err)
		}
		collectPayloads(ev.ProtoReflect(), &all)
	}
	return all
}

// refuseAll is an approval verifier that refuses every signature.
type refuseAll struct{}

func (refuseAll) VerifyApproval(context.Context, loops.Approval) (loops.ApprovalCheck, error) {
	return loops.ApprovalCheck{}, nil
}

func activityOptions(name string) activity.RegisterOptions {
	return activity.RegisterOptions{Name: name}
}

func intentFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := fs.ReadFile(os.DirFS(filepath.Join("..", "..", "intent", "testdata")), name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func referenceRequest(t *testing.T) string { return string(intentFixture(t, "reference-request.txt")) }

// referenceDraftWithSummary is the reference draft, compact, with summary.
func referenceDraftWithSummary(t *testing.T, summary string) json.RawMessage {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(intentFixture(t, "reference-draft.json"), &m); err != nil {
		t.Fatal(err)
	}
	m["summary"] = summary
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// collectPayloads walks a message and gathers every commonpb.Payload.
func collectPayloads(m protoreflect.Message, out *[]*commonpb.Payload) {
	if p, ok := m.Interface().(*commonpb.Payload); ok {
		*out = append(*out, p)
		return
	}
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsMap():
			if fd.MapValue().Message() != nil {
				v.Map().Range(func(_ protoreflect.MapKey, mv protoreflect.Value) bool {
					collectPayloads(mv.Message(), out)
					return true
				})
			}
		case fd.IsList():
			if fd.Message() != nil {
				l := v.List()
				for i := range l.Len() {
					collectPayloads(l.Get(i).Message(), out)
				}
			}
		case fd.Message() != nil:
			collectPayloads(v.Message(), out)
		}
		return true
	})
}

// assertSealed: no canary in the raw events; every payload sealed but the
// tenant header; opened with the codec, the payloads hold every canary.
func assertSealed(t *testing.T, events [][]byte, dc converter.DataConverter, canaries ...string) {
	t.Helper()
	for _, raw := range events {
		for _, c := range canaries {
			if bytes.Contains(raw, []byte(c)) {
				t.Errorf("raw history event carries the canary %q in clear", c)
			}
		}
	}
	var opened strings.Builder
	sealed := 0
	for _, p := range payloadsOf(t, events) {
		switch enc := string(p.GetMetadata()[converter.MetadataEncoding]); enc {
		case codec.EncodingEnvelope:
			var inner converter.RawValue
			if err := dc.FromPayload(p, &inner); err != nil {
				t.Errorf("sealed payload does not open with the codec: %v", err)
				continue
			}
			sealed++
			opened.Write(inner.Payload().GetData())
			opened.WriteByte('\n')
		case codec.EncodingTenant:
		default:
			t.Errorf("payload in clear in the history, encoding %q", enc)
		}
	}
	if sealed == 0 {
		t.Fatal("history holds no sealed payload: the plaintext check would prove nothing")
	}
	for _, c := range canaries {
		if !strings.Contains(opened.String(), c) {
			t.Errorf("canary %q absent from the history opened with the codec: the test would prove nothing", c)
		}
	}
}

func TestHistoryHasNoPlaintext(t *testing.T) {
	t.Run("canary_workflow", func(t *testing.T) {
		o, dc := sealedOptions(t)
		c := dialHist(t, o)
		in, sig, errCanary := newCanary(t, "input"), newCanary(t, "signal"), newCanary(t, "error")
		result := in + "-result"
		queue := startWorker(t, c, func(w worker.Worker) {
			w.RegisterWorkflowWithOptions(canaryWorkflow, workflow.RegisterOptions{Name: canaryWorkflowName})
			w.RegisterActivityWithOptions(func(_ context.Context, s string) (string, error) { return s + "-result", nil },
				activityOptions(canaryEcho))
			w.RegisterActivityWithOptions(func(_ context.Context, s string) error {
				return temporal.NewNonRetryableApplicationError("refused: "+s+" "+errCanary, "Canary", nil)
			}, activityOptions(canaryFail))
		})
		id, err := loops.NewWorkflowID("rempart-hist-canary")
		if err != nil {
			t.Fatal(err)
		}
		ctx := histCtx(t, time.Minute)
		wr, err := c.ExecuteWorkflow(ctx, client.StartWorkflowOptions{ID: id, TaskQueue: queue, WorkflowExecutionTimeout: time.Minute},
			canaryWorkflowName, in)
		if err != nil {
			t.Fatalf("ExecuteWorkflow: %v", err)
		}
		if err := c.SignalWorkflow(ctx, id, wr.GetRunID(), canarySignal, sig); err != nil {
			t.Fatalf("SignalWorkflow: %v", err)
		}
		first := wr.GetRunID()
		var out string
		if err := wr.Get(ctx, &out); err != nil {
			t.Fatalf("workflow: %v", err)
		}
		if out != result+" "+sig {
			t.Fatalf("result %q", out)
		}
		assertSealed(t, historyOf(t, id, first), dc, in, result, sig, errCanary)
	})

	t.Run("demo", func(t *testing.T) {
		o, dc := sealedOptions(t)
		c := dialHist(t, o)
		author, approver := newCanary(t, "author"), newCanary(t, "approver")
		cl := fakeLLM(t, demoactivities.MaxTokensPerCall, json.RawMessage(`{"greeting":"salut"}`), json.RawMessage(`{"greeting":"bonjour"}`))
		queue := startWorker(t, c, func(w worker.Worker) {
			if err := demo.Register(w, &demoactivities.Activities{LLM: cl, Tenant: histTenant}, refuseAll{}); err != nil {
				t.Fatalf("demo.Register: %v", err)
			}
		})
		id, err := loops.NewWorkflowID(demo.IDPrefix)
		if err != nil {
			t.Fatal(err)
		}
		in := demo.Input{Target: "bonjour", Author: author, ApprovalTimeout: 5 * time.Second}
		timeout := demo.ExecutionTimeout(in.ApprovalTimeout)
		ctx := histCtx(t, timeout)
		wr, err := c.ExecuteWorkflow(ctx, client.StartWorkflowOptions{ID: id, TaskQueue: queue, WorkflowExecutionTimeout: timeout}, demo.WorkflowName, in)
		if err != nil {
			t.Fatalf("ExecuteWorkflow: %v", err)
		}
		sig := loops.Approval{Approved: true, PlanHash: "0", Approver: approver, Signature: "x"}
		if err := c.SignalWorkflow(ctx, id, wr.GetRunID(), loops.ApprovalSignal, sig); err != nil {
			t.Fatalf("SignalWorkflow: %v", err)
		}
		first := wr.GetRunID()
		var out demo.Output
		if err := wr.Get(ctx, &out); err != nil {
			t.Fatalf("workflow: %v", err)
		}
		assertSealed(t, historyOf(t, id, first), dc, author, approver, "bonjour")
	})

	t.Run("l1", func(t *testing.T) {
		o, dc := sealedOptions(t)
		c := dialHist(t, o)
		note := newCanary(t, "request")
		summary := newCanary(t, "summary")
		draft := referenceDraftWithSummary(t, "Cluster et VM, note "+summary)
		cl := fakeLLM(t, l1activities.MaxTokensPerCall, draft)
		queue := startWorker(t, c, func(w worker.Worker) {
			if err := l1.Register(w, &l1activities.Activities{LLM: cl, Tenant: histTenant}); err != nil {
				t.Fatalf("l1.Register: %v", err)
			}
		})
		id, err := loops.NewWorkflowID(l1.IDPrefix)
		if err != nil {
			t.Fatal(err)
		}
		in := l1.Input{RequestText: referenceRequest(t) + " Référence interne du projet : " + note + ".", Round: 1}
		in.Context.AllowedRegions = []string{"eu-west-3", "francecentral"}
		ctx := histCtx(t, l1.ExecutionTimeout())
		wr, err := c.ExecuteWorkflow(ctx, client.StartWorkflowOptions{ID: id, TaskQueue: queue, WorkflowExecutionTimeout: l1.ExecutionTimeout()},
			l1.WorkflowName, in)
		if err != nil {
			t.Fatalf("ExecuteWorkflow: %v", err)
		}
		first := wr.GetRunID()
		var out l1.Output
		if err := wr.Get(ctx, &out); err != nil {
			t.Fatalf("workflow: %v", err)
		}
		if out.Status != l1.StatusConverged || out.IR == nil || !strings.Contains(out.IR.Summary, summary) {
			t.Fatalf("status %s, remaining %+v; want converged with the summary of the draft", out.Status, out.Loop.Remaining)
		}
		assertSealed(t, historyOf(t, id, first), dc, note, summary)
	})
}
