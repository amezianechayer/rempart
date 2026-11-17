package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"go.temporal.io/sdk/client"
	tlog "go.temporal.io/sdk/log"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"

	"github.com/amezianechayer/rempart/internal/llm"
	lldomain "github.com/amezianechayer/rempart/internal/llm/domain"
	llmfake "github.com/amezianechayer/rempart/internal/llm/fake"
	"github.com/amezianechayer/rempart/internal/loops"
	"github.com/amezianechayer/rempart/internal/loops/codec"
	"github.com/amezianechayer/rempart/internal/loops/demo"
	"github.com/amezianechayer/rempart/internal/loops/demo/activities"
	l1activities "github.com/amezianechayer/rempart/internal/loops/l1/activities"
	"github.com/amezianechayer/rempart/internal/secrets/envelope"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

var (
	ErrTemporalUnavailable = errors.New("rempart-worker: Temporal unavailable")
	ErrConverterRequired   = errors.New("rempart-worker: Temporal options without the Rempart converters")
)

const workerIdentityPrefix = "rempart-worker"

const (
	fakeModel           = "fake-model-v1"
	demoTarget          = "bonjour"
	demoAuthor          = "demo-author"
	demoApprovalTimeout = 5 * time.Second
	runGrace            = 30 * time.Second
)

// denyAll refuses every approval (D8): the demo always ends in timed_out.
type denyAll struct{}

func (denyAll) VerifyApproval(context.Context, loops.Approval) (loops.ApprovalCheck, error) {
	return loops.ApprovalCheck{}, nil
}

type demoResult struct {
	WorkflowID string `json:"workflow_id"`
	demo.Output
}

func run(ctx context.Context, cfg Config, s *envelope.Sealer, stdout io.Writer) error {
	if !cfg.Dev || cfg.LLMProvider != "fake" || cfg.DemoOnce == cfg.L1Once { // T41, even if LoadConfig is bypassed
		return ErrFakeRequiresDev
	}
	opts, err := clientOptions(cfg, s)
	if err != nil {
		return err
	}
	cl, err := fakeClient(cfg)
	if err != nil {
		return err
	}
	if cfg.L1Once {
		return runL1(ctx, cfg, opts, cl, stdout)
	}
	register := func(w worker.Worker) error {
		return registerDemo(w, opts, &activities.Activities{LLM: cl, Tenant: cfg.Tenant}, denyAll{})
	}
	in := demo.Input{Target: demoTarget, Author: demoAuthor, ApprovalTimeout: demoApprovalTimeout}
	var out demo.Output
	id, err := runOnce(ctx, cfg, opts, onceRun{
		queue: demo.TaskQueue, idPrefix: demo.IDPrefix, workflow: demo.WorkflowName,
		timeout: demo.ExecutionTimeout(in.ApprovalTimeout), register: register, input: in, output: &out,
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(demoResult{WorkflowID: id, Output: out})
}

// onceRun is one workflow run by runOnce.
type onceRun struct {
	queue, idPrefix, workflow string
	timeout                   time.Duration
	register                  func(worker.Worker) error
	input, output             any
}

// runOnce dials Temporal, starts a worker on a fresh queue (D7, T79), runs
// one workflow for the tenant of the process and decodes its result.
func runOnce(ctx context.Context, cfg Config, opts client.Options, r onceRun) (string, error) {
	queue, err := loops.NewWorkflowID(r.queue)
	if err != nil {
		return "", err
	}
	id, err := loops.NewWorkflowID(r.idPrefix)
	if err != nil {
		return "", err
	}
	tc, err := client.DialContext(ctx, opts)
	if err != nil {
		return "", ErrTemporalUnavailable // (bh): fixed message, the cause may quote the address
	}
	defer tc.Close()
	w := worker.New(tc, queue, worker.Options{})
	if err := r.register(w); err != nil {
		return "", err
	}
	if err := w.Start(); err != nil {
		return "", err
	}
	defer w.Stop()
	rctx, cancel := context.WithTimeout(ctx, r.timeout+runGrace)
	defer cancel()
	if rctx, err = tenancy.WithTenant(rctx, cfg.Tenant); err != nil { // header rempart-tenant (D5)
		return "", err
	}
	wr, err := tc.ExecuteWorkflow(rctx, client.StartWorkflowOptions{ID: id, TaskQueue: queue, WorkflowExecutionTimeout: r.timeout}, r.workflow, r.input)
	if err != nil {
		return "", err
	}
	return id, wr.Get(rctx, r.output)
}

// clientOptions checks the address again (bh, T14); opaque identity: no host
// name, no pid; payloads sealed under the tenant of the process (ADR 0009).
func clientOptions(cfg Config, s *envelope.Sealer) (client.Options, error) {
	if !loopbackAddr(cfg.TemporalAddress) || !validNamespace(cfg.Namespace) {
		return client.Options{}, fmt.Errorf("%w: -temporal-address or -namespace", ErrConfig)
	}
	identity, err := loops.NewWorkflowID(workerIdentityPrefix)
	if err != nil {
		return client.Options{}, err
	}
	dc, err := codec.NewDataConverter(s, cfg.Tenant)
	if err != nil {
		return client.Options{}, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	fc, err := codec.NewFailureConverter(dc)
	if err != nil {
		return client.Options{}, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	return client.Options{
		HostPort: cfg.TemporalAddress, Namespace: cfg.Namespace, Identity: identity,
		DataConverter: dc, FailureConverter: fc,
		ContextPropagators: []workflow.ContextPropagator{codec.NewTenantPropagator()},
		Logger:             tlog.NewStructuredLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))),
	}, nil
}

func fakeClient(cfg Config) (*llm.Client, error) {
	root, err := os.OpenRoot(".")
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	opt, err := llmfake.LoadOptions(root.FS(), cfg.FakeScript)
	if err != nil {
		return nil, err
	}
	prov, err := llmfake.New(opt)
	if err != nil {
		return nil, err
	}
	res, err := llmfake.NewStaticResolver(map[tenancy.ID]lldomain.TenantPolicy{cfg.Tenant: {
		Route:     lldomain.Route{Platform: lldomain.PlatformFake, Model: fakeModel},
		Residency: lldomain.ResidencyEU, Retention: lldomain.RetentionZero,
	}})
	if err != nil {
		return nil, err
	}
	tokens := activities.MaxTokensPerCall
	if cfg.L1Once {
		tokens = l1activities.MaxTokensPerCall
	}
	return llm.NewClient(prov, res, nil, llm.Config{MaxTokensPerCall: tokens, AllowFakeRoute: cfg.Dev})
}

// registerDemo registers the demo only on a client whose options carry the
// converters of Rempart (§4.1 of the threat model): nothing in clear.
func registerDemo(r demo.Registry, o client.Options, a *activities.Activities, v demo.ApprovalVerifier) error {
	if codec.Check(o.DataConverter, o.FailureConverter, o.ContextPropagators) != nil {
		return ErrConverterRequired
	}
	return demo.Register(r, a, v)
}
