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

	"github.com/amezianechayer/rempart/internal/llm"
	lldomain "github.com/amezianechayer/rempart/internal/llm/domain"
	llmfake "github.com/amezianechayer/rempart/internal/llm/fake"
	"github.com/amezianechayer/rempart/internal/loops"
	"github.com/amezianechayer/rempart/internal/loops/demo"
	"github.com/amezianechayer/rempart/internal/loops/demo/activities"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

var ErrTemporalUnavailable = errors.New("rempart-worker: Temporal unavailable")

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

func run(ctx context.Context, cfg Config, stdout io.Writer) error {
	if !cfg.Dev || cfg.LLMProvider != "fake" || !cfg.DemoOnce { // T41, even if LoadConfig is bypassed
		return ErrFakeRequiresDev
	}
	opts, err := clientOptions(cfg)
	if err != nil {
		return err
	}
	cl, err := fakeClient(cfg)
	if err != nil {
		return err
	}
	queue, err := loops.NewWorkflowID(demo.TaskQueue) // D7, T79
	if err != nil {
		return err
	}
	id, err := loops.NewWorkflowID(demo.IDPrefix)
	if err != nil {
		return err
	}
	tc, err := client.DialContext(ctx, opts)
	if err != nil {
		return ErrTemporalUnavailable // (bh): fixed message, the cause may quote the address
	}
	defer tc.Close()
	w := worker.New(tc, queue, worker.Options{})
	if err := demo.Register(w, &activities.Activities{LLM: cl, Tenant: cfg.Tenant}, denyAll{}); err != nil {
		return err
	}
	if err := w.Start(); err != nil {
		return err
	}
	defer w.Stop()
	in := demo.Input{Target: demoTarget, Author: demoAuthor, ApprovalTimeout: demoApprovalTimeout}
	timeout := demo.ExecutionTimeout(in.ApprovalTimeout)
	rctx, cancel := context.WithTimeout(ctx, timeout+runGrace)
	defer cancel()
	wr, err := tc.ExecuteWorkflow(rctx, client.StartWorkflowOptions{ID: id, TaskQueue: queue, WorkflowExecutionTimeout: timeout}, demo.WorkflowName, in)
	if err != nil {
		return err
	}
	var out demo.Output
	if err := wr.Get(rctx, &out); err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(demoResult{WorkflowID: id, Output: out})
}

// clientOptions checks the address again (bh, T14); opaque identity: no host name, no pid.
func clientOptions(cfg Config) (client.Options, error) {
	if !loopbackAddr(cfg.TemporalAddress) || !validNamespace(cfg.Namespace) {
		return client.Options{}, fmt.Errorf("%w: -temporal-address or -namespace", ErrConfig)
	}
	identity, err := loops.NewWorkflowID(workerIdentityPrefix)
	if err != nil {
		return client.Options{}, err
	}
	return client.Options{
		HostPort: cfg.TemporalAddress, Namespace: cfg.Namespace, Identity: identity,
		Logger: tlog.NewStructuredLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))),
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
	return llm.NewClient(prov, res, nil, llm.Config{MaxTokensPerCall: activities.MaxTokensPerCall, AllowFakeRoute: cfg.Dev})
}
