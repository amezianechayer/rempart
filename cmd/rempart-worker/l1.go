package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"

	"github.com/amezianechayer/rempart/internal/design"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	intentdomain "github.com/amezianechayer/rempart/internal/intent/domain"
	"github.com/amezianechayer/rempart/internal/llm"
	"github.com/amezianechayer/rempart/internal/loops/codec"
	"github.com/amezianechayer/rempart/internal/loops/l1"
	l1activities "github.com/amezianechayer/rempart/internal/loops/l1/activities"
)

// ErrL1Request: the request file of -l1-request is unreadable or too large.
var ErrL1Request = errors.New("rempart-worker: -l1-request unreadable or larger than 8 KiB")

// demoContext is the tenant context of the demo tenant (M1); in M4 it comes
// from the configuration of the tenant, never from the request.
func demoContext() intentdomain.TenantContext {
	return intentdomain.TenantContext{AllowedRegions: []string{"eu-west-3", "francecentral"}, ForbiddenClouds: []string{}, Compliance: []string{}}
}

// l1Doc is the document written by the target l1-demo: the output of the
// workflow and, once converged, the graph of internal/design (C3).
type l1Doc struct {
	WorkflowID string `json:"workflow_id"`
	l1.Output
	Graph *graphdomain.Graph `json:"graph,omitempty"`
}

func l1Document(id string, out l1.Output) (l1Doc, error) {
	doc := l1Doc{WorkflowID: id, Output: out}
	if out.Status != l1.StatusConverged || out.IR == nil {
		return doc, nil
	}
	g, _, err := design.Build(*out.IR, design.Options{})
	if err != nil {
		return l1Doc{}, err
	}
	doc.Graph = &g
	return doc, nil
}

// readRequest reads the request of -l1-request under the working directory
// (os.Root: no link out of it), 8 KiB at most.
func readRequest(name string) (string, error) {
	root, err := os.OpenRoot(".")
	if err != nil {
		return "", ErrL1Request
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(name)
	if err != nil {
		return "", ErrL1Request
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, l1activities.MaxRequestBytes+1))
	if err != nil || len(b) > l1activities.MaxRequestBytes {
		return "", ErrL1Request
	}
	return string(b), nil
}

func runL1(ctx context.Context, cfg Config, opts client.Options, cl *llm.Client, stdout io.Writer) error {
	text, err := readRequest(cfg.L1Request)
	if err != nil {
		return err
	}
	register := func(w worker.Worker) error {
		return registerL1(w, opts, &l1activities.Activities{LLM: cl, Tenant: cfg.Tenant})
	}
	var out l1.Output
	id, err := runOnce(ctx, cfg, opts, onceRun{
		queue: l1.TaskQueue, idPrefix: l1.IDPrefix, workflow: l1.WorkflowName, timeout: l1.ExecutionTimeout(),
		register: register, input: l1.Input{RequestText: text, Context: demoContext(), Round: 1}, output: &out,
	})
	if err != nil {
		return err
	}
	doc, err := l1Document(id, out)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(doc)
}

// registerL1 registers L1 only on a client whose options carry the converters
// of Rempart (§4.1 of the threat model): nothing in clear.
func registerL1(r l1.Registry, o client.Options, a *l1activities.Activities) error {
	if codec.Check(o.DataConverter, o.FailureConverter, o.ContextPropagators) != nil {
		return ErrConverterRequired
	}
	return l1.Register(r, a)
}
