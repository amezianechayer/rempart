package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"

	"github.com/amezianechayer/rempart/internal/design/fsread"
	"github.com/amezianechayer/rempart/internal/loops/codec"
	"github.com/amezianechayer/rempart/internal/loops/l2"
	l2activities "github.com/amezianechayer/rempart/internal/loops/l2/activities"
	"github.com/amezianechayer/rempart/internal/policy/adapters/opa"
)

// ErrL2Input: the input file of -l2-input is unreadable, too large or not a
// strict L2 input. Fixed message: it never quotes the file.
var ErrL2Input = errors.New("rempart-worker: -l2-input unreadable, larger than 256 KiB or not a strict L2 input")

const maxL2InputBytes = 256 << 10

// l2Doc is the document written by the target l2-demo.
type l2Doc struct {
	WorkflowID string `json:"workflow_id"`
	l2.Output
}

func l2Document(id string, out l2.Output) l2Doc { return l2Doc{WorkflowID: id, Output: out} }

// readL2Input reads the input of -l2-input under the working directory
// (os.Root: no link out of it; fsread: regular file, no blocking on a pipe),
// 256 KiB at most, one JSON value without unknown key.
func readL2Input(name string) (l2.Input, error) {
	root, err := os.OpenRoot(".")
	if err != nil {
		return l2.Input{}, ErrL2Input
	}
	defer func() { _ = root.Close() }()
	raw, err := fsread.RegularIn(root, name, maxL2InputBytes)
	if err != nil {
		return l2.Input{}, ErrL2Input
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var in l2.Input
	if err := dec.Decode(&in); err != nil {
		return l2.Input{}, ErrL2Input
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return l2.Input{}, ErrL2Input
	}
	return in, nil
}

// runL2 compiles the design pack before any connection to Temporal (a pack
// refused stops the process, nothing registered), then runs one L2 workflow.
func runL2(ctx context.Context, cfg Config, opts client.Options, stdout io.Writer) error {
	e, err := opa.NewDesign() //nolint:contextcheck // compiled once at start, independent of the run (ADR 0011 D3)
	if err != nil {
		return err
	}
	in, err := readL2Input(cfg.L2Input)
	if err != nil {
		return err
	}
	register := func(w worker.Worker) error {
		return registerL2(w, opts, &l2activities.Activities{Tenant: cfg.Tenant, Policy: e})
	}
	var out l2.Output
	id, err := runOnce(ctx, cfg, opts, onceRun{
		queue: l2.TaskQueue, idPrefix: l2.IDPrefix, workflow: l2.WorkflowName, timeout: l2.ExecutionTimeout(),
		register: register, input: in, output: &out,
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(l2Document(id, out))
}

// registerL2 registers L2 only on a client whose options carry the converters
// of Rempart (§4.1 of the threat model): nothing in clear.
func registerL2(r l2.Registry, o client.Options, a *l2activities.Activities) error {
	if codec.Check(o.DataConverter, o.FailureConverter, o.ContextPropagators) != nil {
		return ErrConverterRequired
	}
	return l2.Register(r, a)
}
