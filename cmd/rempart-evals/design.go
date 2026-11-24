package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"sync"
	"time"

	tlog "go.temporal.io/sdk/log"
	"go.temporal.io/sdk/testsuite"

	"github.com/amezianechayer/rempart/internal/design/confirm"
	"github.com/amezianechayer/rempart/internal/evals"
	"github.com/amezianechayer/rempart/internal/graph"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	intentdomain "github.com/amezianechayer/rempart/internal/intent/domain"
	"github.com/amezianechayer/rempart/internal/intent/irvalid"
	"github.com/amezianechayer/rempart/internal/llm/schema"
	"github.com/amezianechayer/rempart/internal/loops/l2"
	l2activities "github.com/amezianechayer/rempart/internal/loops/l2/activities"
	"github.com/amezianechayer/rempart/internal/policy"
	"github.com/amezianechayer/rempart/internal/policy/adapters/opa"
)

// Target design (M2-T07): the loop L2 in a fresh in-process test environment
// per run, through the codec of Rempart with the fake key wrapper, on the
// embedded design pack. Deterministic, no model: its identity is empty and its
// baseline is evals/design/baseline.json (ADR 0005, amended by M2-T07).

const (
	maxDesignInputBytes = 64 << 10
	maxUnconfirmed      = 16
	designTestTimeout   = 2 * time.Minute
	// designConfirmer declares the confirmation in place of the human who reads
	// the summary of the subject (ADR 0012 D3).
	designConfirmer = "rempart-evals"
)

var (
	errDesignInput = errors.New("rempart-evals: design input refused")
	// exposureTarget is the grammar of an exposure target named by a case.
	exposureTarget = regexp.MustCompile(`^(lb|wl|data|net):[a-z0-9][a-z0-9.-]{0,80}$`)
	// designPack is the embedded design pack, compiled once per process.
	designPack = sync.OnceValues(opa.NewDesign)
)

type designTarget struct {
	log    io.Writer
	policy policy.Evaluator // nil: the embedded design pack
}

func (designTarget) Identity() Identity { return Identity{} }

func (designTarget) Check(c evals.Case) error {
	_, err := designInputOf(c.Input)
	return err
}

// designInputOf: one JSON object of 64 KiB at most holding exactly one
// subject, ir or graph, valid and of the evaluation tenant, and an optional
// list unconfirmed of at most 16 distinct exposure targets of the subject. The
// target plays the human: it confirms every exposure of the subject but those.
// The error never quotes the input.
func designInputOf(raw json.RawMessage) (l2.Input, error) {
	if len(raw) > maxDesignInputBytes {
		return l2.Input{}, errDesignInput
	}
	v, err := schema.DecodeStrict(raw)
	obj, isObj := v.(map[string]any)
	if err != nil || !isObj {
		return l2.Input{}, errDesignInput
	}
	for k := range obj {
		if k != "ir" && k != "graph" && k != "unconfirmed" {
			return l2.Input{}, errDesignInput
		}
	}
	_, hasIR := obj["ir"]
	_, hasGraph := obj["graph"]
	u, hasUnconfirmed := obj["unconfirmed"]
	if hasIR == hasGraph || (hasUnconfirmed && u == nil) {
		return l2.Input{}, errDesignInput
	}
	var in struct {
		IR          *intentdomain.IR   `json:"ir"`
		Graph       *graphdomain.Graph `json:"graph"`
		Unconfirmed []string           `json:"unconfirmed"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&in) != nil {
		return l2.Input{}, errDesignInput
	}
	var d confirm.Digest
	switch {
	case in.IR != nil && in.IR.TenantID == string(demoTenant) && irvalid.ValidateIR(*in.IR) == nil:
		d, err = confirm.DigestOfIR(*in.IR)
	case in.Graph != nil && in.Graph.TenantID == string(demoTenant) && graph.ValidateSchema(*in.Graph) == nil &&
		graphdomain.Validate(*in.Graph) == nil:
		d, err = confirm.DigestOfGraph(*in.Graph)
	default:
		return l2.Input{}, errDesignInput
	}
	if err != nil || len(in.Unconfirmed) > maxUnconfirmed {
		return l2.Input{}, errDesignInput
	}
	exposed := map[string]bool{}
	for _, k := range d.Exposures {
		exposed[k.Target] = true
	}
	left := map[string]bool{}
	for _, t := range in.Unconfirmed {
		if !exposureTarget.MatchString(t) || !exposed[t] || left[t] {
			return l2.Input{}, errDesignInput
		}
		left[t] = true
	}
	keys := []confirm.ExposureKey{}
	for _, k := range d.Exposures {
		if !left[k.Target] {
			keys = append(keys, k)
		}
	}
	return l2.Input{IR: in.IR, Graph: in.Graph, Confirmation: confirm.Confirmation{
		Subject: d.Subject, SubjectSHA256: d.SubjectSHA256, Exposures: keys, ConfirmedBy: designConfirmer,
	}}, nil
}

func (t designTarget) Run(ctx context.Context, c evals.Case, _ int) (o evals.Outcome, err error) {
	in, err := designInputOf(c.Input)
	if err != nil {
		return evals.Outcome{}, err
	}
	pack := t.policy
	if pack == nil {
		e, err := designPack()
		if err != nil {
			return evals.Outcome{}, fmt.Errorf("rempart-evals: design pack: %w", err)
		}
		pack = e
	}
	defer func() {
		if recover() != nil {
			o, err = evals.Outcome{}, errors.New("rempart-evals: test environment panicked")
		}
	}()
	var suite testsuite.WorkflowTestSuite
	suite.SetLogger(tlog.NewStructuredLogger(slog.New(slog.NewTextHandler(t.log, &slog.HandlerOptions{Level: slog.LevelWarn}))))
	wenv := suite.NewTestWorkflowEnvironment()
	wenv.SetTestTimeout(designTestTimeout)
	if err := sealEnv(wenv); err != nil {
		return evals.Outcome{}, err
	}
	if err := l2.Register(wenv, &l2activities.Activities{Tenant: demoTenant, Policy: pack}); err != nil {
		return evals.Outcome{}, err
	}
	if err := ctx.Err(); err != nil {
		return evals.Outcome{}, err
	}
	start := time.Now()
	wenv.ExecuteWorkflow(l2.WorkflowName, in)
	o.Duration = time.Since(start)
	if !wenv.IsWorkflowCompleted() {
		return evals.Outcome{}, errors.New("rempart-evals: workflow not completed")
	}
	var out l2.Output
	if wenv.GetWorkflowError() != nil || wenv.GetWorkflowResult(&out) != nil {
		o.Err = "workflow_failed"
		return o, nil
	}
	if o.Output, err = json.Marshal(out); err != nil {
		return evals.Outcome{}, fmt.Errorf("rempart-evals: projection: %w", err)
	}
	o.SchemaValid = out.Graph != nil && graph.ValidateSchema(*out.Graph) == nil && graphdomain.Validate(*out.Graph) == nil
	o.Status, o.Escalated = out.Status, out.Status == l2.StatusEscalated
	o.Iterations, o.Tokens = out.Loop.Iterations, out.Loop.Tokens
	return o, nil
}
