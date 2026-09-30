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

	tlog "go.temporal.io/sdk/log"
	"go.temporal.io/sdk/testsuite"

	"github.com/amezianechayer/rempart/internal/evals"
	"github.com/amezianechayer/rempart/internal/llm"
	lldomain "github.com/amezianechayer/rempart/internal/llm/domain"
	llmfake "github.com/amezianechayer/rempart/internal/llm/fake"
	"github.com/amezianechayer/rempart/internal/llm/prompts"
	"github.com/amezianechayer/rempart/internal/llm/schema"
	"github.com/amezianechayer/rempart/internal/loops"
	"github.com/amezianechayer/rempart/internal/loops/demo"
	"github.com/amezianechayer/rempart/internal/loops/demo/activities"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

type Identity struct{ Platform, Region, Model string }

// Target runs the cases of the suites whose suite.yaml names it.
type Target interface {
	Identity() Identity
	// Check refuses, before any run, an input the target cannot run (code 2).
	Check(c evals.Case) error
	// Run executes run number run of c. A behavior, even failed, is an Outcome;
	// an error is an execution failure (code 4).
	Run(ctx context.Context, c evals.Case, run int) (evals.Outcome, error)
}

func targets() map[string]Target { return map[string]Target{"demo": demoTarget{log: os.Stderr}} }

// Wiring of the demo target (D5), the constants of make demo.
const (
	demoTenant      tenancy.ID = "0d3e0000-0000-4000-8000-000000000001"
	demoModel                  = "fake-model-v1"
	demoAuthor                 = "demo-author"
	demoApproval               = 5 * time.Second
	demoTestTimeout            = 60 * time.Second
	maxReplies                 = 8
	maxReplyBytes              = 1024
)

var errDemoInput = errors.New("rempart-evals: demo input refused")

// denyAll refuses every approval, as cmd/rempart-worker does.
type denyAll struct{}

func (denyAll) VerifyApproval(context.Context, loops.Approval) (loops.ApprovalCheck, error) {
	return loops.ApprovalCheck{}, nil
}

// demoTarget runs rempart.demo.v1 in a fresh in-process test environment per run (D1).
type demoTarget struct{ log io.Writer }

func (demoTarget) Identity() Identity { return Identity{Platform: "fake", Model: demoModel} }

func (demoTarget) Check(c evals.Case) error {
	_, _, err := demoInput(c.Input)
	return err
}

// demoInput: D4, exactly target and replies, 1 to 8 objects of at most 1 KiB each.
func demoInput(raw json.RawMessage) (string, [][]byte, error) {
	v, err := schema.DecodeStrict(raw)
	obj, _ := v.(map[string]any)
	target, isStr := obj["target"].(string)
	list, isList := obj["replies"].([]any)
	if err != nil || len(obj) != 2 || !isStr || !activities.ValidTarget(target) || !isList || len(list) < 1 || len(list) > maxReplies {
		return "", nil, errDemoInput
	}
	replies := make([][]byte, 0, len(list))
	for _, r := range list {
		if _, isObj := r.(map[string]any); !isObj {
			return "", nil, errDemoInput
		}
		data, err := json.Marshal(r)
		if err != nil || len(data) > maxReplyBytes {
			return "", nil, errDemoInput
		}
		replies = append(replies, data)
	}
	return target, replies, nil
}

type demoProjection struct {
	Status     string          `json:"status"`
	Reason     string          `json:"reason"`
	Best       json.RawMessage `json:"best"`
	Iterations int             `json:"iterations"`
	Tokens     int             `json:"tokens"`
	Approval   string          `json:"approval"`
	Committed  bool            `json:"committed"`
}

func (t demoTarget) Run(ctx context.Context, c evals.Case, _ int) (o evals.Outcome, err error) {
	target, replies, err := demoInput(c.Input)
	if err != nil {
		return evals.Outcome{}, err
	}
	cl, err := demoClient(replies)
	if err != nil {
		return evals.Outcome{}, err
	}
	defer func() {
		if recover() != nil {
			o, err = evals.Outcome{}, errors.New("rempart-evals: test environment panicked")
		}
	}()
	var suite testsuite.WorkflowTestSuite
	suite.SetLogger(tlog.NewStructuredLogger(slog.New(slog.NewTextHandler(t.log, &slog.HandlerOptions{Level: slog.LevelWarn}))))
	wenv := suite.NewTestWorkflowEnvironment()
	wenv.SetTestTimeout(demoTestTimeout)
	if err := demo.Register(wenv, &activities.Activities{LLM: cl, Tenant: demoTenant}, denyAll{}); err != nil {
		return evals.Outcome{}, err
	}
	if err := ctx.Err(); err != nil {
		return evals.Outcome{}, err
	}
	start := time.Now()
	wenv.ExecuteWorkflow(demo.WorkflowName, demo.Input{Target: target, Author: demoAuthor, ApprovalTimeout: demoApproval})
	o.Duration = time.Since(start)
	if !wenv.IsWorkflowCompleted() {
		return evals.Outcome{}, errors.New("rempart-evals: workflow not completed")
	}
	var out demo.Output
	if wenv.GetWorkflowError() != nil || wenv.GetWorkflowResult(&out) != nil {
		o.Err = "workflow_failed"
		return o, nil
	}
	proj := demoProjection{
		Status: string(out.Loop.Status), Reason: string(out.Loop.Reason), Best: out.Loop.Best,
		Iterations: out.Loop.Iterations, Tokens: out.Loop.Tokens, Approval: string(out.Approval.Outcome), Committed: out.Committed,
	}
	if o.Output, err = json.Marshal(proj); err != nil {
		return evals.Outcome{}, fmt.Errorf("rempart-evals: projection: %w", err)
	}
	o.SchemaValid = schemaValid(out.Loop.Best)
	o.Status, o.Escalated = proj.Status, out.Loop.Status == loops.StatusEscalated
	o.Iterations, o.Tokens = out.Loop.Iterations, out.Loop.Tokens
	return o, nil
}

func schemaValid(best json.RawMessage) bool {
	p, err := prompts.Load(activities.PromptID)
	return len(best) > 0 && err == nil && p.Hash == activities.PromptHash && p.Schema.Validate(best) == nil
}

// demoClient: the fake provider scripted by the replies, route fake (D4, D5).
func demoClient(replies [][]byte) (*llm.Client, error) {
	steps := make([]llmfake.Step, 0, len(replies))
	for i, r := range replies {
		steps = append(steps, llmfake.Step{Response: lldomain.Response{
			Output: r, Model: demoModel, RequestID: fmt.Sprintf("req-eval-%d", i+1),
			Usage: lldomain.Usage{InputTokens: 10, OutputTokens: 5},
		}})
	}
	prov, err := llmfake.New(llmfake.Options{
		Scripts: map[string][]llmfake.Step{activities.PromptID: steps},
		Models:  map[string]lldomain.Capabilities{demoModel: {NativeStructuredOutput: true}},
	})
	if err != nil {
		return nil, err
	}
	res, err := llmfake.NewStaticResolver(map[tenancy.ID]lldomain.TenantPolicy{demoTenant: {
		Route:     lldomain.Route{Platform: lldomain.PlatformFake, Model: demoModel},
		Residency: lldomain.ResidencyEU, Retention: lldomain.RetentionZero,
	}})
	if err != nil {
		return nil, err
	}
	return llm.NewClient(prov, res, nil, llm.Config{MaxTokensPerCall: activities.MaxTokensPerCall, AllowFakeRoute: true})
}
