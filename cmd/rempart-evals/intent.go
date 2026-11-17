package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/converter"
	tlog "go.temporal.io/sdk/log"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/workflow"

	"github.com/amezianechayer/rempart/internal/evals"
	"github.com/amezianechayer/rempart/internal/intent"
	intentdomain "github.com/amezianechayer/rempart/internal/intent/domain"
	"github.com/amezianechayer/rempart/internal/llm"
	lldomain "github.com/amezianechayer/rempart/internal/llm/domain"
	llmfake "github.com/amezianechayer/rempart/internal/llm/fake"
	"github.com/amezianechayer/rempart/internal/llm/schema"
	"github.com/amezianechayer/rempart/internal/loops/codec"
	"github.com/amezianechayer/rempart/internal/loops/l1"
	l1activities "github.com/amezianechayer/rempart/internal/loops/l1/activities"
	"github.com/amezianechayer/rempart/internal/secrets/envelope"
	secretsfake "github.com/amezianechayer/rempart/internal/secrets/fake"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

// Target intent (M1-T06): the loop L1 in a fresh in-process test environment
// per run, through the codec of Rempart with the fake key wrapper (rule
// secrets-fake-dev-only); fake model scripted by the replies of the case, or
// the real model of the real mode (replies then ignored).

const (
	maxIntentReplies    = 8
	maxIntentReplyBytes = 16 << 10
	maxContextItems     = 16
	intentTestTimeout   = 10 * time.Minute
	contextBytes        = "abcdefghijklmnopqrstuvwxyz0123456789-_"
)

var errIntentInput = errors.New("rempart-evals: intent input refused")

type intentTarget struct {
	log  io.Writer
	real *realModel // nil: the fake provider scripted by the case
}

type intentInput struct {
	request string
	context intentdomain.TenantContext
	replies [][]byte
}

func (t intentTarget) Identity() Identity {
	if t.real != nil {
		return Identity{Platform: string(lldomain.PlatformOpenRouter), Model: t.real.model}
	}
	return Identity{Platform: "fake", Model: demoModel}
}

func (intentTarget) Check(c evals.Case) error {
	_, err := intentInputOf(c.Input)
	return err
}

// intentInputOf: exactly request (8 KiB at most), an optional context of the
// tenant and 1 to 8 replies, objects of at most 16 KiB each.
func intentInputOf(raw json.RawMessage) (intentInput, error) {
	v, err := schema.DecodeStrict(raw)
	obj, isObj := v.(map[string]any)
	if err != nil || !isObj {
		return intentInput{}, errIntentInput
	}
	for k := range obj {
		if k != "request" && k != "context" && k != "replies" {
			return intentInput{}, errIntentInput
		}
	}
	request, isStr := obj["request"].(string)
	list, isList := obj["replies"].([]any)
	if !isStr || strings.TrimSpace(request) == "" || len(request) > l1activities.MaxRequestBytes ||
		!isList || len(list) < 1 || len(list) > maxIntentReplies {
		return intentInput{}, errIntentInput
	}
	in := intentInput{request: request}
	for _, r := range list {
		data, err := json.Marshal(r)
		if _, isObj := r.(map[string]any); !isObj || err != nil || len(data) > maxIntentReplyBytes {
			return intentInput{}, errIntentInput
		}
		in.replies = append(in.replies, data)
	}
	if c, present := obj["context"]; present {
		data, err := json.Marshal(c)
		if err != nil {
			return intentInput{}, errIntentInput
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if dec.Decode(&in.context) != nil || !validContext(in.context) {
			return intentInput{}, errIntentInput
		}
	}
	return in, nil
}

func validContext(c intentdomain.TenantContext) bool {
	for _, l := range [][]string{c.AllowedRegions, c.ForbiddenClouds, c.Compliance} {
		if len(l) > maxContextItems {
			return false
		}
		for _, s := range l {
			if s == "" || len(s) > 64 || strings.Trim(s, contextBytes) != "" {
				return false
			}
		}
	}
	return true
}

// intentProjection is what the graders read: never a draft of the model.
type intentProjection struct {
	Status         string                       `json:"status"`
	Reason         string                       `json:"reason"`
	IR             *intentdomain.IR             `json:"ir,omitempty"`
	Contradictions []intentdomain.Contradiction `json:"contradictions"`
	Remaining      []string                     `json:"remaining"` // codes of the findings left at an escalation
	Iterations     int                          `json:"iterations"`
	Tokens         int                          `json:"tokens"`
}

func (t intentTarget) Run(ctx context.Context, c evals.Case, _ int) (o evals.Outcome, err error) {
	in, err := intentInputOf(c.Input)
	if err != nil {
		return evals.Outcome{}, err
	}
	var cl *llm.Client
	if t.real != nil {
		cl, err = t.real.client(l1activities.MaxTokensPerCall)
	} else {
		cl, err = intentClient(in.replies)
	}
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
	wenv.SetTestTimeout(intentTestTimeout)
	if err := sealEnv(wenv); err != nil {
		return evals.Outcome{}, err
	}
	if err := l1.Register(wenv, &l1activities.Activities{LLM: cl, Tenant: demoTenant}); err != nil {
		return evals.Outcome{}, err
	}
	if err := ctx.Err(); err != nil {
		return evals.Outcome{}, err
	}
	start := time.Now()
	wenv.ExecuteWorkflow(l1.WorkflowName, l1.Input{RequestText: in.request, Context: in.context, Round: 1})
	o.Duration = time.Since(start)
	if !wenv.IsWorkflowCompleted() {
		return evals.Outcome{}, errors.New("rempart-evals: workflow not completed")
	}
	var out l1.Output
	if wenv.GetWorkflowError() != nil || wenv.GetWorkflowResult(&out) != nil {
		o.Err = "workflow_failed"
		return o, nil
	}
	proj := intentProjection{
		Status: out.Status, Reason: out.Reason, IR: out.IR, Contradictions: out.Contradictions,
		Remaining: []string{}, Iterations: out.Loop.Iterations, Tokens: out.Loop.Tokens,
	}
	for _, f := range out.Loop.Remaining {
		proj.Remaining = append(proj.Remaining, f.Code)
	}
	if o.Output, err = json.Marshal(proj); err != nil {
		return evals.Outcome{}, fmt.Errorf("rempart-evals: projection: %w", err)
	}
	o.SchemaValid = out.IR != nil && intent.ValidateIR(*out.IR) == nil
	o.Status, o.Escalated = out.Status, out.Status == l1.StatusEscalated
	o.Iterations, o.Tokens = out.Loop.Iterations, out.Loop.Tokens
	if out.IR != nil {
		o.Invented = intentdomain.InventedValues(in.request, *out.IR, in.context)
	}
	return o, nil
}

// sealEnv puts the converters of Rempart for the evaluation tenant on the
// test environment, with the fake key wrapper (no key manager, no secret).
func sealEnv(wenv *testsuite.TestWorkflowEnvironment) error {
	s, err := envelope.NewSealer(secretsfake.NewKeyWrapper([32]byte{0x45, 0x56, 0x41, 0x4c}), envelope.Options{})
	if err != nil {
		return err
	}
	dc, err := codec.NewDataConverter(s, demoTenant)
	if err != nil {
		return err
	}
	fc, err := codec.NewFailureConverter(dc)
	if err != nil {
		return err
	}
	wenv.SetDataConverter(dc)
	wenv.SetFailureConverter(fc)
	wenv.SetContextPropagators([]workflow.ContextPropagator{codec.NewTenantPropagator()})
	wenv.SetHeader(&commonpb.Header{Fields: map[string]*commonpb.Payload{codec.TenantHeader: {
		Metadata: map[string][]byte{converter.MetadataEncoding: []byte(codec.EncodingTenant)},
		Data:     []byte(demoTenant),
	}}})
	return nil
}

// intentClient: the fake provider scripted by the replies, route fake.
func intentClient(replies [][]byte) (*llm.Client, error) {
	steps := make([]llmfake.Step, 0, len(replies))
	for i, r := range replies {
		steps = append(steps, llmfake.Step{Response: lldomain.Response{
			Output: r, Model: demoModel, RequestID: fmt.Sprintf("req-intent-%d", i+1),
			Usage: lldomain.Usage{InputTokens: 100, OutputTokens: 50},
		}})
	}
	prov, err := llmfake.New(llmfake.Options{
		Scripts: map[string][]llmfake.Step{l1activities.PromptID: steps},
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
	return llm.NewClient(prov, res, nil, llm.Config{MaxTokensPerCall: l1activities.MaxTokensPerCall, AllowFakeRoute: true})
}
