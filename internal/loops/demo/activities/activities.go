// Package activities: demo activities; never imports the SDK workflow package (rule l).
package activities

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"go.temporal.io/sdk/temporal"

	"github.com/amezianechayer/rempart/internal/llm"
	lldomain "github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/llm/prompts"
	"github.com/amezianechayer/rempart/internal/llm/schema"
	"github.com/amezianechayer/rempart/internal/loops"
	"github.com/amezianechayer/rempart/internal/loops/domain"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

const (
	PromptID             = "demo.greeting.v1"
	PromptHash           = "507f3f39ffc2182933e9568f6c1f230298babff72bc42026f4c3fd77b57c25cd"
	StrategyDirect       = "direct"
	StrategyReformulate  = "reformulate"
	MaxTargetBytes       = 64
	TargetBytes          = "abcdefghijklmnopqrstuvwxyz0123456789 -"
	MaxTokensPerCall     = 256
	ErrTypeProposeFailed = "ProposeFailed"
	CodeMismatch         = "DEMO-MISMATCH"
	CodeSchema           = "DEMO-SCHEMA"
	hexDigits            = "0123456789abcdef"
)

// Activities: Tenant comes from the worker configuration, never from an input (T3).
type Activities struct {
	LLM    *llm.Client
	Tenant tenancy.ID
}

func ValidTarget(t string) bool {
	return t != "" && len(t) <= MaxTargetBytes && strings.Trim(t, TargetBytes) == ""
}

func (a *Activities) Propose(ctx context.Context, req loops.ProposeRequest) (loops.ProposeResponse, error) {
	target, ok := targetOf(req.Payload)
	instr, known := instruction(req.Strategy)
	if !ok || !known {
		return loops.ProposeResponse{}, refuse("invalid propose request", loops.ErrTypeValidation)
	}
	if a == nil || a.LLM == nil {
		return loops.ProposeResponse{}, refuse("demo activities not configured", loops.ErrTypePolicyViolation)
	}
	tctx, err := tenancy.WithTenant(ctx, a.Tenant)
	if err != nil {
		return loops.ProposeResponse{}, refuse("demo tenant refused", loops.ErrTypePolicyViolation)
	}
	res, err := a.LLM.Structured(tctx, llm.Call{
		PromptID: PromptID, PromptHash: PromptHash, MaxTokens: MaxTokensPerCall,
		Messages: []lldomain.Message{{Role: lldomain.RoleUser, Parts: []lldomain.Part{
			{Text: instr},
			{Untrusted: &lldomain.UntrustedBlock{SourceID: "demo-target", Content: target}},
		}}},
	})
	var used *llm.UsageError
	switch {
	case err == nil: // Usage is untrusted: RunLoop bounds it (T45)
		return loops.ProposeResponse{Candidate: res.Output, Tokens: res.Trace.Usage.InputTokens + res.Trace.Usage.OutputTokens}, nil
	case ctx.Err() != nil:
		return loops.ProposeResponse{}, ctx.Err()
	case errors.As(err, &used): // (ae), (av)
		return loops.ProposeResponse{}, temporal.NewApplicationErrorWithOptions("demo proposer call failed", ErrTypeProposeFailed,
			temporal.ApplicationErrorOptions{
				NonRetryable: !errors.Is(err, schema.ErrOutOfSchema), // (af)
				Details:      []any{loops.ProposeFailure{Tokens: used.Bound}},
			})
	}
	return loops.ProposeResponse{}, refuse("demo proposer refused", loops.ErrTypePolicyViolation)
}

// Verify is deterministic and never calls the model.
func (a *Activities) Verify(_ context.Context, req loops.VerifyRequest) (loops.VerifyResult, error) {
	target, ok := targetOf(req.Payload)
	if !ok {
		return loops.VerifyResult{}, refuse("invalid verify request", loops.ErrTypeValidation)
	}
	p, err := prompts.Load(PromptID)
	if err != nil || p.Hash != PromptHash {
		return loops.VerifyResult{}, refuse("demo prompt changed", loops.ErrTypePolicyViolation)
	}
	conforms := p.Schema.Validate(req.Candidate) == nil // a finding, not an error (nilerr)
	if !conforms {
		return failed(CodeSchema, "candidate does not match the output schema"), nil
	}
	if g, isStr := greeting(req.Candidate); !isStr || g != target {
		return failed(CodeMismatch, "greeting differs from the target"), nil
	}
	return loops.VerifyResult{OK: true}, nil
}

// Commit has no external effect: idempotent on (tenant, workflow, plan hash).
func (a *Activities) Commit(_ context.Context, planHash string) error {
	if len(planHash) != 64 || strings.Trim(planHash, hexDigits) != "" {
		return refuse("invalid plan hash", loops.ErrTypeValidation)
	}
	return nil
}

func targetOf(payload json.RawMessage) (string, bool) {
	v, err := schema.DecodeStrict(payload)
	obj, isObj := v.(map[string]any)
	t, isStr := obj["target"].(string)
	return t, err == nil && isObj && len(obj) == 1 && isStr && ValidTarget(t)
}

func greeting(candidate json.RawMessage) (string, bool) {
	v, err := schema.DecodeStrict(candidate)
	obj, _ := v.(map[string]any)
	g, isStr := obj["greeting"].(string)
	return g, err == nil && isStr
}

func instruction(strategy string) (string, bool) {
	switch strategy {
	case StrategyDirect:
		return "Strategy direct: reply with a greeting equal to the target.", true
	case StrategyReformulate:
		return "Strategy reformulate: the previous greeting differed; reply with the target, in lower case.", true
	}
	return "", false
}

func failed(code, msg string) loops.VerifyResult {
	return loops.VerifyResult{Findings: []domain.Finding{{Code: code, Source: "demo", Severity: domain.SeverityHigh, Resource: "candidate", Message: msg}}}
}

func refuse(msg, errType string) error {
	return temporal.NewNonRetryableApplicationError(msg, errType, nil)
}
