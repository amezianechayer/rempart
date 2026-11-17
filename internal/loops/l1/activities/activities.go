// Package activities: activities of the loop L1 (docs/loops/L1.md); never
// imports the SDK workflow package (rule l). Only Propose calls the model;
// Prepare, Verify and Finalize are deterministic.
package activities

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"unicode/utf8"

	"go.temporal.io/sdk/temporal"

	"github.com/amezianechayer/rempart/internal/intent"
	"github.com/amezianechayer/rempart/internal/intent/domain"
	"github.com/amezianechayer/rempart/internal/llm"
	lldomain "github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/llm/prompts"
	"github.com/amezianechayer/rempart/internal/llm/schema"
	"github.com/amezianechayer/rempart/internal/loops"
	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

const (
	PromptID                  = "intent.extract.v1"
	PromptHash                = "975e8eec60d4b988d032b3d0709846edcd2268ae6fab15b4cfc9bfb48d3a2032"
	StrategyDirect            = "direct"
	StrategyFocusedCorrection = "focused_correction"
	MaxRequestBytes           = 8 << 10 // D9
	MaxAnswers                = 3
	MaxAnswerBytes            = 1 << 10
	MaxFieldBytes             = 128
	MaxContextItems           = 16
	MaxContextItemBytes       = 64
	MaxRounds                 = 3
	MaxTokensPerCall          = 8192
	ErrTypeProposeFailed      = "ProposeFailed"
	CodeDraftInvalid          = "INTENT-DRAFT-INVALID"
	CodeTenantFromModel       = "INTENT-TENANT-FROM-MODEL"
	CodeIRInvalid             = "INTENT-IR-INVALID"
	StatusConverged           = "converged"
	StatusNeedsClarification  = "needs_clarification"
)

// Sources of the untrusted blocks: the model reads the user text, the
// previous draft and its findings only through them (D9, T85).
const (
	SourceRequest       = "request"
	SourceAnswer        = "answer"
	SourcePreviousDraft = "previous-draft"
	SourceFindings      = "findings"
)

const (
	fieldBytes   = "abcdefghijklmnopqrstuvwxyz0123456789_.-[]"
	contextBytes = "abcdefghijklmnopqrstuvwxyz0123456789-_"
)

// Activities: Tenant comes from the worker configuration, never from an input
// (rule 9, T3, ADR 0009).
type Activities struct {
	LLM    *llm.Client
	Tenant tenancy.ID
}

// Answer is the answer of the user to an open question of the previous round.
type Answer struct {
	Field  string `json:"field"`
	Answer string `json:"answer"`
}

// Input of the workflow: no tenant (propagator, rule 9).
type Input struct {
	RequestText  string               `json:"request_text"` // 8 KiB at most
	Context      domain.TenantContext `json:"context"`
	PriorAnswers []Answer             `json:"prior_answers"`
	Round        int                  `json:"round"` // 1 to 3
}

// Prepared is the result of Prepare: the payload of the loop, or an
// unsupported language (obligation (dh)).
type Prepared struct {
	Payload     json.RawMessage `json:"payload"`
	Unsupported bool            `json:"unsupported"`
}

// FinalizeRequest carries the payload and the converged draft.
type FinalizeRequest struct {
	Payload   json.RawMessage `json:"payload"`
	Candidate json.RawMessage `json:"candidate"`
}

// Finalized is the IR with the tenant of the worker and the contradictions
// turned into questions.
type Finalized struct {
	Status         string                 `json:"status"` // converged or needs_clarification
	IR             domain.IR              `json:"ir"`
	Contradictions []domain.Contradiction `json:"contradictions"`
}

// payload is the document of the loop, built by Prepare only.
type payload struct {
	RequestText string               `json:"request_text"`
	Answers     []Answer             `json:"answers"`
	Context     domain.TenantContext `json:"context"`
	Language    domain.Lang          `json:"language"`
}

// userText is what the user wrote: the request, then the answers.
func (p payload) userText() string {
	var b strings.Builder
	b.WriteString(p.RequestText)
	for _, a := range p.Answers {
		b.WriteString("\n")
		b.WriteString(a.Answer)
	}
	return b.String()
}

// Prepare checks the bounds of the input, detects the language of the user
// text and builds the payload of the loop. Deterministic, no model.
func (a *Activities) Prepare(_ context.Context, in Input) (Prepared, error) {
	if what := in.invalid(); what != "" {
		return Prepared{}, refuse("invalid L1 input: "+what, loops.ErrTypeValidation)
	}
	p := payload{RequestText: in.RequestText, Answers: in.PriorAnswers, Context: in.Context}
	if p.Answers == nil {
		p.Answers = []Answer{}
	}
	lang := domain.DetectLanguage(p.userText())
	if lang.Unsupported {
		return Prepared{Unsupported: true}, nil
	}
	p.Language = lang.Primary
	raw, err := json.Marshal(p)
	if err != nil {
		return Prepared{}, refuse("L1 payload not encodable", loops.ErrTypeValidation)
	}
	return Prepared{Payload: raw}, nil
}

// invalid names the first bound broken by in, never quoting a value.
func (in Input) invalid() string {
	switch {
	case !userString(in.RequestText, MaxRequestBytes):
		return "request text"
	case in.Round < 1 || in.Round > MaxRounds:
		return "round"
	case in.Round == 1 && len(in.PriorAnswers) != 0, len(in.PriorAnswers) > MaxAnswers:
		return "answers"
	case slices.ContainsFunc(in.PriorAnswers, func(a Answer) bool {
		return !token(a.Field, MaxFieldBytes, fieldBytes) || !userString(a.Answer, MaxAnswerBytes)
	}):
		return "answer"
	}
	for _, l := range [][]string{in.Context.AllowedRegions, in.Context.ForbiddenClouds, in.Context.Compliance} {
		if len(l) > MaxContextItems || slices.ContainsFunc(l, func(s string) bool { return !token(s, MaxContextItemBytes, contextBytes) }) {
			return "context"
		}
	}
	return ""
}

func userString(s string, limit int) bool {
	return len(s) <= limit && utf8.ValidString(s) && strings.TrimSpace(s) != "" && !strings.ContainsRune(s, 0)
}

func token(s string, limit int, set string) bool {
	return s != "" && len(s) <= limit && strings.Trim(s, set) == ""
}

// decodePayload reads a payload built by Prepare, strictly.
func decodePayload(raw json.RawMessage) (payload, bool) {
	if _, err := schema.DecodeStrict(raw); err != nil {
		return payload{}, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var p payload
	if err := dec.Decode(&p); err != nil {
		return payload{}, false
	}
	in := Input{RequestText: p.RequestText, Context: p.Context, PriorAnswers: p.Answers, Round: MaxRounds}
	if len(p.Answers) == 0 {
		in.Round = 1
	}
	ok := in.invalid() == "" && (p.Language == domain.LangFR || p.Language == domain.LangEN)
	return p, ok
}

// Propose asks the model for a draft: the user text, the previous draft and
// its findings only in untrusted blocks, in a call without tools.
func (a *Activities) Propose(ctx context.Context, req loops.ProposeRequest) (loops.ProposeResponse, error) {
	p, ok := decodePayload(req.Payload)
	instr, known := instruction(req.Strategy)
	if !ok || !known {
		return loops.ProposeResponse{}, refuse("invalid propose request", loops.ErrTypeValidation)
	}
	if a == nil || a.LLM == nil {
		return loops.ProposeResponse{}, refuse("L1 activities not configured", loops.ErrTypePolicyViolation)
	}
	tctx, err := tenancy.WithTenant(ctx, a.Tenant)
	if err != nil {
		return loops.ProposeResponse{}, refuse("L1 tenant refused", loops.ErrTypePolicyViolation)
	}
	parts := []lldomain.Part{{Text: instr}, {Text: contextText(p.Context)}, untrusted(SourceRequest, p.RequestText)}
	for _, an := range p.Answers {
		parts = append(parts, untrusted(SourceAnswer, an.Field+": "+an.Answer))
	}
	if len(req.Best) > 0 {
		parts = append(parts, untrusted(SourcePreviousDraft, string(req.Best)))
	}
	if len(req.Findings) > 0 {
		parts = append(parts, untrusted(SourceFindings, findingsText(req.Findings)))
	}
	res, err := a.LLM.Structured(tctx, llm.Call{
		PromptID: PromptID, PromptHash: PromptHash, MaxTokens: MaxTokensPerCall,
		Messages: []lldomain.Message{{Role: lldomain.RoleUser, Parts: parts}},
	})
	var used *llm.UsageError
	switch {
	case err == nil: // Usage is untrusted: RunLoop bounds it (T45)
		return loops.ProposeResponse{Candidate: res.Output, Tokens: res.Trace.Usage.InputTokens + res.Trace.Usage.OutputTokens}, nil
	case ctx.Err() != nil:
		return loops.ProposeResponse{}, ctx.Err()
	case errors.As(err, &used): // (ae), (av)
		return loops.ProposeResponse{}, temporal.NewApplicationErrorWithOptions("L1 proposer call failed", ErrTypeProposeFailed,
			temporal.ApplicationErrorOptions{
				NonRetryable: !errors.Is(err, schema.ErrOutOfSchema), // (af)
				Details:      []any{loops.ProposeFailure{Tokens: used.Bound}},
			})
	}
	return loops.ProposeResponse{}, refuse("L1 proposer refused", loops.ErrTypePolicyViolation)
}

func untrusted(source, content string) lldomain.Part {
	return lldomain.Part{Untrusted: &lldomain.UntrustedBlock{SourceID: source, Content: content}}
}

func instruction(strategy string) (string, bool) {
	switch strategy {
	case StrategyDirect:
		return "Strategy direct: write the draft of the request.", true
	case StrategyFocusedCorrection:
		return "Strategy focused_correction: the previous draft was rejected again; change only the fields the findings point to.", true
	}
	return "", false
}

// contextText states the tenant context, set by Rempart: values checked by
// Input.invalid, never written by the user nor the model.
func contextText(c domain.TenantContext) string {
	list := func(l []string) string {
		if len(l) == 0 {
			return "none"
		}
		return strings.Join(l, ", ")
	}
	return "Tenant context set by Rempart. Allowed regions: " + list(c.AllowedRegions) +
		". Forbidden clouds: " + list(c.ForbiddenClouds) + ". Compliance frameworks: " + list(c.Compliance) + "."
}

func findingsText(fs []loopsdomain.Finding) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString(f.Code + " (" + string(f.Severity) + ") " + f.Resource + ": " + f.Message + "\n")
	}
	return b.String()
}

// Verify is deterministic and never calls the model: strict draft, no tenant
// key, checks of internal/intent, IR valid once the tenant of the worker is
// injected.
func (a *Activities) Verify(_ context.Context, req loops.VerifyRequest) (loops.VerifyResult, error) {
	p, ok := decodePayload(req.Payload)
	if !ok {
		return loops.VerifyResult{}, refuse("invalid verify request", loops.ErrTypeValidation)
	}
	if a == nil || !customer(a.Tenant) {
		return loops.VerifyResult{}, refuse("L1 activities not configured", loops.ErrTypePolicyViolation)
	}
	if pr, err := prompts.Load(PromptID); err != nil || pr.Hash != PromptHash {
		return loops.VerifyResult{}, refuse("L1 prompt changed", loops.ErrTypePolicyViolation)
	}
	fs := a.check(p, req.Candidate)
	return loops.VerifyResult{OK: !blocking(fs), Findings: fs[:min(len(fs), loops.MaxFindings)]}, nil
}

// check returns the sorted findings of a candidate draft.
func (a *Activities) check(p payload, candidate json.RawMessage) []loopsdomain.Finding {
	d, err := intent.ParseDraft(candidate)
	switch {
	case errors.Is(err, domain.ErrTenantFromModel):
		return []loopsdomain.Finding{finding(CodeTenantFromModel, loopsdomain.SeverityCritical, "draft contains a tenant key; the tenant is never written by the model")}
	case err != nil:
		return []loopsdomain.Finding{finding(CodeDraftInvalid, loopsdomain.SeverityHigh, "draft does not match the output schema")}
	}
	fs := domain.Check(p.userText(), d, p.Context)
	if intent.ValidateIR(d.ToIR(string(a.Tenant))) != nil {
		fs = loopsdomain.Sort(append(fs, finding(CodeIRInvalid, loopsdomain.SeverityHigh, "draft does not convert to a valid Intent IR")))
	}
	return fs
}

func blocking(fs []loopsdomain.Finding) bool {
	return slices.ContainsFunc(fs, func(f loopsdomain.Finding) bool {
		return f.Severity.Weight() >= loopsdomain.SeverityMedium.Weight()
	})
}

// Finalize builds the IR of a converged draft, checked again: tenant of the
// worker, contradictions first among the questions, in the language of the
// request, ValidateIR. Deterministic, no model.
func (a *Activities) Finalize(_ context.Context, req FinalizeRequest) (Finalized, error) {
	p, ok := decodePayload(req.Payload)
	if !ok {
		return Finalized{}, refuse("invalid finalize request", loops.ErrTypeValidation)
	}
	if a == nil || !customer(a.Tenant) {
		return Finalized{}, refuse("L1 activities not configured", loops.ErrTypePolicyViolation)
	}
	if blocking(a.check(p, req.Candidate)) { // never an IR from an unverified draft
		return Finalized{}, refuse("draft not verified", loops.ErrTypeValidation)
	}
	d, err := intent.ParseDraft(req.Candidate)
	if err != nil {
		return Finalized{}, refuse("draft not verified", loops.ErrTypeValidation)
	}
	ir := d.ToIR(string(a.Tenant))
	cs := domain.Contradictions(ir, p.Context)
	ir, _ = domain.WithContradictions(ir, cs, p.Language)
	if intent.ValidateIR(ir) != nil {
		return Finalized{}, refuse("IR not valid", loops.ErrTypeValidation)
	}
	out := Finalized{Status: StatusConverged, IR: ir, Contradictions: slices.Clone(cs)}
	if out.Contradictions == nil {
		out.Contradictions = []domain.Contradiction{}
	}
	if len(ir.OpenQuestions) > 0 {
		out.Status = StatusNeedsClarification
	}
	return out, nil
}

func customer(t tenancy.ID) bool {
	id, err := tenancy.ParseID(string(t))
	return err == nil && id != tenancy.System
}

func finding(code string, sev loopsdomain.Severity, msg string) loopsdomain.Finding {
	return loopsdomain.Finding{Code: code, Source: "intent", Severity: sev, Resource: "draft", Message: msg}
}

func refuse(msg, errType string) error {
	return temporal.NewNonRetryableApplicationError(msg, errType, nil)
}
