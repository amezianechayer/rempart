package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"

	"github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/llm/ports"
	"github.com/amezianechayer/rempart/internal/llm/prompts"
	"github.com/amezianechayer/rempart/internal/llm/redact"
	"github.com/amezianechayer/rempart/internal/llm/schema"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

var (
	ErrInvalidConfig    = errors.New("llm: invalid client configuration")
	ErrTokenBudget      = errors.New("llm: token budget exceeded")
	ErrRequestTooLarge  = errors.New("llm: request text exceeds 1 MiB")
	ErrPromptMismatch   = errors.New("llm: prompt hash differs from the pinned hash")
	ErrSecretInPrompt   = errors.New("llm: static prompt or tool text contains a secret")
	ErrInvalidTools     = errors.New("llm: invalid tool specification")
	ErrFakeRouteRefused = errors.New("llm: fake route refused by configuration")
	ErrModelMismatch    = errors.New("llm: response model differs from route")
	ErrProviderFailed   = errors.New("llm: provider call failed")
	ErrUnknownTool      = errors.New("llm: tool call names an unknown tool")
)

const (
	MaxRequestTextBytes = 1 << 20
	MaxCorrectionsLimit = 3
	MaxTokensLimit      = 1 << 16
)

type Config struct {
	MaxCorrections   int  // 0 to 3, taken as is
	MaxTokensPerCall int  // 1 to MaxTokensLimit, no default
	AllowFakeRoute   bool // tests and the -dev root only (T41)
}

// Call names a pinned prompt: PromptHash must equal the loaded prompt hash.
type Call struct {
	PromptID, PromptHash string
	Messages             []domain.Message
	MaxTokens            int
}

// Trace is evidence metadata: no content, never a request hash.
type Trace struct {
	Tenant               tenancy.ID
	Platform             domain.Platform
	Region, Model        string
	PromptID, PromptHash string
	RequestID            string
	Attempts, Redactions int
	Usage                domain.Usage
}

type Result struct {
	Output json.RawMessage
	Trace  Trace
}

type Client struct {
	provider ports.ModelProvider
	resolver ports.RouteResolver
	promptFS fs.FS
	cfg      Config
}

// NewClient: a nil promptFS selects the embedded prompts.
func NewClient(p ports.ModelProvider, rr ports.RouteResolver, promptFS fs.FS, cfg Config) (*Client, error) {
	if p == nil || rr == nil {
		return nil, fmt.Errorf("%w: provider and resolver are required", ErrInvalidConfig)
	}
	if cfg.MaxCorrections < 0 || cfg.MaxCorrections > MaxCorrectionsLimit {
		return nil, fmt.Errorf("%w: corrections out of range", ErrInvalidConfig)
	}
	if cfg.MaxTokensPerCall < 1 || cfg.MaxTokensPerCall > MaxTokensLimit {
		return nil, fmt.Errorf("%w: token budget out of range", ErrInvalidConfig)
	}
	return &Client{provider: p, resolver: rr, promptFS: promptFS, cfg: cfg}, nil
}

// Structured is the only call that may carry untrusted blocks.
func (c *Client) Structured(ctx context.Context, call Call) (Result, error) {
	res, _, err := c.run(ctx, call, nil, false)
	return res, err
}

// WithTools refuses untrusted blocks and checks each tool call against its tool.
func (c *Client) WithTools(ctx context.Context, call Call, tools []domain.ToolSpec) (Result, []domain.ToolCall, error) {
	return c.run(ctx, call, tools, true)
}

func (c *Client) run(ctx context.Context, call Call, tools []domain.ToolSpec, withTools bool) (Result, []domain.ToolCall, error) {
	if c == nil {
		return Result{}, nil, ErrInvalidConfig
	}
	tenant, err := tenancy.FromContext(ctx) // S1
	if err != nil {
		return Result{}, nil, err
	}
	if err := ctx.Err(); err != nil { // S2
		return Result{}, nil, err
	}
	pre := domain.Request{Messages: call.Messages}
	if withTools && pre.HasUntrusted() { // S3
		return Result{}, nil, domain.ErrUntrustedWithTools
	}
	if err := pre.Validate(); err != nil { // S4
		return Result{}, nil, err
	}
	if call.MaxTokens < 1 || call.MaxTokens > c.cfg.MaxTokensPerCall { // S5
		return Result{}, nil, ErrTokenBudget
	}
	if textSize(call.Messages) > MaxRequestTextBytes { // S6
		return Result{}, nil, ErrRequestTooLarge
	}
	var toolSchemas map[string]*schema.Schema
	if withTools { // S7
		if toolSchemas, err = checkTools(tools); err != nil {
			return Result{}, nil, err
		}
	}
	prompt, err := c.loadPrompt(call) // S8
	if err != nil {
		return Result{}, nil, err
	}
	route, err := c.checkedRoute(ctx, tenant) // S9 to S11
	if err != nil {
		return Result{}, nil, err
	}
	msgs, redactions := redactMessages(call.Messages) // S12
	req := domain.Request{
		PromptID: prompt.ID, PromptHash: prompt.Hash, System: prompt.System,
		Messages: msgs, Schema: prompt.Schema.Raw(), MaxTokens: call.MaxTokens,
	}
	tr := Trace{
		Tenant: tenant, Platform: route.Platform, Region: route.Region, Model: route.Model,
		PromptID: prompt.ID, PromptHash: prompt.Hash, Redactions: redactions,
	}
	for attempt := 0; ; attempt++ {
		if cerr := ctx.Err(); cerr != nil { // S13
			return Result{}, nil, cerr
		}
		var resp domain.Response
		if withTools {
			resp, err = c.provider.WithTools(ctx, route, req, tools)
		} else {
			resp, err = c.provider.Structured(ctx, route, req)
		}
		tr.Attempts++
		if err != nil {
			return Result{}, nil, opaque(ErrProviderFailed, err)
		}
		tr.Usage.InputTokens += resp.Usage.InputTokens
		tr.Usage.OutputTokens += resp.Usage.OutputTokens
		if resp.Model != route.Model { // S14
			return Result{}, nil, ErrModelMismatch
		}
		out, calls, verr := checkOutput(prompt.Schema, toolSchemas, resp) // S15
		if verr == nil {
			tr.RequestID = resp.RequestID
			return Result{Output: out, Trace: tr}, calls, nil
		}
		if !errors.Is(verr, schema.ErrOutOfSchema) || attempt >= c.cfg.MaxCorrections {
			return Result{}, nil, verr
		}
		req.Messages = append(req.Messages, correction(verr))
	}
}

// loadPrompt: a secret in a system prompt is refused, never masked (hash).
func (c *Client) loadPrompt(call Call) (prompts.Prompt, error) {
	load := prompts.Load
	if c.promptFS != nil {
		load = func(id string) (prompts.Prompt, error) { return prompts.LoadFS(c.promptFS, id) }
	}
	p, err := load(call.PromptID)
	if err != nil {
		return prompts.Prompt{}, err
	}
	if call.PromptHash != p.Hash {
		return prompts.Prompt{}, ErrPromptMismatch
	}
	if redact.New().ContainsSecret(p.System) {
		return prompts.Prompt{}, ErrSecretInPrompt
	}
	return p, nil
}

// checkedRoute returns exactly the route that CheckPolicy accepted (T40).
func (c *Client) checkedRoute(ctx context.Context, tenant tenancy.ID) (domain.Route, error) {
	pol, err := c.resolver.Resolve(ctx, tenant)
	if err != nil {
		return domain.Route{}, opaque(domain.ErrNoRoute, err)
	}
	if pol.Route.Platform == domain.PlatformFake && !c.cfg.AllowFakeRoute {
		return domain.Route{}, ErrFakeRouteRefused
	}
	if err := domain.CheckPolicy(pol, c.provider.Capabilities(pol.Route)); err != nil {
		return domain.Route{}, err
	}
	return pol.Route, nil
}

// opaqueError prints only kind: a resolver or provider message may quote input.
type opaqueError struct{ kind, cause error }

func (e *opaqueError) Error() string { return e.kind.Error() }

func (e *opaqueError) Unwrap() []error { return []error{e.kind, e.cause} }

func opaque(kind, cause error) error { return &opaqueError{kind: kind, cause: cause} }
