// Package fake is the deterministic offline model provider and static route
// resolver of ADR 0002: tests and the -dev composition root only (R5, T41).
package fake

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/llm/ports"
)

var (
	ErrNoRecording     = errors.New("fake: no recording for request")
	ErrScriptExhausted = errors.New("fake: script exhausted")
	ErrScripted        = errors.New("fake: scripted provider error")
	ErrInvalidOptions  = errors.New("fake: invalid options")
)

var _ ports.ModelProvider = (*Provider)(nil)

// Step is one answer. A non-empty Err yields ErrScripted; Response must be zero.
type Step struct {
	Response domain.Response
	Err      string
}

// Recording answers one exact request. RequestHash is a lookup key, never an evidence identity.
type Recording struct {
	PromptID, RequestHash string
	Step
}

type Options struct {
	Recordings []Recording
	Scripts    map[string][]Step              // by PromptID, consumed in order
	Models     map[string]domain.Capabilities // any other route requires retention
}

type Call struct {
	WithTools bool
	Route     domain.Route
	Request   domain.Request
	Tools     []domain.ToolSpec
}

type recKey struct{ promptID, hash string }

type Provider struct {
	mu          sync.Mutex
	recordings  map[recKey]Step
	scripts     map[string][]Step
	cursors     map[string]int
	models      map[string]domain.Capabilities
	invocations int
	calls       []Call
}

func New(opt Options) (*Provider, error) {
	p := &Provider{
		recordings: map[recKey]Step{}, scripts: map[string][]Step{},
		cursors: map[string]int{}, models: map[string]domain.Capabilities{},
	}
	for _, r := range opt.Recordings {
		if r.PromptID == "" || !isHash(r.RequestHash) || !validStep(r.Step) {
			return nil, fmt.Errorf("%w: malformed recording", ErrInvalidOptions)
		}
		k := recKey{r.PromptID, r.RequestHash}
		if _, dup := p.recordings[k]; dup {
			return nil, fmt.Errorf("%w: duplicate recording", ErrInvalidOptions)
		}
		p.recordings[k] = cloneStep(r.Step)
	}
	for id, steps := range opt.Scripts {
		if id == "" || len(steps) == 0 {
			return nil, fmt.Errorf("%w: empty script", ErrInvalidOptions)
		}
		for _, s := range steps {
			if !validStep(s) {
				return nil, fmt.Errorf("%w: malformed step", ErrInvalidOptions)
			}
			p.scripts[id] = append(p.scripts[id], cloneStep(s))
		}
	}
	for m, c := range opt.Models {
		if m == "" {
			return nil, fmt.Errorf("%w: empty model", ErrInvalidOptions)
		}
		p.models[m] = c
	}
	return p, nil
}

func (p *Provider) Structured(ctx context.Context, route domain.Route, req domain.Request) (domain.Response, error) {
	return p.call(ctx, false, route, req, nil)
}

func (p *Provider) WithTools(ctx context.Context, route domain.Route, req domain.Request, tools []domain.ToolSpec) (domain.Response, error) {
	return p.call(ctx, true, route, req, tools)
}

func (p *Provider) call(ctx context.Context, withTools bool, route domain.Route, req domain.Request, tools []domain.ToolSpec) (domain.Response, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.invocations++
	if err := ctx.Err(); err != nil {
		return domain.Response{}, err
	}
	if route.Platform != domain.PlatformFake || route.Region != "" {
		return domain.Response{}, fmt.Errorf("%w: not a fake route", domain.ErrInvalidRoute)
	}
	if withTools && req.HasUntrusted() {
		return domain.Response{}, domain.ErrUntrustedWithTools
	}
	if err := req.Validate(); err != nil {
		return domain.Response{}, err
	}
	p.calls = append(p.calls, Call{withTools, route, cloneRequest(req), cloneTools(tools)})
	step, err := p.lookup(req)
	if err != nil {
		return domain.Response{}, err
	}
	if step.Err != "" {
		return domain.Response{}, ErrScripted
	}
	return cloneResponse(step.Response), nil
}

func (p *Provider) lookup(req domain.Request) (Step, error) {
	if s, ok := p.recordings[recKey{req.PromptID, domain.RequestHash(req)}]; ok {
		return s, nil
	}
	steps, ok := p.scripts[req.PromptID]
	if !ok {
		return Step{}, ErrNoRecording
	}
	i := p.cursors[req.PromptID]
	if i >= len(steps) {
		return Step{}, ErrScriptExhausted
	}
	p.cursors[req.PromptID] = i + 1
	return steps[i], nil
}

func (p *Provider) Capabilities(route domain.Route) domain.Capabilities {
	if route.Platform == domain.PlatformFake && route.Region == "" {
		if c, ok := p.models[route.Model]; ok {
			return c
		}
	}
	return domain.Capabilities{RequiresRetention: true}
}

// Invocations counts every Structured and WithTools call, refused ones included.
func (p *Provider) Invocations() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.invocations
}

func (p *Provider) Calls() []Call {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Call, 0, len(p.calls))
	for _, c := range p.calls {
		out = append(out, Call{c.WithTools, c.Route, cloneRequest(c.Request), cloneTools(c.Tools)})
	}
	return out
}

func (p *Provider) Requests() []domain.Request {
	calls := p.Calls()
	out := make([]domain.Request, len(calls))
	for i, c := range calls {
		out[i] = c.Request
	}
	return out
}

func isHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := range len(s) {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validStep(s Step) bool {
	r := s.Response
	zero := len(r.Output) == 0 && len(r.ToolCalls) == 0 && r.Usage == (domain.Usage{}) && r.Model == "" && r.RequestID == ""
	return s.Err == "" || zero
}

func cloneStep(s Step) Step { return Step{cloneResponse(s.Response), s.Err} }

func cloneResponse(r domain.Response) domain.Response {
	r.Output = bytes.Clone(r.Output)
	if r.ToolCalls != nil {
		tc := make([]domain.ToolCall, len(r.ToolCalls))
		for i, c := range r.ToolCalls {
			tc[i] = domain.ToolCall{Name: c.Name, Input: bytes.Clone(c.Input)}
		}
		r.ToolCalls = tc
	}
	return r
}

func cloneRequest(r domain.Request) domain.Request {
	r.Schema = bytes.Clone(r.Schema)
	if r.Messages != nil {
		msgs := make([]domain.Message, len(r.Messages))
		for i, m := range r.Messages {
			msgs[i].Role = m.Role
			if m.Parts != nil {
				msgs[i].Parts = make([]domain.Part, len(m.Parts))
			}
			for j, pt := range m.Parts {
				msgs[i].Parts[j].Text = pt.Text
				if pt.Untrusted != nil {
					b := *pt.Untrusted
					msgs[i].Parts[j].Untrusted = &b
				}
			}
		}
		r.Messages = msgs
	}
	return r
}

func cloneTools(ts []domain.ToolSpec) []domain.ToolSpec {
	if ts == nil {
		return nil
	}
	out := make([]domain.ToolSpec, len(ts))
	for i, t := range ts {
		out[i] = domain.ToolSpec{Name: t.Name, Description: t.Description, InputSchema: bytes.Clone(t.InputSchema)}
	}
	return out
}
