// Package domain holds the LLM contract types, untrusted-data rendering,
// request hashing and the route policy (ADR 0002). Standard library only (R1).
package domain

import (
	"encoding/json"
	"errors"
)

type Platform string

const (
	PlatformAnthropic  Platform = "anthropic"
	PlatformBedrock    Platform = "bedrock"
	PlatformVertex     Platform = "vertex"
	PlatformSelfHosted Platform = "selfhosted"
	PlatformFake       Platform = "fake"
)

// Route is the effective model route. Model is an exact pinned identifier, never an alias.
type Route struct {
	Platform Platform
	Region   string
	Model    string
}

type Role string

const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// UntrustedBlock is untrusted text. It is rendered only by RenderUntrusted,
// only in calls without tools.
type UntrustedBlock struct{ SourceID, Content string }

// Part holds exactly one of Text or Untrusted.
type Part struct {
	Text      string
	Untrusted *UntrustedBlock
}

type Message struct {
	Role  Role
	Parts []Part
}

type ToolSpec struct {
	Name        string
	Description string
	InputSchema json.RawMessage
}

type ToolCall struct {
	Name  string
	Input json.RawMessage
}

type Usage struct{ InputTokens, OutputTokens int }

type Request struct {
	PromptID   string
	PromptHash string
	System     string
	Messages   []Message
	Schema     json.RawMessage
	MaxTokens  int
}

type Response struct {
	Output    json.RawMessage // raw: validated by the service, never by an adapter alone
	ToolCalls []ToolCall
	Usage     Usage
	Model     string // declared by the platform response, compared with Route.Model
	RequestID string
}

type Capabilities struct{ NativeStructuredOutput, StrictTools, RequiresRetention bool }

var (
	ErrResidency          = errors.New("llm: route violates the residency policy")
	ErrRetention          = errors.New("llm: route violates the retention policy")
	ErrModelNotPinned     = errors.New("llm: model is not an exact pinned identifier")
	ErrInvalidRoute       = errors.New("llm: invalid route")
	ErrUntrustedWithTools = errors.New("llm: untrusted block in a call with tools")
	ErrInvalidPart        = errors.New("llm: part must hold exactly one of text or untrusted block")
	ErrInvalidRequest     = errors.New("llm: invalid request")
	ErrNoRoute            = errors.New("llm: no route for tenant")
)

// Validate reports ErrInvalidPart unless exactly one of Text and Untrusted is set.
func (p Part) Validate() error {
	hasText := p.Text != ""
	hasUntrusted := p.Untrusted != nil
	if hasText == hasUntrusted {
		return ErrInvalidPart
	}
	return nil
}

// Validate checks messages, roles and parts; not budgets nor schemas.
func (r Request) Validate() error {
	if len(r.Messages) == 0 {
		return ErrInvalidRequest
	}
	for _, m := range r.Messages {
		if m.Role != RoleUser && m.Role != RoleAssistant {
			return ErrInvalidRequest
		}
		if len(m.Parts) == 0 {
			return ErrInvalidRequest
		}
		for _, p := range m.Parts {
			if err := p.Validate(); err != nil {
				return err
			}
		}
	}
	return nil
}

// HasUntrusted reports whether any part, even an invalid one, carries an UntrustedBlock.
func (r Request) HasUntrusted() bool {
	for _, m := range r.Messages {
		for _, p := range m.Parts {
			if p.Untrusted != nil {
				return true
			}
		}
	}
	return false
}
