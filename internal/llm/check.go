package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/llm/redact"
	"github.com/amezianechayer/rempart/internal/llm/schema"
)

var toolName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// textSize counts text bytes before redaction (bound of M0-T07).
func textSize(msgs []domain.Message) int {
	n := 0
	for _, m := range msgs {
		for _, p := range m.Parts {
			n += len(p.Text)
			if p.Untrusted != nil {
				n += len(p.Untrusted.SourceID) + len(p.Untrusted.Content)
			}
		}
	}
	return n
}

func checkTools(tools []domain.ToolSpec) (map[string]*schema.Schema, error) {
	if len(tools) == 0 {
		return nil, fmt.Errorf("%w: no tool", ErrInvalidTools)
	}
	out := make(map[string]*schema.Schema, len(tools))
	for _, t := range tools {
		if !toolName.MatchString(t.Name) {
			return nil, fmt.Errorf("%w: malformed name", ErrInvalidTools)
		}
		if _, dup := out[t.Name]; dup {
			return nil, fmt.Errorf("%w: duplicate name", ErrInvalidTools)
		}
		if redact.New().ContainsSecret(t.Name) || redact.New().ContainsSecret(t.Description) {
			return nil, ErrSecretInPrompt
		}
		s, err := schema.CompileSchema(t.InputSchema)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidTools, err)
		}
		out[t.Name] = s
	}
	return out, nil
}

// redactMessages returns a redacted deep copy and the number of secrets masked.
func redactMessages(msgs []domain.Message) ([]domain.Message, int) {
	r := redact.New()
	n := 0
	red := func(s string) string {
		out, ms := r.Redact(s)
		n += len(ms)
		return out
	}
	out := make([]domain.Message, len(msgs))
	for i, m := range msgs {
		parts := make([]domain.Part, len(m.Parts))
		for j, p := range m.Parts {
			if p.Untrusted != nil {
				parts[j].Untrusted = &domain.UntrustedBlock{SourceID: red(p.Untrusted.SourceID), Content: red(p.Untrusted.Content)}
			} else {
				parts[j].Text = red(p.Text)
			}
		}
		out[i] = domain.Message{Role: m.Role, Parts: parts}
	}
	return out, n
}

// checkOutput: tool calls are checked against their tool and Output is dropped;
// otherwise Output is checked against the prompt schema. Structured has no tool.
func checkOutput(s *schema.Schema, tools map[string]*schema.Schema, resp domain.Response) (json.RawMessage, []domain.ToolCall, error) {
	if len(resp.ToolCalls) == 0 {
		if err := s.Validate(resp.Output); err != nil {
			return nil, nil, err
		}
		return bytes.Clone(resp.Output), nil, nil
	}
	calls := make([]domain.ToolCall, len(resp.ToolCalls))
	for i, tc := range resp.ToolCalls {
		ts, ok := tools[tc.Name]
		if !ok {
			return nil, nil, ErrUnknownTool
		}
		if err := ts.Validate(tc.Input); err != nil {
			return nil, nil, err
		}
		calls[i] = domain.ToolCall{Name: tc.Name, Input: bytes.Clone(tc.Input)}
	}
	return nil, calls, nil
}

// correction quotes the schema error (keyword and path), never the output.
func correction(err error) domain.Message {
	return domain.Message{Role: domain.RoleUser, Parts: []domain.Part{{
		Text: "The previous answer was rejected: " + err.Error() + ". Answer again with JSON that matches the schema exactly.",
	}}}
}
