package evals

import (
	"errors"
	"testing"
)

// TestBaselinePathEncodesSlash (ADR 0008 D4): an OpenRouter model holds one
// '/', encoded %2f; two '/', a '/' at an end, or a '/' on another platform
// are refused; the existing paths are unchanged.
func TestBaselinePathEncodesSlash(t *testing.T) {
	got, err := BaselinePath("demo", "openrouter", "deepseek/deepseek-chat")
	if err != nil || got != "evals/demo/baseline/openrouter/deepseek%2fdeepseek-chat.json" {
		t.Errorf("BaselinePath(openrouter) = %q, %v", got, err)
	}
	for _, c := range []struct{ platform, model string }{
		{"openrouter", "a/b/c"},
		{"openrouter", "/deepseek-chat"},
		{"openrouter", "deepseek/"},
		{"selfhosted", "qwen/qwen2.5@abc"},
		{"anthropic", "a/b"},
	} {
		if p, err := BaselinePath("demo", c.platform, c.model); !errors.Is(err, ErrInvalidName) {
			t.Errorf("BaselinePath(%s, %s) = %q, %v; want ErrInvalidName", c.platform, c.model, p, err)
		}
	}
	if got, err := BaselinePath("demo", "anthropic", "claude-sonnet-4-5-20250929"); err != nil ||
		got != "evals/demo/baseline/anthropic/claude-sonnet-4-5-20250929.json" {
		t.Errorf("existing path changed: %q, %v", got, err)
	}
	if got, err := BaselinePath("demo", "selfhosted", "qwen2.5@abc:1"); err != nil ||
		got != "evals/demo/baseline/selfhosted/qwen2.5%40abc%3a1.json" {
		t.Errorf("existing path changed: %q, %v", got, err)
	}
}
