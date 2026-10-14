package main

import (
	"strings"
	"testing"

	"github.com/amezianechayer/rempart/internal/llm/apikey"
)

// Tests of the real mode (ADR 0008 D5, D7, M1-T09): --llm openrouter with a
// model of the closed list, a key read from REMPART_LLM_KEY_OPENROUTER, one
// named suite; nothing leaves the process in these tests.

const realKey = "sk-or-v1-EVALS-canary-44a1"

// TestRealModeRefusedWithoutKeyOrModel: every malformed real-mode command
// line is a usage error, before any suite is read or any request sent.
func TestRealModeRefusedWithoutKeyOrModel(t *testing.T) {
	e := newEnv(t, t.TempDir(), noGit(t))
	for name, args := range map[string][]string{
		"no_model":      {"--suite", "demo", "--llm", "openrouter"},
		"model_no_llm":  {"--suite", "demo", "--model", "deepseek/deepseek-chat"},
		"unknown_llm":   {"--suite", "demo", "--llm", "anthropic", "--model", "deepseek/deepseek-chat"},
		"unlisted":      {"--suite", "demo", "--llm", "openrouter", "--model", "openrouter/auto"},
		"variant":       {"--suite", "demo", "--llm", "openrouter", "--model", "deepseek/deepseek-chat:free"},
		"all_suites":    {"--suite", "all", "--llm", "openrouter", "--model", "deepseek/deepseek-chat"},
		"changed":       {"--suite", "changed", "--base", "HEAD", "--llm", "openrouter", "--model", "deepseek/deepseek-chat"},
		"twice":         {"--suite", "demo", "--llm", "openrouter", "--llm", "openrouter", "--model", "deepseek/deepseek-chat"},
		"no_key_in_env": {"--suite", "demo", "--llm", "openrouter", "--model", "deepseek/deepseek-chat"},
	} {
		code, stdout, stderr := runArgs(t, e, args...)
		if code != codeUsage || stdout != "" {
			t.Errorf("%s: code %d, stdout %q; want %d and nothing", name, code, stdout, codeUsage)
		}
		if name == "no_key_in_env" && !strings.Contains(stderr, apikey.EnvOpenRouter) {
			t.Errorf("%s: stderr %q does not name the variable", name, stderr)
		}
	}
}

// TestRealModeTargets: with a key, the demo target runs on the OpenRouter
// route of the model; the key is never printed.
func TestRealModeTargets(t *testing.T) {
	environ := []string{"PATH=/bin", apikey.EnvOpenRouter + "=" + realKey}
	ts, err := realTargets(environ, "openrouter", "deepseek/deepseek-chat")
	if err != nil {
		t.Fatalf("realTargets: %v", err)
	}
	if id := ts["demo"].Identity(); id != (Identity{Platform: "openrouter", Model: "deepseek/deepseek-chat"}) {
		t.Errorf("demo identity %+v", id)
	}
	if _, err := realTargets([]string{"PATH=/bin"}, "openrouter", "deepseek/deepseek-chat"); err == nil ||
		strings.Contains(err.Error(), realKey) {
		t.Errorf("realTargets without key: %v", err)
	}
}
