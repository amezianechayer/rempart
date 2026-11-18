package main

import (
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/amezianechayer/rempart/internal/evals"
	"github.com/amezianechayer/rempart/internal/llm/apikey"
)

// TestRealModeAgainstHTTPTest (M1-T06, review before H-real): the real mode
// runs the whole intent suite against an OpenAI-compatible httptest server on
// 127.0.0.1, with a canary key: the calibration writes the baseline of the
// route, the measurement reads it, and the key never leaves in stdout,
// stderr, the report or the baseline; it is sent only as the bearer token.
func TestRealModeAgainstHTTPTest(t *testing.T) {
	const canary = "sk-or-v1-CANARY-intent-7d1e"
	replies := lastReplies(t)
	var calls, badAuth, unknown atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+canary {
			badAuth.Add(1)
		}
		draft, ok := replyFor(replies, body)
		if !ok {
			unknown.Add(1)
		}
		content, err := json.Marshal(draft)
		if err != nil {
			unknown.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"gen-1","model":"openai/gpt-4o-2024-08-06","provider":"OpenAI","choices":[{"index":0,"finish_reason":"stop",`+
			`"message":{"role":"assistant","content":`+string(content)+`}}],"usage":{"prompt_tokens":120,"completion_tokens":60}}`)
	}))
	t.Cleanup(ts.Close)
	realBaseURL = ts.URL + "/api/v1"
	t.Cleanup(func() { realBaseURL = "" })

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(filepath.Join(dir, "evals", "intent"), os.DirFS("../../evals/intent")); err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, dir, noGit(t))
	e.environ = append(e.environ, apikey.EnvOpenRouter+"="+canary)
	e.confirm = func(prompt string) bool { return !strings.Contains(prompt, canary) }
	args := []string{"--suite", "intent", "--llm", "openrouter", "--model", "openai/gpt-4o-2024-08-06"}

	code, stdout, stderr := runArgs(t, e, append(args, "--write-baseline")...)
	if code != codeOK {
		t.Fatalf("calibration: code %d\n%s", code, stderr)
	}
	baseline, err := fs.ReadFile(os.DirFS(dir), "evals/intent/baseline/openrouter/openai%2fgpt-4o-2024-08-06.json")
	if err != nil {
		t.Fatalf("calibration baseline: %v", err)
	}
	var r evals.Report
	oneDocument(t, stdout, &r)
	if r.Platform != "openrouter" || r.Model != "openai/gpt-4o-2024-08-06" || r.Cases < 22 || r.Runs != 3*r.Cases {
		t.Errorf("report %+v, want the route and the whole suite", r)
	}
	// The registry of validated routes is embedded at build time from the
	// committed baselines (D8): until the human commits this baseline and the
	// binary is rebuilt, the route is refused before any call.
	before := calls.Load()
	code2, stdout2, stderr2 := runArgs(t, e, args...)
	if code2 == codeOK || calls.Load() != before {
		t.Errorf("measurement before the route is registered: code %d, %d calls; want a refusal without call\n%s", code2, calls.Load()-before, stderr2)
	}
	for name, s := range map[string]string{"stdout": stdout + stdout2, "stderr": stderr + stderr2, "baseline": string(baseline)} {
		if strings.Contains(s, canary) || strings.Contains(s, "CANARY") {
			t.Errorf("%s carries the key", name)
		}
	}
	if calls.Load() == 0 || badAuth.Load() != 0 || unknown.Load() != 0 {
		t.Errorf("%d calls, %d without the bearer key, %d of an unknown case", calls.Load(), badAuth.Load(), unknown.Load())
	}
}

// lastReplies maps the request of each case of the intent suite to its last
// scripted reply, the draft a model that follows the instructions returns.
func lastReplies(t *testing.T) map[string]string {
	t.Helper()
	src := os.DirFS("../../evals/intent/cases")
	names, err := fs.Glob(src, "*.yaml")
	if err != nil || len(names) == 0 {
		t.Fatalf("cases: %v", err)
	}
	out := map[string]string{}
	for _, n := range names {
		b, err := fs.ReadFile(src, n)
		if err != nil {
			t.Fatal(err)
		}
		var c struct {
			Input struct {
				Request string           `yaml:"request"`
				Replies []map[string]any `yaml:"replies"`
			} `yaml:"input"`
		}
		if err := yaml.Unmarshal(b, &c); err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		if len(c.Input.Replies) == 0 {
			continue
		}
		last, err := json.Marshal(c.Input.Replies[len(c.Input.Replies)-1])
		if err != nil {
			t.Fatal(err)
		}
		out[c.Input.Request] = string(last)
	}
	return out
}

// replyFor returns the reply of the longest case request quoted in the
// request body (a request may prefix another one).
func replyFor(replies map[string]string, body []byte) (string, bool) {
	var v any
	if json.Unmarshal(body, &v) != nil {
		return "{}", false
	}
	var texts strings.Builder
	var walk func(any)
	walk = func(x any) {
		switch y := x.(type) {
		case string:
			texts.WriteString(y)
		case []any:
			for _, e := range y {
				walk(e)
			}
		case map[string]any:
			for _, e := range y {
				walk(e)
			}
		}
	}
	walk(v)
	all, best := texts.String(), ""
	for req := range replies {
		if len(req) > len(best) && strings.Contains(all, req) {
			best = req
		}
	}
	if best == "" {
		return "{}", false
	}
	return replies[best], true
}
