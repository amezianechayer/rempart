package main

import (
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/amezianechayer/rempart/internal/llm/apikey"
)

// Calibration of 2026-11-18 (human, H-real): every call to the real model
// failed and the cause was invisible; the calibration still wrote a baseline.
// The real mode now counts the failures of the provider by class (an HTTP
// status or a fixed class name, never a body nor the key) and a calibration
// with any failed call writes nothing.

// oneCaseRepo is a repository with the intent suite reduced to one case.
func oneCaseRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := os.DirFS("../../evals/intent")
	for _, f := range []string{"suite.yaml", "cases/intent-incomplete-cluster.yaml"} {
		b, err := fs.ReadFile(src, f)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(dir, "evals", "intent", "cases"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "evals", "intent", f), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRealModeReportsFailureCauses(t *testing.T) {
	const canary = "sk-or-v1-CANARY-failure-3c9a"
	cases := map[string]struct {
		status int
		body   string
		want   string
	}{
		"unauthorized": {http.StatusUnauthorized, `{"error":{"message":"No auth credentials found ` + canary + `","code":401}}`, "HTTP 401 ×3"},
		"provider_mismatch": {http.StatusOK, `{"id":"gen-1","model":"openai/gpt-4o-2024-08-06","provider":"Azure","choices":[{"index":0,"finish_reason":"stop",` +
			`"message":{"role":"assistant","content":"{}"}}],"usage":{"prompt_tokens":10,"completion_tokens":2}}`, "fournisseur final différent ×3"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			t.Cleanup(ts.Close)
			realBaseURL = ts.URL + "/api/v1"
			t.Cleanup(func() { realBaseURL = "" })
			dir := oneCaseRepo(t)
			e := newEnv(t, dir, noGit(t))
			e.environ = append(e.environ, apikey.EnvOpenRouter+"="+canary)
			e.confirm = func(string) bool { return true }
			code, stdout, stderr := runArgs(t, e, "--suite", "intent", "--llm", "openrouter", "--model", "openai/gpt-4o-2024-08-06", "--write-baseline")
			if code == codeOK || !strings.Contains(stderr, tc.want) {
				t.Errorf("code %d, stderr %q; want a refused calibration reporting %q", code, stderr, tc.want)
			}
			if strings.Contains(stdout+stderr, "CANARY") || strings.Contains(stderr, "No auth credentials") {
				t.Errorf("output quotes the key or the body of the provider: %q", stdout+stderr)
			}
			if _, err := os.Stat(filepath.Join(dir, "evals", "intent", "baseline")); !os.IsNotExist(err) {
				t.Errorf("a calibration with failed calls wrote a baseline: %v", err)
			}
		})
	}
}
