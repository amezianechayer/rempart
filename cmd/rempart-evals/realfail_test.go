package main

import (
	"bytes"
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
		// Review of the M1 milestone: a response that the provider adapter
		// accepts but llm.Client refuses (model other than the route) is a
		// failed call too.
		"model_mismatch": {http.StatusOK, `{"id":"gen-1","model":"openai/gpt-4o","provider":"OpenAI","choices":[{"index":0,"finish_reason":"stop",` +
			`"message":{"role":"assistant","content":"{}"}}],"usage":{"prompt_tokens":10,"completion_tokens":2}}`, "modèle de la réponse différent ×3"},
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

// TestCalibrationBelowCriterionRefused (review of the M1 milestone): every
// call succeeds but the drafts fail the case; a real calibration under the
// bar of criterion 1 of M1 (success 0.9, injection resistance 1) writes
// nothing.
func TestCalibrationBelowCriterionRefused(t *testing.T) {
	var draft bytes.Buffer
	if err := json.Compact(&draft, intentFixture(t, "reference-draft.json")); err != nil {
		t.Fatal(err)
	}
	content, err := json.Marshal(draft.String())
	if err != nil {
		t.Fatal(err)
	}
	reply := `{"id":"gen-1","model":"openai/gpt-4o-2024-08-06","provider":"OpenAI","choices":[{"index":0,"finish_reason":"stop",` +
		`"message":{"role":"assistant","content":` + string(content) + `}}],"usage":{"prompt_tokens":120,"completion_tokens":60}}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(ts.Close)
	realBaseURL = ts.URL + "/api/v1"
	t.Cleanup(func() { realBaseURL = "" })
	dir := oneCaseRepo(t)
	e := newEnv(t, dir, noGit(t))
	e.environ = append(e.environ, apikey.EnvOpenRouter+"=sk-or-v1-CANARY-below-5b2e")
	e.confirm = func(string) bool { return true }
	code, _, stderr := runArgs(t, e, "--suite", "intent", "--llm", "openrouter", "--model", "openai/gpt-4o-2024-08-06", "--write-baseline")
	if code == codeOK || !strings.Contains(stderr, "sous le seuil") || strings.Contains(stderr, "échecs du fournisseur") {
		t.Errorf("code %d, stderr %q; want a calibration refused under the threshold, without provider failure", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "evals", "intent", "baseline")); !os.IsNotExist(err) {
		t.Errorf("a calibration under the threshold wrote a baseline: %v", err)
	}
}

// TestRealMeasurementRequiresTTY (review of the M1 milestone, T106): the
// measurement of a real route bills calls too; without a confirmation of the
// human on the terminal it sends nothing.
func TestRealMeasurementRequiresTTY(t *testing.T) {
	var calls atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(ts.Close)
	realBaseURL = ts.URL + "/api/v1"
	t.Cleanup(func() { realBaseURL = "" })
	dir := oneCaseRepo(t)
	e := newEnv(t, dir, noGit(t))
	e.environ = append(e.environ, apikey.EnvOpenRouter+"=sk-or-v1-CANARY-measure-9f3c")
	asked := ""
	e.confirm = func(prompt string) bool { asked = prompt; return false }
	code, stdout, _ := runArgs(t, e, "--suite", "intent", "--llm", "openrouter", "--model", "openai/gpt-4o-2024-08-06")
	if code != codeUsage || stdout != "" || calls.Load() != 0 || !strings.Contains(asked, "openai/gpt-4o-2024-08-06") {
		t.Errorf("code %d, stdout %q, %d calls, prompt %q; want %d, no call, a prompt naming the route", code, stdout, calls.Load(), asked, codeUsage)
	}
	e.confirm = nil
	if code, _, _ := runArgs(t, e, "--suite", "intent", "--llm", "openrouter", "--model", "openai/gpt-4o-2024-08-06"); code != codeUsage || calls.Load() != 0 {
		t.Errorf("no confirmation available: code %d, %d calls; want %d and no call", code, calls.Load(), codeUsage)
	}
}
