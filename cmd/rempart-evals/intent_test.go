package main

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/amezianechayer/rempart/internal/evals"
	"github.com/amezianechayer/rempart/internal/llm/apikey"
	"github.com/amezianechayer/rempart/internal/loops/l1"
)

// M1-T06 (lean mode): the intent target runs the loop L1 through the codec of
// Rempart, scripted by the replies of the case, or on a real model.

func intentFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := fs.ReadFile(os.DirFS("../../internal/intent/testdata"), name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// intentCase builds a case of the intent suite from a request and replies.
func intentCase(t *testing.T, request string, replies ...[]byte) evals.Case {
	t.Helper()
	rs := make([]json.RawMessage, 0, len(replies))
	for _, r := range replies {
		rs = append(rs, r)
	}
	in, err := json.Marshal(map[string]any{"request": request, "replies": rs})
	if err != nil {
		t.Fatal(err)
	}
	return evals.Case{ID: "intent-x", Loop: "L1-intent", Input: in, Expect: evals.Expect{Escalation: ptrBool(false)}, Runs: 1}
}

func ptrBool(b bool) *bool { return &b }

// TestIntentTargetRunsCase: the reference scenario converges into an IR of the
// evaluation tenant without invented value; the C4 injection obeyed by the
// model escalates, without IR and without the exposure.
func TestIntentTargetRunsCase(t *testing.T) {
	tg := intentTarget{log: io.Discard}
	if id := tg.Identity(); id != (Identity{Platform: "fake", Model: demoModel}) {
		t.Errorf("identity %+v", id)
	}
	ref := intentCase(t, string(intentFixture(t, "reference-request.txt")), intentFixture(t, "reference-draft.json"))
	if err := tg.Check(ref); err != nil {
		t.Fatalf("Check: %v", err)
	}
	o, err := tg.Run(context.Background(), ref, 0)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if o.Err != "" || o.Status != l1.StatusConverged || o.Escalated || !o.SchemaValid || o.Invented != 0 || o.Iterations != 1 {
		t.Fatalf("outcome %+v, want converged, schema valid, no invented value", o)
	}
	var out struct {
		IR struct {
			TenantID string `json:"tenant_id"`
		} `json:"ir"`
	}
	if err := json.Unmarshal(o.Output, &out); err != nil || out.IR.TenantID != string(demoTenant) {
		t.Errorf("output %s, %v; want the IR of the evaluation tenant", o.Output, err)
	}
	var top map[string]json.RawMessage // the grader reads max_open_questions at the top level
	if err := json.Unmarshal(o.Output, &top); err != nil || string(top["open_questions"]) != "[]" {
		t.Errorf("output %s: open_questions at the top level %q, want []", o.Output, top["open_questions"])
	}
	obey := intentFixture(t, "drafts/c4-obey-managed-db.json")
	c4 := intentCase(t, string(intentFixture(t, "c4-request.txt")), obey, obey, obey, obey)
	o, err = tg.Run(context.Background(), c4, 0)
	if err != nil {
		t.Fatalf("Run C4: %v", err)
	}
	if o.Status != l1.StatusEscalated || !o.Escalated || o.SchemaValid {
		t.Errorf("C4 outcome %+v, want escalated without IR", o)
	}
	if s := string(o.Output); strings.Contains(s, `"ir"`) || strings.Contains(s, "exposure") || strings.Contains(s, "demande d'exposition") {
		t.Errorf("C4 output carries a draft or an IR: %s", s)
	}
}

// TestIntentInputClosed: the input of a case is exactly request, an optional
// context and 1 to 8 replies, each an object of at most 16 KiB.
func TestIntentInputClosed(t *testing.T) {
	tg := intentTarget{log: io.Discard}
	reply := `{"summary":"x"}`
	for name, in := range map[string]string{
		"unknown_key":     `{"request":"Je veux un cluster.","replies":[` + reply + `],"tenant_id":"x"}`,
		"no_request":      `{"replies":[` + reply + `]}`,
		"empty_request":   `{"request":" ","replies":[` + reply + `]}`,
		"no_replies":      `{"request":"Je veux un cluster."}`,
		"zero_replies":    `{"request":"Je veux un cluster.","replies":[]}`,
		"nine_replies":    `{"request":"Je veux un cluster.","replies":[` + strings.Repeat(reply+",", 8) + reply + `]}`,
		"reply_not_obj":   `{"request":"Je veux un cluster.","replies":["x"]}`,
		"reply_too_large": `{"request":"Je veux un cluster.","replies":[{"summary":"` + strings.Repeat("a", 16<<10) + `"}]}`,
		"request_long":    `{"request":"` + strings.Repeat("a", 8<<10+1) + `","replies":[` + reply + `]}`,
		"context_key":     `{"request":"Je veux un cluster.","context":{"tenant":"x"},"replies":[` + reply + `]}`,
		"context_region":  `{"request":"Je veux un cluster.","context":{"allowed_regions":["EU WEST"]},"replies":[` + reply + `]}`,
		"not_object":      `[]`,
	} {
		c := evals.Case{ID: "intent-x", Loop: "L1-intent", Input: json.RawMessage(in), Runs: 1}
		if err := tg.Check(c); err == nil {
			t.Errorf("%s: input accepted", name)
		}
	}
	ok := `{"request":"Je veux un cluster.","context":{"allowed_regions":["eu-west-3"],"forbidden_clouds":["aws"],"compliance":["nis2"]},"replies":[` + reply + `]}`
	if err := tg.Check(evals.Case{ID: "intent-x", Loop: "L1-intent", Input: json.RawMessage(ok), Runs: 1}); err != nil {
		t.Errorf("valid input refused: %v", err)
	}
}

// TestWriteBaselineRequiresTTY (obligation (ed), D10): in real mode, writing
// the baseline (the calibration of a route) needs a confirmation of the human;
// refused, nothing runs and nothing is written.
func TestWriteBaselineRequiresTTY(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/go.mod", []byte("module x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir+"/evals/intent/cases", 0o700); err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, dir, noGit(t))
	e.environ = append(e.environ, apikey.EnvOpenRouter+"="+realKey)
	asked := ""
	e.confirm = func(prompt string) bool { asked = prompt; return false }
	code, stdout, stderr := runArgs(t, e, "--suite", "intent", "--llm", "openrouter", "--model", "openai/gpt-4o-2024-08-06", "--write-baseline")
	if code != codeUsage || stdout != "" || !strings.Contains(asked, "openai/gpt-4o-2024-08-06") {
		t.Errorf("code %d, stdout %q, prompt %q; want %d after a refused confirmation naming the route", code, stdout, asked, codeUsage)
	}
	if strings.Contains(stderr+asked, realKey) {
		t.Error("the key is printed")
	}
	if _, err := os.Stat(dir + "/evals/intent/baseline"); !os.IsNotExist(err) {
		t.Errorf("baseline directory created: %v", err)
	}
	e.confirm = nil
	if code, _, _ := runArgs(t, e, "--suite", "intent", "--llm", "openrouter", "--model", "openai/gpt-4o-2024-08-06", "--write-baseline"); code != codeUsage {
		t.Errorf("no confirmation available: code %d, want %d", code, codeUsage)
	}
}

// TestRealModeRefusedForAgentsAndCI (review of M1-T06): the real mode and
// any baseline write are refused when the environment is the one of an agent
// (Claude Code) or of a CI, before any confirmation or call.
func TestRealModeRefusedForAgentsAndCI(t *testing.T) {
	for _, v := range []string{"CLAUDECODE=1", "AI_AGENT=1", "CI=true", "GITHUB_ACTIONS=true"} {
		dir := t.TempDir()
		if err := os.WriteFile(dir+"/go.mod", []byte("module x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		e := newEnv(t, dir, noGit(t))
		e.environ = append(e.environ, apikey.EnvOpenRouter+"="+realKey, v)
		asked := false
		e.confirm = func(string) bool { asked = true; return true }
		if code, stdout, _ := runArgs(t, e, "--suite", "intent", "--llm", "openrouter", "--model", "openai/gpt-4o-2024-08-06"); code != codeUsage || stdout != "" || asked {
			t.Errorf("%s, real mode: code %d, stdout %q, asked %v; want %d before any confirmation", v, code, stdout, asked, codeUsage)
		}
	}
	dir := copyFixture(t, "missing")
	before := snapshot(t, dir)
	e := newEnv(t, dir, noGit(t))
	e.environ = append(e.environ, "CLAUDECODE=1")
	e.confirm = func(string) bool { return true }
	if code, _, _ := runArgs(t, e, "--suite", "demo", "--write-baseline"); code != codeUsage || !reflect.DeepEqual(snapshot(t, dir), before) {
		t.Errorf("baseline write under an agent: code %d, want %d and nothing written", code, codeUsage)
	}
}

// TestRealModeIntentTarget: the real mode runs the intent target on the
// OpenRouter route of the model.
func TestRealModeIntentTarget(t *testing.T) {
	ts, err := realTargets([]string{"PATH=/bin", apikey.EnvOpenRouter + "=" + realKey}, "openrouter", "openai/gpt-4o-2024-08-06")
	if err != nil {
		t.Fatal(err)
	}
	if id := ts["intent"].Identity(); id != (Identity{Platform: "openrouter", Model: "openai/gpt-4o-2024-08-06"}) {
		t.Errorf("intent identity %+v", id)
	}
	if !strings.Contains(string(mustJSON(t, targets()["intent"].Identity())), "fake") {
		t.Error("fake mode has no intent target")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
