package opa

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	opaast "github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown/print"

	"github.com/amezianechayer/rempart/policies"
)

// captureModule replaces lib.ko and lib.ok of the tests of the design pack:
// each call prints its control and its input instead of evaluating the pack.
const captureModule = `package rempart.capture

capko(id, inp) if print(json.marshal({"kind": "ko", "id": id, "input": inp}))

capok(id, inp) if print(json.marshal({"kind": "ok", "id": id, "input": inp}))
`

// printSink collects the lines printed by the capture module.
type printSink struct {
	mu    sync.Mutex
	lines []string
}

func (p *printSink) Print(_ print.Context, msg string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lines = append(p.lines, msg)
	return nil
}

type capturedCase struct {
	Kind  string          `json:"kind"`
	ID    string          `json:"id"`
	Input json.RawMessage `json:"input"`
}

var testRuleRe = regexp.MustCompile(`^test_[a-z0-9_]+$`)

// TestRegoCasesReplayedByEngine proves obligation (gz) (T153): every ok and
// ko case of the Rego tests of the design pack, run by opa test, gives the
// same verdict when its input is evaluated by the engine itself (the pack as
// newEngine reads, checks and compiles it, and the prepared query of
// Evaluate). A divergence between opa test and the engine (a rule file the
// engine skips, a deny rule that reads a test package, a compiler option)
// fails here. The cases are captured by replacing lib.ko and lib.ok, with
// the with keyword, by functions that print their arguments.
func TestRegoCasesReplayedByEngine(t *testing.T) {
	e, err := NewDesign()
	if err != nil {
		t.Fatal(err)
	}
	modules := map[string]*opaast.Module{}
	var tests []opaast.Ref
	err = fs.WalkDir(policies.Design, "design", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		src, err := fs.ReadFile(policies.Design, p)
		if err != nil {
			return err
		}
		m, err := opaast.ParseModuleWithOpts(p, string(src), opaast.ParserOptions{ProcessAnnotation: true, RegoVersion: opaast.RegoV1})
		if err != nil {
			return err
		}
		modules[p] = m
		// lib_test.rego holds the helpers and their own tests (ko and ok
		// disagree, for instance), which the capture replaces by definition:
		// only the tests of the controls are replayed.
		if strings.HasSuffix(p, "_test.rego") && p != "design/lib_test.rego" {
			for _, r := range m.Rules {
				if name := r.Head.Name.String(); testRuleRe.MatchString(name) && !slices.ContainsFunc(tests, func(x opaast.Ref) bool {
					return x.Equal(m.Package.Path.Append(opaast.StringTerm(name)))
				}) {
					tests = append(tests, m.Package.Path.Append(opaast.StringTerm(name)))
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	capture, err := opaast.ParseModuleWithOpts("capture.rego", captureModule, opaast.ParserOptions{RegoVersion: opaast.RegoV1})
	if err != nil {
		t.Fatal(err)
	}
	modules["capture.rego"] = capture
	c := opaast.NewCompiler().WithEnablePrintStatements(true)
	if c.Compile(modules); c.Failed() {
		t.Fatalf("compile the pack, its tests and the capture module: %v", c.Errors)
	}
	if len(tests) < 100 {
		t.Fatalf("%d test rules found, want the tests of the design pack", len(tests))
	}

	kos, oks := 0, 0
	for _, test := range tests {
		name := test.String()
		t.Run(strings.TrimPrefix(name, "data.rempart.design_test."), func(t *testing.T) {
			sink := &printSink{}
			q := name + " with data.rempart.design_test.lib.ko as data.rempart.capture.capko" +
				" with data.rempart.design_test.lib.ok as data.rempart.capture.capok"
			rs, err := rego.New(rego.Compiler(c), rego.Query(q), rego.EnablePrintStatements(true), rego.PrintHook(sink)).Eval(context.Background())
			if err != nil || len(rs) != 1 {
				t.Fatalf("eval %s with the capture: %v, %d results", name, err, len(rs))
			}
			if len(sink.lines) == 0 {
				t.Skipf("%s calls neither lib.ko nor lib.ok", name)
			}
			for _, line := range sink.lines {
				var cc capturedCase
				if err := json.Unmarshal([]byte(line), &cc); err != nil {
					t.Fatalf("captured line: %v", err)
				}
				fired := engineFires(t, e, cc.Input, cc.ID)
				switch {
				case cc.Kind == "ko" && !fired:
					t.Errorf("%s: %s fires under opa test (ko case) and not in the engine (T153)", name, cc.ID)
				case cc.Kind == "ok" && fired:
					t.Errorf("%s: %s does not fire under opa test (ok case) and fires in the engine (T153)", name, cc.ID)
				}
				if cc.Kind == "ko" {
					kos++
				} else {
					oks++
				}
			}
		})
	}
	if kos < 80 || oks < 50 {
		t.Errorf("%d ko and %d ok cases replayed, want every case of the tests of the design pack", kos, oks)
	}
}

// engineFires evaluates the prepared query of the engine on the raw input and
// reports whether control id is among its outputs.
func engineFires(t *testing.T, e *Engine, raw json.RawMessage, id string) bool {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("captured input: %v", err)
	}
	value, err := opaast.InterfaceToValue(doc)
	if err != nil {
		t.Fatalf("captured input: %v", err)
	}
	rs, err := e.pq.Eval(context.Background(), rego.EvalParsedInput(value))
	if err != nil {
		t.Fatalf("engine evaluation: %v", err)
	}
	for _, r := range rs {
		if obj, ok := r.Expressions[0].Value.(map[string]any); ok && obj["control_id"] == id {
			return true
		}
	}
	return false
}
