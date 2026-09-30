package domain

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"testing"

	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
)

// Shared fixtures live in internal/intent/testdata (plan M1-intent-ir, section 9).
const testdataDir = "../testdata"

// Workload indices of testdata/reference-draft.json.
const (
	wAppCluster = 0
	wLegacyVMs  = 1
	wObs        = 2
	wGitops     = 3
)

func readText(t *testing.T, name string) string {
	t.Helper()
	b, err := fs.ReadFile(os.DirFS(testdataDir), name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// loadMap decodes a JSON fixture into a generic tree, to be edited by a test
// case before being decoded into a Draft or an IR.
func loadMap(t *testing.T, name string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(readText(t, name)), &m); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	return m
}

// decodeInto decodes the tree m into out with unknown fields refused, the last
// step of intent.ParseDraft (plan P2).
func decodeInto(t *testing.T, m map[string]any, out any) {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		t.Fatalf("decode fixture into %T: %v", out, err)
	}
}

// draftFrom loads a draft fixture, applies edit (if any) and decodes it.
func draftFrom(t *testing.T, name string, edit func(t *testing.T, m map[string]any)) Draft {
	t.Helper()
	m := loadMap(t, name)
	if edit != nil {
		edit(t, m)
	}
	var d Draft
	decodeInto(t, m, &d)
	return d
}

// irFrom loads an IR fixture, applies edit (if any) and decodes it.
func irFrom(t *testing.T, name string, edit func(t *testing.T, m map[string]any)) IR {
	t.Helper()
	m := loadMap(t, name)
	if edit != nil {
		edit(t, m)
	}
	var ir IR
	decodeInto(t, m, &ir)
	return ir
}

// obj returns the object under key in m, failing the test otherwise.
func obj(t *testing.T, m map[string]any, key string) map[string]any {
	t.Helper()
	o, ok := m[key].(map[string]any)
	if !ok {
		t.Fatalf("fixture: %q is not an object", key)
	}
	return o
}

// list returns the array under key in m, failing the test otherwise.
func list(t *testing.T, m map[string]any, key string) []any {
	t.Helper()
	l, ok := m[key].([]any)
	if !ok {
		t.Fatalf("fixture: %q is not an array", key)
	}
	return l
}

// str returns the string under key in m, failing the test otherwise.
func str(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	s, ok := m[key].(string)
	if !ok {
		t.Fatalf("fixture: %q is not a string", key)
	}
	return s
}

// item returns the object at index i of the array under key in m.
func item(t *testing.T, m map[string]any, key string, i int) map[string]any {
	t.Helper()
	l := list(t, m, key)
	if i >= len(l) {
		t.Fatalf("fixture: %q has no index %d", key, i)
	}
	o, ok := l[i].(map[string]any)
	if !ok {
		t.Fatalf("fixture: %q[%d] is not an object", key, i)
	}
	return o
}

// setAssumption sets the value of the assumption on field, adding it if absent.
func setAssumption(t *testing.T, m map[string]any, field, value string) {
	t.Helper()
	l := list(t, m, "assumptions")
	for i := range l {
		if a := item(t, m, "assumptions", i); a["field"] == field {
			a["value"] = value
			return
		}
	}
	m["assumptions"] = append(l, map[string]any{"field": field, "value": value, "rationale": "choisi par le modèle"})
}

// dropAssumption removes every assumption on field.
func dropAssumption(t *testing.T, m map[string]any, field string) {
	t.Helper()
	kept := []any{}
	for i, a := range list(t, m, "assumptions") {
		if item(t, m, "assumptions", i)["field"] != field {
			kept = append(kept, a)
		}
	}
	m["assumptions"] = kept
}

// atLeastMedium keeps the findings that block L1 (success_when: none of them).
func atLeastMedium(findings []loopsdomain.Finding) []loopsdomain.Finding {
	var out []loopsdomain.Finding
	for _, f := range findings {
		if f.Severity.Weight() >= loopsdomain.SeverityMedium.Weight() {
			out = append(out, f)
		}
	}
	return out
}

// hasFinding reports a finding of code and severity; resource "" matches any.
func hasFinding(findings []loopsdomain.Finding, code string, sev loopsdomain.Severity, resource string) bool {
	for _, f := range findings {
		if f.Code == code && f.Severity == sev && (resource == "" || f.Resource == resource) {
			return true
		}
	}
	return false
}
