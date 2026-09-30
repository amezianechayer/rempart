package domain

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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
	b, err := os.ReadFile(filepath.Join(testdataDir, name))
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
func draftFrom(t *testing.T, name string, edit func(m map[string]any)) Draft {
	t.Helper()
	m := loadMap(t, name)
	if edit != nil {
		edit(m)
	}
	var d Draft
	decodeInto(t, m, &d)
	return d
}

// irFrom loads an IR fixture, applies edit (if any) and decodes it.
func irFrom(t *testing.T, name string, edit func(m map[string]any)) IR {
	t.Helper()
	m := loadMap(t, name)
	if edit != nil {
		edit(m)
	}
	var ir IR
	decodeInto(t, m, &ir)
	return ir
}

// item returns the object at index i of the array under key in m.
func item(m map[string]any, key string, i int) map[string]any {
	return m[key].([]any)[i].(map[string]any)
}

// setAssumption sets the value of the assumption on field, adding it if absent.
func setAssumption(m map[string]any, field, value string) {
	list, _ := m["assumptions"].([]any)
	for _, a := range list {
		if o := a.(map[string]any); o["field"] == field {
			o["value"] = value
			return
		}
	}
	m["assumptions"] = append(list, map[string]any{"field": field, "value": value, "rationale": "choisi par le modèle"})
}

// dropAssumption removes every assumption on field.
func dropAssumption(m map[string]any, field string) {
	list, _ := m["assumptions"].([]any)
	kept := []any{}
	for _, a := range list {
		if a.(map[string]any)["field"] != field {
			kept = append(kept, a)
		}
	}
	m["assumptions"] = kept
}

// atLeastMedium keeps the findings that block L1 (success_when: none of them).
func atLeastMedium(fs []loopsdomain.Finding) []loopsdomain.Finding {
	var out []loopsdomain.Finding
	for _, f := range fs {
		if f.Severity.Weight() >= loopsdomain.SeverityMedium.Weight() {
			out = append(out, f)
		}
	}
	return out
}

// hasFinding reports a finding of code and severity; resource "" matches any.
func hasFinding(fs []loopsdomain.Finding, code string, sev loopsdomain.Severity, resource string) bool {
	for _, f := range fs {
		if f.Code == code && f.Severity == sev && (resource == "" || f.Resource == resource) {
			return true
		}
	}
	return false
}
