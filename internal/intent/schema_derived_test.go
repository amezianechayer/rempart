package intent_test

import (
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// Paths from this package directory (internal/intent) to the canonical IR
// schema and to the reference schema of the intent-to-spec skill.
const (
	irSchemaPath         = "../../schemas/intent/v1.json"
	skillReferenceIRPath = "../../.claude/skills/intent-to-spec/references/intent-ir-v1.schema.json"
)

// TestSchemaDerivedFromReference: ADR 0006 decision 1, table 5.1 of the plan.
// schemas/intent/v1.json is the skill reference with exactly the listed
// deviations, and every object schema refuses additional properties.
func TestSchemaDerivedFromReference(t *testing.T) {
	got := decodeTree(t, readRepoFile(t, irSchemaPath))
	ref := decodeTree(t, readRepoFile(t, skillReferenceIRPath))

	deviations := map[string]any{
		"/properties/tenant_id": map[string]any{
			"type":    "string",
			"pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
		},
		"/properties/assumptions/items/properties/value": map[string]any{
			"type": "string", "minLength": float64(1), "maxLength": float64(200),
		},
		"/properties/open_questions/items/properties/default": map[string]any{
			"type": "string", "minLength": float64(1), "maxLength": float64(200),
		},
		"/properties/data/items/properties/id": map[string]any{
			"type": "string", "pattern": "^[a-z][a-z0-9-]{1,40}$",
		},
	}
	for ptr, want := range deviations {
		if v, ok := lookup(got, ptr); !ok || !reflect.DeepEqual(v, want) {
			t.Errorf("v1.json at %s: got %v, want %v", ptr, v, want)
		}
		if v, _ := lookup(ref, ptr); reflect.DeepEqual(v, want) {
			t.Errorf("reference at %s already equals the deviation: table 5.1 is stale", ptr)
		}
		if !replace(ref, ptr, want) {
			t.Fatalf("reference schema has no node at %s", ptr)
		}
	}
	for _, d := range diff("", ref, got) {
		t.Errorf("v1.json deviates from the reference outside table 5.1 at %s", d)
	}

	walkObjects("", got, func(ptr string, n map[string]any) {
		if ap, ok := n["additionalProperties"].(bool); !ok || ap {
			t.Errorf("v1.json object schema at %q: additionalProperties must be false", ptr)
		}
	})
}

func readRepoFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func splitPointer(ptr string) []string {
	return strings.Split(strings.TrimPrefix(ptr, "/"), "/")
}

func lookup(v any, ptr string) (any, bool) {
	for _, s := range splitPointer(ptr) {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		if v, ok = m[s]; !ok {
			return nil, false
		}
	}
	return v, true
}

// replace sets the node at ptr, whose parent must exist, to val.
func replace(v any, ptr string, val any) bool {
	segs := splitPointer(ptr)
	parent, ok := lookup(v, "/"+strings.Join(segs[:len(segs)-1], "/"))
	if len(segs) == 1 {
		parent, ok = v, true
	}
	m, isMap := parent.(map[string]any)
	if !ok || !isMap {
		return false
	}
	if _, ok := m[segs[len(segs)-1]]; !ok {
		return false
	}
	m[segs[len(segs)-1]] = val
	return true
}

// diff returns the JSON pointers where a and b differ (deepest differing node).
func diff(ptr string, a, b any) []string {
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if aok && bok {
		var out []string
		for k := range am {
			out = append(out, diff(ptr+"/"+k, am[k], bm[k])...)
		}
		for k := range bm {
			if _, ok := am[k]; !ok {
				out = append(out, ptr+"/"+k)
			}
		}
		return out
	}
	al, aok := a.([]any)
	bl, bok := b.([]any)
	if aok && bok && len(al) == len(bl) {
		var out []string
		for i := range al {
			out = append(out, diff(ptr+"/"+strconv.Itoa(i), al[i], bl[i])...)
		}
		return out
	}
	if !reflect.DeepEqual(a, b) {
		return []string{ptr}
	}
	return nil
}

// walkObjects calls f on every subschema whose type is object, root included.
func walkObjects(ptr string, v any, f func(string, map[string]any)) {
	switch n := v.(type) {
	case map[string]any:
		if n["type"] == "object" {
			f(ptr, n)
		}
		for k, c := range n {
			walkObjects(ptr+"/"+k, c, f)
		}
	case []any:
		for i, c := range n {
			walkObjects(ptr+"/"+strconv.Itoa(i), c, f)
		}
	}
}
