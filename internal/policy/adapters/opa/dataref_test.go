package opa

import (
	"errors"
	"strings"
	"testing"
)

// foreignRefReason is the reason of the barrier for obligation (fk).
const foreignRefReason = "data reference outside the pack"

// withRef is the test deny rule reading extra after its output is bound.
func withRef(extra string) map[string]string {
	return map[string]string{"t.rego": module("t", meta("TST-001", "high", "escalate"), computeBody+"\n\t"+extra)}
}

// TestEngineRefusesForeignDataRefs proves obligation (fk) (ADR 0011 D3, T109):
// before compilation, the barrier refuses every reference to data outside
// data.rempart.<compiled pack> (bare data, an index on data or on rempart, the
// root rempart, another pack, a test package), in a rule body, a helper rule,
// a comprehension, an every domain, an index or an import; references inside
// the pack, imported or direct, stay admitted.
func TestEngineRefusesForeignDataRefs(t *testing.T) {
	const header = "package rempart.design.t\n\n"
	refused := map[string]map[string]string{
		"bare_data":       withRef("x := data\n\tx != null"),
		"data_index":      withRef("x := data[_]\n\tx != null"),
		"data_rempart":    withRef("x := data.rempart\n\tx != null"),
		"rempart_index":   withRef("p := \"iac\"\n\tx := data.rempart[p]\n\tx != null"),
		"other_pack":      withRef("x := data.rempart.iac\n\tx != null"),
		"other_pack_rule": withRef("data.rempart.iac.lib.y"),
		"test_package":    withRef("x := data.rempart.design_test\n\tx != null"),
		"comprehension":   withRef("x := [y | some y in data.rempart.k8s]\n\tcount(x) >= 0"),
		"every_domain":    withRef("every y in data.rempart.iac { y }"),
		"in_index":        withRef("x := input.graph.nodes[data.rempart.iac.i]\n\tx != null"),
		"helper_rule": {"t.rego": module("t", meta("TST-001", "high", "escalate"), computeBody) +
			"\nhelper := data.rempart.runtime\n"},
		"import_other_pack": {"t.rego": header + "import data.rempart.iac.lib\n\n" + meta("TST-001", "high", "escalate") +
			"deny contains f if {\n" + computeBody + "\n\tlib.y\n}\n"},
		"import_root": {"t.rego": header + "import data\n\n" + meta("TST-001", "high", "escalate") +
			"deny contains f if {\n" + computeBody + "\n\tdata.y\n}\n"},
	}
	for name, files := range refused {
		t.Run("refused_"+name, func(t *testing.T) {
			e, err := newEngine(pack(files), DefaultOptions)
			if !errors.Is(err, ErrPackInvalid) || e != nil {
				t.Fatalf("newEngine = %v, %v; want ErrPackInvalid", e, err)
			}
			if !strings.Contains(err.Error(), foreignRefReason) {
				t.Fatalf("newEngine refused for another reason: %v; want %q", err, foreignRefReason)
			}
		})
	}

	lib := "package rempart.design.lib\n\nis_compute(n) if n.kind == \"Compute\"\n"
	admitted := map[string]map[string]string{
		"own_pack_import": {"lib.rego": lib, "t.rego": header + "import data.rempart.design.lib\n\n" + meta("TST-001", "high", "escalate") +
			"deny contains f if {\n\tsome n in input.graph.nodes\n\tlib.is_compute(n)\n\tmeta := rego.metadata.rule()\n" +
			"\tf := {\"control_id\": meta.custom.control_id, \"resource\": n.id}\n}\n"},
		"own_pack_direct": {"lib.rego": lib, "t.rego": header + meta("TST-001", "high", "escalate") +
			"deny contains f if {\n\tsome n in input.graph.nodes\n\tdata.rempart.design.lib.is_compute(n)\n\tmeta := rego.metadata.rule()\n" +
			"\tf := {\"control_id\": meta.custom.control_id, \"resource\": n.id}\n}\n"},
	}
	for name, files := range admitted {
		t.Run("admitted_"+name, func(t *testing.T) {
			if _, err := newEngine(pack(files), DefaultOptions); err != nil {
				t.Fatalf("newEngine: %v; a reference inside the pack is admitted", err)
			}
		})
	}
}
