package opa

import (
	"errors"
	"strings"
	"testing"

	opaast "github.com/open-policy-agent/opa/v1/ast"
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
		// Review of M3-T01 (high, T108, T109): a reference whose head is a
		// composite term (array, object, set, comprehension, call) hides the
		// data reference inside its head.
		"head_array":                withRef("x := [data.rempart.iac][0]\n\tx != null"),
		"head_object":               withRef("x := {\"a\": data.rempart.iac}[\"a\"]\n\tx != null"),
		"head_set":                  withRef("x := {data.rempart.iac}[_]\n\tx != null"),
		"head_array_comprehension":  withRef("x := [y | y := data.rempart.iac][0]\n\tx != null"),
		"head_object_comprehension": withRef("x := {k: v | some k, v in data.rempart.iac}[_]\n\tx != null"),
		"head_set_comprehension":    withRef("x := {y | some y in data.rempart.iac}[_]\n\tx != null"),
		"head_call":                 withRef("x := object.union(data.rempart.iac, {})[_]\n\tx != null"),
		"every_composite_domain":    withRef("every y in [data.rempart.iac][0] { y }"),
		"test_package_composite":    withRef("[v | v := data.rempart.design_test.h.on][0]"),
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

// TestCompiledDataRefsChecked proves the second barrier of obligation (fk)
// (review of M3-T01, defense in depth): on the compiled modules (imports
// resolved, comprehensions rewritten), checkCompiledDataRefs refuses a data
// reference outside the pack whatever the form that produced it, and admits
// the compiled design pack of the repository.
func TestCompiledDataRefsChecked(t *testing.T) {
	compile := func(t *testing.T, files map[string]string) *opaast.Compiler {
		t.Helper()
		modules := map[string]*opaast.Module{}
		for name, src := range files {
			m, err := opaast.ParseModuleWithOpts(name, src, opaast.ParserOptions{ProcessAnnotation: true, RegoVersion: opaast.RegoV1})
			if err != nil {
				t.Fatal(err)
			}
			modules[name] = m
		}
		c := opaast.NewCompiler()
		if c.Compile(modules); c.Failed() {
			t.Fatalf("compile: %v", c.Errors)
		}
		return c
	}
	iac := "package rempart.iac.lib\n\nsecret := \"s\"\n"
	for name, body := range map[string]string{
		"direct":        "\tx := data.rempart.iac.lib.secret\n\tx != \"\"",
		"head_array":    "\tx := [data.rempart.iac.lib.secret][0]\n\tx != \"\"",
		"comprehension": "\tx := [y | y := data.rempart.iac.lib.secret][0]\n\tx != \"\"",
		"call":          "\tx := object.union({\"s\": data.rempart.iac.lib.secret}, {})[\"s\"]\n\tx != \"\"",
	} {
		t.Run("refused_"+name, func(t *testing.T) {
			c := compile(t, map[string]string{"iac.rego": iac, "t.rego": "package rempart.design.t\n\nok if {\n" + body + "\n}\n"})
			err := checkCompiledDataRefs(c)
			if !errors.Is(err, ErrPackInvalid) || !strings.Contains(err.Error(), foreignRefReason) {
				t.Fatalf("checkCompiledDataRefs = %v; want ErrPackInvalid, %q", err, foreignRefReason)
			}
		})
	}
	t.Run("admitted_design_pack", func(t *testing.T) {
		if _, err := NewDesign(); err != nil {
			t.Fatalf("NewDesign: %v; the design pack reads data.rempart.design only", err)
		}
	})
}
