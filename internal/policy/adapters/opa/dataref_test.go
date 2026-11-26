package opa

import (
	"errors"
	"strings"
	"testing"

	opaast "github.com/open-policy-agent/opa/v1/ast"
)

// Reasons of the two barriers of obligation (fk), distinct so that a test
// tells which one refused (obligation (hd), review of M3-T01).
const (
	foreignRefReason  = "data reference outside the pack"             // checkModule, before compilation
	compiledRefReason = "compiled reference to data outside the pack" // checkCompiledDataRefs
)

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

// headRefForms are rules whose head reference holds a data reference outside
// the pack (second pass of the review of M3-T01): OPA's AST visitor does not
// walk Head.Reference, so a barrier must walk it itself.
var headRefForms = map[string]string{
	"multi_value_head":    "h[data.rempart.design_test.h.on] contains 1\n",
	"single_value_head":   "h[data.rempart.design_test.h.on].z := true\n",
	"function_head":       "a[data.rempart.iac.k].f(x) := x\n",
	"else_chain_value":    "e.x := 1 if {\n\tcount(input.graph.nodes) == 1\n} else := data.rempart.iac.v\n",
	"nested_head_term":    "n[[data.rempart.iac.k][0]] contains 1\n",
	"head_object_index":   "o[{\"k\": data.rempart.design_test.v}[\"k\"]] contains 1\n",
	"head_with_body_data": "w[n.id] contains y if {\n\tsome n in input.graph.nodes\n\ty := data.rempart.iac.v\n}\n",
}

// TestSourceBarrierWalksRuleHeads proves obligation (hd): the barrier before
// compilation (checkModule), alone, refuses a data reference outside the pack
// held in the head reference of a rule, an else chain included, with its own
// reason; a head reference that reads input is admitted.
func TestSourceBarrierWalksRuleHeads(t *testing.T) {
	parse := func(t *testing.T, src string) *opaast.Module {
		t.Helper()
		m, err := opaast.ParseModuleWithOpts("t.rego", "package rempart.design.t\n\n"+src, opaast.ParserOptions{
			ProcessAnnotation: true, RegoVersion: opaast.RegoV1, Capabilities: capabilities(),
		})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return m
	}
	for name, src := range headRefForms {
		t.Run("refused_"+name, func(t *testing.T) {
			err := checkModule(parse(t, src))
			if !errors.Is(err, ErrPackInvalid) || !strings.Contains(err.Error(), foreignRefReason) {
				t.Fatalf("checkModule = %v; want ErrPackInvalid, %q (the head reference is not walked)", err, foreignRefReason)
			}
		})
		t.Run("engine_refused_"+name, func(t *testing.T) {
			files := map[string]string{"t.rego": module("t", meta("TST-001", "high", "escalate"), computeBody) + "\n" + src}
			e, err := newEngine(pack(files), DefaultOptions)
			if e != nil || !errors.Is(err, ErrPackInvalid) || !strings.Contains(err.Error(), foreignRefReason) {
				t.Fatalf("newEngine = %v, %v; want the source barrier (%q)", e, err, foreignRefReason)
			}
		})
	}
	t.Run("admitted_input_head", func(t *testing.T) {
		if err := checkModule(parse(t, "h[n.id] contains 1 if {\n\tsome n in input.graph.nodes\n}\n\nk[x.id] := 1 if {\n\tsome x in input.graph.nodes\n}\n")); err != nil {
			t.Fatalf("checkModule = %v; a head reference on input is admitted", err)
		}
	})
}

// engineCompile compiles files with the options of newEngine (strict mode,
// capabilities, input schema, no print), the source barrier skipped: the
// second barrier is then the only one on the path.
func engineCompile(t *testing.T, files map[string]string) *opaast.Compiler {
	t.Helper()
	modules := map[string]*opaast.Module{}
	for name, src := range files {
		m, err := opaast.ParseModuleWithOpts(name, src, opaast.ParserOptions{ProcessAnnotation: true, RegoVersion: opaast.RegoV1, Capabilities: capabilities()})
		if err != nil {
			t.Fatal(err)
		}
		modules[name] = m
	}
	ss, err := inputSchema()
	if err != nil {
		t.Fatal(err)
	}
	c := opaast.NewCompiler().WithStrict(true).WithCapabilities(capabilities()).WithEnablePrintStatements(false).WithSchemas(ss)
	if c.Compile(modules); c.Failed() {
		t.Fatalf("compile: %v", c.Errors)
	}
	return c
}

// TestCompiledDataRefsChecked proves the second barrier of obligation (fk)
// alone (obligation (hd)): on modules compiled with the options of the engine,
// none of them foreign (every module is package rempart.design.t),
// checkCompiledDataRefs refuses a data reference outside the pack, in a body,
// a composite head, a comprehension, a call or a rule head reference, with
// its own reason; it admits a reference inside the pack and the compiled
// design pack.
func TestCompiledDataRefsChecked(t *testing.T) {
	const header = "package rempart.design.t\n\n"
	refused := map[string]string{
		"direct":        "ok if {\n\tx := data.rempart.iac.lib.secret\n\tx != \"\"\n}\n",
		"head_array":    "ok if {\n\tx := [data.rempart.iac.lib.secret][0]\n\tx != \"\"\n}\n",
		"comprehension": "ok if {\n\tx := [y | y := data.rempart.iac.lib.secret][0]\n\tx != \"\"\n}\n",
		"call":          "ok if {\n\tx := object.union({\"s\": data.rempart.iac.lib.secret}, {})[\"s\"]\n\tx != \"\"\n}\n",
		"test_package":  "ok if {\n\tdata.rempart.design_test.lib.base\n}\n",
	}
	for name, src := range headRefForms {
		refused["rule_"+name] = src
	}
	for name, src := range refused {
		t.Run("refused_"+name, func(t *testing.T) {
			err := checkCompiledDataRefs(engineCompile(t, map[string]string{"t.rego": header + src}))
			if !errors.Is(err, ErrPackInvalid) || !strings.Contains(err.Error(), compiledRefReason) {
				t.Fatalf("checkCompiledDataRefs = %v; want ErrPackInvalid, %q", err, compiledRefReason)
			}
		})
	}
	t.Run("admitted_own_pack", func(t *testing.T) {
		files := map[string]string{
			"lib.rego": "package rempart.design.lib\n\ny := 1\n",
			"t.rego":   header + "ok if {\n\tdata.rempart.design.lib.y == 1\n}\n\nh[n.id] contains 1 if {\n\tsome n in input.graph.nodes\n}\n",
		}
		if err := checkCompiledDataRefs(engineCompile(t, files)); err != nil {
			t.Fatalf("checkCompiledDataRefs = %v; a reference inside the pack is admitted", err)
		}
	})
	t.Run("admitted_design_pack", func(t *testing.T) {
		if _, err := NewDesign(); err != nil {
			t.Fatalf("NewDesign: %v; the design pack reads data.rempart.design only", err)
		}
	})
}
