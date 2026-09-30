package archtest

import (
	"slices"
	"testing"
)

// M0-T03b step B, plan docs/plans/M0-pile-dev-harden.md D6 and D7:
// obligations (bd) and (bf), threats T73 (bypass of the source rules) and T74.

const (
	clientImp   = `"go.temporal.io/sdk/client"`
	temporalImp = `"go.temporal.io/sdk/temporal"`
)

// goFile builds a Go file of package pkg with the given import lines.
func goFile(pkg string, imports []string, body string) string {
	s := "package " + pkg + "\n\n"
	if len(imports) > 0 {
		s += "import (\n"
		for _, i := range imports {
			s += "\t" + i + "\n"
		}
		s += ")\n\n"
	}
	return s + body
}

// expectNoViolation fails on any violation of the sources.
func expectNoViolation(t *testing.T, edits ...srcEdit) {
	t.Helper()
	for _, v := range checkSources(t, repoSources(t, edits...)) {
		t.Errorf("%s: %s: %s", v.Pos, v.Rule, v.Detail)
	}
}

// TestSearchAttributeKeysRefused (bd, D6): the memo and search attributes are
// set through a field of an SDK options literal as well as through a call. In
// workflow code, in any package under cmd/ and in any package with a file
// importing the SDK, a Memo, SearchAttributes or TypedSearchAttributes key of a
// composite literal is refused, and so is the selector.
func TestSearchAttributeKeysRefused(t *testing.T) {
	const opts = "type opts struct{ Memo map[string]string }\n\n"
	runSourceCases(t, "loops-no-search-attributes", "", []srcCase{
		sc("child_options_keyed_memo", "", "key Memo", beforeRun("\t_ = workflow.ChildWorkflowOptions{Memo: nil}")),
		sc("child_options_keyed_typed", "", "key TypedSearchAttributes",
			fx(`"go.temporal.io/sdk/workflow"`, "\"go.temporal.io/sdk/temporal\"\n\t\"go.temporal.io/sdk/workflow\""),
			beforeRun("\t_ = workflow.ChildWorkflowOptions{TypedSearchAttributes: temporal.NewSearchAttributes()}")),
		sc("child_options_pointer_untyped", "", "key SearchAttributes",
			beforeRun("\t_ = &workflow.ChildWorkflowOptions{WorkflowID: \"c\", SearchAttributes: nil}")),
		sc("start_options_in_cmd", "", "key Memo", addFile("cmd/rempart-worker/opts.go",
			goFile("main", []string{clientImp}, "var _ = client.StartWorkflowOptions{Memo: nil}\n"))),
		sc("schedule_action_in_cmd", "", "key SearchAttributes", addFile("cmd/rempart-worker/opts.go",
			goFile("main", []string{clientImp},
				"var _ = client.ScheduleOptions{ID: \"s\", Action: &client.ScheduleWorkflowAction{ID: \"w\"}, SearchAttributes: nil}\n"))),
		sc("schedule_typed_in_cmd", "", "key TypedSearchAttributes", addFile("cmd/rempart-worker/opts.go",
			goFile("main", []string{clientImp, temporalImp},
				"var _ = client.ScheduleWorkflowAction{ID: \"w\", TypedSearchAttributes: temporal.NewSearchAttributes()}\n"))),
		// ScheduleWorkflowAction has a fourth field that carries search
		// attributes (go.temporal.io/sdk v1.49.0, internal/schedule_client.go).
		sc("schedule_untyped_in_cmd", "", "key UntypedSearchAttributes", addFile("cmd/rempart-worker/opts.go",
			goFile("main", []string{clientImp},
				"var _ = client.ScheduleWorkflowAction{ID: \"w\", UntypedSearchAttributes: nil}\n"))),
		sc("schedule_untyped_selector_in_cmd", "", "UntypedSearchAttributes", addFile("cmd/rempart-worker/opts.go",
			goFile("main", []string{clientImp},
				"func f(a *client.ScheduleWorkflowAction) { a.UntypedSearchAttributes = nil }\n"))),
		// Under cmd/, without any SDK import: the options may be built in a
		// helper package and handed over later.
		sc("memo_key_in_cmd_without_sdk", "", "key Memo",
			addFile("cmd/rempart-tool/opts.go", goFile("main", nil, opts+"var _ = opts{Memo: nil}\n"))),
		sc("selector_in_cmd_without_sdk", "", "Memo",
			addFile("cmd/rempart-tool/opts.go", goFile("main", nil, opts+"func f(o opts) { _ = o.Memo }\n"))),
		sc("sdk_importer_outside_cmd", "", "key Memo", addFile("internal/other/opts.go",
			goFile("other", []string{clientImp}, "var _ = client.StartWorkflowOptions{Memo: nil}\n"))),
		sc("sdk_importer_renamed", "", "key Memo", addFile("internal/other/opts.go",
			goFile("other", []string{"tc " + clientImp}, "var _ = tc.StartWorkflowOptions{Memo: nil}\n"))),
		// The scope is the package: a sibling file importing the SDK brings
		// the file that builds the literal into it.
		sc("sdk_importer_sibling_file", "", "key Memo",
			addFile("internal/other/sdk.go", goFile("other", []string{"_ " + clientImp}, "")),
			addFile("internal/other/opts.go", goFile("other", nil, opts+"var _ = opts{Memo: nil}\n"))),
		sc("sdk_subpackage_importer", "", "key SearchAttributes", addFile("internal/other/opts.go",
			goFile("other", []string{"_ " + temporalImp},
				"type opts struct{ SearchAttributes map[string]any }\n\nvar _ = opts{SearchAttributes: nil}\n"))),
	})
	runSourceCases(t, "loops-keyed-literals", "composite literal element without field name", []srcCase{
		sc("start_options_unkeyed_in_cmd", "", "", addFile("cmd/rempart-worker/opts.go",
			goFile("main", []string{clientImp}, "var _ = client.StartWorkflowOptions{\"id\", \"q\"}\n"))),
		sc("module_struct_unkeyed_in_cmd", "", "", addFile("cmd/rempart-tool/pair.go",
			goFile("main", nil, "type pair struct{ a, b string }\n\nvar _ = pair{\"a\", \"b\"}\n"))),
	})
	t.Run("conforming", func(t *testing.T) {
		expectNoViolation(t,
			// Outside the scope: no SDK import, not under cmd/, not workflow code.
			addFile("internal/other/note.go", goFile("other", nil,
				"type note struct{ Memo string }\n\nvar _ = note{Memo: \"x\"}\n\n"+
					"func f(n note) string { return n.Memo }\n\ntype pair struct{ a, b string }\n\nvar _ = pair{\"a\", \"b\"}\n")),
			// cmdx is not cmd.
			addFile("cmdx/tool/opts.go", goFile("tool", nil, opts+"var _ = opts{Memo: nil}\n")),
			// Keyed options without memo or search attributes, and a map with
			// a string key.
			addFile("cmd/rempart-worker/opts.go", goFile("main", []string{clientImp},
				"var _ = client.StartWorkflowOptions{ID: \"x\"}\n\nvar _ = map[string]string{\"Memo\": \"x\"}\n\n"+
					"var _ = []string{\"Memo\", \"SearchAttributes\"}\n")))
	})
}

// TestLinknameRefusedEverywhere (bf, D7): a go:linkname directive in any non
// test file reaches unexported code of another package, loops included, out of
// sight of the import rules. Under internal/loops it stays under the single rule
// loops-no-reflection.
func TestLinknameRefusedEverywhere(t *testing.T) {
	linkname := func(pkg, directive string) string {
		return goFile(pkg, []string{`_ "unsafe"`}, directive+"\nfunc nanotime() int64\n")
	}
	runSourceCases(t, "no-linkname", "go:linkname directive", []srcCase{
		sc("linkname_in_cmd", "", "", addFile("cmd/rempart-worker/clock.go",
			linkname("main", "//go:linkname nanotime runtime.nanotime"))),
		sc("linkname_in_internal", "", "", addFile("internal/llm/clock.go",
			linkname("llm", "//go:linkname nanotime runtime.nanotime"))),
		sc("linkname_pull_from_loops", "", "", addFile("internal/other/pull.go",
			goFile("other", []string{`_ "unsafe"`},
				"//go:linkname runLoop "+modulePath+"/internal/loops.RunLoop\nfunc runLoop()\n"))),
		sc("linkname_one_argument", "", "", addFile("internal/other/push.go",
			linkname("other", "//go:linkname nanotime"))),
		sc("linkname_in_root_package", "", "", addFile("clock.go",
			linkname("rempart", "//go:linkname nanotime runtime.nanotime"))),
		sc("linkname_in_function_body", "", "", addFile("internal/other/body.go",
			goFile("other", nil, "func f() {\n\t//go:linkname x runtime.x\n}\n"))),
	})
	t.Run("conforming", func(t *testing.T) {
		expectNoViolation(t,
			addFile("internal/other/doc.go", goFile("other", nil,
				"// go:linkname is not a directive with a space.\n\n/*go:linkname a b*/\n\nvar x = \"//go:linkname a b\"\n")),
			addFile("cmd/rempart-worker/doc.go", goFile("main", nil, "// go:linkname nanotime runtime.nanotime\n")))
	})
	t.Run("loops_keeps_its_rule", func(t *testing.T) {
		got := checkSources(t, repoSources(t, addFile("internal/loops/clock.go",
			linkname("loops", "//go:linkname nanotime runtime.nanotime"))))
		want := []SourceViolation{
			{"loops-no-reflection", "internal/loops/clock.go:4", "import unsafe"},
			{"loops-no-reflection", "internal/loops/clock.go:7", "go:linkname directive"},
		}
		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})
}

// TestCmdNotImported (bf, D7, T74): a package under cmd/ is a composition root;
// imported from elsewhere, it would carry its wiring (fake adapters, -dev
// paths) into workflow or library code. Only a package under cmd/ may import
// one.
func TestCmdNotImported(t *testing.T) {
	cmdImp := func(p string) string { return "_ \"" + modulePath + p + "\"" }
	runSourceCases(t, "no-cmd-import", "", []srcCase{
		sc("workflow_imports_cmd", "", modulePath+"/internal/loops/fixture imports "+modulePath+"/cmd/rempart-worker/wire",
			fx(loopsImp+"\n)", loopsImp+"\n\t_ \""+modulePath+"/cmd/rempart-worker/wire\"\n)")),
		sc("internal_imports_cmd", "", modulePath+"/internal/llm imports "+modulePath+"/cmd/rempart-worker",
			addFile("internal/llm/wire.go", goFile("llm", []string{cmdImp("/cmd/rempart-worker")}, ""))),
		sc("imports_cmd_root", "", " imports "+modulePath+"/cmd",
			addFile("internal/other/wire.go", goFile("other", []string{cmdImp("/cmd")}, ""))),
		sc("root_package_imports_cmd", "", modulePath+" imports "+modulePath+"/cmd/rempart",
			addFile("wire.go", goFile("rempart", []string{cmdImp("/cmd/rempart")}, ""))),
		sc("cmdx_imports_cmd", "", modulePath+"/cmdx/tool imports "+modulePath+"/cmd/rempart-worker/wire",
			addFile("cmdx/tool/wire.go", goFile("tool", []string{cmdImp("/cmd/rempart-worker/wire")}, ""))),
	})
	t.Run("conforming", func(t *testing.T) {
		expectNoViolation(t,
			addFile("cmd/rempart-worker/wire.go", goFile("main", []string{cmdImp("/cmd/rempart-worker/wire")}, "")),
			addFile("cmd/rempart/wire.go", goFile("main", []string{cmdImp("/cmd/rempart-worker/wire")}, "")),
			addFile("internal/other/wire.go", goFile("other", []string{cmdImp("/cmdx/tool"), `_ "example.com/cmd/x"`}, "")))
	})
}
