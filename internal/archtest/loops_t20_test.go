package archtest

import (
	"maps"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

// M0-T20, plan docs/plans/M0-worker-demo.md section 5.1: obligations (at),
// (au), (aw), (ax), the ignored directory imports (decision 7 of M0-T19d) and
// the anthropic-unwired-m0 rule. Threat T73 (bypass of the source rules),
// T41 (unwired real adapter).

// beforeRun inserts code in the fixture workflow, before the RunLoop call.
func beforeRun(code string) srcEdit {
	const at = "\tres, err := "
	return fx(at, code+"\n"+at)
}

// TestKeyedLiteralsInWorkflowCode (at, D12): in workflow code, a composite
// literal whose element has no field name hides a field (Validator) from the
// rules that read keys. Only a literal of explicit array, slice or map type is
// admitted unkeyed; an elided element type counts as a struct.
func TestKeyedLiteralsInWorkflowCode(t *testing.T) {
	const validator = "func(ctx workflow.Context, in string) error { return nil }"
	runSourceCases(t, "loops-keyed-literals", "composite literal element without field name", []srcCase{
		sc("validator_unkeyed", "", "", beforeRun("\t_ = workflow.UpdateHandlerOptions{"+validator+", 0, \"\"}")),
		sc("sdk_struct_unkeyed", "", "", beforeRun("\t_ = workflow.Execution{\"id\", \"run\"}")),
		sc("elided_in_slice", "", "", beforeRun("\t_ = []workflow.Execution{{\"id\", \"run\"}}")),
		sc("elided_in_map", "", "", beforeRun("\t_ = map[string]loops.Approval{\"a\": {true, \"h\", \"bob\", \"s\"}}")),
		sc("alias_type", "", "",
			fx("const verifyApproval", "type execution = workflow.Execution\n\nconst verifyApproval"),
			beforeRun("\t_ = execution{\"id\", \"run\"}")),
		sc("module_struct_unkeyed", "", "", beforeRun("\t_ = loops.Approval{true, \"h\", \"bob\", \"s\"}")),
	})
	t.Run("conforming", func(t *testing.T) {
		got := checkSources(t, repoSources(t, beforeRun(
			"\t_ = []string{\"a\"}\n"+
				"\t_ = [2]int{1, 2}\n"+
				"\t_ = [...]string{\"a\", \"b\"}\n"+
				"\t_ = map[string]int{\"a\": 1}\n"+
				"\t_ = workflow.Execution{ID: \"id\", RunID: \"run\"}\n"+
				"\t_ = []workflow.Execution{{ID: \"id\"}}\n"+
				"\t_ = map[string]loops.Approval{\"a\": {Approver: \"bob\"}}\n"+
				"\t_ = loops.ApprovalResult{}")))
		for _, v := range got {
			t.Errorf("%s: %s: %s", v.Pos, v.Rule, v.Detail)
		}
	})
}

// actsFile writes a file of the activity package internal/loops/fixture/acts,
// which does not import go.temporal.io/sdk/workflow.
func actsFile(imports, body string) srcEdit {
	return addFile("internal/loops/fixture/acts/acts.go", "package acts\n\nimport (\n"+imports+"\n)\n\n"+body)
}

// heartbeatBody decodes heartbeat details into a struct: fine outside the
// loops packages or in the fake, refused in any other package of internal/loops.
const heartbeatBody = "func Take(ctx context.Context) (a loops.Approval) {\n\t_ = activity.GetHeartbeatDetails(ctx, &a)\n\treturn a\n}\n"

const heartbeatImports = "\t\"context\"\n\n\t\"go.temporal.io/sdk/activity\"\n\n\t" + loopsImp

// TestActivityPackagesDecodingTargets (au, D13): the decoding names and their
// targets are checked in every package under internal/loops but the fake, not
// only in files importing sdk/workflow: an activity package decodes with the
// same data converter.
func TestActivityPackagesDecodingTargets(t *testing.T) {
	runSourceCases(t, "loops-raw-decoding-target", "", []srcCase{
		sc("receive_param", "", "Receive target", actsFile("\t\"context\"\n\n\t"+loopsImp,
			"type receiver interface{ Receive(ctx context.Context, v any) bool }\n\n"+
				"func Take(ctx context.Context, c receiver) loops.Approval {\n\tvar a loops.Approval\n\tc.Receive(ctx, &a)\n\treturn a\n}\n")),
		sc("get_value", "", "Get used as a value", actsFile("\t\"go.temporal.io/sdk/converter\"\n\n\t"+loopsImp,
			"func Take(v converter.EncodedValue) loops.Approval {\n\tget := v.Get\n\tvar a loops.Approval\n\t_ = get(&a)\n\treturn a\n}\n")),
		sc("details_param", "", "Details target", actsFile("\t\"go.temporal.io/sdk/temporal\"\n\n\t"+loopsImp,
			"func Take(ae *temporal.ApplicationError) (a loops.Approval) {\n\t_ = ae.Details(&a)\n\treturn a\n}\n")),
		sc("get_heartbeat_details", "", "GetHeartbeatDetails target", actsFile(heartbeatImports, heartbeatBody)),
	})
	admitted := []struct {
		name string
		edit srcEdit
	}{
		{"fake_package", addFile("internal/loops/fake/heartbeat.go",
			"package fake\n\nimport (\n"+heartbeatImports+"\n)\n\n"+heartbeatBody)},
		{"outside_loops", addFile("internal/other/heartbeat.go",
			"package other\n\nimport (\n"+heartbeatImports+"\n)\n\n"+heartbeatBody)},
		{"conforming", actsFile("\t\"context\"\n\n\t\"go.temporal.io/sdk/activity\"\n\t\"go.temporal.io/sdk/converter\"\n\t\"go.temporal.io/sdk/temporal\"",
			"type receiver interface{ Receive(ctx context.Context, v any) bool }\n\n"+
				"func Take(ctx context.Context, c receiver, ae *temporal.ApplicationError) error {\n"+
				"\tvar raw, d converter.RawValue\n\tc.Receive(ctx, &raw)\n"+
				"\t_ = activity.GetHeartbeatDetails(ctx, &raw)\n\treturn ae.Details(&d)\n}\n")},
	}
	for _, c := range admitted {
		t.Run(c.name, func(t *testing.T) {
			for _, v := range checkSources(t, repoSources(t, c.edit)) {
				t.Errorf("%s: %s: %s", v.Pos, v.Rule, v.Detail)
			}
		})
	}
}

// TestLoopsNoReflection (aw, D14): reflect, unsafe, cgo, a go:linkname
// directive or a non-Go source reach values or code the source rules cannot
// see. All are refused anywhere under internal/loops, the fake included.
func TestLoopsNoReflection(t *testing.T) {
	runSourceCases(t, "loops-no-reflection", "", []srcCase{
		sc("reflect_in_loops", "", "import reflect",
			addFile("internal/loops/refl.go", "package loops\n\nimport \"reflect\"\n\nvar _ = reflect.TypeOf\n")),
		sc("unsafe_in_demo", "", "import unsafe",
			addFile("internal/loops/demo/size.go", "package demo\n\nimport \"unsafe\"\n\nvar _ = unsafe.Sizeof(0)\n")),
		sc("reflect_in_activities", "", "import reflect",
			addFile("internal/loops/demo/activities/refl.go", "package activities\n\nimport \"reflect\"\n\nvar _ = reflect.TypeOf\n")),
		sc("reflect_in_fake", "", "import reflect",
			addFile("internal/loops/fake/refl.go", "package fake\n\nimport \"reflect\"\n\nvar _ = reflect.TypeOf\n")),
		sc("cgo_import", "", "import C",
			addFile("internal/loops/cgo.go", "package loops\n\n// int one(void) { return 1; }\nimport \"C\"\n\nvar _ = C.one\n")),
		sc("linkname_directive", "", "go:linkname directive",
			addFile("internal/loops/clock.go", "package loops\n\n//go:linkname nanotime runtime.nanotime\nfunc nanotime() int64\n")),
	})
	t.Run("asm_file", func(t *testing.T) {
		file := func(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }
		base := func() fstest.MapFS {
			return fstest.MapFS{
				"go.mod":                      file("module " + modulePath + "\n"),
				"internal/loops/runloop.go":   file("package loops\n\nfunc RunLoop() {}\n"),
				"internal/loops/approvals.go": file("package loops\n\nfunc AwaitApprovals() {}\n"),
				"internal/loops/fake/fake.go": file("package fake\n"),
			}
		}
		for _, p := range []string{"internal/loops/x.s", "internal/loops/demo/y.c", "internal/loops/fake/z.syso", "internal/loops/demo/activities/w.S"} {
			fsys := base()
			fsys[p] = file("TEXT ·RunLoop(SB),0,$0\n")
			srcs, err := ReadSources(fsys)
			if err == nil {
				t.Errorf("ReadSources accepted %s (read %v)", p, slices.Sorted(maps.Keys(srcs)))
				continue
			}
			if !strings.Contains(err.Error(), p) {
				t.Errorf("error %q does not name %s", err, p)
			}
		}
		// Outside internal/loops, a non-Go source is not this rule's concern.
		fsys := base()
		fsys["internal/other/x.s"] = file("TEXT ·f(SB),0,$0\n")
		srcs, err := ReadSources(fsys)
		if err != nil {
			t.Fatalf("ReadSources with internal/other/x.s: %v", err)
		}
		if got := checkSources(t, srcs); len(got) != 0 {
			t.Errorf("violations: %v", got)
		}
	})
	t.Run("outside_loops", func(t *testing.T) {
		got := checkSources(t, repoSources(t,
			addFile("internal/other/refl.go", "package other\n\nimport (\n\t\"reflect\"\n\t\"unsafe\"\n)\n\nvar _ = reflect.TypeOf\n\nvar _ = unsafe.Sizeof(0)\n")))
		for _, v := range got {
			t.Errorf("%s: %s: %s", v.Pos, v.Rule, v.Detail)
		}
	})
}

// TestSearchAttributesRefused (ax, D15): search attributes and the memo are
// visible to anyone who lists workflows and are decoded outside the rules.
func TestSearchAttributesRefused(t *testing.T) {
	runSourceCases(t, "loops-no-search-attributes", "", []srcCase{
		sc("get_typed", "", "GetTypedSearchAttributes", beforeRun("\t_ = workflow.GetTypedSearchAttributes(ctx)")),
		sc("upsert_typed", "", "UpsertTypedSearchAttributes", beforeRun("\t_ = workflow.UpsertTypedSearchAttributes(ctx)")),
		sc("upsert_untyped", "", "UpsertSearchAttributes", beforeRun("\t_ = workflow.UpsertSearchAttributes(ctx, nil)")),
		sc("info_search_attributes", "", "SearchAttributes", beforeRun("\t_ = workflow.GetInfo(ctx).SearchAttributes")),
		sc("upsert_memo", "", "UpsertMemo", beforeRun("\t_ = workflow.UpsertMemo(ctx, nil)")),
	})
	t.Run("conforming", func(t *testing.T) {
		got := checkSources(t, repoSources(t, beforeRun(
			"\t_ = workflow.GetInfo(ctx).WorkflowExecution.ID\n\t_ = workflow.GetInfo(ctx).Attempt")))
		for _, v := range got {
			t.Errorf("%s: %s: %s", v.Pos, v.Rule, v.Detail)
		}
	})
}

// TestIgnoredDirImportRefused (T73, decision 7 of M0-T19d): go ./... and
// ReadSources skip directories starting with _ or . and testdata, go build
// compiles them when imported. No package of the module imports one.
func TestIgnoredDirImportRefused(t *testing.T) {
	runSourceCases(t, "no-ignored-dir-import", "", []srcCase{
		sc("underscore_dir", "", "import "+modulePath+"/internal/_dev",
			fx(loopsImp+"\n)", loopsImp+"\n\t_ \""+modulePath+"/internal/_dev\"\n)")),
		sc("dot_dir", "", "import "+modulePath+"/.tools/gen",
			addFile("cmd/rempart-worker/wire.go", "package main\n\nimport _ \""+modulePath+"/.tools/gen\"\n")),
		sc("testdata_dir", "", "import "+modulePath+"/internal/loops/demo/testdata/stub",
			addFile("internal/llm/wire.go", "package llm\n\nimport _ \""+modulePath+"/internal/loops/demo/testdata/stub\"\n")),
	})
	t.Run("conforming", func(t *testing.T) {
		// Module packages without an ignored element, and paths outside the
		// module whatever their elements.
		got := checkSources(t, repoSources(t, addFile("cmd/rempart-worker/wire.go",
			"package main\n\nimport (\n\t_ \"example.com/_x/.y/testdata\"\n\n\t_ \""+modulePath+"/internal/loops/demo\"\n"+
				"\t_ \""+modulePath+"/internal/loops/demo/activities\"\n)\n")))
		for _, v := range got {
			t.Errorf("%s: %s: %s", v.Pos, v.Rule, v.Detail)
		}
	})
}

// TestAnthropicAdapterUnwired (T41, T20 section 3.1): until M0-T20b hardens the
// Anthropic adapter, no package of the module but the adapter itself imports
// it, cmd included.
func TestAnthropicAdapterUnwired(t *testing.T) {
	const (
		m       = modulePath
		rule    = "anthropic-unwired-m0"
		adapter = m + "/internal/llm/adapters/anthropic"
	)
	rules := DefaultRules(m)
	i := slices.IndexFunc(rules, func(r Rule) bool { return r.Name == rule })
	if i < 0 {
		t.Fatalf("DefaultRules has no rule %s", rule)
	}
	if r := rules[i]; r.Kind != Confine || !slices.Equal(r.AllowedFrom, []string{adapter + "/..."}) ||
		!slices.Equal(r.Targets, []string{adapter + "/..."}) {
		t.Fatalf("%s: kind %d, Targets %q, AllowedFrom %q; want Confine on %s/... allowed from the adapter only",
			rule, r.Kind, r.Targets, r.AllowedFrom, adapter)
	}
	only := func(vs []Violation) []Violation {
		var out []Violation
		for _, v := range vs {
			if v.Rule == rule {
				out = append(out, v)
			}
		}
		return out
	}
	t.Run("from_cmd", func(t *testing.T) {
		got := Check(m, []Package{{ImportPath: m + "/cmd/rempart-worker", Imports: []string{adapter, m + "/internal/llm"}}}, rules)
		expectViolations(t, got, []Violation{{Rule: rule, Importer: m + "/cmd/rempart-worker", Imported: adapter}})
	})
	t.Run("from_internal", func(t *testing.T) {
		got := Check(m, []Package{{ImportPath: m + "/internal/llm/wire", Imports: []string{adapter + "/stream"}}}, rules)
		expectViolations(t, only(got), []Violation{{Rule: rule, Importer: m + "/internal/llm/wire", Imported: adapter + "/stream"}})
	})
	t.Run("none", func(t *testing.T) {
		got := Check(m, []Package{
			{ImportPath: adapter, Imports: []string{
				"context", "github.com/anthropics/anthropic-sdk-go", adapter + "/internal/wire",
				m + "/internal/llm/domain", m + "/internal/llm/ports",
			}},
			{ImportPath: adapter + "/internal/wire", Imports: []string{"encoding/json"}},
			{ImportPath: m + "/cmd/rempart-worker", Imports: []string{m + "/internal/llm", m + "/internal/llm/fake"}},
		}, rules)
		expectViolations(t, got, nil)
	})
}
