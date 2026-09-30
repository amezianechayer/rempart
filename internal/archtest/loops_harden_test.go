package archtest

import (
	"io/fs"
	"maps"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

// M0-T19d, plan section 6.1: obligations (ai) to (al) of M0-T19c.

// hardenLoopsFile writes a file of package internal/loops that imports
// encoding/json and sdk/workflow (both used, so the file stays valid Go).
func hardenLoopsFile(name, body string) srcEdit {
	return addFile("internal/loops/"+name, "package loops\n\nimport (\n\t\"encoding/json\"\n\n\t\"go.temporal.io/sdk/workflow\"\n)\n\n"+
		"var _ json.RawMessage\n\nvar _ workflow.Context\n\n"+body)
}

// TestReadSourcesModuleFiles (ai, threat T74): a go.mod outside the root makes
// its directory a separate module that go ./... skips and the rules would read
// as part of this one; go.work and go.work.sum redirect module resolution and
// vendor/modules.txt substitutes the vendored copies. ReadSources fails closed
// on each, at any depth and even in a directory go patterns ignore.
func TestReadSourcesModuleFiles(t *testing.T) {
	file := func(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }
	base := func() fstest.MapFS {
		return fstest.MapFS{
			"go.mod":                      file("module " + modulePath + "\n"),
			"internal/loops/runloop.go":   file("package loops\n\nfunc RunLoop() {}\n"),
			"internal/loops/approvals.go": file("package loops\n\nfunc AwaitApprovals() {}\n"),
			"internal/loops/fake/fake.go": file("package fake\n"),
		}
	}
	refused := []struct{ name, path, data string }{
		{"nested_go_mod", "internal/x/go.mod", "module example.com/x\n"},
		{"go_mod_under_testdata", "internal/archtest/testdata/m/go.mod", "module example.com/m\n"},
		{"go_mod_under_underscore_dir", "_tools/go.mod", "module example.com/tools\n"},
		{"go_mod_under_dot_dir", ".tools/go.mod", "module example.com/tools\n"},
		{"go_work", "go.work", "go 1.25\n\nuse ./internal/x\n"},
		{"go_work_sum", "go.work.sum", ""},
		{"nested_go_work", "internal/x/go.work", "go 1.25\n\nuse .\n"},
		{"vendor_modules", "vendor/modules.txt", "# go.temporal.io/sdk v1.0.0\n"},
		{"nested_vendor_modules", "internal/x/vendor/modules.txt", "# go.temporal.io/sdk v1.0.0\n"},
	}
	for _, c := range refused {
		t.Run(c.name, func(t *testing.T) {
			fsys := base()
			fsys[c.path] = file(c.data)
			srcs, err := ReadSources(fsys)
			if err == nil {
				t.Fatalf("ReadSources accepted %s (read %v)", c.path, slices.Sorted(maps.Keys(srcs)))
			}
			if !strings.Contains(err.Error(), c.path) {
				t.Errorf("error %q does not name %s", err, c.path)
			}
		})
	}
	t.Run("admitted", func(t *testing.T) {
		// The root go.mod, a modules.txt outside any vendor directory and a
		// go.mod under .git (never walked) stay admitted.
		fsys := base()
		fsys["docs/modules.txt"] = file("not a vendor manifest\n")
		fsys["docs/vendor.md"] = file("vendor/modules.txt is refused\n")
		fsys[".git/m/go.mod"] = file("module example.com/m\n")
		srcs, err := ReadSources(fsys)
		if err != nil {
			t.Fatalf("ReadSources: %v", err)
		}
		if _, ok := srcs["internal/loops/runloop.go"]; !ok {
			t.Errorf("ReadSources skipped internal/loops/runloop.go: %v", slices.Sorted(maps.Keys(srcs)))
		}
		if got := checkSources(t, srcs); len(got) != 0 {
			t.Errorf("violations: %v", got)
		}
	})
}

// TestMethodValuesRefused (aj, threat T73): in workflow code, a decoding method
// or function kept as a value (method value, method expression, parenthesized
// callee) escapes the target check of each call; so does an update validator
// set outside the SetUpdateHandlerWithOptions call. Such values are refused,
// and every Validator must be a function literal taking workflow.Context or
// converter.RawValue only.
func TestMethodValuesRefused(t *testing.T) {
	const at = "\tres, err := "
	withImports := fx(`"go.temporal.io/sdk/workflow"`,
		"\"go.temporal.io/sdk/converter\"\n\t\"go.temporal.io/sdk/temporal\"\n\t\"go.temporal.io/sdk/workflow\"")
	sig := "workflow.GetSignalChannel(ctx, loops.ApprovalSignal)"
	before := func(code string) srcEdit { return fx(at, code+"\n"+at) }
	rawHandler := "func(ctx workflow.Context, raw converter.RawValue) error { return nil }"
	structHandler := "func(ctx workflow.Context, a loops.Approval) error { return nil }"
	withOptions := "\t_ = workflow.SetUpdateHandlerWithOptions(ctx, \"u\", " + rawHandler + ", opts)"
	runSourceCases(t, "loops-raw-decoding-target", "", []srcCase{
		sc("receive_value", "", "Receive used as a value",
			before("\trecv := "+sig+".Receive\n\tvar a loops.Approval\n\trecv(ctx, &a)")),
		sc("receive_async_value", "", "ReceiveAsync used as a value",
			before("\tra := "+sig+".ReceiveAsync\n\tvar a loops.Approval\n\t_ = ra(&a)")),
		sc("direct_future_get_value", "", "Get used as a value",
			before("\tget := workflow.ExecuteActivity(ctx, verifyApproval).Get\n\tvar a loops.Approval\n\t_ = get(ctx, &a)")),
		sc("method_expression", "", "Get used as a value",
			before("\tget := workflow.Future.Get\n\tvar a loops.Approval\n\t_ = get(workflow.ExecuteActivity(ctx, verifyApproval), ctx, &a)")),
		sc("parenthesized_call", "", "ReceiveAsync used as a value",
			before("\tvar a loops.Approval\n\t_ = ("+sig+".ReceiveAsync)(&a)")),
		sc("set_update_handler_value", "", "SetUpdateHandler used as a value",
			before("\tset := workflow.SetUpdateHandler\n\t_ = set(ctx, \"u\", "+structHandler+")")),
		sc("details_value", "", "Details used as a value", withImports,
			before("\tvar ae *temporal.ApplicationError\n\tdetails := ae.Details\n\tvar a loops.Approval\n\t_ = details(&a)")),
		sc("validator_stored_options", "", "Validator handler", withImports,
			before("\topts := workflow.UpdateHandlerOptions{Validator: "+structHandler+"}\n"+withOptions)),
		sc("validator_assigned", "", "Validator set outside a composite literal", withImports,
			before("\tvar opts workflow.UpdateHandlerOptions\n\topts.Validator = "+structHandler+"\n"+withOptions)),
		sc("validator_named_function", "", "Validator handler", withImports,
			fx("const verifyApproval", "func validate(ctx workflow.Context, a loops.Approval) error { return nil }\n\nconst verifyApproval"),
			before("\topts := workflow.UpdateHandlerOptions{Validator: validate}\n"+withOptions)),
	})
	t.Run("conforming", func(t *testing.T) {
		// Decoding methods called directly, raw validators stored or inline.
		got := checkSources(t, repoSources(t, withImports, before(
			"\tvar raw converter.RawValue\n\t"+sig+".Receive(ctx, &raw)\n"+
				"\t_ = "+sig+".ReceiveAsync(nil)\n"+
				"\tvar out loops.ApprovalCheck\n\t_ = workflow.ExecuteActivity(ctx, verifyApproval).Get(ctx, &out)\n"+
				"\topts := workflow.UpdateHandlerOptions{Validator: "+rawHandler+"}\n"+withOptions+"\n"+
				"\t_ = workflow.SetUpdateHandlerWithOptions(ctx, \"v\", "+rawHandler+", workflow.UpdateHandlerOptions{Validator: "+rawHandler+"})")))
		for _, v := range got {
			t.Errorf("%s: %s: %s", v.Pos, v.Rule, v.Detail)
		}
	})
}

// TestSpecClosuresAndMethods (ak, threat T73): a method taking a LoopSpec or an
// ApprovalRequest used as a value in internal/loops (method value, method
// expression, pointer receiver included), or any function literal taking one,
// anywhere in the module, is a RunLoop copy that a registration would feed
// from the workflow input.
func TestSpecClosuresAndMethods(t *testing.T) {
	const engine = "type engine struct{}\n\nfunc (engine) run(ctx workflow.Context, spec LoopSpec) {}\n\n"
	runSourceCases(t, "loops-no-spec-entrypoint", "", []srcCase{
		sc("method_value_in_loops", "", "run takes a LoopSpec or an ApprovalRequest and is used as a value",
			hardenLoopsFile("v2.go", engine+"var registry = []any{engine{}.run}\n")),
		sc("method_expression_in_loops", "", "run takes a LoopSpec or an ApprovalRequest and is used as a value",
			hardenLoopsFile("v2.go", engine+"var registry = []any{engine.run}\n")),
		sc("pointer_method_expression", "", "run takes a LoopSpec or an ApprovalRequest and is used as a value",
			hardenLoopsFile("v2.go", "type engine struct{}\n\nfunc (*engine) run(ctx workflow.Context, spec LoopSpec) {}\n\n"+
				"var registry = []any{(*engine).run}\n")),
		sc("returned_closure", "", "function literal takes a LoopSpec or an ApprovalRequest",
			hardenLoopsFile("v2.go", "func newRunner() func(workflow.Context, LoopSpec) {\n"+
				"\treturn func(ctx workflow.Context, spec LoopSpec) {}\n}\n\nvar registry = []any{newRunner()}\n")),
		sc("closure_in_unexported_var", "", "function literal takes a LoopSpec or an ApprovalRequest",
			hardenLoopsFile("v2.go", "var awaitAll = func(ctx workflow.Context, req ApprovalRequest) {}\n\nvar registry = []any{awaitAll}\n")),
		sc("closure_outside_loops", "", "function literal takes a LoopSpec or an ApprovalRequest",
			addFile("cmd/rempart-worker/wire.go", "package main\n\nimport (\n\t\"go.temporal.io/sdk/workflow\"\n\n\t"+loopsImp+"\n)\n\n"+
				"var run = func(ctx workflow.Context, spec loops.LoopSpec) {}\n")),
	})
	t.Run("conforming", func(t *testing.T) {
		// A spec method called directly, a method value and a closure that
		// take no spec stay admitted.
		got := checkSources(t, repoSources(t, hardenLoopsFile("v2.go", engine+
			"func (engine) name() string { return \"engine\" }\n\n"+
			"func (e engine) start(ctx workflow.Context) { e.run(ctx, LoopSpec{}) }\n\n"+
			"var registry = []any{engine{}.name, engine.start, func(ctx workflow.Context) {}}\n")))
		for _, v := range got {
			t.Errorf("%s: %s: %s", v.Pos, v.Rule, v.Detail)
		}
	})
}

// TestSourceRuleGaps (al): cases the M0-T19c acceptance found untested. E5: a
// generic with several type parameters (IndexListExpr); E6: the
// LastHeartbeatDetails target; E9: an alias chain declared in reverse order,
// in one file or across files (the spec types need a fixed point).
func TestSourceRuleGaps(t *testing.T) {
	withImports := fx(`"go.temporal.io/sdk/workflow"`,
		"\"go.temporal.io/sdk/converter\"\n\t\"go.temporal.io/sdk/temporal\"\n\t\"go.temporal.io/sdk/workflow\"")
	const runG = "func RunG[S, T any](ctx workflow.Context, spec S, n T) {}\n"
	runSourceCases(t, "loops-no-spec-entrypoint", "", []srcCase{
		sc("generic_list_in_loops", "", "RunG instantiated", hardenLoopsFile("v2.go", runG+"\nvar _ = RunG[LoopSpec, int]\n")),
		sc("generic_list_outside", "", "RunG instantiated", hardenLoopsFile("v2.go", runG),
			fx("const verifyApproval", "var runG = loops.RunG[int, loops.ApprovalRequest]\n\nconst verifyApproval")),
		sc("last_heartbeat_details_struct", "loops-raw-decoding-target", "LastHeartbeatDetails target", withImports,
			fx("\tres, err := ", "\tvar te *temporal.TimeoutError\n\tvar a loops.Approval\n\t_ = te.LastHeartbeatDetails(&a)\n\tres, err := ")),
		sc("alias_chain_reversed", "", "RunLoopV2", hardenLoopsFile("v2.go",
			"func RunLoopV2(ctx workflow.Context, spec SpecC) {}\n\ntype SpecC = SpecB\n\ntype SpecB = SpecA\n\ntype SpecA = LoopSpec\n")),
		// Files are indexed in path order: aa_run.go before mm_alias.go before
		// zz_alias.go, the reverse of the alias chain.
		sc("alias_chain_across_files", "", "RunLoopV2",
			hardenLoopsFile("aa_run.go", "func RunLoopV2(ctx workflow.Context, spec SpecZ) {}\n"),
			hardenLoopsFile("mm_alias.go", "type SpecZ = SpecY\n"),
			hardenLoopsFile("zz_alias.go", "type SpecY = LoopSpec\n")),
	})
}

// TestMakefileGoworkOff (ai, decision D11, out of plan table 6.1): besides the
// fail-closed ReadSources, every go command of the Makefile runs with
// GOWORK=off, set by exactly one "export GOWORK := off" line and by no other.
func TestMakefileGoworkOff(t *testing.T) {
	_, fsys := repoRoot(t)
	b, err := fs.ReadFile(fsys, "Makefile")
	if err != nil {
		t.Fatalf("Makefile: %v", err)
	}
	var lines []string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.Contains(l, "GOWORK") {
			lines = append(lines, l)
		}
	}
	if !slices.Equal(lines, []string{"export GOWORK := off"}) {
		t.Errorf("Makefile lines naming GOWORK: %q, want exactly [\"export GOWORK := off\"]", lines)
	}
}
