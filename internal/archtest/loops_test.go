package archtest

import (
	"cmp"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

const (
	fixturePath = "internal/loops/fixture/workflow.go"
	loopsImp    = `"github.com/amezianechayer/rempart/internal/loops"`
	fakeImp     = `"github.com/amezianechayer/rempart/internal/loops/fake"`
)

const fixtureOK = `package fixture

import (
	"encoding/json"
	"time"

	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"

	"github.com/amezianechayer/rempart/internal/loops"
)

const verifyApproval = "demo.VerifyApproval"

func Spec() loops.LoopSpec {
	return loops.LoopSpec{
		ID: "demo", ProposeActivity: "demo.Propose", VerifyActivity: "demo.Verify",
		Strategies: []string{"direct", "strict"},
		Budget: loops.Budget{MaxIterations: loops.MaxIterationsLimit / 20, MaxTokens: 10_000, MaxWallTime: 10 * time.Minute},
	}
}

func Workflow(ctx workflow.Context, target json.RawMessage, author string, wait time.Duration) error {
	res, err := loops.RunLoop(ctx, Spec(), target)
	if err != nil {
		return err
	}
	_, err = loops.AwaitApprovals(ctx, loops.ApprovalRequest{
		PlanHash: string(res.Best), Author: author, Required: 1,
		NeedsSecurityRole: false, VerifyActivity: verifyApproval,
	}, wait)
	return err
}

func Register(r worker.Registry) {
	r.RegisterWorkflowWithOptions(Workflow, workflow.RegisterOptions{Name: "rempart.demo.v1"})
}
`

// srcEdit replaces old by repl once in file; an empty old writes file.
type srcEdit struct{ file, old, repl string }

func fx(old, repl string) srcEdit { return srcEdit{fixturePath, old, repl} }

func addFile(file, src string) srcEdit { return srcEdit{file, "", src} }

type srcCase struct {
	name, rule, detail string // empty: the default of runSourceCases
	edits              []srcEdit
}

func sc(name, rule, detail string, edits ...srcEdit) srcCase {
	return srcCase{name, rule, detail, edits}
}

func repoSources(t *testing.T, edits ...srcEdit) map[string]string {
	t.Helper()
	_, fsys := repoRoot(t)
	srcs, err := ReadSources(fsys)
	if err != nil {
		t.Fatalf("ReadSources: %v", err)
	}
	srcs[fixturePath] = fixtureOK
	for _, e := range edits {
		if e.old == "" {
			srcs[e.file] = e.repl
		} else {
			srcs[e.file] = mustReplace(t, srcs[e.file], e.old, e.repl)
		}
	}
	return srcs
}

func checkSources(t *testing.T, srcs map[string]string) []SourceViolation {
	t.Helper()
	files, err := ParseSources(modulePath, srcs)
	if err != nil {
		t.Fatalf("ParseSources: %v", err)
	}
	return CheckLoopSources(modulePath, files)
}

func runSourceCases(t *testing.T, rule, detail string, cases []srcCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, d := cmp.Or(c.rule, rule), cmp.Or(c.detail, detail)
			got := checkSources(t, repoSources(t, c.edits...))
			if len(got) == 0 {
				t.Fatalf("no violation, want %s mentioning %q", r, d)
			}
			for _, v := range got {
				if v.Rule != r {
					t.Errorf("%s: %s (%s), want only %s", v.Pos, v.Rule, v.Detail, r)
				}
			}
			if !slices.ContainsFunc(got, func(v SourceViolation) bool { return strings.Contains(v.Detail, d) }) {
				t.Errorf("no violation mentions %q: %v", d, got)
			}
		})
	}
}

func TestLoopSourcesConform(t *testing.T) {
	srcs := repoSources(t)
	if srcs["internal/loops/runloop.go"] == "" || srcs["internal/loops/runloop_test.go"] != "" {
		t.Fatal("ReadSources must read internal/loops/runloop.go and no test file")
	}
	for _, v := range checkSources(t, srcs) {
		t.Errorf("%s: %s: %s", v.Pos, v.Rule, v.Detail)
	}
	if got := checkSources(t, map[string]string{"x.go": "package x"}); len(got) != 2 {
		t.Errorf("without package loops: %v, want RunLoop and AwaitApprovals not declared", got)
	}
}

func TestRunLoopNotRegistered(t *testing.T) {
	runSourceCases(t, "runloop-not-registered", "RunLoop used as a value", []srcCase{
		sc("registered", "", "", fx("(Workflow,", "(loops.RunLoop,")),
		sc("registered_by_name", "", "string names RunLoop", fx(`"rempart.demo.v1"`, `"RunLoop"`)),
		sc("child_workflow", "", "", fx("res, err := loops.RunLoop(ctx, Spec(), target)",
			"var res loops.LoopResult\n\terr := workflow.ExecuteChildWorkflow(ctx, loops.RunLoop, Spec(), target).Get(ctx, &res)")),
		sc("registered_inside_loops", "", "", addFile("internal/loops/register.go",
			"package loops\n\nimport \"go.temporal.io/sdk/worker\"\n\nfunc Register(r worker.Registry) { r.RegisterWorkflow(RunLoop) }\n")),
		sc("renamed_import", "", "", addFile("internal/loops/fixture/alias.go",
			"package fixture\n\nimport lp "+loopsImp+"\n\nvar start = lp.RunLoop\n")),
		// Renamed unexported: an exported Run taking a LoopSpec would also break
		// loops-no-spec-entrypoint (M0-T19c V2).
		sc("api_renamed", "", "RunLoop not declared", srcEdit{"internal/loops/runloop.go", "func RunLoop(", "func runLoop("}),
		sc("dot_import", "no-dot-import", "dot import", addFile("internal/loops/fixture/dot.go",
			"package fixture\n\nimport . "+loopsImp+"\n\nvar start = RunLoop\n")),
	})
}

func TestLoopSpecsAreConstants(t *testing.T) {
	runSourceCases(t, "loop-spec-constant", "RunLoop spec", []srcCase{
		sc("spec_parameter", "", "", fx("func Spec() loops.LoopSpec {", "func Spec(n int) loops.LoopSpec {")),
		sc("package_variable", "", "", fx("loops.RunLoop(ctx, Spec(), target)", "loops.RunLoop(ctx, demoSpec, target)"),
			fx("const verifyApproval", "var demoSpec = Spec()\n\nconst verifyApproval")),
		sc("shadowed_spec", "", "", fx("\tres, err := ",
			"\tSpec := func() loops.LoopSpec { return loops.LoopSpec{ID: string(target)} }\n\tres, err := ")),
		sc("field_from_variable", "", "", fx(`ID: "demo",`, "ID: demoID,"),
			fx("const verifyApproval", "var demoID = \"demo\"\n\nconst verifyApproval")),
		sc("budget_field_missing", "", "", fx("MaxTokens: 10_000, ", "")),
		sc("build_variant", "", "", addFile("internal/loops/fixture/spec_dev.go",
			"//go:build dev\n\npackage fixture\n\nimport "+loopsImp+"\n\nfunc Spec() loops.LoopSpec { return loops.LoopSpec{} }\n")),
	})
}

func TestAwaitApprovalsNotRegistered(t *testing.T) {
	const req = "approval-request-constant"
	runSourceCases(t, "await-approvals-not-registered", "request", []srcCase{
		sc("registered", "", "AwaitApprovals used as a value",
			fx("\tr.RegisterWorkflowWithOptions(", "\tr.RegisterWorkflow(loops.AwaitApprovals)\n\tr.RegisterWorkflowWithOptions(")),
		sc("started_by_name", "", "string names AwaitApprovals",
			addFile("cmd/rempart/start.go", "package main\n\nconst workflowType = \"AwaitApprovals\"\n")),
		sc("request_variable", req, "", fx("_, err = loops.AwaitApprovals(ctx, loops.ApprovalRequest{", "req := loops.ApprovalRequest{"),
			fx("}, wait)", "}\n\t_, err = loops.AwaitApprovals(ctx, req, wait)")),
		sc("required_computed", req, "", fx("Required: 1,", "Required: len(author),")),
		sc("shadowed_constant", req, "", fx("\t_, err = loops.AwaitApprovals(", "\tverifyApproval := author\n\t_, err = loops.AwaitApprovals(")),
		sc("security_role_omitted", req, "", fx("NeedsSecurityRole: false, ", "")),
	})
}

func TestLoopsNoJSONDecoding(t *testing.T) {
	const at = "const verifyApproval"
	runSourceCases(t, "loops-no-json-decoding", "", []srcCase{
		sc("decoder_in_workflow", "", "json.NewDecoder", fx(at, "var decode = json.NewDecoder\n\n"+at)),
		sc("json_v2", "", "encoding/json/v2", fx(`"encoding/json"`, "\"encoding/json\"\n\tjsonv2 \"encoding/json/v2\"")),
		sc("converter_decoding", "", "converter.GetDefaultDataConverter",
			fx(`"encoding/json"`, "\"encoding/json\"\n\t\"go.temporal.io/sdk/converter\""), fx(at, "var dc = converter.GetDefaultDataConverter\n\n"+at)),
		sc("unmarshal_method", "loops-no-unmarshal-method", "UnmarshalText",
			fx(at, "type Target string\n\nfunc (t *Target) UnmarshalText(p []byte) error { return nil }\n\n"+at)),
	})
}

func TestLoopsFakeTestsOnly(t *testing.T) {
	runSourceCases(t, "loops-fake-tests-only", " imports ", []srcCase{
		sc("worker_dev_build", "", "", addFile("cmd/rempart-worker/dev.go", "//go:build dev\n\npackage main\n\nimport _ "+fakeImp+"\n")),
		sc("workflow_package", "", "", fx(loopsImp+"\n)", loopsImp+"\n\t_ "+fakeImp+"\n)")),
	})
}

// TestSourceRulesHardening holds the cases added by test-author on top of the
// 25 cases of plan section 5.1 (out-of-plan mutations and bypass attempts).
// Its name keeps it out of the counts of acceptance criterion 1.
func TestSourceRulesHardening(t *testing.T) {
	const at = "const verifyApproval"
	t.Run("decoding", func(t *testing.T) {
		runSourceCases(t, "loops-no-json-decoding", "", []srcCase{
			sc("yaml_import", "", "import gopkg.in/yaml.v3", fx(`"encoding/json"`, "\"encoding/json\"\n\t_ \"gopkg.in/yaml.v3\"")),
			sc("toml_import", "", "import github.com/BurntSushi/toml",
				fx(`"encoding/json"`, "\"encoding/json\"\n\t_ \"github.com/BurntSushi/toml\"")),
			sc("gob_import", "", "import encoding/gob", fx(`"encoding/json"`, "\"encoding/json\"\n\t_ \"encoding/gob\"")),
			sc("xml_import", "", "import encoding/xml", fx(`"encoding/json"`, "\"encoding/json\"\n\t_ \"encoding/xml\"")),
			// A file of a workflow package that does not import sdk/workflow
			// itself: the converter call is invisible to workflowcheck.
			sc("sibling_file_converter", "", "converter.GetDefaultDataConverter", addFile("internal/loops/fixture/decode.go",
				"package fixture\n\nimport \"go.temporal.io/sdk/converter\"\n\nvar dc = converter.GetDefaultDataConverter\n")),
		})
		runSourceCases(t, "loops-no-unmarshal-method", "GobDecode", []srcCase{
			sc("gob_decode_method", "", "", fx(at, "type Target string\n\nfunc (t *Target) GobDecode(p []byte) error { return nil }\n\n"+at)),
		})
	})
	t.Run("request", func(t *testing.T) {
		runSourceCases(t, "approval-request-constant", "request", []srcCase{
			// A local variable named after an imported package: time.Minute is
			// then a field computed from the input.
			sc("shadowed_package", "", "", fx("\t_, err = loops.AwaitApprovals(",
				"\ttime := struct{ Minute int }{Minute: len(author)}\n\t_, err = loops.AwaitApprovals("),
				fx("NeedsSecurityRole: false, ", "NeedsSecurityRole: false, MaxIgnored: time.Minute, ")),
			sc("shadowed_true_local", "", "", fx("\t_, err = loops.AwaitApprovals(",
				"\ttrue := author == \"\"\n\t_, err = loops.AwaitApprovals("),
				fx("NeedsSecurityRole: false, ", "NeedsSecurityRole: true, ")),
			sc("shadowed_true_package", "", "", fx(at, "var true = len(verifyApproval) > 100\n\n"+at),
				fx("NeedsSecurityRole: false, ", "NeedsSecurityRole: true, ")),
		})
	})
}

// TestReadSourcesNestedBin: Go builds and imports a package in any directory
// named bin, the root one included (a file forced past .gitignore). A
// dev-tagged file there must not hide an import of the loops fake (T33, T41;
// M0-T19c V2 removes the root bin exception).
func TestReadSourcesNestedBin(t *testing.T) {
	file := func(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }
	dev := "//go:build dev\n\npackage bin\n\nimport _ " + fakeImp + "\n"
	fsys := fstest.MapFS{
		"go.mod":                        file("module " + modulePath + "\n"),
		"bin/rempart":                   file("\x7fELF"),
		"bin/dev.go":                    file(dev),
		"internal/loops/runloop.go":     file("package loops\n\nfunc RunLoop() {}\n"),
		"internal/loops/approvals.go":   file("package loops\n\nfunc AwaitApprovals() {}\n"),
		"internal/loops/fake/fake.go":   file("package fake\n"),
		"cmd/rempart-worker/bin/dev.go": file(dev),
	}
	srcs, err := ReadSources(fsys)
	if err != nil {
		t.Fatalf("ReadSources: %v", err)
	}
	for _, p := range []string{"bin/dev.go", "cmd/rempart-worker/bin/dev.go"} {
		if _, ok := srcs[p]; !ok {
			t.Errorf("ReadSources skipped %s: %v", p, slices.Sorted(maps.Keys(srcs)))
		}
	}
	got := checkSources(t, srcs)
	want := []SourceViolation{
		{"loops-fake-tests-only", "bin/dev.go:5", modulePath + "/bin imports " + modulePath + "/internal/loops/fake"},
		{
			"loops-fake-tests-only", "cmd/rempart-worker/bin/dev.go:5",
			modulePath + "/cmd/rempart-worker/bin imports " + modulePath + "/internal/loops/fake",
		},
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestReadSourcesSymlinks (M0-T19c V2, threat T74): fs.WalkDir does not follow
// a symbolic link, go build does. ReadSources fails closed on any symbolic
// link outside .git, whatever its target and even in a skipped directory.
func TestReadSourcesSymlinks(t *testing.T) {
	file := func(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }
	link := func(target string) *fstest.MapFile {
		return &fstest.MapFile{Data: []byte(target), Mode: fs.ModeSymlink | 0o777}
	}
	base := func() fstest.MapFS {
		return fstest.MapFS{
			"go.mod":                      file("module " + modulePath + "\n"),
			"internal/loops/runloop.go":   file("package loops\n\nfunc RunLoop() {}\n"),
			"internal/loops/approvals.go": file("package loops\n\nfunc AwaitApprovals() {}\n"),
			"internal/loops/fake/fake.go": file("package fake\n"),
		}
	}
	cases := []struct{ name, path, target string }{
		{"dir_to_fake", "internal/devwire", "loops/fake"},
		{"dir_to_loops", "internal/lp", "loops"},
		{"go_file", "internal/lp2/runloop.go", "../loops/runloop.go"},
		{"non_go_file", "docs/notes.md", "../README.md"},
		{"root_bin", "bin", "internal/loops/fake"},
		{"under_underscore_dir", "internal/_x/sub", "../loops/fake"},
		{"under_dot_dir", ".claude/skills/x", "../../internal/loops"},
		{"under_testdata", "internal/archtest/testdata/lp", "../../loops"},
		{"outside_repository", "internal/ext", "/usr/lib/go"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fsys := base()
			fsys[c.path] = link(c.target)
			srcs, err := ReadSources(fsys)
			if err == nil {
				t.Fatalf("ReadSources accepted the symbolic link %s -> %s (read %v)", c.path, c.target, slices.Sorted(maps.Keys(srcs)))
			}
			if !strings.Contains(err.Error(), c.path) {
				t.Errorf("error %q does not name %s", err, c.path)
			}
		})
	}
	t.Run("git_dir_allowed", func(t *testing.T) {
		fsys := base()
		fsys[".git/hooks/pre-commit"] = link("../../scripts/pre-commit")
		srcs, err := ReadSources(fsys)
		if err != nil {
			t.Fatalf("ReadSources: %v", err)
		}
		if got := checkSources(t, srcs); len(got) != 0 {
			t.Errorf("violations: %v", got)
		}
	})
	t.Run("real_directory_link", func(t *testing.T) {
		root := t.TempDir()
		writeFiles(t, root, map[string]string{
			"go.mod":                      "module " + modulePath + "\n",
			"internal/loops/runloop.go":   "package loops\n\nfunc RunLoop() {}\n",
			"internal/loops/approvals.go": "package loops\n\nfunc AwaitApprovals() {}\n",
			"internal/loops/fake/fake.go": "package fake\n",
		})
		symlinkOrSkip(t, "loops/fake", filepath.Join(root, "internal", "devwire"))
		if _, err := ReadSources(os.DirFS(root)); err == nil || !strings.Contains(err.Error(), "internal/devwire") {
			t.Errorf("ReadSources on a real directory link: err = %v, want an error naming internal/devwire", err)
		}
	})
}

// TestWorkflowDecodingTargets (M0-T19c V2): in the workflow code of
// internal/loops, the SDK decodes a signal, a side effect or an error detail
// into its target with the data converter, out of sight of workflowcheck. The
// only admitted target is &x, x a local converter.RawValue (or nil); Get with
// a context is admitted only on a future returned directly by
// workflow.ExecuteActivity, ExecuteLocalActivity or ExecuteChildWorkflow.
func TestWorkflowDecodingTargets(t *testing.T) {
	const at = "\tres, err := "
	withImports := fx(`"go.temporal.io/sdk/workflow"`,
		"\"go.temporal.io/sdk/converter\"\n\t\"go.temporal.io/sdk/temporal\"\n\t\"go.temporal.io/sdk/workflow\"")
	sig := "workflow.GetSignalChannel(ctx, loops.ApprovalSignal)"
	before := func(code string) srcEdit { return fx(at, code+"\n"+at) }
	runSourceCases(t, "loops-raw-decoding-target", "", []srcCase{
		sc("receive_struct", "", "Receive target", before("\tvar a loops.Approval\n\t"+sig+".Receive(ctx, &a)")),
		sc("receive_async_struct", "", "ReceiveAsync target", before("\tvar a loops.Approval\n\t_ = "+sig+".ReceiveAsync(&a)")),
		sc("receive_with_timeout_struct", "", "ReceiveWithTimeout target",
			before("\tvar a loops.Approval\n\t_, _ = "+sig+".ReceiveWithTimeout(ctx, time.Second, &a)")),
		sc("receive_async_more_flag_struct", "", "ReceiveAsyncWithMoreFlag target",
			before("\tvar a loops.Approval\n\t_, _ = "+sig+".ReceiveAsyncWithMoreFlag(&a)")),
		sc("side_effect_get_struct", "", "Get target",
			before("\tvar a loops.Approval\n\t_ = workflow.SideEffect(ctx, func(workflow.Context) any { return nil }).Get(&a)")),
		sc("stored_future_get_struct", "", "Get target",
			before("\tf := workflow.ExecuteActivity(ctx, verifyApproval)\n\tvar a loops.Approval\n\t_ = f.Get(ctx, &a)")),
		sc("context_first_values_get", "", "Get target",
			before("\tvar a loops.Approval\n\tvar ev interface{ Get(...any) error }\n\t_ = ev.Get(ctx, &a)")),
		sc("details_struct", "", "Details target",
			before("\tvar ae *temporal.ApplicationError\n\tvar a loops.Approval\n\t_ = ae.Details(&a)"), withImports),
		sc("last_completion_result_struct", "", "GetLastCompletionResult target",
			before("\tvar a loops.Approval\n\t_ = workflow.GetLastCompletionResult(ctx, &a)")),
		sc("raw_through_pointer", "", "Receive target",
			before("\tvar raw converter.RawValue\n\tp := &raw\n\t"+sig+".Receive(ctx, p)"), withImports),
		sc("raw_shadowed_by_struct", "", "ReceiveAsync target",
			before("\tvar raw converter.RawValue\n\t_ = raw\n\tfunc() {\n\t\tvar raw loops.Approval\n\t\t_ = "+sig+".ReceiveAsync(&raw)\n\t}()"), withImports),
		sc("raw_shadowed_by_define", "", "ReceiveAsync target",
			before("\tvar raw converter.RawValue\n\t_ = raw\n\tfunc() {\n\t\traw := loops.Approval{}\n\t\t_ = "+sig+".ReceiveAsync(&raw)\n\t}()"), withImports),
		sc("foreign_execute_activity", "", "Get target",
			fx(`"go.temporal.io/sdk/workflow"`, "\"go.temporal.io/sdk/workflow\"\n\twfx \"example.com/wfx\""),
			before("\tvar a loops.Approval\n\t_ = wfx.ExecuteActivity(ctx, verifyApproval).Get(ctx, &a)")),
		sc("raw_at_package_level", "", "Receive target",
			fx("const verifyApproval", "var pkgRaw converter.RawValue\n\nconst verifyApproval"),
			before("\t"+sig+".Receive(ctx, &pkgRaw)"), withImports),
		sc("raw_type_alias", "", "Receive target",
			fx("const verifyApproval", "type Raw = loops.Approval\n\nconst verifyApproval"),
			before("\tvar raw Raw\n\t"+sig+".Receive(ctx, &raw)")),
		// The SDK decodes update, validator and query arguments too.
		sc("update_handler_struct", "", "SetUpdateHandler handler",
			before("\t_ = workflow.SetUpdateHandler(ctx, \"approve\", func(ctx workflow.Context, a loops.Approval) error { return nil })")),
		sc("query_handler_struct", "", "SetQueryHandler handler",
			before("\t_ = workflow.SetQueryHandler(ctx, \"q\", func(a loops.Approval) (string, error) { return \"\", nil })")),
		sc("update_validator_struct", "", "SetUpdateHandlerWithOptions handler", withImports, before(
			"\t_ = workflow.SetUpdateHandlerWithOptions(ctx, \"u\", func(ctx workflow.Context, raw converter.RawValue) error { return nil },\n"+
				"\t\tworkflow.UpdateHandlerOptions{Validator: func(ctx workflow.Context, a loops.Approval) error { return nil }})")),
		sc("named_update_handler", "", "SetUpdateHandler handler",
			fx("const verifyApproval", "func approve(ctx workflow.Context, a loops.Approval) error { return nil }\n\nconst verifyApproval"),
			before("\t_ = workflow.SetUpdateHandler(ctx, \"approve\", approve)")),
		sc("sibling_file", "", "Receive target", addFile("internal/loops/fixture/receive.go",
			"package fixture\n\nimport (\n\t\"go.temporal.io/sdk/workflow\"\n\n\t"+loopsImp+"\n)\n\n"+
				"func receive(ctx workflow.Context, c workflow.ReceiveChannel) (a loops.Approval) {\n\tc.Receive(ctx, &a)\n\treturn a\n}\n")),
	})
	t.Run("conforming", func(t *testing.T) {
		got := checkSources(t, repoSources(t, withImports, before(
			"\tvar raw converter.RawValue\n\t"+sig+".Receive(ctx, &raw)\n"+
				"\t_ = "+sig+".ReceiveAsync(nil)\n"+
				"\tvar ae *temporal.ApplicationError\n\tvar d1, d2 converter.RawValue\n\t_ = ae.Details(&d1, &d2)\n"+
				"\tvar out loops.ApprovalCheck\n\t_ = workflow.ExecuteActivity(ctx, verifyApproval).Get(ctx, &out)\n"+
				"\t_ = workflow.ExecuteChildWorkflow(ctx, Workflow).Get(ctx, nil)\n"+
				"\t_ = workflow.SetUpdateHandler(ctx, \"u\", func(ctx workflow.Context, raw converter.RawValue) error { return nil })")))
		for _, v := range got {
			t.Errorf("%s: %s: %s", v.Pos, v.Rule, v.Detail)
		}
	})
}

// TestSpecEntrypoints (M0-T19c V2): no exported function, method or function
// variable of internal/loops but RunLoop and AwaitApprovals takes a LoopSpec or
// an ApprovalRequest, directly, through a pointer, slice, alias or struct: a
// RunLoopV2 copy registered as a workflow would take its spec from the input.
func TestSpecEntrypoints(t *testing.T) {
	loopsFile := func(name, body string) srcEdit {
		return addFile("internal/loops/"+name, "package loops\n\nimport (\n\t\"encoding/json\"\n\n\t\"go.temporal.io/sdk/workflow\"\n)\n\n"+
			"var _ json.RawMessage\n\nvar _ workflow.Context\n\n"+body)
	}
	runSourceCases(t, "loops-no-spec-entrypoint", "", []srcCase{
		sc("run_loop_v2", "", "RunLoopV2", loopsFile("v2.go",
			"func RunLoopV2(ctx workflow.Context, spec LoopSpec, payload json.RawMessage) (LoopResult, error) {\n\treturn LoopResult{}, nil\n}\n")),
		sc("await_approvals_v2", "", "AwaitApprovalsV2", loopsFile("v2.go",
			"func AwaitApprovalsV2(ctx workflow.Context, req ApprovalRequest) (ApprovalResult, error) {\n\treturn ApprovalResult{}, nil\n}\n")),
		sc("pointer_param", "", "RunLoopV2", loopsFile("v2.go", "func RunLoopV2(ctx workflow.Context, spec *LoopSpec) {}\n")),
		sc("variadic_param", "", "AwaitAll", loopsFile("v2.go", "func AwaitAll(ctx workflow.Context, reqs ...ApprovalRequest) {}\n")),
		sc("alias_param", "", "RunLoopV2", loopsFile("v2.go", "type SpecV2 = LoopSpec\n\nfunc RunLoopV2(ctx workflow.Context, spec SpecV2) {}\n")),
		sc("defined_type_param", "", "RunLoopV2", loopsFile("v2.go", "type SpecV2 LoopSpec\n\nfunc RunLoopV2(ctx workflow.Context, spec SpecV2) {}\n")),
		sc("wrapping_struct_param", "", "RunLoopV2",
			loopsFile("v2.go", "type Input struct{ Spec LoopSpec }\n\nfunc RunLoopV2(ctx workflow.Context, in Input) {}\n")),
		sc("exported_method", "", "Run", loopsFile("v2.go", "type Engine struct{}\n\nfunc (Engine) Run(ctx workflow.Context, spec LoopSpec) {}\n")),
		sc("exported_func_literal_var", "", "RunLoopV3",
			loopsFile("v2.go", "var RunLoopV3 = func(ctx workflow.Context, spec LoopSpec) {}\n")),
		sc("exported_var_of_unexported_func", "", "RunLoopV4",
			loopsFile("v2.go", "func runLoopV4(ctx workflow.Context, spec LoopSpec) {}\n\nvar RunLoopV4 = runLoopV4\n")),
		sc("exported_func_typed_var", "", "RunLoopV5",
			loopsFile("v2.go", "var RunLoopV5 func(workflow.Context, LoopSpec)\n")),
		// An unexported copy registered from package loops, a generic copy
		// instantiated with a spec type, in loops or outside.
		sc("unexported_used_as_value", "", "runLoopV2",
			loopsFile("v2.go", "func runLoopV2(ctx workflow.Context, spec LoopSpec) {}\n\nvar registry = []any{runLoopV2}\n")),
		sc("generic_instantiated_in_loops", "", "RunG",
			loopsFile("v2.go", "func RunG[S any](ctx workflow.Context, spec S) {}\n\nvar _ = RunG[LoopSpec]\n")),
		sc("generic_instantiated_outside", "", "RunG",
			loopsFile("v2.go", "func RunG[S any](ctx workflow.Context, spec S) {}\n"),
			fx("const verifyApproval", "var runG = loops.RunG[loops.LoopSpec]\n\nconst verifyApproval")),
		sc("generic_instantiated_with_wrapper", "", "RunG",
			loopsFile("v2.go", "func RunG[S any](ctx workflow.Context, spec S) {}\n"),
			addFile("cmd/rempart-worker/wire.go", "package main\n\nimport "+loopsImp+"\n\n"+
				"type input struct{ Spec loops.LoopSpec }\n\nvar run = loops.RunG[input]\n")),
		sc("subpackage_qualified", "", "RunFixture",
			fx("func Register(", "func RunFixture(ctx workflow.Context, spec loops.LoopSpec) {}\n\nfunc Register(")),
	})
	t.Run("conforming", func(t *testing.T) {
		// Unexported helpers (screen in approvals.go), receivers (Validate)
		// and results (Spec in the fixture) stay admitted.
		got := checkSources(t, repoSources(t, loopsFile("v2.go",
			"func check(req ApprovalRequest) bool { return req.Required > 0 }\n\n"+
				"func (s LoopSpec) Name() string { return s.ID }\n\nfunc Default() LoopSpec { return LoopSpec{} }\n\n"+
				"func pick[T any](v T) T { return v }\n\nvar _ = pick[int]\n\nvar _ = check(ApprovalRequest{})\n")))
		for _, v := range got {
			t.Errorf("%s: %s: %s", v.Pos, v.Rule, v.Detail)
		}
	})
}
