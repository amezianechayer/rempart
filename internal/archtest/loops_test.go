package archtest

import (
	"cmp"
	"maps"
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
		sc("api_renamed", "", "RunLoop not declared", srcEdit{"internal/loops/runloop.go", "func RunLoop(", "func Run("}),
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
				"\ttime := struct{ Minute int }{len(author)}\n\t_, err = loops.AwaitApprovals("),
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
// named bin; only the root bin (build outputs, ignored by git) may be skipped.
// A dev-tagged file there must not hide an import of the loops fake (T33, T41).
func TestReadSourcesNestedBin(t *testing.T) {
	file := func(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }
	fsys := fstest.MapFS{
		"go.mod":                        file("module " + modulePath + "\n"),
		"bin/rempart":                   file("\x7fELF"),
		"internal/loops/runloop.go":     file("package loops\n\nfunc RunLoop() {}\n"),
		"internal/loops/approvals.go":   file("package loops\n\nfunc AwaitApprovals() {}\n"),
		"internal/loops/fake/fake.go":   file("package fake\n"),
		"cmd/rempart-worker/bin/dev.go": file("//go:build dev\n\npackage bin\n\nimport _ " + fakeImp + "\n"),
	}
	srcs, err := ReadSources(fsys)
	if err != nil {
		t.Fatalf("ReadSources: %v", err)
	}
	if _, ok := srcs["cmd/rempart-worker/bin/dev.go"]; !ok {
		t.Fatalf("ReadSources skipped cmd/rempart-worker/bin/dev.go: %v", slices.Sorted(maps.Keys(srcs)))
	}
	got := checkSources(t, srcs)
	want := []SourceViolation{{
		"loops-fake-tests-only", "cmd/rempart-worker/bin/dev.go:5",
		modulePath + "/cmd/rempart-worker/bin imports " + modulePath + "/internal/loops/fake",
	}}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
