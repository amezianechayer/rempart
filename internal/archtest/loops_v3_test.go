package archtest

import (
	"slices"
	"testing"
)

// M0-T03b amendment V3, C4 (docs/plans/M0-pile-dev-harden.md), threat T73:
// the memo and the search attributes are also set through the raw API types
// (go.temporal.io/api, not the SDK) and through an alias of an SDK options
// type declared in one package and filled in another. The scope of
// loops-no-search-attributes covers every package under internal/loops, and
// UpsertedMemo (command.ModifyWorkflowPropertiesCommandAttributes) is refused
// as a key and as a selector.

const (
	workflowServiceImp = `workflowservice "go.temporal.io/api/workflowservice/v1"`
	commandImp         = `commandpb "go.temporal.io/api/command/v1"`
	loopsOptsImp       = `"github.com/amezianechayer/rempart/internal/loops/opts"`
)

// sdkAliasFile declares, in a package of internal/loops importing the SDK, an
// alias of the start options (a type without any composite literal).
func sdkAliasFile() srcEdit {
	return addFile("internal/loops/opts/opts.go",
		goFile("opts", []string{clientImp}, "type StartOptions = client.StartWorkflowOptions\n"))
}

func TestSearchAttributesAllLoopsPackages(t *testing.T) {
	runSourceCases(t, "loops-no-search-attributes", "", []srcCase{
		// A package of internal/loops that imports the API but not the SDK.
		sc("api_start_request_memo", "", "key Memo", addFile("internal/loops/raw/start.go",
			goFile("raw", []string{workflowServiceImp}, "var _ = workflowservice.StartWorkflowExecutionRequest{Memo: nil}\n"))),
		sc("api_start_request_search_attributes", "", "key SearchAttributes", addFile("internal/loops/raw/start.go",
			goFile("raw", []string{workflowServiceImp}, "var _ = &workflowservice.StartWorkflowExecutionRequest{SearchAttributes: nil}\n"))),
		sc("api_start_request_selector", "", "Memo", addFile("internal/loops/raw/start.go",
			goFile("raw", []string{workflowServiceImp}, "func f(r *workflowservice.StartWorkflowExecutionRequest) { r.Memo = nil }\n"))),
		sc("api_upserted_memo", "", "key UpsertedMemo", addFile("internal/loops/raw/props.go",
			goFile("raw", []string{commandImp}, "var _ = commandpb.ModifyWorkflowPropertiesCommandAttributes{UpsertedMemo: nil}\n"))),
		// Under cmd/ (already in the scope): the key alone is the fix.
		sc("api_upserted_memo_in_cmd", "", "key UpsertedMemo", addFile("cmd/rempart-worker/props.go",
			goFile("main", []string{commandImp}, "var _ = commandpb.ModifyWorkflowPropertiesCommandAttributes{UpsertedMemo: nil}\n"))),
		sc("upserted_memo_selector_in_cmd", "", "UpsertedMemo", addFile("cmd/rempart-worker/props.go",
			goFile("main", []string{commandImp}, "func f(a *commandpb.ModifyWorkflowPropertiesCommandAttributes) { a.UpsertedMemo = nil }\n"))),
		sc("upserted_memo_in_workflow", "", "key UpsertedMemo",
			fx(`"go.temporal.io/sdk/workflow"`, "\"go.temporal.io/sdk/workflow\"\n\t"+commandImp),
			beforeRun("\t_ = commandpb.ModifyWorkflowPropertiesCommandAttributes{UpsertedMemo: nil}")),
		// The alias is declared in a package importing the SDK and filled in
		// another package of internal/loops that does not import it.
		sc("alias_options_in_loops", "", "key Memo", sdkAliasFile(),
			addFile("internal/loops/launch/launch.go", goFile("launch", []string{loopsOptsImp}, "var _ = opts.StartOptions{Memo: nil}\n"))),
		sc("alias_selector_in_loops", "", "Memo", sdkAliasFile(),
			addFile("internal/loops/launch/launch.go", goFile("launch", []string{loopsOptsImp}, "func f(o *opts.StartOptions) { o.Memo = nil }\n"))),
		sc("alias_options_in_fake", "", "key TypedSearchAttributes", sdkAliasFile(),
			addFile("internal/loops/fake/launch.go", goFile("fake", []string{loopsOptsImp}, "var _ = opts.StartOptions{TypedSearchAttributes: nil}\n"))),
	})
	t.Run("positions", func(t *testing.T) {
		got := checkSources(t, repoSources(t, sdkAliasFile(),
			addFile("internal/loops/launch/launch.go", goFile("launch", []string{loopsOptsImp},
				"var _ = opts.StartOptions{ID: \"x\", Memo: nil}\n"))))
		want := []SourceViolation{{"loops-no-search-attributes", "internal/loops/launch/launch.go:7", "key Memo in a composite literal"}}
		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})
	t.Run("conforming", func(t *testing.T) {
		expectNoViolation(t,
			// Under internal/loops: fields named otherwise, maps and slices of strings.
			addFile("internal/loops/raw/start.go", goFile("raw", []string{workflowServiceImp},
				"var _ = workflowservice.StartWorkflowExecutionRequest{WorkflowId: \"x\", Namespace: \"rempart\"}\n\n"+
					"var _ = map[string]string{\"Memo\": \"x\", \"UpsertedMemo\": \"y\"}\n\n"+
					"var _ = []string{\"UpsertedMemo\"}\n")),
			sdkAliasFile(),
			addFile("internal/loops/launch/launch.go", goFile("launch", []string{loopsOptsImp},
				"var _ = opts.StartOptions{ID: \"x\", TaskQueue: \"q\"}\n")),
			// Outside the scope: a note with an UpsertedMemo field, no SDK, not cmd, not loops.
			addFile("internal/other/props.go", goFile("other", nil,
				"type props struct{ UpsertedMemo string }\n\nvar _ = props{UpsertedMemo: \"x\"}\n\n"+
					"func f(p props) string { return p.UpsertedMemo }\n")))
	})
}
