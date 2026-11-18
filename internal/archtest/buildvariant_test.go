package archtest

import "testing"

// TestBuildVariantCannotHideImports (obligation (er), T103, review of the M1
// close): the import rules read the packages of go list in the default build
// configuration; a file behind a build constraint or a GOOS or GOARCH file
// name suffix would import out of their sight (an adapter, the calibration
// client or the fake key wrapper wired in the worker). Any build constraint
// in a non-test file is refused, the integration tag included (it only
// hides a file outside a test), and so is a cgo file.
func TestBuildVariantCannotHideImports(t *testing.T) {
	const m = "github.com/amezianechayer/rempart/"
	file := func(pkg, constraint, imp string) string {
		return constraint + "\n\npackage " + pkg + "\n\nimport _ \"" + imp + "\"\n"
	}
	const tag = "//go:build rempart_variant"
	runSourceCases(t, "no-build-constraint", "build constraint", []srcCase{
		sc("adapters_edge", "", "", addFile("internal/intent/zz_variant.go", file("intent", tag, m+"internal/llm/adapters/openaicompat"))),
		sc("sdk_confine_anthropic", "", "", addFile("internal/llm/zz_variant.go", file("llm", tag, "github.com/anthropics/anthropic-sdk-go"))),
		sc("sdk_confine_temporal", "", "", addFile("internal/intent/zz_variant.go", file("intent", tag, "go.temporal.io/sdk/client"))),
		sc("sdk_confine_sql", "", "", addFile("internal/intent/zz_variant.go", file("intent", tag, "database/sql"))),
		sc("fakes_wired_in_cmd", "", "", addFile("internal/intent/zz_variant.go", file("intent", tag, m+"internal/llm/fake"))),
		sc("llm_adapters_evals_cli_only", "", "", addFile("cmd/rempart-worker/zz_variant.go", file("main", tag, m+"internal/llm/adapters/openaicompat"))),
		sc("llm_calibration_evals_cli_only", "", "", addFile("cmd/rempart-worker/zz_variant.go", file("main", tag, m+"internal/llm/calibration"))),
		sc("secrets_fake_dev_only", "", "", addFile("cmd/rempart-worker/zz_variant.go", file("main", tag, m+"internal/secrets/fake"))),
		sc("domain_pure", "", "", addFile("internal/intent/domain/zz_variant.go", file("domain", tag, m+"internal/llm"))),
		sc("loops_agnostic", "", "", addFile("internal/loops/domain/zz_variant.go", file("domain", tag, m+"internal/intent"))),
		sc("legacy_plus_build", "", "", addFile("internal/intent/zz_variant.go", file("intent", "// +build rempart_variant", m+"internal/llm/fake"))),
		sc("negated_integration", "", "", addFile("internal/intent/zz_variant.go", file("intent", "//go:build !integration", m+"internal/llm/fake"))),
		sc("integration_and_more", "", "", addFile("internal/intent/zz_variant.go", file("intent", "//go:build integration && linux", m+"internal/llm/fake"))),
		sc("goos_suffix", "", "GOOS or GOARCH", addFile("cmd/rempart-worker/zz_windows.go", "package main\n\nimport _ \""+m+"internal/secrets/fake\"\n")),
		sc("goos_goarch_suffix", "", "GOOS or GOARCH", addFile("internal/intent/zz_linux_arm64.go", "package intent\n\nimport _ \""+m+"internal/llm/fake\"\n")),
		sc("goarch_suffix", "", "GOOS or GOARCH", addFile("internal/intent/zz_wasm.go", "package intent\n\nimport _ \"database/sql\"\n")),
		// Review of M2-T01: forms cmd/go reads as constraints, the integration
		// tag outside a test, and a cgo file (ignored by go list without cgo).
		sc("plus_build_no_space", "", "", addFile("cmd/rempart-worker/zz_variant.go", file("main", "//+build rempart_variant", m+"internal/secrets/fake"))),
		sc("plus_build_tab", "", "", addFile("cmd/rempart-worker/zz_variant.go", file("main", "//\t+build rempart_variant", m+"internal/secrets/fake"))),
		sc("integration_non_test", "", "", addFile("cmd/rempart-worker/zz_variant.go", file("main", "//go:build integration", m+"internal/secrets/fake"))),
		sc("cgo_file", "", "cgo", addFile("cmd/rempart-worker/zz_cgo.go", "package main\n\nimport \"C\"\n\nimport _ \""+m+"internal/secrets/fake\"\n")),
	})

	t.Run("suffix_like_names_admitted", func(t *testing.T) {
		srcs := repoSources(t, addFile("internal/intent/zz_window.go", "package intent\n\nimport _ \"strings\"\n"))
		if got := checkSources(t, srcs); len(got) != 0 {
			t.Errorf("violations %v, want none for a name that is no GOOS or GOARCH", got)
		}
	})
}
