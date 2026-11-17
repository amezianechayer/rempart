package archtest

import (
	"io/fs"
	"path"
	"strings"
	"testing"
)

// TestVerifyNeverRunsRealModel (M1-T06, ADR 0008): neither the Makefile nor
// a GitHub workflow runs the real mode of rempart-evals or reads a model key:
// the real mode is a manual tool of the human, outside make verify and CI.
func TestVerifyNeverRunsRealModel(t *testing.T) {
	_, fsys := repoRoot(t)
	files := []string{"Makefile"}
	if entries, err := fs.ReadDir(fsys, ".github/workflows"); err == nil {
		for _, e := range entries {
			if ext := path.Ext(e.Name()); ext == ".yml" || ext == ".yaml" {
				files = append(files, ".github/workflows/"+e.Name())
			}
		}
	}
	if len(files) < 2 {
		t.Fatalf("files checked %q, want the Makefile and at least one workflow", files)
	}
	for _, f := range files {
		src, err := readRepoFile(fsys, f, "M1-T06")
		if err != nil {
			t.Fatal(err)
		}
		for _, banned := range []string{"--llm", "-llm=openrouter", "-llm=anthropic", "REMPART_LLM_KEY", "OPENROUTER", "--write-baseline --llm"} {
			if strings.Contains(src, banned) {
				t.Errorf("%s contains %q: the real mode stays out of verify and CI", f, banned)
			}
		}
	}
}
