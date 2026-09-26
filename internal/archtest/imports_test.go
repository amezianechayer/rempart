package archtest

import (
	"context"
	"io/fs"
	"path"
	"slices"
	"strings"
	"testing"
	"time"
)

// trackSources makes every Go source, go.mod and go.sum of the repository part
// of the go test cache key. go test caches a result according to the files the
// test binary opens or inspects; the files read by the go list subprocess are
// invisible to it. Listing every directory and inspecting every source means an
// added or modified file invalidates a cached PASS.
func trackSources(t *testing.T, fsys fs.FS) {
	t.Helper()
	tracked := 0
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if p != "." && (strings.HasPrefix(name, ".") || name == "testdata" || name == "bin") {
				return fs.SkipDir
			}
			return nil
		}
		if name != "go.mod" && name != "go.sum" && path.Ext(name) != ".go" {
			return nil
		}
		if _, statErr := fs.Stat(fsys, p); statErr != nil {
			return statErr
		}
		tracked++
		return nil
	})
	if err != nil {
		t.Fatalf("tracking repository sources: %v", err)
	}
	if tracked == 0 {
		t.Fatal("tracking repository sources: no Go source found")
	}
}

func TestRepositoryConforms(t *testing.T) {
	dir, fsys := repoRoot(t)
	trackSources(t, fsys)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	pkgs, err := LoadPackages(ctx, dir)
	if err != nil {
		t.Fatalf("LoadPackages: %v", err)
	}
	const m = modulePath

	t.Run("loaded", func(t *testing.T) {
		seen := map[string]bool{}
		for _, p := range pkgs {
			if p.ImportPath != m && !strings.HasPrefix(p.ImportPath, m+"/") {
				t.Errorf("go list returned %s, outside module %s", p.ImportPath, m)
			}
			if seen[p.ImportPath] {
				t.Errorf("go list returned %s twice", p.ImportPath)
			}
			seen[p.ImportPath] = true
		}
		ref := referenceLayout()
		var want []string
		for _, b := range ref.Binaries {
			want = append(want, m+"/cmd/"+b)
		}
		for _, d := range ref.Domains {
			want = append(want, m+"/internal/"+d)
		}
		want = append(want, m+"/internal/"+testPackage)
		for _, w := range want {
			if !seen[w] {
				t.Errorf("go list did not return %s: the check would run on a partial package set", w)
			}
		}
	})

	t.Run("test_imports_excluded", func(t *testing.T) {
		i := slices.IndexFunc(pkgs, func(p Package) bool { return p.ImportPath == m+"/internal/"+testPackage })
		if i < 0 {
			t.Fatalf("go list did not return %s/internal/%s", m, testPackage)
		}
		imports := pkgs[i].Imports
		if !slices.Contains(imports, "os/exec") {
			t.Errorf("%s: Imports %q lack os/exec (imported by packages.go)", pkgs[i].ImportPath, imports)
		}
		if slices.Contains(imports, "testing") {
			t.Errorf("%s: Imports %q contain testing, test-only imports must not be decoded", pkgs[i].ImportPath, imports)
		}
	})

	t.Run("negative_control_on_real_packages", func(t *testing.T) {
		mutated := make([]Package, 0, len(pkgs))
		found := false
		for _, p := range pkgs {
			q := Package{ImportPath: p.ImportPath, Imports: slices.Clone(p.Imports)}
			if q.ImportPath == m+"/internal/loops" {
				q.Imports = append(q.Imports, m+"/internal/llm")
				found = true
			}
			mutated = append(mutated, q)
		}
		if !found {
			t.Fatalf("go list did not return %s/internal/loops", m)
		}
		got := Check(m, mutated, DefaultRules(m))
		expectViolations(t, got, []Violation{
			{Rule: "loops-agnostic", Importer: m + "/internal/loops", Imported: m + "/internal/llm"},
		})
	})

	t.Run("no_violation", func(t *testing.T) {
		for _, v := range Check(m, pkgs, DefaultRules(m)) {
			t.Errorf("%s: %s imports %s", v.Rule, v.Importer, v.Imported)
		}
	})
}
