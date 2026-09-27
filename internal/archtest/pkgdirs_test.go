package archtest

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// symlinkOrSkip creates the symbolic link name -> target, or skips the test on
// a system that cannot create one.
func symlinkOrSkip(t *testing.T, target, name string) {
	t.Helper()
	if err := os.Symlink(target, name); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
}

func mkdirs(t *testing.T, root string, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(d)), 0o750); err != nil {
			t.Fatal(err)
		}
	}
}

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestCheckPackageDirs (M0-T19c V2, threat T74): a committed directory symlink
// gives a protected package a second import path that go list ./... does not
// list but go build compiles. Every in-module package must live at the module
// root plus its relative import path, symlinks resolved, and every in-module
// import must be a listed package.
func TestCheckPackageDirs(t *testing.T) {
	const m = "example.com/m"
	root := t.TempDir()
	mkdirs(t, root, "a", "cmd/w")
	symlinkOrSkip(t, "a", filepath.Join(root, "lp"))
	link := filepath.Join(t.TempDir(), "root")
	symlinkOrSkip(t, root, link)
	dir := func(base, rel string) string { return filepath.Join(base, filepath.FromSlash(rel)) }
	ok := []Package{
		{ImportPath: m, Dir: root},
		{ImportPath: m + "/a", Dir: dir(root, "a"), Imports: []string{"fmt"}},
		{ImportPath: m + "/cmd/w", Dir: dir(root, "cmd/w"), Imports: []string{"example.com/other", "fmt", m + "/a"}},
	}
	cases := []struct {
		name string
		root string
		pkgs []Package
		want []Violation
	}{
		{"conforming", root, ok, nil},
		{"root_reached_through_symlink", link, []Package{
			{ImportPath: m + "/a", Dir: dir(link, "a")},
			{ImportPath: m + "/cmd/w", Dir: dir(link, "cmd/w"), Imports: []string{m + "/a"}},
		}, nil},
		{"out_of_module_ignored", root, []Package{
			{ImportPath: "example.com/other", Dir: "/nowhere", Imports: []string{m + "/lp"}},
			{ImportPath: "example.com/mx", Dir: "/nowhere"},
		}, nil},
		{
			"symlinked_package_listed", root, append(slices.Clone(ok),
				Package{ImportPath: m + "/lp", Dir: dir(root, "lp")}),
			[]Violation{{Rule: "package-dir", Importer: m + "/lp", Imported: dir(root, "lp")}},
		},
		{"symlinked_package_imported_not_listed", root, []Package{
			{ImportPath: m + "/a", Dir: dir(root, "a")},
			{ImportPath: m + "/cmd/w", Dir: dir(root, "cmd/w"), Imports: []string{m + "/a", m + "/lp"}},
		}, []Violation{{Rule: "package-unlisted", Importer: m + "/cmd/w", Imported: m + "/lp"}}},
		{
			"dir_of_another_package", root,
			[]Package{{ImportPath: m + "/a", Dir: dir(root, "cmd/w")}},
			[]Violation{{Rule: "package-dir", Importer: m + "/a", Imported: dir(root, "cmd/w")}},
		},
		{
			"empty_dir", root,
			[]Package{{ImportPath: m + "/a", Dir: ""}},
			[]Violation{{Rule: "package-dir", Importer: m + "/a", Imported: ""}},
		},
		{
			"missing_dir", root,
			[]Package{{ImportPath: m + "/a", Dir: dir(root, "nope")}},
			[]Violation{{Rule: "package-dir", Importer: m + "/a", Imported: dir(root, "nope")}},
		},
		{
			"relative_dir", root,
			[]Package{{ImportPath: m + "/a", Dir: "a"}},
			[]Violation{{Rule: "package-dir", Importer: m + "/a", Imported: "a"}},
		},
		{"sorted_output", root, []Package{
			{ImportPath: m + "/cmd/w", Dir: dir(root, "cmd/w"), Imports: []string{m + "/z", m + "/lp"}},
			{ImportPath: m + "/lp", Dir: dir(root, "lp")},
		}, []Violation{
			{Rule: "package-dir", Importer: m + "/lp", Imported: dir(root, "lp")},
			{Rule: "package-unlisted", Importer: m + "/cmd/w", Imported: m + "/z"},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckPackageDirs(m, c.root, c.pkgs)
			expectViolations(t, got, c.want)
			if c.want == nil && got != nil {
				t.Errorf("CheckPackageDirs returned a non-nil empty slice, want nil")
			}
		})
	}
	t.Run("missing_root", func(t *testing.T) {
		got := CheckPackageDirs(m, filepath.Join(root, "nope"), ok)
		if len(got) == 0 {
			t.Fatal("no violation for a module root that does not exist")
		}
	})
}

// TestPackageDirsRealModule builds a real module with a symlinked package
// imported by a command and runs the real go list on it.
func TestPackageDirsRealModule(t *testing.T) {
	if testing.Short() {
		t.Skip("runs go list")
	}
	const m = "example.com/m"
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"go.mod":        "module " + m + "\n\ngo 1.25\n",
		"secret/s.go":   "package secret\n\nfunc F() {}\n",
		"cmd/w/main.go": "package main\n\nimport \"" + m + "/lp\"\n\nfunc main() { secret.F() }\n",
	})
	symlinkOrSkip(t, "secret", filepath.Join(root, "lp"))
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	pkgs, err := LoadPackages(ctx, root)
	if err != nil {
		t.Fatalf("LoadPackages: %v", err)
	}
	if slices.ContainsFunc(pkgs, func(p Package) bool { return strings.HasSuffix(p.ImportPath, "/lp") }) {
		t.Logf("go list now lists the symlinked package: %v", pkgs)
	}
	got := CheckPackageDirs(m, root, pkgs)
	if !slices.ContainsFunc(got, func(v Violation) bool {
		return (v.Rule == "package-unlisted" && v.Imported == m+"/lp") || (v.Rule == "package-dir" && v.Importer == m+"/lp")
	}) {
		t.Errorf("symlinked package %s/lp not reported: %v (packages %v)", m, got, pkgs)
	}
}
