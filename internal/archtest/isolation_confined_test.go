package archtest

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// isolationCalls are the calls that build or leave namespaces and mounts
// (ADR 0015 D11, rule isolation-confined): refused outside toolexecDir, by
// import path then name.
var isolationCalls = map[string][]string{
	"syscall":               {"Mount", "Unmount", "PivotRoot", "Chroot", "Unshare", "Setns", "Sethostname"},
	"golang.org/x/sys/unix": {"Mount", "Unmount", "PivotRoot", "Chroot", "Unshare", "Setns", "Sethostname", "MoveMount", "OpenTree", "Fsopen", "Fsmount", "Fsconfig", "MountSetattr"},
}

// checkIsolationSource refuses, in a Go file outside toolexecDir, a call or a
// reference to an isolation call, through the import name in use, and a dot
// import of a package that has one.
func checkIsolationSource(name, src string) []string {
	var problems problemList
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		problems.addf("%s: cannot parse: %v", name, err)
		return problems
	}
	local := map[string]string{}
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		if _, ok := isolationCalls[p]; !ok {
			continue
		}
		n := p[strings.LastIndex(p, "/")+1:]
		if imp.Name != nil {
			n = imp.Name.Name
		}
		if n == "." {
			problems.addf("%s: dot import of %s hides its isolation calls (ADR 0015 D11)", name, p)
			continue
		}
		local[n] = p
	}
	ast.Inspect(f, func(x ast.Node) bool {
		sel, ok := x.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok {
			if p, ok := local[id.Name]; ok && slices.Contains(isolationCalls[p], sel.Sel.Name) {
				problems.addf("%s:%d: %s.%s outside %s (ADR 0015 D11, rule isolation-confined)", name, fset.Position(sel.Pos()).Line, p, sel.Sel.Name, toolexecDir)
			}
		}
		return true
	})
	return problems
}

// TestIsolationConfined proves ADR 0015 D11 (T161): no Go file outside
// toolexec mounts, pivots, unshares, enters a namespace or changes the host
// name, with negative controls.
func TestIsolationConfined(t *testing.T) {
	for _, c := range []struct {
		name, src string
		want      []string
	}{
		{"allowed_getpid", "package p\n\nimport \"syscall\"\n\nvar _ = syscall.Getpid\n", nil},
		{"mount", "package p\n\nimport \"syscall\"\n\nfunc f() { _ = syscall.Mount(\"a\", \"b\", \"\", 0, \"\") }\n", []string{"syscall.Mount"}},
		{"pivot_root", "package p\n\nimport \"syscall\"\n\nvar _ = syscall.PivotRoot\n", []string{"syscall.PivotRoot"}},
		{"unshare", "package p\n\nimport \"syscall\"\n\nvar _ = syscall.Unshare\n", []string{"syscall.Unshare"}},
		{"renamed", "package p\n\nimport sc \"syscall\"\n\nvar _ = sc.Setns\n", []string{"syscall.Setns"}},
		{"unix_open_tree", "package p\n\nimport \"golang.org/x/sys/unix\"\n\nvar _ = unix.OpenTree\n", []string{"golang.org/x/sys/unix.OpenTree"}},
		{"dot", "package p\n\nimport . \"syscall\"\n\nvar _ = Chroot\n", []string{"dot import of syscall"}},
	} {
		t.Run(c.name, func(t *testing.T) { expectProblems(t, checkIsolationSource(c.name+".go", c.src), c.want) })
	}
	_, fsys := repoRoot(t)
	files := 0
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir() && (p == ".git" || p == toolexecDir || strings.HasSuffix(p, "/testdata") || p == "testdata"):
			return fs.SkipDir
		case d.IsDir() || !strings.HasSuffix(p, ".go"):
			return nil
		}
		src, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		files++
		reportProblems(t, checkIsolationSource(p, string(src)))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 50 {
		t.Errorf("%d Go files checked, want the sources of the repository", files)
	}
}

// helperCall is the statement every main and TestMain linking toolexec
// starts with (ADR 0015 D4).
const helperCall = "toolexec.MaybeHelper"

// checkHelperFirst checks, in the Go sources srcs of one package, that the
// function fn (main or TestMain) exists and that its first statement is a call
// of helperCall (or MaybeHelper inside the toolexec package itself).
func checkHelperFirst(pkg string, srcs map[string]string, fn string, inToolexec bool) []string {
	var problems problemList
	found := false
	for name, src := range srcs {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
		if err != nil {
			problems.addf("%s: cannot parse: %v", name, err)
			continue
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Name.Name != fn {
				continue
			}
			found = true
			first := ""
			if fd.Body != nil && len(fd.Body.List) > 0 {
				if es, ok := fd.Body.List[0].(*ast.ExprStmt); ok {
					if call, ok := es.X.(*ast.CallExpr); ok && len(call.Args) == 0 {
						switch fun := call.Fun.(type) {
						case *ast.SelectorExpr:
							if id, ok := fun.X.(*ast.Ident); ok {
								first = id.Name + "." + fun.Sel.Name
							}
						case *ast.Ident:
							if inToolexec {
								first = "toolexec." + fun.Name
							}
						}
					}
				}
			}
			if first != helperCall {
				problems.addf("%s: %s of %s does not start with %s() (ADR 0015 D4, rule toolexec-helper-first)", name, fn, pkg, helperCall)
			}
		}
	}
	if !found {
		problems.addf("%s links toolexec and has no %s starting with %s() (ADR 0015 D4, rule toolexec-helper-first)", pkg, fn, helperCall)
	}
	return problems
}

// TestToolexecHelperFirst proves ADR 0015 D4 (T162): every binary that links
// toolexec, test binaries included, starts its main or TestMain with
// toolexec.MaybeHelper(), so that a run of a tool re-executing that binary
// becomes the helper and never its normal main.
func TestToolexecHelperFirst(t *testing.T) {
	for _, c := range []struct {
		name, src, fn string
		want          []string
	}{
		{"main_first", "package main\n\nimport \"x/toolexec\"\n\nfunc main() {\n\ttoolexec.MaybeHelper()\n\trun()\n}\n", "main", nil},
		{"main_second", "package main\n\nimport \"x/toolexec\"\n\nfunc main() {\n\tsetup()\n\ttoolexec.MaybeHelper()\n}\n", "main", []string{"does not start with"}},
		{"testmain_missing", "package p\n\nfunc TestX(t *testing.T) {}\n", "TestMain", []string{"has no TestMain"}},
		{"testmain_deferred", "package p\n\nfunc TestMain(m *testing.M) {\n\tdefer toolexec.MaybeHelper()\n\tos.Exit(m.Run())\n}\n", "TestMain", []string{"does not start with"}},
		{"testmain_other_call", "package p\n\nfunc TestMain(m *testing.M) {\n\tother.MaybeHelper()\n\tos.Exit(m.Run())\n}\n", "TestMain", []string{"does not start with"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			expectProblems(t, checkHelperFirst("p", map[string]string{c.name + ".go": c.src}, c.fn, false), c.want)
		})
	}

	dir, fsys := repoRoot(t)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "list", "-test", "-f", "{{.ImportPath}}|{{.Name}}|{{.Dir}}|{{join .Deps \" \"}}", "./...")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -test: %v", err)
	}
	toolexecPkg := modulePath + "/" + toolexecDir
	checked := 0
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.SplitN(line, "|", 4)
		if len(parts) != 4 || parts[1] != "main" || !slices.Contains(strings.Fields(parts[3]), toolexecPkg) {
			continue
		}
		rel, err := filepath.Rel(dir, parts[2])
		if err != nil {
			t.Fatal(err)
		}
		rel = filepath.ToSlash(rel)
		isTest := strings.HasSuffix(parts[0], ".test")
		entries, err := fs.ReadDir(fsys, rel)
		if err != nil {
			t.Fatal(err)
		}
		srcs := map[string]string{}
		for _, e := range entries {
			n := e.Name()
			if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") != isTest {
				continue
			}
			b, err := fs.ReadFile(fsys, rel+"/"+n)
			if err != nil {
				t.Fatal(err)
			}
			srcs[rel+"/"+n] = string(b)
		}
		fn := "main"
		if isTest {
			fn = "TestMain"
		}
		checked++
		reportProblems(t, checkHelperFirst(parts[0], srcs, fn, rel == toolexecDir))
	}
	if checked < 2 {
		t.Errorf("%d binaries link toolexec, want at least the tests of toolexec and validate", checked)
	}
}

// hooksVar is the switch of the test hooks of the helper (review of M3-T02b).
const hooksVar = "testHooksAllowed"

// checkHooksTestOnly refuses, in a non-test Go file, any write of hooksVar:
// an assignment, an initial value, its address taken.
func checkHooksTestOnly(name, src string) []string {
	var problems problemList
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		problems.addf("%s: cannot parse: %v", name, err)
		return problems
	}
	isVar := func(e ast.Expr) bool {
		id, ok := e.(*ast.Ident)
		return ok && id.Name == hooksVar
	}
	ast.Inspect(f, func(x ast.Node) bool {
		switch n := x.(type) {
		case *ast.AssignStmt:
			for _, l := range n.Lhs {
				if isVar(l) {
					problems.addf("%s:%d: %s assigned outside a test file (review of M3-T02b)", name, fset.Position(l.Pos()).Line, hooksVar)
				}
			}
		case *ast.ValueSpec:
			for _, id := range n.Names {
				if id.Name == hooksVar && len(n.Values) > 0 {
					problems.addf("%s:%d: %s given an initial value (review of M3-T02b)", name, fset.Position(id.Pos()).Line, hooksVar)
				}
			}
		case *ast.UnaryExpr:
			if n.Op == token.AND && isVar(n.X) {
				problems.addf("%s:%d: address of %s taken outside a test file (review of M3-T02b)", name, fset.Position(n.Pos()).Line, hooksVar)
			}
		}
		return true
	})
	return problems
}

// TestToolexecHooksTestOnly proves that the test hooks of the helper (no
// Landlock, a refused subset=pid) are switched on by a test file of toolexec
// only (T167): no other source file of toolexec, the only package that sees
// the unexported switch, writes it; with negative controls.
func TestToolexecHooksTestOnly(t *testing.T) {
	for _, c := range []struct {
		name, src string
		want      []string
	}{
		{"declared", "package p\n\nvar testHooksAllowed bool\n\nfunc f() bool { return testHooksAllowed }\n", nil},
		{"assigned", "package p\n\nfunc init() { testHooksAllowed = true }\n", []string{"assigned outside a test file"}},
		{"initial_value", "package p\n\nvar testHooksAllowed = true\n", []string{"initial value"}},
		{"address", "package p\n\nfunc f() { p := &testHooksAllowed; *p = true }\n", []string{"address of"}},
		{"multi_assign", "package p\n\nfunc f() { var x int; x, testHooksAllowed = 1, true; _ = x }\n", []string{"assigned outside a test file"}},
	} {
		t.Run(c.name, func(t *testing.T) { expectProblems(t, checkHooksTestOnly(c.name+".go", c.src), c.want) })
	}
	_, fsys := repoRoot(t)
	entries, err := fs.ReadDir(fsys, toolexecDir)
	if err != nil {
		t.Fatal(err)
	}
	checked, declared := 0, false
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		b, err := fs.ReadFile(fsys, toolexecDir+"/"+n)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		declared = declared || strings.Contains(string(b), "var "+hooksVar+" bool")
		reportProblems(t, checkHooksTestOnly(toolexecDir+"/"+n, string(b)))
	}
	if checked < 3 || !declared {
		t.Errorf("%d source files of %s checked, switch declared %v: want the sources and the declaration", checked, toolexecDir, declared)
	}
}
