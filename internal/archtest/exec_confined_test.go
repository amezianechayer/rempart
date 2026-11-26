package archtest

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// toolexecDir is the only package that starts a process for the IaC chain
// (ADR 0014 D6, T8).
const toolexecDir = "internal/validate/toolexec"

// processStarters are the functions that start a process without os/exec,
// by import path then name (ADR 0014 D6, deviation 8).
// Raw system calls are refused too (obligation (hj)): SYS_EXECVE and
// SYS_EXECVEAT reach execve without any of the functions above.
var processStarters = map[string][]string{
	"os":                    {"StartProcess"},
	"syscall":               {"Exec", "ForkExec", "StartProcess", "Syscall", "Syscall6", "RawSyscall", "RawSyscall6"},
	"golang.org/x/sys/unix": {"Exec", "Syscall", "Syscall6", "RawSyscall", "RawSyscall6", "RawSyscallNoError", "SyscallNoError"},
}

// forbiddenImports load or run code outside Go's own process model
// (obligation (hj)): a Go plugin, and cgo.
var forbiddenImports = map[string]string{
	"plugin": "a Go plugin loads native code",
	"C":      "cgo runs native code, which can start a process",
}

// allowedTransitiveExec are the packages outside the repository and the
// standard library that import os/exec and are linked in cmd/rempart or
// cmd/rempart-worker (obligation (hj)): a new one is a dependency that can
// start a process, reviewed before it is admitted.
var allowedTransitiveExec = []string{"github.com/open-policy-agent/opa/internal/compiler/wasm"}

// checkProcessSource refuses, in a Go file outside toolexecDir, any call or
// reference to a process starter, through the import name in use (renamed
// imports included), and a dot import of a package that has one.
func checkProcessSource(name, src string) []string {
	var problems problemList
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		problems.addf("%s: cannot parse: %v", name, err)
		return problems
	}
	local := map[string]string{} // name in the file -> import path
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		if why, bad := forbiddenImports[p]; bad {
			problems.addf("%s: import %q outside %s: %s (ADR 0014 D6, T8)", name, p, toolexecDir, why)
			continue
		}
		if _, starter := processStarters[p]; !starter {
			continue
		}
		n := p[strings.LastIndex(p, "/")+1:]
		if imp.Name != nil {
			n = imp.Name.Name
		}
		if n == "." {
			problems.addf("%s: dot import of %s hides its process starters (ADR 0014 D6)", name, p)
			continue
		}
		local[n] = p
	}
	ast.Inspect(f, func(x ast.Node) bool {
		sel, ok := x.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if p, ok := local[id.Name]; ok && slices.Contains(processStarters[p], sel.Sel.Name) {
			problems.addf("%s:%d: %s.%s starts a process outside %s (ADR 0014 D6, T8)", name, fset.Position(sel.Pos()).Line, p, sel.Sel.Name, toolexecDir)
		}
		return true
	})
	return problems
}

// TestExecConfined proves ADR 0014 D6 and deviation 8 (T8): rule
// exec-confined in DefaultRules confines os/exec to toolexec, the
// architecture tests and the evaluation command; no package of the
// repository breaks it; no non-test Go file outside toolexec starts a process
// through os.StartProcess, syscall or x/sys/unix.
func TestExecConfined(t *testing.T) {
	const m = modulePath
	var rule Rule
	for _, r := range DefaultRules(m) {
		if r.Name == "exec-confined" {
			rule = r
		}
	}
	allowed := []string{m + "/" + toolexecDir, m + "/internal/archtest", m + "/cmd/rempart-evals"}
	if rule.Kind != Confine || !slices.Equal(rule.Targets, []string{"os/exec"}) || !slices.Equal(rule.AllowedFrom, allowed) {
		t.Fatalf("rule exec-confined = %+v, want Confine of os/exec to %q", rule, allowed)
	}

	t.Run("rule_negative_control", func(t *testing.T) {
		pkgs := []Package{{ImportPath: m + "/internal/iacgen", Imports: []string{"os/exec"}}, {ImportPath: m + "/" + toolexecDir, Imports: []string{"os/exec"}}}
		got := Check(m, pkgs, []Rule{rule})
		if len(got) != 1 || !strings.Contains(formatViolations(got), m+"/internal/iacgen") {
			t.Fatalf("violations = %s, want exactly internal/iacgen", formatViolations(got))
		}
	})

	t.Run("source_negative_controls", func(t *testing.T) {
		cases := []struct {
			name, src string
			want      []string
		}{
			{"allowed_kill", "package p\n\nimport \"syscall\"\n\nvar _ = syscall.Kill\n", nil},
			{"os_start_process", "package p\n\nimport \"os\"\n\nvar _ = os.StartProcess\n", []string{"os.StartProcess"}},
			{"syscall_exec", "package p\n\nimport \"syscall\"\n\nfunc f() { _ = syscall.Exec(\"/bin/sh\", nil, nil) }\n", []string{"syscall.Exec"}},
			{"syscall_fork_exec", "package p\n\nimport \"syscall\"\n\nvar _ = syscall.ForkExec\n", []string{"syscall.ForkExec"}},
			{"syscall_start_process", "package p\n\nimport \"syscall\"\n\nvar _ = syscall.StartProcess\n", []string{"syscall.StartProcess"}},
			{"unix_exec", "package p\n\nimport \"golang.org/x/sys/unix\"\n\nvar _ = unix.Exec\n", []string{"golang.org/x/sys/unix.Exec"}},
			{"renamed_syscall", "package p\n\nimport sc \"syscall\"\n\nvar _ = sc.ForkExec\n", []string{"syscall.ForkExec"}},
			{"renamed_os", "package p\n\nimport sys \"os\"\n\nvar _ = sys.StartProcess\n", []string{"os.StartProcess"}},
			{"dot_syscall", "package p\n\nimport . \"syscall\"\n\nvar _ = ForkExec\n", []string{"dot import of syscall"}},
			// Obligation (hj): raw system calls, plugins, cgo.
			{"raw_syscall_execve", "package p\n\nimport \"syscall\"\n\nfunc f() { syscall.RawSyscall(syscall.SYS_EXECVE, 0, 0, 0) }\n", []string{"syscall.RawSyscall"}},
			{"syscall6", "package p\n\nimport \"syscall\"\n\nvar _ = syscall.Syscall6\n", []string{"syscall.Syscall6"}},
			{"unix_syscall", "package p\n\nimport \"golang.org/x/sys/unix\"\n\nfunc f() { unix.Syscall(unix.SYS_EXECVEAT, 0, 0, 0) }\n", []string{"golang.org/x/sys/unix.Syscall"}},
			{"unix_raw_no_error", "package p\n\nimport \"golang.org/x/sys/unix\"\n\nvar _ = unix.RawSyscallNoError\n", []string{"golang.org/x/sys/unix.RawSyscallNoError"}},
			{"plugin_open", "package p\n\nimport \"plugin\"\n\nvar _, _ = plugin.Open(\"x.so\")\n", []string{"import \"plugin\""}},
			{"renamed_plugin", "package p\n\nimport pl \"plugin\"\n\nvar _, _ = pl.Open(\"x.so\")\n", []string{"import \"plugin\""}},
			{"cgo", "package p\n\n// #include <unistd.h>\nimport \"C\"\n\nfunc f() { C.execv(nil, nil) }\n", []string{"import \"C\""}},
			{"allowed_sys_constant", "package p\n\nimport \"syscall\"\n\nvar _ = syscall.SIGKILL\n", nil},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) { expectProblems(t, checkProcessSource(c.name+".go", c.src), c.want) })
		}
	})

	dir, fsys := repoRoot(t)
	t.Run("repository_imports", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
		defer cancel()
		pkgs, err := LoadPackages(ctx, dir)
		if err != nil {
			t.Fatalf("LoadPackages: %v", err)
		}
		if got := Check(m, pkgs, []Rule{rule}); got != nil {
			t.Errorf("exec-confined violations:\n%s", formatViolations(got))
		}
	})
	// Obligation (hj): the third-party packages linked in the binaries that
	// import os/exec are frozen.
	t.Run("transitive_importers", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}} {{join .Imports \" \"}}{{end}}", "./cmd/rempart", "./cmd/rempart-worker")
		cmd.Dir = dir
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list -deps: %v", err)
		}
		var got []string
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || !slices.Contains(fields[1:], "os/exec") || strings.HasPrefix(fields[0], m+"/") {
				continue
			}
			if !slices.Contains(got, fields[0]) {
				got = append(got, fields[0])
			}
		}
		slices.Sort(got)
		if !slices.Equal(got, allowedTransitiveExec) {
			t.Errorf("packages outside the repository importing os/exec in the binaries: %q, want %q (a new one is reviewed before it is admitted, ADR 0014 D6)", got, allowedTransitiveExec)
		}
	})
	t.Run("repository_sources", func(t *testing.T) {
		files := 0
		err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
			switch {
			case err != nil:
				return err
			case d.IsDir() && (p == ".git" || p == toolexecDir || strings.HasSuffix(p, "/testdata") || p == "testdata"):
				return fs.SkipDir
			case d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go"):
				return nil
			}
			src, err := fs.ReadFile(fsys, p)
			if err != nil {
				return err
			}
			files++
			reportProblems(t, checkProcessSource(p, string(src)))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if files < 50 {
			t.Errorf("%d Go files checked, want the sources of the repository", files)
		}
	})
}
