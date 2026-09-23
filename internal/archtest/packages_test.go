package archtest

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestDecodePackages(t *testing.T) {
	t.Run("valid_stream", func(t *testing.T) {
		// The package without Imports comes after one with Imports: a decoder
		// that reused its value would leak the previous imports.
		in := "{\n\t\"ImportPath\": \"example.com/m/a\",\n\t\"Imports\": [\n\t\t\"fmt\",\n\t\t\"example.com/m/b\"\n\t]\n}\n" +
			"{\n\t\"ImportPath\": \"example.com/m/b\"\n}\n" +
			"{\"ImportPath\":\"example.com/m/c\",\"Imports\":[\"example.com/m/a\"]}"
		got, err := decodePackages(strings.NewReader(in))
		if err != nil {
			t.Fatalf("decodePackages: %v", err)
		}
		want := []Package{
			{ImportPath: "example.com/m/a", Imports: []string{"fmt", "example.com/m/b"}},
			{ImportPath: "example.com/m/b", Imports: nil},
			{ImportPath: "example.com/m/c", Imports: []string{"example.com/m/a"}},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("decodePackages = %#v, want %#v", got, want)
		}
		if len(got) == 3 && got[1].Imports != nil {
			t.Errorf("package without Imports decoded with Imports %q, want nil", got[1].Imports)
		}
	})

	t.Run("unknown_fields_ignored", func(t *testing.T) {
		in := `{"Dir": "/src/m/a", "ImportPath": "example.com/m/a", "Name": "a",
			"GoFiles": ["a.go"], "Standard": false, "TestImports": ["testing"],
			"XTestImports": ["example.com/m/fake"], "Imports": ["fmt"], "Deps": ["fmt", "io"]}`
		got, err := decodePackages(strings.NewReader(in))
		if err != nil {
			t.Fatalf("decodePackages: %v", err)
		}
		want := []Package{{ImportPath: "example.com/m/a", Imports: []string{"fmt"}}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("decodePackages = %#v, want %#v (test imports must not be decoded)", got, want)
		}
	})

	rejected := []struct{ name, in string }{
		{"truncated", `{"ImportPath": "example.com/m/a", "Imports": ["fmt"`},
		{"truncated_second_object", `{"ImportPath": "example.com/m/a"} {"ImportPath": "exa`},
		{"not_an_object", `[1]`},
		{"string_value", `"example.com/m/a"`},
		{"null_value", `null`},
		{"import_path_wrong_type", `{"ImportPath": 3}`},
		{"imports_wrong_type", `{"ImportPath": "example.com/m/a", "Imports": "fmt"}`},
		{"empty_import_path", `{"ImportPath": "", "Imports": ["fmt"]}`},
		{"missing_import_path", `{"Imports": ["fmt"]}`},
		{"duplicate_import_path", `{"ImportPath": "example.com/m/a"} {"ImportPath": "example.com/m/b"} {"ImportPath": "example.com/m/a"}`},
		{"trailing_garbage", `{"ImportPath": "example.com/m/a"}}{`},
		{"not_json", `go: cannot find main module`},
	}
	for _, c := range rejected {
		t.Run(c.name, func(t *testing.T) {
			got, err := decodePackages(strings.NewReader(c.in))
			if !errors.Is(err, ErrDecode) {
				t.Fatalf("decodePackages(%q) = %v, %v; want ErrDecode", c.in, got, err)
			}
			if errors.Is(err, ErrNoPackages) {
				t.Errorf("error %v also matches ErrNoPackages", err)
			}
		})
	}

	for _, in := range []string{"", " \n\t\n"} {
		t.Run("empty_stream", func(t *testing.T) {
			got, err := decodePackages(strings.NewReader(in))
			if !errors.Is(err, ErrNoPackages) {
				t.Fatalf("decodePackages(%q) = %v, %v; want ErrNoPackages", in, got, err)
			}
		})
	}
}

func TestGoListEnv(t *testing.T) {
	const (
		readonly = "GOFLAGS=-mod=readonly"
		workOff  = "GOWORK=off"
	)
	cases := []struct {
		name    string
		environ []string
		want    []string
	}{
		{
			name:    "empty",
			environ: nil,
			want:    []string{readonly, workOff},
		},
		{
			name: "inherited_kept_in_order",
			environ: []string{
				"PATH=/usr/local/go/bin:/usr/bin", "HOME=/home/dev", "GOCACHE=/home/dev/.cache/go-build",
				"GOPROXY=https://proxy.golang.org", "GOTOOLCHAIN=auto",
			},
			want: []string{
				"PATH=/usr/local/go/bin:/usr/bin", "HOME=/home/dev", "GOCACHE=/home/dev/.cache/go-build",
				"GOPROXY=https://proxy.golang.org", "GOTOOLCHAIN=auto", readonly, workOff,
			},
		},
		{
			name:    "goflags_mod_removed",
			environ: []string{"PATH=/usr/bin", "GOFLAGS=-mod=mod", "HOME=/home/dev"},
			want:    []string{"PATH=/usr/bin", "HOME=/home/dev", readonly, workOff},
		},
		{
			name:    "goflags_tags_removed",
			environ: []string{"GOFLAGS=-tags=x", "PATH=/usr/bin"},
			want:    []string{"PATH=/usr/bin", readonly, workOff},
		},
		{
			name:    "gowork_removed",
			environ: []string{"GOWORK=/tmp/go.work", "PATH=/usr/bin"},
			want:    []string{"PATH=/usr/bin", readonly, workOff},
		},
		{
			name:    "empty_values_removed",
			environ: []string{"GOFLAGS=", "GOWORK=", "PATH=/usr/bin"},
			want:    []string{"PATH=/usr/bin", readonly, workOff},
		},
		{
			name:    "repeated_entries_removed",
			environ: []string{"GOFLAGS=-mod=mod", readonly, "GOWORK=off", "GOFLAGS=-tags=x", "GOWORK=/w/go.work"},
			want:    []string{readonly, workOff},
		},
		{
			name:    "neighbour_keys_kept",
			environ: []string{"GOFLAGSX=1", "XGOFLAGS=2", "GOWORKDIR=/w", "GOFLAGS=-mod=mod"},
			want:    []string{"GOFLAGSX=1", "XGOFLAGS=2", "GOWORKDIR=/w", readonly, workOff},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := slices.Clone(c.environ)
			got := goListEnv(c.environ)
			if !slices.Equal(got, c.want) {
				t.Errorf("goListEnv(%q) = %q, want %q", c.environ, got, c.want)
			}
			if !slices.Equal(c.environ, before) {
				t.Errorf("goListEnv modified its input: %q, was %q", c.environ, before)
			}
			for _, key := range []string{"GOFLAGS=", "GOWORK="} {
				n := 0
				for _, e := range got {
					if strings.HasPrefix(e, key) {
						n++
					}
				}
				if n != 1 {
					t.Errorf("goListEnv: %d entries with prefix %s, want exactly 1", n, key)
				}
			}
		})
	}
}

func TestGoListCommand(t *testing.T) {
	const dir = "/nonexistent/module"
	env := []string{"PATH=/usr/bin", "GOFLAGS=-mod=mod", "GOWORK=/tmp/go.work", "HOME=/home/dev"}
	cmd := goListCmd(t.Context(), dir, env)
	if cmd == nil {
		t.Fatal("goListCmd returned nil")
	}
	if want := []string{"go", "list", "-json", "./..."}; !slices.Equal(cmd.Args, want) {
		t.Errorf("Args = %q, want %q", cmd.Args, want)
	}
	if base := filepath.Base(cmd.Path); base != "go" && base != "go.exe" {
		t.Errorf("Path = %q, want the go binary", cmd.Path)
	}
	if cmd.Dir != dir {
		t.Errorf("Dir = %q, want %q", cmd.Dir, dir)
	}
	if want := goListEnv(env); !slices.Equal(cmd.Env, want) {
		t.Errorf("Env = %q, want %q", cmd.Env, want)
	}
	if cmd.WaitDelay <= 0 {
		t.Errorf("WaitDelay = %v, want a positive bound", cmd.WaitDelay)
	}
	if cmd.Stdin != nil {
		t.Errorf("Stdin = %v, want nil (/dev/null)", cmd.Stdin)
	}
	if cmd.Process != nil {
		t.Errorf("goListCmd started the process, want a command built but not run")
	}
}

// Rules of checkExecUsage, the static proof that the production code of this
// package runs no shell and exactly one process, `go list -json ./...`.
const (
	execFile      = "packages.go"
	execImport    = "os/exec"
	execCallName  = "CommandContext"
	execShortName = "Command"
)

func goListArgs() []string { return []string{"go", "list", "-json", "./..."} }

func forbiddenShellLiterals() []string {
	return []string{"sh", "bash", "/bin/sh", "/bin/bash", "-c", "cmd.exe", "powershell"}
}

func forbiddenSelectors() map[string][]string {
	return map[string][]string{
		"os":      {"StartProcess"},
		"syscall": {"Exec", "ForkExec", "StartProcess"},
	}
}

// checkExecUsage parses the given non-test Go files (name to source) and
// reports every departure from the process execution rule.
func checkExecUsage(files map[string]string) []string {
	var problems problemList
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	calls := 0
	importedBy := false
	for _, name := range names {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, files[name], parser.SkipObjectResolution)
		if err != nil {
			problems.addf("%s: cannot parse: %v", name, err)
			continue
		}
		execName := ""
		for _, imp := range f.Imports {
			p, unqErr := strconv.Unquote(imp.Path.Value)
			if unqErr != nil || p != execImport {
				continue
			}
			if name != execFile {
				problems.addf("%s: imports %s, only %s may", name, execImport, execFile)
			}
			importedBy = importedBy || name == execFile
			execName = "exec"
			if imp.Name != nil {
				execName = imp.Name.Name
			}
			if execName == "." || execName == "_" {
				problems.addf("%s: imports %s as %q, want a plain import", name, execImport, execName)
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BasicLit:
				if x.Kind == token.STRING {
					if s, unqErr := strconv.Unquote(x.Value); unqErr == nil && slices.Contains(forbiddenShellLiterals(), s) {
						problems.addf("%s:%d: shell string literal %q", name, fset.Position(x.Pos()).Line, s)
					}
				}
			case *ast.SelectorExpr:
				id, ok := x.X.(*ast.Ident)
				if !ok {
					return true
				}
				if slices.Contains(forbiddenSelectors()[id.Name], x.Sel.Name) {
					problems.addf("%s:%d: forbidden process call %s.%s", name, fset.Position(x.Pos()).Line, id.Name, x.Sel.Name)
				}
				if execName != "" && id.Name == execName && x.Sel.Name == execShortName {
					problems.addf("%s:%d: exec.Command without context", name, fset.Position(x.Pos()).Line)
				}
			case *ast.CallExpr:
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				id, ok := sel.X.(*ast.Ident)
				if !ok || execName == "" || id.Name != execName || sel.Sel.Name != execCallName {
					return true
				}
				calls++
				problems = append(problems, checkCommandArgs(name, fset.Position(x.Pos()).Line, x)...)
			}
			return true
		})
	}
	if !importedBy {
		problems.addf("%s: does not import %s", execFile, execImport)
	}
	if calls != 1 {
		problems.addf("%d calls to exec.%s, want exactly 1", calls, execCallName)
	}
	return problems
}

// checkCommandArgs checks that exec.CommandContext receives a context then
// exactly the four string literals of goListArgs, without a spread slice.
func checkCommandArgs(name string, line int, call *ast.CallExpr) []string {
	var problems problemList
	if call.Ellipsis.IsValid() {
		problems.addf("%s:%d: exec.%s with variable arguments (spread slice)", name, line, execCallName)
	}
	want := goListArgs()
	if len(call.Args) != 1+len(want) {
		problems.addf("%s:%d: exec.%s has %d arguments after the context, want %d literals %q",
			name, line, execCallName, len(call.Args)-1, len(want), want)
		return problems
	}
	for i, arg := range call.Args[1:] {
		lit, ok := arg.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			problems.addf("%s:%d: exec.%s argument %d is not a string literal, want %q",
				name, line, execCallName, i+1, want[i])
			continue
		}
		if s, err := strconv.Unquote(lit.Value); err != nil || s != want[i] {
			problems.addf("%s:%d: exec.%s argument %d is %s, want %q", name, line, execCallName, i+1, lit.Value, want[i])
		}
	}
	return problems
}

const validPackagesSource = `package archtest

import (
	"context"
	"os/exec"
	"time"
)

func goListCmd(ctx context.Context, moduleDir string, environ []string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "go", "list", "-json", "./...")
	cmd.Dir = moduleDir
	cmd.Env = goListEnv(environ)
	cmd.WaitDelay = 10 * time.Second
	return cmd
}
`

const validRulesSource = `package archtest

import "strings"

func isStdlib(p string) bool {
	first, _, _ := strings.Cut(p, "/")
	return first != "" && !strings.Contains(first, ".")
}
`

func TestLoadPackagesNoShell(t *testing.T) {
	t.Run("negative_controls", func(t *testing.T) {
		valid := func() map[string]string {
			return map[string]string{execFile: validPackagesSource, "rules.go": validRulesSource}
		}
		withPackages := func(t *testing.T, old, replacement string) map[string]string {
			t.Helper()
			files := valid()
			files[execFile] = mustReplace(t, files[execFile], old, replacement)
			return files
		}
		const call = `exec.CommandContext(ctx, "go", "list", "-json", "./...")`
		cases := []struct {
			name  string
			files func(t *testing.T) map[string]string
			want  []string
		}{
			{"valid", func(*testing.T) map[string]string { return valid() }, nil},
			{"shell_wrapper", func(t *testing.T) map[string]string {
				return withPackages(t, call, `exec.CommandContext(ctx, "sh", "-c", "go list -json ./...")`)
			}, []string{`shell string literal "sh"`, `shell string literal "-c"`, "arguments after the context"}},
			{"bash_absolute_path", func(t *testing.T) map[string]string {
				return withPackages(t, call, `exec.CommandContext(ctx, "/bin/bash", "-c", "go", "list")`)
			}, []string{`shell string literal "/bin/bash"`, `argument 1 is "/bin/bash"`}},
			{"variable_args", func(t *testing.T) map[string]string {
				return withPackages(t, call, `exec.CommandContext(ctx, "go", args...)`)
			}, []string{"spread slice"}},
			{"variable_binary", func(t *testing.T) map[string]string {
				return withPackages(t, call, `exec.CommandContext(ctx, moduleDir, "list", "-json", "./...")`)
			}, []string{"argument 1 is not a string literal"}},
			{"wrong_arguments", func(t *testing.T) map[string]string {
				return withPackages(t, call, `exec.CommandContext(ctx, "go", "list", "-json", "-deps", "./...")`)
			}, []string{"has 5 arguments after the context"}},
			{"command_without_context", func(t *testing.T) map[string]string {
				return withPackages(t, call, `exec.Command("go", "list", "-json", "./...")`)
			}, []string{"exec.Command without context", "0 calls to exec.CommandContext"}},
			{"renamed_import", func(t *testing.T) map[string]string {
				files := withPackages(t, `"os/exec"`, `run "os/exec"`)
				files[execFile] = mustReplace(t, files[execFile], call,
					`run.Command("go", "list", "-json", "./...")`)
				return files
			}, []string{"exec.Command without context"}},
			{"exec_outside_packages_go", func(t *testing.T) map[string]string {
				files := valid()
				files["rules.go"] = mustReplace(t, files["rules.go"], `import "strings"`,
					"import (\n\t\"os/exec\"\n\t\"strings\"\n)\n\nvar _ = exec.ErrDot")
				return files
			}, []string{"rules.go: imports os/exec, only packages.go may"}},
			{"start_process", func(t *testing.T) map[string]string {
				files := valid()
				files["rules.go"] = mustReplace(t, files["rules.go"], `import "strings"`,
					"import (\n\t\"os\"\n\t\"strings\"\n)\n\nvar _, _ = os.StartProcess(\"/usr/bin/env\", nil, nil)")
				return files
			}, []string{"forbidden process call os.StartProcess"}},
			{"syscall_exec", func(t *testing.T) map[string]string {
				files := valid()
				files["rules.go"] = mustReplace(t, files["rules.go"], `import "strings"`,
					"import (\n\t\"strings\"\n\t\"syscall\"\n)\n\nvar _ = syscall.Exec(\"/usr/bin/env\", nil, nil)")
				return files
			}, []string{"forbidden process call syscall.Exec"}},
			{"syscall_fork_exec", func(t *testing.T) map[string]string {
				files := valid()
				files["rules.go"] = mustReplace(t, files["rules.go"], `import "strings"`,
					"import (\n\t\"strings\"\n\t\"syscall\"\n)\n\nvar _, _ = syscall.ForkExec(\"/usr/bin/env\", nil, nil)")
				return files
			}, []string{"forbidden process call syscall.ForkExec"}},
			{"second_command", func(t *testing.T) map[string]string {
				return withPackages(t, "\treturn cmd\n",
					"\t_ = exec.CommandContext(ctx, \"go\", \"list\", \"-json\", \"./...\")\n\treturn cmd\n")
			}, []string{"2 calls to exec.CommandContext"}},
			{"powershell_literal", func(t *testing.T) map[string]string {
				files := valid()
				files["rules.go"] = mustReplace(t, files["rules.go"], `"/"`, `"powershell"`)
				return files
			}, []string{`shell string literal "powershell"`}},
			{"missing_packages_go", func(*testing.T) map[string]string {
				return map[string]string{"rules.go": validRulesSource}
			}, []string{"packages.go: does not import os/exec", "0 calls to exec.CommandContext"}},
			{"unparsable_file", func(*testing.T) map[string]string {
				files := valid()
				files["rules.go"] = "package archtest\n\nfunc {"
				return files
			}, []string{"rules.go: cannot parse"}},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				expectProblems(t, checkExecUsage(c.files(t)), c.want)
			})
		}
	})

	t.Run("repository", func(t *testing.T) {
		_, fsys := repoRoot(t)
		const dir = "internal/archtest"
		entries, err := fs.ReadDir(fsys, dir)
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		files := map[string]string{}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			data, readErr := fs.ReadFile(fsys, path.Join(dir, name))
			if readErr != nil {
				t.Fatalf("%s/%s: %v", dir, name, readErr)
			}
			files[name] = string(data)
		}
		for _, required := range []string{"packages.go", "rules.go"} {
			if _, ok := files[required]; !ok {
				t.Errorf("%s/%s: file does not exist", dir, required)
			}
		}
		reportProblems(t, checkExecUsage(files))
	})
}

func TestLoadPackagesErrors(t *testing.T) {
	t.Run("empty_dir", func(t *testing.T) {
		pkgs, err := LoadPackages(t.Context(), "")
		if !errors.Is(err, ErrModuleDir) {
			t.Fatalf("LoadPackages(\"\") = %v, %v; want ErrModuleDir", pkgs, err)
		}
	})

	t.Run("canceled_context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		pkgs, err := LoadPackages(ctx, t.TempDir())
		if !errors.Is(err, ErrGoList) || !errors.Is(err, context.Canceled) {
			t.Fatalf("LoadPackages with a canceled context = %v, %v; want ErrGoList wrapping context.Canceled", pkgs, err)
		}
		if pkgs != nil {
			t.Errorf("LoadPackages returned packages %v with an error", pkgs)
		}
	})

	t.Run("no_go_mod", func(t *testing.T) {
		pkgs, err := LoadPackages(t.Context(), t.TempDir())
		if !errors.Is(err, ErrGoList) {
			t.Fatalf("LoadPackages outside a module = %v, %v; want ErrGoList", pkgs, err)
		}
		// The tail of go list stderr is part of the message. Go 1.27.1 says
		// "directory prefix . does not contain main module"; older releases
		// mention go.mod.
		if msg := err.Error(); !strings.Contains(msg, "main module") && !strings.Contains(msg, "go.mod") {
			t.Errorf("error %q does not carry the go list diagnostic (main module or go.mod)", msg)
		}
		if pkgs != nil {
			t.Errorf("LoadPackages returned packages %v with an error", pkgs)
		}
	})

	t.Run("module_without_packages", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/empty\n\ngo 1.24\n"), 0o600); err != nil {
			t.Fatalf("write go.mod: %v", err)
		}
		pkgs, err := LoadPackages(t.Context(), dir)
		if !errors.Is(err, ErrNoPackages) {
			t.Fatalf("LoadPackages on a module without packages = %v, %v; want ErrNoPackages", pkgs, err)
		}
		if errors.Is(err, ErrGoList) {
			t.Errorf("error %v matches ErrGoList, want only ErrNoPackages (go list exits 0)", err)
		}
	})
}
