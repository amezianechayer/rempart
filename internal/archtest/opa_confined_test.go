package archtest

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	opaModule     = "github.com/open-policy-agent/opa"
	opaRegoImport = opaModule + "/v1/rego"
	opaASTImport  = opaModule + "/v1/ast"
	opaAdapterDir = "internal/policy/adapters/opa"
)

// allowedRegoSelectors is the closed list of ADR 0011 D1: the options and types
// of package rego the adapter may name. Never Target (Wasm), Runtime, Load,
// LoadBundle, Store, Trace, PrintHook, EnablePrintStatements, Function* or a
// plugin: no input-output, no state between evaluations.
var allowedRegoSelectors = []string{
	"Compiler", "EvalParsedInput", "ExpressionValue", "New", "PreparedEvalQuery",
	"Query", "Result", "ResultSet", "StrictBuiltinErrors",
}

// forbiddenASTSelectors: package ast functions that change the global builtin
// table or capabilities of every compiler of the process.
var forbiddenASTSelectors = []string{"RegisterBuiltin"}

// opaSelectors returns, for one Go source file, the OPA packages it imports and
// the selectors it applies to the rego and ast imports (any local name).
func opaSelectors(name, src string) (imports, rego, astSel []string, err error) {
	f, err := parser.ParseFile(token.NewFileSet(), name, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, nil, nil, err
	}
	local := map[string]string{} // local name -> import path
	for _, spec := range f.Imports {
		p, _ := strconv.Unquote(spec.Path.Value)
		if !strings.HasPrefix(p, opaModule) {
			continue
		}
		imports = append(imports, p)
		n := path.Base(p)
		if spec.Name != nil {
			n = spec.Name.Name
		}
		local[n] = p
	}
	ast.Inspect(f, func(node ast.Node) bool {
		sel, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		switch local[id.Name] {
		case opaRegoImport:
			rego = append(rego, sel.Sel.Name)
		case opaASTImport:
			astSel = append(astSel, sel.Sel.Name)
		}
		return true
	})
	return imports, rego, astSel, nil
}

// checkOPASource applies ADR 0011 D1 to one file of the adapter.
func checkOPASource(name, src string) []string {
	imports, rego, astSel, err := opaSelectors(name, src)
	if err != nil {
		return []string{name + ": " + err.Error()}
	}
	var problems []string
	for _, p := range imports {
		if p != opaRegoImport && p != opaASTImport {
			problems = append(problems, name+": imports "+p+" (only "+opaRegoImport+" and "+opaASTImport+")")
		}
	}
	for _, s := range rego {
		if !slices.Contains(allowedRegoSelectors, s) {
			problems = append(problems, name+": rego."+s+" outside the closed list of ADR 0011 D1")
		}
	}
	for _, s := range astSel {
		if slices.Contains(forbiddenASTSelectors, s) {
			problems = append(problems, name+": ast."+s+" changes the builtins of every compiler")
		}
	}
	return problems
}

// TestOPAConfined proves ADR 0011 D6 and D1 (T6, T109): rule opa-confined in
// DefaultRules, no violation in the repository, the adapter as the only
// importer of OPA and of the embedded pack, no OPA under internal/graph,
// internal/design, internal/threat, internal/intent (criterion 5 of M2-T03),
// and the adapter limited to the closed list of rego options.
func TestOPAConfined(t *testing.T) {
	const m = modulePath
	var rule Rule
	for _, r := range DefaultRules(m) {
		if r.Name == "opa-confined" {
			rule = r
		}
	}
	if rule.Kind != Confine || !slices.Equal(rule.Targets, []string{opaModule + "/...", m + "/policies/..."}) ||
		!slices.Equal(rule.AllowedFrom, []string{m + "/" + opaAdapterDir + "/..."}) {
		t.Fatalf("rule opa-confined = %+v, want Confine of %s/... and %s/policies/... to %s/%s/...", rule, opaModule, m, m, opaAdapterDir)
	}

	t.Run("source_negative_controls", func(t *testing.T) {
		const head = "package opa\n\nimport (\n\t\"github.com/open-policy-agent/opa/v1/ast\"\n\t\"github.com/open-policy-agent/opa/v1/rego\"\n)\n\n"
		cases := []struct {
			name, src string
			want      []string
		}{
			{"allowed", head + "var _ = rego.New(rego.Query(\"data.x\"), rego.StrictBuiltinErrors(true))\nvar _ = ast.NewCompiler\n", nil},
			{"wasm_target", head + "var _ = rego.Target(\"wasm\")\nvar _ = ast.NewCompiler\n", []string{"rego.Target"}},
			{"runtime", head + "var _ = rego.Runtime(nil)\nvar _ = ast.NewCompiler\n", []string{"rego.Runtime"}},
			{"print_hook", head + "var _ = rego.EnablePrintStatements(true)\nvar _ = ast.NewCompiler\n", []string{"rego.EnablePrintStatements"}},
			{"custom_function", head + "var _ = rego.Function1\nvar _ = ast.NewCompiler\n", []string{"rego.Function1"}},
			{"store", head + "var _ = rego.Store(nil)\nvar _ = ast.NewCompiler\n", []string{"rego.Store"}},
			{"global_builtin", head + "var _ = rego.New\nfunc init() { ast.RegisterBuiltin(nil) }\n", []string{"ast.RegisterBuiltin"}},
			{"renamed_import", "package opa\n\nimport r \"github.com/open-policy-agent/opa/v1/rego\"\n\nvar _ = r.Trace(true)\n", []string{"rego.Trace"}},
			{"other_package", "package opa\n\nimport \"github.com/open-policy-agent/opa/v1/topdown\"\n\nvar _ = topdown.Eval\n", []string{"imports " + opaModule + "/v1/topdown"}},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) { expectProblems(t, checkOPASource(c.name+".go", c.src), c.want) })
		}
	})

	dir, fsys := repoRoot(t)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	pkgs, err := LoadPackages(ctx, dir)
	if err != nil {
		t.Fatalf("LoadPackages: %v", err)
	}

	t.Run("repository", func(t *testing.T) {
		if got := Check(m, pkgs, []Rule{rule}); got != nil {
			t.Errorf("opa-confined violations:\n%s", formatViolations(got))
		}
		var importers []string
		for _, p := range pkgs {
			if slices.ContainsFunc(p.Imports, func(i string) bool { return Match(opaModule+"/...", i) || Match(m+"/policies/...", i) }) {
				importers = append(importers, p.ImportPath)
			}
		}
		if want := []string{m + "/" + opaAdapterDir}; !slices.Equal(importers, want) {
			t.Errorf("importers of OPA or of the pack %q, want exactly %q", importers, want)
		}
	})

	t.Run("pure_domains_without_opa", func(t *testing.T) {
		byPath := map[string]Package{}
		for _, p := range pkgs {
			byPath[p.ImportPath] = p
		}
		var reaches func(p string, seen map[string]bool) bool
		reaches = func(p string, seen map[string]bool) bool {
			if seen[p] {
				return false
			}
			seen[p] = true
			for _, i := range byPath[p].Imports {
				if strings.HasPrefix(i, opaModule) || i == m+"/policies" || i == m+"/"+opaAdapterDir {
					return true
				}
				if _, own := byPath[i]; own && reaches(i, seen) {
					return true
				}
			}
			return false
		}
		checked := 0
		for _, p := range pkgs {
			for _, root := range []string{"internal/graph", "internal/design", "internal/threat", "internal/intent"} {
				if Match(m+"/"+root+"/...", p.ImportPath) {
					checked++
					if reaches(p.ImportPath, map[string]bool{}) {
						t.Errorf("%s reaches OPA or the policy adapter", p.ImportPath)
					}
				}
			}
		}
		if checked < 4 {
			t.Errorf("only %d packages checked under the pure roots", checked)
		}
	})

	t.Run("adapter_options_closed", func(t *testing.T) {
		entries, err := fs.ReadDir(fsys, opaAdapterDir)
		if err != nil {
			t.Fatalf("%s: %v", opaAdapterDir, err)
		}
		var regoSeen int
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			raw, err := fs.ReadFile(fsys, opaAdapterDir+"/"+name)
			if err != nil {
				t.Fatal(err)
			}
			_, rego, _, err := opaSelectors(name, string(raw))
			if err != nil {
				t.Fatal(err)
			}
			regoSeen += len(rego)
			reportProblems(t, checkOPASource(opaAdapterDir+"/"+name, string(raw)))
		}
		if regoSeen == 0 {
			t.Errorf("%s: no rego selector found, the check saw nothing", opaAdapterDir)
		}
	})
}
