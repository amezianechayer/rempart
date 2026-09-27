# M0-T19c `loops-archtest` : règles de source de `internal/loops`

2026-09-27, `architect`, proposé. Cadrage : `M0-overview.md` 0 bis, `M0-demo-prep.md` 12 et 13, obligations (d), (k), (l), (p), décision 5 de M0-T19b. Sans ADR. Revue sécurité : oui.

## 0. Amendements

BASE `7873925`. Aucun.

## 1. Objet

Rendre mécaniques (d), (p) (T54), (l), (k) (T41) par `go/ast` et `go/parser` seuls, `go.mod` inchangé ; retirer `workflowcheck.config.yaml`. Hors : `internal/loops`, T19d, T20.

## 2. Décisions

- **D1** Syntaxe seule ; `go/types` écarté (importeur lent ou nouvelle dépendance `x/tools`). Échec fermé, faux positifs acceptés.
- **D2** Tout `.go` non test, **toutes étiquettes** (T33), hors `.x`, `_x`, `testdata`, `bin`. `RunLoop` et `AwaitApprovals` déclarés exactement une fois, sinon échec.
- **D3 Enregistrement.** Référence aux deux fonctions (alias quelconque, ou nue dans `loops`) : appelé direct seulement, ce qui exclut `RegisterWorkflow*`, `Execute*Workflow`, `NewContinueAsNewError`, affectation. Chaîne les nommant refusée hors `internal/archtest`. Import `.` refusé.
- **D4 Spécification.** Argument `F()` ou `pkg.F()`, `F` unique, `func() loops.LoopSpec { return <littéral> }`, clés de `contract` sans doublon, requises présentes, valeurs constantes. Variable de paquet, littéral en ligne, paramètre, variante d'étiquette : refusés.
- **D5 Requête.** Littéral `loops.ApprovalRequest` dans l'appel ; `Required`, `NeedsSecurityRole`, `VerifyActivity`, `MaxIgnored` constants ; `PlanHash`, `Author`, délai libres (délai borné).
- **D6 Constante.** Littéral, `true`, `false`, constante de paquet unique, unité de `time`, opérateurs, `[]string{...}` ; un nom déclaré dans la déclaration englobante masque.
- **D7 Décodage.** Code de workflow (`loops`, `domain`, `codec`, fichier important `sdk/workflow`) : pas d'import `json` (sauf `encoding/json`), `yaml`, `toml`, `gob`, `xml`, `asn1`, `csv` ; seuls `json.RawMessage` et `converter.{RawValue,MetadataEncoding,MetadataEncodingJSON}`. Tout `internal/loops/...` : ni `Unmarshal*` ni `GobDecode` (le convertisseur du SDK les appelle hors de vue de workflowcheck).
- **D8 Faux.** `loops-fake-tests-only` dans `DefaultRules` (`Confine`, aucun importeur) et règle de source homonyme, qui voit les fichiers étiquetés.
- **D9** `workflowcheck.config.yaml` supprimé, `-config` retiré.

## 3. Code de référence, `internal/archtest/loopsrc.go`

```go
package archtest

import (
	"cmp"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"
)

type SourceFile struct {
	Path, Pkg string // path from the module root; import path of its directory
	File      *ast.File
	Fset      *token.FileSet
}

type SourceViolation struct{ Rule, Pos, Detail string }

// contract: fields admitted in the loops literals; "?" marks an optional one.
var contract = map[string]string{
	"LoopSpec":        "ID ProposeActivity VerifyActivity Strategies Budget ?SwitchAfter ?EscalateAfter ?ActivityTimeout",
	"Budget":          "MaxIterations MaxTokens MaxWallTime",
	"ApprovalRequest": "PlanHash Author Required NeedsSecurityRole VerifyActivity ?MaxIgnored",
}

func ReadSources(fsys fs.FS) (map[string]string, error) {
	srcs := map[string]string{}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() && (path.Ext(p) != ".go" || strings.HasSuffix(p, "_test.go")) {
			return err
		}
		if n := d.Name(); d.IsDir() && p != "." && (n[0] == '.' || n[0] == '_' || n == "testdata" || n == "bin") {
			return fs.SkipDir
		}
		if !d.IsDir() {
			b, err := fs.ReadFile(fsys, p)
			srcs[p] = string(b)
			return err
		}
		return nil
	})
	return srcs, err
}

func ParseSources(module string, srcs map[string]string) ([]SourceFile, error) {
	fset := token.NewFileSet()
	var out []SourceFile
	for _, p := range slices.Sorted(maps.Keys(srcs)) {
		f, err := parser.ParseFile(fset, p, srcs[p], parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			return nil, fmt.Errorf("archtest: %w", err)
		}
		pkg := module
		if d := path.Dir(p); d != "." {
			pkg += "/" + d
		}
		out = append(out, SourceFile{p, pkg, f, fset})
	}
	return out, nil
}

func guarded(name string) string {
	return map[string]string{"RunLoop": "runloop-not-registered", "AwaitApprovals": "await-approvals-not-registered"}[name]
}

type funcRef struct {
	decl *ast.FuncDecl
	file *SourceFile
}

type srcChecker struct {
	module, loops string
	kind          map[string]string // "pkg.name" -> const, var, type, func, or dup (build variants)
	funcs         map[string]funcRef
	imps          map[*ast.File]map[string]string
	out           []SourceViolation
}

func CheckLoopSources(module string, files []SourceFile) []SourceViolation {
	c := &srcChecker{
		module: module, loops: module + "/internal/loops", kind: map[string]string{},
		funcs: map[string]funcRef{}, imps: map[*ast.File]map[string]string{},
	}
	for i := range files {
		c.index(&files[i])
	}
	for i := range files {
		c.file(&files[i])
	}
	for _, fn := range []string{"RunLoop", "AwaitApprovals"} {
		if c.kind[c.loops+"."+fn] != "func" {
			c.out = append(c.out, SourceViolation{guarded(fn), c.loops, fn + " not declared once in package loops"})
		}
	}
	slices.SortFunc(c.out, func(a, b SourceViolation) int {
		return cmp.Or(cmp.Compare(a.Pos, b.Pos), cmp.Compare(a.Rule, b.Rule), cmp.Compare(a.Detail, b.Detail))
	})
	return slices.Compact(c.out)
}

func (c *srcChecker) index(sf *SourceFile) {
	imp := map[string]string{}
	for _, is := range sf.File.Imports {
		p, _ := strconv.Unquote(is.Path.Value)
		name := path.Base(p)
		if is.Name != nil {
			name = is.Name.Name
		}
		imp[name] = p
	}
	c.imps[sf.File] = imp
	declare := func(name, kind string) {
		if _, seen := c.kind[sf.Pkg+"."+name]; seen {
			kind = "dup"
		}
		c.kind[sf.Pkg+"."+name] = kind
	}
	for _, d := range sf.File.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil {
				declare(d.Name.Name, "func")
				c.funcs[sf.Pkg+"."+d.Name.Name] = funcRef{d, sf}
			}
		case *ast.GenDecl:
			for _, s := range d.Specs {
				switch s := s.(type) {
				case *ast.ValueSpec:
					for _, n := range s.Names {
						declare(n.Name, d.Tok.String())
					}
				case *ast.TypeSpec:
					declare(s.Name.Name, "type")
				}
			}
		}
	}
}

func (c *srcChecker) file(sf *SourceFile) {
	imp, fake := c.imps[sf.File], c.loops+"/fake"
	wf := sf.Pkg == c.loops || under(sf.Pkg, c.loops+"/domain") || under(sf.Pkg, c.loops+"/codec") ||
		under(sf.Pkg, c.loops) && slices.Contains(slices.Collect(maps.Values(imp)), "go.temporal.io/sdk/workflow")
	for _, is := range sf.File.Imports {
		p, _ := strconv.Unquote(is.Path.Value)
		if is.Name != nil && is.Name.Name == "." {
			c.add(sf, is, "no-dot-import", "dot import of "+p)
		}
		if under(p, fake) && !under(sf.Pkg, fake) {
			c.add(sf, is, "loops-fake-tests-only", sf.Pkg+" imports "+p)
		}
		if wf && ((p != "encoding/json" && strings.Contains(p, "json")) || strings.Contains(p, "yaml") ||
			strings.Contains(p, "toml") || slices.Contains([]string{"encoding/gob", "encoding/xml", "encoding/asn1", "encoding/csv"}, p)) {
			c.add(sf, is, "loops-no-json-decoding", "import "+p)
		}
	}
	walk(sf.File, func(n ast.Node, stack []ast.Node) {
		if len(stack) == 0 {
			return
		}
		parent := stack[len(stack)-1]
		switch n := n.(type) {
		case *ast.BasicLit:
			if _, isImport := parent.(*ast.ImportSpec); !isImport && n.Kind == token.STRING && sf.Pkg != c.module+"/internal/archtest" {
				s, _ := strconv.Unquote(n.Value)
				for _, g := range []string{"RunLoop", "AwaitApprovals"} {
					if strings.Contains(s, g) {
						c.add(sf, n, guarded(g), "string names "+g)
					}
				}
			}
		case *ast.SelectorExpr:
			pkg, name, ok := c.resolve(sf, nil, n)
			switch {
			case !ok:
			case pkg == c.loops && guarded(name) != "":
				c.ref(sf, n, name, stack)
			case wf && pkg == "encoding/json" && name != "RawMessage",
				wf && pkg == "go.temporal.io/sdk/converter" && !slices.Contains([]string{"RawValue", "MetadataEncoding", "MetadataEncodingJSON"}, name):
				c.add(sf, n, "loops-no-json-decoding", pkg+"."+name)
			}
		case *ast.Ident:
			fd, isFunc := parent.(*ast.FuncDecl)
			sel, isSel := parent.(*ast.SelectorExpr)
			if sf.Pkg == c.loops && guarded(n.Name) != "" && (!isFunc || fd.Name != n) && (!isSel || sel.Sel != n) {
				c.ref(sf, n, n.Name, stack)
			}
		case *ast.FuncDecl:
			if m := n.Name.Name; n.Recv != nil && under(sf.Pkg, c.loops) && (strings.HasPrefix(m, "Unmarshal") || m == "GobDecode") {
				c.add(sf, n, "loops-no-unmarshal-method", "method "+m)
			}
		}
	})
}

func (c *srcChecker) ref(sf *SourceFile, n ast.Expr, name string, stack []ast.Node) {
	call, ok := stack[len(stack)-1].(*ast.CallExpr)
	locals := declNames(stack[1]) // enclosing top-level declaration
	switch {
	case !ok || call.Fun != n:
		c.add(sf, n, guarded(name), name+" used as a value, not called")
	case name == "RunLoop" && !c.specCall(sf, locals, call):
		c.add(sf, call, "loop-spec-constant", "RunLoop spec is not a call to a constant spec function")
	case name == "AwaitApprovals" && (len(call.Args) != 3 || call.Ellipsis.IsValid() ||
		!c.keyed(sf, locals, call.Args[1], "ApprovalRequest", func(k string, v ast.Expr) bool {
			return k == "PlanHash" || k == "Author" || c.isConst(sf, locals, v)
		})):
		c.add(sf, call, "approval-request-constant", "AwaitApprovals request is not a constant literal")
	}
}

func (c *srcChecker) specCall(sf *SourceFile, locals map[string]bool, call *ast.CallExpr) bool {
	if len(call.Args) != 3 || call.Ellipsis.IsValid() {
		return false
	}
	arg, ok := call.Args[1].(*ast.CallExpr)
	if !ok || len(arg.Args) != 0 {
		return false
	}
	pkg, name, ok := c.resolve(sf, locals, arg.Fun)
	if !ok || c.kind[pkg+"."+name] != "func" {
		return false
	}
	fn := c.funcs[pkg+"."+name]
	d, res := fn.decl, fn.decl.Type.Results
	if d.Body == nil || d.Type.TypeParams != nil || len(d.Type.Params.List) != 0 || res == nil ||
		len(res.List) != 1 || len(res.List[0].Names) != 0 || len(d.Body.List) != 1 {
		return false
	}
	ret, ok := d.Body.List[0].(*ast.ReturnStmt)
	fl := declNames(d)
	k := func(_ string, v ast.Expr) bool { return c.isConst(fn.file, fl, v) }
	return ok && len(ret.Results) == 1 && c.isLoops(fn.file, fl, res.List[0].Type, "LoopSpec") &&
		c.keyed(fn.file, fl, ret.Results[0], "LoopSpec", func(key string, v ast.Expr) bool {
			if key == "Budget" {
				return c.keyed(fn.file, fl, v, "Budget", k)
			}
			return k(key, v)
		})
}

func (c *srcChecker) keyed(sf *SourceFile, locals map[string]bool, e ast.Expr, typ string, ok func(string, ast.Expr) bool) bool {
	lit, isLit := e.(*ast.CompositeLit)
	if !isLit || !c.isLoops(sf, locals, lit.Type, typ) {
		return false
	}
	left := map[string]bool{} // field -> required
	for _, f := range strings.Fields(contract[typ]) {
		left[strings.TrimPrefix(f, "?")] = !strings.HasPrefix(f, "?")
	}
	for _, el := range lit.Elts {
		kv, isKV := el.(*ast.KeyValueExpr)
		if !isKV {
			return false
		}
		key, isID := kv.Key.(*ast.Ident)
		if !isID {
			return false
		}
		if _, known := left[key.Name]; !known || !ok(key.Name, kv.Value) {
			return false
		}
		delete(left, key.Name) // a repeated key is now unknown
	}
	return !slices.Contains(slices.Collect(maps.Values(left)), true)
}

func (c *srcChecker) isConst(sf *SourceFile, locals map[string]bool, e ast.Expr) bool {
	switch e := e.(type) {
	case *ast.BasicLit:
		return true
	case *ast.ParenExpr:
		return c.isConst(sf, locals, e.X)
	case *ast.UnaryExpr:
		return e.Op != token.AND && e.Op != token.ARROW && c.isConst(sf, locals, e.X)
	case *ast.BinaryExpr:
		return c.isConst(sf, locals, e.X) && c.isConst(sf, locals, e.Y)
	case *ast.CompositeLit:
		at, isArr := e.Type.(*ast.ArrayType)
		if !isArr || at.Len != nil || !c.isName(sf, locals, at.Elt, "string") || len(e.Elts) == 0 {
			return false
		}
		return !slices.ContainsFunc(e.Elts, func(x ast.Expr) bool { return !c.isConst(sf, locals, x) })
	case *ast.Ident:
		if c.isName(sf, locals, e, "true") || c.isName(sf, locals, e, "false") {
			return true
		}
	}
	pkg, name, ok := c.resolve(sf, locals, e)
	if pkg == "time" {
		return ok && slices.Contains([]string{"Nanosecond", "Microsecond", "Millisecond", "Second", "Minute", "Hour"}, name)
	}
	return ok && c.kind[pkg+"."+name] == "const"
}

func (c *srcChecker) isName(sf *SourceFile, locals map[string]bool, e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name && !locals[name] && c.kind[sf.Pkg+"."+name] == ""
}

func (c *srcChecker) resolve(sf *SourceFile, locals map[string]bool, e ast.Expr) (pkg, name string, ok bool) {
	switch e := e.(type) {
	case *ast.Ident:
		return sf.Pkg, e.Name, !locals[e.Name]
	case *ast.SelectorExpr:
		if x, isID := e.X.(*ast.Ident); isID && !locals[x.Name] {
			p, imported := c.imps[sf.File][x.Name]
			return p, e.Sel.Name, imported
		}
	}
	return "", "", false
}

func (c *srcChecker) isLoops(sf *SourceFile, locals map[string]bool, e ast.Expr, typ string) bool {
	pkg, name, ok := c.resolve(sf, locals, e)
	return ok && pkg == c.loops && name == typ && c.kind[pkg+"."+name] == "type"
}

func (c *srcChecker) add(sf *SourceFile, n ast.Node, rule, detail string) {
	c.out = append(c.out, SourceViolation{rule, fmt.Sprintf("%s:%d", sf.Path, sf.Fset.Position(n.Pos()).Line), detail})
}

func under(p, root string) bool { return p == root || strings.HasPrefix(p, root+"/") }

// declNames: every name declared under n, a superset of the shadowing names.
func declNames(n ast.Node) map[string]bool {
	names := map[string]bool{}
	add := func(es ...ast.Expr) {
		for _, e := range es {
			if id, ok := e.(*ast.Ident); ok {
				names[id.Name] = true
			}
		}
	}
	ast.Inspect(n, func(x ast.Node) bool {
		switch x := x.(type) {
		case *ast.Field:
			for _, id := range x.Names {
				add(id)
			}
		case *ast.ValueSpec:
			for _, id := range x.Names {
				add(id)
			}
		case *ast.TypeSpec:
			add(x.Name)
		case *ast.AssignStmt:
			if x.Tok == token.DEFINE {
				add(x.Lhs...)
			}
		case *ast.RangeStmt:
			if x.Tok == token.DEFINE {
				add(x.Key, x.Value)
			}
		}
		return true
	})
	return names
}

func walk(root ast.Node, f func(n ast.Node, stack []ast.Node)) {
	var stack []ast.Node
	ast.Inspect(root, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		f(n, stack)
		stack = append(stack, n)
		return true
	})
}
```

## 4. Autres changements non test

- `rules.go`, fin de `DefaultRules` (commentaire de R5 : « sauf `internal/loops/fake` ») :
```go
		{ // M0-T19c, obligation (k): the keyless approval verifier, tests only (T41)
			Name: "loops-fake-tests-only", Kind: Confine,
			Targets: []string{m("internal/loops/fake/...")},
		},
```
- `Makefile`, `arch-test` : `go tool workflowcheck ./internal/loops/...` ; `git rm workflowcheck.config.yaml`.
- Commentaire de paquet de `internal/loops/fake/approvals.go` : « tests only (rule loops-fake-tests-only, threat T41) ».

## 5. Tests (phase tests, `test-author`)

### 5.1 `internal/archtest/loops_test.go`

Chaque cas part des sources réelles plus `fixtureOK` (forme imposée à T19d), puis applique ses modifications.

```go
package archtest

import (
	"cmp"
	"slices"
	"strings"
	"testing"
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

func sc(name, rule, detail string, edits ...srcEdit) srcCase { return srcCase{name, rule, detail, edits} }

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
```

### 5.2 `rules_test.go` et fixtures (motif : (k) interdit le faux de boucle à tout importeur non test)

- `defaultRuleNames`, `names_and_kinds` : `"loops-fake-tests-only"`, `Confine` en dernier.
- `fakes-wired-in-cmd` (cas, fixtures) : plus d'import de `internal/loops/fake` ; `internal/graph` vers `internal/graph/fake` remplace `internal/loops/demo`.
- Cas et fixtures `loops-fake-tests-only` : `cmd/rempart-evals`, `cmd/rempart-worker` importent `internal/loops/fake` (violation) ou `internal/loops` (conforme).

Rouge attendu : `undefined: ReadSources`.

## 6. Critères d'acceptation (racine, après impl)

1. `go test -count=1 -run 'TestLoop|NotRegistered' -v ./internal/archtest/` : `grep -c '^--- PASS'` `6`, `grep -c '^    --- PASS'` `25`, `grep -c -- '--- FAIL'` `0`.
2. `go test -count=1 -run '^TestRuleDetectsViolation$' -v ./internal/archtest/ | grep -c -- '--- PASS: TestRuleDetectsViolation/loops-fake-tests-only/'` : `2` ; `go test -count=1 ./internal/archtest/` : `ok`.
3. `test ! -e workflowcheck.config.yaml; echo rc=$?` : `rc=0` ; `grep -c workflowcheck Makefile` : `1` ; `grep -c -- '-config' Makefile` : `0`.
4. `go tool workflowcheck ./internal/loops/...; echo rc=$?` : seule sortie `rc=0` ; sur copie privée (T72), `func probe(ctx workflow.Context, b []byte) { var a Approval; _ = json.NewDecoder(bytes.NewReader(b)).Decode(&a) }` ajoutée à `approvals.go` est signalée.
5. `git diff --exit-code 7873925 -- go.mod go.sum; echo rc=$?` : `rc=0`.
6. `grep -rl --include='*.go' 'rempart/internal/loops/fake"' . | grep -vc '_test\.go$'` : `0`.
7. `go test -short -count=1 -race ./internal/loops/...` : `ok` ; `make verify-quick; echo rc=$?` : `rc=0`.
8. Section 7 : 20 sur 20 sur copie privée ; `git diff --exit-code <commit des tests> -- internal/archtest/*_test.go internal/archtest/testdata; echo rc=$?` : `rc=0`.
9. `wc -c < docs/plans/M0-loops-archtest.md` : au plus 30000.

## 7. Mutations (une à la fois ; `go test ./internal/archtest/` échoue)

| # | Mutation | Détectée par |
|---|---|---|
| 1 | `ref` : `!ok \|\| call.Fun != n` devient `!ok` | `registered_inside_loops` |
| 2 | branche `*ast.BasicLit` supprimée | `registered_by_name`, `started_by_name` |
| 3 | `index` : `is.Name` ignoré | `renamed_import` |
| 4 | contrôle de l'import `.` supprimé | `dot_import` |
| 5 | boucle d'existence supprimée | `api_renamed` |
| 6 | `len(d.Type.Params.List) != 0` retiré | `spec_parameter` |
| 7 | `specCall` : `c.kind[...] != "func"` devient `false` | `build_variant` |
| 8 | `resolve` : `!locals[...]` devient `true` | `shadowed_spec`, `shadowed_constant` |
| 9 | `declare` : `kind = "dup"` retiré | `build_variant` |
| 10 | `keyed` : dernière ligne `return true` | `budget_field_missing`, `security_role_omitted` |
| 11 | `isConst` : `case *ast.CallExpr: return true` | `required_computed` |
| 12 | `isConst` : `== "const"` devient `!= ""` | `field_from_variable` |
| 13 | cas `AwaitApprovals` de `ref` supprimé | `request_variable` |
| 14 | `json.X` : `name != "RawMessage"` devient `false` | `decoder_in_workflow` |
| 15 | `wf` réduit aux paquets moteur | `decoder_in_workflow` |
| 16 | clause `json` des imports retirée | `json_v2` |
| 17 | `converter.X` : tout nom admis | `converter_decoding` |
| 18 | `HasPrefix(m, "Unmarshal")` devient `m == "UnmarshalJSON"` | `unmarshal_method` |
| 19 | contrôle d'import du faux supprimé | `worker_dev_build` |
| 20 | règle retirée de `DefaultRules` | `TestRuleDetectsViolation` |

Les 25 cas de 5.1 sont les fixtures de code interdit ; chacun ne déclenche que la règle visée.

## 8. Menaces

T54, T41 vérifiés ; T33 : ces règles voient les fichiers étiquetés ; T16 : plus d'exemption workflowcheck. **T73 (nouvelle)** : contournement des règles non typées (nom construit à l'exécution, réflexion, `unsafe`, `linkname`, génération de code, champ embarqué ou externe muni d'`UnmarshalJSON`, dossier `_x/`, `main` sous `internal/loops/fake`) ; parade : échec fermé, revue, `go/types` au premier contournement.

## 9. Points non vérifiés

Rien n'a été exécuté : compilation, `gofumpt` (`-w` permis), `golangci-lint`, silence de workflowcheck, conformité du dépôt réel (relue à la main), décomptes, taille exacte de ce plan.

## 10. Tâches ordonnées

1. Principal : `rempart-state phase tests`.
2. `test-author` : 5.1, 5.2 ; sur copie privée, section 3 verte, 20 mutations détectées ; sur le dépôt, rouge.
3. Principal : `git add` des tests, `phase impl`.
4. Cycles : `loopsrc.go` ; `rules.go` et commentaire du faux ; `Makefile` et `git rm workflowcheck.config.yaml` (critères 3, 4, 7).
5. `security-reviewer`, puis `acceptance-verifier` (critères 1 à 9, copie privée).
6. Principal : `docs/STATUS.md` ((d), (k), (l), (p), décision 5 soldées), menaces, commit `test(archtest): source rules for loop registration, constant specs, decoding and fakes (M0-T19c)`, `phase free`.

## 11. Décisions humaines requises

1. **Faux** (décision 4 de M0-demo-prep) : « tests seulement », étiquettes comprises ; `make demo` (T20) enregistre un vérificateur qui refuse tout (`timed_out`) ; `TestDemoApprovedEndToEnd` (`_test.go`) garde le faux.
2. **`Author` et délai de T19d** issus de l'entrée : `Author` non authentifié jusqu'à M4 (T12, T18), ou auteur constant.
3. **Formes imposées à T19d** : `func Spec() loops.LoopSpec`, littéral `loops.ApprovalRequest` dans l'appel.
4. Exemption d'`internal/archtest` (chaînes) ; `.` interdit partout ; `linkname` non couvert (T73) ; rien ne fige le `Makefile` contre une future exemption workflowcheck.
