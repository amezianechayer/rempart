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

// ReadSources reads the non-test Go files of fsys, except under a directory
// that go patterns ignore (".x", "_x", testdata: threat T73). It walks every
// directory but .git and fails closed on any symbolic link (threat T74).
func ReadSources(fsys fs.FS) (map[string]string, error) {
	srcs := map[string]string{}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case p == ".git" && d.IsDir():
			return fs.SkipDir
		case d.Type()&fs.ModeSymlink != 0:
			return fmt.Errorf("archtest: symbolic link %s: go build follows it, the rules do not (T74)", p)
		case !d.IsDir() && moduleFile(p): // (ai)
			return fmt.Errorf("archtest: %s: nested module, workspace or vendor directory (T74)", p)
		case !d.IsDir() && strings.HasPrefix(p, "internal/loops/") && slices.Contains(foreignSources, path.Ext(p)): // (aw)
			return fmt.Errorf("archtest: %s: non-Go source under internal/loops (T73)", p)
		case d.IsDir() || path.Ext(p) != ".go" || strings.HasSuffix(p, "_test.go") || ignoredDir(p):
			return nil
		}
		b, err := fs.ReadFile(fsys, p)
		srcs[p] = string(b)
		return err
	})
	return srcs, err
}

func moduleFile(p string) bool {
	switch path.Base(p) {
	case "go.mod":
		return p != "go.mod"
	case "go.work", "go.work.sum":
		return true
	case "modules.txt":
		return path.Base(path.Dir(p)) == "vendor"
	}
	return false
}

var foreignSources = []string{".s", ".S", ".sx", ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".m", ".f", ".F", ".for", ".f90", ".syso", ".swig", ".swigcxx"}

var searchNames = []string{"GetTypedSearchAttributes", "UpsertTypedSearchAttributes", "UpsertSearchAttributes", "SearchAttributes", "TypedSearchAttributes", "UpsertMemo", "Memo", "UntypedSearchAttributes", "UpsertedMemo"}

var searchKeys = []string{"Memo", "SearchAttributes", "TypedSearchAttributes", "UntypedSearchAttributes", "UpsertedMemo"} // (bd), V3 C4

func ignoredElem(e string) bool { return e != "" && (e[0] == '_' || e[0] == '.' || e == "testdata") }

func unkeyed(lit *ast.CompositeLit) bool {
	return slices.ContainsFunc(lit.Elts, func(e ast.Expr) bool { _, kv := e.(*ast.KeyValueExpr); return !kv })
}

// decodingNames are admitted in workflow code only as the Fun of a call (aj).
var decodingNames = []string{
	"Receive", "ReceiveWithTimeout", "ReceiveAsync", "ReceiveAsyncWithMoreFlag", "Get", "Details",
	"LastHeartbeatDetails", "GetLastCompletionResult", "SetUpdateHandler", "SetUpdateHandlerWithOptions",
	"SetQueryHandler", "SetQueryHandlerWithOptions", "GetHeartbeatDetails",
}

func ignoredDir(p string) bool {
	return slices.ContainsFunc(strings.Split(path.Dir(p), "/"), func(e string) bool {
		return e != "." && (e[0] == '.' || e[0] == '_' || e == "testdata")
	})
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

type typeRef struct {
	spec *ast.TypeSpec
	file *SourceFile
}

const (
	workflowPkg  = "go.temporal.io/sdk/workflow"
	converterPkg = "go.temporal.io/sdk/converter"
)

type srcChecker struct {
	module, loops string
	kind          map[string]string // "pkg.name" -> const, var, type, func, or dup (build variants)
	funcs         map[string]funcRef
	methods       []funcRef
	specMethods   map[string]bool
	imps          map[*ast.File]map[string]string
	wfPkg         map[string]bool // packages with a file importing sdk/workflow
	sdkPkg        map[string]bool // packages with a file importing the SDK (bd)
	types         []typeRef       // type declarations of the module
	specTypes     map[string]bool // "pkg.name" of LoopSpec, ApprovalRequest and the types built on them
	out           []SourceViolation
}

func CheckLoopSources(module string, files []SourceFile) []SourceViolation {
	c := &srcChecker{
		module: module, loops: module + "/internal/loops", kind: map[string]string{},
		funcs: map[string]funcRef{}, imps: map[*ast.File]map[string]string{}, wfPkg: map[string]bool{},
		sdkPkg: map[string]bool{},
	}
	for i := range files {
		c.index(&files[i])
	}
	c.specTypes = map[string]bool{c.loops + ".LoopSpec": true, c.loops + ".ApprovalRequest": true}
	for grown := true; grown; { // fixed point: aliases, defined types, wrapping structs
		grown = false
		for _, t := range c.types {
			if k := t.file.Pkg + "." + t.spec.Name.Name; !c.specTypes[k] && c.mentions(t.file, t.spec.Type) {
				c.specTypes[k], grown = true, true
			}
		}
	}
	c.specMethods = map[string]bool{} // (ak)
	for _, m := range c.methods {
		if c.takesSpec(m.file, m.decl.Type) {
			c.specMethods[m.file.Pkg+"."+m.decl.Name.Name] = true
		}
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
		if p == "go.temporal.io/sdk/workflow" {
			c.wfPkg[sf.Pkg] = true
		}
		if under(p, "go.temporal.io/sdk") { // (bd)
			c.sdkPkg[sf.Pkg] = true
		}
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
			} else {
				c.methods = append(c.methods, funcRef{d, sf})
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
					c.types = append(c.types, typeRef{s, sf})
				}
			}
		}
	}
}

func (c *srcChecker) file(sf *SourceFile) {
	fake := c.loops + "/fake"
	inLoops := under(sf.Pkg, c.loops)
	dec := inLoops && !under(sf.Pkg, fake) // (au)
	wf := sf.Pkg == c.loops || under(sf.Pkg, c.loops+"/domain") || under(sf.Pkg, c.loops+"/codec") ||
		under(sf.Pkg, c.loops) && c.wfPkg[sf.Pkg]
	cmd := under(sf.Pkg, c.module+"/cmd")
	sa := wf || cmd || inLoops || c.sdkPkg[sf.Pkg] // (bd), V3 C4: every package under internal/loops
	for _, is := range sf.File.Imports {
		p, _ := strconv.Unquote(is.Path.Value)
		if is.Name != nil && is.Name.Name == "." {
			c.add(sf, is, "no-dot-import", "dot import of "+p)
		}
		if under(p, fake) && !under(sf.Pkg, fake) {
			c.add(sf, is, "loops-fake-tests-only", sf.Pkg+" imports "+p)
		}
		if under(p, c.module) && slices.ContainsFunc(strings.Split(p, "/"), ignoredElem) { // T73
			c.add(sf, is, "no-ignored-dir-import", "import "+p)
		}
		if under(p, c.module+"/cmd") && !under(sf.Pkg, c.module+"/cmd") { // (bf)
			c.add(sf, is, "no-cmd-import", sf.Pkg+" imports "+p)
		}
		if inLoops && slices.Contains([]string{"reflect", "unsafe", "C"}, p) { // (aw)
			c.add(sf, is, "loops-no-reflection", "import "+p)
		}
		if wf && ((p != "encoding/json" && strings.Contains(p, "json")) || strings.Contains(p, "yaml") ||
			strings.Contains(p, "toml") || slices.Contains([]string{"encoding/gob", "encoding/xml", "encoding/asn1", "encoding/csv"}, p)) {
			c.add(sf, is, "loops-no-json-decoding", "import "+p)
		}
	}
	for _, cg := range sf.File.Comments { // (aw)
		for _, cm := range cg.List {
			switch {
			case !strings.HasPrefix(cm.Text, "//go:linkname"):
			case inLoops: // (aw)
				c.add(sf, cm, "loops-no-reflection", "go:linkname directive")
			default: // (bf)
				c.add(sf, cm, "no-linkname", "go:linkname directive")
			}
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
			call, isCall := parent.(*ast.CallExpr)
			called := isCall && call.Fun == n
			switch {
			case dec && !called && slices.Contains(decodingNames, n.Sel.Name):
				c.add(sf, n, "loops-raw-decoding-target", n.Sel.Name+" used as a value, not called")
			case wf && n.Sel.Name == "Validator":
				c.add(sf, n, "loops-raw-decoding-target", "Validator set outside a composite literal")
			case sa && slices.Contains(searchNames, n.Sel.Name):
				c.add(sf, n, "loops-no-search-attributes", n.Sel.Name)
			case !called && under(sf.Pkg, c.loops) && c.specMethods[sf.Pkg+"."+n.Sel.Name]:
				c.add(sf, n, "loops-no-spec-entrypoint", n.Sel.Name+" takes a LoopSpec or an ApprovalRequest and is used as a value")
			}
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
			call, isCall := parent.(*ast.CallExpr)
			if fn, ok := c.funcs[sf.Pkg+"."+n.Name]; ok && under(sf.Pkg, c.loops) && guarded(n.Name) == "" &&
				(!isFunc || fd.Name != n) && (!isSel || sel.Sel != n) && (!isCall || call.Fun != n) &&
				c.kind[sf.Pkg+"."+n.Name] == "func" && !declNames(stack[1])[n.Name] && c.takesSpec(fn.file, fn.decl.Type) {
				c.add(sf, n, "loops-no-spec-entrypoint", n.Name+" takes a LoopSpec or an ApprovalRequest and is used as a value")
			}
		case *ast.IndexExpr:
			c.instance(sf, n.X, []ast.Expr{n.Index})
		case *ast.IndexListExpr:
			c.instance(sf, n.X, n.Indices)
		case *ast.FuncDecl:
			if m := n.Name.Name; n.Recv != nil && under(sf.Pkg, c.loops) && (strings.HasPrefix(m, "Unmarshal") || m == "GobDecode") {
				c.add(sf, n, "loops-no-unmarshal-method", "method "+m)
			}
		case *ast.CallExpr:
			if dec {
				c.decodeTargets(sf, n, stack)
			}
		case *ast.CompositeLit:
			switch n.Type.(type) {
			case *ast.ArrayType, *ast.MapType: // an elided type counts as a struct (D12)
			default:
				if (wf || cmd) && unkeyed(n) { // (at), (bd)
					c.add(sf, n, "loops-keyed-literals", "composite literal element without field name")
				}
			}
		case *ast.KeyValueExpr:
			if k, isID := n.Key.(*ast.Ident); wf && isID && k.Name == "Validator" && !c.admittedHandler(sf, declNames(stack[1]), n.Value) {
				c.add(sf, n, "loops-raw-decoding-target", "Validator handler takes a parameter other than workflow.Context or converter.RawValue")
			}
			if k, isID := n.Key.(*ast.Ident); sa && isID && slices.Contains(searchKeys, k.Name) { // (bd)
				c.add(sf, n, "loops-no-search-attributes", "key "+k.Name+" in a composite literal")
			}
		case *ast.FuncLit:
			if c.takesSpec(sf, n.Type) {
				c.add(sf, n, "loops-no-spec-entrypoint", "function literal takes a LoopSpec or an ApprovalRequest")
			}
		}
	})
	if under(sf.Pkg, c.loops) {
		c.entrypoints(sf)
	}
}

// instance: a generic function of internal/loops instantiated with a spec type
// is a RunLoop copy taking its spec from the workflow input.
func (c *srcChecker) instance(sf *SourceFile, x ast.Expr, indices []ast.Expr) {
	pkg, name, ok := c.resolve(sf, nil, x)
	if _, isFunc := c.funcs[pkg+"."+name]; ok && isFunc && under(pkg, c.loops) &&
		slices.ContainsFunc(indices, func(e ast.Expr) bool { return c.mentions(sf, e) }) {
		c.add(sf, x, "loops-no-spec-entrypoint", name+" instantiated with a LoopSpec or an ApprovalRequest")
	}
}

// handlers: the SDK decodes update, validator and query arguments; each
// handler is a function literal whose parameters are workflow.Context or
// converter.RawValue only.
func (c *srcChecker) handlers(sf *SourceFile, call *ast.CallExpr, locals map[string]bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	m := ""
	if ok {
		m = sel.Sel.Name
	}
	if !slices.Contains([]string{"SetUpdateHandler", "SetUpdateHandlerWithOptions", "SetQueryHandler", "SetQueryHandlerWithOptions"}, m) {
		return
	}
	fns := []ast.Expr{}
	if len(call.Args) > 2 {
		fns = append(fns, call.Args[2])
	}
	for _, a := range call.Args[min(len(call.Args), 3):] {
		ast.Inspect(a, func(n ast.Node) bool {
			if kv, ok := n.(*ast.KeyValueExpr); ok {
				if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Validator" {
					fns = append(fns, kv.Value)
				}
			}
			return true
		})
	}
	for _, f := range fns {
		if !c.admittedHandler(sf, locals, f) {
			c.add(sf, call, "loops-raw-decoding-target", m+" handler takes a parameter other than workflow.Context or converter.RawValue")
		}
	}
}

// decodeTargets: the SDK decodes a signal, a side effect, an error detail or
// a completion result into its target with the data converter, out of sight of
// workflowcheck. Admitted target: nil or &x, x declared in the enclosing
// top-level declaration with the type converter.RawValue only. Get with two
// arguments is a future's Get(ctx, &x) only on a future returned directly by
// workflow.ExecuteActivity, ExecuteLocalActivity or ExecuteChildWorkflow.
func (c *srcChecker) decodeTargets(sf *SourceFile, call *ast.CallExpr, stack []ast.Node) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || len(call.Args) == 0 {
		return
	}
	top := stack[1]
	locals := declNames(top)
	c.handlers(sf, call, locals)
	targets := call.Args
	switch sel.Sel.Name {
	case "Receive", "ReceiveWithTimeout", "ReceiveAsync", "ReceiveAsyncWithMoreFlag":
		targets = call.Args[len(call.Args)-1:]
	case "GetLastCompletionResult", "GetHeartbeatDetails":
		targets = call.Args[1:]
	case "Details", "LastHeartbeatDetails":
	case "Get":
		if len(call.Args) == 2 && c.directFuture(sf, locals, sel.X) {
			targets = nil // activity and child results: decoded by design (plan D7)
		}
	default:
		return
	}
	for _, t := range targets {
		if !c.rawTarget(sf, top, locals, t) {
			c.add(sf, call, "loops-raw-decoding-target", sel.Sel.Name+" target is not nil or &x, x a local converter.RawValue")
		}
	}
}

func (c *srcChecker) directFuture(sf *SourceFile, locals map[string]bool, e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	pkg, name, ok := c.resolve(sf, locals, call.Fun)
	return ok && pkg == workflowPkg && slices.Contains([]string{"ExecuteActivity", "ExecuteLocalActivity", "ExecuteChildWorkflow"}, name)
}

func (c *srcChecker) rawTarget(sf *SourceFile, top ast.Node, locals map[string]bool, e ast.Expr) bool {
	if c.isName(sf, locals, e, "nil") {
		return true
	}
	u, ok := e.(*ast.UnaryExpr)
	if !ok || u.Op != token.AND {
		return false
	}
	x, ok := u.X.(*ast.Ident)
	if !ok {
		return false
	}
	types, typed := localTypes(top, x.Name)
	return typed && len(types) > 0 && !slices.ContainsFunc(types, func(t ast.Expr) bool {
		pkg, name, ok := c.resolve(sf, locals, t)
		return !ok || pkg != converterPkg || name != "RawValue"
	})
}

// localTypes returns the declared types of every declaration of name under n;
// typed is false if one of them has no explicit type.
func localTypes(n ast.Node, name string) (types []ast.Expr, typed bool) {
	typed = true
	has := func(ids ...ast.Expr) bool {
		return slices.ContainsFunc(ids, func(e ast.Expr) bool { id, ok := e.(*ast.Ident); return ok && id.Name == name })
	}
	idents := func(ids []*ast.Ident) []ast.Expr {
		out := make([]ast.Expr, len(ids))
		for i, id := range ids {
			out[i] = id
		}
		return out
	}
	ast.Inspect(n, func(x ast.Node) bool {
		switch x := x.(type) {
		case *ast.Field:
			if has(idents(x.Names)...) {
				types = append(types, x.Type)
			}
		case *ast.ValueSpec:
			if has(idents(x.Names)...) {
				types = append(types, x.Type)
				typed = typed && x.Type != nil
			}
		case *ast.TypeSpec:
			typed = typed && x.Name.Name != name
		case *ast.AssignStmt:
			typed = typed && (x.Tok != token.DEFINE || !has(x.Lhs...))
		case *ast.RangeStmt:
			typed = typed && (x.Tok != token.DEFINE || !has(x.Key, x.Value))
		}
		return true
	})
	return types, typed
}

// entrypoints: under internal/loops, no exported function, method or function
// variable but RunLoop and AwaitApprovals takes a spec type as a parameter.
func (c *srcChecker) entrypoints(sf *SourceFile) {
	bad := func(n ast.Node, name string) {
		c.add(sf, n, "loops-no-spec-entrypoint", name+" takes a LoopSpec or an ApprovalRequest")
	}
	for _, d := range sf.File.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Name.IsExported() && (d.Recv != nil || sf.Pkg != c.loops || guarded(d.Name.Name) == "") &&
				c.takesSpec(sf, d.Type) {
				bad(d, d.Name.Name)
			}
		case *ast.GenDecl:
			for _, s := range d.Specs {
				vs, ok := s.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, n := range vs.Names {
					if !n.IsExported() {
						continue
					}
					if vs.Type != nil && c.funcTypeTakesSpec(sf, vs.Type) {
						bad(n, n.Name)
					}
					for j, v := range vs.Values {
						if (len(vs.Values) != len(vs.Names) || j == i) && c.funcValueTakesSpec(sf, v) {
							bad(n, n.Name)
						}
					}
				}
			}
		}
	}
}

func (c *srcChecker) takesSpec(sf *SourceFile, ft *ast.FuncType) bool {
	return slices.ContainsFunc(ft.Params.List, func(f *ast.Field) bool { return c.mentions(sf, f.Type) })
}

// funcTypeTakesSpec: a function type literal, or a named type of internal/loops
// built on a spec type, declared as the type of a variable.
func (c *srcChecker) funcTypeTakesSpec(sf *SourceFile, t ast.Expr) bool {
	if ft, ok := t.(*ast.FuncType); ok {
		return c.takesSpec(sf, ft)
	}
	pkg, name, ok := c.resolve(sf, nil, t)
	return ok && c.specTypes[pkg+"."+name]
}

func (c *srcChecker) funcValueTakesSpec(sf *SourceFile, v ast.Expr) bool {
	if fl, ok := v.(*ast.FuncLit); ok {
		return c.takesSpec(sf, fl.Type)
	}
	pkg, name, ok := c.resolve(sf, nil, v)
	fn, isFunc := c.funcs[pkg+"."+name]
	return ok && isFunc && (pkg != c.loops || guarded(name) == "") && c.takesSpec(fn.file, fn.decl.Type)
}

// mentions reports whether the type expression t names a spec type.
func (c *srcChecker) mentions(sf *SourceFile, t ast.Expr) bool {
	found := false
	ast.Inspect(t, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SelectorExpr:
			pkg, name, ok := c.resolve(sf, nil, n)
			found = found || ok && c.specTypes[pkg+"."+name]
			return false
		case *ast.Ident:
			found = found || c.specTypes[sf.Pkg+"."+n.Name]
		}
		return !found
	})
	return found
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

func (c *srcChecker) admittedHandler(sf *SourceFile, locals map[string]bool, f ast.Expr) bool {
	fl, ok := f.(*ast.FuncLit)
	return ok && !slices.ContainsFunc(fl.Type.Params.List, func(p *ast.Field) bool {
		pkg, name, ok := c.resolve(sf, locals, p.Type)
		admitted := pkg == workflowPkg && name == "Context" || pkg == converterPkg && name == "RawValue"
		return !ok || !admitted
	})
}
