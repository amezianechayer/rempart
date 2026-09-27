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
		if n := d.Name(); d.IsDir() && p != "." && (n[0] == '.' || n[0] == '_' || n == "testdata" || p == "bin") {
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
	wfPkg         map[string]bool // packages with a file importing sdk/workflow
	out           []SourceViolation
}

func CheckLoopSources(module string, files []SourceFile) []SourceViolation {
	c := &srcChecker{
		module: module, loops: module + "/internal/loops", kind: map[string]string{},
		funcs: map[string]funcRef{}, imps: map[*ast.File]map[string]string{}, wfPkg: map[string]bool{},
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
		if p == "go.temporal.io/sdk/workflow" {
			c.wfPkg[sf.Pkg] = true
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
	fake := c.loops + "/fake"
	wf := sf.Pkg == c.loops || under(sf.Pkg, c.loops+"/domain") || under(sf.Pkg, c.loops+"/codec") ||
		under(sf.Pkg, c.loops) && c.wfPkg[sf.Pkg]
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
