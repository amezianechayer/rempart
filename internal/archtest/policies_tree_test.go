package archtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
)

// opaAdapterSources is the directory of the OPA adapter (rule opa-confined).
const opaAdapterSources = "internal/policy/adapters/opa"

// policiesImport is the import path of the embedded packs.
const policiesImport = modulePath + "/policies"

// regoPackageRe is the package clause of a .rego file: the first line that is
// neither empty nor a comment.
var regoPackageRe = regexp.MustCompile(`^package\s+([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)*)\s*$`)

// adapterReads returns the variables of policies that the adapter sources
// read: selectors <name>.<Var> on the import of policiesImport, by the name
// the file gives it (obligation (hb)); a comment or a string never counts.
func adapterReads(srcs map[string]string, problems *problemList) map[string]bool {
	reads := map[string]bool{}
	for name, src := range srcs {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
		if err != nil {
			problems.addf("%s: cannot parse: %v", name, err)
			continue
		}
		local := ""
		for _, imp := range f.Imports {
			if p, err := strconv.Unquote(imp.Path.Value); err == nil && p == policiesImport {
				local = "policies"
				if imp.Name != nil {
					local = imp.Name.Name
				}
			}
		}
		if local == "" || local == "_" || local == "." {
			continue
		}
		ast.Inspect(f, func(x ast.Node) bool {
			if sel, ok := x.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == local {
					reads[sel.Sel.Name] = true
				}
			}
			return true
		})
	}
	return reads
}

// regoPackage returns the package clause of a .rego source, "" when the first
// line that is neither empty nor a comment is not a package clause.
func regoPackage(src string) string {
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if m := regoPackageRe.FindStringSubmatch(line); m != nil {
			return m[1]
		}
		return ""
	}
	return ""
}

// embedPatternRe is the only form of a //go:embed pattern of policies/embed.go:
// the .rego files of one pack directory, never a directory (which would embed
// files that opa test reads but the engine refuses).
var embedPatternRe = regexp.MustCompile(`^[a-z][a-z0-9_]*/\*\.rego$`)

// policiesEmbeds parses policies/embed.go: pack directory -> variable of type
// embed.FS whose //go:embed directive names <dir>/*.rego. Any other directive
// form is a problem.
func policiesEmbeds(src string, problems *problemList) map[string]string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "policies/embed.go", src, parser.ParseComments)
	if err != nil {
		problems.addf("policies/embed.go: %v", err)
		return nil
	}
	out := map[string]string{}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			doc := vs.Doc
			if doc == nil && len(gd.Specs) == 1 {
				doc = gd.Doc
			}
			if doc == nil {
				continue
			}
			for _, c := range doc.List {
				rest, isEmbed := strings.CutPrefix(c.Text, "//go:embed")
				if !isEmbed {
					continue
				}
				sel, isSel := vs.Type.(*ast.SelectorExpr)
				if !isSel || sel.Sel.Name != "FS" || len(vs.Names) != 1 {
					problems.addf("policies/embed.go: //go:embed on a variable other than one embed.FS: %q", c.Text)
					continue
				}
				fields := strings.Fields(rest)
				if len(fields) != 1 || !embedPatternRe.MatchString(fields[0]) {
					problems.addf("policies/embed.go: //go:embed pattern must be exactly <pack>/*.rego (obligation (fl)): %q", c.Text)
					continue
				}
				out[path.Dir(fields[0])] = vs.Names[0].Name
			}
		}
	}
	return out
}

// checkPoliciesTree applies obligation (fl) (ADR 0011 verification 13, T109)
// to fsys rooted at policies/, embedSrc being policies/embed.go and adapterSrcs
// the non-test sources of the OPA adapter, by file name:
//  1. every file is policies/embed.go, a .gitkeep, or a .rego file of a pack
//     directory (a data file would be read by opa test and ignored by the
//     engine); no symbolic link, no special file;
//  2. no directory below a pack directory (opa test loads it, the pattern
//     <pack>/*.rego does not embed it);
//  3. every directory holding a .rego file is embedded by a directive
//     //go:embed <pack>/*.rego, on a variable the adapter reads (policies.<Var>,
//     found by go/ast, obligation (hb));
//  4. the package of every .rego file is bound to its pack directory
//     (obligation (he), T153, T155): rempart.<pack>.<name> for a rule file,
//     rempart.<pack>_test.<name> for a test file (_test.rego, skipped by the
//     engine, read by opa test).
func checkPoliciesTree(fsys fs.FS, embedSrc string, adapterSrcs map[string]string) []string {
	var problems problemList
	embeds := policiesEmbeds(embedSrc, &problems)
	reads := adapterReads(adapterSrcs, &problems)
	regoDirs := map[string]bool{}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == "." {
			return nil
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0 || (!d.IsDir() && !d.Type().IsRegular()):
			problems.addf("policies/%s: symbolic link or special file (obligation (fl))", p)
			return nil
		case d.IsDir():
			if strings.Contains(p, "/") {
				problems.addf("policies/%s: directory below a pack directory, read by opa test and never embedded (obligation (fl))", p)
				return fs.SkipDir
			}
			return nil
		}
		dir, name := path.Split(p)
		dir = strings.TrimSuffix(dir, "/")
		switch {
		case name == ".gitkeep":
		case dir == "" && name == "embed.go":
		case dir != "" && strings.HasSuffix(name, ".rego"):
			regoDirs[dir] = true
			src, err := fs.ReadFile(fsys, p)
			if err != nil {
				problems.addf("policies/%s: %v", p, err)
				return nil
			}
			want := "rempart." + dir + "."
			if strings.HasSuffix(name, "_test.rego") {
				want = "rempart." + dir + "_test."
			}
			if pkg := regoPackage(string(src)); !strings.HasPrefix(pkg, want) || strings.Count(pkg, ".") != 2 {
				problems.addf("policies/%s: package %q, want %s<name> (package bound to its pack directory, obligation (he))", p, pkg, want)
			}
		default:
			problems.addf("policies/%s: only .rego files of a pack directory, embed.go and .gitkeep are allowed under policies/ (obligation (fl))", p)
		}
		return nil
	})
	if err != nil {
		problems.addf("policies: %v", err)
	}
	dirs := make([]string, 0, len(regoDirs))
	for dir := range regoDirs {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		v, ok := embeds[dir]
		switch {
		case !ok:
			problems.addf("policies/%s: .rego files not embedded by //go:embed %s/*.rego in policies/embed.go (obligation (fl))", dir, dir)
		case !reads[v]:
			problems.addf("policies/%s: embedded variable %s not read by the OPA adapter (%s): the pack would never be compiled (obligation (fl))",
				dir, v, opaAdapterSources)
		}
	}
	return problems
}

// opaAdapterFiles reads the non-test Go sources of the OPA adapter, by path.
func opaAdapterFiles(t *testing.T, repo fs.FS) map[string]string {
	t.Helper()
	entries, err := fs.ReadDir(repo, opaAdapterSources)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
			src, err := fs.ReadFile(repo, opaAdapterSources+"/"+e.Name())
			if err != nil {
				t.Fatal(err)
			}
			out[opaAdapterSources+"/"+e.Name()] = string(src)
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s: no Go source", opaAdapterSources)
	}
	return out
}

// TestPoliciesTreeClosed proves obligation (fl) (ADR 0011 verification 13,
// T109) on the repository, with negative controls on synthetic trees.
func TestPoliciesTreeClosed(t *testing.T) {
	_, repo := repoRoot(t)
	embedSrc, err := readRepoFile(repo, "policies/embed.go", "M2-T03")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("repository", func(t *testing.T) {
		sub, err := fs.Sub(repo, "policies")
		if err != nil {
			t.Fatal(err)
		}
		reportProblems(t, checkPoliciesTree(sub, embedSrc, opaAdapterFiles(t, repo)))
	})

	const adapterHead = "package opa\n\nimport \"" + policiesImport + "\"\n\n"
	const adapter = adapterHead + "func NewDesign() (*Engine, error) { return newEngine(policies.Design, DefaultOptions) }\n"
	const newIaC = "func NewIaC() (*Engine, error) { return newEngine(policies.IaC, DefaultOptions) }\n"
	const iacVar = "\n//go:embed iac/*.rego\nvar IaC embed.FS\n"
	file := func(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }
	base := func(extra map[string]*fstest.MapFile) fstest.MapFS {
		m := fstest.MapFS{
			"embed.go":           file(embedSrc),
			"design/a.rego":      file("package rempart.design.a\n"),
			"design/a_test.rego": file("package rempart.design_test.a\n"),
			"design/.gitkeep":    file(""),
			"iac/.gitkeep":       file(""),
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	cases := []struct {
		name             string
		fsys             fstest.MapFS
		embed, adapterGo string
		want             []string
	}{
		{name: "valid", fsys: base(nil)},
		{
			name: "valid_second_pack", fsys: base(map[string]*fstest.MapFile{"iac/b.rego": file("package rempart.iac.b\n")}),
			embed: embedSrc + iacVar, adapterGo: adapter + newIaC,
		},
		{
			name: "valid_renamed_import", fsys: base(map[string]*fstest.MapFile{"iac/b.rego": file("# Pack IaC.\n\npackage rempart.iac.b\n")}),
			embed: embedSrc + iacVar,
			adapterGo: "package opa\n\nimport pol \"" + policiesImport + "\"\n\nfunc NewDesign() (*Engine, error) { return newEngine(pol.Design, DefaultOptions) }\n" +
				"func NewIaC() (*Engine, error) { return newEngine(pol.IaC, DefaultOptions) }\n",
		},
		// Obligation (hb): a comment or a string naming the variable is not a read.
		{
			name: "read_in_comment_only", fsys: base(map[string]*fstest.MapFile{"iac/b.rego": file("package rempart.iac.b\n")}),
			embed: embedSrc + iacVar, adapterGo: adapter + "// policies.IaC is compiled by NewIaC.\n",
			want: []string{"embedded variable IaC not read by the OPA adapter"},
		},
		{
			name: "read_in_string_only", fsys: base(map[string]*fstest.MapFile{"iac/b.rego": file("package rempart.iac.b\n")}),
			embed: embedSrc + iacVar, adapterGo: adapter + "var name = \"policies.IaC\"\n",
			want: []string{"embedded variable IaC not read by the OPA adapter"},
		},
		{
			name: "read_of_another_package", fsys: base(map[string]*fstest.MapFile{"iac/b.rego": file("package rempart.iac.b\n")}),
			embed: embedSrc + iacVar, adapterGo: "package opa\n\nimport policies \"example.com/other\"\nimport real \"" + policiesImport + "\"\n\nvar _ = real.Design\nvar _ = policies.IaC\n",
			want: []string{"embedded variable IaC not read by the OPA adapter"},
		},
		// Obligation (he) (T153, T155): package bound to its pack directory.
		{
			name: "iac_declares_design", fsys: base(map[string]*fstest.MapFile{"iac/b.rego": file("package rempart.design.x\n")}),
			embed: embedSrc + iacVar, adapterGo: adapter + newIaC,
			want: []string{"policies/iac/b.rego: package \"rempart.design.x\", want rempart.iac."},
		},
		{
			name: "test_file_in_rule_package", fsys: base(map[string]*fstest.MapFile{"design/c_test.rego": file("package rempart.design.c\n")}),
			want: []string{"policies/design/c_test.rego: package \"rempart.design.c\", want rempart.design_test."},
		},
		{
			name: "rule_file_in_test_package", fsys: base(map[string]*fstest.MapFile{"design/c.rego": file("package rempart.design_test.c\n")}),
			want: []string{"policies/design/c.rego: package \"rempart.design_test.c\", want rempart.design."},
		},
		{
			name: "nested_package", fsys: base(map[string]*fstest.MapFile{"design/c.rego": file("package rempart.design.c.d\n")}),
			want: []string{"policies/design/c.rego: package \"rempart.design.c.d\""},
		},
		{
			name: "no_package_clause", fsys: base(map[string]*fstest.MapFile{"design/c.rego": file("# x\nc := 1\n")}),
			want: []string{"policies/design/c.rego: package \"\""},
		},
		{name: "json_file", fsys: base(map[string]*fstest.MapFile{"design/data.json": file(`{"skip": true}`)}), want: []string{"policies/design/data.json"}},
		{name: "yaml_file", fsys: base(map[string]*fstest.MapFile{"design/data.yaml": file("skip: true\n")}), want: []string{"policies/design/data.yaml"}},
		{name: "go_file_in_pack", fsys: base(map[string]*fstest.MapFile{"design/x.go": file("package design\n")}), want: []string{"policies/design/x.go"}},
		{name: "other_root_file", fsys: base(map[string]*fstest.MapFile{"README.md": file("x\n")}), want: []string{"policies/README.md"}},
		{name: "rego_at_root", fsys: base(map[string]*fstest.MapFile{"x.rego": file("package rempart.x\n")}), want: []string{"policies/x.rego"}},
		{
			name: "second_level", fsys: base(map[string]*fstest.MapFile{"design/sub/b.rego": file("package rempart.design.sub\n")}),
			want: []string{"policies/design/sub: directory below a pack directory"},
		},
		{
			name: "pack_not_embedded", fsys: base(map[string]*fstest.MapFile{"iac/b.rego": file("package rempart.iac.b\n")}),
			want: []string{"policies/iac: .rego files not embedded"},
		},
		{
			name: "embedded_never_read", fsys: base(map[string]*fstest.MapFile{"iac/b.rego": file("package rempart.iac.b\n")}),
			embed: embedSrc + iacVar, want: []string{"embedded variable IaC not read by the OPA adapter"},
		},
		{
			name: "whole_directory_pattern", fsys: base(nil), embed: strings.Replace(embedSrc, "//go:embed design/*.rego", "//go:embed design", 1),
			want: []string{"pattern must be exactly <pack>/*.rego", "policies/design: .rego files not embedded"},
		},
		{
			name: "symlink", fsys: base(map[string]*fstest.MapFile{"design/b.rego": {Data: []byte("a.rego"), Mode: fs.ModeSymlink}}),
			want: []string{"policies/design/b.rego: symbolic link"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			embed, adapterGo := c.embed, c.adapterGo
			if embed == "" {
				embed = embedSrc
			}
			if adapterGo == "" {
				adapterGo = adapter
			}
			if c.name == "whole_directory_pattern" && embed == embedSrc {
				t.Fatalf("mutation did not apply: %s", strconv.Quote(embedSrc))
			}
			expectProblems(t, checkPoliciesTree(c.fsys, embed, map[string]string{"adapter.go": adapterGo}), c.want)
		})
	}
}
