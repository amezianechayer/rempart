package archtest

import (
	"cmp"
	"path/filepath"
	"slices"
	"strings"
)

// CheckPackageDirs fails closed on the packages of module reached through a
// symbolic link (threat T74): go list ./... does not list a symlinked
// directory, go build compiles it under a second import path. Every listed
// package of module must live, symlinks resolved, at root plus its relative
// import path ("package-dir"), and every import of the module by a listed
// package must itself be listed ("package-unlisted").
func CheckPackageDirs(module, root string, pkgs []Package) []Violation {
	var out []Violation
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil || !filepath.IsAbs(root) {
		return []Violation{{Rule: "package-dir", Importer: "(root)", Imported: root}}
	}
	listed := map[string]bool{}
	for _, p := range pkgs {
		listed[p.ImportPath] = true
	}
	for _, p := range pkgs {
		if !inModule(module, p.ImportPath) {
			continue
		}
		want := filepath.Join(realRoot, filepath.FromSlash(strings.TrimPrefix(strings.TrimPrefix(p.ImportPath, module), "/")))
		got, err := filepath.EvalSymlinks(p.Dir)
		if p.Dir == "" || !filepath.IsAbs(p.Dir) || err != nil || got != want {
			out = append(out, Violation{Rule: "package-dir", Importer: p.ImportPath, Imported: p.Dir})
		}
		for _, imp := range p.Imports {
			if inModule(module, imp) && !listed[imp] {
				out = append(out, Violation{Rule: "package-unlisted", Importer: p.ImportPath, Imported: imp})
			}
		}
	}
	slices.SortFunc(out, func(a, b Violation) int {
		return cmp.Or(cmp.Compare(a.Rule, b.Rule), cmp.Compare(a.Importer, b.Importer), cmp.Compare(a.Imported, b.Imported))
	})
	return slices.Compact(out)
}
