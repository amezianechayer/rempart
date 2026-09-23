package archtest

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

// visionLayout is the repository layout described by the "Modules" block of
// docs/00-VISION.md section 4 and by its "Outillage de développement" line.
type visionLayout struct {
	Binaries, Domains, TopLevel, PolicySubdirs, ToolingCmd, ToolingInternal []string
}

// testPackage is the development tooling package holding these tests: its
// directory and doc.go are required even though it is not a product domain.
const testPackage = "archtest"

// referenceLayout is the layout coded in the test. vision_concordance proves
// it matches docs/00-VISION.md; a change of the vision (by ADR) must update it.
func referenceLayout() visionLayout {
	return visionLayout{
		Binaries: []string{"rempartd", "rempart-worker", "rempart-runner", "rempart", "rempart-mcp"},
		Domains: []string{
			"intent", "design", "threat", "policy", "iacgen", "validate", "plan",
			"apply", "runner", "inventory", "graph", "attackpath", "remediate", "drift",
			"finops", "compliance", "evidence", "loops", "llm", "secrets", "tenancy",
		},
		TopLevel:        []string{"policies", "modules", "schemas", "evals", "web"},
		PolicySubdirs:   []string{"design", "iac", "runtime", "k8s"},
		ToolingCmd:      []string{"rempart-evals"},
		ToolingInternal: []string{"archtest", "evals"},
	}
}

// Analysis rules of parseVisionLayout (docs/plans/M0-squelette.md section 8.2):
//  1. find the line exactly equal to "### Modules", then the first block fenced
//     by lines starting with three backquotes, before the next heading; a missing
//     title, block or closing fence is an error;
//  2. in the block, "cmd/ <list>": split the list on ",", keep the first word of
//     each piece (binaries);
//  3. "internal/" alone: the following lines of the form "  <name>/" are the
//     domains, up to the first line not starting with two spaces; a line starting
//     with two spaces that is not a domain entry is an error;
//  4. "policies/ <list>": every "<name>/" of the list is a policy subdirectory;
//  5. "<name>/ ..." lines other than cmd/ and internal/: top-level directories;
//  6. outside the block, the first line starting with "Outillage de
//     développement": every `internal/<name>` and `cmd/<name>` is tooling.
var (
	visionCmdRe       = regexp.MustCompile(`^cmd/\s+(.*)$`)
	visionInternalRe  = regexp.MustCompile(`^internal/\s*$`)
	visionDomainRe    = regexp.MustCompile(`^  ([a-z][a-z0-9]*)/`)
	visionPoliciesRe  = regexp.MustCompile(`^policies/\s+(.*)$`)
	visionSubdirRe    = regexp.MustCompile(`([a-z0-9]+)/`)
	visionTopLevelRe  = regexp.MustCompile(`^([a-z]+)/\s`)
	toolingInternalRe = regexp.MustCompile("`internal/([a-z][a-z0-9]*)`")
	toolingCmdRe      = regexp.MustCompile("`cmd/([a-z][a-z0-9-]*)`")
)

const (
	visionModulesTitle = "### Modules"
	visionToolingLine  = "Outillage de développement"
	codeFence          = "```"
)

func parseVisionLayout(markdown string) (visionLayout, error) {
	var layout visionLayout
	lines := strings.Split(strings.ReplaceAll(markdown, "\r\n", "\n"), "\n")

	title := slices.Index(lines, visionModulesTitle)
	if title < 0 {
		return layout, fmt.Errorf("no line %q in the vision document", visionModulesTitle)
	}
	open := -1
	for i := title + 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], codeFence) {
			open = i
			break
		}
		if strings.HasPrefix(lines[i], "#") {
			break
		}
	}
	if open < 0 {
		return layout, fmt.Errorf("section %q has no fenced code block", visionModulesTitle)
	}
	closing := -1
	for i := open + 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], codeFence) {
			closing = i
			break
		}
	}
	if closing < 0 {
		return layout, fmt.Errorf("fenced code block of section %q is not closed", visionModulesTitle)
	}

	block := lines[open+1 : closing]
	for i := 0; i < len(block); i++ {
		line := block[i]
		if m := visionCmdRe.FindStringSubmatch(line); m != nil {
			for _, piece := range strings.Split(m[1], ",") {
				if words := strings.Fields(piece); len(words) > 0 {
					layout.Binaries = append(layout.Binaries, words[0])
				}
			}
			continue
		}
		if visionInternalRe.MatchString(line) {
			for i+1 < len(block) && strings.HasPrefix(block[i+1], "  ") {
				i++
				m := visionDomainRe.FindStringSubmatch(block[i])
				if m == nil {
					return layout, fmt.Errorf("modules block line %q: not a domain entry of the form \"  <name>/\"", block[i])
				}
				layout.Domains = append(layout.Domains, m[1])
			}
			continue
		}
		if m := visionPoliciesRe.FindStringSubmatch(line); m != nil {
			for _, sub := range visionSubdirRe.FindAllStringSubmatch(m[1], -1) {
				layout.PolicySubdirs = append(layout.PolicySubdirs, sub[1])
			}
		}
		if m := visionTopLevelRe.FindStringSubmatch(line); m != nil && m[1] != "cmd" && m[1] != "internal" {
			layout.TopLevel = append(layout.TopLevel, m[1])
		}
	}

	for i, line := range lines {
		if i >= open && i <= closing || !strings.HasPrefix(line, visionToolingLine) {
			continue
		}
		for _, m := range toolingCmdRe.FindAllStringSubmatch(line, -1) {
			layout.ToolingCmd = append(layout.ToolingCmd, m[1])
		}
		for _, m := range toolingInternalRe.FindAllStringSubmatch(line, -1) {
			layout.ToolingInternal = append(layout.ToolingInternal, m[1])
		}
		break
	}
	return layout, nil
}

// compareLayout compares two layouts as sets, field by field.
func compareLayout(got, want visionLayout) []string {
	fields := []struct {
		name      string
		got, want []string
	}{
		{"binary (cmd/)", got.Binaries, want.Binaries},
		{"domain (internal/)", got.Domains, want.Domains},
		{"top-level directory", got.TopLevel, want.TopLevel},
		{"policy subdirectory (policies/)", got.PolicySubdirs, want.PolicySubdirs},
		{"development tooling command (cmd/)", got.ToolingCmd, want.ToolingCmd},
		{"development tooling package (internal/)", got.ToolingInternal, want.ToolingInternal},
	}
	var problems []string
	for _, f := range fields {
		for _, w := range f.want {
			if !slices.Contains(f.got, w) {
				problems = append(problems, fmt.Sprintf(
					"docs/00-VISION.md section 4: %s %q is expected by the test but not listed in the vision", f.name, w))
			}
		}
		for _, g := range f.got {
			if !slices.Contains(f.want, g) {
				problems = append(problems, fmt.Sprintf(
					"docs/00-VISION.md section 4: %s %q is listed in the vision but unknown to the test (update the test with the ADR)", f.name, g))
			}
		}
	}
	return problems
}

// checkLayout checks the repository tree against referenceLayout. It returns
// readable problems, each naming the faulty path, or nothing if conforming.
func checkLayout(fsys fs.FS) []string {
	ref := referenceLayout()
	var problems []string
	for _, d := range append(slices.Clone(ref.Domains), testPackage) {
		problems = append(problems, checkDocFile(fsys, d)...)
	}
	for _, b := range ref.Binaries {
		problems = append(problems, checkMainFile(fsys, b)...)
	}
	problems = append(problems, checkCmdDirs(fsys, ref)...)
	problems = append(problems, checkInternalDirs(fsys, ref)...)
	for _, top := range ref.TopLevel {
		if top != "policies" {
			problems = appendDirProblem(problems, fsys, top, "top-level directory of docs/00-VISION.md section 4")
			continue
		}
		for _, sub := range ref.PolicySubdirs {
			problems = appendDirProblem(problems, fsys, "policies/"+sub, "policy subdirectory of docs/00-VISION.md section 4")
		}
	}
	return problems
}

func appendDirProblem(problems []string, fsys fs.FS, name, role string) []string {
	info, err := fs.Stat(fsys, name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return append(problems, fmt.Sprintf("%s: directory does not exist (%s)", name, role))
	case err != nil:
		return append(problems, fmt.Sprintf("%s: %v", name, err))
	case !info.IsDir():
		return append(problems, fmt.Sprintf("%s: not a directory (%s)", name, role))
	}
	return problems
}

// readTreeFile reads a Go file of the tree; ok is false when a problem was appended.
func readTreeFile(problems []string, fsys fs.FS, name, role string) (src []byte, updated []string, ok bool) {
	data, err := fs.ReadFile(fsys, name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, append(problems, fmt.Sprintf("%s: file does not exist (%s)", name, role)), false
	case err != nil:
		return nil, append(problems, fmt.Sprintf("%s: %v", name, err)), false
	}
	return data, problems, true
}

// checkDocFile requires internal/<pkg>/doc.go declaring package <pkg> with a
// package comment starting with "Package <pkg> ".
func checkDocFile(fsys fs.FS, pkg string) []string {
	dir := "internal/" + pkg
	problems := appendDirProblem(nil, fsys, dir, "package listed in docs/00-VISION.md section 4, created by M0-T01")
	if len(problems) > 0 {
		return problems
	}
	name := dir + "/doc.go"
	src, problems, ok := readTreeFile(problems, fsys, name, "package documentation, created by M0-T01")
	if !ok {
		return problems
	}
	f, err := parser.ParseFile(token.NewFileSet(), name, src, parser.PackageClauseOnly|parser.ParseComments)
	if err != nil {
		return append(problems, fmt.Sprintf("%s: cannot parse: %v", name, err))
	}
	if f.Name.Name != pkg {
		problems = append(problems, fmt.Sprintf("%s: package clause is %q, want %q", name, f.Name.Name, pkg))
	}
	prefix := "Package " + pkg + " "
	if f.Doc == nil || !strings.HasPrefix(f.Doc.Text(), prefix) {
		problems = append(problems, fmt.Sprintf("%s: package comment must start with %q", name, prefix))
	}
	return problems
}

// checkMainFile requires cmd/<bin>/main.go declaring func main() without
// receiver, type parameters, parameters or results. The package clause of every
// file under cmd/ is checked by checkMainPackageDir.
func checkMainFile(fsys fs.FS, bin string) []string {
	dir := "cmd/" + bin
	problems := appendDirProblem(nil, fsys, dir, "binary listed in docs/00-VISION.md section 4, created by M0-T01")
	if len(problems) > 0 {
		return problems
	}
	name := dir + "/main.go"
	src, problems, ok := readTreeFile(problems, fsys, name, "entry point of the binary")
	if !ok {
		return problems
	}
	f, err := parser.ParseFile(token.NewFileSet(), name, src, parser.SkipObjectResolution)
	if err != nil {
		return append(problems, fmt.Sprintf("%s: cannot parse: %v", name, err))
	}
	if !hasMainFunc(f) {
		problems = append(problems, fmt.Sprintf(
			"%s: no func main() declaration (without receiver, parameters or results)", name))
	}
	return problems
}

func hasMainFunc(f *ast.File) bool {
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "main" || fd.Recv != nil || fd.Body == nil {
			continue
		}
		if fd.Type.TypeParams.NumFields() == 0 && fd.Type.Params.NumFields() == 0 && fd.Type.Results.NumFields() == 0 {
			return true
		}
	}
	return false
}

// checkCmdDirs requires every directory under cmd/ to be a known binary or
// development tool made of package main files.
func checkCmdDirs(fsys fs.FS, ref visionLayout) []string {
	entries, err := fs.ReadDir(fsys, "cmd")
	if errors.Is(err, fs.ErrNotExist) {
		return []string{"cmd: directory does not exist (binaries of docs/00-VISION.md section 4, created by M0-T01)"}
	}
	if err != nil {
		return []string{fmt.Sprintf("cmd: %v", err)}
	}
	allowed := append(slices.Clone(ref.Binaries), ref.ToolingCmd...)
	var problems []string
	for _, e := range entries {
		name := "cmd/" + e.Name()
		if !e.IsDir() {
			if strings.HasSuffix(e.Name(), ".go") {
				problems = append(problems, name+": Go file directly under cmd/ (each binary has its own directory)")
			}
			continue
		}
		if !slices.Contains(allowed, e.Name()) {
			problems = append(problems, name+
				": directory not listed in docs/00-VISION.md section 4 (binaries or development tooling); a new binary needs an ADR")
		}
		problems = append(problems, checkMainPackageDir(fsys, name)...)
	}
	return problems
}

// checkMainPackageDir requires at least one non-test Go file in dir, all of them in package main.
func checkMainPackageDir(fsys fs.FS, dir string) []string {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return []string{fmt.Sprintf("%s: %v", dir, err)}
	}
	var problems []string
	goFiles := 0
	for _, e := range entries {
		base := e.Name()
		if e.IsDir() || !strings.HasSuffix(base, ".go") || strings.HasSuffix(base, "_test.go") {
			continue
		}
		goFiles++
		name := path.Join(dir, base)
		src, updated, ok := readTreeFile(problems, fsys, name, "Go file of a binary")
		problems = updated
		if !ok {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, src, parser.PackageClauseOnly)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: cannot parse: %v", name, err))
			continue
		}
		if f.Name.Name != "main" {
			problems = append(problems, fmt.Sprintf(
				"%s: package clause is %q, want \"main\" (every non-test Go file under cmd/<binary>/ belongs to the binary)",
				name, f.Name.Name))
		}
	}
	if goFiles == 0 {
		problems = append(problems, dir+": no non-test Go file (a directory under cmd/ is a binary)")
	}
	return problems
}

// checkInternalDirs requires every directory under internal/ to be a domain or
// a development tooling package listed in the vision.
func checkInternalDirs(fsys fs.FS, ref visionLayout) []string {
	entries, err := fs.ReadDir(fsys, "internal")
	if errors.Is(err, fs.ErrNotExist) {
		return []string{"internal: directory does not exist (domains of docs/00-VISION.md section 4, created by M0-T01)"}
	}
	if err != nil {
		return []string{fmt.Sprintf("internal: %v", err)}
	}
	allowed := append(slices.Clone(ref.Domains), ref.ToolingInternal...)
	var problems []string
	for _, e := range entries {
		name := "internal/" + e.Name()
		switch {
		case !e.IsDir() && strings.HasSuffix(e.Name(), ".go"):
			problems = append(problems, name+": Go file directly under internal/ (each domain has its own directory)")
		case e.IsDir() && !slices.Contains(allowed, e.Name()):
			problems = append(problems, name+
				": directory not listed in docs/00-VISION.md section 4 (domains or development tooling); a new domain needs an ADR")
		}
	}
	return problems
}

// validTree is a conforming synthetic repository tree.
func validTree() fstest.MapFS {
	ref := referenceLayout()
	tree := fstest.MapFS{}
	for _, d := range append(slices.Clone(ref.Domains), testPackage) {
		tree["internal/"+d+"/doc.go"] = &fstest.MapFile{Data: []byte(
			"// Package " + d + " is a domain of the synthetic tree.\n//\n// No code yet.\npackage " + d + "\n")}
	}
	for _, b := range ref.Binaries {
		tree["cmd/"+b+"/main.go"] = &fstest.MapFile{Data: []byte(mainSource)}
	}
	for _, sub := range ref.PolicySubdirs {
		tree["policies/"+sub+"/.gitkeep"] = &fstest.MapFile{}
	}
	for _, top := range []string{"modules", "schemas", "evals", "web"} {
		tree[top+"/.gitkeep"] = &fstest.MapFile{}
	}
	return tree
}

const mainSource = "// Command x is a stub.\npackage main\n\nimport \"os\"\n\nfunc main() {\n\tos.Exit(2)\n}\n"

// syntheticVision mirrors docs/00-VISION.md section 4 (Modules block and tooling line).
func syntheticVision() string {
	return strings.Join([]string{
		"# Rempart",
		"",
		"## 4. Architecture",
		"",
		"### Stack",
		"Go (hexagonal).",
		"",
		visionModulesTitle,
		codeFence,
		"cmd/            rempartd (API), rempart-worker (Temporal), rempart-runner (côté client), rempart (CLI), rempart-mcp",
		"internal/",
		"  intent/       Intent IR, NL vers IR, clarifications",
		"  design/       graphe d'architecture, planification CIDR, patterns",
		"  threat/       STRIDE sur le graphe d'architecture",
		"  policy/       moteur OPA, packs, mapping conformité",
		"  iacgen/       génération OpenTofu depuis le graphe validé",
		"  validate/     chaîne de validation, normalisation des erreurs",
		"  plan/         plan, rayon d'impact, risque, équivalence graphe/plan",
		"  apply/        orchestration de l'apply (via runner), vérifications post-déploiement, rollback",
		"  runner/       protocole runner : récupération de plans signés, exécution, attestations",
		"  inventory/    collecteurs (aws, azure, ovh, scaleway, kubernetes)",
		"  graph/        graphe de sécurité unifié, atteignabilité, permissions effectives",
		"  attackpath/   chemins d'attaque non destructifs",
		"  remediate/    finding vers source IaC vers correctif vers PR",
		"  drift/        dérive",
		"  finops/       coûts, anomalies, recommandations",
		"  compliance/   contrôles, preuves, exports",
		"  evidence/     dossiers de preuves signés, journal chaîné",
		"  loops/        un workflow Temporal par boucle",
		"  llm/          ModelProvider, prompts versionnés, rédaction, quarantaine des données non fiables",
		"  secrets/      intégration OpenBao, identifiants dynamiques",
		"  tenancy/      isolation, RBAC, identités",
		"policies/       design/, iac/, runtime/, k8s/ + tests",
		"modules/        modules OpenTofu internes + tests",
		"schemas/        JSON Schemas versionnés (intent, graph, evidence, findings)",
		"evals/          jeux d'évaluation par boucle + labo vulnérable",
		"web/            interface",
		codeFence,
		"",
		visionToolingLine + ", jamais livré aux clients : `cmd/rempart-evals` (exécuteur d'evals), " +
			"`internal/evals` (noyau d'évaluation), `internal/archtest` (tests d'architecture), `scripts/` (outils), `.github/` (CI).",
		"",
		"### Mode runner",
		codeFence,
		"cmd/            rempart-extra",
		codeFence,
		"",
	}, "\n")
}

func TestLayoutMatchesVision(t *testing.T) {
	t.Run("negative_controls", func(t *testing.T) {
		treeCases := []struct {
			name   string
			mutate func(tree fstest.MapFS)
			want   []string
		}{
			{name: "valid_tree"},
			{
				name: "valid_tree_with_tooling",
				mutate: func(tree fstest.MapFS) {
					tree["internal/evals/doc.go"] = &fstest.MapFile{Data: []byte("// Package evals runs evaluations.\npackage evals\n")}
					tree["cmd/rempart-evals/main.go"] = &fstest.MapFile{Data: []byte(mainSource)}
				},
			},
			{
				name: "valid_tree_with_external_test_file",
				mutate: func(tree fstest.MapFS) {
					tree["cmd/rempart/main_test.go"] = &fstest.MapFile{Data: []byte("package main_test\n")}
				},
			},
			{
				name:   "missing_domain",
				mutate: func(tree fstest.MapFS) { delete(tree, "internal/graph/doc.go") },
				want:   []string{"internal/graph: directory does not exist"},
			},
			{
				name: "missing_doc_file",
				mutate: func(tree fstest.MapFS) {
					delete(tree, "internal/drift/doc.go")
					tree["internal/drift/drift.go"] = &fstest.MapFile{Data: []byte("// Package drift detects drift.\npackage drift\n")}
				},
				want: []string{"internal/drift/doc.go: file does not exist"},
			},
			{
				name: "missing_archtest_doc_file",
				mutate: func(tree fstest.MapFS) {
					delete(tree, "internal/archtest/doc.go")
					tree["internal/archtest/layout_test.go"] = &fstest.MapFile{Data: []byte("package archtest\n")}
				},
				want: []string{"internal/archtest/doc.go: file does not exist"},
			},
			{
				name: "doc_wrong_package",
				mutate: func(tree fstest.MapFS) {
					tree["internal/policy/doc.go"] = &fstest.MapFile{Data: []byte("// Package policy wraps OPA.\npackage policies\n")}
				},
				want: []string{"internal/policy/doc.go", `package clause is "policies"`},
			},
			{
				name: "doc_without_package_comment",
				mutate: func(tree fstest.MapFS) {
					tree["internal/threat/doc.go"] = &fstest.MapFile{Data: []byte("package threat\n")}
				},
				want: []string{"internal/threat/doc.go", `"Package threat "`},
			},
			{
				name: "doc_comment_names_another_package",
				mutate: func(tree fstest.MapFS) {
					tree["internal/intent/doc.go"] = &fstest.MapFile{Data: []byte("// Package intents turns requests into IR.\npackage intent\n")}
				},
				want: []string{"internal/intent/doc.go", `"Package intent "`},
			},
			{
				name: "unknown_internal_dir",
				mutate: func(tree fstest.MapFS) {
					tree["internal/utils/utils.go"] = &fstest.MapFile{Data: []byte("// Package utils is a grab bag.\npackage utils\n")}
				},
				want: []string{"internal/utils: directory not listed"},
			},
			{
				name: "go_file_directly_under_internal",
				mutate: func(tree fstest.MapFS) {
					tree["internal/helpers.go"] = &fstest.MapFile{Data: []byte("package internal\n")}
				},
				want: []string{"internal/helpers.go"},
			},
			{
				name: "cmd_not_main",
				mutate: func(tree fstest.MapFS) {
					tree["cmd/rempart/main.go"] = &fstest.MapFile{Data: []byte("package rempart\n\nfunc main() {}\n")}
				},
				want: []string{"cmd/rempart/main.go", `package clause is "rempart"`},
			},
			{
				name: "cmd_without_main_func",
				mutate: func(tree fstest.MapFS) {
					tree["cmd/rempart-mcp/main.go"] = &fstest.MapFile{Data: []byte("package main\n\nfunc run() {}\n")}
				},
				want: []string{"cmd/rempart-mcp/main.go: no func main()"},
			},
			{
				name: "cmd_main_with_parameters",
				mutate: func(tree fstest.MapFS) {
					tree["cmd/rempartd/main.go"] = &fstest.MapFile{Data: []byte("package main\n\nfunc main(args []string) {}\n")}
				},
				want: []string{"cmd/rempartd/main.go: no func main()"},
			},
			{
				name: "cmd_main_is_a_method",
				mutate: func(tree fstest.MapFS) {
					tree["cmd/rempart-worker/main.go"] = &fstest.MapFile{Data: []byte("package main\n\ntype app struct{}\n\nfunc (app) main() {}\n")}
				},
				want: []string{"cmd/rempart-worker/main.go: no func main()"},
			},
			{
				name: "cmd_main_in_another_file",
				mutate: func(tree fstest.MapFS) {
					delete(tree, "cmd/rempart/main.go")
					tree["cmd/rempart/cli.go"] = &fstest.MapFile{Data: []byte(mainSource)}
				},
				want: []string{"cmd/rempart/main.go: file does not exist"},
			},
			{
				name: "cmd_extra_file_not_main",
				mutate: func(tree fstest.MapFS) {
					tree["cmd/rempart-runner/version.go"] = &fstest.MapFile{Data: []byte("package version\n")}
				},
				want: []string{"cmd/rempart-runner/version.go", `package clause is "version"`},
			},
			{
				name: "unknown_cmd_dir",
				mutate: func(tree fstest.MapFS) {
					tree["cmd/rempart-debug/main.go"] = &fstest.MapFile{Data: []byte(mainSource)}
				},
				want: []string{"cmd/rempart-debug: directory not listed"},
			},
			{
				name: "cmd_dir_without_go_file",
				mutate: func(tree fstest.MapFS) {
					tree["cmd/rempart-evals/README.md"] = &fstest.MapFile{Data: []byte("# evals\n")}
				},
				want: []string{"cmd/rempart-evals: no non-test Go file"},
			},
			{
				name:   "missing_policy_subdir",
				mutate: func(tree fstest.MapFS) { delete(tree, "policies/k8s/.gitkeep") },
				want:   []string{"policies/k8s: directory does not exist"},
			},
			{
				name: "top_level_entry_is_a_file",
				mutate: func(tree fstest.MapFS) {
					delete(tree, "web/.gitkeep")
					tree["web"] = &fstest.MapFile{Data: []byte("not a directory\n")}
				},
				want: []string{"web: not a directory"},
			},
		}
		for _, tc := range treeCases {
			t.Run(tc.name, func(t *testing.T) {
				tree := validTree()
				if tc.mutate != nil {
					tc.mutate(tree)
				}
				expectProblems(t, checkLayout(tree), tc.want)
			})
		}

		vision := syntheticVision()
		visionCases := []struct {
			name     string
			markdown string
			wantErr  string
			want     []string
		}{
			{name: "vision_valid", markdown: vision},
			{
				name:     "vision_without_modules_block",
				markdown: mustReplace(t, vision, visionModulesTitle+"\n"+codeFence+"\n", visionModulesTitle+"\nSee the code.\n\n### Layout\n"+codeFence+"\n"),
				wantErr:  "has no fenced code block",
			},
			{
				name:     "vision_without_modules_title",
				markdown: mustReplace(t, vision, visionModulesTitle+"\n", "### Modules Go\n"),
				wantErr:  `no line "### Modules"`,
			},
			{
				name:     "vision_unclosed_block",
				markdown: strings.Split(vision, "web/            interface\n")[0] + "web/            interface\n",
				wantErr:  "is not closed",
			},
			{
				name:     "vision_malformed_domain_line",
				markdown: mustReplace(t, vision, "  drift/        dérive", "  Drift/        dérive"),
				wantErr:  `"  Drift/`,
			},
			{
				name:     "vision_extra_domain",
				markdown: mustReplace(t, vision, "  drift/        dérive\n", "  drift/        dérive\n  cache/        cache partagé\n"),
				want:     []string{`domain (internal/) "cache" is listed in the vision but unknown to the test`},
			},
			{
				name:     "vision_missing_binary",
				markdown: mustReplace(t, vision, ", rempart-mcp\n", "\n"),
				want:     []string{`binary (cmd/) "rempart-mcp" is expected by the test`},
			},
			{
				name:     "vision_missing_policy_subdir",
				markdown: mustReplace(t, vision, "runtime/, k8s/ + tests", "runtime/ + tests"),
				want:     []string{`policy subdirectory (policies/) "k8s"`},
			},
			{
				name:     "vision_extra_top_level_dir",
				markdown: mustReplace(t, vision, "web/            interface\n", "web/            interface\ndeploy/         manifests\n"),
				want:     []string{`top-level directory "deploy"`},
			},
			{
				name:     "vision_missing_tooling_line",
				markdown: mustReplace(t, vision, visionToolingLine+",", "Development tooling,"),
				want:     []string{`development tooling command (cmd/) "rempart-evals"`, `development tooling package (internal/) "archtest"`},
			},
		}
		for _, tc := range visionCases {
			t.Run(tc.name, func(t *testing.T) {
				got, err := parseVisionLayout(tc.markdown)
				if tc.wantErr != "" {
					expectError(t, err, tc.wantErr)
					return
				}
				if err != nil {
					t.Fatalf("parseVisionLayout: %v", err)
				}
				expectProblems(t, compareLayout(got, referenceLayout()), tc.want)
			})
		}
	})

	t.Run("vision_concordance", func(t *testing.T) {
		_, fsys := repoRoot(t)
		markdown, err := readRepoFile(fsys, "docs/00-VISION.md", "reference document, changed only through an ADR")
		if err != nil {
			t.Fatal(err)
		}
		got, err := parseVisionLayout(markdown)
		if err != nil {
			t.Fatalf("docs/00-VISION.md: %v", err)
		}
		reportProblems(t, compareLayout(got, referenceLayout()))
	})

	t.Run("repository", func(t *testing.T) {
		_, fsys := repoRoot(t)
		reportProblems(t, checkLayout(fsys))
	})
}
