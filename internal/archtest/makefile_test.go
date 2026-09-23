package archtest

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// makeRule is a parsed Makefile rule.
type makeRule struct {
	Prereqs []string
	Recipe  []string // logical lines, continuations joined, @ - + prefixes removed
	Line    int      // line of the first rule naming the target
}

// makeLine is a logical Makefile line (continuations joined) and the number of
// its first physical line.
type makeLine struct {
	Num  int
	Text string
}

type parsedMakefile struct {
	Rules map[string]makeRule
	Phony map[string]bool
	Lines []makeLine // every logical line, comments included, for whole-file rules
}

// Analysis rules of parseMakefile, a subset of GNU make syntax
// (docs/plans/M0-squelette.md section 8.4):
//  1. lines ending with a backslash are joined with the next one (separated by
//     one space, leading blanks of the next line removed) before classification;
//  2. a blank line or a line starting with "#" (outside a recipe) is ignored;
//  3. an assignment (NAME = := ::= :::= ?= += != value) is ignored;
//  4. include, -include, sinclude, export, unexport, override and vpath
//     directives are ignored;
//  5. ifeq, ifneq, ifdef, ifndef, else, endif, define and endef are errors: the
//     test parser must be extended before the Makefile uses them;
//  6. a rule is a line not starting with a tab whose first ":" is not followed
//     by "=": targets before ":", prerequisites after it (up to ";" or "#",
//     order-only prerequisites after "|" included); text after ";" is the first
//     recipe line; ".PHONY" feeds the set of phony targets (several lines
//     allowed); double-colon and static pattern rules are errors;
//  7. a recipe is made of the lines starting with a tab that follow a rule;
//     @ - + prefixes are removed; a blank line or a comment in column 0 does not
//     end the recipe; a recipe line outside a rule is an error;
//  8. two rules with a recipe for the same target are an error.
var (
	makeAssignRe      = regexp.MustCompile(`^[A-Za-z0-9_.]+\s*(::?=|:::=|\?=|\+=|!=|=)`)
	makeIgnoredRe     = regexp.MustCompile(`^(include|-include|sinclude|export|unexport|override|vpath)(\s|$)`)
	makeUnsupportedRe = regexp.MustCompile(`^(ifeq|ifneq|ifdef|ifndef|else|endif|define|endef)(\s|\(|$)`)
)

func parseMakefile(src string) (parsedMakefile, error) {
	p := makeParser{
		mf:         parsedMakefile{Rules: map[string]makeRule{}, Phony: map[string]bool{}, Lines: joinMakeLines(src)},
		recipeRule: map[string]int{},
	}
	for _, ln := range p.mf.Lines {
		if err := p.parseLine(ln); err != nil {
			return p.mf, err
		}
	}
	return p.mf, nil
}

func joinMakeLines(src string) []makeLine {
	var lines []makeLine
	pending := false
	for i, raw := range strings.Split(src, "\n") {
		raw = strings.TrimSuffix(raw, "\r")
		if pending {
			lines[len(lines)-1].Text += " " + strings.TrimLeft(raw, " \t")
		} else {
			lines = append(lines, makeLine{Num: i + 1, Text: raw})
		}
		last := &lines[len(lines)-1]
		pending = strings.HasSuffix(last.Text, `\`)
		if pending {
			last.Text = strings.TrimRight(strings.TrimSuffix(last.Text, `\`), " ")
		}
	}
	return lines
}

type makeParser struct {
	mf          parsedMakefile
	current     []string       // targets of the rule whose recipe is being read, nil if none
	currentLine int            // line of that rule
	recipeRule  map[string]int // target -> line of the rule owning its recipe
}

func (p *makeParser) parseLine(ln makeLine) error {
	if strings.HasPrefix(ln.Text, "\t") {
		if p.current == nil {
			return fmt.Errorf("line %d: recipe line outside a rule", ln.Num)
		}
		return p.addRecipe(ln.Text[1:], ln.Num)
	}
	text := strings.TrimSpace(ln.Text)
	if text == "" || strings.HasPrefix(text, "#") {
		return nil
	}
	p.current = nil
	switch {
	case makeUnsupportedRe.MatchString(text):
		return fmt.Errorf("line %d: unsupported directive %q: update the test parser before using it", ln.Num, text)
	case makeIgnoredRe.MatchString(text), makeAssignRe.MatchString(text):
		return nil
	}
	return p.parseRule(text, ln.Num)
}

func (p *makeParser) parseRule(text string, num int) error {
	colon := strings.IndexByte(text, ':')
	if colon < 0 {
		return fmt.Errorf("line %d: unrecognized line %q", num, text)
	}
	rest := text[colon+1:]
	switch {
	case strings.HasPrefix(rest, "="):
		return fmt.Errorf("line %d: unrecognized assignment %q", num, text)
	case strings.HasPrefix(rest, ":"):
		return fmt.Errorf("line %d: double-colon rule %q not supported: update the test parser", num, text)
	}
	targets := strings.Fields(text[:colon])
	if len(targets) == 0 {
		return fmt.Errorf("line %d: rule without target %q", num, text)
	}
	inline := ""
	if i := strings.IndexAny(rest, ";#"); i >= 0 {
		if rest[i] == ';' {
			inline = rest[i+1:]
		}
		rest = rest[:i]
	}
	var prereqs []string
	for _, f := range strings.Fields(rest) {
		if f == "|" {
			continue
		}
		if strings.Contains(f, ":") {
			return fmt.Errorf("line %d: static pattern rule or unsupported prerequisite %q: update the test parser", num, f)
		}
		prereqs = append(prereqs, f)
	}
	p.current, p.currentLine = targets, num
	for _, target := range targets {
		if target == ".PHONY" {
			for _, pr := range prereqs {
				p.mf.Phony[pr] = true
			}
			continue
		}
		r, seen := p.mf.Rules[target]
		if !seen {
			r.Line = num
		}
		r.Prereqs = append(r.Prereqs, prereqs...)
		p.mf.Rules[target] = r
	}
	return p.addRecipe(inline, num)
}

func (p *makeParser) addRecipe(text string, num int) error {
	cmd := strings.TrimSpace(strings.TrimLeft(text, "@-+ \t"))
	if cmd == "" {
		return nil
	}
	for _, target := range p.current {
		if target == ".PHONY" {
			continue
		}
		if owner, ok := p.recipeRule[target]; ok && owner != p.currentLine {
			return fmt.Errorf("line %d: second recipe for target %q (first recipe under the rule of line %d)", num, target, owner)
		}
		p.recipeRule[target] = p.currentLine
		r := p.mf.Rules[target]
		r.Recipe = append(r.Recipe, cmd)
		p.mf.Rules[target] = r
	}
	return nil
}

// requiredMakeTargets must each be defined once and declared .PHONY.
func requiredMakeTargets() []string {
	return []string{
		"verify-quick", "verify", "evals", "dev", "dev-preflight", "dev-down", "sandbox-guard",
		"sandbox-plan", "sandbox-apply", "sandbox-destroy", "update-baseline", "arch-test", "opa-test",
	}
}

var (
	makeCallRe        = regexp.MustCompile(`\$[({]MAKE[)}]|\bmake\b`)
	makeTokenRe       = regexp.MustCompile(`[A-Za-z0-9._/-]+`)
	callerVarRe       = regexp.MustCompile(`(^|[^$])\$[({](SCENARIO|EVAL|POLICIES_DIR|OPA)[)}:]`)
	readRe            = regexp.MustCompile(`\bread\b`)
	ttyRedirectRe     = regexp.MustCompile(`(^|\s)0?<\s*/dev/tty(\s|$)`)
	notInVerifyQuick  = regexp.MustCompile(`\bdocker\b|govulncheck|-tags[= ]?integration|\bcurl\b|\bwget\b|\bgo (get|install)\b`)
	regoGlobRe        = regexp.MustCompile(`\*\.rego`)
	opaTestRe         = regexp.MustCompile(`(opa|\$\(OPA\)'?|"\$\$OPA") test`)
	templateOpaCondRe = regexp.MustCompile(`\[\s*-d\s+policies\s*\]`)
	overrideValueRe   = regexp.MustCompile(`^override\s+([A-Za-z0-9_]+)\s*:=\s*\$\(value ([A-Za-z0-9_]+)\)\s*$`)
	evalsGuardRe      = regexp.MustCompile(`^test\s+-d\s+cmd/rempart-evals\s*\|\|`)
	evalCheckRe       = regexp.MustCompile(`^\[\[\s+"\$\$(EVAL|\{EVAL(:-)?\})"\s+=~\s+\^\S+\$\$\s+\]\]\s+\|\|\s+\{.*\bexit\s+[1-9][0-9]*\s*;\s*\}$`)
	goRunRe           = regexp.MustCompile(`\bgo run\b`)
	verifyQuickSteps  = []struct {
		desc string
		re   *regexp.Regexp
	}{
		{"go build ./...", regexp.MustCompile(`^go build \./\.\.\.$`)},
		{"golangci-lint run", regexp.MustCompile(`^golangci-lint run\b`)},
		{"go test -short ./...", regexp.MustCompile(`^go test\b.*-short.*\./\.\.\.`)},
		{"$(MAKE) opa-test", regexp.MustCompile(`\$\(MAKE\).*(^|\s)opa-test(\s|$)`)},
		{"$(MAKE) arch-test", regexp.MustCompile(`\$\(MAKE\).*(^|\s)arch-test(\s|$)`)},
	}
)

// checkMakefile applies rules 1 to 15 of docs/plans/M0-squelette.md section 8.4.
func checkMakefile(mf parsedMakefile) []string {
	var problems problemList
	checkMakeTargets(mf, &problems)
	checkSandboxTargets(mf, &problems)
	checkVerifyTargets(mf, &problems)
	checkOpaTest(mf, &problems)
	checkCallerVariables(mf, &problems)
	checkEvalsTargets(mf, &problems)

	for _, l := range mf.Lines {
		if m := callerVarRe.FindStringSubmatch(l.Text); m != nil {
			problems.addf("Makefile line %d: %s interpolated by make (read it from the environment with \"$$%s\" in the recipe): %q",
				l.Num, m[2], m[2], l.Text)
		}
	}
	if !strings.Contains(strings.Join(mf.Rules["update-baseline"].Recipe, "\n"), "--write-baseline") {
		problems.addf("Makefile: target update-baseline must pass --write-baseline")
	}
	if !strings.Contains(strings.Join(mf.Rules["arch-test"].Recipe, "\n"), "./internal/archtest/...") {
		problems.addf("Makefile: target arch-test must test ./internal/archtest/...")
	}
	return problems
}

// checkMakeTargets: rule 1.
func checkMakeTargets(mf parsedMakefile, problems *problemList) {
	for _, name := range requiredMakeTargets() {
		if _, ok := mf.Rules[name]; !ok {
			problems.addf("Makefile: target %s is not defined", name)
		}
		if !mf.Phony[name] {
			problems.addf("Makefile: target %s is not declared .PHONY", name)
		}
	}
}

// checkSandboxTargets: rules 2 to 4 and 14 (threat T8, human approval).
func checkSandboxTargets(mf parsedMakefile, problems *problemList) {
	for _, name := range []string{"sandbox-plan", "sandbox-apply", "sandbox-destroy"} {
		if r := mf.Rules[name]; !slices.Contains(r.Prereqs, "sandbox-guard") {
			problems.addf("Makefile line %d: target %s must have sandbox-guard as a prerequisite (the guard runs before any validation or prompt)",
				r.Line, name)
		}
	}
	guard := mf.Rules["sandbox-guard"].Recipe
	joined := strings.Join(guard, "\n")
	if !strings.Contains(joined, "scripts/sandbox.sh absent") || !strings.Contains(joined, "exit 2") {
		problems.addf("Makefile: target sandbox-guard must report \"scripts/sandbox.sh absent\" and exit 2")
	}
	for _, l := range guard {
		if readRe.MatchString(l) {
			problems.addf("Makefile: target sandbox-guard must not prompt (read): %q", l)
		}
	}
	for _, name := range []string{"sandbox-apply", "sandbox-destroy"} {
		recipe := mf.Rules[name].Recipe
		confirm := slices.IndexFunc(recipe, func(l string) bool { return readRe.MatchString(l) && strings.Contains(l, `"oui"`) })
		call := slices.IndexFunc(recipe, func(l string) bool { return strings.Contains(l, "scripts/sandbox.sh") })
		switch {
		case confirm < 0:
			problems.addf("Makefile: target %s has no human confirmation (a read line checking \"oui\")", name)
		case call < 0:
			problems.addf("Makefile: target %s never calls scripts/sandbox.sh", name)
		case confirm > call:
			problems.addf("Makefile: target %s asks for confirmation after calling scripts/sandbox.sh", name)
		}
		if confirm >= 0 && !readsFromTTY(recipe[confirm]) {
			problems.addf("Makefile: target %s reads the confirmation from standard input: the read command itself must redirect </dev/tty "+
				"(a pipe must not answer \"oui\"): %q", name, recipe[confirm])
		}
	}
}

// readsFromTTY reports whether the read command of a recipe line takes its
// input from /dev/tty: the redirection must be outside quotes (not a decoy in
// the prompt text) and belong to the read command, not to a later command of
// the same line.
func readsFromTTY(line string) bool {
	plain := shellUnquoted(line)
	loc := readRe.FindStringIndex(plain)
	if loc == nil {
		return false
	}
	cmd := plain[loc[0]:]
	if i := strings.IndexAny(cmd, ";&|"); i >= 0 {
		cmd = cmd[:i]
	}
	return ttyRedirectRe.MatchString(cmd)
}

// shellUnquoted drops the quoted text (single quotes, double quotes) and the
// backslash-escaped characters of a shell command line.
func shellUnquoted(s string) string {
	var b strings.Builder
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote == 0 && (c == '\'' || c == '"'):
			quote = c
		case quote == 0 && c == '\\':
			i++
		case quote == 0:
			b.WriteByte(c)
		case c == quote:
			quote = 0
		case quote == '"' && c == '\\':
			i++
		}
	}
	return b.String()
}

// callerVariables are set by the caller on the make command line and read by
// the recipes from the environment (threat T8).
func callerVariables() []string { return []string{"SCENARIO", "EVAL", "POLICIES_DIR", "OPA"} }

// checkCallerVariables: rule 13 (R1-a). Each caller variable is frozen by
// "override X := $(value X)" (make never expands the raw text given on the
// command line) before any export line naming it, and it is exported. A bare
// "export" exports every variable, so it names each of them.
func checkCallerVariables(mf parsedMakefile, problems *problemList) {
	frozen := map[string]int{}   // variable -> line of its first override := $(value ...)
	exported := map[string]int{} // variable -> line of its first export
	for _, l := range mf.Lines {
		if strings.HasPrefix(l.Text, "\t") {
			continue // recipe line: shell, not make
		}
		text := strings.TrimSpace(l.Text)
		if m := overrideValueRe.FindStringSubmatch(text); m != nil && m[1] == m[2] {
			if _, seen := frozen[m[1]]; !seen {
				frozen[m[1]] = l.Num
			}
			continue
		}
		names, all, ok := exportedNames(text)
		if !ok {
			continue
		}
		for _, v := range callerVariables() {
			if _, seen := exported[v]; !seen && (all || slices.Contains(names, v)) {
				exported[v] = l.Num
			}
		}
	}
	for _, v := range callerVariables() {
		freeze, isFrozen := frozen[v]
		export, isExported := exported[v]
		switch {
		case !isFrozen:
			problems.addf("Makefile: caller variable %s is not frozen by \"override %s := $(value %s)\" "+
				"(make would expand a command-line value such as $(shell ...), threat T8)", v, v, v)
		case isExported && export < freeze:
			problems.addf("Makefile line %d: caller variable %s is exported before \"override %s := $(value %s)\" (line %d)",
				export, v, v, v, freeze)
		}
		if !isExported {
			problems.addf("Makefile: caller variable %s is not exported (recipes read it from the environment as \"$$%s\")", v, v)
		}
	}
}

// exportedNames parses an export directive: ok is false for any other line,
// all is true for a bare "export" (every variable exported).
func exportedNames(text string) (names []string, all, ok bool) {
	if i := strings.IndexByte(text, '#'); i >= 0 {
		text = text[:i]
	}
	fields := strings.Fields(text)
	if len(fields) == 0 || fields[0] != "export" {
		return nil, false, false
	}
	if len(fields) == 1 {
		return nil, true, true
	}
	for _, f := range fields[1:] {
		if i := strings.IndexAny(f, ":?+!="); i >= 0 {
			if i > 0 {
				names = append(names, f[:i])
			}
			break
		}
		names = append(names, f)
	}
	return names, false, true
}

// checkEvalsTargets: rule 15 (R1-e). The presence guard of cmd/rempart-evals
// stays the first recipe line (criterion 6a), then EVAL is checked against an
// anchored allowlist, failing the recipe, before go run.
func checkEvalsTargets(mf parsedMakefile, problems *problemList) {
	for _, name := range []string{"evals", "update-baseline"} {
		recipe := mf.Rules[name].Recipe
		if len(recipe) == 0 || !evalsGuardRe.MatchString(recipe[0]) {
			problems.addf("Makefile: target %s: the first recipe line must be the guard \"test -d cmd/rempart-evals || ...\" "+
				"(criterion 6a: code 2 before M0-T23, before any validation)", name)
		}
		check := slices.IndexFunc(recipe, evalCheckRe.MatchString)
		run := slices.IndexFunc(recipe, goRunRe.MatchString)
		switch {
		case check < 0:
			problems.addf("Makefile: target %s does not validate EVAL before go run "+
				"(want [[ \"$${EVAL:-}\" =~ ^allowlist$$ ]] || { ...; exit 2; }, threat T8)", name)
		case run < 0:
			problems.addf("Makefile: target %s never runs go run ./cmd/rempart-evals", name)
		case check > run:
			problems.addf("Makefile: target %s validates EVAL after go run", name)
		}
	}
}

// checkVerifyTargets: rules 6 to 9.
func checkVerifyTargets(mf parsedMakefile, problems *problemList) {
	next := 0
	for _, l := range mf.Rules["verify-quick"].Recipe {
		if next < len(verifyQuickSteps) && verifyQuickSteps[next].re.MatchString(l) {
			next++
		}
	}
	if next < len(verifyQuickSteps) {
		problems.addf("Makefile: target verify-quick: step %q missing or out of order "+
			"(want go build ./..., golangci-lint run, go test -short ./..., $(MAKE) opa-test, $(MAKE) arch-test)",
			verifyQuickSteps[next].desc)
	}

	reachable := reachableTargets(mf, "verify-quick")
	for _, name := range reachable {
		for _, l := range mf.Rules[name].Recipe {
			if notInVerifyQuick.MatchString(l) {
				problems.addf("Makefile: target %s (reachable from verify-quick): recipe line %q needs Docker, the network or integration tags",
					name, l)
			}
		}
	}

	verify := mf.Rules["verify"]
	if !slices.Contains(verify.Prereqs, "verify-quick") {
		problems.addf("Makefile line %d: target verify must have verify-quick as a prerequisite", verify.Line)
	}
	joined := strings.Join(verify.Recipe, "\n")
	for _, want := range []string{"go test -tags=integration ./...", "go tool govulncheck ./..."} {
		if !strings.Contains(joined, want) {
			problems.addf("Makefile: target verify must run %q", want)
		}
	}
	for _, l := range mf.Lines {
		if strings.Contains(l.Text, "govulncheck") && !strings.Contains(l.Text, "go tool govulncheck") {
			problems.addf("Makefile line %d: govulncheck must run as \"go tool govulncheck\" (version pinned by go.mod): %q", l.Num, l.Text)
		}
	}
}

// reachableTargets returns, sorted, the targets reachable from root through
// prerequisites and through targets named on a recipe line calling make.
func reachableTargets(mf parsedMakefile, root string) []string {
	seen := map[string]bool{root: true}
	queue := []string{root}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		r, ok := mf.Rules[name]
		if !ok {
			continue
		}
		next := slices.Clone(r.Prereqs)
		for _, l := range r.Recipe {
			if makeCallRe.MatchString(l) {
				next = append(next, makeTokenRe.FindAllString(l, -1)...)
			}
		}
		for _, n := range next {
			if _, defined := mf.Rules[n]; defined && !seen[n] {
				seen[n] = true
				queue = append(queue, n)
			}
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// checkOpaTest: rule 10.
func checkOpaTest(mf parsedMakefile, problems *problemList) {
	recipe := strings.Join(mf.Rules["opa-test"].Recipe, "\n")
	if !regoGlobRe.MatchString(recipe) {
		problems.addf("Makefile: target opa-test must look for *.rego files before running OPA")
	}
	if !strings.Contains(recipe, "command -v") {
		problems.addf("Makefile: target opa-test must fail when opa is missing (command -v) instead of skipping silently")
	}
	rego := strings.Index(recipe, ".rego")
	loc := opaTestRe.FindStringIndex(recipe)
	switch {
	case loc == nil:
		problems.addf("Makefile: target opa-test never runs opa test")
	case rego < 0 || rego > loc[0]:
		problems.addf("Makefile: target opa-test runs opa test before looking for .rego files")
	}
	for _, l := range mf.Lines {
		if templateOpaCondRe.MatchString(l.Text) {
			problems.addf("Makefile line %d: template condition [ -d policies ] runs OPA on directories without .rego files: %q", l.Num, l.Text)
		}
	}
}

// targetMakefile is the Makefile of docs/plans/M0-squelette.md section 6.1,
// verbatim (recipe lines start with a tab): the conforming negative control.
const targetMakefile = `# Rempart : vérification et outillage. Issu de Makefile.template (M0-T01).
# Le hook Stop exige ` + "`make verify-quick`" + ` : cette cible ne demande ni réseau ni Docker
# (hors premier téléchargement des modules Go et de la chaîne d'outils).
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := verify-quick

EVAL ?= all
POLICIES_DIR ?= policies
OPA ?= opa

# Variables fournies par l'appelant (menace T8). $(value ...) fige le texte brut : une valeur
# passée en ligne de commande, par exemple SCENARIO='$(shell ...)', n'est jamais développée
# par make. Les recettes les lisent par le shell ("$$VAR"), jamais par make.
override SCENARIO := $(value SCENARIO)
override EVAL := $(value EVAL)
override POLICIES_DIR := $(value POLICIES_DIR)
override OPA := $(value OPA)
export SCENARIO EVAL POLICIES_DIR OPA

.PHONY: verify-quick verify opa-test arch-test evals update-baseline
.PHONY: dev dev-preflight dev-down sandbox-guard sandbox-plan sandbox-apply sandbox-destroy

verify-quick:
	go build ./...
	golangci-lint run ./...
	go test -short ./...
	$(MAKE) --no-print-directory opa-test
	$(MAKE) --no-print-directory arch-test

verify: verify-quick
	go test -tags=integration ./...
	go tool govulncheck ./...

# Étape OPA active seulement s'il existe au moins un fichier .rego sous POLICIES_DIR.
# Dans ce cas, opa absent est une erreur : jamais de saut silencieux.
opa-test:
	@if [ -z "$$(find "$$POLICIES_DIR" -type f -name '*.rego' -print -quit 2>/dev/null)" ]; then \
		echo "opa-test : aucun fichier .rego sous $$POLICIES_DIR, étape OPA sans objet."; \
	elif ! command -v "$$OPA" >/dev/null 2>&1; then \
		echo "opa-test : fichiers .rego présents sous $$POLICIES_DIR mais $$OPA introuvable (voir docs/SETUP.md)." >&2; \
		exit 2; \
	else \
		"$$OPA" check "$$POLICIES_DIR"; \
		"$$OPA" test "$$POLICIES_DIR"; \
	fi

arch-test:
	go test -count=1 ./internal/archtest/...

# Evals : livrées par M0-T23 (cmd/rempart-evals). Avant : code 2, aucune action.
evals:
	@test -d cmd/rempart-evals || { echo "evals : indisponible avant M0-T23 (cmd/rempart-evals absent) ; aucune action." >&2; exit 2; }
	@[[ "$${EVAL:-}" =~ ^[a-z0-9][a-z0-9/_-]{0,126}$$ ]] || { echo "EVAL requis, au format [a-z0-9/_-] (ex. EVAL=demo)." >&2; exit 2; }
	go run ./cmd/rempart-evals --suite "$$EVAL"

# Réservé aux humains (bloqué pour l'agent par le hook guard_bash). Fonctionnel à partir de M0-T23.
update-baseline:
	@test -d cmd/rempart-evals || { echo "update-baseline : indisponible avant M0-T23 (cmd/rempart-evals absent) ; aucune action." >&2; exit 2; }
	@[[ "$${EVAL:-}" =~ ^[a-z0-9][a-z0-9/_-]{0,126}$$ ]] || { echo "EVAL requis, au format [a-z0-9/_-] (ex. EVAL=demo)." >&2; exit 2; }
	go run ./cmd/rempart-evals --suite "$$EVAL" --write-baseline

# Pile de développement : livrée par M0-T03 (docker-compose.yml, dev-preflight en prérequis).
dev:
	@echo "dev : pile de développement livrée par M0-T03 (docker-compose.yml absent) ; aucune action." >&2
	@exit 2

# Vérifie Docker Engine, le plugin compose v2 et l'accès au démon, sans rien démarrer.
dev-preflight:
	@docker compose version >/dev/null 2>&1 || { echo "dev-preflight : Docker Engine et le plugin compose v2 sont requis (voir docs/SETUP.md)." >&2; exit 2; }
	@docker info >/dev/null 2>&1 || { echo "dev-preflight : démon Docker injoignable (voir docs/SETUP.md)." >&2; exit 2; }
	@echo "dev-preflight : Docker et compose v2 disponibles."

# Arrêt idempotent : rien à arrêter tant que M0-T03 n'a pas livré docker-compose.yml.
dev-down:
	@echo "dev-down : aucune pile à arrêter avant M0-T03 (docker-compose.yml absent)."

# Garde des trois cibles de bac à sable (scripts/sandbox.sh arrive en M3).
# Prérequis : s'exécute avant toute validation et toute question interactive.
sandbox-guard:
	@test -e scripts/sandbox.sh || { echo "sandbox : scripts/sandbox.sh absent (livré en M3) ; aucune action." >&2; exit 2; }
	@test -x scripts/sandbox.sh || { echo "sandbox : scripts/sandbox.sh non exécutable ; aucune action." >&2; exit 2; }

sandbox-plan: sandbox-guard
	@[[ "$${SCENARIO:-}" =~ ^[a-z0-9][a-z0-9-]{0,62}$$ ]] || { echo "SCENARIO requis, au format [a-z0-9-] (ex. SCENARIO=demo)." >&2; exit 2; }
	./scripts/sandbox.sh plan "$$SCENARIO"

# Approbation humaine exigée deux fois : permission "ask" de Claude Code ET confirmation
# tapée au terminal (lue sur /dev/tty : un tube sur l'entrée standard ne suffit pas).
sandbox-apply: sandbox-guard
	@[[ "$${SCENARIO:-}" =~ ^[a-z0-9][a-z0-9-]{0,62}$$ ]] || { echo "SCENARIO requis, au format [a-z0-9-] (ex. SCENARIO=demo)." >&2; exit 2; }
	@read -r -p "Appliquer $$SCENARIO sur le compte SANDBOX ? Tape 'oui' : " a </dev/tty; [ "$$a" = "oui" ]
	./scripts/sandbox.sh apply "$$SCENARIO"

sandbox-destroy: sandbox-guard
	@[[ "$${SCENARIO:-}" =~ ^[a-z0-9][a-z0-9-]{0,62}$$ ]] || { echo "SCENARIO requis, au format [a-z0-9-] (ex. SCENARIO=demo)." >&2; exit 2; }
	@read -r -p "Détruire $$SCENARIO sur le compte SANDBOX ? Tape 'oui' : " a </dev/tty; [ "$$a" = "oui" ]
	./scripts/sandbox.sh destroy "$$SCENARIO"
`

// editRule rewrites the rule of target in a synthetic Makefile: edit receives
// the rule line and its recipe lines (tabs included) and returns the lines
// replacing them. A target that is not found exactly once stops the test.
func editRule(t *testing.T, src, target string, edit func(rule string, recipe []string) []string) string {
	t.Helper()
	lines := strings.Split(src, "\n")
	start := -1
	for i, l := range lines {
		if strings.HasPrefix(l, target+":") && !strings.HasPrefix(l, target+":=") {
			if start >= 0 {
				t.Fatalf("rule %q found twice in the synthetic Makefile", target)
			}
			start = i
		}
	}
	if start < 0 {
		t.Fatalf("rule %q not found in the synthetic Makefile", target)
	}
	end := start + 1
	for end < len(lines) && strings.HasPrefix(lines[end], "\t") {
		end++
	}
	replacement := edit(lines[start], slices.Clone(lines[start+1:end]))
	return strings.Join(slices.Concat(lines[:start], replacement, lines[end:]), "\n")
}

func setRecipe(t *testing.T, src, target string, recipe ...string) string {
	t.Helper()
	return editRule(t, src, target, func(rule string, _ []string) []string {
		out := []string{rule}
		for _, r := range recipe {
			out = append(out, "\t"+r)
		}
		return out
	})
}

func setRuleLine(t *testing.T, src, target, rule string) string {
	t.Helper()
	return editRule(t, src, target, func(_ string, recipe []string) []string {
		return append([]string{rule}, recipe...)
	})
}

func removeRule(t *testing.T, src, target string) string {
	t.Helper()
	return editRule(t, src, target, func(string, []string) []string { return nil })
}

func TestMakefileTargets(t *testing.T) {
	t.Run("negative_controls", func(t *testing.T) {
		valid := targetMakefile
		const (
			applyConfirm   = "\t@read -r -p \"Appliquer $$SCENARIO sur le compte SANDBOX ? Tape 'oui' : \" a </dev/tty; [ \"$$a\" = \"oui\" ]\n"
			destroyConfirm = "\t@read -r -p \"Détruire $$SCENARIO sur le compte SANDBOX ? Tape 'oui' : \" a </dev/tty; [ \"$$a\" = \"oui\" ]\n"
			destroyLines   = destroyConfirm + "\t./scripts/sandbox.sh destroy \"$$SCENARIO\"\n"
			guardMessage   = "echo \"sandbox : scripts/sandbox.sh absent (livré en M3) ; aucune action.\" >&2; exit 2; }\n"
			callerExports  = "export SCENARIO EVAL POLICIES_DIR OPA\n"
			evalCheck      = "\t@[[ \"$${EVAL:-}\" =~ ^[a-z0-9][a-z0-9/_-]{0,126}$$ ]] || " +
				"{ echo \"EVAL requis, au format [a-z0-9/_-] (ex. EVAL=demo).\" >&2; exit 2; }"
		)
		// editEvalsRecipe rewrites the recipe lines of target through edit.
		editEvalsRecipe := func(target string, edit func(recipe []string) []string) string {
			return editRule(t, valid, target, func(rule string, recipe []string) []string {
				return append([]string{rule}, edit(recipe)...)
			})
		}
		cases := []struct {
			name    string
			src     string
			wantErr string
			want    []string
		}{
			{name: "valid", src: valid},
			{name: "missing_target", src: removeRule(t, valid, "dev-down"), want: []string{"target dev-down is not defined"}},
			{
				name: "not_phony",
				src:  mustReplace(t, valid, "dev-down sandbox-guard sandbox-plan", "dev-down sandbox-plan"),
				want: []string{"target sandbox-guard is not declared .PHONY"},
			},
			{
				name: "sandbox_apply_without_guard",
				src:  setRuleLine(t, valid, "sandbox-apply", "sandbox-apply:"),
				want: []string{"target sandbox-apply must have sandbox-guard as a prerequisite"},
			},
			{
				name: "guard_without_message",
				src:  mustReplace(t, valid, guardMessage, "exit 2; }\n"),
				want: []string{"target sandbox-guard must report \"scripts/sandbox.sh absent\""},
			},
			{
				name: "guard_exits_zero",
				src:  setRecipe(t, valid, "sandbox-guard", `@test -e scripts/sandbox.sh || { echo "sandbox : scripts/sandbox.sh absent" >&2; exit 0; }`),
				want: []string{"target sandbox-guard must report \"scripts/sandbox.sh absent\" and exit 2"},
			},
			{
				name: "guard_prompts",
				src: editRule(t, valid, "sandbox-guard", func(rule string, recipe []string) []string {
					return append([]string{rule, "\t@read -r -p \"Continuer ? \" a"}, recipe...)
				}),
				want: []string{"target sandbox-guard must not prompt (read)"},
			},
			{
				name: "apply_without_confirmation",
				src:  mustReplace(t, valid, applyConfirm, ""),
				want: []string{"target sandbox-apply has no human confirmation"},
			},
			{
				name: "apply_confirmation_accepts_anything",
				src:  mustReplace(t, valid, applyConfirm, "\t@read -r -p \"Appliquer ? \" a </dev/tty\n"),
				want: []string{"target sandbox-apply has no human confirmation"},
			},
			{
				name: "destroy_confirms_after_script",
				src:  mustReplace(t, valid, destroyLines, "\t./scripts/sandbox.sh destroy \"$$SCENARIO\"\n"+destroyConfirm),
				want: []string{"target sandbox-destroy asks for confirmation after calling scripts/sandbox.sh"},
			},
			{
				name: "confirmation_from_stdin",
				src:  mustReplace(t, valid, applyConfirm, strings.Replace(applyConfirm, " a </dev/tty;", " a;", 1)),
				want: []string{"target sandbox-apply reads the confirmation from standard input"},
			},
			{
				name: "confirmation_tty_on_test_command",
				src: mustReplace(t, valid, destroyConfirm,
					strings.Replace(destroyConfirm, " a </dev/tty; [ \"$$a\" = \"oui\" ]", " a; [ \"$$a\" = \"oui\" ] </dev/tty", 1)),
				want: []string{"target sandbox-destroy reads the confirmation from standard input"},
			},
			{
				name: "confirmation_tty_only_in_prompt_text",
				src: mustReplace(t, valid, applyConfirm,
					"\t@read -r -p \"Appliquer $$SCENARIO </dev/tty ? Tape 'oui' : \" a; [ \"$$a\" = \"oui\" ]\n"),
				want: []string{"target sandbox-apply reads the confirmation from standard input"},
			},
			{
				name: "opa_unconditional",
				src:  setRecipe(t, valid, "opa-test", "opa check policies && opa test policies"),
				want: []string{"target opa-test must look for *.rego files", "target opa-test must fail when opa is missing"},
			},
			{
				name: "opa_test_before_rego_lookup",
				src: setRecipe(t, valid, "opa-test",
					"command -v opa >/dev/null || exit 2", "opa test policies", "find policies -name '*.rego' -print -quit"),
				want: []string{"target opa-test runs opa test before looking for .rego files"},
			},
			{
				name: "template_opa_condition",
				src:  setRecipe(t, valid, "opa-test", "@if [ -d policies ]; then opa check policies && opa test policies; fi"),
				want: []string{"template condition [ -d policies ]"},
			},
			{
				name: "docker_reachable_from_verify_quick",
				src: setRecipe(t,
					editRule(t, valid, "verify-quick", func(rule string, recipe []string) []string {
						return append(append([]string{rule}, recipe...), "\t$(MAKE) --no-print-directory dev")
					}),
					"dev", "docker compose up -d temporal postgres openbao"),
				want: []string{"target dev (reachable from verify-quick)", "docker compose up"},
			},
			{
				name: "docker_reachable_through_prerequisite",
				src:  setRuleLine(t, valid, "verify-quick", "verify-quick: dev-preflight"),
				want: []string{"target dev-preflight (reachable from verify-quick)", "docker info"},
			},
			{
				name: "network_hidden_in_continuation",
				src: setRecipe(t, valid, "arch-test",
					"go test -count=1 ./internal/archtest/... && \\", "\tcurl -fsS https://example.invalid/report"),
				want: []string{"target arch-test (reachable from verify-quick)", "curl -fsS"},
			},
			{
				name: "docker_in_inline_recipe",
				src:  setRuleLine(t, valid, "arch-test", "arch-test: ; docker compose up -d"),
				want: []string{"target arch-test (reachable from verify-quick)", "docker compose up -d"},
			},
			{
				name: "integration_tests_in_verify_quick",
				src:  mustReplace(t, valid, "\tgo test -short ./...\n", "\tgo test -short -tags=integration ./...\n"),
				want: []string{"target verify-quick (reachable from verify-quick)", "-tags=integration"},
			},
			{
				name: "verify_quick_out_of_order",
				src: mustReplace(t, valid, "\tgo build ./...\n\tgolangci-lint run ./...\n",
					"\tgolangci-lint run ./...\n\tgo build ./...\n"),
				want: []string{"target verify-quick: step"},
			},
			{
				name: "verify_quick_without_arch_test",
				src:  mustReplace(t, valid, "\t$(MAKE) --no-print-directory arch-test\n", ""),
				want: []string{`step "$(MAKE) arch-test" missing or out of order`},
			},
			{
				name: "bare_govulncheck",
				src:  mustReplace(t, valid, "\tgo tool govulncheck ./...\n", "\tgovulncheck ./...\n"),
				want: []string{"govulncheck must run as \"go tool govulncheck\"", "target verify must run \"go tool govulncheck ./...\""},
			},
			{
				name: "verify_without_integration",
				src:  mustReplace(t, valid, "\tgo test -tags=integration ./...\n", ""),
				want: []string{"target verify must run \"go test -tags=integration ./...\""},
			},
			{
				name: "verify_without_verify_quick",
				src:  setRuleLine(t, valid, "verify", "verify:"),
				want: []string{"target verify must have verify-quick as a prerequisite"},
			},
			{
				name: "scenario_interpolated",
				src:  mustReplace(t, valid, "./scripts/sandbox.sh plan \"$$SCENARIO\"", "./scripts/sandbox.sh plan $(SCENARIO)"),
				want: []string{"SCENARIO interpolated by make"},
			},
			{
				name: "eval_interpolated_with_braces",
				src:  mustReplace(t, valid, "--suite \"$$EVAL\"\n", "--suite ${EVAL}\n"),
				want: []string{"EVAL interpolated by make"},
			},
			{
				name: "opa_dir_interpolated_by_make",
				src:  mustReplace(t, valid, "\"$$OPA\" check \"$$POLICIES_DIR\"", "\"$$OPA\" check '$(POLICIES_DIR)'"),
				want: []string{"POLICIES_DIR interpolated by make"},
			},
			{
				name: "opa_binary_interpolated_by_make",
				src:  mustReplace(t, valid, "command -v \"$$OPA\"", "command -v '$(OPA)'"),
				want: []string{"OPA interpolated by make"},
			},
			{
				name: "opa_env_test_before_rego_lookup",
				src: setRecipe(t, valid, "opa-test",
					`command -v "$$OPA" >/dev/null || exit 2`, `"$$OPA" test "$$POLICIES_DIR"`,
					`find "$$POLICIES_DIR" -name '*.rego' -print -quit`),
				want: []string{"target opa-test runs opa test before looking for .rego files"},
			},
			{
				name: "caller_variable_not_frozen",
				src:  mustReplace(t, valid, "override EVAL := $(value EVAL)\n", ""),
				want: []string{"caller variable EVAL is not frozen"},
			},
			{
				name: "override_only_in_comment",
				src:  mustReplace(t, valid, "override OPA := $(value OPA)\n", "# override OPA := $(value OPA)\n"),
				want: []string{"caller variable OPA is not frozen"},
			},
			{
				name: "override_expands_caller_value",
				src:  mustReplace(t, valid, "override SCENARIO := $(value SCENARIO)\n", "override SCENARIO := $(SCENARIO)\n"),
				want: []string{"caller variable SCENARIO is not frozen", "SCENARIO interpolated by make"},
			},
			{
				name: "override_after_export",
				src:  mustReplace(t, valid, "EVAL ?= all\n", "EVAL ?= all\nexport EVAL\n"),
				want: []string{"caller variable EVAL is exported before \"override EVAL := $(value EVAL)\""},
			},
			{
				name: "bare_export_before_override",
				src:  mustReplace(t, valid, "EVAL ?= all\n", "export\nEVAL ?= all\n"),
				want: []string{"caller variable SCENARIO is exported before", "caller variable OPA is exported before"},
			},
			{
				name: "caller_variable_not_exported",
				src:  mustReplace(t, valid, callerExports, "export SCENARIO EVAL POLICIES_DIR\n"),
				want: []string{"caller variable OPA is not exported"},
			},
			{
				name: "caller_variable_exported_only_in_recipe",
				src: editRule(t, mustReplace(t, valid, callerExports, "export SCENARIO EVAL OPA\n"), "arch-test",
					func(rule string, recipe []string) []string {
						return append([]string{rule, "\texport POLICIES_DIR"}, recipe...)
					}),
				want: []string{"caller variable POLICIES_DIR is not exported"},
			},
			{
				name: "eval_not_validated",
				src: editEvalsRecipe("evals", func(recipe []string) []string {
					return slices.DeleteFunc(recipe, func(l string) bool { return strings.Contains(l, "=~") })
				}),
				want: []string{"target evals does not validate EVAL before go run"},
			},
			{
				name: "eval_validation_before_guard",
				src: editEvalsRecipe("evals", func(recipe []string) []string {
					if len(recipe) < 2 || recipe[1] != evalCheck {
						t.Fatalf("evals recipe = %q, want the guard then the EVAL check", recipe)
					}
					recipe[0], recipe[1] = recipe[1], recipe[0]
					return recipe
				}),
				want: []string{"target evals: the first recipe line must be the guard"},
			},
			{
				name: "eval_validated_after_go_run",
				src: editEvalsRecipe("update-baseline", func(recipe []string) []string {
					if len(recipe) != 3 || recipe[1] != evalCheck {
						t.Fatalf("update-baseline recipe = %q, want the guard, the EVAL check, go run", recipe)
					}
					return []string{recipe[0], recipe[2], recipe[1]}
				}),
				want: []string{"target update-baseline validates EVAL after go run"},
			},
			{
				name: "eval_validation_unanchored",
				src: editEvalsRecipe("evals", func(recipe []string) []string {
					for i, l := range recipe {
						recipe[i] = strings.Replace(l, "=~ ^[a-z0-9][a-z0-9/_-]{0,126}$$ ]]", "=~ [a-z0-9/_-]+ ]]", 1)
					}
					return recipe
				}),
				want: []string{"target evals does not validate EVAL before go run"},
			},
			{
				name: "eval_validation_failure_ignored",
				src: editEvalsRecipe("update-baseline", func(recipe []string) []string {
					for i, l := range recipe {
						if l == evalCheck {
							recipe[i] = "\t@[[ \"$${EVAL:-}\" =~ ^[a-z0-9][a-z0-9/_-]{0,126}$$ ]] || echo \"EVAL invalide\" >&2"
						}
					}
					return recipe
				}),
				want: []string{"target update-baseline does not validate EVAL before go run"},
			},
			{
				name: "update_baseline_without_flag",
				src:  setRecipe(t, valid, "update-baseline", `go run ./cmd/rempart-evals --suite "$$EVAL"`),
				want: []string{"target update-baseline must pass --write-baseline"},
			},
			{
				name: "arch_test_wrong_package",
				src:  setRecipe(t, valid, "arch-test", "go test -count=1 ./..."),
				want: []string{"target arch-test must test ./internal/archtest/..."},
			},
			{
				name:    "duplicate_rule",
				src:     valid + "\ndev-down:\n\t@echo \"second recipe\"\n",
				wantErr: `second recipe for target "dev-down"`,
			},
			{
				name:    "unsupported_conditional",
				src:     mustReplace(t, valid, "OPA ?= opa\n", "OPA ?= opa\nifeq ($(CI),true)\nEVAL := changed\nendif\n"),
				wantErr: `unsupported directive "ifeq ($(CI),true)"`,
			},
			{
				name:    "recipe_outside_rule",
				src:     "\tdocker compose up -d\n" + valid,
				wantErr: "line 1: recipe line outside a rule",
			},
			{
				name:    "double_colon_rule",
				src:     valid + "\ndev-down::\n\t@echo \"again\"\n",
				wantErr: "double-colon rule",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				mf, err := parseMakefile(tc.src)
				if tc.wantErr != "" {
					expectError(t, err, tc.wantErr)
					return
				}
				if err != nil {
					t.Fatalf("parseMakefile: %v", err)
				}
				expectProblems(t, checkMakefile(mf), tc.want)
			})
		}

		t.Run("valid_parse_structure", func(t *testing.T) {
			mf, err := parseMakefile(valid)
			if err != nil {
				t.Fatalf("parseMakefile: %v", err)
			}
			if got, want := mf.Rules["verify-quick"].Line, slices.Index(strings.Split(valid, "\n"), "verify-quick:")+1; got != want {
				t.Errorf("verify-quick rule line = %d, want %d", got, want)
			}
			opa := mf.Rules["opa-test"].Recipe
			if len(opa) != 1 || !strings.HasPrefix(opa[0], "if [ -z ") || !strings.HasSuffix(opa[0], "fi") {
				t.Errorf("opa-test recipe = %q, want one logical line (continuations joined, @ removed)", opa)
			}
			if got := mf.Rules["sandbox-apply"].Prereqs; !slices.Equal(got, []string{"sandbox-guard"}) {
				t.Errorf("sandbox-apply prerequisites = %q, want [sandbox-guard]", got)
			}
			if got := len(mf.Phony); got != len(requiredMakeTargets()) {
				t.Errorf("%d phony targets, want %d", got, len(requiredMakeTargets()))
			}
			if got := reachableTargets(mf, "verify-quick"); !slices.Equal(got, []string{"arch-test", "opa-test", "verify-quick"}) {
				t.Errorf("targets reachable from verify-quick = %q, want [arch-test opa-test verify-quick]", got)
			}
		})
	})

	t.Run("repository", func(t *testing.T) {
		_, fsys := repoRoot(t)
		src, err := readRepoFile(fsys, "Makefile", "created by M0-T01")
		if err != nil {
			t.Fatal(err)
		}
		mf, err := parseMakefile(src)
		if err != nil {
			t.Fatalf("Makefile: %v", err)
		}
		reportProblems(t, checkMakefile(mf))
	})
}
