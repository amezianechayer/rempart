package archtest

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// makeRule is a parsed Makefile rule.
type makeRule struct {
	Prereqs    []string
	Recipe     []string // logical lines, continuations joined, @ - + prefixes removed
	Line       int      // line of the rule naming the target (a single one, D8)
	RecipeLine int      // V2: first physical line of the first recipe line (empty ones included), 0 if none
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
	Lines []makeLine     // every logical line, comments included, for whole-file rules
	Vars  map[string]int // V2: variable name -> line of its last assignment (D8 step 3), for the oracle
	// V3, D16: line of the rule "Makefile: ;", 0 if absent. Not in Rules: it is
	// no target of the checks, only the barrier against remaking the Makefile.
	SelfRule int
}

// Grammar of parseMakefile: the closed subset of GNU make of
// docs/plans/M0-make-subcalls.md D8 (M0-T04b V1, threat T32). Whatever it does
// not recognize is an error, never ignored:
//  1. lexMakefile (V2, D11 to D14) does not imitate make, it refuses every form
//     on which its split and the one of make could disagree: control bytes (CR
//     included), an even number of trailing backslashes, a continuation outside
//     a recipe line or open at the end of the file, non-ASCII text outside a
//     column-0 comment and a recipe line, invisible, bidirectional or Unicode
//     blank characters; only a recipe line ending with an odd number of
//     backslashes is joined with the next physical line (one space, leading
//     blanks of the next line removed); blanks are spaces and tabs only;
//  2. a line starting with a tab is a recipe line of the current rule (@ - +
//     prefixes removed); outside a rule, or after a .PHONY line, it is an error;
//     a blank line or a make comment does not end the recipe;
//  3. a blank line, or a line whose text starts with "#", is a make comment;
//  4. any other line holding "#" is an error (E1): no trailing comment;
//  5. ifeq, ifneq, ifdef, ifndef, else, endif, define, endef are errors (E2);
//  6. an assignment ([override|export] NAME op value) must name a variable of
//     makeVariables (E3) and be one of its allowed whole-line forms (E4);
//  7. "export" must list names of makeExportable (E5);
//  8. ".PHONY:" lists targets of the form [a-z][a-z0-9-]*;
//  9. a rule is one target of that form, ":", then zero or more prerequisites
//     of that form separated by one space; a target named by two rule lines is
//     an error (E7);
//  10. V3, D16: the physical line "Makefile: ;", exactly, at most once (a
//     second one is E7), sets SelfRule; any other rule line naming Makefile is
//     an error (E15); a recipe line after it is E8;
//  11. any other line is an error (E6): include, -include, sinclude, vpath,
//     unexport, special targets, inline recipes, target-specific variables,
//     double-colon and pattern rules, expansions outside recipes.
var (
	makeUnsupportedRe = regexp.MustCompile(`^(ifeq|ifneq|ifdef|ifndef|else|endif|define|endef)(\s|\(|$)`)
	// Any assignment shape, recognized to be refused unless allowed (D8 step 3).
	makeAssignShapeRe = regexp.MustCompile(`^(?:(?:override|export)\s+)?([^\s:#=!?+]+)\s*(?::{1,3}=|[?+!]?=)`)
	makeExportWordRe  = regexp.MustCompile(`^export(\s|$)`)
	makeExportRe      = regexp.MustCompile(`^export((?: [A-Z_]+)+)$`)
	makePhonyRe       = regexp.MustCompile(`^\.PHONY:((?: [a-z][a-z0-9-]*)+)$`)
	makeRuleRe        = regexp.MustCompile(`^([a-z][a-z0-9-]*):((?: [a-z][a-z0-9-]*)*)$`)
	// V3, D16: any rule line naming the Makefile as its target, to be refused
	// unless it is exactly makeSelfRule.
	makeSelfRuleShapeRe = regexp.MustCompile(`^Makefile\s*:`)
)

// makeSelfRule is the only rule naming the Makefile (V3, D16): an explicit rule
// with neither prerequisite nor recipe, so GNU make never looks for a built-in
// implicit rule remaking the Makefile (Makefile.sh, RCS, SCCS; threat T32).
const makeSelfRule = "Makefile: ;"

// makeVariables: the only variables the Makefile may assign (D8 step 3).
func makeVariables() []string {
	return []string{"SHELL", ".SHELLFLAGS", ".DEFAULT_GOAL", "EVAL", "EVAL_BASE", "POLICIES_DIR", "OPA", "SCENARIO", "GOWORK", "GOFLAGS"}
}

// makeExportable: the only names "export" may list (D8 step 4).
func makeExportable() []string {
	return []string{"SCENARIO", "EVAL", "EVAL_BASE", "POLICIES_DIR", "OPA", "GOWORK", "GOFLAGS"}
}

// makeAssignForms: whole-line forms allowed for the variables of makeVariables,
// besides "override NAME := $(value NAME)" for callerVariables() (overrideValueRe,
// both names equal). Values are frozen where a value without "$" would divert
// the execution (SHELL, .SHELLFLAGS, GOWORK, GOFLAGS).
var makeAssignForms = []*regexp.Regexp{
	regexp.MustCompile(`^SHELL := /bin/bash$`),
	regexp.MustCompile(`^\.SHELLFLAGS := -eu -o pipefail -c$`),
	regexp.MustCompile(`^\.DEFAULT_GOAL := verify-quick$`),
	regexp.MustCompile(`^(EVAL|POLICIES_DIR|OPA) \?= [A-Za-z0-9._/-]+$`),
	regexp.MustCompile(`^export GOWORK := off$`),
	regexp.MustCompile(`^override GOFLAGS := -mod=readonly$`),
}

// parseMakefile lexes src with lexMakefile (D11 to D14), then parses the closed
// grammar of docs/plans/M0-make-subcalls.md D8. Errors start with "line <n>: ",
// n being the first physical line of the refused logical line (E1 to E8) or
// the physical line at fault (lexer, E9 to E14).
func parseMakefile(src string) (parsedMakefile, error) {
	lines, err := lexMakefile(src)
	if err != nil {
		return parsedMakefile{Rules: map[string]makeRule{}, Phony: map[string]bool{}, Vars: map[string]int{}}, err
	}
	p := makeParser{
		mf: parsedMakefile{Rules: map[string]makeRule{}, Phony: map[string]bool{}, Vars: map[string]int{}, Lines: lines},
	}
	for _, ln := range p.mf.Lines {
		if err := p.parseLine(ln); err != nil {
			return p.mf, err
		}
	}
	return p.mf, nil
}

// lexMakefile splits src into logical lines (M0-T04b V2, D11 to D13). A
// physical line joins the next one only if it belongs to a recipe line and
// ends with an odd number of backslashes; every form on which this lexer and
// GNU make could disagree is an error naming the physical line at fault.
// Checks, in this order, for each physical line: E9 (control byte), E10 (even
// number of trailing backslashes), E11 (a line starting a non-recipe logical
// line ends with a backslash), E12 or E13 (non-ASCII text); then E14 if a
// continuation is still open at the end of src. A logical line is a recipe
// line if its first physical line starts with a tab, a column-0 comment if its
// first physical line starts with "#". Joining keeps the V1 text: the final
// backslash and the spaces before it removed, one space, the next physical
// line with leading spaces and tabs removed.
func lexMakefile(src string) ([]makeLine, error) {
	physical := strings.Split(src, "\n")
	if strings.HasSuffix(src, "\n") {
		physical = physical[:len(physical)-1] // the final newline ends the last line, it opens none
	}
	var lines []makeLine
	pending, recipe := false, false
	for i, raw := range physical {
		num := i + 1
		if !pending {
			recipe = strings.HasPrefix(raw, "\t")
		}
		comment := !pending && strings.HasPrefix(raw, "#")
		if err := lexPhysicalLine(raw, num, recipe, comment); err != nil {
			return nil, err
		}
		if pending {
			lines[len(lines)-1].Text += " " + strings.TrimLeft(raw, " \t")
		} else {
			lines = append(lines, makeLine{Num: num, Text: raw})
		}
		last := &lines[len(lines)-1]
		pending = trailingBackslashes(raw)%2 == 1
		if pending {
			last.Text = strings.TrimRight(strings.TrimSuffix(last.Text, `\`), " ")
		}
	}
	if pending {
		return nil, fmt.Errorf("line %d: continuation at end of file (D11)", len(physical))
	}
	return lines, nil
}

// lexPhysicalLine applies E9 to E13 to the physical line raw, number num, part
// of a recipe line or first line of a column-0 comment.
func lexPhysicalLine(raw string, num int, recipe, comment bool) error {
	for i := range len(raw) {
		if b := raw[i]; (b < 0x20 && b != '\t') || b == 0x7f {
			return fmt.Errorf("line %d: control byte 0x%02x not allowed (D13): %q", num, b, raw)
		}
	}
	n := trailingBackslashes(raw)
	switch {
	case n > 0 && n%2 == 0:
		return fmt.Errorf("line %d: line ends with an even number of backslashes (D11): %q", num, raw)
	case n > 0 && !recipe:
		return fmt.Errorf("line %d: continuation outside a recipe line not allowed (D12): %q", num, raw)
	}
	ascii := true
	for i := range len(raw) {
		if raw[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return nil
	}
	if !recipe && !comment {
		return fmt.Errorf("line %d: non-ASCII byte outside a column-0 comment or a recipe line (D13): %q", num, raw)
	}
	for _, r := range raw {
		if r >= utf8.RuneSelf && !allowedMakeRune(r) {
			return fmt.Errorf("line %d: character %U not allowed in a comment or recipe line (D13): %q", num, r, raw)
		}
	}
	return nil
}

// trailingBackslashes counts the backslashes ending s.
func trailingBackslashes(s string) int {
	return len(s) - len(strings.TrimRight(s, `\`))
}

// allowedMakeRune reports whether a non-ASCII rune may appear in a column-0
// comment or a recipe line (D13 (iv)): categories L, M, N, P, S, U+FFFD
// excluded (it also stands for invalid UTF-8). Spaces, separators, C1 controls
// and format characters (invisible or bidirectional) are refused.
func allowedMakeRune(r rune) bool {
	return r != utf8.RuneError && unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S)
}

// makeTrim removes leading and trailing spaces and tabs only (D14): GNU make
// does not treat NBSP, NEL or U+2028 as blanks.
func makeTrim(s string) string { return strings.Trim(s, " \t") }

// isMakeComment reports whether l is a make comment (D3): its text does not
// start with a tab and, makeTrim applied, starts with "#". It is the only
// predicate classifying a line of parsedMakefile.Lines as a comment.
func isMakeComment(l makeLine) bool {
	return !strings.HasPrefix(l.Text, "\t") && strings.HasPrefix(makeTrim(l.Text), "#")
}

type makeParser struct {
	mf      parsedMakefile
	current string // target of the rule whose recipe is being read, "" if none
}

func (p *makeParser) parseLine(ln makeLine) error {
	if strings.HasPrefix(ln.Text, "\t") {
		if p.current == "" {
			return fmt.Errorf("line %d: recipe line outside a rule", ln.Num)
		}
		p.addRecipe(ln.Text[1:], ln.Num)
		return nil
	}
	text := makeTrim(ln.Text)
	if text == "" || isMakeComment(ln) {
		return nil
	}
	p.current = ""
	switch {
	case strings.Contains(text, "#"):
		return fmt.Errorf("line %d: comment after make syntax not allowed (D8): %q", ln.Num, text)
	case makeUnsupportedRe.MatchString(text):
		return fmt.Errorf("line %d: unsupported directive %q: update the test parser before using it", ln.Num, text)
	}
	if m := makeAssignShapeRe.FindStringSubmatch(text); m != nil {
		if err := checkMakeAssignment(text, m[1], ln.Num); err != nil {
			return err
		}
		p.mf.Vars[m[1]] = ln.Num
		return nil
	}
	if makeExportWordRe.MatchString(text) {
		return checkMakeExport(text, ln.Num)
	}
	if m := makePhonyRe.FindStringSubmatch(text); m != nil {
		for _, name := range strings.Fields(m[1]) {
			p.mf.Phony[name] = true
		}
		return nil
	}
	if makeSelfRuleShapeRe.MatchString(text) {
		return p.parseSelfRule(ln)
	}
	m := makeRuleRe.FindStringSubmatch(text)
	if m == nil {
		return fmt.Errorf("line %d: line outside the Makefile grammar of the tests (D8): %q", ln.Num, text)
	}
	target := m[1]
	if r, seen := p.mf.Rules[target]; seen {
		return fmt.Errorf("line %d: target %q already named by the rule of line %d (D8)", ln.Num, target, r.Line)
	}
	p.mf.Rules[target] = makeRule{Prereqs: strings.Fields(m[2]), Line: ln.Num}
	p.current = target
	return nil
}

// parseSelfRule: D8 step 10 (V3, D16). The whole line, blanks included, must
// be makeSelfRule; p.current stays "" so a recipe line after it is refused.
func (p *makeParser) parseSelfRule(ln makeLine) error {
	if ln.Text != makeSelfRule {
		return fmt.Errorf("line %d: rule naming Makefile must be exactly %q (D16): %q", ln.Num, makeSelfRule, ln.Text)
	}
	if p.mf.SelfRule != 0 {
		return fmt.Errorf("line %d: target %q already named by the rule of line %d (D8)", ln.Num, "Makefile", p.mf.SelfRule)
	}
	p.mf.SelfRule = ln.Num
	return nil
}

// checkMakeAssignment: D8 step 3, name being the assigned variable.
func checkMakeAssignment(text, name string, num int) error {
	if !slices.Contains(makeVariables(), name) {
		return fmt.Errorf("line %d: variable %q not allowed in the Makefile (D8)", num, name)
	}
	if m := overrideValueRe.FindStringSubmatch(text); m != nil && m[1] == m[2] && slices.Contains(callerVariables(), m[1]) {
		return nil
	}
	for _, re := range makeAssignForms {
		if re.MatchString(text) {
			return nil
		}
	}
	return fmt.Errorf("line %d: form not allowed for variable %s (D8): %q", num, name, text)
}

// checkMakeExport: D8 step 4. A bare "export" exports every variable.
func checkMakeExport(text string, num int) error {
	m := makeExportRe.FindStringSubmatch(text)
	if m == nil {
		return fmt.Errorf("line %d: export not allowed (D8): %q", num, text)
	}
	for _, name := range strings.Fields(m[1]) {
		if !slices.Contains(makeExportable(), name) {
			return fmt.Errorf("line %d: export not allowed (D8): %q", num, text)
		}
	}
	return nil
}

// addRecipe adds the recipe line text (tab removed), first physical line num,
// to the current rule. An empty recipe line is a recipe for make: it sets
// RecipeLine, it adds nothing to Recipe.
func (p *makeParser) addRecipe(text string, num int) {
	r := p.mf.Rules[p.current]
	if r.RecipeLine == 0 {
		r.RecipeLine = num
	}
	if cmd := makeTrim(strings.TrimLeft(text, "@-+ \t")); cmd != "" {
		r.Recipe = append(r.Recipe, cmd)
	}
	p.mf.Rules[p.current] = r
}

// checkMakefileSelfRule (M0-T04b V3, D16, T32): the Makefile holds the rule
// "Makefile: ;" (parseMakefile admits it once, in that form only).
func checkMakefileSelfRule(mf parsedMakefile) []string {
	var problems problemList
	if mf.SelfRule == 0 {
		problems.addf("Makefile: rule %q missing: GNU make would remake the Makefile from Makefile.sh, Makefile,v, RCS/ or SCCS/ "+
			"by a built-in implicit rule, before any recipe and even under -n (D16, T32)", makeSelfRule)
	}
	return problems
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
		{subMakePrefix + "opa-test", regexp.MustCompile(`^` + regexp.QuoteMeta(subMakePrefix+"opa-test") + `$`)},
		{subMakePrefix + "arch-test", regexp.MustCompile(`^` + regexp.QuoteMeta(subMakePrefix+"arch-test") + `$`)},
	}
)

// T32, obligation (bp): GNU make does not pass -f to sub-makes through MAKEFLAGS.
const subMakePrefix = "$(MAKE) -f Makefile --no-print-directory "

var (
	subMakeRefRe       = regexp.MustCompile(`\bMAKE\b|\bg?make\b|\bMAKEFILES\b`)
	canonicalSubMakeRe = regexp.MustCompile(`^\t@?\$\(MAKE\) -f Makefile --no-print-directory ([a-z][a-z0-9-]*)( >&2)?$`)
)

// expandsMake reports whether make expands something in a recipe line (D7):
// a "$" left once the "$$" pairs are removed, left to right.
func expandsMake(recipeLine string) bool {
	return strings.Contains(strings.ReplaceAll(recipeLine, "$$", ""), "$")
}

// checkSubMakeCalls reports every non-comment logical line of the Makefile that
// mentions make (D2) or, for a recipe line, expands make syntax (D7), and is
// not exactly a canonical sub-make recipe line naming a defined target (D1,
// D3, D5, D9). At most one problem per line. See docs/plans/M0-make-subcalls.md.
func checkSubMakeCalls(mf parsedMakefile) []string {
	var problems problemList
	for _, l := range mf.Lines {
		recipe := strings.HasPrefix(l.Text, "\t")
		if isMakeComment(l) {
			continue // make comment (D3); a recipe line starting with # is shell text
		}
		if m := canonicalSubMakeRe.FindStringSubmatch(l.Text); m != nil {
			if _, ok := mf.Rules[m[1]]; !ok {
				problems.addf("Makefile line %d: sub-make target %q is not defined", l.Num, m[1])
			}
			continue
		}
		switch {
		case subMakeRefRe.MatchString(l.Text):
			problems.addf("Makefile line %d: sub-make must be exactly \"$(MAKE) -f Makefile --no-print-directory <target>\" "+
				"on its own recipe line (T32): %q", l.Num, l.Text)
		case recipe && expandsMake(l.Text):
			problems.addf("Makefile line %d: recipe line expands make syntax outside the canonical sub-make (D7, T32): %q", l.Num, l.Text)
		}
	}
	return problems
}

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
// the recipes from the environment (threat T8). EVAL_BASE (M0-T23): the base
// commit of the targeted evals of make verify, read by the shell, never by make.
func callerVariables() []string {
	return []string{"SCENARIO", "EVAL", "EVAL_BASE", "POLICIES_DIR", "OPA"}
}

// checkCallerVariables: rule 13 (R1-a). Each caller variable is frozen by
// "override X := $(value X)" (make never expands the raw text given on the
// command line) before any export line naming it, and it is exported. A bare
// "export" exports every variable, so it names each of them.
func checkCallerVariables(mf parsedMakefile, problems *problemList) {
	frozen := map[string]int{}   // variable -> line of its first override := $(value ...)
	exported := map[string]int{} // variable -> line of its first export
	for _, l := range mf.Lines {
		if strings.HasPrefix(l.Text, "\t") || isMakeComment(l) {
			continue // recipe line (shell, not make) or make comment
		}
		text := makeTrim(l.Text)
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
			"(want go build ./..., golangci-lint run, go test -short ./..., %sopa-test, %sarch-test)",
			verifyQuickSteps[next].desc, subMakePrefix, subMakePrefix)
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
	// M0-T03b (D4): the integration tests of the whole module may run as the
	// two passes of TestMakeDevUsesWait, the first one listing the packages.
	if !strings.Contains(joined, "go test -tags=integration ./...") && !strings.Contains(joined, "go test -tags=integration $$(go list ./...") {
		problems.addf("Makefile: target verify must run %q", "go test -tags=integration ./...")
	}
	if !strings.Contains(joined, "go tool govulncheck ./...") {
		problems.addf("Makefile: target verify must run %q", "go tool govulncheck ./...")
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

// selfRuleComment precedes the line "Makefile: ;" (D16) in targetMakefile and
// in the reference Makefile of M0-T04b V3: three column-0 make comments.
const selfRuleComment = `# Menace T32 : sans règle explicite pour lui, GNU make referait le Makefile par une règle
# implicite intégrée (Makefile.sh, Makefile,v, RCS/, SCCS/) avant toute recette, même sous -n.
# Cette règle sans prérequis ni recette l'en empêche (M0-make-subcalls D16).`

// targetMakefile is the Makefile of docs/plans/M0-squelette.md section 6.1,
// amended by docs/plans/M0-make-subcalls.md (sub-makes in the canonical form
// "$(MAKE) -f Makefile --no-print-directory <target>", V3 D16: the rule
// "Makefile: ;" after the .PHONY lines), recipe lines starting with a tab: the
// conforming negative control.
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
override EVAL_BASE := $(value EVAL_BASE)
override POLICIES_DIR := $(value POLICIES_DIR)
override OPA := $(value OPA)
export SCENARIO EVAL EVAL_BASE POLICIES_DIR OPA

.PHONY: verify-quick verify opa-test arch-test evals update-baseline
.PHONY: dev dev-preflight dev-down sandbox-guard sandbox-plan sandbox-apply sandbox-destroy

` + selfRuleComment + `
Makefile: ;

verify-quick:
	go build ./...
	golangci-lint run ./...
	go test -short ./...
	$(MAKE) -f Makefile --no-print-directory opa-test
	$(MAKE) -f Makefile --no-print-directory arch-test

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
			callerExports  = "export SCENARIO EVAL EVAL_BASE POLICIES_DIR OPA\n"
			evalCheck      = "\t@[[ \"$${EVAL:-}\" =~ ^[a-z0-9][a-z0-9/_-]{0,126}$$ ]] || " +
				"{ echo \"EVAL requis, au format [a-z0-9/_-] (ex. EVAL=demo).\" >&2; exit 2; }"
		)
		// editEvalsRecipe rewrites the recipe lines of target through edit.
		editEvalsRecipe := func(target string, edit func(recipe []string) []string) string {
			return editRule(t, valid, target, func(rule string, recipe []string) []string {
				return append([]string{rule}, edit(recipe)...)
			})
		}
		// Mutations refused by the grammar of parseMakefile (M0-make-subcalls D8).
		inlineDocker := setRuleLine(t, valid, "arch-test", "arch-test: ; docker compose up -d")
		overrideExpands := mustReplace(t, valid, "override SCENARIO := $(value SCENARIO)\n", "override SCENARIO := $(SCENARIO)\n")
		bareExport := mustReplace(t, valid, "EVAL ?= all\n", "export\nEVAL ?= all\n")
		duplicate := valid + "\ndev-down:\n\t@echo \"second recipe\"\n"
		duplicateLines := exactLines(duplicate, "dev-down:")
		if len(duplicateLines) != 2 {
			t.Fatalf("duplicate_rule: rule line dev-down: found on lines %d, want 2 lines", duplicateLines)
		}
		doubleColon := valid + "\ndev-down::\n\t@echo \"again\"\n"
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
						return append(append([]string{rule}, recipe...), "\t"+subMakePrefix+"dev")
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
				// M0-make-subcalls D8: an inline recipe is outside the grammar.
				name:    "docker_in_inline_recipe",
				src:     inlineDocker,
				wantErr: fmt.Sprintf("line %d: %s", physicalLine(t, inlineDocker, "arch-test: ;"), errOutsideGrammar),
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
				src:  mustReplace(t, valid, "\t"+subMakePrefix+"arch-test\n", ""),
				want: []string{`step "` + subMakePrefix + `arch-test" missing or out of order`},
			},
			{
				// M0-make-subcalls: the pre-T32 form, without -f Makefile, is not the step.
				name: "verify_quick_sub_make_without_file",
				src:  mustReplace(t, valid, "\t"+subMakePrefix+"opa-test\n", "\t$(MAKE) --no-print-directory opa-test\n"),
				want: []string{`step "` + subMakePrefix + `opa-test" missing or out of order`},
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
				// M0-make-subcalls D8: the only override of SCENARIO is $(value SCENARIO).
				name: "override_expands_caller_value",
				src:  overrideExpands,
				wantErr: fmt.Sprintf("line %d: %s", physicalLine(t, overrideExpands, "override SCENARIO := $(SCENARIO)"),
					errFormNotAllowed("SCENARIO")),
			},
			{
				name: "override_after_export",
				src:  mustReplace(t, valid, "EVAL ?= all\n", "EVAL ?= all\nexport EVAL\n"),
				want: []string{"caller variable EVAL is exported before \"override EVAL := $(value EVAL)\""},
			},
			{
				// M0-make-subcalls D8: a bare export (every variable) is refused.
				name:    "bare_export_before_override",
				src:     bareExport,
				wantErr: fmt.Sprintf("line %d: %s", exactLine(t, bareExport, "export"), errExportNotAllowed),
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
				// M0-make-subcalls D8: a second rule line naming a target (E7).
				name:    "duplicate_rule",
				src:     duplicate,
				wantErr: errAlreadyNamed(duplicateLines[1], "dev-down", duplicateLines[0]),
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
				// M0-make-subcalls D8: a double-colon rule is outside the grammar.
				name:    "double_colon_rule",
				src:     doubleColon,
				wantErr: fmt.Sprintf("line %d: %s", physicalLine(t, doubleColon, "dev-down::"), errOutsideGrammar),
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

// TestMakefileGoflagsNeutralized (ax, D15, threat T74): a GOFLAGS taken from
// the environment (-mod=mod, -overlay, -modfile, -tags) would let go build and
// go test compile other sources than the ones the rules read. The Makefile
// overrides it with -mod=readonly and exports it, each by exactly one line,
// override first; no other line, recipe included, names GOFLAGS.
func TestMakefileGoflagsNeutralized(t *testing.T) {
	_, fsys := repoRoot(t)
	src, err := readRepoFile(fsys, "Makefile", "created by M0-T01")
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, l := range strings.Split(src, "\n") {
		if strings.Contains(l, "GOFLAGS") {
			lines = append(lines, l)
		}
	}
	want := []string{"override GOFLAGS := -mod=readonly", "export GOFLAGS"}
	if !slices.Equal(lines, want) {
		t.Errorf("Makefile lines naming GOFLAGS: %q, want exactly %q in this order", lines, want)
	}
}

// demoRunFlags are the flags of go run in the demo recipe (docs/plans/M0-worker-demo.md
// section 4.4): the fake model behind -dev, the fixed demo tenant, the literal
// loopback address, the script under testdata.
func demoRunFlags() []string {
	return []string{
		"-dev", "-demo-once", "-llm=fake", "-tenant=0d3e0000-0000-4000-8000-000000000001",
		"-temporal-address=127.0.0.1:7233", "-namespace=rempart",
		"-fake-script=internal/loops/demo/testdata/scripts/converge.json",
	}
}

// demoRecipeLines returns the logical recipe lines of the rule "demo:", tabs
// and prefixes kept.
func demoRecipeLines(mf parsedMakefile) []string {
	var out []string
	in := false
	for _, l := range mf.Lines {
		switch {
		case strings.HasPrefix(l.Text, "\t"):
			if in {
				out = append(out, l.Text)
			}
		case makeTrim(l.Text) == "" || isMakeComment(l):
		default:
			in = strings.HasPrefix(l.Text, "demo:")
		}
	}
	return out
}

// checkDemoTarget: make demo writes exactly one JSON document on stdout (dev
// on stderr, recipe lines silenced by @), runs the worker with exactly the
// flags of section 4.4, and make interpolates nothing but $(MAKE) (T8).
func checkDemoTarget(mf parsedMakefile) []string {
	var problems problemList
	r, ok := mf.Rules["demo"]
	if !ok {
		problems.addf("Makefile: target demo is not defined")
		return problems
	}
	if !mf.Phony["demo"] {
		problems.addf("Makefile: target demo is not declared .PHONY")
	}
	if len(r.Prereqs) != 0 {
		problems.addf("Makefile line %d: target demo has prerequisites %q: dev runs in the recipe, its stdout sent to stderr", r.Line, r.Prereqs)
	}
	for _, l := range demoRecipeLines(mf) {
		if !strings.HasPrefix(l, "\t@") {
			problems.addf("Makefile: demo recipe line %q is not silenced by @ (make would echo it on stdout)", l)
		}
		if strings.Contains(strings.ReplaceAll(l, "$(MAKE)", ""), "$(") || strings.Contains(l, "${") {
			problems.addf("Makefile: demo recipe line %q interpolates a make variable other than $(MAKE)", l)
		}
	}
	if len(r.Recipe) != 2 {
		problems.addf("Makefile: demo recipe has %d lines, want 2 (dev, then go run)", len(r.Recipe))
		return problems
	}
	if want := subMakePrefix + "dev >&2"; r.Recipe[0] != want {
		problems.addf("Makefile: first demo recipe line %q, want %q", r.Recipe[0], want)
	}
	fields := strings.Fields(r.Recipe[1])
	if len(fields) < 3 || !slices.Equal(fields[:3], []string{"go", "run", "./cmd/rempart-worker"}) {
		problems.addf("Makefile: second demo recipe line %q does not start with \"go run ./cmd/rempart-worker\"", r.Recipe[1])
		return problems
	}
	flags := slices.Clone(fields[3:])
	want := demoRunFlags()
	slices.Sort(flags)
	slices.Sort(want)
	if !slices.Equal(flags, want) {
		problems.addf("Makefile: demo runs the worker with %q, want exactly %q", fields[3:], demoRunFlags())
	}
	return problems
}

// TestMakefileDemoTarget (M0-T20, criterion 8): the demo target of the
// repository, and negative controls of its checker.
func TestMakefileDemoTarget(t *testing.T) {
	const (
		devLine = "\t@" + subMakePrefix + "dev >&2\n"
		runHead = "\t@go run ./cmd/rempart-worker -dev -demo-once -llm=fake -tenant=0d3e0000-0000-4000-8000-000000000001 \\\n"
		runTail = "\t\t-temporal-address=127.0.0.1:7233 -namespace=rempart \\\n" +
			"\t\t-fake-script=internal/loops/demo/testdata/scripts/converge.json\n"
	)
	valid := ".PHONY: dev demo\n\ndev:\n\t@echo dev\n\n# Demo.\ndemo:\n" + devLine + runHead + runTail
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{name: "valid", src: valid},
		{name: "missing", src: ".PHONY: dev\n\ndev:\n\t@echo dev\n", want: []string{"target demo is not defined"}},
		{name: "not_phony", src: mustReplace(t, valid, ".PHONY: dev demo\n", ".PHONY: dev\n"), want: []string{"not declared .PHONY"}},
		{name: "dev_prerequisite", src: mustReplace(t, valid, "demo:\n"+devLine, "demo: dev\n"), want: []string{"has prerequisites"}},
		{name: "dev_on_stdout", src: mustReplace(t, valid, " dev >&2\n", " dev\n"), want: []string{"first demo recipe line"}},
		{
			// M0-make-subcalls: the pre-T32 form, without -f Makefile.
			name: "dev_without_file", src: mustReplace(t, valid, devLine, "\t@$(MAKE) --no-print-directory dev >&2\n"),
			want: []string{"first demo recipe line"},
		},
		{name: "echoed_line", src: mustReplace(t, valid, "\t@go run", "\tgo run"), want: []string{"not silenced by @"}},
		{name: "anthropic", src: mustReplace(t, valid, "-llm=fake", "-llm=anthropic"), want: []string{"demo runs the worker with"}},
		{name: "without_dev", src: mustReplace(t, valid, " -dev -demo-once", " -demo-once"), want: []string{"demo runs the worker with"}},
		{
			name: "secret_flag", src: mustReplace(t, valid, " -namespace=rempart", " -namespace=rempart -anthropic-key=x"),
			want: []string{"demo runs the worker with"},
		},
		{name: "remote_temporal", src: mustReplace(t, valid, "127.0.0.1:7233", "10.0.0.1:7233"), want: []string{"demo runs the worker with"}},
		{
			name: "tenant_variable", src: mustReplace(t, valid, "-tenant=0d3e0000-0000-4000-8000-000000000001", "-tenant=$(TENANT)"),
			want: []string{"interpolates a make variable", "demo runs the worker with"},
		},
		{name: "namespace_braces", src: mustReplace(t, valid, "-namespace=rempart", "-namespace=${NS}"), want: []string{"interpolates a make variable"}},
		{name: "piped", src: mustReplace(t, valid, "converge.json\n", "converge.json | jq .\n"), want: []string{"demo runs the worker with"}},
		{name: "other_package", src: mustReplace(t, valid, "./cmd/rempart-worker", "./cmd/rempart"), want: []string{"does not start with"}},
		{name: "extra_line", src: valid + "\t@echo done\n", want: []string{"demo recipe has 3 lines"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mf, err := parseMakefile(tc.src)
			if err != nil {
				t.Fatalf("parseMakefile: %v", err)
			}
			expectProblems(t, checkDemoTarget(mf), tc.want)
		})
	}

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
		reportProblems(t, checkDemoTarget(mf))
		if _, err := readRepoFile(fsys, "internal/loops/demo/testdata/scripts/converge.json", "M0-T20"); err != nil {
			t.Errorf("script of make demo: %v", err)
		}
		if slices.Contains(reachableTargets(mf, "verify-quick"), "demo") {
			t.Error("target demo is reachable from verify-quick (it needs the dev stack)")
		}
	})
}

// physicalLine returns the 1-based number of the single physical line of src
// containing fragment. A fragment found zero or several times stops the test:
// the wanted line number would not designate the mutated line.
func physicalLine(t *testing.T, src, fragment string) int {
	t.Helper()
	num := 0
	for i, l := range strings.Split(src, "\n") {
		if strings.Contains(l, fragment) {
			if num != 0 {
				t.Fatalf("fragment %q found on lines %d and %d, want exactly one line", fragment, num, i+1)
			}
			num = i + 1
		}
	}
	if num == 0 {
		t.Fatalf("fragment %q not found", fragment)
	}
	return num
}

// exactLines returns the 1-based numbers of the physical lines of src equal to line.
func exactLines(src, line string) []int {
	var nums []int
	for i, l := range strings.Split(src, "\n") {
		if l == line {
			nums = append(nums, i+1)
		}
	}
	return nums
}

// exactLine returns the number of the single physical line of src equal to
// line; zero or several such lines stop the test.
func exactLine(t *testing.T, src, line string) int {
	t.Helper()
	nums := exactLines(src, line)
	if len(nums) != 1 {
		t.Fatalf("line %q found on lines %d, want exactly one line", line, nums)
	}
	return nums[0]
}

// Stable fragments of the errors of parseMakefile (docs/plans/M0-make-subcalls.md
// section 3, codes E1 to E8), always preceded by "line <n>: ".
const (
	errTrailingComment  = "comment after make syntax not allowed (D8)"                               // E1
	errUnsupported      = "unsupported directive"                                                    // E2
	errExportNotAllowed = "export not allowed (D8)"                                                  // E5
	errOutsideGrammar   = "line outside the Makefile grammar of the tests (D8)"                      // E6
	errRecipeOutside    = "recipe line outside a rule"                                               // E8
	errD7               = "recipe line expands make syntax outside the canonical sub-make (D7, T32)" // D7 problem
)

// Stable fragments of the lexer errors of parseMakefile (M0-T04b V2, codes E9 to
// E14), preceded by "line <n>: ", n being the physical line at fault.
const (
	errEvenBackslashes   = "line ends with an even number of backslashes (D11)"               // E10
	errContinuation      = "continuation outside a recipe line not allowed (D12)"             // E11
	errNonASCII          = "non-ASCII byte outside a column-0 comment or a recipe line (D13)" // E12
	errContinuationAtEOF = "continuation at end of file (D11)"                                // E14
)

// Stable fragments of D16 (M0-T04b V3): E15, a line naming the Makefile as a
// rule target in any other form than "Makefile: ;"; the problem of
// checkMakefileSelfRule when that line is missing.
const (
	errSelfRuleForm    = `rule naming Makefile must be exactly "Makefile: ;" (D16)` // E15
	errSelfRuleMissing = `rule "Makefile: ;" missing`                               // D16 problem
)

// errControlByte is E9 for the byte b.
func errControlByte(b byte) string {
	return fmt.Sprintf("control byte 0x%02x not allowed (D13)", b)
}

// errCharacter is E13 for the rune r.
func errCharacter(r rune) string {
	return fmt.Sprintf("character %U not allowed in a comment or recipe line (D13)", r)
}

// errVariableNotAllowed is E3 for name.
func errVariableNotAllowed(name string) string {
	return fmt.Sprintf("variable %q not allowed in the Makefile (D8)", name)
}

// errFormNotAllowed is E4 for name.
func errFormNotAllowed(name string) string {
	return fmt.Sprintf("form not allowed for variable %s (D8)", name)
}

// errAlreadyNamed is the whole E7 error: the rule line num names target,
// already named by the rule line first.
func errAlreadyNamed(num int, target string, first int) string {
	return fmt.Sprintf("line %d: target %q already named by the rule of line %d (D8)", num, target, first)
}

// TestMakefileGrammar (M0-T04b V1, threat T32): parseMakefile refuses every
// line outside the closed grammar D8 of docs/plans/M0-make-subcalls.md, with
// an error naming the mutated line. Nothing it does not recognize is ignored:
// $(eval include ...) hidden behind "# :", .RECIPEPREFIX, include, assignment
// of MAKE or of any unlisted variable, target-specific variables, inline
// recipes, special targets.
func TestMakefileGrammar(t *testing.T) {
	valid := targetMakefile
	const (
		opaLine      = "OPA ?= opa\n"
		opaOverride  = "override OPA := $(value OPA)\n"
		exportLine   = "export SCENARIO EVAL EVAL_BASE POLICIES_DIR OPA\n"
		secondPhony  = ".PHONY: dev dev-preflight dev-down sandbox-guard sandbox-plan sandbox-apply sandbox-destroy\n"
		archCall     = "\t" + subMakePrefix + "arch-test\n"
		evilInclude  = "$(eval include evil.mk)"
		recipePrefix = ".RECIPEPREFIX"
	)
	// afterOPA inserts lines (newline included) after "OPA ?= opa".
	afterOPA := func(lines string) string { return mustReplace(t, valid, opaLine, opaLine+lines) }

	type testCase struct {
		name    string
		src     string
		wantErr string                                // "": conforming input
		check   func(t *testing.T, mf parsedMakefile) // conforming input: what the parser must have read
	}
	// at builds a negative case whose error names the physical line holding fragment.
	at := func(name, src, fragment, code string) testCase {
		return testCase{name: name, src: src, wantErr: fmt.Sprintf("line %d: %s", physicalLine(t, src, fragment), code)}
	}
	// atExact is at for a mutated line given whole (its text is part of other lines).
	atExact := func(name, src, line, code string) testCase {
		return testCase{name: name, src: src, wantErr: fmt.Sprintf("line %d: %s", exactLine(t, src, line), code)}
	}

	g1 := valid + evilInclude + " # :\n"
	g2 := valid + "X := evil.mk\n$(eval -include $(X)) # :\n"
	g3 := valid + recipePrefix + " := >\nverify-quick:\n>@echo SHADOW # :\n"
	g15 := mustReplace(t, afterOPA("SUB := $(MAKE)\n"), archCall, "\t$(SUB) -f Makefile --no-print-directory dev\n")
	g25 := valid + "%:\n\t@echo x\n"
	g32 := valid + "arch-test: opa-test\n"
	g32Lines := exactLines(g32, "arch-test:")
	if len(g32Lines) != 1 {
		t.Fatalf("duplicate_rule_line: rule line arch-test: found on lines %d, want 1", g32Lines)
	}
	// addRecipeLines appends recipe or column-0 lines (tabs given) after the recipe of target.
	addRecipeLines := func(target string, lines ...string) string {
		return editRule(t, valid, target, func(rule string, recipe []string) []string {
			return slices.Concat([]string{rule}, recipe, lines)
		})
	}
	n1 := valid + "# fin \\\\\ninclude evil.mk\n"
	n1b := afterOPA("  # x \\\\\n-include evil.mk\n")
	n1c := valid + "# fin \\\\\nverify-quick:\n\t@echo SHADOW-dup\n"
	n3 := addRecipeLines("dev", "\t@echo ok \\\\", "include evil.mk")
	n4 := mustReplace(t, valid, "SHELL := /bin/bash\n", "SHELL := /bin/bash\r\n")
	n7 := mustReplace(t, valid, "étape OPA sans objet.", "étape OPA\x1b[8m sans objet.")
	n8 := addRecipeLines("dev", "\t@echo a \\\\\\\\", "\t@true")
	n10 := mustReplace(t, valid, "EVAL ?= all\n", "EVAL ?= \\\nall\n")
	n11 := addRecipeLines("dev", "\t@echo \"a\u202eb\"")
	n14 := valid + "\t@echo x \\"
	// V3, D16: the rule "Makefile: ;" is admitted once, in that exact form only.
	const selfRule = "Makefile: ;\n"
	selfTwice := valid + "\n" + selfRule
	selfTwiceLines := exactLines(selfTwice, "Makefile: ;")
	if len(selfTwiceLines) != 2 {
		t.Fatalf("self_rule_twice: line Makefile: ; found on lines %d, want 2 lines", selfTwiceLines)
	}
	// withSelf replaces the rule "Makefile: ;" of the template by lines (newline included).
	withSelf := func(lines string) string { return mustReplace(t, valid, selfRule, lines) }
	selfRecipe := withSelf(selfRule + "\t@cp Makefile.sh Makefile\n")
	selfRecipeAfterBlank := withSelf(selfRule + "\n# x\n\t@cp Makefile.sh Makefile\n")
	negatives := []testCase{
		at("eval_include_comment_colon", g1, evilInclude, errTrailingComment),                                       // G1, BLOCK finding 1
		at("eval_include_indirect", g2, "X := evil.mk", errVariableNotAllowed("X")),                                 // G2, BLOCK finding 1
		at("recipeprefix", g3, recipePrefix, errVariableNotAllowed(recipePrefix)),                                   // G3, BLOCK finding 3
		at("include_directive", afterOPA("include evil.mk\n"), "include evil.mk", errOutsideGrammar),                // G4
		at("dash_include_directive", afterOPA("-include evil.mk\n"), "-include evil.mk", errOutsideGrammar),         // G5
		at("sinclude_directive", afterOPA("sinclude evil.mk\n"), "sinclude evil.mk", errOutsideGrammar),             // G6
		at("vpath_directive", afterOPA("vpath %.mk evil\n"), "vpath %.mk", errOutsideGrammar),                       // G7
		at("unexport_directive", afterOPA("unexport OPA\n"), "unexport OPA", errOutsideGrammar),                     // G8
		at("define_block", afterOPA("define X\nendef\n"), "define X", errUnsupported),                               // G9
		at("assign_make", afterOPA("MAKE := make -f GNUmakefile\n"), "MAKE := make", errVariableNotAllowed("MAKE")), // G10
		at("redefine_make", mustReplace(t, valid, opaOverride, opaOverride+"override MAKE := make -f GNUmakefile\n"), // G11
			"override MAKE", errVariableNotAllowed("MAKE")),
		at("assign_make_command", afterOPA("MAKE_COMMAND := evil\n"), "MAKE_COMMAND", errVariableNotAllowed("MAKE_COMMAND")), // G12
		at("assign_makeflags", afterOPA("MAKEFLAGS := -i\n"), "MAKEFLAGS", errVariableNotAllowed("MAKEFLAGS")),               // G13
		at("makefiles_assignment", mustReplace(t, valid, exportLine, exportLine+"export MAKEFILES := evil.mk\n"), // G14
			"MAKEFILES", errVariableNotAllowed("MAKEFILES")),
		at("indirect_variable", g15, "SUB := $(MAKE)", errVariableNotAllowed("SUB")), // G15
		at("value_other_name", mustReplace(t, valid, "override EVAL := $(value EVAL)\n", "override EVAL := $(value OPA)\n"), // G16
			"override EVAL := $(value OPA)", errFormNotAllowed("EVAL")),
		at("assign_dollar_value", mustReplace(t, valid, "EVAL ?= all\n", "EVAL ?= $(shell id)\n"), "EVAL ?= $(shell id)", errFormNotAllowed("EVAL")), // G17
		at("shell_assign", mustReplace(t, valid, "EVAL ?= all\n", "EVAL != id\n"), "EVAL != id", errFormNotAllowed("EVAL")),                          // G18
		at("assign_shell_other", mustReplace(t, valid, "SHELL := /bin/bash\n", "SHELL := /tmp/evil.sh\n"), "SHELL := /tmp/evil.sh", // G19
			errFormNotAllowed("SHELL")),
		at("shellflags_changed", mustReplace(t, valid, ".SHELLFLAGS := -eu -o pipefail -c\n", ".SHELLFLAGS := -c evil\n"), // G20
			".SHELLFLAGS := -c evil", errFormNotAllowed(".SHELLFLAGS")),
		atExact("bare_export", afterOPA("export\n"), "export", errExportNotAllowed),                                                          // G21
		at("export_other_name", mustReplace(t, valid, exportLine, exportLine+"export MAKEFLAGS\n"), "export MAKEFLAGS", errExportNotAllowed), // G22
		at("unknown_special_var", valid+".SECONDEXPANSION:\n", ".SECONDEXPANSION:", errOutsideGrammar),                                       // G23
		at("ignore_special_target", valid+".IGNORE:\n", ".IGNORE:", errOutsideGrammar),                                                       // G24
		atExact("target_bad_chars", g25, "%:", errOutsideGrammar),                                                                            // G25
		at("target_specific_variable", setRuleLine(t, valid, "arch-test", "arch-test: export MAKEFILES = evil.mk"), // G26
			"arch-test: export", errOutsideGrammar),
		at("prereq_expansion", setRuleLine(t, valid, "verify", "verify: verify-quick "+evilInclude), // G27
			"verify: verify-quick $(eval", errOutsideGrammar),
		at("phony_expansion", mustReplace(t, valid, ".PHONY: dev dev-preflight ", ".PHONY: "+evilInclude+" dev dev-preflight "), // G28
			".PHONY: $(eval", errOutsideGrammar),
		at("inline_recipe", setRuleLine(t, valid, "arch-test", "arch-test: ; "+subMakePrefix+"opa-test"), "arch-test: ;", errOutsideGrammar), // G29
		// G30, G31: ASCII (V2), a non-ASCII byte there would be refused first by E12.
		atExact("rule_trailing_comment", setRuleLine(t, valid, "dev-down", "dev-down: # stop"), "dev-down: # stop", errTrailingComment),               // G30
		at("assign_trailing_comment", mustReplace(t, valid, "EVAL ?= all\n", "EVAL ?= all # default\n"), "EVAL ?= all # default", errTrailingComment), // G31
		{name: "duplicate_rule_line", src: g32, wantErr: errAlreadyNamed(exactLine(t, g32, "arch-test: opa-test"), "arch-test", g32Lines[0])},         // G32
		at("phony_with_recipe", mustReplace(t, valid, secondPhony, secondPhony+"\t@echo x\n"), "\t@echo x", errRecipeOutside),                         // G33
		// Frozen values: a value without "$" is enough to divert go or make (D8 (iii)).
		at("gowork_changed", mustReplace(t, valid, exportLine, exportLine+"export GOWORK := /tmp/go.work\n"), // G34
			"GOWORK := /tmp/go.work", errFormNotAllowed("GOWORK")),
		at("goflags_changed", mustReplace(t, valid, exportLine, exportLine+"override GOFLAGS := -mod=mod\n"), // G35
			"GOFLAGS := -mod=mod", errFormNotAllowed("GOFLAGS")),
		at("default_goal_changed", mustReplace(t, valid, ".DEFAULT_GOAL := verify-quick\n", ".DEFAULT_GOAL := demo\n"), // G36
			".DEFAULT_GOAL := demo", errFormNotAllowed(".DEFAULT_GOAL")), // G36

		// V2, D11 to D13: forms on which this lexer and GNU make could disagree
		// are refused, the error naming the physical line at fault. N1 to N3:
		// second BLOCK, an even number of trailing backslashes does not continue
		// a line for make, the V1 parser swallowed the next line that make reads.
		atExact("comment_even_backslash_include", n1, `# fin \\`, errEvenBackslashes),                    // N1
		atExact("indented_comment_even_backslash", n1b, `  # x \\`, errEvenBackslashes),                  // N1b
		atExact("comment_even_backslash_shadow_rule", n1c, `# fin \\`, errEvenBackslashes),               // N1c
		atExact("recipe_even_backslash_include", n3, "\t@echo ok \\\\", errEvenBackslashes),              // N3
		at("crlf_line", n4, "SHELL := /bin/bash", errControlByte(0x0d)),                                  // N4
		at("nul_byte", afterOPA("# a\x00b\n"), "# a\x00b", errControlByte(0x00)),                         // N5
		at("nbsp_before_comment", afterOPA("\u00a0# include evil.mk\n"), "\u00a0# include", errNonASCII), // N6
		at("control_char", n7, "\x1b[8m", errControlByte(0x1b)),                                          // N7, continuation line
		atExact("even_backslash_recipe", n8, "\t@echo a \\\\\\\\", errEvenBackslashes),                   // N8
		atExact("comment_continuation", valid+"# fin \\\ninclude evil.mk\n", `# fin \`, errContinuation), // N9
		at("assign_continuation", n10, "EVAL ?= \\", errContinuation),                                    // N10
		at("bidi_in_recipe", n11, "a\u202eb", errCharacter('\u202e')),                                    // N11
		at("invalid_utf8_comment", afterOPA("# a\xffb\n"), "# a\xffb", errCharacter('\ufffd')),           // N12
		at("nonascii_indented_comment", afterOPA("  # arrêt\n"), "  # arrêt", errNonASCII),               // N13
		{name: "continuation_at_eof", src: n14, wantErr: fmt.Sprintf("line %d: %s", // N14
			exactLine(t, n14, "\t@echo x \\"), errContinuationAtEOF)},

		// V3, D16 (third BLOCK): "Makefile: ;" once, in that exact form. Any other
		// rule naming the Makefile could give it a recipe or prerequisites that
		// remake it, or leave the implicit rule search on.
		{name: "self_rule_twice", src: selfTwice, wantErr: errAlreadyNamed(selfTwiceLines[1], "Makefile", selfTwiceLines[0])}, // S1
		atExact("self_rule_prerequisite", withSelf("Makefile: x\n"), "Makefile: x", errSelfRuleForm),                          // S2
		atExact("self_rule_prerequisite_sh", withSelf("Makefile: Makefile.sh\n"), "Makefile: Makefile.sh", errSelfRuleForm),   // S3
		atExact("self_rule_inline_recipe", withSelf("Makefile: ; echo\n"), "Makefile: ; echo", errSelfRuleForm),               // S4
		atExact("self_rule_inline_copy", withSelf("Makefile: ; cp Makefile.sh $@\n"), "Makefile: ; cp Makefile.sh $@", errSelfRuleForm),
		atExact("self_rule_without_semicolon", withSelf("Makefile:\n"), "Makefile:", errSelfRuleForm), // S5
		atExact("self_rule_glued_semicolon", withSelf("Makefile:;\n"), "Makefile:;", errSelfRuleForm),
		atExact("self_rule_space_before_colon", withSelf("Makefile : ;\n"), "Makefile : ;", errSelfRuleForm),
		atExact("self_rule_double_colon", withSelf("Makefile:: ;\n"), "Makefile:: ;", errSelfRuleForm),
		atExact("self_rule_trailing_space", withSelf("Makefile: ; \n"), "Makefile: ; ", errSelfRuleForm),
		atExact("self_rule_leading_space", withSelf(" Makefile: ;\n"), " Makefile: ;", errSelfRuleForm),
		atExact("self_rule_tab_before_semicolon", withSelf("Makefile:\t;\n"), "Makefile:\t;", errSelfRuleForm),
		at("self_rule_recipe_line", selfRecipe, "\t@cp Makefile.sh Makefile", errRecipeOutside),
		at("self_rule_recipe_after_comment", selfRecipeAfterBlank, "\t@cp Makefile.sh Makefile", errRecipeOutside),
		// Other targets stay [a-z][a-z0-9-]*: the shape of Makefile alone is admitted.
		atExact("other_file_rule", withSelf(selfRule+"Makefile.sh: ;\n"), "Makefile.sh: ;", errOutsideGrammar),
		atExact("makefile_prerequisite", withSelf(selfRule+"verify: Makefile\n"), "verify: Makefile", errOutsideGrammar),
	}
	positives := []testCase{
		{name: "valid_template", src: valid, // GP1
			// V3, D16: the rule "Makefile: ;" is read, apart from the rules of the checks.
			check: func(t *testing.T, mf parsedMakefile) {
				if want := exactLine(t, valid, "Makefile: ;"); mf.SelfRule != want {
					t.Errorf("SelfRule = %d, want %d (line of \"Makefile: ;\")", mf.SelfRule, want)
				}
				if _, ok := mf.Rules["Makefile"]; ok {
					t.Error("Rules holds Makefile: the rule \"Makefile: ;\" is no target of the checks")
				}
			}},
		{name: "self_rule_first_line", src: selfRule + withSelf(""), // GP7
			check: func(t *testing.T, mf parsedMakefile) {
				if mf.SelfRule != 1 {
					t.Errorf("SelfRule = %d, want 1", mf.SelfRule)
				}
			}},
		{name: "self_rule_absent", src: withSelf(""), // GP8: the grammar admits it, checkMakefileSelfRule requires it
			check: func(t *testing.T, mf parsedMakefile) {
				if mf.SelfRule != 0 {
					t.Errorf("SelfRule = %d, want 0", mf.SelfRule)
				}
			}},
		{name: "go_env_lines", src: mustReplace(t, valid, exportLine, // GP2
			exportLine+"export GOWORK := off\noverride GOFLAGS := -mod=readonly\nexport GOFLAGS\n")},
		{name: "comments_with_syntax", src: mustReplace(t, valid, ".DEFAULT_GOAL := verify-quick\n", // GP3
			".DEFAULT_GOAL := verify-quick\n# "+evilInclude+" # :\n  # include evil.mk\n")},
		{name: "reference_dev_makefile", src: referenceDevMakefile(t)}, // GP4
		// V2, D13: French text in a column-0 comment and in a recipe line.
		{name: "french_text", src: editRule(t, afterOPA("# Étape « démo » d’essai, arrêt : à revoir\n"), "dev-down", // GP5
			func(rule string, recipe []string) []string {
				return slices.Concat([]string{rule}, recipe, []string{"\t@echo \"arrêt : terminé, « rien » à faire\""})
			})},
		// V2, D11: an odd number of backslashes greater than one continues a recipe line.
		// Joined like one backslash (make joins too): one logical recipe line, the
		// final backslash removed, a line read alone would diverge from make.
		{name: "odd_backslash_recipe", src: addRecipeLines("dev", "\t@echo a \\\\\\", "\t\tb"), // GP6
			check: func(t *testing.T, mf parsedMakefile) {
				recipe := mf.Rules["dev"].Recipe
				if !slices.Contains(recipe, `echo a \\ b`) || slices.Contains(recipe, "b") {
					t.Errorf("dev recipe = %q, want the logical line %q (three backslashes continue the line)", recipe, `echo a \\ b`)
				}
			}},
	}

	run := func(t *testing.T, cases []testCase) {
		t.Helper()
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				mf, err := parseMakefile(tc.src)
				if tc.wantErr == "" {
					if err != nil {
						t.Fatalf("parseMakefile refused a conforming input: %v", err)
					}
					if tc.check != nil {
						tc.check(t, mf)
					}
					return
				}
				expectError(t, err, tc.wantErr)
			})
		}
	}
	t.Run("negative_controls", func(t *testing.T) { run(t, negatives) })
	t.Run("positive_controls", func(t *testing.T) { run(t, positives) })

	// V3, D16: checkMakefileSelfRule requires the rule the grammar admits.
	t.Run("self_rule", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			src  string
			want []string
		}{
			{name: "present", src: valid},
			{name: "absent", src: withSelf(""), want: []string{"Makefile: " + errSelfRuleMissing, "(D16, T32)"}},
			{name: "only_in_comment", src: withSelf("# Makefile: ;\n"), want: []string{"Makefile: " + errSelfRuleMissing}},
			{name: "only_in_recipe", src: withSelf("") + "\t@echo 'Makefile: ;'\n", want: []string{"Makefile: " + errSelfRuleMissing}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				mf, err := parseMakefile(tc.src)
				if err != nil {
					t.Fatalf("parseMakefile: %v", err)
				}
				expectProblems(t, checkMakefileSelfRule(mf), tc.want)
			})
		}
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
		// V3, D16 (criterion: grep -c '^Makefile: ;$' Makefile is 1).
		reportProblems(t, checkMakefileSelfRule(mf))
		if n := len(exactLines(src, "Makefile: ;")); n != 1 {
			t.Errorf("Makefile: %d lines \"Makefile: ;\", want exactly 1 (D16)", n)
		}
	})
}

// TestMakefileSubMakeCalls (M0-T04b, threat T32, obligation (bp)): GNU make does
// not pass -f through MAKEFLAGS, so a sub-make without "-f Makefile" reads the
// default file of the directory (a GNUmakefile or makefile would shadow it).
// Every line mentioning make must be exactly a canonical sub-make recipe line
// naming a defined target, and no other recipe line may expand make syntax
// (V1, D7: $(MAKE_COMMAND), computed names, $(eval ...), automatic variables)
// (docs/plans/M0-make-subcalls.md sections 2 and 5).
func TestMakefileSubMakeCalls(t *testing.T) {
	valid := targetMakefile
	const (
		archCall = "\t" + subMakePrefix + "arch-test\n"
		opaCall  = "\t" + subMakePrefix + "opa-test\n"
		mustBe   = `sub-make must be exactly "$(MAKE) -f Makefile --no-print-directory <target>" on its own recipe line (T32)`
	)
	// replaceArch replaces the arch-test sub-make of verify-quick by lines.
	replaceArch := func(lines string) string { return mustReplace(t, valid, archCall, lines) }
	// addRecipeLine appends a recipe line (tab included) to the rule of target.
	addRecipeLine := func(target, line string) string {
		return editRule(t, valid, target, func(rule string, recipe []string) []string {
			return append(append([]string{rule}, recipe...), line)
		})
	}

	type testCase struct {
		name string
		src  string
		want []string // nil: conforming input
	}
	// negative builds a case whose refused line is the physical line holding fragment.
	negative := func(name, src, fragment string) testCase {
		return testCase{name: name, src: src, want: []string{fmt.Sprintf("Makefile line %d: %s", physicalLine(t, src, fragment), mustBe)}}
	}
	// expands builds a case whose line, holding fragment, is refused by D7.
	expands := func(name, src, fragment string) testCase {
		return testCase{name: name, src: src, want: []string{fmt.Sprintf("Makefile line %d: %s", physicalLine(t, src, fragment), errD7)}}
	}

	undefined := replaceArch("\t" + subMakePrefix + "nope\n")
	negatives := []testCase{
		negative("without_file", mustReplace(t, valid, opaCall, "\t$(MAKE) --no-print-directory opa-test\n"), "$(MAKE) --no-print-directory opa-test"),
		negative("file_after_option", replaceArch("\t$(MAKE) --no-print-directory -f Makefile dev\n"), "--no-print-directory -f Makefile dev"),
		negative("other_file", replaceArch("\t$(MAKE) -f GNUmakefile --no-print-directory arch-test\n"), "-f GNUmakefile"),
		negative("dot_slash_file", replaceArch("\t$(MAKE) -f ./Makefile --no-print-directory arch-test\n"), "-f ./Makefile"),
		negative("glued_file", replaceArch("\t$(MAKE) -fMakefile --no-print-directory arch-test\n"), "-fMakefile"),
		negative("second_file", replaceArch("\t$(MAKE) -f Makefile -f evil.mk --no-print-directory arch-test\n"), "-f evil.mk"),
		negative("long_file", replaceArch("\t$(MAKE) --file=Makefile --no-print-directory arch-test\n"), "--file=Makefile"),
		negative("long_makefile", replaceArch("\t$(MAKE) --makefile Makefile --no-print-directory arch-test\n"), "--makefile Makefile"),
		negative("change_directory", replaceArch("\t$(MAKE) -f Makefile -C sub --no-print-directory arch-test\n"), "-C sub"),
		negative("long_directory", replaceArch("\t$(MAKE) -f Makefile --directory=sub --no-print-directory arch-test\n"), "--directory=sub"),
		negative("include_dir", replaceArch("\t$(MAKE) -f Makefile -I inc --no-print-directory arch-test\n"), "-I inc"),
		negative("makefiles_env", replaceArch("\tMAKEFILES=evil.mk "+subMakePrefix+"arch-test\n"), "MAKEFILES=evil.mk"),
		negative("braces", replaceArch("\t${MAKE} -f Makefile --no-print-directory arch-test\n"), "${MAKE}"),
		negative("literal_make", replaceArch("\tmake -f Makefile --no-print-directory arch-test\n"), "\tmake -f Makefile"),
		negative("gmake_path", replaceArch("\t/usr/bin/gmake -f Makefile --no-print-directory arch-test\n"), "/usr/bin/gmake"),
		negative("ignore_errors_prefix", replaceArch("\t-"+subMakePrefix+"arch-test\n"), "\t-$(MAKE)"),
		negative("second_call", replaceArch("\t"+subMakePrefix+"arch-test && $(MAKE) --no-print-directory dev\n"), "arch-test && $(MAKE)"),
		negative("trailing_make", replaceArch("\t"+subMakePrefix+"arch-test; make dev\n"), "arch-test; make dev"),
		negative("extra_variable", replaceArch("\t"+subMakePrefix+"arch-test EVAL=x\n"), "arch-test EVAL=x"),
		{
			name: "undefined_target",
			src:  undefined,
			want: []string{fmt.Sprintf(`Makefile line %d: sub-make target "nope" is not defined`, physicalLine(t, undefined, "directory nope"))},
		},
		negative("hidden_in_continuation", replaceArch("\t$(MAKE) -f Makefile \\\n\t\t--no-print-directory -f evil.mk dev\n"),
			"\t$(MAKE) -f Makefile \\"),
		negative("shell_comment_in_recipe", addRecipeLine("verify", "\t# $(MAKE) --no-print-directory dev"), "# $(MAKE)"),
		// V1, D7: make expansions in a recipe outside the canonical prefix (BLOCK finding 2).
		expands("make_command", replaceArch("\t$(MAKE_COMMAND) -f evil.mk arch-test\n"), "$(MAKE_COMMAND)"),
		expands("computed_name", replaceArch("\t$(MA$(NOTHING)KE) -f evil.mk arch-test\n"), "$(MA$(NOTHING)KE)"),
		expands("dollar_in_recipe_other", addRecipeLine("dev", "\t$(shell id)"), "\t$(shell id)"),
		expands("automatic_var_in_recipe", addRecipeLine("dev", "\techo $@"), "echo $@"),
		expands("makeflags_in_recipe", addRecipeLine("dev", "\t@echo \"$(MAKEFLAGS)\""), "$(MAKEFLAGS)"),
		expands("triple_dollar", addRecipeLine("dev", "\techo $$$(shell id)"), "$$$(shell id)"),
		expands("eval_in_recipe", addRecipeLine("dev", "\t$(eval include evil.mk)"), "$(eval include evil.mk)"),
		// SUB := $(MAKE) is refused by D8 (TestMakefileGrammar G15); the reference alone by D7.
		expands("indirect_reference", replaceArch("\t$(SUB) -f Makefile --no-print-directory dev\n"), "$(SUB)"),
		expands("shell_comment_expansion", addRecipeLine("verify", "\t# $(shell id)"), "# $(shell id)"),
		expands("expansion_in_continuation", addRecipeLine("dev", "\techo ok \\\n\t$(shell id)"), "echo ok \\"),
		// V1, D2 kept (D9): make named in shell text.
		negative("shell_make_variable", addRecipeLine("dev", "\tMAKE=/tmp/x true"), "MAKE=/tmp/x"),
		negative("makefiles_shell_env", addRecipeLine("dev", "\tMAKEFILES=evil.mk go test ./..."), "MAKEFILES=evil.mk"),
	}
	positives := []testCase{
		{name: "valid_template", src: valid},
		{name: "make_comment", src: mustReplace(t, valid, ".DEFAULT_GOAL := verify-quick\n",
			".DEFAULT_GOAL := verify-quick\n# Le hook Stop exige make verify-quick\n  # Le hook Stop exige $(MAKE) -C ailleurs\n")},
		{name: "silenced_to_stderr", src: replaceArch("\t@" + subMakePrefix + "arch-test >&2\n")},
		{name: "canonical_continuation", src: replaceArch("\t$(MAKE) -f Makefile \\\n\t\t--no-print-directory arch-test\n")},
		{name: "echo_makefile_word", src: addRecipeLine("dev", "\t@echo \"voir Makefile\"")},
		{name: "shell_dollar", src: addRecipeLine("dev", "\t@echo \"$$HOME $${USER:-x} $$(id -u)\"")},
	}

	run := func(t *testing.T, cases []testCase) {
		t.Helper()
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				mf, err := parseMakefile(tc.src)
				if err != nil {
					t.Fatalf("parseMakefile: %v", err)
				}
				problems := checkSubMakeCalls(mf)
				expectProblems(t, problems, tc.want)
				// Each mutation changes one logical line: exactly one problem, on that line.
				if tc.want != nil && len(problems) != 1 {
					t.Errorf("%d problems, want exactly 1 (the mutated line):\n%s", len(problems), strings.Join(problems, "\n"))
				}
			})
		}
	}
	t.Run("negative_controls", func(t *testing.T) { run(t, negatives) })
	t.Run("positive_controls", func(t *testing.T) { run(t, positives) })

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
		reportProblems(t, checkSubMakeCalls(mf))
	})
}

// TestMakeLexerHelpers (M0-T04b V2, D14, threat T32): GNU make only treats
// spaces and tabs as blanks. NBSP, NEL and U+2028 are text for make, so a line
// they start is not a comment and a sub-make behind them is checked. Tested
// directly: D13 keeps these characters out of any input parseMakefile accepts.
func TestMakeLexerHelpers(t *testing.T) {
	t.Run("trim_ascii_blanks_only", func(t *testing.T) { // H1
		if got, want := makeTrim(" \t\u00a0x\u0085\t "), "\u00a0x\u0085"; got != want {
			t.Errorf("makeTrim removed Unicode blanks: got %q, want %q", got, want)
		}
		if got := makeTrim(" \tx\t "); got != "x" {
			t.Errorf("makeTrim(%q) = %q, want %q", " \tx\t ", got, "x")
		}
	})
	t.Run("comment_after_unicode_blank", func(t *testing.T) { // H2
		for _, tc := range []struct {
			text string
			want bool
		}{
			{"\u00a0# x", false}, // NBSP is not a blank for make
			{"  \t# x", true},    // spaces then a tab: make comment
			{"\t# x", false},     // recipe line: shell text
		} {
			if got := isMakeComment(makeLine{Num: 1, Text: tc.text}); got != tc.want {
				t.Errorf("isMakeComment(%q) = %t, want %t", tc.text, got, tc.want)
			}
		}
	})
	t.Run("submake_after_unicode_blank", func(t *testing.T) { // H3
		const mustBe = `sub-make must be exactly "$(MAKE) -f Makefile --no-print-directory <target>" on its own recipe line (T32)`
		problems := checkSubMakeCalls(parsedMakefile{
			Rules: map[string]makeRule{},
			Lines: []makeLine{{Num: 1, Text: "\u2028# $(MAKE) -C x"}},
		})
		if len(problems) != 1 || !strings.HasPrefix(problems[0], "Makefile line 1: "+mustBe) {
			t.Errorf("problems = %q, want exactly one starting with %q", problems, "Makefile line 1: "+mustBe)
		}
	})
}
