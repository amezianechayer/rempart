package archtest

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Threat T31, hardening required before scripts/sandbox.sh exists (plan
// docs/plans/M0-squelette.md section 0, M3-T01). make -i, MAKEFLAGS=i, a "-"
// prefix or .IGNORE ignore the failure of a recipe line and run the next one:
// with the validation of SCENARIO and the confirmation on lines of their own,
// a refused confirmation (no terminal) would still call scripts/sandbox.sh.
// Each sandbox target therefore has a single recipe line, in a closed form,
// that chains the validation, the confirmation read on /dev/tty and the call
// by &&; no recipe line of the Makefile carries a "-" or "+" prefix; nothing
// names .IGNORE or MAKEFLAGS.

// sandboxValidation is the check of SCENARIO that opens every sandbox line.
const sandboxValidation = `{ [[ "$${SCENARIO:-}" =~ ^[a-z0-9][a-z0-9-]{0,62}$$ ]] || ` +
	`{ echo "SCENARIO requis, au format [a-z0-9-] (ex. SCENARIO=demo)." >&2; exit 2; }; }`

// sandboxLineRe is the closed form of the only recipe line of a sandbox
// target (tab removed): the validation, then for apply and destroy the
// confirmation read on /dev/tty, then the call, chained by &&. The prompt is
// a double-quoted text with no expansion but $$SCENARIO (validated before).
func sandboxLineRe(verb string, confirm bool) *regexp.Regexp {
	prompt := `"(?:[^"$` + "`" + `\\]|\$\$SCENARIO)*"`
	s := `^@` + regexp.QuoteMeta(sandboxValidation)
	if confirm {
		s += ` && read -r -p ` + prompt + ` a </dev/tty && \[ "\$\$a" = "oui" \]`
	}
	return regexp.MustCompile(s + ` && \./scripts/sandbox\.sh ` + verb + ` "\$\$SCENARIO"$`)
}

// checkSandboxChained: one recipe line per sandbox target, in its closed form.
func checkSandboxChained(mf parsedMakefile) []string {
	var problems problemList
	for _, c := range []struct {
		target, verb string
		confirm      bool
	}{{"sandbox-plan", "plan", false}, {"sandbox-apply", "apply", true}, {"sandbox-destroy", "destroy", true}} {
		lines := recipeLines(mf, c.target)
		if len(lines) != 1 {
			problems.addf("Makefile: target %s must have exactly one recipe line chaining the validation of SCENARIO, "+
				"the confirmation and the call of scripts/sandbox.sh by && (T31): %d lines", c.target, len(lines))
			continue
		}
		if line := strings.TrimPrefix(lines[0], "\t"); !sandboxLineRe(c.verb, c.confirm).MatchString(line) {
			problems.addf("Makefile: target %s: recipe line outside the closed form of T31 (validation && confirmation && call): %q", c.target, line)
		}
	}
	return problems
}

var (
	ignoreSpecialRe = regexp.MustCompile(`\.IGNORE\b`)
	makeflagsRe     = regexp.MustCompile(`\b(GNU)?MAKEFLAGS\b|\bMFLAGS\b`)
)

// checkIgnoreErrorForms: no recipe line with a "-" prefix (errors ignored) or
// a "+" prefix (run under -n), no .IGNORE, no MAKEFLAGS, GNUMAKEFLAGS or
// MFLAGS named outside a make comment, in make or in shell text (T31).
func checkIgnoreErrorForms(lines []makeLine) []string {
	var problems problemList
	for _, l := range lines {
		if isMakeComment(l) {
			continue
		}
		if rest, recipe := strings.CutPrefix(l.Text, "\t"); recipe {
			prefix := rest[:len(rest)-len(strings.TrimLeft(rest, "@-+ \t"))]
			if strings.Contains(prefix, "-") {
				problems.addf("Makefile line %d: recipe prefix - ignores the failure of the line (T31): %q", l.Num, l.Text)
			}
			if strings.Contains(prefix, "+") {
				problems.addf("Makefile line %d: recipe prefix + runs the line under -n (T31): %q", l.Num, l.Text)
			}
		}
		if ignoreSpecialRe.MatchString(l.Text) {
			problems.addf("Makefile line %d: .IGNORE ignores the failure of recipe lines (T31): %q", l.Num, l.Text)
		}
		if makeflagsRe.MatchString(l.Text) {
			problems.addf("Makefile line %d: MAKEFLAGS (or GNUMAKEFLAGS, MFLAGS) named: it can carry -i, -k or -n (T31): %q", l.Num, l.Text)
		}
	}
	return problems
}

// sandboxMakeProblems lexes and parses src, then applies both checks.
func sandboxMakeProblems(src string) []string {
	lines, err := lexMakefile(src)
	if err != nil {
		return []string{"Makefile: " + err.Error()}
	}
	problems := checkIgnoreErrorForms(lines)
	mf, err := parseMakefile(src)
	if err != nil {
		return append(problems, "Makefile: "+err.Error())
	}
	return append(problems, checkSandboxChained(mf)...)
}

const sandboxFixture = `.PHONY: sandbox-guard sandbox-plan sandbox-apply sandbox-destroy

sandbox-guard:
	@test -x scripts/sandbox.sh || { echo "sandbox : scripts/sandbox.sh absent ; aucune action." >&2; exit 2; }

sandbox-plan: sandbox-guard
	@` + sandboxValidation + ` && ./scripts/sandbox.sh plan "$$SCENARIO"

sandbox-apply: sandbox-guard
	@` + sandboxValidation + ` && read -r -p "Appliquer $$SCENARIO sur le compte SANDBOX ? Tape 'oui' : " a </dev/tty && [ "$$a" = "oui" ] && ./scripts/sandbox.sh apply "$$SCENARIO"

sandbox-destroy: sandbox-guard
	@` + sandboxValidation + ` && read -r -p "Détruire $$SCENARIO sur le compte SANDBOX ? Tape 'oui' : " a </dev/tty && [ "$$a" = "oui" ] && ./scripts/sandbox.sh destroy "$$SCENARIO"
`

// TestSandboxRecipesChained proves the hardening of T31 on the Makefile of the
// repository, with negative controls on a synthetic Makefile.
func TestSandboxRecipesChained(t *testing.T) {
	_, repo := repoRoot(t)
	src, err := readRepoFile(repo, "Makefile", "M0-T01")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("repository", func(t *testing.T) { reportProblems(t, sandboxMakeProblems(src)) })

	f := sandboxFixture
	planCall := `@` + sandboxValidation + ` && ./scripts/sandbox.sh plan "$$SCENARIO"`
	applyRead := `a </dev/tty && [ "$$a" = "oui" ] && ./scripts/sandbox.sh apply`
	cases := []struct {
		name, src string
		want      []string
	}{
		{"valid", f, nil},
		{
			"two_lines", mustReplace(t, f, planCall, `@`+sandboxValidation+"\n\t./scripts/sandbox.sh plan \"$$SCENARIO\""),
			[]string{"target sandbox-plan must have exactly one recipe line"},
		},
		{
			"semicolon_after_read", mustReplace(t, f, applyRead, `a </dev/tty; [ "$$a" = "oui" ] && ./scripts/sandbox.sh apply`),
			[]string{"target sandbox-apply: recipe line outside the closed form"},
		},
		{
			"or_before_call", mustReplace(t, f, planCall, `@`+sandboxValidation+` || ./scripts/sandbox.sh plan "$$SCENARIO"`),
			[]string{"target sandbox-plan: recipe line outside the closed form"},
		},
		{
			"validation_without_exit", mustReplace(t, f, planCall, strings.Replace(planCall, "exit 2;", "true;", 1)),
			[]string{"target sandbox-plan: recipe line outside the closed form"},
		},
		{
			"substitution_in_prompt", mustReplace(t, f, `"Appliquer $$SCENARIO`, `"Appliquer $$(id) $$SCENARIO`),
			[]string{"target sandbox-apply: recipe line outside the closed form"},
		},
		{
			"backquote_in_prompt", mustReplace(t, f, `"Appliquer $$SCENARIO`, "\"Appliquer `id` $$SCENARIO"),
			[]string{"target sandbox-apply: recipe line outside the closed form"},
		},
		{"dash_prefix", mustReplace(t, f, "\t"+planCall, "\t-"+planCall), []string{"recipe prefix - ignores the failure"}},
		{"dash_after_at", mustReplace(t, f, "\t"+planCall, "\t@-"+planCall[1:]), []string{"recipe prefix - ignores the failure"}},
		{"plus_prefix", mustReplace(t, f, "\t"+planCall, "\t+"+planCall), []string{"recipe prefix + runs the line under -n"}},
		{"dash_prefix_other_target", f + "\nother:\n\t-false\n", []string{"recipe prefix - ignores the failure"}},
		{"ignore_special_target", f + "\n.IGNORE:\n", []string{".IGNORE ignores the failure"}},
		{"ignore_named_target", f + "\n.IGNORE: sandbox-apply\n", []string{".IGNORE ignores the failure"}},
		{"makeflags_assigned", f + "\nMAKEFLAGS += -i\n", []string{"MAKEFLAGS (or GNUMAKEFLAGS, MFLAGS) named"}},
		{"makeflags_shell", f + "\nother:\n\t@MAKEFLAGS= true\n", []string{"MAKEFLAGS (or GNUMAKEFLAGS, MFLAGS) named"}},
		{"makeflags_read", f + "\nother:\n\t@echo \"$$MAKEFLAGS\"\n", []string{"MAKEFLAGS (or GNUMAKEFLAGS, MFLAGS) named"}},
		{"gnumakeflags", f + "\nother:\n\t@GNUMAKEFLAGS=i true\n", []string{"MAKEFLAGS (or GNUMAKEFLAGS, MFLAGS) named"}},
		{"comment_admitted", f + "\n# MAKEFLAGS, .IGNORE et le préfixe - sont refusés (T31).\n", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { expectProblems(t, sandboxMakeProblems(c.src), c.want) })
	}
}

// TestSandboxIgnoreErrorsNeverCalls runs GNU make on a copy of the Makefile
// with a fake scripts/sandbox.sh that records its calls, in a new session with
// no controlling terminal (setsid): under make -i, MAKEFLAGS=i or -k, with the
// confirmation impossible or SCENARIO invalid, the script is never called. A
// control call (plan, valid scenario, no flag) proves the fake is reachable.
func TestSandboxIgnoreErrorsNeverCalls(t *testing.T) {
	for _, bin := range []string{"make", "setsid"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Fatalf("%s is required by this test (T31): %v", bin, err)
		}
	}
	_, repo := repoRoot(t)
	src, err := readRepoFile(repo, "Makefile", "M0-T01")
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	if err := os.WriteFile(filepath.Join(work, "Makefile"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(work, "scripts"), 0o700); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(work, "scripts", "sandbox.sh")
	if err := os.WriteFile(fake, []byte("#!/bin/bash\nprintf '%s\\n' \"$*\" >> \"$SANDBOX_LOG\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // G302: the fake script must be executable by its owner; temporary directory of this test.
	if err := os.Chmod(fake, 0o700); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(work, "calls.log")
	calls := func(t *testing.T) []string {
		t.Helper()
		data, err := os.ReadFile(logPath) //nolint:gosec // G304: temporary file of this test.
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		return strings.Fields(strings.ReplaceAll(string(data), " ", "_"))
	}
	run := func(t *testing.T, env []string, args ...string) scriptResult {
		t.Helper()
		_ = os.Remove(logPath)
		return runInEnv(t, work, append([]string{"SANDBOX_LOG=" + logPath}, env...), "setsid", append([]string{"-w", "make"}, args...)...)
	}

	t.Run("control_plan_calls_the_fake", func(t *testing.T) {
		res := run(t, []string{"SCENARIO=demo"}, "-f", "Makefile", "sandbox-plan")
		if got := calls(t); res.code != 0 || !slices.Equal(got, []string{"plan_demo"}) {
			t.Fatalf("make sandbox-plan SCENARIO=demo: code %d, calls %q, stderr %q; want code 0 and one call plan demo", res.code, got, res.stderr)
		}
	})
	cases := []struct {
		name string
		env  []string
		args []string
	}{
		{"apply_ignore_errors", []string{"SCENARIO=demo"}, []string{"-i", "-f", "Makefile", "sandbox-apply"}},
		{"destroy_ignore_errors", []string{"SCENARIO=demo"}, []string{"-i", "-f", "Makefile", "sandbox-destroy"}},
		{"apply_makeflags_i", []string{"SCENARIO=demo", "MAKEFLAGS=i"}, []string{"-f", "Makefile", "sandbox-apply"}},
		{"destroy_makeflags_ik", []string{"SCENARIO=demo", "MAKEFLAGS=ik"}, []string{"-f", "Makefile", "sandbox-destroy"}},
		{"apply_keep_going", []string{"SCENARIO=demo"}, []string{"-k", "-f", "Makefile", "sandbox-apply"}},
		{"destroy_ignore_and_keep_going", []string{"SCENARIO=demo"}, []string{"-i", "-k", "-f", "Makefile", "sandbox-destroy"}},
		{"plan_invalid_scenario_ignore_errors", []string{"SCENARIO=../x"}, []string{"-i", "-f", "Makefile", "sandbox-plan"}},
		{"plan_invalid_scenario_makeflags_i", []string{"SCENARIO=a;b", "MAKEFLAGS=i"}, []string{"-f", "Makefile", "sandbox-plan"}},
		{"plan_no_scenario_ignore_errors", nil, []string{"-i", "-f", "Makefile", "sandbox-plan"}},
		{"apply_invalid_scenario_ignore_errors", []string{"SCENARIO=BAD"}, []string{"-i", "-f", "Makefile", "sandbox-apply"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := run(t, c.env, c.args...)
			if got := calls(t); len(got) != 0 {
				t.Errorf("make %q with %q called scripts/sandbox.sh %q (code %d, stderr %q): T31", c.args, c.env, got, res.code, res.stderr)
			}
		})
	}
}
