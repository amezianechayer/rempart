package archtest

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Differential oracle of the Makefile parser of the tests (M0-T04b V2, D15,
// threat T32; docs/plans/M0-make-subcalls.md sections 3, 5.6 and 6). The lexer
// of parseMakefile refuses the forms on which it could disagree with GNU make;
// the oracle confronts what it read with the database of GNU make itself
// (make -p), to catch a divergence nobody has imagined yet: a makefile read in
// addition, a variable, target, prerequisite or recipe added or moved, an
// implicit rule, a warning. No recipe runs: the only goal is defined by --eval
// with neither prerequisite nor recipe, -n, -r (no built-in rule, so no rule
// remaking the Makefile), minimal environment. make missing, or not GNU Make
// 4.x, fails the test: it never passes it.

// makeOracleGoal: the only goal given to make; defined by --eval, with neither
// prerequisite nor recipe, so no recipe runs.
const makeOracleGoal = "__rempart_oracle__"

// makeDatabase is what GNU Make 4.x reports with -p after reading one makefile.
type makeDatabase struct {
	Code          int
	Stderr        string
	MakefileList  []string                // fields of MAKEFILE_LIST
	Vars          map[string][]int        // every "(from 'Makefile', line N)" variable header, any section
	Targets       map[string]makeDBTarget // "# Files" section, "# Not a target:" entries excluded
	ImplicitRules int                     // "# N implicit rules"
}

type makeDBTarget struct {
	Prereqs    []string // sorted
	RecipeLine int      // "recipe to execute (from 'Makefile', line N)", 0 if none
	Commands   int      // V3, D16: non-blank recipe lines printed under the entry
}

var (
	// "# makefile (from 'Makefile', line 5)", "# 'override' directive (from ...)".
	makeDBVarHeaderRe = regexp.MustCompile(`^# (.+) \(from '([^']*)', line ([0-9]+)\)$`)
	// The line after a variable header: "NAME = value", "NAME := value", or a
	// target-specific variable "target: NAME = value".
	makeDBVarLineRe  = regexp.MustCompile(`^(?:[^\s:]+ ?: )?([^\s:#=]+) :?=(?: |$)`)
	makeDBRecipeRe   = regexp.MustCompile(`^#  recipe to execute \(from '([^']*)', line ([0-9]+)\):$`)
	makeDBImplicitRe = regexp.MustCompile(`^# ([0-9]+) implicit rules, `)
	// A target entry of the "# Files" section: "name: prerequisites", "name:: ...".
	makeDBTargetRe = regexp.MustCompile(`^([^\s#:][^:]*?)(::?)(?: (.*))?$`)
)

// runMakeDatabase runs, in dir, through runInEnv (minimal environment: no
// MAKEFLAGS, MAKELEVEL, MAKEFILES, MAKE, MAKE_COMMAND, GNUMAKEFLAGS; LC_ALL=C;
// timeout 30 s):
//
//	make -n -r -p -f Makefile --eval=__rempart_oracle__: __rempart_oracle__
//
// It first checks that "make --version" starts with "GNU Make 4.": otherwise
// the test fails. A non-zero exit code returns the code and stderr only (O1
// then stop); otherwise the output must parse.
func runMakeDatabase(t *testing.T, dir string) makeDatabase {
	t.Helper()
	version := runInEnv(t, dir, nil, "make", "--version")
	if version.code != 0 || !strings.HasPrefix(version.stdout, "GNU Make 4.") {
		t.Fatalf("the oracle needs GNU Make 4.x (D15): make --version exited with code %d: %q", version.code, firstLine(version.stdout))
	}
	res := runInEnv(t, dir, nil, "make", "-n", "-r", "-p", "-f", "Makefile", "--eval="+makeOracleGoal+":", makeOracleGoal)
	if res.code != 0 {
		return makeDatabase{Code: res.code, Stderr: res.stderr}
	}
	db, err := parseMakeDatabase(res.stdout)
	if err != nil {
		t.Fatalf("make -p output (format drift, D15): %v", err)
	}
	db.Stderr = res.stderr
	return db
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

// parseMakeDatabase reads the standard output of make -p. A missing
// "# Variables", "# Files" or implicit rules count ("# N implicit rules" or
// "# No implicit rules."), a missing MAKEFILE_LIST, or a Makefile variable
// header not followed by a variable line is an error (format drift fails the
// test, it never passes it).
func parseMakeDatabase(out string) (makeDatabase, error) {
	db := makeDatabase{Vars: map[string][]int{}, Targets: map[string]makeDBTarget{}}
	lines := strings.Split(out, "\n")
	var sawVariables, sawFiles, sawImplicit, sawList, inFiles, notTarget bool
	current := "" // target entry whose recipe header may follow
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		switch line {
		case "# Variables":
			sawVariables = true
			continue
		case "# Files":
			sawFiles, inFiles = true, true
			continue
		case "# files hash-table stats:", "# VPATH Search Paths":
			inFiles, current = false, ""
			continue
		case "# No implicit rules.":
			sawImplicit = true
			continue
		}
		if m := makeDBImplicitRe.FindStringSubmatch(line); m != nil {
			n, err := strconv.Atoi(m[1])
			if err != nil {
				return db, fmt.Errorf("line %d: implicit rules count %q: %w", i+1, m[1], err)
			}
			db.ImplicitRules, sawImplicit = n, true
			continue
		}
		if m := makeDBVarHeaderRe.FindStringSubmatch(line); m != nil {
			if i+1 >= len(lines) {
				return db, fmt.Errorf("line %d: variable header %q at end of output", i+1, line)
			}
			next := lines[i+1]
			v := makeDBVarLineRe.FindStringSubmatch(next)
			if v == nil {
				return db, fmt.Errorf("line %d: variable header %q followed by %q, want NAME = ... or NAME := ...", i+1, line, next)
			}
			i++
			if v[1] == "MAKEFILE_LIST" && !inFiles {
				db.MakefileList, sawList = strings.Fields(strings.SplitN(next, "=", 2)[1]), true
			}
			if m[2] == "Makefile" {
				n, _ := strconv.Atoi(m[3])
				db.Vars[v[1]] = append(db.Vars[v[1]], n)
			}
			continue
		}
		if !inFiles {
			if strings.HasPrefix(line, "MAKEFILE_LIST :") {
				db.MakefileList, sawList = strings.Fields(strings.SplitN(line, "=", 2)[1]), true
			}
			continue
		}
		switch {
		case line == "# Not a target:":
			notTarget = true
		case strings.HasPrefix(line, "\t"):
			if current != "" && strings.TrimSpace(line) != "" {
				tg := db.Targets[current]
				tg.Commands++
				db.Targets[current] = tg
			}
		case line == "":
		case strings.HasPrefix(line, "#"):
			if m := makeDBRecipeRe.FindStringSubmatch(line); m != nil && current != "" {
				n, _ := strconv.Atoi(m[2])
				tg := db.Targets[current]
				tg.RecipeLine = n
				db.Targets[current] = tg
			}
		default:
			m := makeDBTargetRe.FindStringSubmatch(line)
			if m == nil {
				return db, fmt.Errorf("line %d: unreadable entry of the Files section: %q", i+1, line)
			}
			if notTarget {
				notTarget, current = false, ""
				continue
			}
			name := m[1]
			if m[2] == "::" {
				name += "::"
			}
			prereqs := strings.Fields(m[3])
			slices.Sort(prereqs)
			db.Targets[name] = makeDBTarget{Prereqs: prereqs}
			current = name
		}
	}
	var missing []string
	for _, s := range []struct {
		seen bool
		name string
	}{{sawVariables, "# Variables"}, {sawFiles, "# Files"}, {sawImplicit, "implicit rules count"}, {sawList, "MAKEFILE_LIST"}} {
		if !s.seen {
			missing = append(missing, s.name)
		}
	}
	if len(missing) > 0 {
		return db, errors.New("missing in make -p output: " + strings.Join(missing, ", "))
	}
	return db, nil
}

// compareMakeDatabase compares what parseMakefile read (mf) with what make
// read (db); base is the database of an empty Makefile read the same way,
// whose targets and implicit rules are subtracted (built-ins, oracle goal).
// Problems in the order O1 (then stop), O2, O3, O4 by name, O5 by name (V3,
// D16: target Makefile included when the parser read "Makefile: ;"), then a
// command make read under target Makefile (D16), O6.
func compareMakeDatabase(mf parsedMakefile, db, base makeDatabase) []string {
	var problems problemList
	if db.Code != 0 {
		problems.addf("make exited with code %d (oracle): %q", db.Code, db.Stderr)
		return problems
	}
	if db.Stderr != "" {
		problems.addf("make wrote on stderr (oracle): %q", db.Stderr)
	}
	if !slices.Equal(db.MakefileList, []string{"Makefile"}) {
		problems.addf("MAKEFILE_LIST is %q, want [Makefile] (oracle)", db.MakefileList)
	}

	// Variables. MAKEFILE_LIST (defined by make at line 1) is compared above.
	names := slices.Collect(maps.Keys(db.Vars))
	for name := range mf.Vars {
		if _, ok := db.Vars[name]; !ok {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	for _, name := range names {
		if name == "MAKEFILE_LIST" {
			continue
		}
		var want []int
		if l, ok := mf.Vars[name]; ok {
			want = []int{l}
		}
		if got := db.Vars[name]; !slices.Equal(got, want) {
			problems.addf("variable %s: make defines it at lines %v, the test parser at %v (oracle)", name, got, want)
		}
	}

	// Targets: make's minus the identical entries of the empty Makefile.
	got := map[string]makeDBTarget{}
	for name, tg := range db.Targets {
		if b, ok := base.Targets[name]; ok && slices.Equal(b.Prereqs, tg.Prereqs) && b.RecipeLine == tg.RecipeLine {
			continue
		}
		got[name] = tg
	}
	want := map[string]makeDBTarget{}
	for name, r := range mf.Rules {
		prereqs := slices.Clone(r.Prereqs)
		slices.Sort(prereqs)
		want[name] = makeDBTarget{Prereqs: prereqs, RecipeLine: r.RecipeLine}
	}
	if mf.SelfRule != 0 { // V3, D16: "Makefile: ;", an empty recipe at its line
		want["Makefile"] = makeDBTarget{RecipeLine: mf.SelfRule}
	}
	phony := slices.Sorted(maps.Keys(mf.Phony))
	want[".PHONY"] = makeDBTarget{Prereqs: phony}
	targets := slices.Collect(maps.Keys(got))
	for name := range want {
		if _, ok := got[name]; !ok {
			targets = append(targets, name)
		}
	}
	slices.Sort(targets)
	for _, name := range targets {
		g, gok := got[name]
		w, wok := want[name]
		if gok != wok || !slices.Equal(g.Prereqs, w.Prereqs) || g.RecipeLine != w.RecipeLine {
			problems.addf("target %s: make read %s, the test parser %s (oracle)", name, describeDBTarget(g, gok), describeDBTarget(w, wok))
		}
	}

	if tg, ok := got["Makefile"]; ok && tg.Commands != 0 {
		problems.addf("target Makefile: make read %d recipe commands, want none (D16, oracle)", tg.Commands)
	}

	if n := db.ImplicitRules - base.ImplicitRules; n != 0 {
		problems.addf("%d implicit rules defined by the Makefile, want 0 (oracle)", n)
	}
	return problems
}

func describeDBTarget(tg makeDBTarget, ok bool) string {
	if !ok {
		return "no such target"
	}
	return fmt.Sprintf("prerequisites %q, recipe line %d", tg.Prereqs, tg.RecipeLine)
}

// writeOracleMakefile writes src as Makefile, and each extra file, in a fresh
// directory and returns it.
func writeOracleMakefile(t *testing.T, src string, extra map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{"Makefile": src}
	maps.Copy(files, extra)
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// mustParseMakefile is parseMakefile for an input the grammar accepts: the
// oracle never runs make after a refused parse.
func mustParseMakefile(t *testing.T, src string) parsedMakefile {
	t.Helper()
	mf, err := parseMakefile(src)
	if err != nil {
		t.Fatalf("parseMakefile (the oracle runs make only on an accepted Makefile): %v", err)
	}
	return mf
}

// TestMakefileOracle (M0-T04b V2, D15, T32): subtests
// negative_controls/<name>, positive_controls/<name>, repository. A negative
// control runs make on the template plus lines the parser did not see (the
// facts of the parser are those of the template alone) and wants exactly the
// listed problems, in order.
func TestMakefileOracle(t *testing.T) {
	base := runMakeDatabase(t, writeOracleMakefile(t, "", nil))
	template := mustParseMakefile(t, targetMakefile)
	templateLines := strings.Count(targetMakefile, "\n")
	selfLine := exactLine(t, targetMakefile, "Makefile: ;")

	type oracleCase struct {
		name  string
		src   string            // Makefile read by make
		extra map[string]string // other files of the directory
		mf    parsedMakefile    // what the parser read
		want  []string          // fragments, one per problem, in order; nil: none
	}
	negatives := []oracleCase{
		{ // OC1
			name: "extra_makefile", src: targetMakefile + "include extra.mk\n", extra: map[string]string{"extra.mk": "# vide\n"}, mf: template,
			want: []string{fmt.Sprintf("MAKEFILE_LIST is %q, want [Makefile] (oracle)", []string{"Makefile", "extra.mk"})},
		},
		{ // OC2, form of N1c without the comment
			name: "hidden_duplicate_recipe", src: targetMakefile + "verify-quick:\n\t@echo SHADOW-dup\n", mf: template,
			want: []string{
				"make wrote on stderr (oracle): \"Makefile:" + strconv.Itoa(templateLines+2) + ": warning: overriding recipe for target 'verify-quick'",
				fmt.Sprintf("target verify-quick: make read prerequisites [], recipe line %d, the test parser prerequisites [], recipe line %d (oracle)",
					templateLines+2, template.Rules["verify-quick"].RecipeLine),
			},
		},
		{ // OC3
			name: "hidden_assignment", src: targetMakefile + "EXTRA_X := 1\n", mf: template,
			want: []string{fmt.Sprintf("variable EXTRA_X: make defines it at lines [%d], the test parser at [] (oracle)", templateLines+1)},
		},
		{ // OC4
			name: "hidden_target", src: targetMakefile + "extra:\n", mf: template,
			want: []string{"target extra: make read prerequisites [], recipe line 0, the test parser no such target (oracle)"},
		},
		{ // OC5
			name: "hidden_pattern_rule", src: targetMakefile + "%.x:\n\t@true\n", mf: template,
			want: []string{"1 implicit rules defined by the Makefile, want 0 (oracle)"},
		},
		{ // OC6
			name: "missing_include", src: targetMakefile + "include absent.mk\n", mf: template,
			want: []string{"make exited with code 2 (oracle): \"Makefile:" + strconv.Itoa(templateLines+1) + ": absent.mk: No such file or directory"},
		},
		// V3, D16: make reads the rule "Makefile: ;" (target Makefile, no
		// prerequisite, empty recipe at its line) exactly when the parser does.
		{ // OC7
			name: "self_rule_unseen_by_parser", src: targetMakefile, mf: withoutSelfRule(template),
			want: []string{fmt.Sprintf("target Makefile: make read prerequisites [], recipe line %d, the test parser no such target (oracle)", selfLine)},
		},
		{ // OC8, the line blanked: every other line keeps its number
			name: "self_rule_absent_for_make", src: mustReplace(t, targetMakefile, "\nMakefile: ;\n", "\n\n"), mf: template,
			want: []string{fmt.Sprintf("target Makefile: make read no such target, the test parser prerequisites [], recipe line %d (oracle)", selfLine)},
		},
		{ // OC9, a command make would run to remake the Makefile, hidden from the parser
			name: "self_rule_hidden_command", src: mustReplace(t, targetMakefile, "\nMakefile: ;\n", "\nMakefile: ; @true\n"), mf: template,
			want: []string{"target Makefile: make read 1 recipe commands, want none (D16, oracle)"},
		},
	}
	reference := referenceDevMakefile(t)
	positives := []oracleCase{
		{name: "valid_template", src: targetMakefile, mf: template},                           // OP1
		{name: "reference_dev_makefile", src: reference, mf: mustParseMakefile(t, reference)}, // OP2
	}

	run := func(t *testing.T, cases []oracleCase) {
		t.Helper()
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				problems := compareMakeDatabase(tc.mf, runMakeDatabase(t, writeOracleMakefile(t, tc.src, tc.extra)), base)
				if len(problems) != len(tc.want) {
					t.Fatalf("%d problems, want %d (%q):\n%s", len(problems), len(tc.want), tc.want, strings.Join(problems, "\n"))
				}
				for i, w := range tc.want {
					if !strings.Contains(problems[i], w) {
						t.Errorf("problem %d = %q, want it to mention %q", i+1, problems[i], w)
					}
				}
			})
		}
	}
	t.Run("negative_controls", func(t *testing.T) { run(t, negatives) })
	t.Run("positive_controls", func(t *testing.T) { run(t, positives) })

	t.Run("repository", func(t *testing.T) {
		dir, fsys := repoRoot(t)
		src, err := readRepoFile(fsys, "Makefile", "created by M0-T01")
		if err != nil {
			t.Fatal(err)
		}
		mf := mustParseMakefile(t, src)
		db := runMakeDatabase(t, dir)
		reportProblems(t, compareMakeDatabase(mf, db, base))
		// V3, D16: make itself holds the rule that stops it from remaking the Makefile.
		if tg, ok := db.Targets["Makefile"]; !ok || len(tg.Prereqs) != 0 || tg.Commands != 0 {
			t.Errorf("make database: target Makefile %s, want prerequisites [] and no command (rule \"Makefile: ;\", D16)", describeDBTarget(tg, ok))
		}
	})
}

// withoutSelfRule returns mf as the parser would have read it without the rule
// "Makefile: ;" (V3, D16).
func withoutSelfRule(mf parsedMakefile) parsedMakefile {
	mf.SelfRule = 0
	return mf
}
