package archtest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// Checks of the development stack scripts (docs/plans/M0-pile-dev.md section
// 4.2): scripts/dev-env.sh is run for real by bash in a temporary Git work
// tree (no Docker, no network); scripts/dev/postgres-init.sh is checked
// statically. No message ever contains a secret value: every 64-digit
// hexadecimal run is redacted before being reported.

// devEnvKeys are the variables of .env.dev, in their mandatory order.
func devEnvKeys() []string {
	return []string{"POSTGRES_PASSWORD", "TEMPORAL_DB_PASSWORD", "REMPART_DB_PASSWORD", "OPENBAO_DEV_ROOT_TOKEN"}
}

var (
	hex64Re        = regexp.MustCompile(`[0-9a-f]{64}`)
	devEnvLineRe   = regexp.MustCompile(`^([A-Z][A-Z0-9_]*)=([0-9a-f]{64})$`)
	devEnvSourceRe = regexp.MustCompile(`(^|[;&|({]\s*|\bthen\s+|\bdo\s+|\s)(source|eval)(\s|$)`)
	devEnvDotRe    = regexp.MustCompile(`(^|[;&|({]\s*|\bthen\s+|\bdo\s+)\.\s+\S`)
)

// redactHex hides every 64-digit hexadecimal run (the format of the values of
// .env.dev) in a text meant for a test message.
func redactHex(s string) string { return hex64Re.ReplaceAllString(s, "[redacted]") }

// fixtureValue is a deterministic, distinct, well-formed value per key. It is
// not a secret: it only exists in temporary directories of these tests.
func fixtureValue(key string) string {
	sum := sha256.Sum256([]byte("rempart-test-fixture/" + key))
	return hex.EncodeToString(sum[:])
}

// fixtureLines returns the four well-formed lines of a valid .env.dev.
func fixtureLines() []string {
	lines := make([]string, 0, len(devEnvKeys()))
	for _, k := range devEnvKeys() {
		lines = append(lines, k+"="+fixtureValue(k))
	}
	return lines
}

// scriptResult is the outcome of one process run by these tests.
type scriptResult struct {
	code   int
	stdout string
	stderr string
}

func (r scriptResult) output() string { return redactHex(r.stdout + r.stderr) }

// runIn runs name with args in dir, with a minimal environment (no variable of
// the calling process leaks into it, in particular no secret exported by
// dev-env.sh run) and a 30 s deadline.
func runIn(t *testing.T, dir, name string, args ...string) scriptResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	//nolint:gosec // G204: test helper, name and args are literals of these tests or temporary paths.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"TMPDIR=" + t.TempDir(),
		"LC_ALL=C",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
	}
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	res := scriptResult{stdout: stdout.String(), stderr: stderr.String()}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		res.code = exitErr.ExitCode()
	default:
		t.Fatalf("%s %q: %v", name, args, err)
	}
	return res
}

// devEnvWorkspace describes the Git state of the directory dev-env.sh runs in.
type devEnvWorkspace int

const (
	wsIgnored      devEnvWorkspace = iota // Git work tree ignoring .env.*
	wsNoGitignore                         // Git work tree without .gitignore
	wsOtherIgnored                        // Git work tree ignoring .env only
	wsNoGit                               // plain directory, not a Git work tree
)

// newWorkspace creates a temporary directory for dev-env.sh.
func newWorkspace(t *testing.T, kind devEnvWorkspace) string {
	t.Helper()
	for _, tool := range []string{"bash", "git"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s is required by these tests: %v", tool, err)
		}
	}
	dir := t.TempDir()
	if kind == wsNoGit {
		return dir
	}
	if r := runIn(t, dir, "git", "init", "-q"); r.code != 0 {
		t.Fatalf("git init: exit %d: %s", r.code, r.output())
	}
	var ignore string
	switch kind {
	case wsIgnored:
		ignore = ".env.*\n"
	case wsOtherIgnored:
		ignore = ".env\n"
	default:
		return dir
	}
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(ignore), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// writeScript writes the script under test outside the workspace and returns its path.
func writeScript(t *testing.T, src string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dev-env.sh")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeEnvFile writes .env.dev in dir with the given lines and mode.
func writeEnvFile(t *testing.T, dir string, lines []string, mode fs.FileMode) {
	t.Helper()
	path := filepath.Join(dir, ".env.dev")
	content := ""
	if len(lines) > 0 {
		content = strings.Join(lines, "\n") + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// readEnvFile reads .env.dev of dir as lines; ok is false if it does not exist.
func readEnvFile(t *testing.T, dir string) (lines []string, ok bool) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, ".env.dev"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n"), true
}

// leftoverTemps lists the files of dir named .env.dev.* (temporary files of ensure).
func leftoverTemps(t *testing.T, dir string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".env.dev.*"))
	if err != nil {
		t.Fatal(err)
	}
	for i, m := range matches {
		matches[i] = filepath.Base(m)
	}
	return matches
}

func exists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	return true
}

// expectExit reports a problem if r.code is not want.
func expectExit(problems *problemList, what string, r scriptResult, want int) {
	if r.code != want {
		problems.addf("%s: exit %d, want %d; output: %q", what, r.code, want, r.output())
	}
}

// checkGeneratedFile checks a .env.dev written by ensure: regular file, mode
// 600, the four keys in order, 64 hexadecimal digits each, distinct values.
func checkGeneratedFile(t *testing.T, dir string, problems *problemList) []string {
	t.Helper()
	info, err := os.Lstat(filepath.Join(dir, ".env.dev"))
	if errors.Is(err, fs.ErrNotExist) {
		problems.addf("ensure: .env.dev not created")
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		problems.addf("ensure: .env.dev is not a regular file (mode %v)", info.Mode())
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		problems.addf("ensure: .env.dev has mode %o, want 600", perm)
	}
	lines, _ := readEnvFile(t, dir)
	var keys, values []string
	for i, l := range lines {
		m := devEnvLineRe.FindStringSubmatch(l)
		if m == nil {
			problems.addf("ensure: .env.dev line %d is not KEY=<64 lowercase hex digits>: %q", i+1, redactHex(l))
			continue
		}
		keys = append(keys, m[1])
		values = append(values, m[2])
	}
	if !slices.Equal(keys, devEnvKeys()) {
		problems.addf("ensure: .env.dev keys are %q, want %q in this order", keys, devEnvKeys())
	}
	sorted := slices.Sorted(slices.Values(values))
	if len(slices.Compact(sorted)) != len(values) {
		problems.addf("ensure: .env.dev values are not distinct")
	}
	if tmp := leftoverTemps(t, dir); len(tmp) > 0 {
		problems.addf("ensure: temporary files left behind: %q", tmp)
	}
	return values
}

// devEnvCheck is one behaviour of dev-env.sh; it returns the departures of the
// script at path from that behaviour.
type devEnvCheck struct {
	name string
	run  func(t *testing.T, script string) []string
}

func devEnvChecks() []devEnvCheck {
	return []devEnvCheck{
		{"creates_file", checkDevEnvCreatesFile},
		{"idempotent", checkDevEnvIdempotent},
		{"output_has_no_secret", checkDevEnvOutputHasNoSecret},
		{"not_ignored", checkDevEnvNotIgnored},
		{"world_readable", checkDevEnvWorldReadable},
		{"symlink", checkDevEnvSymlink},
		{"malformed_line", checkDevEnvMalformedLine},
		{"missing_key", checkDevEnvMissingKey},
		{"run_exports", checkDevEnvRunExports},
		{"run_without_command", checkDevEnvRunWithoutCommand},
	}
}

func checkDevEnvCreatesFile(t *testing.T, script string) []string {
	var problems problemList
	dir := newWorkspace(t, wsIgnored)
	expectExit(&problems, "ensure on an empty work tree", runIn(t, dir, "bash", script, "ensure"), 0)
	checkGeneratedFile(t, dir, &problems)
	return problems
}

func checkDevEnvIdempotent(t *testing.T, script string) []string {
	var problems problemList
	dir := newWorkspace(t, wsIgnored)
	expectExit(&problems, "first ensure", runIn(t, dir, "bash", script, "ensure"), 0)
	first, _ := readEnvFile(t, dir)
	expectExit(&problems, "second ensure", runIn(t, dir, "bash", script, "ensure"), 0)
	second, _ := readEnvFile(t, dir)
	if !slices.Equal(first, second) {
		problems.addf("second ensure rewrote .env.dev (values must be generated once)")
	}
	checkGeneratedFile(t, dir, &problems)

	// An existing valid file is kept as is.
	dir = newWorkspace(t, wsIgnored)
	writeEnvFile(t, dir, fixtureLines(), 0o600)
	expectExit(&problems, "ensure on an existing valid .env.dev", runIn(t, dir, "bash", script, "ensure"), 0)
	if got, _ := readEnvFile(t, dir); !slices.Equal(got, fixtureLines()) {
		problems.addf("ensure rewrote an existing valid .env.dev")
	}
	return problems
}

func checkDevEnvOutputHasNoSecret(t *testing.T, script string) []string {
	var problems problemList
	dir := newWorkspace(t, wsIgnored)
	runs := []struct {
		what string
		res  scriptResult
	}{
		{"first ensure", runIn(t, dir, "bash", script, "ensure")},
		{"second ensure", runIn(t, dir, "bash", script, "ensure")},
		{"run true", runIn(t, dir, "bash", script, "run", "true")},
	}
	lines, ok := readEnvFile(t, dir)
	if !ok {
		problems.addf("ensure: .env.dev not created")
		return problems
	}
	for _, l := range lines {
		k, v, found := strings.Cut(l, "=")
		if !found || v == "" {
			continue
		}
		for _, r := range runs {
			if strings.Contains(r.stdout, v) || strings.Contains(r.stderr, v) {
				problems.addf("%s: output contains the value of %s", r.what, k)
			}
		}
	}
	return problems
}

func checkDevEnvNotIgnored(t *testing.T, script string) []string {
	var problems problemList
	for _, ws := range []struct {
		name string
		kind devEnvWorkspace
	}{
		{"work tree without .gitignore", wsNoGitignore},
		{"work tree ignoring .env only", wsOtherIgnored},
		{"directory outside Git", wsNoGit},
	} {
		dir := newWorkspace(t, ws.kind)
		expectExit(&problems, "ensure in a "+ws.name, runIn(t, dir, "bash", script, "ensure"), 2)
		if exists(t, filepath.Join(dir, ".env.dev")) {
			problems.addf("ensure in a %s wrote .env.dev (it must refuse to write a file Git would commit)", ws.name)
		}
		if tmp := leftoverTemps(t, dir); len(tmp) > 0 {
			problems.addf("ensure in a %s left temporary files %q", ws.name, tmp)
		}
	}
	return problems
}

func checkDevEnvWorldReadable(t *testing.T, script string) []string {
	var problems problemList
	for _, mode := range []fs.FileMode{0o644, 0o640, 0o604, 0o700} {
		dir := newWorkspace(t, wsIgnored)
		writeEnvFile(t, dir, fixtureLines(), mode)
		expectExit(&problems, "run touch ran with .env.dev in mode "+mode.String(), runIn(t, dir, "bash", script, "run", "touch", "ran"), 2)
		if exists(t, filepath.Join(dir, "ran")) {
			problems.addf("run executed its command with .env.dev in mode %v", mode)
		}
		expectExit(&problems, "ensure with .env.dev in mode "+mode.String(), runIn(t, dir, "bash", script, "ensure"), 2)
		if got, _ := readEnvFile(t, dir); !slices.Equal(got, fixtureLines()) {
			problems.addf("ensure rewrote .env.dev in mode %v instead of refusing it", mode)
		}
	}
	return problems
}

func checkDevEnvSymlink(t *testing.T, script string) []string {
	var problems problemList
	// Link to a valid file elsewhere.
	dir := newWorkspace(t, wsIgnored)
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte(strings.Join(fixtureLines(), "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, ".env.dev")); err != nil {
		t.Fatal(err)
	}
	expectExit(&problems, "run touch ran with .env.dev a symlink", runIn(t, dir, "bash", script, "run", "touch", "ran"), 2)
	if exists(t, filepath.Join(dir, "ran")) {
		problems.addf("run executed its command with .env.dev a symlink")
	}
	expectExit(&problems, "ensure with .env.dev a symlink", runIn(t, dir, "bash", script, "ensure"), 2)
	if data, err := os.ReadFile(target); err != nil || string(data) != strings.Join(fixtureLines(), "\n")+"\n" {
		problems.addf("ensure modified the target of the .env.dev symlink")
	}

	// Dangling link: ensure must not create its target.
	dir = newWorkspace(t, wsIgnored)
	dangling := filepath.Join(t.TempDir(), "planted")
	if err := os.Symlink(dangling, filepath.Join(dir, ".env.dev")); err != nil {
		t.Fatal(err)
	}
	expectExit(&problems, "ensure with .env.dev a dangling symlink", runIn(t, dir, "bash", script, "ensure"), 2)
	if exists(t, dangling) {
		problems.addf("ensure wrote through a dangling .env.dev symlink")
	}
	return problems
}

// malformedEnvCases are .env.dev files with valid keys but one bad line.
func malformedEnvCases() map[string][]string {
	valid := fixtureLines()
	with := func(i int, line string) []string {
		out := slices.Clone(valid)
		out[i] = line
		return out
	}
	v0 := fixtureValue("POSTGRES_PASSWORD")
	return map[string][]string{
		"command_substitution_key":   with(0, "X=$(touch pwned)"),
		"command_substitution_value": with(0, "POSTGRES_PASSWORD=$(touch pwned)"),
		"backticks_value":            with(0, "POSTGRES_PASSWORD=`touch pwned`"),
		"short_value":                with(0, "POSTGRES_PASSWORD="+v0[:63]),
		"long_value":                 with(0, "POSTGRES_PASSWORD="+v0+"0"),
		"uppercase_hex":              with(0, "POSTGRES_PASSWORD="+strings.ToUpper(v0)),
		"trailing_space":             with(0, "POSTGRES_PASSWORD="+v0+" "),
		"trailing_command":           with(0, "POSTGRES_PASSWORD="+v0+";touch pwned"),
		"export_prefix":              with(0, "export POSTGRES_PASSWORD="+v0),
		"space_around_equal":         with(0, "POSTGRES_PASSWORD = "+v0),
		"quoted_value":               with(0, "POSTGRES_PASSWORD=\""+v0+"\""),
		"crlf":                       with(0, "POSTGRES_PASSWORD="+v0+"\r"),
		"lowercase_key":              with(0, "postgres_password="+v0),
		"empty_line":                 append(slices.Clone(valid), ""),
		"comment_line":               append([]string{"# comment"}, valid...),
	}
}

func checkDevEnvMalformedLine(t *testing.T, script string) []string {
	var problems problemList
	cases := malformedEnvCases()
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for k := range cases {
			if !yield(k) {
				return
			}
		}
	}) {
		dir := newWorkspace(t, wsIgnored)
		writeEnvFile(t, dir, cases[name], 0o600)
		expectExit(&problems, "run touch ran with a malformed line ("+name+")", runIn(t, dir, "bash", script, "run", "touch", "ran"), 2)
		if exists(t, filepath.Join(dir, "ran")) {
			problems.addf("run executed its command despite a malformed line (%s)", name)
		}
		if exists(t, filepath.Join(dir, "pwned")) {
			problems.addf("a malformed line (%s) was evaluated by the shell: pwned created", name)
		}
	}
	return problems
}

func checkDevEnvMissingKey(t *testing.T, script string) []string {
	var problems problemList
	valid := fixtureLines()
	cases := []struct {
		name  string
		lines []string
	}{
		{"missing_last_key", valid[:3]},
		{"missing_first_key", valid[1:]},
		{"empty_file", nil},
		{"wrong_order", []string{valid[1], valid[0], valid[2], valid[3]}},
		{"duplicate_key", []string{valid[0], valid[1], valid[2], valid[3], valid[3]}},
		{"extra_key", append(slices.Clone(valid), "LD_PRELOAD="+fixtureValue("LD_PRELOAD"))},
		{"extra_key_first", append([]string{"BASH_ENV=" + fixtureValue("BASH_ENV")}, valid...)},
	}
	for _, c := range cases {
		dir := newWorkspace(t, wsIgnored)
		writeEnvFile(t, dir, c.lines, 0o600)
		expectExit(&problems, "run touch ran ("+c.name+")", runIn(t, dir, "bash", script, "run", "touch", "ran"), 2)
		if exists(t, filepath.Join(dir, "ran")) {
			problems.addf("run executed its command with the wrong keys (%s)", c.name)
		}
		expectExit(&problems, "ensure ("+c.name+")", runIn(t, dir, "bash", script, "ensure"), 2)
	}
	return problems
}

func checkDevEnvRunExports(t *testing.T, script string) []string {
	var problems problemList
	dir := newWorkspace(t, wsIgnored)
	writeEnvFile(t, dir, fixtureLines(), 0o600)

	r := runIn(t, dir, "bash", script, "run", "env")
	expectExit(&problems, "run env", r, 0)
	got := map[string]string{}
	for _, l := range strings.Split(r.stdout, "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			got[k] = v
		}
	}
	for _, k := range devEnvKeys() {
		switch v, ok := got[k]; {
		case !ok:
			problems.addf("run env: %s not exported", k)
		case v != fixtureValue(k):
			problems.addf("run env: %s exported with another value than the one of .env.dev", k)
		}
	}

	r = runIn(t, dir, "bash", script, "run", "printf", "%s|", "a b", "$HOME", "c")
	expectExit(&problems, "run printf", r, 0)
	if r.stdout != "a b|$HOME|c|" {
		problems.addf("run printf: arguments not passed verbatim, got %q, want %q", r.stdout, "a b|$HOME|c|")
	}

	r = runIn(t, dir, "bash", script, "run", "bash", "-c", "exit 7")
	expectExit(&problems, "run bash -c 'exit 7' (exit status of the command)", r, 7)
	return problems
}

func checkDevEnvRunWithoutCommand(t *testing.T, script string) []string {
	var problems problemList
	dir := newWorkspace(t, wsIgnored)
	writeEnvFile(t, dir, fixtureLines(), 0o600)
	expectExit(&problems, "run without command", runIn(t, dir, "bash", script, "run"), 2)
	expectExit(&problems, "no subcommand", runIn(t, dir, "bash", script), 2)
	expectExit(&problems, "unknown subcommand", runIn(t, dir, "bash", script, "print"), 2)
	return problems
}

// checkDevEnvStatic: umask 077 before anything but set -euo pipefail, and the
// file is never evaluated by the shell (no source, no eval, no dot-sourcing).
func checkDevEnvStatic(src string) []string {
	var problems problemList
	var statements []string
	for i, l := range strings.Split(src, "\n") {
		text := strings.TrimSpace(l)
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		statements = append(statements, text)
		if devEnvSourceRe.MatchString(text) || devEnvDotRe.MatchString(text) {
			problems.addf("scripts/dev-env.sh line %d: the shell must never evaluate a file or a string (source, eval, .): %q", i+1, redactHex(l))
		}
	}
	umask := slices.Index(statements, "umask 077")
	switch {
	case umask < 0:
		problems.addf("scripts/dev-env.sh: umask 077 missing")
	case !slices.Equal(statements[:umask], []string{"set -euo pipefail"}):
		problems.addf("scripts/dev-env.sh: umask 077 must be the first statement after set -euo pipefail, found after %q", statements[:umask])
	}
	return problems
}

// referenceDevEnv is scripts/dev-env.sh of docs/plans/M0-pile-dev.md section
// 3.2, verbatim.
const referenceDevEnv = `#!/usr/bin/env bash
# Secrets de la pile de dev (M0-T03), depuis la racine du dépôt. N'affiche aucune valeur.
#   ensure          crée .env.dev s'il manque (600), puis le valide
#   run CMD [ARG]   valide .env.dev, exporte ses variables, exécute CMD
set -euo pipefail
umask 077
readonly file=.env.dev
readonly keys=(POSTGRES_PASSWORD TEMPORAL_DB_PASSWORD REMPART_DB_PASSWORD OPENBAO_DEV_ROOT_TOKEN)
die() { echo "dev-env : $*" >&2; exit 2; }
gen() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }

check() {
  [[ -f $file && ! -L $file ]] || die "$file absent ou lien symbolique (lance make dev)."
  local mode; mode=$(stat -c %a "$file" 2>/dev/null || stat -f %Lp "$file")
  [[ $mode == 600 ]] || die "$file doit avoir les droits 600 (actuels : $mode)."
  local -a seen=(); local line n=0
  while IFS= read -r line || [[ -n $line ]]; do
    n=$((n + 1))
    [[ $line =~ ^([A-Z][A-Z0-9_]*)=[0-9a-f]{64}$ ]] || die "$file : ligne $n mal formée."
    seen+=("${BASH_REMATCH[1]}")
  done <"$file"
  [[ "${seen[*]}" == "${keys[*]}" ]] || die "$file : clés attendues ${keys[*]}, dans cet ordre."
}

ensure() {
  git check-ignore -q -- "$file" || die "$file n'est pas ignoré par Git : refus d'écrire."
  if [[ ! -e $file && ! -L $file ]]; then
    local tmp; tmp=$(mktemp .env.dev.XXXXXX)
    trap 'rm -f -- "$tmp"' EXIT
    for k in "${keys[@]}"; do printf '%s=%s\n' "$k" "$(gen)"; done >"$tmp"
    mv -- "$tmp" "$file"
    trap - EXIT
  fi
  check
}

run() {
  (($# > 0)) || die "usage : dev-env.sh run CMD [ARG...]"
  check
  local k v
  while IFS='=' read -r k v; do export "$k=$v"; done <"$file"
  exec "$@"
}

case "${1:-}" in
  ensure) ensure ;;
  run) shift; run "$@" ;;
  *) die "usage : dev-env.sh ensure | run CMD [ARG...]" ;;
esac
`

func TestDevEnvScript(t *testing.T) {
	t.Run("negative_controls", func(t *testing.T) {
		checks := map[string]devEnvCheck{}
		for _, c := range devEnvChecks() {
			checks[c.name] = c
			t.Run("reference/"+c.name, func(t *testing.T) {
				expectProblems(t, c.run(t, writeScript(t, referenceDevEnv)), nil)
			})
		}
		t.Run("reference/umask_first", func(t *testing.T) { expectProblems(t, checkDevEnvStatic(referenceDevEnv), nil) })

		mutations := []struct {
			name, check, old, replacement string
			want                          []string
		}{
			{
				name: "no_mode_check", check: "world_readable", // mutation 17
				old:  "  [[ $mode == 600 ]] || die \"$file doit avoir les droits 600 (actuels : $mode).\"\n",
				want: []string{"with .env.dev in mode -rw-r--r--: exit 0, want 2", "run executed its command with .env.dev in mode -rw-r--r--"},
			},
			{
				name: "lax_value_format", check: "malformed_line", // mutation 18
				old: "=[0-9a-f]{64}$ ]]", replacement: "=.*$ ]]",
				want: []string{"malformed line (command_substitution_value): exit 0, want 2", "run executed its command despite a malformed line (short_value)"},
			},
			{
				name: "no_ignore_check", check: "not_ignored", // mutation 19
				old:  "  git check-ignore -q -- \"$file\" || die \"$file n'est pas ignoré par Git : refus d'écrire.\"\n",
				want: []string{"ensure in a work tree without .gitignore: exit 0, want 2", "wrote .env.dev"},
			},
			{
				name: "run_skips_check", check: "world_readable",
				old: "  check\n  local k v\n", replacement: "  local k v\n",
				want: []string{"run executed its command with .env.dev in mode"},
			},
			{
				name: "keys_not_checked", check: "missing_key",
				old:  "  [[ \"${seen[*]}\" == \"${keys[*]}\" ]] || die \"$file : clés attendues ${keys[*]}, dans cet ordre.\"\n",
				want: []string{"run executed its command with the wrong keys (missing_last_key)", "(extra_key_first)"},
			},
			{
				name: "symlink_followed", check: "symlink",
				old: "[[ -f $file && ! -L $file ]]", replacement: "[[ -f $file ]]",
				want: []string{},
			},
			{
				name: "constant_generator", check: "creates_file",
				old: "gen() { od -An -N32 -tx1 /dev/urandom | tr -d ' \\n'; }", replacement: "gen() { printf '%064d' 0; }",
				want: []string{"values are not distinct"},
			},
			{
				name: "short_generator", check: "creates_file",
				old: "-N32", replacement: "-N16",
				want: []string{"is not KEY=<64 lowercase hex digits>"},
			},
			{
				name: "regenerates", check: "idempotent",
				old: "  if [[ ! -e $file && ! -L $file ]]; then\n", replacement: "  if true; then\n",
				want: []string{"second ensure rewrote .env.dev", "ensure rewrote an existing valid .env.dev"},
			},
			{
				name: "prints_values", check: "output_has_no_secret",
				old: "  check\n}\n\nrun() {", replacement: "  check\n  cat -- \"$file\" >&2\n}\n\nrun() {",
				want: []string{"first ensure: output contains the value of POSTGRES_PASSWORD", "OPENBAO_DEV_ROOT_TOKEN"},
			},
			{
				name: "missing_command_accepted", check: "run_without_command",
				old:  "  (($# > 0)) || die \"usage : dev-env.sh run CMD [ARG...]\"\n",
				want: []string{"run without command: exit 0, want 2"},
			},
			{
				name: "command_not_exec", check: "run_exports",
				old: "  exec \"$@\"\n", replacement: "  \"$@\" || true\n",
				want: []string{"(exit status of the command): exit 0, want 7"},
			},
		}
		for _, m := range mutations {
			t.Run(m.name, func(t *testing.T) {
				mutated := mustReplace(t, referenceDevEnv, m.old, m.replacement)
				if len(m.want) == 0 {
					// Documented non-detection: the mode check (stat of the link
					// itself, 777) still refuses the link; the behaviour holds.
					expectProblems(t, checks[m.check].run(t, writeScript(t, mutated)), nil)
					return
				}
				expectProblems(t, checks[m.check].run(t, writeScript(t, mutated)), m.want)
			})
		}

		static := []struct{ name, old, replacement, want string }{
			{"no_umask", "umask 077\n", "", "umask 077 missing"},
			{"umask_late", "umask 077\nreadonly file=.env.dev\n", "readonly file=.env.dev\numask 077\n", "umask 077 must be the first statement"},
			{"no_set_e", "set -euo pipefail\n", "", "umask 077 must be the first statement"},
			{"source", "  while IFS='=' read -r k v; do export \"$k=$v\"; done <\"$file\"\n", "  set -a; source \"$file\"; set +a\n", "must never evaluate"},
			{"dot_source", "  while IFS='=' read -r k v; do export \"$k=$v\"; done <\"$file\"\n", "  set -a; . \"./$file\"; set +a\n", "must never evaluate"},
			{"eval", "  while IFS='=' read -r k v; do export \"$k=$v\"; done <\"$file\"\n", "  while IFS= read -r line; do eval \"export $line\"; done <\"$file\"\n", "must never evaluate"},
		}
		for _, s := range static {
			t.Run("static_"+s.name, func(t *testing.T) {
				expectProblems(t, checkDevEnvStatic(mustReplace(t, referenceDevEnv, s.old, s.replacement)), []string{s.want})
			})
		}
	})

	t.Run("repository", func(t *testing.T) {
		_, fsys := repoRoot(t)
		src, err := readRepoFile(fsys, "scripts/dev-env.sh", "created by M0-T03")
		if err != nil {
			t.Fatal(err)
		}
		script := writeScript(t, src)
		for _, c := range devEnvChecks() {
			t.Run(c.name, func(t *testing.T) { reportProblems(t, c.run(t, script)) })
		}
		t.Run("umask_first", func(t *testing.T) { reportProblems(t, checkDevEnvStatic(src)) })
		t.Run("scripts_mode_755", func(t *testing.T) {
			for _, name := range []string{"scripts/dev-env.sh", "scripts/dev-bootstrap.sh", "scripts/dev/postgres-init.sh"} {
				info, err := fs.Stat(fsys, name)
				if err != nil {
					t.Errorf("%s: %v (created by M0-T03)", name, err)
					continue
				}
				if perm := info.Mode().Perm(); perm != 0o755 {
					t.Errorf("%s: mode %o, want 755", name, perm)
				}
			}
		})
	})
}

// Static checks of scripts/dev/postgres-init.sh (ADR 0003, decision D5).
var (
	pgGetenvRe      = regexp.MustCompile(`^\\getenv\s+([a-z_][a-z0-9_]*)\s+([A-Z_][A-Z0-9_]*)$`)
	pgPasswordRe    = regexp.MustCompile(`(?i)\bPASSWORD\b\s*(\S*)`)
	pgPasswordVarRe = regexp.MustCompile(`^:'([a-z_][a-z0-9_]*)';?$`)
	pgExpandRe      = regexp.MustCompile(`\$\{?(POSTGRES_PASSWORD|TEMPORAL_DB_PASSWORD|REMPART_DB_PASSWORD)\b`)
	pgPsqlVarRe     = regexp.MustCompile(`(?:^|\s)(?:-v|--set|--variable)(?:\s+|=)?(\S+)`)
	pgCreateRoleRe  = regexp.MustCompile(`(?i)^CREATE\s+(?:ROLE|USER)\s+(\S+)\s*(.*?);?$`)
	pgCreateDBRe    = regexp.MustCompile(`(?i)^CREATE\s+DATABASE\s+(\S+)\s+OWNER\s+(\S+);$`)
	pgRevokeRe      = regexp.MustCompile(`^REVOKE CONNECT, TEMPORARY ON DATABASE (.+) FROM PUBLIC;$`)
	pgGrantRe       = regexp.MustCompile(`(?i)\bGRANT\b`)
	pgPrivilegeRe   = regexp.MustCompile(`(?i)(^|[^A-Za-z_])(SUPERUSER|CREATEDB|CREATEROLE|REPLICATION|BYPASSRLS)\b`)
	pgAlterRoleRe   = regexp.MustCompile(`(?i)\bALTER\s+(ROLE|USER|DATABASE|SCHEMA|DEFAULT\s+PRIVILEGES)\b`)
	pgHeredocRe     = regexp.MustCompile(`<<-?\s*(\S+)`)
)

func pgRoleAttributes() []string {
	return []string{"NOSUPERUSER", "NOCREATEDB", "NOCREATEROLE", "NOREPLICATION", "NOBYPASSRLS"}
}

// pgExpectedRoles: role name to its login attribute.
func pgExpectedRoles() map[string]string {
	return map[string]string{"temporal": "LOGIN", "rempart_owner": "NOLOGIN", "rempart": "LOGIN"}
}

func pgExpectedDatabases() map[string]string {
	return map[string]string{"temporal": "temporal", "temporal_visibility": "temporal", "rempart": "rempart_owner"}
}

func pgRevokedDatabases() []string {
	return []string{"postgres", "rempart", "temporal", "temporal_visibility", "template1"}
}

const pgOnlyGrant = "GRANT CONNECT ON DATABASE rempart TO rempart;"

// checkPostgresInit applies the rules of TestPostgresInitScript.
func checkPostgresInit(src string) []string {
	var problems problemList
	lines := strings.Split(src, "\n")
	getenv := map[string]string{} // psql variable -> environment variable
	var heredocs []string
	firstRole, panicLine, logStmtLine, psqlLine := -1, -1, -1, -1
	roles := map[string]string{}
	dbs := map[string]string{}
	var revoked []string
	for i, raw := range lines {
		l := strings.TrimSpace(raw)
		num := i + 1
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if m := pgExpandRe.FindStringSubmatch(l); m != nil {
			problems.addf("scripts/dev/postgres-init.sh line %d: %s expanded by the shell (a password must never be an argument; use \\getenv): %q", num, m[1], l)
		}
		for _, m := range pgHeredocRe.FindAllStringSubmatch(l, -1) {
			heredocs = append(heredocs, m[1])
		}
		if strings.HasPrefix(l, "psql ") {
			if psqlLine < 0 {
				psqlLine = num
			}
			for _, m := range pgPsqlVarRe.FindAllStringSubmatch(l, -1) {
				if m[1] != "ON_ERROR_STOP=1" {
					problems.addf("scripts/dev/postgres-init.sh line %d: psql variable %q set on the command line (passwords come from \\getenv only)", num, m[1])
				}
			}
			for _, flag := range []string{"-v ON_ERROR_STOP=1", "--no-psqlrc"} {
				if !strings.Contains(l, flag) {
					problems.addf("scripts/dev/postgres-init.sh line %d: psql without %s", num, flag)
				}
			}
		}
		if m := pgGetenvRe.FindStringSubmatch(l); m != nil {
			getenv[m[1]] = m[2]
		}
		switch l {
		case "SET log_min_error_statement = panic;":
			panicLine = num
		case "SET log_statement = none;":
			logStmtLine = num
		}
		if m := pgCreateRoleRe.FindStringSubmatch(l); m != nil {
			if firstRole < 0 {
				firstRole = num
			}
			problems = append(problems, checkPgRole(num, m[1], m[2], getenv, roles)...)
		}
		if m := pgPasswordRe.FindStringSubmatch(l); m != nil && pgCreateRoleRe.FindStringSubmatch(l) == nil {
			problems.addf("scripts/dev/postgres-init.sh line %d: PASSWORD outside CREATE ROLE: %q", num, redactHex(l))
		}
		if m := pgCreateDBRe.FindStringSubmatch(l); m != nil {
			dbs[m[1]] = m[2]
		}
		if m := pgRevokeRe.FindStringSubmatch(l); m != nil {
			for _, db := range strings.Split(m[1], ",") {
				revoked = append(revoked, strings.TrimSpace(db))
			}
		}
		if pgGrantRe.MatchString(l) && l != pgOnlyGrant {
			problems.addf("scripts/dev/postgres-init.sh line %d: GRANT not allowed, the only one is %q: %q", num, pgOnlyGrant, l)
		}
		if m := pgPrivilegeRe.FindStringSubmatch(l); m != nil {
			problems.addf("scripts/dev/postgres-init.sh line %d: privilege %s granted (every role is NO%s): %q", num, m[2], strings.ToUpper(m[2]), l)
		}
		if m := pgAlterRoleRe.FindStringSubmatch(l); m != nil {
			problems.addf("scripts/dev/postgres-init.sh line %d: ALTER %s not allowed: %q", num, strings.ToUpper(m[1]), l)
		}
	}

	if !slices.Equal(heredocs, []string{"'SQL'"}) {
		problems.addf("scripts/dev/postgres-init.sh: heredocs are %q, want exactly one, <<'SQL' (quoted: no shell expansion)", heredocs)
	}
	if psqlLine < 0 {
		problems.addf("scripts/dev/postgres-init.sh: psql never called")
	}
	for _, env := range []string{"TEMPORAL_DB_PASSWORD", "REMPART_DB_PASSWORD"} {
		if !slices.Contains(mapValues(getenv), env) {
			problems.addf("scripts/dev/postgres-init.sh: \\getenv of %s missing", env)
		}
	}
	switch {
	case panicLine < 0:
		problems.addf("scripts/dev/postgres-init.sh: SET log_min_error_statement = panic; missing (a failed CREATE ROLE would log the password)")
	case firstRole >= 0 && panicLine > firstRole:
		problems.addf("scripts/dev/postgres-init.sh: SET log_min_error_statement = panic; (line %d) after the first CREATE ROLE (line %d)", panicLine, firstRole)
	}
	switch {
	case logStmtLine < 0:
		problems.addf("scripts/dev/postgres-init.sh: SET log_statement = none; missing")
	case firstRole >= 0 && logStmtLine > firstRole:
		problems.addf("scripts/dev/postgres-init.sh: SET log_statement = none; (line %d) after the first CREATE ROLE (line %d)", logStmtLine, firstRole)
	}
	for name, login := range pgExpectedRoles() {
		if got, ok := roles[name]; !ok {
			problems.addf("scripts/dev/postgres-init.sh: role %s not created", name)
		} else if got != login {
			problems.addf("scripts/dev/postgres-init.sh: role %s is %s, want %s", name, got, login)
		}
	}
	for name := range roles {
		if _, ok := pgExpectedRoles()[name]; !ok {
			problems.addf("scripts/dev/postgres-init.sh: unexpected role %s", name)
		}
	}
	if want := pgExpectedDatabases(); !mapsEqual(dbs, want) {
		problems.addf("scripts/dev/postgres-init.sh: databases and owners are %v, want %v", dbs, want)
	}
	slices.Sort(revoked)
	if !slices.Equal(revoked, pgRevokedDatabases()) {
		problems.addf("scripts/dev/postgres-init.sh: REVOKE CONNECT, TEMPORARY ... FROM PUBLIC covers %q, want %q", revoked, pgRevokedDatabases())
	}
	if n := strings.Count(src, pgOnlyGrant); n != 1 {
		problems.addf("scripts/dev/postgres-init.sh: %q appears %d times, want 1", pgOnlyGrant, n)
	}
	return problems
}

// checkPgRole checks the attributes of one CREATE ROLE and records its login attribute.
func checkPgRole(num int, name, attrs string, getenv, roles map[string]string) []string {
	var problems problemList
	if _, dup := roles[name]; dup {
		problems.addf("scripts/dev/postgres-init.sh line %d: role %s created twice", num, name)
	}
	fields := strings.Fields(strings.ToUpper(attrs))
	for _, a := range pgRoleAttributes() {
		if !slices.Contains(fields, a) {
			problems.addf("scripts/dev/postgres-init.sh line %d: role %s without %s", num, name, a)
		}
	}
	login := ""
	switch {
	case slices.Contains(fields, "LOGIN") && !slices.Contains(fields, "NOLOGIN"):
		login = "LOGIN"
	case slices.Contains(fields, "NOLOGIN") && !slices.Contains(fields, "LOGIN"):
		login = "NOLOGIN"
	default:
		problems.addf("scripts/dev/postgres-init.sh line %d: role %s must state exactly one of LOGIN, NOLOGIN", num, name)
	}
	roles[name] = login
	m := pgPasswordRe.FindStringSubmatch(attrs)
	switch {
	case m == nil && login == "LOGIN":
		problems.addf("scripts/dev/postgres-init.sh line %d: login role %s without password", num, name)
	case m != nil && login == "NOLOGIN":
		problems.addf("scripts/dev/postgres-init.sh line %d: NOLOGIN role %s with a password", num, name)
	case m != nil:
		v := pgPasswordVarRe.FindStringSubmatch(m[1])
		if v == nil {
			problems.addf("scripts/dev/postgres-init.sh line %d: role %s: PASSWORD must be :'<variable read by \\getenv>', not a literal", num, name)
		} else if _, ok := getenv[v[1]]; !ok {
			problems.addf("scripts/dev/postgres-init.sh line %d: role %s: password variable %s not read by \\getenv before", num, name, v[1])
		}
	}
	return problems
}

func mapValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// referencePostgresInit is scripts/dev/postgres-init.sh of
// docs/plans/M0-pile-dev.md section 3.3, verbatim.
const referencePostgresInit = `#!/usr/bin/env bash
# Bases et rôles distincts (M0-T03, ADR 0003), une fois sur volume vide.
# Aucun mot de passe littéral ni en argument.
set -euo pipefail
for v in TEMPORAL_DB_PASSWORD REMPART_DB_PASSWORD; do
  [[ "${!v:-}" =~ ^[0-9a-f]{64}$ ]] || { echo "postgres-init : $v absent ou mal formé." >&2; exit 2; }
done
psql -v ON_ERROR_STOP=1 --no-psqlrc --username postgres --dbname postgres <<'SQL'
SET log_min_error_statement = panic;
SET log_statement = none;
\getenv temporal_pw TEMPORAL_DB_PASSWORD
\getenv rempart_pw REMPART_DB_PASSWORD
CREATE ROLE temporal LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'temporal_pw';
CREATE ROLE rempart_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE rempart LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'rempart_pw';
CREATE DATABASE temporal OWNER temporal;
CREATE DATABASE temporal_visibility OWNER temporal;
CREATE DATABASE rempart OWNER rempart_owner;
REVOKE CONNECT, TEMPORARY ON DATABASE temporal, temporal_visibility, rempart, postgres, template1 FROM PUBLIC;
GRANT CONNECT ON DATABASE rempart TO rempart;
SQL
`

func TestPostgresInitScript(t *testing.T) { // [ADR-0003]
	t.Run("negative_controls", func(t *testing.T) {
		valid := referencePostgresInit
		const (
			revokeLine  = "REVOKE CONNECT, TEMPORARY ON DATABASE temporal, temporal_visibility, rempart, postgres, template1 FROM PUBLIC;\n"
			grantLine   = "GRANT CONNECT ON DATABASE rempart TO rempart;\n"
			panicLine   = "SET log_min_error_statement = panic;\n"
			rempartPw   = "PASSWORD :'rempart_pw';"
			rempartRole = "CREATE ROLE rempart LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS "
		)
		cases := []struct {
			name string
			src  string
			want []string
		}{
			{name: "valid", src: valid},
			{
				name: "no_revoke", // mutation 20
				src:  mustReplace(t, valid, revokeLine, ""),
				want: []string{"REVOKE CONNECT, TEMPORARY ... FROM PUBLIC covers [], want"},
			},
			{
				name: "revoke_without_template1",
				src:  mustReplace(t, valid, ", postgres, template1 FROM", ", postgres FROM"),
				want: []string{"covers [\"postgres\" \"rempart\" \"temporal\" \"temporal_visibility\"]"},
			},
			{
				name: "revoke_connect_only",
				src:  mustReplace(t, valid, "REVOKE CONNECT, TEMPORARY ON", "REVOKE CONNECT ON"),
				want: []string{"covers [], want"},
			},
			{
				name: "grant_temporal_to_rempart", // mutation 21
				src:  mustReplace(t, valid, grantLine, grantLine+"GRANT CONNECT ON DATABASE temporal TO rempart;\n"),
				want: []string{"GRANT not allowed, the only one is \"GRANT CONNECT ON DATABASE rempart TO rempart;\": \"GRANT CONNECT ON DATABASE temporal TO rempart;\""},
			},
			{
				name: "grant_owner_membership",
				src:  mustReplace(t, valid, grantLine, grantLine+"GRANT rempart_owner TO rempart;\n"),
				want: []string{"GRANT not allowed", "GRANT rempart_owner TO rempart;"},
			},
			{
				name: "grant_all_lowercase",
				src:  mustReplace(t, valid, grantLine, "grant all on database rempart to rempart;\n"),
				want: []string{"GRANT not allowed", "appears 0 times, want 1"},
			},
			{
				name: "bypassrls", // mutation 22
				src:  mustReplace(t, valid, rempartRole, "CREATE ROLE rempart LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS "),
				want: []string{"role rempart without NOBYPASSRLS", "privilege BYPASSRLS granted"},
			},
			{
				name: "missing_nocreatedb",
				src:  mustReplace(t, valid, "CREATE ROLE temporal LOGIN NOSUPERUSER NOCREATEDB ", "CREATE ROLE temporal LOGIN NOSUPERUSER "),
				want: []string{"role temporal without NOCREATEDB"},
			},
			{
				name: "alter_role_superuser",
				src:  mustReplace(t, valid, grantLine, grantLine+"ALTER ROLE rempart SUPERUSER;\n"),
				want: []string{"privilege SUPERUSER granted", "ALTER ROLE not allowed"},
			},
			{
				name: "owner_can_login",
				src:  mustReplace(t, valid, "CREATE ROLE rempart_owner NOLOGIN ", "CREATE ROLE rempart_owner LOGIN "),
				want: []string{"role rempart_owner is LOGIN, want NOLOGIN"},
			},
			{
				name: "app_role_owns_database",
				src:  mustReplace(t, valid, "CREATE DATABASE rempart OWNER rempart_owner;", "CREATE DATABASE rempart OWNER rempart;"),
				want: []string{"databases and owners are"},
			},
			{
				name: "literal_password",
				src:  mustReplace(t, valid, rempartPw, "PASSWORD 'FAKE-dev-password';"),
				want: []string{"role rempart: PASSWORD must be :'<variable read by \\getenv>', not a literal"},
			},
			{
				name: "password_variable_not_from_getenv",
				src:  mustReplace(t, valid, rempartPw, "PASSWORD :'other_pw';"),
				want: []string{"password variable other_pw not read by \\getenv"},
			},
			{
				name: "password_on_command_line",
				src: mustReplace(t, mustReplace(t, valid, "\\getenv rempart_pw REMPART_DB_PASSWORD\n", ""),
					"psql -v ON_ERROR_STOP=1 ", "psql -v ON_ERROR_STOP=1 -v rempart_pw=\"$REMPART_DB_PASSWORD\" "),
				want: []string{"REMPART_DB_PASSWORD expanded by the shell", "psql variable \"rempart_pw=\\\"$REMPART_DB_PASSWORD\\\"\" set on the command line", "\\getenv of REMPART_DB_PASSWORD missing"},
			},
			{
				name: "password_set_long_flag",
				src:  mustReplace(t, valid, "psql -v ON_ERROR_STOP=1 ", "psql -v ON_ERROR_STOP=1 --set=temporal_pw=x "),
				want: []string{"psql variable \"temporal_pw=x\" set on the command line"},
			},
			{
				name: "unquoted_heredoc",
				src:  mustReplace(t, valid, "<<'SQL'", "<<SQL"),
				want: []string{"heredocs are [\"SQL\"], want exactly one, <<'SQL'"},
			},
			{
				name: "panic_after_create_role",
				src:  mustReplace(t, mustReplace(t, valid, panicLine, ""), grantLine, grantLine+panicLine),
				want: []string{"SET log_min_error_statement = panic; (line", "after the first CREATE ROLE"},
			},
			{
				name: "no_panic",
				src:  mustReplace(t, valid, panicLine, ""),
				want: []string{"SET log_min_error_statement = panic; missing"},
			},
			{
				name: "no_log_statement",
				src:  mustReplace(t, valid, "SET log_statement = none;\n", ""),
				want: []string{"SET log_statement = none; missing"},
			},
			{
				name: "psqlrc_read",
				src:  mustReplace(t, valid, " --no-psqlrc", ""),
				want: []string{"psql without --no-psqlrc"},
			},
			{
				name: "no_on_error_stop",
				src:  mustReplace(t, valid, "psql -v ON_ERROR_STOP=1 ", "psql "),
				want: []string{"psql without -v ON_ERROR_STOP=1"},
			},
			{
				name: "extra_role",
				src:  mustReplace(t, valid, grantLine, grantLine+"CREATE ROLE admin LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'rempart_pw';\n"),
				want: []string{"unexpected role admin"},
			},
			{
				name: "alter_password",
				src:  mustReplace(t, valid, grantLine, grantLine+"ALTER ROLE rempart PASSWORD 'x';\n"),
				want: []string{"PASSWORD outside CREATE ROLE", "ALTER ROLE not allowed"},
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) { expectProblems(t, checkPostgresInit(tc.src), tc.want) })
		}
	})
	t.Run("repository", func(t *testing.T) {
		_, fsys := repoRoot(t)
		src, err := readRepoFile(fsys, "scripts/dev/postgres-init.sh", "created by M0-T03")
		if err != nil {
			t.Fatal(err)
		}
		reportProblems(t, checkPostgresInit(src))
	})
}
