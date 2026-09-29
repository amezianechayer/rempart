package archtest

import (
	"cmp"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// M0-T03b amendment V3 (docs/plans/M0-pile-dev-harden.md), after the security
// review BLOCK on 6edc17f:
//   - C1: dev-env.sh reads .env.dev once; check fills an array of validated
//     pairs, run exports that array with builtin export; a last line without a
//     final newline is exported too.
//   - C2: docs/SETUP.md and docker-compose.yml cite compose in the D1 form
//     only; the go test that receives the secrets targets ./internal/archtest
//     only (D4); SETUP.md states Engine 28, local unix socket, COMPOSE_*
//     ignored.
//   - C3: dev-env.sh run runs bash scripts/dev-preflight.sh (output on stderr)
//     before exec when the command is docker.
//
// No Docker, no network: docker is a fake on PATH.

// referenceDevEnvV3 is scripts/dev-env.sh with the C1 and C3 fixes of
// amendment V3.
const referenceDevEnvV3 = `#!/usr/bin/env bash
# Secrets de la pile de dev (M0-T03), depuis la racine du dépôt. N'affiche aucune valeur.
#   ensure          crée .env.dev s'il manque (600), puis le valide
#   run CMD [ARG]   valide .env.dev (lu une seule fois), exporte ses paires validées
#                   (prioritaires sur le shell), retire les variables COMPOSE_*, lance
#                   scripts/dev-preflight.sh si CMD est docker, exécute CMD (M0-T03b)
set -euo pipefail
umask 077
readonly file=.env.dev
readonly keys=(POSTGRES_PASSWORD TEMPORAL_DB_PASSWORD REMPART_DB_PASSWORD OPENBAO_DEV_ROOT_TOKEN)
pairs=()
die() { echo "dev-env : $*" >&2; exit 2; }
gen() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }

# check valide .env.dev en une seule lecture et garde ses paires dans pairs (V3).
check() {
  [[ -f $file && ! -L $file ]] || die "$file absent ou lien symbolique (lance make dev)."
  local mode; mode=$(stat -c %a "$file" 2>/dev/null || stat -f %Lp "$file")
  [[ $mode == 600 ]] || die "$file doit avoir les droits 600 (actuels : $mode)."
  local -a seen=(); local line n=0
  pairs=()
  while IFS= read -r line || [[ -n $line ]]; do
    n=$((n + 1))
    [[ $line =~ ^([A-Z][A-Z0-9_]*)=[0-9a-f]{64}$ ]] || die "$file : ligne $n mal formée."
    seen+=("${BASH_REMATCH[1]}")
    pairs+=("$line")
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
  local n
  for n in "${!COMPOSE_@}"; do unset -v "$n"; done
  if [[ $1 == docker ]]; then bash scripts/dev-preflight.sh >&2; fi
  builtin export -- "${pairs[@]}"
  exec "$@"
}

case "${1:-}" in
  ensure) ensure ;;
  run) shift; run "$@" ;;
  *) die "usage : dev-env.sh ensure | run CMD [ARG...]" ;;
esac
`

// writeEnvFileRaw writes .env.dev in dir with exactly content, mode 600.
func writeEnvFileRaw(t *testing.T, dir, content string) {
	t.Helper()
	path := filepath.Join(dir, ".env.dev")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

// inheritedSecrets are weak values a caller's shell could hold for the keys of
// .env.dev, plus DOCKER_HOST (kept by run) and the COMPOSE_* variables.
func inheritedSecrets() []string {
	return append([]string{
		"OPENBAO_DEV_ROOT_TOKEN=root",
		"POSTGRES_PASSWORD=weak",
		"DOCKER_HOST=unix:///x.sock",
	}, inheritedComposeVars()...)
}

// expectFixtureEnv reports every key of .env.dev whose value in got is not the
// value of the fixture, and every COMPOSE_* variable still present.
func expectFixtureEnv(problems *problemList, what string, got map[string]string) {
	for _, k := range devEnvKeys() {
		if got[k] != fixtureValue(k) {
			problems.addf("%s: %s not overridden by .env.dev (the inherited value or none reached the command)", what, k)
		}
	}
	for k := range got {
		if strings.HasPrefix(k, "COMPOSE_") {
			problems.addf("%s: %s still exported", what, k)
		}
	}
}

// checkDevEnvRunNoFinalNewline (C1): a .env.dev whose last line has no final
// newline is accepted by check (read ... || [[ -n $line ]]); run must export
// that last line too, or the inherited OPENBAO_DEV_ROOT_TOKEN=root reaches the
// command while the file passed validation.
func checkDevEnvRunNoFinalNewline(t *testing.T, script string) []string {
	var problems problemList
	dir := newWorkspace(t, wsIgnored)
	writeEnvFileRaw(t, dir, strings.Join(fixtureLines(), "\n"))
	r := runInEnv(t, dir, inheritedSecrets(), "bash", script, "run", "env")
	expectExit(&problems, "no final newline: run env", r, 0)
	got := envMap(r.stdout)
	expectFixtureEnv(&problems, "no final newline: run env", got)
	if got["DOCKER_HOST"] != "unix:///x.sock" {
		problems.addf("no final newline: run env: DOCKER_HOST not kept")
	}
	return problems
}

// swapBashEnv simulates a concurrent writer of .env.dev, deterministically:
// sourced through BASH_ENV, it rewrites .env.dev with $REMPART_SWAP just after
// check returns into run (DEBUG trap, inherited by functions through set -T).
// A run that exports what check validated is not affected; a run that reads
// the file again exports unvalidated lines.
const swapBashEnv = `set -T
rempart_checked=
rempart_swapped=
trap 'if [[ ${FUNCNAME[0]:-} == check ]]; then rempart_checked=1; elif [[ -n $rempart_checked && -z $rempart_swapped && ${FUNCNAME[0]:-} == run ]]; then rempart_swapped=1; cat -- "$REMPART_SWAP" >.env.dev; fi' DEBUG
`

// swappedEnvContent replaces every value and adds a key: none of it passes check.
const swappedEnvContent = "POSTGRES_PASSWORD=weak\nTEMPORAL_DB_PASSWORD=weak\nREMPART_DB_PASSWORD=weak\nOPENBAO_DEV_ROOT_TOKEN=root\nREMPART_INJECTED=planted\n"

// checkDevEnvRunExportsValidatedPairs (C1): .env.dev is read once; what run
// exports is what check validated, even if the file changes in between.
func checkDevEnvRunExportsValidatedPairs(t *testing.T, script string) []string {
	var problems problemList
	dir := newWorkspace(t, wsIgnored)
	writeEnvFile(t, dir, fixtureLines(), 0o600)
	tmp := t.TempDir()
	bashEnv := filepath.Join(tmp, "swap.bash")
	swap := filepath.Join(tmp, "swapped.env")
	for p, c := range map[string]string{bashEnv: swapBashEnv, swap: swappedEnvContent} {
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r := runInEnv(t, dir, []string{"BASH_ENV=" + bashEnv, "REMPART_SWAP=" + swap}, "bash", script, "run", "env")
	after, err := fs.ReadFile(os.DirFS(dir), ".env.dev")
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != swappedEnvContent {
		problems.addf("swapped file: the simulated concurrent writer did not run (run must call check, then export its pairs)")
	}
	if r.code != 0 && r.stdout == "" {
		return problems // refused before running the command: no unvalidated value reached it
	}
	got := envMap(r.stdout)
	expectFixtureEnv(&problems, "swapped file: run env", got)
	if _, ok := got["REMPART_INJECTED"]; ok {
		problems.addf("swapped file: run env: REMPART_INJECTED exported (a line never validated reached the command)")
	}
	return problems
}

// checkDevEnvRunExportNotShadowed (C1): bash imports exported functions from
// the environment; a function named export would turn run's export into a no
// op and let the inherited values reach the command. run uses builtin export.
func checkDevEnvRunExportNotShadowed(t *testing.T, script string) []string {
	var problems problemList
	dir := newWorkspace(t, wsIgnored)
	writeEnvFile(t, dir, fixtureLines(), 0o600)
	extra := append(inheritedSecrets(), "BASH_FUNC_export%%=() { return 0; }")
	r := runInEnv(t, dir, extra, "bash", script, "run", "env")
	if r.code != 0 && r.stdout == "" {
		return problems // refused before running the command: acceptable
	}
	expectExit(&problems, "export function: run env", r, 0)
	expectFixtureEnv(&problems, "export function: run env", envMap(r.stdout))
	return problems
}

func devEnvV3Checks() []devEnvCheck {
	return []devEnvCheck{
		{"run_overrides_environment_no_final_newline", checkDevEnvRunNoFinalNewline},
		{"run_exports_validated_pairs", checkDevEnvRunExportsValidatedPairs},
		{"run_export_not_shadowed", checkDevEnvRunExportNotShadowed},
	}
}

// envFileReadRe matches a read of .env.dev in dev-env.sh: a redirection from
// $file, or $file as an argument of a command that prints or loads it.
var envFileReadRe = regexp.MustCompile(`<\s*"?\$\{?file\}?"?|\b(cat|head|tail|sed|awk|grep|cut|tr|mapfile|readarray|source)\b[^;|&]*\$\{?file\b`)

// checkDevEnvReadsOnce (C1, static): dev-env.sh reads .env.dev in one place.
func checkDevEnvReadsOnce(src string) []string {
	var problems problemList
	var reads []int
	for i, l := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		for range envFileReadRe.FindAllStringIndex(l, -1) {
			reads = append(reads, i+1)
		}
	}
	if len(reads) != 1 {
		problems.addf("scripts/dev-env.sh: .env.dev is read at lines %v, want exactly one read (check validates and keeps the pairs, run exports them, V3 C1)", reads)
	}
	return problems
}

// fakeDockerRunnable is fakeDocker that also accepts the D1 compose calls.
func fakeDockerRunnable(t *testing.T) string {
	t.Helper()
	return mustReplace(t, fakeDocker, `  *) echo "fake docker: unexpected call"`,
		"  \"compose -p rempart-dev \"*) echo fake-compose-ran ;;\n  *) echo \"fake docker: unexpected call\"")
}

var d1UpArgs = []string{"docker", "compose", "-p", "rempart-dev", "--env-file", ".env.dev", "-f", "docker-compose.yml", "up", "-d"}

type devEnvDockerCase struct {
	name        string
	env         []string
	args        []string // after "run"; d1UpArgs when nil
	noPreflight bool     // scripts/dev-preflight.sh absent from the work tree
	code        int      // -1: any non-zero code
	ran         bool
	want        string // substring of stderr on refusal
	hidden      string // value that must not be displayed
}

func devEnvDockerCases() []devEnvDockerCase {
	return []devEnvDockerCase{
		{name: "local_daemon", env: []string{"FAKE_SERVER_VERSION=29.3.1"}, ran: true},
		{
			name: "docker_host_tcp", env: []string{"DOCKER_HOST=tcp://127.0.0.1:2375"},
			code: 2, want: "DOCKER_HOST ne désigne pas un socket unix local", hidden: "127.0.0.1:2375",
		},
		{
			name: "docker_host_ssh_other_subcommand", env: []string{"DOCKER_HOST=ssh://deploy@build.example.net"},
			args: []string{"docker", "ps"}, code: 2, want: "DOCKER_HOST ne désigne pas un socket unix local", hidden: "build.example.net",
		},
		{
			name: "context_ssh", env: []string{"FAKE_CONTEXT_HOST=ssh://ops@203.0.113.8"},
			code: 2, want: "le contexte Docker courant ne désigne pas un socket unix local", hidden: "203.0.113.8",
		},
		{name: "engine_27", env: []string{"FAKE_SERVER_VERSION=27.5.1"}, code: 2, want: "Docker Engine 28 ou plus requis"},
		{name: "preflight_missing", noPreflight: true, code: -1},
		{name: "non_docker_command", env: []string{"DOCKER_HOST=tcp://127.0.0.1:2375"}, args: []string{"printf", "non-docker-ran"}, ran: true},
	}
}

// checkDevEnvRunDockerPreflight (C3): run docker ... runs
// bash scripts/dev-preflight.sh first, its output on stderr; a refusal (remote
// daemon, engine older than 28, preflight missing) stops run before the
// command. Other commands run without it.
func checkDevEnvRunDockerPreflight(t *testing.T, script, preflight string) []string {
	t.Helper()
	var problems problemList
	bin := writeExecutable(t, "docker", fakeDockerRunnable(t))
	for _, c := range devEnvDockerCases() {
		dir := newWorkspace(t, wsIgnored)
		writeEnvFile(t, dir, fixtureLines(), 0o600)
		if !c.noPreflight {
			if err := os.MkdirAll(filepath.Join(dir, "scripts"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "scripts", "dev-preflight.sh"), []byte(preflight), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		args := c.args
		if args == nil {
			args = d1UpArgs
		}
		log := filepath.Join(t.TempDir(), "docker.log")
		extra := append([]string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "FAKE_LOG=" + log}, c.env...)
		r := runInEnv(t, dir, extra, "bash", append([]string{script, "run"}, args...)...)
		var calls []string
		if data, err := fs.ReadFile(os.DirFS(filepath.Dir(log)), filepath.Base(log)); err == nil {
			calls = strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
		}
		command := strings.Join(args[1:], " ")
		isDocker := args[0] == "docker"
		ran := isDocker && slices.Contains(calls, command) || !isDocker && r.stdout == "non-docker-ran"
		switch {
		case c.code == -1 && r.code == 0:
			problems.addf("%s: exit 0, want a refusal; output: %q", c.name, r.output())
		case c.code != -1 && r.code != c.code:
			problems.addf("%s: exit %d, want %d; output: %q", c.name, r.code, c.code, r.output())
		}
		switch {
		case c.ran && !ran:
			problems.addf("%s: the command did not run (docker calls %q)", c.name, calls)
		case !c.ran && ran:
			problems.addf("%s: %q ran despite the refusal of dev-preflight (C3)", c.name, command)
		}
		if isDocker && c.ran {
			if r.stdout != "fake-compose-ran\n" {
				problems.addf("%s: stdout %q, want only the output of the command (dev-preflight on stderr)", c.name, r.output())
			}
			if !strings.Contains(r.stderr, strings.TrimSuffix(preflightOK, "\n")) {
				problems.addf("%s: dev-preflight did not run before docker (stderr %q)", c.name, r.output())
			}
			if i, j := slices.Index(calls, "info"), slices.Index(calls, command); i < 0 || i > j {
				problems.addf("%s: docker calls %q, want the checks of dev-preflight before the command", c.name, calls)
			}
		}
		if !isDocker && slices.Contains(calls, "info") {
			problems.addf("%s: dev-preflight ran for a command other than docker", c.name)
		}
		if c.want != "" && !strings.Contains(r.stderr, c.want) {
			problems.addf("%s: stderr %q does not mention %q", c.name, r.output(), c.want)
		}
		if c.hidden != "" && strings.Contains(r.stdout+r.stderr, c.hidden) {
			problems.addf("%s: output shows the value %q", c.name, c.hidden)
		}
		for _, k := range devEnvKeys() {
			if strings.Contains(r.stdout+r.stderr, fixtureValue(k)) {
				problems.addf("%s: output contains the value of %s", c.name, k)
			}
		}
	}
	return problems
}

func TestDevEnvSingleRead(t *testing.T) {
	t.Run("negative_controls", func(t *testing.T) {
		for _, c := range append(devEnvChecks(), devEnvV3Checks()...) {
			t.Run("reference_v3/"+c.name, func(t *testing.T) {
				expectProblems(t, c.run(t, writeScript(t, referenceDevEnvV3)), nil)
			})
		}
		t.Run("reference_v3/umask_first", func(t *testing.T) { expectProblems(t, checkDevEnvStatic(referenceDevEnvV3), nil) })
		t.Run("reference_v3/reads_file_once", func(t *testing.T) { expectProblems(t, checkDevEnvReadsOnce(referenceDevEnvV3), nil) })

		// The form of 6edc17f (plan V1): the defects the review found.
		v1 := []struct {
			name string
			run  func(t *testing.T, script string) []string
			want []string
		}{
			{"run_overrides_environment_no_final_newline", checkDevEnvRunNoFinalNewline, []string{"no final newline: run env: OPENBAO_DEV_ROOT_TOKEN not overridden"}},
			{"run_exports_validated_pairs", checkDevEnvRunExportsValidatedPairs, []string{"swapped file: run env: POSTGRES_PASSWORD not overridden", "REMPART_INJECTED exported"}},
			{"run_export_not_shadowed", checkDevEnvRunExportNotShadowed, []string{"export function: run env: OPENBAO_DEV_ROOT_TOKEN not overridden"}},
		}
		for _, c := range v1 {
			t.Run("v1_form/"+c.name, func(t *testing.T) { expectProblems(t, c.run(t, writeScript(t, referenceDevEnv)), c.want) })
		}
		t.Run("v1_form/reads_file_once", func(t *testing.T) {
			expectProblems(t, checkDevEnvReadsOnce(referenceDevEnv), []string{".env.dev is read at lines [22 42]"})
		})

		const exportLine = "  builtin export -- \"${pairs[@]}\"\n"
		mutations := []struct {
			name, old, replacement string
			check                  func(t *testing.T, script string) []string
			want                   []string
		}{
			{
				name: "rereads_in_run", old: exportLine,
				replacement: "  local k v\n  while IFS='=' read -r k v; do builtin export \"$k=$v\"; done <\"$file\"\n",
				check:       checkDevEnvRunNoFinalNewline, want: []string{"OPENBAO_DEV_ROOT_TOKEN not overridden"},
			},
			{
				name: "rereads_in_run_swap", old: exportLine,
				replacement: "  local k v\n  while IFS='=' read -r k v || [[ -n $k ]]; do builtin export \"$k=$v\"; done <\"$file\"\n",
				check:       checkDevEnvRunExportsValidatedPairs, want: []string{"REMPART_INJECTED exported"},
			},
			{
				name: "plain_export", old: "builtin export --", replacement: "export --",
				check: checkDevEnvRunExportNotShadowed, want: []string{"export function: run env: POSTGRES_PASSWORD not overridden"},
			},
			{
				name: "pairs_not_filled", old: "    pairs+=(\"$line\")\n", replacement: "",
				check: checkDevEnvRunNoFinalNewline, want: []string{"POSTGRES_PASSWORD not overridden"},
			},
		}
		for _, m := range mutations {
			t.Run(m.name, func(t *testing.T) {
				expectProblems(t, m.check(t, writeScript(t, mustReplace(t, referenceDevEnvV3, m.old, m.replacement))), m.want)
			})
		}
		t.Run("static_rereads_in_run", func(t *testing.T) {
			src := mustReplace(t, referenceDevEnvV3, exportLine, "  local k v\n  while IFS='=' read -r k v; do builtin export \"$k=$v\"; done <\"$file\"\n")
			expectProblems(t, checkDevEnvReadsOnce(src), []string{".env.dev is read at lines"})
		})
		t.Run("static_mapfile", func(t *testing.T) {
			src := mustReplace(t, referenceDevEnvV3, exportLine, "  mapfile -t lines <\"$file\"\n"+exportLine)
			expectProblems(t, checkDevEnvReadsOnce(src), []string{".env.dev is read at lines"})
		})
	})
	t.Run("repository", func(t *testing.T) {
		_, fsys := repoRoot(t)
		src, err := readRepoFile(fsys, "scripts/dev-env.sh", "created by M0-T03")
		if err != nil {
			t.Fatal(err)
		}
		script := writeScript(t, src)
		for _, c := range devEnvV3Checks() {
			t.Run(c.name, func(t *testing.T) { reportProblems(t, c.run(t, script)) })
		}
		t.Run("reads_file_once", func(t *testing.T) { reportProblems(t, checkDevEnvReadsOnce(src)) })
	})
}

func TestDevEnvRunPreflight(t *testing.T) {
	t.Run("negative_controls", func(t *testing.T) {
		t.Run("reference_v3", func(t *testing.T) {
			expectProblems(t, checkDevEnvRunDockerPreflight(t, writeScript(t, referenceDevEnvV3), referenceDevPreflight), nil)
		})
		t.Run("v1_form", func(t *testing.T) {
			expectProblems(t, checkDevEnvRunDockerPreflight(t, writeScript(t, referenceDevEnv), referenceDevPreflight), []string{
				"docker_host_tcp: exit 0, want 2",
				"docker_host_tcp: \"compose -p rempart-dev --env-file .env.dev -f docker-compose.yml up -d\" ran despite the refusal",
				"context_ssh: \"compose -p rempart-dev",
				"engine_27: \"compose -p rempart-dev",
				"preflight_missing: exit 0, want a refusal",
				"local_daemon: dev-preflight did not run before docker",
			})
		})
		const preflightLine = "  if [[ $1 == docker ]]; then bash scripts/dev-preflight.sh >&2; fi\n"
		mutations := []struct {
			name, old, replacement string
			want                   []string
		}{
			{name: "no_preflight", old: preflightLine, replacement: "", want: []string{"docker_host_tcp: \"compose -p rempart-dev", "engine_27: \"compose -p rempart-dev"}},
			{name: "preflight_on_stdout", old: "dev-preflight.sh >&2;", replacement: "dev-preflight.sh;", want: []string{"local_daemon: stdout"}},
			{name: "preflight_ignored", old: "dev-preflight.sh >&2;", replacement: "dev-preflight.sh >&2 || true;", want: []string{"docker_host_tcp: \"compose -p rempart-dev", "preflight_missing: exit 0"}},
			{name: "preflight_for_every_command", old: "if [[ $1 == docker ]]; then", replacement: "if true; then", want: []string{"non_docker_command: the command did not run"}},
			{name: "preflight_compose_only", old: "if [[ $1 == docker ]]; then", replacement: "if [[ ${2:-} == compose ]]; then", want: []string{"docker_host_ssh_other_subcommand: \"ps\" ran despite the refusal"}},
		}
		for _, m := range mutations {
			t.Run(m.name, func(t *testing.T) {
				mutated := mustReplace(t, referenceDevEnvV3, m.old, m.replacement)
				expectProblems(t, checkDevEnvRunDockerPreflight(t, writeScript(t, mutated), referenceDevPreflight), m.want)
			})
		}
	})
	t.Run("repository", func(t *testing.T) {
		_, fsys := repoRoot(t)
		src, err := readRepoFile(fsys, "scripts/dev-env.sh", "created by M0-T03")
		if err != nil {
			t.Fatal(err)
		}
		preflight, err := readRepoFile(fsys, "scripts/dev-preflight.sh", "created by M0-T03b")
		if err != nil {
			t.Fatal(err)
		}
		reportProblems(t, checkDevEnvRunDockerPreflight(t, writeScript(t, src), preflight))
	})
}

// docComposeRe finds a citation of compose in a document: "docker compose" or
// "docker-compose" followed by the end of the line or a character that ends a
// word ("docker-compose.yml" is a file name, not a citation).
var docComposeRe = regexp.MustCompile(`\bdocker[ -]compose(?:$|[^\w.-])`)

// docGoTestRe finds a secret-bearing go test in a document.
var docGoTestRe = regexp.MustCompile(`dev-env\.sh run go test\b`)

// checkDocComposeLines (C2): on every line (comments and headings included),
// each citation of compose is the D1 form reached through
// "bash scripts/dev-env.sh run ", followed by a space, ")", "`" or the end of
// the line; every "dev-env.sh run go test" gives the secrets to
// ./internal/archtest only (D4): its package arguments, up to the end of the
// shell command, are exactly ./internal/archtest (a flag value is written
// -flag=value).
func checkDocComposeLines(name, src string) []string {
	var problems problemList
	for i, text := range strings.Split(src, "\n") {
		for _, loc := range docComposeRe.FindAllStringIndex(text, -1) {
			at := text[loc[0]:]
			if strings.HasPrefix(at, "docker-compose") {
				problems.addf("%s line %d: legacy docker-compose binary: docker compose outside %q: %q", name, i+1, composeViaEnv+"<sous-commande>", text)
				continue
			}
			before := text[:loc[0]]
			viaRunner := strings.HasSuffix(before, devEnvRunner) && runnerBoundary(strings.TrimSuffix(before, devEnvRunner))
			after, form := strings.CutPrefix(at, composeForm)
			form = form && (after == "" || strings.ContainsRune(" )`", rune(after[0])))
			if !viaRunner || !form {
				problems.addf("%s line %d: docker compose outside %q (D1): %q", name, i+1, composeViaEnv+"<sous-commande>", text)
			}
		}
		for _, loc := range docGoTestRe.FindAllStringIndex(text, -1) {
			rest := text[loc[1]:]
			if end := strings.IndexAny(rest, "`);|&"); end >= 0 {
				rest = rest[:end]
			}
			var pkgs []string
			for _, f := range strings.Fields(rest) {
				if f = strings.Trim(f, `'"`); !strings.HasPrefix(f, "-") {
					pkgs = append(pkgs, f)
				}
			}
			if len(pkgs) == 0 || slices.ContainsFunc(pkgs, func(p string) bool { return p != "./internal/archtest" && p != "./internal/archtest/" }) {
				problems.addf("%s line %d: dev-env.sh run go test gives the secrets of .env.dev to %q, want ./internal/archtest only (D4): %q", name, i+1, pkgs, text)
			}
		}
	}
	return problems
}

// setupRequired are the statements docs/SETUP.md makes about the stack (C2).
func setupRequired() []struct{ text, why string } {
	return []struct{ text, why string }{
		{"Docker Engine 28", "minimum engine of dev-preflight (D3)"},
		{"socket unix local", "only a local unix socket is accepted (D3)"},
		{"`COMPOSE_*`", "the COMPOSE_* variables are ignored (D2)"},
		{"ignorées", "the COMPOSE_* variables are ignored (D2)"},
		{composeViaEnv + "down -v", "full reset in the D1 form"},
		{"go test -tags=integration $(go list ./... | grep -v '/internal/archtest$')", "first pass of D4, without the secrets"},
		{verifySecretLine, "second pass of D4, secrets to ./internal/archtest only"},
	}
}

func checkSetupContent(src string) []string {
	var problems problemList
	for _, r := range setupRequired() {
		if !strings.Contains(src, r.text) {
			problems.addf("docs/SETUP.md: does not state %q (%s)", r.text, r.why)
		}
	}
	return problems
}

// referenceSetupDevSection is the development stack section of docs/SETUP.md
// with the C2 fixes of amendment V3.
const referenceSetupDevSection = "## Pile de développement (M0-T03, M0-T03b)\n" +
	"- Prérequis, vérifiés par `make dev-preflight` et avant toute commande `docker` passée à `dev-env.sh run` : Docker Engine 28 ou plus avec le plugin compose v2, démon joint par un socket unix local (`DOCKER_HOST` vide ou de la forme `unix:///<chemin>`, contexte Docker courant de même forme). Un démon distant (TCP, TLS, `ssh://`) est refusé.\n" +
	"- `make dev` : vérifie Docker (`dev-preflight`), crée `.env.dev` s'il manque (secrets aléatoires, droits 600, ignoré par Git), démarre PostgreSQL, Temporal et OpenBao en mode dev (`bash scripts/dev-env.sh run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml up -d --wait`), puis crée le namespace Temporal `rempart` (rétention 7 jours). Idempotent.\n" +
	"- Ports publiés sur `127.0.0.1` seulement : Temporal `7233`, OpenBao `8200`. PostgreSQL n'est pas publié.\n" +
	"- `make dev-down` arrête la pile et garde le volume de données. Réinitialisation complète : `bash scripts/dev-env.sh run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml down -v`, puis supprimer `.env.dev`. Si `.env.dev` a été perdu alors que le volume `rempart-dev_pgdata` existe, `make dev` refuse de continuer : supprimer le volume (`docker volume rm rempart-dev_pgdata`), puis relancer.\n" +
	"- Toute commande compose s'écrit `bash scripts/dev-env.sh run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml <sous-commande>` : `dev-env.sh` valide `.env.dev` et exporte ses valeurs, qui priment sur celles du shell ; `-p` fixe le projet ; le `-f` explicite empêche la fusion d'un fichier `override`. Les variables `COMPOSE_*` du shell (`COMPOSE_PROJECT_NAME`, `COMPOSE_FILE`, `COMPOSE_ENV_FILES`, etc.) sont ignorées : `dev-env.sh run` les retire avant d'exécuter la commande.\n" +
	"- Ne jamais afficher les secrets : pas de `cat .env.dev`, pas de sous-commande `config` de compose sans filtre `jq` ciblé, pas de `docker inspect` sans `--format` ciblé. Les journaux d'OpenBao sont coupés, car la bannière du mode dev affiche le jeton root.\n" +
	"- Tests d'intégration, en deux passes (`make verify` les enchaîne) : `go test -tags=integration $(go list ./... | grep -v '/internal/archtest$')`, sans aucun secret, puis `bash scripts/dev-env.sh run go test -count=1 -tags=integration ./internal/archtest`, seul paquet qui reçoit les valeurs de `.env.dev` (le script valide le fichier avant de les exporter).\n" +
	"- Docker Hub limite les téléchargements anonymes (erreur 429). Parade : démon lancé avec un miroir, par exemple `dockerd --registry-mirror=https://mirror.gcr.io`, ou `\"registry-mirrors\"` dans `/etc/docker/daemon.json`. Les images restent épinglées par empreinte `sha256`, le miroir ne peut donc pas en substituer une autre.\n"

// composeHeaderLine is line 1 of docker-compose.yml (plan section 3).
const composeHeaderLine = "# Pile de dev (M0-T03). Toujours : bash scripts/dev-env.sh run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml\n"

func TestSetupDocCommands(t *testing.T) {
	t.Run("negative_controls", func(t *testing.T) {
		ref := referenceSetupDevSection
		t.Run("reference_setup", func(t *testing.T) {
			expectProblems(t, append(checkDocComposeLines("docs/SETUP.md", ref), checkSetupContent(ref)...), nil)
		})
		t.Run("reference_compose_header", func(t *testing.T) {
			expectProblems(t, checkDocComposeLines("docker-compose.yml", composeHeaderLine+"name: rempart-dev\n"), nil)
		})
		const reset = "bash scripts/dev-env.sh run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml down -v"
		const secretTest = verifySecretLine
		lines := []struct {
			name, file, src, old, replacement string
			want                              []string
		}{
			{name: "reset_bare", old: reset, replacement: "docker compose --env-file .env.dev -f docker-compose.yml down -v", want: []string{"docs/SETUP.md line 5: docker compose outside"}},
			{name: "inline_up_bare", old: "(`bash scripts/dev-env.sh run docker compose", replacement: "(`docker compose", want: []string{"line 3: docker compose outside"}},
			{name: "cited_alone", old: "pas de sous-commande `config` de compose", replacement: "pas de `docker compose config`", want: []string{"line 7: docker compose outside"}},
			{name: "project_missing", old: "run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml down", replacement: "run docker compose --env-file .env.dev -f docker-compose.yml down", want: []string{"line 5: docker compose outside"}},
			{name: "runner_lookalike", old: "`bash scripts/dev-env.sh run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml <", replacement: "`bash scripts/dev-env.sh.bak run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml <", want: []string{"line 6: docker compose outside"}},
			{name: "file_suffix", old: "-f docker-compose.yml down -v`", replacement: "-f docker-compose.yml.bak down -v`", want: []string{"line 5: docker compose outside"}},
			{name: "legacy_binary", old: "`docker volume rm rempart-dev_pgdata`", replacement: "`docker-compose down -v`", want: []string{"line 5: legacy docker-compose binary"}},
			{name: "go_test_all_packages", old: secretTest, replacement: "bash scripts/dev-env.sh run go test -tags=integration ./...", want: []string{"line 8: dev-env.sh run go test gives the secrets of .env.dev to [\"./...\"]"}},
			{name: "go_test_list", old: secretTest, replacement: "bash scripts/dev-env.sh run go test -tags=integration $(go list ./...)", want: []string{"gives the secrets of .env.dev to [\"$(go\""}},
			{name: "go_test_two_packages", old: secretTest, replacement: secretTest + " ./internal/llm", want: []string{"to [\"./internal/archtest\" \"./internal/llm\"]"}},
			{name: "go_test_no_package", old: secretTest, replacement: "bash scripts/dev-env.sh run go test -count=1 -tags=integration", want: []string{"to [], want ./internal/archtest only"}},
			{name: "go_test_flag_value", old: secretTest, replacement: secretTest + " -run TestDevStack", want: []string{"\"TestDevStack\""}},
			{name: "compose_comment_bare", file: "docker-compose.yml", src: composeHeaderLine, old: "Toujours : bash scripts/dev-env.sh run docker compose -p rempart-dev", replacement: "Toujours : docker compose", want: []string{"docker-compose.yml line 1: docker compose outside"}},
		}
		for _, c := range lines {
			t.Run(c.name, func(t *testing.T) {
				file, src := cmp.Or(c.file, "docs/SETUP.md"), cmp.Or(c.src, ref)
				expectProblems(t, checkDocComposeLines(file, mustReplace(t, src, c.old, c.replacement)), c.want)
			})
		}
		content := []struct{ name, old, replacement, want string }{
			{"engine_recent", "Docker Engine 28 ou plus", "Docker Engine récent", "does not state \"Docker Engine 28\""},
			{"no_unix_socket", "socket unix local", "socket", "does not state \"socket unix local\""},
			{"compose_vars_not_mentioned", "Les variables `COMPOSE_*` du shell (`COMPOSE_PROJECT_NAME`, `COMPOSE_FILE`, `COMPOSE_ENV_FILES`, etc.) sont ignorées : `dev-env.sh run` les retire avant d'exécuter la commande.", "", "does not state \"`COMPOSE_*`\""},
			{"no_plain_pass", "`go test -tags=integration $(go list ./... | grep -v '/internal/archtest$')`, sans aucun secret, puis ", "", "first pass of D4"},
			{"secret_pass_all", "run go test -count=1 -tags=integration ./internal/archtest`", "run go test -count=1 -tags=integration ./...`", "second pass of D4"},
			{"no_reset", "Réinitialisation complète : `bash scripts/dev-env.sh run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml down -v`, puis supprimer `.env.dev`. ", "", "full reset in the D1 form"},
		}
		for _, c := range content {
			t.Run("content_"+c.name, func(t *testing.T) {
				expectProblems(t, checkSetupContent(mustReplace(t, ref, c.old, c.replacement)), []string{c.want})
			})
		}
	})
	t.Run("repository", func(t *testing.T) {
		_, fsys := repoRoot(t)
		setup, err := readRepoFile(fsys, "docs/SETUP.md", "created by M0-T01")
		if err != nil {
			t.Fatal(err)
		}
		compose, err := readRepoFile(fsys, "docker-compose.yml", "created by M0-T03")
		if err != nil {
			t.Fatal(err)
		}
		t.Run("setup_lines", func(t *testing.T) { reportProblems(t, checkDocComposeLines("docs/SETUP.md", setup)) })
		t.Run("setup_content", func(t *testing.T) { reportProblems(t, checkSetupContent(setup)) })
		t.Run("compose_lines", func(t *testing.T) { reportProblems(t, checkDocComposeLines("docker-compose.yml", compose)) })
	})
}
