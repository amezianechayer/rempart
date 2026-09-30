package archtest

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Checks of the hardened development stack (docs/plans/M0-pile-dev-harden.md,
// step A, obligations (an) to (as)): compose only through dev-env.sh run with
// an explicit project, dev-env.sh run overriding the inherited environment and
// dropping COMPOSE_*, dev-preflight.sh refusing remote daemons and engines
// older than 28, postgres-init.sh validating the superuser password, script
// modes. No Docker, no network: docker and psql are fakes on PATH.

// runInEnv runs name like runIn, with extra appended to the minimal
// environment (a later entry replaces an earlier one with the same key).
func runInEnv(t *testing.T, dir string, extra []string, name string, args ...string) scriptResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	//nolint:gosec // G204: test helper, name and args are literals of these tests or temporary paths.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append([]string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"TMPDIR=" + t.TempDir(),
		"LC_ALL=C",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
	}, extra...)
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

// writeExecutable writes a fake command named name in a fresh directory and
// returns that directory, to be put first on PATH.
func writeExecutable(t *testing.T, name, src string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // G302: the fake command must be executable by its owner; temporary directory of this test.
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// writeNamedScript writes a script under test outside any workspace.
func writeNamedScript(t *testing.T, name, src string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func envMap(stdout string) map[string]string {
	got := map[string]string{}
	for _, l := range strings.Split(stdout, "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			got[k] = v
		}
	}
	return got
}

// inheritedComposeVars are five COMPOSE_* variables a caller could set to make
// compose read another file, another project or another env file (T77).
func inheritedComposeVars() []string {
	return []string{
		"COMPOSE_PROJECT_NAME=evil",
		"COMPOSE_FILE=/dev/null",
		"COMPOSE_ENV_FILES=/tmp/evil.env",
		"COMPOSE_PROFILES=evil",
		"COMPOSE_PATH_SEPARATOR=:",
	}
}

// checkDevEnvRunOverridesEnvironment (an), (ao): the values of .env.dev win
// over the inherited environment, no COMPOSE_* variable reaches the command,
// the other variables (DOCKER_HOST) are kept. The same holds when bash has no
// compgen builtin (risk R2: a bash built without programmable completion,
// simulated by BASH_ENV running "enable -n compgen"); refusing to run is also
// acceptable there, running with COMPOSE_* is not.
func checkDevEnvRunOverridesEnvironment(t *testing.T, script string) []string {
	var problems problemList
	dir := newWorkspace(t, wsIgnored)
	writeEnvFile(t, dir, fixtureLines(), 0o600)
	extra := append([]string{
		"OPENBAO_DEV_ROOT_TOKEN=root",
		"POSTGRES_PASSWORD=weak",
		"DOCKER_HOST=unix:///x.sock",
	}, inheritedComposeVars()...)

	noCompgen := filepath.Join(t.TempDir(), "no-compgen.bash")
	if err := os.WriteFile(noCompgen, []byte("enable -n compgen\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct {
		what  string
		extra []string
	}{
		{"", extra},
		{"without compgen: ", append(slices.Clone(extra), "BASH_ENV="+noCompgen)},
	} {
		r := runInEnv(t, dir, v.extra, "bash", script, "run", "env")
		got := envMap(r.stdout)
		if v.what != "" && r.code != 0 && r.stdout == "" {
			continue // refused before running the command: no leak
		}
		expectExit(&problems, v.what+"run env with an inherited environment", r, 0)
		for _, k := range devEnvKeys() {
			if got[k] != fixtureValue(k) {
				problems.addf("%srun env: %s not overridden by .env.dev (the inherited value or none reached the command)", v.what, k)
			}
		}
		for _, kv := range inheritedComposeVars() {
			k, _, _ := strings.Cut(kv, "=")
			if _, ok := got[k]; ok {
				problems.addf("%srun env: %s still exported (compose would read it, T77)", v.what, k)
			}
		}
		for k := range got {
			if strings.HasPrefix(k, "COMPOSE_") && !slices.ContainsFunc(inheritedComposeVars(), func(kv string) bool { return strings.HasPrefix(kv, k+"=") }) {
				problems.addf("%srun env: %s still exported", v.what, k)
			}
		}
		if got["DOCKER_HOST"] != "unix:///x.sock" {
			problems.addf("%srun env: DOCKER_HOST not kept (run only drops COMPOSE_*)", v.what)
		}
	}
	return problems
}

// devScriptNames are the scripts of the development stack (D5).
func devScriptNames() []string {
	return []string{"scripts/dev-env.sh", "scripts/dev-bootstrap.sh", "scripts/dev-preflight.sh", "scripts/dev/postgres-init.sh"}
}

// checkScriptModes (as, D5): no script is writable by the group or others;
// postgres-init.sh is readable and executable by others (uid 999 runs it in
// the container through a read-only bind mount).
func checkScriptModes(modes map[string]fs.FileMode) []string {
	var problems problemList
	for _, name := range slices.Sorted(maps.Keys(modes)) {
		perm := modes[name].Perm()
		if perm&0o022 != 0 {
			problems.addf("%s: mode %o is writable by the group or others (D5)", name, perm)
		}
		if name == "scripts/dev/postgres-init.sh" && perm&0o005 != 0o005 {
			problems.addf("%s: mode %o, others must read and execute it (uid 999 in the container, D5)", name, perm)
		}
	}
	return problems
}

type scriptModeCase struct {
	name  string
	modes map[string]fs.FileMode
	want  []string
}

func scriptModeCases() []scriptModeCase {
	with := func(name string, mode fs.FileMode) map[string]fs.FileMode {
		m := map[string]fs.FileMode{}
		for _, n := range devScriptNames() {
			m[n] = 0o755
		}
		m[name] = mode
		return m
	}
	return []scriptModeCase{
		{name: "all_755", modes: with("scripts/dev-env.sh", 0o755)},
		{name: "dev_env_700", modes: with("scripts/dev-env.sh", 0o700)},
		{name: "dev_env_644", modes: with("scripts/dev-env.sh", 0o644)},
		{name: "dev_env_775", modes: with("scripts/dev-env.sh", 0o775), want: []string{"scripts/dev-env.sh: mode 775 is writable by the group or others"}}, // A15
		{name: "preflight_757", modes: with("scripts/dev-preflight.sh", 0o757), want: []string{"scripts/dev-preflight.sh: mode 757 is writable"}},
		{name: "bootstrap_777", modes: with("scripts/dev-bootstrap.sh", 0o777), want: []string{"scripts/dev-bootstrap.sh: mode 777 is writable"}},
		{name: "postgres_init_751", modes: with("scripts/dev/postgres-init.sh", 0o751), want: []string{"scripts/dev/postgres-init.sh: mode 751, others must read and execute it"}}, // A16
		{name: "postgres_init_754", modes: with("scripts/dev/postgres-init.sh", 0o754), want: []string{"mode 754, others must read and execute it"}},
		{name: "postgres_init_700", modes: with("scripts/dev/postgres-init.sh", 0o700), want: []string{"mode 700, others must read and execute it"}},
	}
}

// referenceDevPreflight is scripts/dev-preflight.sh of
// docs/plans/M0-pile-dev-harden.md section 3, verbatim.
const referenceDevPreflight = `#!/usr/bin/env bash
# Pile de dev (M0-T03b), sans rien démarrer : compose v2, démon local par socket unix,
# Docker Engine 28 ou plus (publication sur 127.0.0.1 étanche).
set -euo pipefail
die() { echo "dev-preflight : $*" >&2; exit 2; }
local_endpoint() { [[ $1 =~ ^unix:///[A-Za-z0-9._/-]+$ && $1 != *..* ]]; }

docker compose version >/dev/null 2>&1 || die "Docker Engine et le plugin compose v2 sont requis (voir docs/SETUP.md)."
if [[ -n ${DOCKER_HOST:-} ]] && ! local_endpoint "$DOCKER_HOST"; then
  die "DOCKER_HOST ne désigne pas un socket unix local : démon distant refusé (voir docs/SETUP.md)."
fi
host=$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null) || die "contexte Docker illisible (voir docs/SETUP.md)."
local_endpoint "$host" || die "le contexte Docker courant ne désigne pas un socket unix local : démon distant refusé (voir docs/SETUP.md)."
docker info >/dev/null 2>&1 || die "démon Docker injoignable (voir docs/SETUP.md)."
version=$(docker version --format '{{.Server.Version}}' 2>/dev/null) || die "version du démon Docker illisible (voir docs/SETUP.md)."
[[ $version =~ ^([0-9]{1,4})\.[0-9] ]] || die "version du démon Docker illisible (voir docs/SETUP.md)."
((10#${BASH_REMATCH[1]} >= 28)) || die "Docker Engine 28 ou plus requis (voir docs/SETUP.md)."
echo "dev-preflight : Docker Engine 28 ou plus, compose v2 et démon local disponibles."
`

const preflightOK = "dev-preflight : Docker Engine 28 ou plus, compose v2 et démon local disponibles.\n"

// fakeDocker answers the four calls of dev-preflight.sh like Docker 29 does
// (risk R1, checked on the real CLI: without an explicit context, "docker
// context inspect" reports DOCKER_HOST when it is set). Every call is logged;
// any other call fails with 99.
const fakeDocker = `#!/usr/bin/env bash
printf '%s\n' "$*" >>"$FAKE_LOG"
case "$*" in
  "compose version") exit "${FAKE_COMPOSE_RC:-0}" ;;
  "context inspect --format {{.Endpoints.docker.Host}}")
    [[ ${FAKE_CONTEXT_RC:-0} == 0 ]] || { echo 'context "x": context not found' >&2; exit 1; }
    if [[ -n ${FAKE_CONTEXT_HOST+set} ]]; then printf '%s\n' "$FAKE_CONTEXT_HOST"
    else printf '%s\n' "${DOCKER_HOST:-unix:///var/run/docker.sock}"; fi ;;
  info) exit "${FAKE_INFO_RC:-0}" ;;
  "version --format {{.Server.Version}}") printf '%s\n' "${FAKE_SERVER_VERSION-29.3.1}" ;;
  *) echo "fake docker: unexpected call" >&2; exit 99 ;;
esac
`

type preflightCase struct {
	name   string
	env    []string // DOCKER_HOST and FAKE_* entries
	code   int
	want   string   // substring of the refusal message
	hidden []string // values that must not appear in the output
	noInfo bool     // docker info must not run (host checks come first)
}

func preflightCases() []preflightCase {
	return []preflightCase{
		{name: "local_socket", env: []string{"FAKE_CONTEXT_HOST=unix:///var/run/docker.sock", "FAKE_SERVER_VERSION=29.3.1"}},
		{name: "rootless", env: []string{"DOCKER_HOST=unix:///run/user/1000/docker.sock", "FAKE_SERVER_VERSION=28.5.2"}},
		{name: "engine_28", env: []string{"FAKE_SERVER_VERSION=28.0.0"}},
		{
			name: "docker_host_tcp", env: []string{"DOCKER_HOST=tcp://127.0.0.1:2375"},
			code: 2, want: "DOCKER_HOST ne désigne pas un socket unix local", hidden: []string{"tcp://127.0.0.1:2375"}, noInfo: true,
		},
		{
			name: "docker_host_ssh", env: []string{"DOCKER_HOST=ssh://deploy@build.example.net"},
			code: 2, want: "DOCKER_HOST ne désigne pas un socket unix local", hidden: []string{"build.example.net"}, noInfo: true,
		},
		{
			name: "docker_host_traversal", env: []string{"DOCKER_HOST=unix:///var/run/../../home/evil/relay.sock"},
			code: 2, want: "DOCKER_HOST ne désigne pas un socket unix local", hidden: []string{"relay.sock"}, noInfo: true,
		},
		{
			name: "docker_host_not_quoted", env: []string{"DOCKER_HOST=unix:///var/run/docker.sock tcp://203.0.113.7:2375"},
			code: 2, want: "DOCKER_HOST ne désigne pas un socket unix local", hidden: []string{"203.0.113.7"}, noInfo: true,
		},
		{
			name: "docker_host_newline", env: []string{"DOCKER_HOST=unix:///var/run/docker.sock\ntcp://203.0.113.9:2375"},
			code: 2, want: "DOCKER_HOST ne désigne pas un socket unix local", hidden: []string{"203.0.113.9"}, noInfo: true,
		},
		{
			name: "context_tcp", env: []string{"FAKE_CONTEXT_HOST=tcp://203.0.113.7:2376"},
			code: 2, want: "le contexte Docker courant ne désigne pas un socket unix local", hidden: []string{"203.0.113.7"}, noInfo: true,
		},
		{
			name: "context_ssh", env: []string{"FAKE_CONTEXT_HOST=ssh://ops@203.0.113.8"},
			code: 2, want: "le contexte Docker courant ne désigne pas un socket unix local", hidden: []string{"203.0.113.8"}, noInfo: true,
		},
		{
			name: "context_error", env: []string{"FAKE_CONTEXT_RC=1"},
			code: 2, want: "contexte Docker illisible", hidden: []string{"context not found"}, noInfo: true,
		},
		{
			name: "context_empty", env: []string{"FAKE_CONTEXT_HOST="},
			code: 2, want: "contexte Docker", noInfo: true,
		},
		{name: "engine_27", env: []string{"FAKE_SERVER_VERSION=27.5.1"}, code: 2, want: "Docker Engine 28 ou plus requis", hidden: []string{"27.5.1"}},
		{name: "engine_octal_like", env: []string{"FAKE_SERVER_VERSION=08.1.0"}, code: 2, want: "Docker Engine 28 ou plus requis", hidden: []string{"08.1.0"}},
		{name: "engine_garbage", env: []string{"FAKE_SERVER_VERSION=podman-5.2"}, code: 2, want: "version du démon Docker illisible", hidden: []string{"podman-5.2"}},
		{name: "engine_empty", env: []string{"FAKE_SERVER_VERSION="}, code: 2, want: "version du démon Docker illisible"},
		{name: "compose_missing", env: []string{"FAKE_COMPOSE_RC=1"}, code: 2, want: "plugin compose v2 sont requis", noInfo: true},
		{name: "daemon_down", env: []string{"FAKE_INFO_RC=1"}, code: 2, want: "démon Docker injoignable"},
	}
}

// runPreflightCase runs the script under test with the fake docker first on
// PATH and returns its departures from c.
func runPreflightCase(t *testing.T, script string, c preflightCase) []string {
	t.Helper()
	var problems problemList
	bin := writeExecutable(t, "docker", fakeDocker)
	log := filepath.Join(t.TempDir(), "docker.log")
	extra := append([]string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "FAKE_LOG=" + log}, c.env...)
	r := runInEnv(t, t.TempDir(), extra, "bash", script)
	var calls []string
	if data, err := fs.ReadFile(os.DirFS(filepath.Dir(log)), filepath.Base(log)); err == nil {
		calls = strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	}
	out := r.stdout + r.stderr
	if r.code != c.code {
		problems.addf("%s: exit %d, want %d; output: %q", c.name, r.code, c.code, out)
	}
	if c.code == 0 {
		if r.stdout != preflightOK {
			problems.addf("%s: stdout %q, want %q", c.name, r.stdout, preflightOK)
		}
		if !slices.Contains(calls, "info") || !slices.Contains(calls, "version --format {{.Server.Version}}") {
			problems.addf("%s: docker calls %q, want info and version", c.name, calls)
		}
	} else {
		if !strings.Contains(r.stderr, c.want) {
			problems.addf("%s: stderr %q does not mention %q", c.name, r.stderr, c.want)
		}
		if strings.Contains(r.stdout, preflightOK) {
			problems.addf("%s: success message printed despite the refusal", c.name)
		}
	}
	if c.noInfo && slices.Contains(calls, "info") {
		problems.addf("%s: docker info ran before the host checks refused (D3)", c.name)
	}
	for _, h := range c.hidden {
		if strings.Contains(out, h) {
			problems.addf("%s: output shows the value %q (no value is displayed, D3)", c.name, h)
		}
	}
	return problems
}

func checkDevPreflight(t *testing.T, script string) []string {
	t.Helper()
	var problems []string
	for _, c := range preflightCases() {
		problems = append(problems, runPreflightCase(t, script, c)...)
	}
	return problems
}

func TestDevPreflightScript(t *testing.T) {
	for _, tool := range []string{"bash"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s is required by these tests: %v", tool, err)
		}
	}
	t.Run("negative_controls", func(t *testing.T) {
		script := writeNamedScript(t, "dev-preflight.sh", referenceDevPreflight)
		for _, c := range preflightCases() {
			t.Run("reference/"+c.name, func(t *testing.T) { expectProblems(t, runPreflightCase(t, script, c), nil) })
		}
		mutations := []struct {
			name, old, replacement string
			want                   []string
		}{
			{
				name: "no_docker_host_check", // A8
				old:  `if [[ -n ${DOCKER_HOST:-} ]] && ! local_endpoint "$DOCKER_HOST"; then`, replacement: "if false; then",
				want: []string{"docker_host_tcp: stderr", "docker_host_not_quoted: stderr"},
			},
			{
				name: "docker_host_unquoted",
				old:  `! local_endpoint "$DOCKER_HOST"; then`, replacement: `! local_endpoint $DOCKER_HOST; then`,
				want: []string{"docker_host_not_quoted: stderr"},
			},
			{
				name: "no_context_check", // A9
				old:  `local_endpoint "$host" || die`, replacement: "true || die",
				want: []string{"context_tcp: exit 0, want 2", "context_ssh: exit 0, want 2", "context_tcp: docker info ran"},
			},
			{
				name: "engine_min_20", // A10
				old:  ">= 28))", replacement: ">= 20))",
				want: []string{"engine_27: exit 0, want 2"},
			},
			{
				name: "lax_endpoint", // A11
				old:  "^unix:///[A-Za-z0-9._/-]+$", replacement: "^[a-z]+://.+$",
				want: []string{"docker_host_tcp: exit 0, want 2", "docker_host_ssh: exit 0, want 2", "context_tcp: exit 0, want 2"},
			},
			{
				name: "no_traversal_check",
				old:  " && $1 != *..* ]]", replacement: " ]]",
				want: []string{"docker_host_traversal: exit 0, want 2"},
			},
			{
				name: "info_before_host_checks",
				old:  "docker compose version >/dev/null 2>&1 || die", replacement: "docker info >/dev/null 2>&1 || true\ndocker compose version >/dev/null 2>&1 || die",
				want: []string{"docker_host_tcp: docker info ran before the host checks refused"},
			},
			{
				name: "prints_host",
				old:  `local_endpoint "$host" || die "`, replacement: `local_endpoint "$host" || die "$host : `,
				want: []string{"context_tcp: output shows the value"},
			},
			{
				name: "no_compose_check",
				old:  "docker compose version >/dev/null 2>&1 || die", replacement: "true || die",
				want: []string{"compose_missing: exit 0, want 2"},
			},
			{
				name: "no_daemon_check",
				old:  "docker info >/dev/null 2>&1 || die", replacement: "true || die",
				want: []string{"daemon_down: exit 0, want 2", "local_socket: docker calls"},
			},
		}
		for _, m := range mutations {
			t.Run(m.name, func(t *testing.T) {
				mutated := writeNamedScript(t, "dev-preflight.sh", mustReplace(t, referenceDevPreflight, m.old, m.replacement))
				expectProblems(t, checkDevPreflight(t, mutated), m.want)
			})
		}
	})
	t.Run("repository", func(t *testing.T) {
		_, fsys := repoRoot(t)
		src, err := readRepoFile(fsys, "scripts/dev-preflight.sh", "created by M0-T03b")
		if err != nil {
			t.Fatal(err)
		}
		script := writeNamedScript(t, "dev-preflight.sh", src)
		for _, c := range preflightCases() {
			t.Run(c.name, func(t *testing.T) { reportProblems(t, runPreflightCase(t, script, c)) })
		}
	})
}

// composeForm is the only accepted compose invocation (D1, D2), without its subcommand.
const composeForm = "docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml"

// runnerBoundary reports whether s, the text before "bash scripts/dev-env.sh
// run ", ends where a shell word starts.
func runnerBoundary(s string) bool {
	return s == "" || strings.ContainsRune(" \t(;&|@{`", rune(s[len(s)-1]))
}

// checkComposeInvocations (an): on every non-comment logical line, each
// compose call but "docker compose version" is exactly the D1 form, reached
// through "bash scripts/dev-env.sh run ", and followed by a space, ")" or the
// end of the line. The legacy docker-compose binary is refused.
func checkComposeInvocations(name, src string) []string {
	var problems problemList
	for _, l := range joinShellLines(src) {
		text := l.Text
		if strings.HasPrefix(strings.TrimLeft(text, " \t"), "#") {
			continue
		}
		for _, loc := range composeCallRe.FindAllStringIndex(text, -1) {
			at := text[loc[0]:]
			if strings.HasPrefix(at, "docker-compose") {
				problems.addf("%s line %d: legacy docker-compose binary: docker compose outside %q: %q", name, l.Num, composeViaEnv+"<subcommand>", text)
				continue
			}
			if strings.HasPrefix(at[len("docker compose"):], " version") {
				continue
			}
			before := text[:loc[0]]
			viaRunner := strings.HasSuffix(before, devEnvRunner) && runnerBoundary(strings.TrimSuffix(before, devEnvRunner))
			after, form := strings.CutPrefix(at, composeForm)
			form = form && (after == "" || after[0] == ' ' || after[0] == ')')
			if !viaRunner || !form {
				problems.addf("%s line %d: docker compose outside %q (D1, D2): %q", name, l.Num, composeViaEnv+"<subcommand>", text)
			}
		}
	}
	return problems
}

// joinShellLines splits a shell script (or the Makefile, already accepted by
// lexMakefile) into the logical lines bash reads, for checkComposeInvocations
// (M0-T04b V3, D18): a physical line ending with an odd number of backslashes
// is joined with the next one (final backslash and spaces before it removed,
// one space, leading blanks of the next line removed), unless the logical line
// built so far holds a shell comment (shellComment): bash never continues a
// comment. An even number of backslashes ends the line. It is not the Makefile
// lexer: parseMakefile uses lexMakefile (M0-T04b V2, D11 to D14), stricter,
// which refuses a make comment ending with a backslash; make itself joins a
// recipe line ending with a backslash, but the shell it runs does not continue
// a comment, so the next physical line runs on its own.
func joinShellLines(src string) []makeLine {
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
		pending = trailingBackslashes(last.Text)%2 == 1 && !shellComment(last.Text)
		if pending {
			last.Text = strings.TrimRight(strings.TrimSuffix(last.Text, `\`), " ")
		}
	}
	return lines
}

// shellComment reports whether the logical line text holds a bash comment: a
// "#" outside quotes, not escaped by a backslash, at the start of a word (line
// start, or after a blank or one of ; & | ( ) < >). A line starting with a tab
// may be a Makefile recipe line: its @ - + prefixes, which make removes before
// running the shell, are skipped first. Approximation on the safe side for
// D18: a line wrongly seen as a comment is not joined, so its next physical
// line is checked on its own.
func shellComment(text string) bool {
	i := 0
	if strings.HasPrefix(text, "\t") {
		for i < len(text) && strings.IndexByte(" \t@-+", text[i]) >= 0 {
			i++
		}
	}
	wordStart := true
	var quote byte
	for ; i < len(text); i++ {
		c := text[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
		case quote == '"':
			switch c {
			case '\\':
				i++
			case '"':
				quote = 0
			}
		case c == '\\':
			i++
		case c == '\'' || c == '"':
			quote = c
		case c == '#' && wordStart:
			return true
		}
		wordStart = quote == 0 && strings.IndexByte(" \t;&|()<>", c) >= 0
	}
	return false
}

// TestJoinShellLines (M0-T04b V3, D18): the logical lines bash reads. A
// physical line continues only if it ends with an odd number of backslashes
// and holds no shell comment (an unquoted, unescaped "#" starting a word,
// after the @ - + prefixes of a Makefile recipe line); bash never continues a
// comment, even one started on a joined line.
func TestJoinShellLines(t *testing.T) {
	type line = makeLine
	for _, c := range []struct {
		name, src string
		want      []line
	}{
		{"one_backslash", "a \\\n  b\n", []line{{1, "a b"}, {3, ""}}},
		{"two_backslashes", "a \\\\\nb\n", []line{{1, `a \\`}, {2, "b"}, {3, ""}}},
		{"three_backslashes", "a \\\\\\\nb", []line{{1, `a \\ b`}}},
		{"four_backslashes", "a \\\\\\\\\nb", []line{{1, `a \\\\`}, {2, "b"}}},
		{"column0_comment", "# a \\\nb", []line{{1, `# a \`}, {2, "b"}}},
		{"indented_comment", "  \t# a \\\nb", []line{{1, "  \t# a \\"}, {2, "b"}}},
		{"recipe_comment", "\t@# a \\\n\tb", []line{{1, "\t@# a \\"}, {2, "\tb"}}},
		{"recipe_prefixes_comment", "\t-+@ # a \\\n\tb", []line{{1, "\t-+@ # a \\"}, {2, "\tb"}}},
		{"trailing_comment", "a # b \\\nc", []line{{1, `a # b \`}, {2, "c"}}},
		{"trailing_comment_tab", "a\t#b \\\nc", []line{{1, "a\t#b \\"}, {2, "c"}}},
		{"comment_on_joined_line", "a \\\n # b \\\nc", []line{{1, `a # b \`}, {3, "c"}}},
		{"comment_after_operator", "a;# b \\\nc", []line{{1, `a;# b \`}, {2, "c"}}},
		{"double_quoted_hash", "echo \"# x\" \\\nb", []line{{1, `echo "# x" b`}}},
		{"single_quoted_hash", "echo '# x' \\\nb", []line{{1, `echo '# x' b`}}},
		{"escaped_hash", "echo \\# x \\\nb", []line{{1, `echo \# x b`}}},
		{"hash_inside_word", "echo a#b $# ${#x} ${v#*.} \\\nb", []line{{1, "echo a#b $# ${#x} ${v#*.} b"}}},
		{"escaped_quote_then_hash", "echo \"a\\\"\" # c \\\nb", []line{{1, `echo "a\"" # c \`}, {2, "b"}}},
		{"double_quoted_blank_hash", "echo \"a # x\" \\\nb", []line{{1, `echo "a # x" b`}}},
		{"single_quoted_blank_hash", "echo 'a # x' \\\nb", []line{{1, `echo 'a # x' b`}}},
		{"escaped_blank_hash", "echo a\\ #b \\\nc", []line{{1, `echo a\ #b c`}}},
		{"escaped_quote_in_double_quotes", "echo \"a\\\" # x\" \\\nb", []line{{1, `echo "a\" # x" b`}}},
		{"backslash_in_single_quotes", "echo 'a\\' # c \\\nb", []line{{1, `echo 'a\' # c \`}, {2, "b"}}},
		{"crlf", "a \\\r\nb\r\n", []line{{1, "a b"}, {3, ""}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := joinShellLines(c.src); !slices.Equal(got, c.want) {
				t.Errorf("joinShellLines(%q) =\n%+v\nwant\n%+v", c.src, got, c.want)
			}
		})
	}
}

// bootstrapComposeLine is line 4 of scripts/dev-bootstrap.sh (section 3).
const bootstrapComposeLine = "compose=(bash scripts/dev-env.sh run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml)"

// referenceDevBootstrap is scripts/dev-bootstrap.sh of docs/plans/M0-pile-dev.md
// section 3.4 with line 4 of docs/plans/M0-pile-dev-harden.md section 3.
const referenceDevBootstrap = `#!/usr/bin/env bash
# Préparation idempotente après up --wait (M0-T03). A1 : ni Transit, ni clé, ni jeton du worker.
set -euo pipefail
` + bootstrapComposeLine + `
tcli() { "${compose[@]}" exec -T temporal temporal "$@" --address temporal:7233 >/dev/null 2>&1; }
ok=
for _ in $(seq 1 60); do
  # Un namespace créé met quelques secondes à atteindre le cache : on réessaie la mise à jour (V1).
  if tcli operator namespace update --namespace rempart --retention 168h; then ok=1; break; fi
  tcli operator namespace create --namespace rempart --retention 168h || true
  sleep 2
done
[[ -n $ok ]] || { echo "dev-bootstrap : namespace Temporal rempart indisponible." >&2; exit 2; }
"${compose[@]}" exec -T openbao bao status -address=http://127.0.0.1:8200 >/dev/null \
  || { echo "dev-bootstrap : OpenBao scellé ou injoignable." >&2; exit 2; }
echo "dev-bootstrap : pile prête."
`

func TestComposeOnlyThroughDevEnv(t *testing.T) {
	t.Run("negative_controls", func(t *testing.T) {
		makefile := referenceDevMakefile(t)
		const upForm = "bash scripts/dev-env.sh run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml up"
		cases := []struct {
			name, file, src string
			want            []string
		}{
			{name: "conforming", file: "Makefile", src: makefile},
			{name: "conforming_bootstrap", file: "scripts/dev-bootstrap.sh", src: referenceDevBootstrap},
			{name: "conforming_version_and_comment", file: "scripts/x.sh", src: "docker compose version >/dev/null\n# docker compose up -d\n  # docker-compose up\n"},
			{
				name: "makefile_up_bare", file: "Makefile", // A1
				src:  mustReplace(t, makefile, upForm, "docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml up"),
				want: []string{"Makefile line", "docker compose outside"},
			},
			{
				name: "makefile_down_bare", file: "Makefile", // A2
				src:  mustReplace(t, makefile, "then bash scripts/dev-env.sh run docker compose", "then docker compose"),
				want: []string{"Makefile line", "docker compose outside"},
			},
			{
				name: "bootstrap_array_bare", file: "scripts/dev-bootstrap.sh", // A4
				src:  mustReplace(t, referenceDevBootstrap, "compose=(bash scripts/dev-env.sh run docker compose", "compose=(docker compose"),
				want: []string{"scripts/dev-bootstrap.sh line 4: docker compose outside"},
			},
			{
				name: "project_missing", file: "Makefile", // A3
				src:  mustReplace(t, makefile, "-p rempart-dev --env-file .env.dev -f docker-compose.yml up", "--env-file .env.dev -f docker-compose.yml up"),
				want: []string{"docker compose outside"},
			},
			{
				name: "project_other", file: "scripts/dev-bootstrap.sh",
				src:  mustReplace(t, referenceDevBootstrap, "-p rempart-dev ", "-p evil "),
				want: []string{"scripts/dev-bootstrap.sh line 4: docker compose outside"},
			},
			{
				name: "project_after_file", file: "Makefile",
				src:  mustReplace(t, makefile, "-p rempart-dev --env-file .env.dev -f docker-compose.yml up", "--env-file .env.dev -f docker-compose.yml -p rempart-dev up"),
				want: []string{"docker compose outside"},
			},
			{
				name: "runner_lookalike", file: "scripts/dev-bootstrap.sh",
				src:  mustReplace(t, referenceDevBootstrap, "bash scripts/dev-env.sh run", "bash scripts/dev-env.sh.bak run"),
				want: []string{"scripts/dev-bootstrap.sh line 4: docker compose outside"},
			},
			{
				name: "runner_other_path", file: "scripts/dev-bootstrap.sh",
				src:  mustReplace(t, referenceDevBootstrap, "bash scripts/dev-env.sh run", "bash /tmp/scripts/dev-env.sh run"),
				want: []string{"docker compose outside"},
			},
			{
				name: "runner_glued", file: "scripts/dev-bootstrap.sh",
				src:  mustReplace(t, referenceDevBootstrap, "compose=(bash scripts/dev-env.sh run", "compose=(xbash scripts/dev-env.sh run"),
				want: []string{"docker compose outside"},
			},
			{
				name: "file_suffix", file: "scripts/dev-bootstrap.sh",
				src:  mustReplace(t, referenceDevBootstrap, "-f docker-compose.yml)", "-f docker-compose.yml.bak)"),
				want: []string{"docker compose outside"},
			},
			{
				name: "legacy_binary", file: "scripts/dev-bootstrap.sh",
				src:  mustReplace(t, referenceDevBootstrap, "run docker compose -p", "run docker-compose -p"),
				want: []string{"legacy docker-compose binary"},
			},
			{
				name: "continuation_line", file: "scripts/x.sh",
				src:  "#!/usr/bin/env bash\ntrue && \\\n  docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml up -d\n",
				want: []string{"scripts/x.sh line 2: docker compose outside"},
			},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) { expectProblems(t, checkComposeInvocations(c.file, c.src), c.want) })
		}
	})
	// V3, D18 (third BLOCK): bash never continues a comment and only an odd
	// number of trailing backslashes continues a line. A compose call bash runs
	// on its own line must be checked on its own line: joined to a comment it
	// was skipped, joined behind a runner written in a comment it looked
	// conforming. Script without behavior test: a copy of scripts/check-tools.sh.
	t.Run("shell_line_joins", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join("testdata", "shell", "check-tools.sh"))
		if err != nil {
			t.Fatal(err)
		}
		tools := string(data)
		if !strings.HasSuffix(tools, "\n") {
			t.Fatal("testdata/shell/check-tools.sh must end with a newline")
		}
		next := strings.Count(tools, "\n") + 1 // number of the first appended line
		const (
			file    = "scripts/check-tools.sh"
			other   = "docker compose -p other up -d"
			runner  = "bash scripts/dev-env.sh run "
			fullUp  = composeForm + " up -d"
			outside = "docker compose outside"
		)
		at := func(n int) string { return fmt.Sprintf("%s line %d: %s", file, n, outside) }
		makefile := referenceDevMakefile(t)
		recipeComment := editRule(t, makefile, "dev-preflight", func(rule string, recipe []string) []string {
			return slices.Concat([]string{rule}, recipe, []string{"\t@# compose \\", "\t" + other})
		})
		cases := []struct {
			name, file, src string
			want            []string // nil: conforming
		}{
			{name: "fixture_conforming", file: file, src: tools},
			{name: "comment_then_call", file: file, src: tools + "# compose \\\n" + other + "\n", want: []string{at(next + 1)}},                             // D18 a
			{name: "indented_comment_then_call", file: file, src: tools + "  # compose \\\n  " + other + "\n", want: []string{at(next + 1)}},                // D18 a
			{name: "even_backslashes_then_call", file: file, src: tools + "echo a \\\\\n" + other + "\n", want: []string{at(next + 1)}},                     // D18 b
			{name: "four_backslashes_then_call", file: file, src: tools + "echo a \\\\\\\\\n" + other + "\n", want: []string{at(next + 1)}},                 // D18 b
			{name: "runner_in_comment_then_form", file: file, src: tools + "# " + runner + "\\\n" + fullUp + "\n", want: []string{at(next + 1)}},            // D18 a
			{name: "runner_in_trailing_comment", file: file, src: tools + "true # " + runner + "\\\n" + fullUp + "\n", want: []string{at(next + 1)}},        // D18 a, trailing comment
			{name: "runner_after_even_backslashes", file: file, src: tools + "echo " + runner + "\\\\\n" + fullUp + "\n", want: []string{at(next + 1)}},     // D18 b
			{name: "comment_inside_continuation", file: file, src: tools + "true \\\n  # " + runner + "\\\n" + fullUp + "\n", want: []string{at(next + 2)}}, // bash: the comment ends the joined line
			{
				name: "recipe_comment_then_call", file: "Makefile", src: recipeComment,
				want: []string{fmt.Sprintf("Makefile line %d: %s", exactLine(t, recipeComment, "\t"+other), outside)},
			},
			// Continuations bash does make: the joined line is the one checked.
			{name: "odd_backslashes_join", file: file, src: tools + "true && \\\\\\\n  " + other + "\n", want: []string{at(next)}},
			{name: "runner_then_form", file: file, src: tools + "true && " + runner + "\\\n  " + fullUp + "\n"},
			{name: "quoted_hash_then_form", file: file, src: tools + "echo \"#\" '#' && " + runner + "\\\n  " + fullUp + "\n"},
			{name: "escaped_hash_then_form", file: file, src: tools + "echo \\# a#b $# ${#x} ${v#*.} && " + runner + "\\\n  " + fullUp + "\n"},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				problems := checkComposeInvocations(c.file, c.src)
				expectProblems(t, problems, c.want)
				if c.want != nil && len(problems) != len(c.want) {
					t.Errorf("%d problems, want %d:\n%s", len(problems), len(c.want), strings.Join(problems, "\n"))
				}
			})
		}
	})
	t.Run("repository", func(t *testing.T) {
		_, fsys := repoRoot(t)
		src, err := readRepoFile(fsys, "Makefile", "created by M0-T01")
		if err != nil {
			t.Fatal(err)
		}
		reportProblems(t, checkComposeInvocations("Makefile", src))
		err = fs.WalkDir(fsys, "scripts", func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil || d.IsDir() {
				return walkErr
			}
			data, readErr := fs.ReadFile(fsys, path)
			if readErr != nil {
				return readErr
			}
			reportProblems(t, checkComposeInvocations(path, string(data)))
			return nil
		})
		if err != nil {
			t.Fatalf("scripts: %v", err)
		}
	})
}

// checkDevBootstrap (an): the only line of dev-bootstrap.sh naming docker is
// the compose array of section 3; every docker call goes through it.
func checkDevBootstrap(src string) []string {
	var problems problemList
	var docker []string
	for _, l := range strings.Split(src, "\n") {
		if strings.Contains(l, "docker") {
			docker = append(docker, l)
		}
	}
	if !slices.Equal(docker, []string{bootstrapComposeLine}) {
		problems.addf("scripts/dev-bootstrap.sh: lines naming docker are %q, want exactly [%q] (D1)", docker, bootstrapComposeLine)
	}
	return problems
}

func TestDevBootstrapScript(t *testing.T) {
	t.Run("negative_controls", func(t *testing.T) {
		valid := referenceDevBootstrap
		cases := []struct {
			name, src string
			want      []string
		}{
			{name: "valid", src: valid},
			{
				name: "old_form",
				src:  mustReplace(t, valid, bootstrapComposeLine, "compose=(docker compose --env-file .env.dev -f docker-compose.yml)"),
				want: []string{"lines naming docker are [\"compose=(docker compose --env-file .env.dev -f docker-compose.yml)\"]"},
			},
			{
				name: "no_project",
				src:  mustReplace(t, valid, " -p rempart-dev", ""),
				want: []string{"lines naming docker are"},
			},
			{
				name: "second_docker_call",
				src:  mustReplace(t, valid, "echo \"dev-bootstrap : pile prête.\"", "docker exec rempart-dev-openbao-1 bao status >/dev/null\necho \"dev-bootstrap : pile prête.\""),
				want: []string{"docker exec rempart-dev-openbao-1"},
			},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) { expectProblems(t, checkDevBootstrap(c.src), c.want) })
		}
	})
	t.Run("repository", func(t *testing.T) {
		_, fsys := repoRoot(t)
		src, err := readRepoFile(fsys, "scripts/dev-bootstrap.sh", "created by M0-T03")
		if err != nil {
			t.Fatal(err)
		}
		reportProblems(t, checkDevBootstrap(src))
	})
}

// referencePostgresInitHarden returns scripts/dev/postgres-init.sh with line 5
// of docs/plans/M0-pile-dev-harden.md section 3 (ar: POSTGRES_PASSWORD checked).
func referencePostgresInitHarden(t *testing.T) string {
	t.Helper()
	return mustReplace(t, referencePostgresInit,
		"for v in TEMPORAL_DB_PASSWORD REMPART_DB_PASSWORD; do",
		"for v in POSTGRES_PASSWORD TEMPORAL_DB_PASSWORD REMPART_DB_PASSWORD; do")
}

// fakePsql drains its standard input and leaves a witness file.
const fakePsql = `#!/usr/bin/env bash
cat >/dev/null
: >"$FAKE_WITNESS"
`

// checkPostgresInitValidates (ar): valid passwords reach psql; a missing or
// malformed POSTGRES_PASSWORD or TEMPORAL_DB_PASSWORD stops the script with
// code 2 before psql, without printing any value.
func checkPostgresInitValidates(t *testing.T, script string) []string {
	t.Helper()
	var problems problemList
	valid := map[string]string{}
	for _, k := range []string{"POSTGRES_PASSWORD", "TEMPORAL_DB_PASSWORD", "REMPART_DB_PASSWORD"} {
		valid[k] = fixtureValue(k)
	}
	with := func(k, v string, drop bool) map[string]string {
		m := maps.Clone(valid)
		if drop {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	cases := []struct {
		name string
		env  map[string]string
		code int
	}{
		{"valid", valid, 0},
		{"postgres_missing", with("POSTGRES_PASSWORD", "", true), 2},
		{"postgres_root", with("POSTGRES_PASSWORD", "root", false), 2},
		{"postgres_uppercase", with("POSTGRES_PASSWORD", strings.ToUpper(fixtureValue("POSTGRES_PASSWORD")), false), 2},
		{"postgres_63_digits", with("POSTGRES_PASSWORD", strings.Repeat("7", 63), false), 2},
		{"temporal_missing", with("TEMPORAL_DB_PASSWORD", "", true), 2},
	}
	bin := writeExecutable(t, "psql", fakePsql)
	for _, c := range cases {
		witness := filepath.Join(t.TempDir(), "psql-ran")
		extra := []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "FAKE_WITNESS=" + witness}
		for _, k := range slices.Sorted(maps.Keys(c.env)) {
			extra = append(extra, k+"="+c.env[k])
		}
		r := runInEnv(t, t.TempDir(), extra, "bash", script)
		if r.code != c.code {
			problems.addf("%s: exit %d, want %d; output: %q", c.name, r.code, c.code, r.output())
		}
		ran := exists(t, witness)
		switch {
		case c.code == 0 && !ran:
			problems.addf("%s: psql did not run with valid passwords", c.name)
		case c.code != 0 && ran:
			problems.addf("%s: psql ran despite an invalid password", c.name)
		}
		for k, v := range c.env {
			if strings.Contains(r.stdout+r.stderr, v) {
				problems.addf("%s: output contains the value of %s", c.name, k)
			}
		}
	}
	return problems
}

func TestPostgresInitValidatesPasswords(t *testing.T) {
	t.Run("negative_controls", func(t *testing.T) {
		harden := referencePostgresInitHarden(t)
		t.Run("reference", func(t *testing.T) {
			expectProblems(t, checkPostgresInitValidates(t, writeNamedScript(t, "postgres-init.sh", harden)), nil)
		})
		t.Run("reference_static", func(t *testing.T) { expectProblems(t, checkPostgresInit(harden), nil) })
		t.Run("m0_t03_form", func(t *testing.T) { // A7: POSTGRES_PASSWORD not checked
			expectProblems(t, checkPostgresInitValidates(t, writeNamedScript(t, "postgres-init.sh", referencePostgresInit)),
				[]string{"postgres_root: exit 0, want 2", "postgres_root: psql ran despite an invalid password", "postgres_missing: exit 0, want 2"})
		})
		t.Run("prints_value", func(t *testing.T) {
			leaky := mustReplace(t, harden, `echo "postgres-init : $v absent ou mal formé."`, `echo "postgres-init : $v=${!v:-} absent ou mal formé."`)
			expectProblems(t, checkPostgresInitValidates(t, writeNamedScript(t, "postgres-init.sh", leaky)),
				[]string{"postgres_root: output contains the value of POSTGRES_PASSWORD"})
		})
	})
	t.Run("repository", func(t *testing.T) {
		_, fsys := repoRoot(t)
		src, err := readRepoFile(fsys, "scripts/dev/postgres-init.sh", "created by M0-T03")
		if err != nil {
			t.Fatal(err)
		}
		reportProblems(t, checkPostgresInitValidates(t, writeNamedScript(t, "postgres-init.sh", src)))
	})
}
