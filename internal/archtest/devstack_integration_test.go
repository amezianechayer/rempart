//go:build integration

package archtest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"go.temporal.io/sdk/client"
)

// Integration tests of the development stack (docs/plans/M0-pile-dev.md
// section 4.3). They need the stack started by `make dev` and run through
// `bash scripts/dev-env.sh run go test -tags=integration ...`, which exports
// the four values of .env.dev. A missing variable fails the test (D7): they
// are never skipped. Every output is redacted before being logged, and no
// response body carrying a secret is ever logged.

const devStackTimeout = 60 * time.Second

var (
	devStackValueRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
	publishedPortRe = regexp.MustCompile(`:[1-9][0-9]{0,4}$`)
)

// devStackSecrets returns the four values of .env.dev from the environment,
// failing the test (never skipping it) if one is missing or malformed.
func devStackSecrets(t *testing.T) map[string]string {
	t.Helper()
	values := map[string]string{}
	for _, k := range devEnvKeys() {
		v, ok := os.LookupEnv(k)
		switch {
		case !ok || v == "":
			t.Fatalf("%s is not set: run the integration tests with "+
				"`bash scripts/dev-env.sh run go test -tags=integration ...` after `make dev` (D7)", k)
		case !devStackValueRe.MatchString(v):
			t.Fatalf("%s is not 64 lowercase hexadecimal digits (value not shown): check .env.dev with scripts/dev-env.sh", k)
		}
		values[k] = v
	}
	return values
}

// redactSecrets replaces every value of secrets (and any 64-digit hexadecimal
// run) in s, so that s can be logged.
func redactSecrets(s string, secrets map[string]string) string {
	for _, k := range devEnvKeys() {
		if v := secrets[k]; v != "" {
			s = strings.ReplaceAll(s, v, "["+k+" redacted]")
		}
	}
	return redactHex(s)
}

// devStack runs the commands of the integration tests from the repository root.
type devStack struct {
	t       *testing.T
	root    string
	secrets map[string]string
}

func newDevStack(t *testing.T) *devStack {
	t.Helper()
	secrets := devStackSecrets(t)
	root, _ := repoRoot(t)
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("docker is required by the integration tests: %v", err)
	}
	return &devStack{t: t, root: root, secrets: secrets}
}

// baseEnv is the environment of the processes started by these tests: the
// calling environment without COMPOSE_* variables (threat N8: they would
// substitute or merge another compose file) and without PGPASSWORD.
func (s *devStack) baseEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "COMPOSE_") || strings.HasPrefix(kv, "PGPASSWORD=") {
			continue
		}
		env = append(env, kv)
	}
	return env
}

// run runs a process in the repository root with extra environment entries.
func (s *devStack) run(ctx context.Context, extraEnv []string, name string, args ...string) scriptResult {
	s.t.Helper()
	//nolint:gosec // G204: test helper, name is "docker" and args are literals of these tests.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = s.root
	cmd.Env = append(s.baseEnv(), extraEnv...)
	cmd.Stdin = nil
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
		s.t.Fatalf("%s %q: %v", name, args, err)
	}
	return res
}

// compose runs docker compose --env-file .env.dev -f docker-compose.yml args (D9).
func (s *devStack) compose(ctx context.Context, extraEnv []string, args ...string) scriptResult {
	s.t.Helper()
	full := append([]string{"compose", "--env-file", ".env.dev", "-f", "docker-compose.yml"}, args...)
	return s.run(ctx, extraEnv, "docker", full...)
}

// redact hides the secrets in s.
func (s *devStack) redact(v string) string { return redactSecrets(v, s.secrets) }

func (s *devStack) out(r scriptResult) string { return s.redact(r.stdout + r.stderr) }

// requireRunning fails the test unless the three services are running.
func (s *devStack) requireRunning(ctx context.Context) {
	s.t.Helper()
	r := s.compose(ctx, nil, "ps", "--services", "--status", "running")
	if r.code != 0 {
		s.t.Fatalf("compose ps: exit %d: %s (start the stack with make dev)", r.code, s.out(r))
	}
	got := strings.Fields(r.stdout)
	slices.Sort(got)
	if want := []string{"openbao", "postgres", "temporal"}; !slices.Equal(got, want) {
		s.t.Fatalf("running services are %q, want %q (start the stack with make dev)", got, want)
	}
}

func devStackContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), devStackTimeout)
	t.Cleanup(cancel)
	return ctx
}

// isNamespaceNotFound reports whether err is serviceerror.NamespaceNotFound or
// serviceerror.NotFound. The type is matched by name to avoid importing
// go.temporal.io/api directly (it stays an indirect dependency in go.mod).
func isNamespaceNotFound(err error) bool {
	for e := err; e != nil; e = errors.Unwrap(e) {
		switch fmt.Sprintf("%T", e) {
		case "*serviceerror.NamespaceNotFound", "*serviceerror.NotFound":
			return true
		}
	}
	return false
}

func TestDevStackTemporalHealthy(t *testing.T) {
	s := newDevStack(t)
	ctx := devStackContext(t)
	s.requireRunning(ctx)

	opts := client.Options{HostPort: "127.0.0.1:7233", Namespace: "rempart"}
	c, err := client.DialContext(ctx, opts)
	if err != nil {
		t.Fatalf("client.Dial 127.0.0.1:7233: %s", s.redact(err.Error()))
	}
	defer c.Close()
	if _, err := c.CheckHealth(ctx, &client.CheckHealthRequest{}); err != nil {
		t.Fatalf("CheckHealth: %s", s.redact(err.Error()))
	}

	nc, err := client.NewNamespaceClient(opts)
	if err != nil {
		t.Fatalf("NewNamespaceClient: %s", s.redact(err.Error()))
	}
	defer nc.Close()
	resp, err := nc.Describe(ctx, "rempart")
	if err != nil {
		t.Fatalf("Describe(rempart): %s (dev-bootstrap.sh creates it)", s.redact(err.Error()))
	}
	if got := resp.GetConfig().GetWorkflowExecutionRetentionTtl().AsDuration(); got != 168*time.Hour {
		t.Errorf("namespace rempart: retention %v, want 168h0m0s (D6)", got)
	}
	if got := resp.GetNamespaceInfo().GetName(); got != "rempart" {
		t.Errorf("Describe(rempart) returned namespace %q", got)
	}

	switch _, err := nc.Describe(ctx, "default"); {
	case err == nil:
		t.Errorf("namespace default exists, want NotFound (SKIP_DEFAULT_NAMESPACE_CREATION, D6)")
	case !isNamespaceNotFound(err):
		t.Errorf("Describe(default): %T %s, want serviceerror.NamespaceNotFound", err, s.redact(err.Error()))
	}
}

// psqlAs runs `select 1` as role on database db over TCP inside the postgres
// container; the password goes through the environment (-e PGPASSWORD without
// a value), never through an argument.
func (s *devStack) psqlAs(ctx context.Context, role, db, password string) scriptResult {
	s.t.Helper()
	return s.compose(ctx, []string{"PGPASSWORD=" + password},
		"exec", "-T", "-e", "PGPASSWORD", "postgres",
		"psql", "-X", "-h", "127.0.0.1", "-U", role, "-d", db, "-tAc", "select 1")
}

// catalog runs a query as the postgres superuser over the local socket (peer).
func (s *devStack) catalog(ctx context.Context, query string) string {
	s.t.Helper()
	r := s.compose(ctx, nil, "exec", "-T", "-u", "postgres", "postgres",
		"psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres", "-tAc", query)
	if r.code != 0 {
		s.t.Fatalf("catalog query %q: exit %d: %s", query, r.code, s.out(r))
	}
	return strings.TrimSpace(r.stdout)
}

func isConnectRefused(stderr string) bool {
	return strings.Contains(stderr, "permission denied for database") ||
		strings.Contains(stderr, "User does not have CONNECT privilege")
}

func TestDevStackPostgresRolesSeparated(t *testing.T) { // [ADR-0003]
	s := newDevStack(t)
	ctx := devStackContext(t)
	s.requireRunning(ctx)
	rempartPw, temporalPw := s.secrets["REMPART_DB_PASSWORD"], s.secrets["TEMPORAL_DB_PASSWORD"]

	for _, c := range []struct{ role, db, password string }{
		{"rempart", "rempart", rempartPw},
		{"temporal", "temporal", temporalPw},
		{"temporal", "temporal_visibility", temporalPw},
	} {
		r := s.psqlAs(ctx, c.role, c.db, c.password)
		if r.code != 0 || strings.TrimSpace(r.stdout) != "1" {
			t.Errorf("%s on database %s: exit %d, output %q, want select 1 to return 1", c.role, c.db, r.code, s.out(r))
		}
	}

	for _, c := range []struct{ role, db, password string }{
		{"rempart", "temporal", rempartPw},
		{"rempart", "temporal_visibility", rempartPw},
		{"rempart", "postgres", rempartPw},
		{"rempart", "template1", rempartPw},
		{"temporal", "rempart", temporalPw},
		{"temporal", "postgres", temporalPw},
		{"temporal", "template1", temporalPw},
	} {
		r := s.psqlAs(ctx, c.role, c.db, c.password)
		if r.code == 0 || !isConnectRefused(r.stderr) {
			t.Errorf("%s on database %s: exit %d, output %q, want the connection refused "+
				"(permission denied for database, or User does not have CONNECT privilege)", c.role, c.db, r.code, s.out(r))
		}
	}

	// Witness: a wrong password is refused for the right reason, which proves
	// the refusals above are not authentication failures.
	if r := s.psqlAs(ctx, "rempart", "rempart", "FAKE-password"); r.code == 0 || !strings.Contains(r.stderr, "password authentication failed") {
		t.Errorf("rempart with a wrong password: exit %d, output %q, want password authentication failed", r.code, s.out(r))
	}

	// The application role owns nothing and cannot create objects in public.
	r := s.compose(ctx, []string{"PGPASSWORD=" + rempartPw},
		"exec", "-T", "-e", "PGPASSWORD", "postgres",
		"psql", "-X", "-v", "ON_ERROR_STOP=1", "-h", "127.0.0.1", "-U", "rempart", "-d", "rempart", "-tAc", "create table public.rempart_probe (i int)")
	if r.code == 0 || !strings.Contains(r.stderr, "permission denied for schema public") {
		t.Errorf("rempart creating a table in public: exit %d, output %q, want permission denied for schema public", r.code, s.out(r))
	}

	checks := []struct{ what, query, want string }{
		{
			"roles and login attribute",
			"select coalesce(string_agg(rolname || ':' || rolcanlogin, ' ' order by rolname), '') from pg_roles where rolname in ('rempart', 'rempart_owner', 'temporal')",
			"rempart:true rempart_owner:false temporal:true",
		},
		{
			"roles with a privilege (rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls)",
			"select coalesce(string_agg(rolname, ' ' order by rolname), '') from pg_roles where rolname in ('rempart', 'rempart_owner', 'temporal') " +
				"and (rolsuper or rolcreatedb or rolcreaterole or rolreplication or rolbypassrls)",
			"",
		},
		{
			"databases rempart may connect to",
			"select coalesce(string_agg(datname, ' ' order by datname), '') from pg_database where datallowconn and has_database_privilege('rempart', oid, 'CONNECT')",
			"rempart",
		},
		{
			"databases temporal may connect to",
			"select coalesce(string_agg(datname, ' ' order by datname), '') from pg_database where datallowconn and has_database_privilege('temporal', oid, 'CONNECT')",
			"temporal temporal_visibility",
		},
		{
			"databases with TEMPORARY for rempart",
			"select coalesce(string_agg(datname, ' ' order by datname), '') from pg_database where datallowconn and has_database_privilege('rempart', oid, 'TEMPORARY')",
			"",
		},
		{
			"database owners",
			"select string_agg(datname || ':' || pg_get_userbyid(datdba), ' ' order by datname) from pg_database where datname in ('rempart', 'temporal', 'temporal_visibility')",
			"rempart:rempart_owner temporal:temporal temporal_visibility:temporal",
		},
		{
			"memberships of rempart",
			"select count(*) from pg_auth_members m join pg_roles r on r.oid = m.member where r.rolname = 'rempart'",
			"0",
		},
		{
			"age extension installed",
			"select count(*) from pg_extension where extname = 'age'",
			"0",
		},
		{
			"age extension available",
			"select count(*) from pg_available_extensions where name = 'age'",
			"0",
		},
	}
	for _, c := range checks {
		if got := s.catalog(ctx, c.query); got != c.want {
			t.Errorf("catalog, %s: got %q, want %q", c.what, s.redact(got), c.want)
		}
	}
}

// openBaoGet sends a GET to the local OpenBao, without proxy. The body is
// returned to the caller and never logged here.
func openBaoGet(ctx context.Context, t *testing.T, path, token string) (int, []byte) {
	t.Helper()
	httpClient := &http.Client{
		Transport: &http.Transport{Proxy: nil},
		Timeout:   10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:8200"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("GET %s: reading the body: %v", path, err)
	}
	return resp.StatusCode, body
}

func TestDevStackOpenBaoReady(t *testing.T) {
	s := newDevStack(t)
	ctx := devStackContext(t)
	s.requireRunning(ctx)
	token := s.secrets["OPENBAO_DEV_ROOT_TOKEN"]

	code, body := openBaoGet(ctx, t, "/v1/sys/health", "")
	if code != http.StatusOK {
		t.Fatalf("GET /v1/sys/health: status %d, want 200", code)
	}
	var health struct {
		Initialized *bool `json:"initialized"`
		Sealed      *bool `json:"sealed"`
	}
	if err := json.Unmarshal(body, &health); err != nil {
		t.Fatalf("GET /v1/sys/health: %v", err)
	}
	if health.Initialized == nil || !*health.Initialized {
		t.Errorf("OpenBao not initialized")
	}
	if health.Sealed == nil || *health.Sealed {
		t.Errorf("OpenBao sealed")
	}

	for _, c := range []struct{ what, token string }{
		{"without token", ""},
		{"with the token root", "root"},
		{"with a forged token", "s.FAKEFAKEFAKEFAKEFAKEFAKE"},
	} {
		if code, _ := openBaoGet(ctx, t, "/v1/sys/mounts", c.token); code != http.StatusForbidden {
			t.Errorf("GET /v1/sys/mounts %s: status %d, want 403", c.what, code)
		}
	}

	if code, _ := openBaoGet(ctx, t, "/v1/auth/token/lookup-self", token); code != http.StatusOK {
		t.Errorf("GET /v1/auth/token/lookup-self with OPENBAO_DEV_ROOT_TOKEN: status %d, want 200", code)
	}

	code, body = openBaoGet(ctx, t, "/v1/sys/mounts", token)
	if code != http.StatusOK {
		t.Fatalf("GET /v1/sys/mounts with OPENBAO_DEV_ROOT_TOKEN: status %d, want 200", code)
	}
	var mounts struct {
		Data map[string]struct {
			Type string `json:"type"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &mounts); err != nil {
		t.Fatalf("GET /v1/sys/mounts: %v", err)
	}
	var paths []string
	for p, m := range mounts.Data {
		paths = append(paths, p)
		if m.Type == "transit" {
			t.Errorf("mount %s is a transit engine: Transit arrives in M1 (A1)", p)
		}
	}
	slices.Sort(paths)
	if want := []string{"cubbyhole/", "identity/", "secret/", "sys/"}; !slices.Equal(paths, want) {
		t.Errorf("OpenBao mounts are %q, want %q", paths, want)
	}
}

// hostNonLoopbackIPs returns the addresses of the host interfaces that are
// neither loopback nor IPv6 link-local (a link-local address needs a zone).
func hostNonLoopbackIPs(t *testing.T) []net.IP {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatalf("net.InterfaceAddrs: %v", err)
	}
	var ips []net.IP
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.IsLoopback() || n.IP.IsUnspecified() || (n.IP.To4() == nil && n.IP.IsLinkLocalUnicast()) {
			continue
		}
		ips = append(ips, n.IP)
	}
	return ips
}

func TestDevStackLoopbackOnly(t *testing.T) {
	s := newDevStack(t)
	ctx := devStackContext(t)
	s.requireRunning(ctx)

	for _, c := range []struct{ service, port, want string }{
		{"temporal", "7233", "127.0.0.1:7233"},
		{"openbao", "8200", "127.0.0.1:8200"},
	} {
		r := s.compose(ctx, nil, "port", c.service, c.port)
		if r.code != 0 || strings.TrimSpace(r.stdout) != c.want {
			t.Errorf("compose port %s %s: exit %d, output %q, want %q", c.service, c.port, r.code, s.out(r), c.want)
		}
	}
	// compose prints "invalid IP:0" (or nothing) for a port that is not
	// published: any non-zero host port is a publication.
	if r := s.compose(ctx, nil, "port", "postgres", "5432"); publishedPortRe.MatchString(strings.TrimSpace(r.stdout)) {
		t.Errorf("compose port postgres 5432: %q, want nothing (PostgreSQL is not published, D1)", s.out(r))
	}
	r := s.compose(ctx, nil, "ps", "-q", "postgres")
	id := strings.TrimSpace(r.stdout)
	if r.code != 0 || id == "" {
		t.Fatalf("compose ps -q postgres: exit %d: %s", r.code, s.out(r))
	}
	r = s.run(ctx, nil, "docker", "inspect", "--format", "{{json .HostConfig.PortBindings}}", id)
	if got := strings.TrimSpace(r.stdout); r.code != 0 || (got != "{}" && got != "null") {
		t.Errorf("postgres: HostConfig.PortBindings is %q (exit %d), want none (D1)", s.redact(got), r.code)
	}

	ips := hostNonLoopbackIPs(t)
	if len(ips) == 0 {
		t.Fatalf("no non-loopback address on the host: the test cannot prove the ports are loopback only")
	}
	dialer := net.Dialer{Timeout: time.Second}
	for _, ip := range ips {
		for _, port := range []string{"7233", "8200", "5432"} {
			addr := net.JoinHostPort(ip.String(), port)
			dctx, cancel := context.WithTimeout(ctx, time.Second)
			conn, err := dialer.DialContext(dctx, "tcp", addr)
			cancel()
			if err == nil {
				_ = conn.Close()
				t.Errorf("TCP %s accepted a connection: the port must only listen on 127.0.0.1", addr)
			}
		}
	}
	t.Logf("checked %d non-loopback addresses", len(ips))
}

func TestDevStackLogsHaveNoSecrets(t *testing.T) {
	s := newDevStack(t)
	ctx := devStackContext(t)
	s.requireRunning(ctx)

	for _, service := range []string{"postgres", "temporal", "openbao"} {
		r := s.compose(ctx, nil, "logs", "--no-color", service)
		all := r.stdout + r.stderr
		for _, k := range devEnvKeys() {
			if strings.Contains(all, s.secrets[k]) {
				t.Errorf("service %s: logs contain the value of %s", service, k)
			}
		}
		if service != "openbao" && (r.code != 0 || strings.TrimSpace(r.stdout) == "") {
			// Empty logs would make the check above vacuous.
			t.Errorf("service %s: compose logs exit %d with %d bytes, want a readable, non-empty log", service, r.code, len(r.stdout))
		}
	}

	r := s.compose(ctx, nil, "ps", "-q", "openbao")
	id := strings.TrimSpace(r.stdout)
	if r.code != 0 || id == "" {
		t.Fatalf("compose ps -q openbao: exit %d: %s", r.code, s.out(r))
	}
	r = s.run(ctx, nil, "docker", "inspect", "--format", "{{.HostConfig.LogConfig.Type}}", id)
	if got := strings.TrimSpace(r.stdout); r.code != 0 || got != "none" {
		t.Errorf("openbao: LogConfig.Type is %q (exit %d), want none (the dev banner prints the root token, D4)", s.redact(got), r.code)
	}
}
