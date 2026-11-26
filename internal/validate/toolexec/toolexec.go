// Package toolexec is the only runner of external commands of the IaC chain
// (ADR 0014 D6, rule exec-confined, threat T8): no shell, a built
// environment from an allow-list, a workspace created by Rempart, a checksum
// checked right before the run on a binary no one else can change, a timeout
// that kills the tool and all its descendants, bounded outputs. Every run is
// isolated (ADR 0015, T157): new namespaces, a closed read-only tree, no
// network, no capability; without the full isolation nothing runs.
package toolexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

// UnreachableProxy is the proxy forced on every tool: a local address where
// nothing listens, so a tool that tries the network fails (D8, risk 1:
// declarative, the production isolation is a network namespace).
const UnreachableProxy = "http://127.0.0.1:9"

// Errors of Run. Fixed messages: never a value of the spec or of the tool.
var (
	ErrSpec           = errors.New("toolexec: invalid spec")
	ErrChecksum       = errors.New("toolexec: tool checksum mismatch")
	ErrTimeout        = errors.New("toolexec: tool timed out")
	ErrOutputTooLarge = errors.New("toolexec: tool output over its bound")
	ErrKilled         = errors.New("toolexec: tool killed by a signal")
)

// Tool is a binary of the lock: its absolute path and its exact SHA-256. The
// binary must be read-only and owned by the user, in a directory no one else
// can write (obligation (hi)): the private copy of validate.LoadToolchain.
type Tool struct{ Name, Version, Path, SHA256 string }

// Spec is one run. Env holds NAME=value entries added to the built
// environment, under the allow-list of envRules (obligation (hf)); the forced
// variables cannot be overridden; a path it names (TF_CLI_CONFIG_FILE,
// TFLINT_PLUGIN_DIR) is under an entry of ReadOnly (ADR 0015 D11). The tool
// runs in the tree of Workspace, read-only; WriteData makes data/ writable
// (OpenTofu runs only); ReadOnly lists extra read-only directories of the
// tree of the tool (the private copy of the toolchain).
type Spec struct {
	Tool                 Tool
	Args                 []string
	Workspace            *Workspace
	Env                  []string
	WriteData            bool
	ReadOnly             []string
	Timeout              time.Duration
	MaxStdout, MaxStderr int64
}

// Workspace is the working directory of the runs on one tree, created by
// Rempart (obligation (hf), T159): tree/ holds only the files written through
// WriteFile and is the directory of every run; data/ is TF_DATA_DIR, outside
// the tree, so that a .terraform/ of the tree is never read; path/ is an
// empty directory, the only entry of PATH. Close removes it all.
type Workspace struct {
	mu     sync.Mutex
	base   string
	root   *os.Root
	closed bool
}

// NewWorkspace creates an empty private workspace.
func NewWorkspace() (*Workspace, error) {
	base, err := os.MkdirTemp("", "rempart-ws-")
	if err != nil {
		return nil, fmt.Errorf("toolexec: workspace: %w", err)
	}
	for _, d := range []string{"tree", "data", "path"} {
		if err := os.Mkdir(filepath.Join(base, d), 0o700); err != nil {
			_ = os.RemoveAll(base)
			return nil, fmt.Errorf("toolexec: workspace: %w", err)
		}
	}
	// path/ stays empty: read-only even for its owner (obligation (hq)).
	if err := os.Chmod(filepath.Join(base, "path"), 0o500); err != nil { //nolint:gosec // G302: an empty directory, searchable by its owner.
		_ = os.RemoveAll(base)
		return nil, fmt.Errorf("toolexec: workspace: %w", err)
	}
	root, err := os.OpenRoot(filepath.Join(base, "tree"))
	if err != nil {
		_ = os.RemoveAll(base)
		return nil, fmt.Errorf("toolexec: workspace: %w", err)
	}
	return &Workspace{base: base, root: root}, nil
}

// Dir is the tree of the workspace, the working directory of every run,
// read-only for every tool (ADR 0015 D5).
func (w *Workspace) Dir() string { return filepath.Join(w.base, "tree") }

// DataDir is data/ of the workspace: TF_DATA_DIR and the plan files, writable
// for a run with Spec.WriteData only.
func (w *Workspace) DataDir() string { return filepath.Join(w.base, "data") }

// pathDir is the empty directory that PATH names.
func (w *Workspace) pathDir() string { return filepath.Join(w.base, "path") }

// WriteFile writes data to the new file rel of the tree (slash-separated,
// relative, no . or .. element), its directories created: through os.Root,
// so that no path and no link leads out of the tree; a file is written once.
func (w *Workspace) WriteFile(rel string, data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return invalid("closed workspace")
	}
	if rel == "." || strings.ContainsRune(rel, 0) || !fs.ValidPath(rel) {
		return invalid("workspace path")
	}
	if dir := path.Dir(rel); dir != "." {
		if err := w.root.MkdirAll(dir, 0o700); err != nil {
			return invalid("workspace path")
		}
	}
	f, err := w.root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return invalid("workspace write")
	}
	_, werr := f.Write(data)
	if err := f.Close(); werr == nil {
		werr = err
	}
	if werr != nil {
		return fmt.Errorf("toolexec: workspace write: %w", werr)
	}
	return nil
}

// Close removes the workspace; it is then refused by Run and WriteFile.
func (w *Workspace) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	_ = w.root.Close()
	return os.RemoveAll(w.base)
}

func (w *Workspace) open() bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return !w.closed
}

// Result is a completed run: the exit code, the full outputs and the
// isolation it ran in.
type Result struct {
	ExitCode       int
	Stdout, Stderr []byte
	Isolation      Isolation
}

var (
	hashRe    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	forced    = map[string]bool{
		"PATH": true, "HOME": true, "TMPDIR": true, "TF_DATA_DIR": true,
		"HTTPS_PROXY": true, "HTTP_PROXY": true, "https_proxy": true, "http_proxy": true,
		"NO_PROXY": true, "no_proxy": true, "ALL_PROXY": true, "all_proxy": true,
	}
	one     = regexp.MustCompile(`^1$`)
	fakeKey = regexp.MustCompile(`^FAKE[A-Z0-9-]*$`)
	// envRules is the allow-list of Spec.Env (obligation (hf), T159): a name
	// outside it (TF_CLI_ARGS*, TF_REATTACH_PROVIDERS, TF_PLUGIN_CACHE_DIR,
	// TF_LOG*, LD_*, GODEBUG, PYTHONPATH, any credential) is refused, and so
	// is a value outside its form; the AWS keys are the FAKE keys of D8 only.
	envRules = []struct {
		name  *regexp.Regexp
		value func(string) bool
	}{
		{regexp.MustCompile(`^(TF_CLI_CONFIG_FILE|TFLINT_PLUGIN_DIR)$`), func(v string) bool { return filepath.IsAbs(v) && filepath.Clean(v) == v }},
		{regexp.MustCompile(`^(CHECKPOINT_DISABLE|TF_IN_AUTOMATION)$`), one.MatchString},
		{regexp.MustCompile(`^TF_VAR_[a-z0-9_]+$`), func(string) bool { return true }},
		{regexp.MustCompile(`^AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY)$`), fakeKey.MatchString},
	}
)

// envAllowed reports whether the entry k=v is in the allow-list.
func envAllowed(k, v string) bool {
	for _, r := range envRules {
		if r.name.MatchString(k) {
			return r.value(v)
		}
	}
	return false
}

func invalid(reason string) error { return fmt.Errorf("%w: %s", ErrSpec, reason) }

func check(s Spec) error {
	switch {
	case !filepath.IsAbs(s.Tool.Path) || filepath.Clean(s.Tool.Path) != s.Tool.Path:
		return invalid("tool path")
	case !hashRe.MatchString(s.Tool.SHA256):
		return invalid("tool sha256")
	case !s.Workspace.open():
		return invalid("workspace")
	case s.Timeout <= 0 || s.MaxStdout <= 0 || s.MaxStderr <= 0:
		return invalid("bounds")
	}
	for _, a := range s.Args {
		if strings.ContainsRune(a, 0) {
			return invalid("argument with a NUL byte")
		}
	}
	seen := map[string]bool{}
	if err := checkReadOnly(s); err != nil {
		return err
	}
	vars := map[string]string{}
	for _, e := range s.Env {
		k, v, ok := strings.Cut(e, "=")
		switch {
		case !ok || !envNameRe.MatchString(k) || strings.ContainsRune(e, 0):
			return invalid("env entry")
		case forced[k] || forced[strings.ToUpper(k)]:
			return invalid("env entry overrides a forced variable")
		case !envAllowed(k, v):
			return invalid("env entry outside the allow-list")
		case seen[k]:
			return invalid("env entry repeated")
		}
		seen[k] = true
		vars[k] = v
	}
	// ADR 0015 D11, obligation (hr): a path the environment names is under a
	// read-only entry; tofu runs with its CLI configuration, always.
	for _, k := range []string{"TF_CLI_CONFIG_FILE", "TFLINT_PLUGIN_DIR"} {
		if v, ok := vars[k]; ok && !under(v, s.ReadOnly) {
			return invalid("path of the environment outside the read-only entries")
		}
	}
	if s.Tool.Name == "tofu" && vars["TF_CLI_CONFIG_FILE"] == "" {
		return invalid("tofu without its CLI configuration")
	}
	if dir := filepath.Dir(s.Tool.Path); dir == "/" || isSystemPath(dir) || dir == s.Workspace.base || strings.HasPrefix(dir, s.Workspace.base+"/") {
		return invalid("tool directory")
	}
	return nil
}

// under reports whether p is strictly under one of the directories roots.
func under(p string, roots []string) bool {
	for _, r := range roots {
		if strings.HasPrefix(p, r+"/") {
			return true
		}
	}
	return false
}

// checkReadOnly applies ADR 0015 D11 to Spec.ReadOnly: each entry is an
// absolute clean directory of the effective user that no one else can write,
// neither /, a system directory of the tree, the temporary directory itself,
// an ancestor of the workspace, nor in the workspace; no entry is an ancestor
// of another.
func checkReadOnly(s Spec) error {
	tmp := filepath.Clean(os.TempDir())
	base := s.Workspace.base
	for i, p := range s.ReadOnly {
		switch {
		case !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" || p == tmp || isSystemPath(p):
			return invalid("read-only entry")
		case base == p || strings.HasPrefix(base, p+"/") || strings.HasPrefix(p, base+"/"):
			return invalid("read-only entry and the workspace overlap")
		}
		info, err := os.Lstat(p)
		if err != nil || !info.IsDir() || !ownedPrivate(info, 0o022) {
			return invalid("read-only entry not a private directory")
		}
		for j, q := range s.ReadOnly {
			if i != j && (p == q || strings.HasPrefix(q, p+"/")) {
				return invalid("read-only entries overlap")
			}
		}
	}
	return nil
}

// ownedPrivate reports whether info is owned by the effective user and none
// of the bits of mask is set in its permissions.
func ownedPrivate(info fs.FileInfo, mask fs.FileMode) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid() && info.Mode().Perm()&mask == 0
}

// bounded keeps at most limit bytes; past it, it records the overflow and
// calls stop once (the process group is killed).
type bounded struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	limit    int64
	overflow bool
	stop     func()
}

func (b *bounded) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.overflow {
		return len(p), nil
	}
	if int64(b.buf.Len())+int64(len(p)) > b.limit {
		b.overflow = true
		b.buf.Reset()
		if b.stop != nil {
			go b.stop()
		}
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *bounded) over() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.overflow
}

// Run runs the tool of s (ADR 0015): spec checked; binary checked and copied
// into a sealed memfd; without the full isolation, ErrIsolationUnavailable
// before any process; then the helper builds the closed tree and executes
// the tool, which becomes PID 1 of its namespaces: arguments as they are (no
// shell), environment built from s.Env and the forced variables only (PATH
// the empty directory of the workspace, TF_DATA_DIR its data directory, fresh
// HOME and TMPDIR removed afterwards, proxies to UnreachableProxy, NO_PROXY
// empty), the tool and all its descendants killed past s.Timeout. A non-zero
// exit code is a Result, not an error; a timeout, an output over its bound, a
// failed isolation or a tool killed by a signal is an error with an empty
// Result.
func Run(ctx context.Context, s Spec) (Result, error) {
	if err := check(s); err != nil {
		return Result{}, err
	}
	bin, err := sealedCopy(s.Tool)
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = bin.Close() }()
	iso := probeFunc(ctx)
	if iso.Level != LevelFull {
		return Result{}, ErrIsolationUnavailable
	}
	scratch, err := os.MkdirTemp("", "rempart-tool-")
	if err != nil {
		return Result{}, fmt.Errorf("toolexec: ephemeral directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	home, tmp, root := filepath.Join(scratch, "home"), filepath.Join(scratch, "tmp"), filepath.Join(scratch, "root")
	for _, d := range []string{home, tmp, root} {
		if err := os.Mkdir(d, 0o700); err != nil {
			return Result{}, fmt.Errorf("toolexec: ephemeral directory: %w", err)
		}
	}
	env := append([]string{
		"PATH=" + s.Workspace.pathDir(), "TF_DATA_DIR=" + s.Workspace.DataDir(),
		"HOME=" + home, "TMPDIR=" + tmp,
		"HTTPS_PROXY=" + UnreachableProxy, "HTTP_PROXY=" + UnreachableProxy,
		"https_proxy=" + UnreachableProxy, "http_proxy=" + UnreachableProxy,
		"ALL_PROXY=" + UnreachableProxy, "all_proxy=" + UnreachableProxy,
		"NO_PROXY=", "no_proxy=",
	}, s.Env...)
	cfg := helperConfig{
		Root: root, Tool: s.Tool.Path, Args: append([]string{s.Tool.Path}, s.Args...), Env: env,
		Tree: s.Workspace.Dir(), PathDir: s.Workspace.pathDir(), Home: home, Tmp: tmp, ReadOnly: s.ReadOnly,
	}
	if s.WriteData {
		cfg.Data = s.Workspace.DataDir()
	}

	runCtx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	var state *os.ProcessState
	stopped := make(chan struct{})
	var stopOnce sync.Once
	stop := func() { stopOnce.Do(func() { close(stopped); cancel() }) }
	stdout := &bounded{limit: s.MaxStdout, stop: stop}
	stderr := &bounded{limit: s.MaxStderr, stop: stop}
	state, err = launch(runCtx, cfg, bin, stdout, stderr)
	switch {
	case errors.Is(err, ErrIsolationSetup):
		return Result{}, err
	case stdout.over() || stderr.over():
		return Result{}, ErrOutputTooLarge
	case errors.Is(runCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil:
		return Result{}, ErrTimeout
	case ctx.Err() != nil:
		return Result{}, fmt.Errorf("toolexec: %w", ctx.Err())
	case err != nil:
		return Result{}, fmt.Errorf("toolexec: start %s: %w", s.Tool.Name, err)
	case state == nil:
		return Result{}, ErrIsolationSetup
	case !state.Exited():
		return Result{}, ErrKilled
	}
	return Result{ExitCode: state.ExitCode(), Stdout: stdout.buf.Bytes(), Stderr: stderr.buf.Bytes(), Isolation: iso}, nil
}
