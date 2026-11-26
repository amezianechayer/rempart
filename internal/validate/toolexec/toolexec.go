// Package toolexec is the only runner of external commands of the IaC chain
// (ADR 0014 D6, rule exec-confined, threat T8): no shell, a built
// environment, a checksum checked right before the run, a timeout that kills
// the whole process group, bounded outputs.
package toolexec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
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
)

// Tool is a binary of the lock: its absolute path and its exact SHA-256.
type Tool struct{ Name, Version, Path, SHA256 string }

// Spec is one run. Env holds NAME=value entries added to the built
// environment; the forced variables cannot be overridden.
type Spec struct {
	Tool                 Tool
	Args                 []string
	Dir                  string
	Env                  []string
	Timeout              time.Duration
	MaxStdout, MaxStderr int64
}

// Result is a completed run: the exit code and the full outputs.
type Result struct {
	ExitCode       int
	Stdout, Stderr []byte
}

var (
	hashRe    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	forced    = map[string]bool{
		"PATH": true, "HOME": true, "TMPDIR": true,
		"HTTPS_PROXY": true, "HTTP_PROXY": true, "https_proxy": true, "http_proxy": true,
		"NO_PROXY": true, "no_proxy": true, "ALL_PROXY": true, "all_proxy": true,
	}
)

func invalid(reason string) error { return fmt.Errorf("%w: %s", ErrSpec, reason) }

func check(s Spec) error {
	switch {
	case !filepath.IsAbs(s.Tool.Path) || filepath.Clean(s.Tool.Path) != s.Tool.Path:
		return invalid("tool path")
	case !hashRe.MatchString(s.Tool.SHA256):
		return invalid("tool sha256")
	case !filepath.IsAbs(s.Dir):
		return invalid("dir")
	case s.Timeout <= 0 || s.MaxStdout <= 0 || s.MaxStderr <= 0:
		return invalid("bounds")
	}
	for _, a := range s.Args {
		if strings.ContainsRune(a, 0) {
			return invalid("argument with a NUL byte")
		}
	}
	seen := map[string]bool{}
	for _, e := range s.Env {
		k, _, ok := strings.Cut(e, "=")
		switch {
		case !ok || !envNameRe.MatchString(k) || strings.ContainsRune(e, 0):
			return invalid("env entry")
		case forced[k] || forced[strings.ToUpper(k)]:
			return invalid("env entry overrides a forced variable")
		case seen[k]:
			return invalid("env entry repeated")
		}
		seen[k] = true
	}
	if info, err := os.Stat(s.Dir); err != nil || !info.IsDir() {
		return invalid("dir")
	}
	return nil
}

// verify hashes the regular file at path, never through a symbolic link.
func verify(path, want string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return invalid("tool is not a regular file")
	}
	f, err := os.Open(path) //nolint:gosec // G304: the path of a locked tool, checked by its hash below.
	if err != nil {
		return invalid("tool unreadable")
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return invalid("tool unreadable")
	}
	if hex.EncodeToString(h.Sum(nil)) != want {
		return ErrChecksum
	}
	return nil
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

// Run runs the tool of s: spec checked, SHA-256 of the binary checked right
// before the run, arguments passed as they are (no shell), environment built
// from s.Env and the forced variables only (PATH, fresh HOME and TMPDIR
// removed afterwards, proxies to UnreachableProxy, NO_PROXY empty), the whole
// process group killed past s.Timeout. A non-zero exit code is a Result, not
// an error; a timeout or an output over its bound is an error with an empty
// Result.
func Run(ctx context.Context, s Spec) (Result, error) {
	if err := check(s); err != nil {
		return Result{}, err
	}
	if err := verify(s.Tool.Path, s.Tool.SHA256); err != nil {
		return Result{}, err
	}
	scratch, err := os.MkdirTemp("", "rempart-tool-")
	if err != nil {
		return Result{}, fmt.Errorf("toolexec: ephemeral directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	home, tmp := filepath.Join(scratch, "home"), filepath.Join(scratch, "tmp")
	for _, d := range []string{home, tmp} {
		if err := os.Mkdir(d, 0o700); err != nil {
			return Result{}, fmt.Errorf("toolexec: ephemeral directory: %w", err)
		}
	}
	env := append([]string{
		"PATH=/usr/bin:/bin", "HOME=" + home, "TMPDIR=" + tmp,
		"HTTPS_PROXY=" + UnreachableProxy, "HTTP_PROXY=" + UnreachableProxy,
		"https_proxy=" + UnreachableProxy, "http_proxy=" + UnreachableProxy,
		"ALL_PROXY=" + UnreachableProxy, "all_proxy=" + UnreachableProxy,
		"NO_PROXY=", "no_proxy=",
	}, s.Env...)

	runCtx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, s.Tool.Path, s.Args...) //nolint:gosec // G204: a locked binary checked by its hash, arguments as an array, no shell (D6).
	cmd.Dir = s.Dir
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	killGroup := func() {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
	}
	cmd.Cancel = func() error { killGroup(); return nil }
	cmd.WaitDelay = 2 * time.Second
	stdout := &bounded{limit: s.MaxStdout, stop: killGroup}
	stderr := &bounded{limit: s.MaxStderr, stop: killGroup}
	cmd.Stdout, cmd.Stderr = stdout, stderr

	err = cmd.Run()
	// The group may outlive the leader (a child in the background): kill it
	// whatever the outcome.
	killGroup()
	switch {
	case stdout.over() || stderr.over():
		return Result{}, ErrOutputTooLarge
	case errors.Is(runCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil:
		return Result{}, ErrTimeout
	case ctx.Err() != nil:
		return Result{}, fmt.Errorf("toolexec: %w", ctx.Err())
	}
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		return Result{}, fmt.Errorf("toolexec: start %s: %w", s.Tool.Name, err)
	}
	return Result{ExitCode: cmd.ProcessState.ExitCode(), Stdout: stdout.buf.Bytes(), Stderr: stderr.buf.Bytes()}, nil
}
