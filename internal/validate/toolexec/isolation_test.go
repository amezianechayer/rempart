package toolexec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// ADR 0015 (obligation (hg), T157): every run of a tool is isolated. The fake
// tool is this test binary itself, copied read-only and hashed (D12): its
// TestMain recognizes the first argument fakeToolArg and runs one action.
// Each attack is first run directly, outside isolation, and must succeed (the
// witness); then through Run, where it must fail.

const fakeToolArg = "fake-tool"

// The test hooks of the helper (no Landlock, a refused subset=pid) are honored
// in the test binary of this package only.
func init() { testHooksAllowed = true }

// withTestHooks attaches test hooks to the runs made with ctx.
func withTestHooks(ctx context.Context, h testHooks) context.Context {
	return context.WithValue(ctx, testHooksKey{}, h)
}

// layers are the two runs of an isolation test: with the Landlock layer, and
// without it (test hook), so that the namespaces and mounts of D5 are proven
// on their own; D7 is a layer, never a substitute (review of M3-T02b, medium
// finding 4).
func layers() []struct {
	name string
	ctx  context.Context
} {
	return []struct {
		name string
		ctx  context.Context
	}{
		{"landlock", context.Background()},
		{"mounts_only", withTestHooks(context.Background(), testHooks{NoLandlock: true})},
	}
}

// testKeyctl are keyctl(2) and add_key(2) by architecture, for the keyring
// witness.
var testKeyctl = map[string]struct{ keyctl, addKey uintptr }{"amd64": {250, 248}, "arm64": {219, 217}}

const (
	tkJoinSession = 1           // KEYCTL_JOIN_SESSION_KEYRING
	tkSetPerm     = 5           // KEYCTL_SETPERM
	tkLink        = 8           // KEYCTL_LINK
	tkSearch      = 10          // KEYCTL_SEARCH
	tkRead        = 11          // KEYCTL_READ
	tkSpecSession = ^uintptr(2) // KEY_SPEC_SESSION_KEYRING, -3
)

// readSessionKey searches the session keyring for the user key desc and
// prints its payload.
func readSessionKey(keyctl uintptr, desc string) error {
	typ, d := []byte("user\x00"), []byte(desc+"\x00")
	//nolint:gosec // G103: keyctl takes pointers to NUL-terminated strings.
	id, _, e := syscall.Syscall6(keyctl, tkSearch, tkSpecSession, uintptr(unsafe.Pointer(&typ[0])), uintptr(unsafe.Pointer(&d[0])), 0, 0)
	if e != 0 {
		return fmt.Errorf("search: %w", e)
	}
	payload := []byte(strings.Repeat("\x00", 128))
	//nolint:gosec // G103: keyctl takes a pointer to its buffer.
	n, _, e := syscall.Syscall6(keyctl, tkRead, id, uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)), 0, 0)
	if e != 0 {
		return fmt.Errorf("read: %w", e)
	}
	fmt.Printf("payload %q\n", payload[:min(int(n), len(payload))])
	return nil
}

func TestMain(m *testing.M) {
	MaybeHelper()
	if len(os.Args) > 2 && os.Args[1] == fakeToolArg {
		os.Exit(goToolAction(os.Args[2], os.Args[3:]))
	}
	os.Exit(m.Run())
}

// goToolAction is the fake tool: exit 0 when the action succeeds, 1 when it
// fails (the error on stdout), 2 on a usage error.
func goToolAction(action string, args []string) int {
	fail := func(err error) int {
		if err != nil {
			fmt.Println(err)
			return 1
		}
		fmt.Println("ok")
		return 0
	}
	arg := func(i int) string {
		if i < len(args) {
			return args[i]
		}
		return ""
	}
	switch action {
	case "noop":
		return 0
	case "read":
		_, err := os.ReadFile(arg(0))
		return fail(err)
	case "write":
		return fail(os.WriteFile(arg(0), []byte("x"), 0o600))
	case "ls":
		entries, err := os.ReadDir(arg(0))
		for _, e := range entries {
			fmt.Println(e.Name())
		}
		return fail(err)
	case "tcp":
		c, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", arg(0))
		if err == nil {
			_ = c.Close()
		}
		return fail(err)
	case "udp":
		c, err := (&net.Dialer{}).DialContext(context.Background(), "udp", arg(0))
		if err == nil {
			_, err = c.Write([]byte(arg(1)))
			_ = c.Close()
		}
		return fail(err)
	case "unix":
		c, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "unix", arg(0))
		if err == nil {
			_ = c.Close()
		}
		return fail(err)
	case "kill0":
		pid, _ := strconv.Atoi(arg(0))
		return fail(syscall.Kill(pid, 0))
	case "procs":
		entries, err := os.ReadDir("/proc")
		n := 0
		for _, e := range entries {
			if _, convErr := strconv.Atoi(e.Name()); convErr == nil {
				n++
			}
		}
		fmt.Println(n)
		if err != nil {
			return 1
		}
		return 0
	case "tty":
		b, err := os.ReadFile("/proc/self/stat")
		if err != nil {
			return fail(err)
		}
		fields := strings.Fields(string(b[bytes.LastIndexByte(b, ')')+1:]))
		fmt.Println("tty_nr=" + fields[4])
		if fields[4] != "0" {
			return 0
		}
		f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err == nil {
			_ = f.Close()
			return 0
		}
		return 1
	case "userns":
		self, _ := os.Executable()
		cmd := exec.CommandContext(context.Background(), self, fakeToolArg, "noop") //nolint:gosec // G204: the fake tool itself.
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER}
		return fail(cmd.Run())
	case "escapee":
		// A descendant in a new session, outliving the tool by 1.5 s.
		self, _ := os.Executable()
		cmd := exec.CommandContext(context.Background(), self, fakeToolArg, "linger", arg(0)) //nolint:gosec // G204: the fake tool itself.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		return fail(cmd.Start())
	case "linger":
		time.Sleep(1500 * time.Millisecond)
		return fail(os.WriteFile(arg(0), []byte("survived"), 0o600))
	case "sleep":
		time.Sleep(30 * time.Second)
		return 0
	case "stat":
		_, err := os.Lstat(arg(0))
		return fail(err)
	case "chmodsame":
		// A chmod to the current mode changes nothing; it is refused on a
		// read-only mount (EROFS) and for a non-owner (EPERM).
		var st syscall.Stat_t
		if err := syscall.Stat(arg(0), &st); err != nil {
			return fail(err)
		}
		return fail(syscall.Chmod(arg(0), st.Mode&0o7777))
	case "fchmod0same":
		var st syscall.Stat_t
		if err := syscall.Fstat(0, &st); err != nil {
			return fail(err)
		}
		return fail(syscall.Fchmod(0, st.Mode&0o7777))
	case "creds":
		b, err := os.ReadFile("/proc/self/status")
		if err != nil {
			return fail(err)
		}
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "Cap") || strings.HasPrefix(l, "NoNewPrivs:") || strings.HasPrefix(l, "Seccomp:") {
				fmt.Println(l)
			}
		}
		for _, f := range []string{"uid_map", "gid_map", "setgroups"} {
			b, err := os.ReadFile("/proc/self/" + f) //nolint:gosec // G304: a fixed file of /proc/self.
			if err != nil {
				return fail(err)
			}
			fmt.Printf("%s: %s\n", f, strings.Join(strings.Fields(string(b)), " "))
		}
		return 0
	case "fds":
		// Raw system calls only, so that no descriptor of the Go runtime is in
		// the list: one line per descriptor above 2.
		dir, err := syscall.Open("/proc/self/fd", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
		if err != nil {
			return fail(err)
		}
		buf := make([]byte, 8192)
		var names []string
		for {
			n, err := syscall.ReadDirent(dir, buf)
			if err != nil {
				return fail(err)
			}
			if n == 0 {
				break
			}
			_, _, names = syscall.ParseDirent(buf[:n], -1, names)
		}
		for _, name := range names {
			if fd, _ := strconv.Atoi(name); fd > 2 && fd != dir {
				target, _ := os.Readlink("/proc/self/fd/" + name)
				fmt.Printf("fd %d %s\n", fd, target)
			}
		}
		return 0
	case "keyring":
		nr, ok := testKeyctl[runtime.GOARCH]
		if !ok {
			return 2
		}
		return fail(readSessionKey(nr.keyctl, arg(0)))
	case "keylink":
		// The attack by serial number: a fresh session keyring (no possession
		// inherited), then a link of a keyring of the launcher by its number,
		// that its "user" rights grant to any process of the same kuid.
		nr, ok := testKeyctl[runtime.GOARCH]
		serial, err := strconv.ParseUint(arg(0), 10, 31)
		if !ok || err != nil {
			return 2
		}
		if _, _, e := syscall.RawSyscall(nr.keyctl, tkJoinSession, 0, 0); e != 0 {
			return fail(fmt.Errorf("join: %w", e))
		}
		if _, _, e := syscall.RawSyscall(nr.keyctl, tkLink, uintptr(serial), tkSpecSession); e != 0 {
			return fail(fmt.Errorf("link: %w", e))
		}
		return fail(readSessionKey(nr.keyctl, arg(1)))
	case "addkey":
		nr, ok := testKeyctl[runtime.GOARCH]
		if !ok {
			return 2
		}
		typ, d, v := []byte("user\x00"), []byte("rempart-planted\x00"), []byte("x")
		//nolint:gosec // G103: add_key takes pointers to its type, description and payload.
		_, _, e := syscall.Syscall6(nr.addKey, uintptr(unsafe.Pointer(&typ[0])), uintptr(unsafe.Pointer(&d[0])), uintptr(unsafe.Pointer(&v[0])), uintptr(len(v)), tkSpecSession, 0)
		if e != 0 {
			return fail(e)
		}
		return fail(nil)
	case "unixlisten":
		l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", filepath.Join(os.TempDir(), "plugin.sock"))
		if err == nil {
			_ = l.Close()
		}
		return fail(err)
	}
	return 2
}

var (
	selfOnce sync.Once
	selfSrc  []byte
	selfErr  error
)

// selfTool copies the test binary, read-only, in a fresh private directory and
// returns the Tool that names it.
func selfTool(t *testing.T) Tool {
	t.Helper()
	selfOnce.Do(func() {
		var exe string
		if exe, selfErr = os.Executable(); selfErr == nil {
			selfSrc, selfErr = os.ReadFile(exe) //nolint:gosec // G304: the test binary itself.
		}
	})
	if selfErr != nil {
		t.Fatal(selfErr)
	}
	path := filepath.Join(t.TempDir(), "fake-go-tool")
	if err := os.WriteFile(path, selfSrc, 0o500); err != nil { //nolint:gosec // G306: the fake tool is executable by its owner, read-only.
		t.Fatal(err)
	}
	sum := sha256.Sum256(selfSrc)
	return Tool{Name: "fake", Version: "1.0.0", Path: path, SHA256: hex.EncodeToString(sum[:])}
}

// requireIsolation skips the test when the kernel does not offer the full
// isolation, and fails it instead when REMPART_REQUIRE_SANDBOX=1 (D12): a
// skipped isolation test is never a silent success.
func requireIsolation(t *testing.T) {
	t.Helper()
	iso := Probe(context.Background())
	if iso.Level == LevelFull {
		return
	}
	if os.Getenv("REMPART_REQUIRE_SANDBOX") == "1" {
		t.Fatalf("isolation unavailable (%s) and REMPART_REQUIRE_SANDBOX=1", iso.Reason)
	}
	t.Skipf("isolation unavailable: %s", iso.Reason)
}

// isoSpec is a run of the fake tool action in ws, data/ writable.
func isoSpec(t *testing.T, ws *Workspace, tool Tool, action string, args ...string) Spec {
	t.Helper()
	return Spec{
		Tool: tool, Args: append([]string{fakeToolArg, action}, args...), Workspace: ws, WriteData: true,
		Timeout: 30 * time.Second, MaxStdout: 1 << 20, MaxStderr: 1 << 20,
	}
}

// isolated runs the action through Run and returns its exit code.
func isolated(t *testing.T, s Spec) int {
	t.Helper()
	return isolatedIn(t, context.Background(), s)
}

// isolatedIn is isolated with the context ctx (test hooks).
func isolatedIn(t *testing.T, ctx context.Context, s Spec) int {
	t.Helper()
	res, err := Run(ctx, s)
	if err != nil {
		t.Fatalf("Run %v: %v", s.Args, err)
	}
	if res.Isolation.Level != LevelFull {
		t.Fatalf("Run %v: isolation %+v, want full", s.Args, res.Isolation)
	}
	return res.ExitCode
}

// direct runs the action outside isolation (the witness) and returns its exit
// code.
func direct(t *testing.T, tool Tool, action string, args ...string) int {
	t.Helper()
	code, _ := directOutput(t, context.Background(), tool, action, args...)
	return code
}

// directOutput is direct with the context ctx and the output of the action.
func directOutput(t *testing.T, ctx context.Context, tool Tool, action string, args ...string) (int, []byte) {
	t.Helper()
	cmd := exec.CommandContext(ctx, tool.Path, append([]string{fakeToolArg, action}, args...)...) //nolint:gosec // G204: the fake tool.
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, out
	case errors.As(err, &ee):
		t.Logf("direct %s: %s", action, bytes.TrimSpace(out))
		return ee.ExitCode(), out
	}
	t.Fatalf("direct %s: %v", action, err)
	return -1, nil
}

// attack asserts the witness (direct run succeeds) then the isolated failure.
func attack(t *testing.T, tool Tool, ws *Workspace, action string, args ...string) {
	t.Helper()
	attackIn(t, context.Background(), tool, ws, action, args...)
}

// attackIn is attack with the context ctx (test hooks).
func attackIn(t *testing.T, ctx context.Context, tool Tool, ws *Workspace, action string, args ...string) {
	t.Helper()
	if code, _ := directOutput(t, ctx, tool, action, args...); code != 0 {
		t.Skipf("witness: %s %v fails outside isolation (code %d): the environment already blocks it", action, args, code)
	}
	if code := isolatedIn(t, ctx, isoSpec(t, ws, tool, action, args...)); code != 1 {
		t.Errorf("%s %v under isolation: exit %d, want 1 (refused)", action, args, code)
	}
}

// TestIsolationProbe proves D2 and D3: the probe runs the helper for real and
// reports the full level, cached for the process; every Result carries it.
func TestIsolationProbe(t *testing.T) {
	requireIsolation(t)
	a, b := Probe(context.Background()), Probe(context.Background())
	if a != b || a.Level != LevelFull || a.Reason != "" {
		t.Fatalf("Probe = %+v then %+v, want the same full level", a, b)
	}
	res, err := Run(context.Background(), isoSpec(t, workspace(t), selfTool(t), "noop"))
	if err != nil || res.ExitCode != 0 || res.Isolation != a {
		t.Fatalf("Run = %+v, %v; want exit 0 and Isolation %+v", res, err, a)
	}
}

// TestIsolationFailsClosed proves D1 (T162): without the full isolation, Run
// refuses before any process, with ErrIsolationUnavailable; it never skips.
func TestIsolationFailsClosed(t *testing.T) {
	saved := probeFunc
	t.Cleanup(func() { probeFunc = saved })
	probeFunc = func(context.Context) Isolation { return Isolation{Reason: "test: no namespaces"} }
	ws := workspace(t)
	marker := filepath.Join(ws.DataDir(), "ran")
	_, err := Run(context.Background(), isoSpec(t, ws, selfTool(t), "write", marker))
	if !errors.Is(err, ErrIsolationUnavailable) {
		t.Fatalf("Run without isolation = %v, want ErrIsolationUnavailable", err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the tool ran without isolation")
	}
}

// prGetDumpable is PR_GET_DUMPABLE.
const prGetDumpable = 3

// TestIsolationLauncherNotDumpable proves D2 (P1, F10): after a run, the
// launcher is not dumpable (its environment and memory are closed to a
// process of the same uid without CAP_SYS_PTRACE).
func TestIsolationLauncherNotDumpable(t *testing.T) {
	requireIsolation(t)
	if code := isolated(t, isoSpec(t, workspace(t), selfTool(t), "noop")); code != 0 {
		t.Fatalf("noop: exit %d", code)
	}
	v, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prGetDumpable, 0, 0)
	if errno != 0 || v != 0 {
		t.Fatalf("PR_GET_DUMPABLE = %d (%v), want 0 after a run", v, errno)
	}
}

// TestIsolationKillsEscapedDescendants proves D8 (P3, F3): a descendant that
// leaves the session of the tool (setsid) dies with the tool, the PID
// namespace taking it down; it never outlives Run.
func TestIsolationKillsEscapedDescendants(t *testing.T) {
	requireIsolation(t)
	tool := selfTool(t)
	witness := filepath.Join(t.TempDir(), "survived")
	if code := direct(t, tool, "escapee", witness); code != 0 {
		t.Fatalf("witness escapee: exit %d", code)
	}
	ws := workspace(t)
	marker := filepath.Join(ws.DataDir(), "survived")
	if code := isolated(t, isoSpec(t, ws, tool, "escapee", marker)); code != 0 {
		t.Fatalf("escapee under isolation: exit %d", code)
	}
	time.Sleep(2500 * time.Millisecond)
	if _, err := os.Stat(witness); err != nil {
		t.Skipf("witness: the escaped descendant did not survive outside isolation: %v", err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a descendant that left the session outlived the isolated tool")
	}
}

// TestIsolationNoNetwork proves D3 and D5 (P4, P5): the network namespace of
// the tool is empty: neither the loopback of the host (TCP, UDP) nor an
// abstract Unix socket of the host is reachable.
func TestIsolationNoNetwork(t *testing.T) {
	requireIsolation(t)
	tool, ws := selfTool(t), workspace(t)
	for _, m := range layers() {
		t.Run(m.name, func(t *testing.T) { noNetwork(t, m.ctx, tool, ws) })
	}
}

func noNetwork(t *testing.T, ctx context.Context, tool Tool, ws *Workspace) {
	t.Run("tcp", func(t *testing.T) {
		l, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Close() }()
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
		attackIn(t, ctx, tool, ws, "tcp", l.Addr().String())
	})
	t.Run("udp", func(t *testing.T) {
		pc, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = pc.Close() }()
		attackIn(t, ctx, tool, ws, "udp", pc.LocalAddr().String(), "token")
	})
	t.Run("abstract_unix", func(t *testing.T) {
		name := fmt.Sprintf("@rempart-test-%d", os.Getpid())
		l, err := (&net.ListenConfig{}).Listen(ctx, "unix", name)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Close() }()
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
		attackIn(t, ctx, tool, ws, "unix", name)
	})
}

// TestIsolationFilesystemClosed proves D5 and D6 (P2, P8, P9, P11): the root
// of the tool holds the closed list only; a file of the host outside it, a
// named Unix socket of the host (the Docker socket, the D-Bus bus) are
// absent; the tree and the root are read-only; the tool cannot create a
// nested user namespace.
func TestIsolationFilesystemClosed(t *testing.T) {
	requireIsolation(t)
	tool, ws := selfTool(t), workspace(t)
	for _, m := range layers() {
		t.Run(m.name, func(t *testing.T) { filesystemClosed(t, m.ctx, tool, ws) })
	}
}

func filesystemClosed(t *testing.T, ctx context.Context, tool Tool, ws *Workspace) {
	t.Run("root_closed_list", func(t *testing.T) {
		res, err := Run(ctx, isoSpec(t, ws, tool, "ls", "/"))
		if err != nil || res.ExitCode != 0 {
			t.Fatalf("ls /: %+v, %v", res, err)
		}
		allowed := map[string]bool{"usr": true, "bin": true, "sbin": true, "lib": true, "lib64": true, "etc": true, "dev": true, "proc": true}
		top := map[string]bool{}
		for _, p := range []string{ws.Dir(), ws.DataDir(), filepath.Dir(tool.Path), os.TempDir()} {
			if parts := strings.Split(strings.TrimPrefix(p, "/"), "/"); len(parts) > 0 {
				top[parts[0]] = true
			}
		}
		for _, name := range strings.Fields(string(res.Stdout)) {
			if name != "ok" && !allowed[name] && !top[name] {
				t.Errorf("/%s visible to the tool: outside the closed list of D5", name)
			}
		}
	})
	t.Run("host_file", func(t *testing.T) {
		secret := filepath.Join(t.TempDir(), "secret")
		if err := os.WriteFile(secret, []byte("s"), 0o600); err != nil {
			t.Fatal(err)
		}
		attackIn(t, ctx, tool, ws, "read", secret)
	})
	t.Run("unix_pathname", func(t *testing.T) {
		sock := filepath.Join(t.TempDir(), "docker.sock")
		l, err := (&net.ListenConfig{}).Listen(ctx, "unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Close() }()
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
		attackIn(t, ctx, tool, ws, "unix", sock)
	})
	t.Run("tree_read_only", func(t *testing.T) {
		attackIn(t, ctx, tool, ws, "write", filepath.Join(ws.Dir(), "dropped.trivyignore"))
	})
	t.Run("root_read_only", func(t *testing.T) {
		if code := isolatedIn(t, ctx, isoSpec(t, ws, tool, "write", "/dropped")); code != 1 {
			t.Errorf("write / under isolation: exit %d, want 1", code)
		}
	})
	t.Run("nested_user_namespace", func(t *testing.T) {
		attackIn(t, ctx, tool, ws, "userns")
	})
	t.Run("data_writable_when_asked", func(t *testing.T) {
		if code := isolatedIn(t, ctx, isoSpec(t, ws, tool, "write", filepath.Join(ws.DataDir(), "plan.bin"))); code != 0 {
			t.Fatalf("write data/ with WriteData: exit %d, want 0", code)
		}
		s := isoSpec(t, ws, tool, "write", filepath.Join(ws.DataDir(), "other"))
		s.WriteData = false
		if code := isolatedIn(t, ctx, s); code != 1 {
			t.Errorf("write data/ without WriteData: exit %d, want 1", code)
		}
	})
}

// TestIsolationPrivateCopiesReadOnly proves D5 and D13 (obligation (hn), P6):
// an entry of Spec.ReadOnly (the private copy of the toolchain) is visible to
// the tool and read-only for it.
func TestIsolationPrivateCopiesReadOnly(t *testing.T) {
	requireIsolation(t)
	tool, ws := selfTool(t), workspace(t)
	private := t.TempDir()
	plugin := filepath.Join(private, "tflint-ruleset-aws")
	if err := os.WriteFile(plugin, []byte("ruleset"), 0o500); err != nil { //nolint:gosec // G306: a fake ruleset, executable by its owner.
		t.Fatal(err)
	}
	read := isoSpec(t, ws, tool, "read", plugin)
	read.ReadOnly = []string{private}
	if code := isolated(t, read); code != 0 {
		t.Fatalf("read a ReadOnly entry: exit %d, want 0", code)
	}
	if code := direct(t, tool, "write", filepath.Join(private, "planted")); code != 0 {
		t.Fatalf("witness: write in the private copy outside isolation: exit %d", code)
	}
	for _, m := range layers() {
		t.Run(m.name, func(t *testing.T) {
			for _, action := range [][]string{{"write", filepath.Join(private, "planted-2")}, {"chmodsame", plugin}} {
				s := isoSpec(t, ws, tool, action[0], action[1:]...)
				s.ReadOnly = []string{private}
				if code := isolatedIn(t, m.ctx, s); code != 1 {
					t.Errorf("%v in a ReadOnly entry under isolation: exit %d, want 1", action, code)
				}
			}
		})
	}
}

// TestIsolationHidesProcesses proves D3 and D5 (P1, P7, P12): the tool sees
// only the processes of its own PID namespace and cannot signal a process of
// the host of the same uid.
func TestIsolationHidesProcesses(t *testing.T) {
	requireIsolation(t)
	tool, ws := selfTool(t), workspace(t)
	victim := exec.CommandContext(context.Background(), tool.Path, fakeToolArg, "sleep") //nolint:gosec // G204: the fake tool.
	if err := victim.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = victim.Process.Kill(); _, _ = victim.Process.Wait() })
	for _, m := range layers() {
		t.Run(m.name, func(t *testing.T) { attackIn(t, m.ctx, tool, ws, "kill0", strconv.Itoa(victim.Process.Pid)) })
	}
	// P7: the environment of another process of the same uid (the victim is
	// dumpable; the launcher is not, see TestIsolationLauncherNotDumpable).
	attack(t, tool, ws, "read", fmt.Sprintf("/proc/%d/environ", victim.Process.Pid))
	res, err := Run(context.Background(), isoSpec(t, ws, tool, "procs"))
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("procs: %+v, %v", res, err)
	}
	if n, _ := strconv.Atoi(strings.TrimSpace(string(res.Stdout))); n != 1 {
		t.Errorf("the tool sees %d processes in /proc, want 1 (itself, PID 1 of its namespace)", n)
	}
}

// TestIsolationParallelRunsSeparated proves D5 (P11, T3): two runs in
// parallel, on the workspaces of two tenants, do not see each other's tree.
func TestIsolationParallelRunsSeparated(t *testing.T) {
	requireIsolation(t)
	tool := selfTool(t)
	wsA, wsB := workspace(t), workspace(t)
	if err := wsB.WriteFile("main.tf", []byte("tenant b")); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(wsB.Dir(), "main.tf")
	if code := direct(t, tool, "read", other); code != 0 {
		t.Fatalf("witness: read the tree of tenant B outside isolation: exit %d", code)
	}
	var wg sync.WaitGroup
	codes := make([]int, 2)
	errs := make([]error, 2)
	for i, s := range []Spec{isoSpec(t, wsA, tool, "read", other), isoSpec(t, wsB, tool, "sleep")} {
		if i == 1 {
			s.Timeout = 2 * time.Second
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := Run(context.Background(), s)
			codes[i], errs[i] = res.ExitCode, err
		}()
	}
	wg.Wait()
	if errs[0] != nil || codes[0] != 1 {
		t.Errorf("tenant A reads the tree of tenant B: exit %d, %v; want 1", codes[0], errs[0])
	}
	if !errors.Is(errs[1], ErrTimeout) {
		t.Errorf("tenant B run: %v, want ErrTimeout (it was sleeping)", errs[1])
	}
}

// openPTY opens a pseudo-terminal pair through /dev/ptmx and TIOCGPTPEER.
func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	var unlock int32
	//nolint:gosec // G103: TIOCSPTLCK takes a pointer to an int, the ioctl of a test pseudo-terminal.
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), 0x40045431 /* TIOCSPTLCK */, uintptr(unsafe.Pointer(&unlock))); e != 0 {
		t.Skipf("no pseudo-terminal: %v", e)
	}
	fd, _, e := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), 0x5441 /* TIOCGPTPEER */, uintptr(syscall.O_RDWR|syscall.O_NOCTTY))
	if e != 0 {
		t.Skipf("no pseudo-terminal: %v", e)
	}
	return m, os.NewFile(fd, "pty")
}

// TestIsolationNoTerminal proves D2 (P13): the tool has no controlling
// terminal and cannot open /dev/tty. Witness: the same action, run with a
// controlling terminal outside isolation, sees it.
func TestIsolationNoTerminal(t *testing.T) {
	requireIsolation(t)
	tool := selfTool(t)
	master, slave := openPTY(t)
	defer func() { _ = master.Close(); _ = slave.Close() }()
	go func() { _, _ = io.Copy(io.Discard, master) }()
	cmd := exec.CommandContext(context.Background(), tool.Path, fakeToolArg, "tty") //nolint:gosec // G204: the fake tool.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Run(); err != nil {
		t.Skipf("witness: no controlling terminal outside isolation: %v", err)
	}
	if code := isolated(t, isoSpec(t, workspace(t), tool, "tty")); code != 1 {
		t.Errorf("tty under isolation: exit %d, want 1 (no controlling terminal, no /dev/tty)", code)
	}
}

// TestIsolationLandlockLayer proves D7: on a kernel with Landlock (ABI 4 or
// more), the helper adds a Landlock domain before the exec; a TCP connect is
// then refused by Landlock itself (EACCES), not only by the empty network
// namespace (ENETUNREACH), and Result reports the ABI.
func TestIsolationLandlockLayer(t *testing.T) {
	requireIsolation(t)
	iso := Probe(context.Background())
	if iso.LandlockABI < 4 {
		if os.Getenv("REMPART_REQUIRE_SANDBOX") == "1" && iso.LandlockABI > 0 {
			t.Fatalf("Landlock ABI %d: under 4, the TCP layer cannot be proven", iso.LandlockABI)
		}
		t.Skipf("Landlock ABI %d, under 4: no TCP rule to prove", iso.LandlockABI)
	}
	tool, ws := selfTool(t), workspace(t)
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	if code := direct(t, tool, "tcp", l.Addr().String()); code != 0 {
		t.Fatalf("witness: tcp outside isolation: exit %d", code)
	}
	res, err := Run(context.Background(), isoSpec(t, ws, tool, "tcp", l.Addr().String()))
	if err != nil || res.ExitCode != 1 {
		t.Fatalf("tcp under isolation: %+v, %v; want exit 1", res, err)
	}
	if !strings.Contains(string(res.Stdout), "permission denied") {
		t.Errorf("tcp under isolation failed with %q, want permission denied (Landlock), not only the empty network", bytes.TrimSpace(res.Stdout))
	}
	if res.Isolation.LandlockABI != iso.LandlockABI {
		t.Errorf("Result.Isolation.LandlockABI = %d, want %d", res.Isolation.LandlockABI, iso.LandlockABI)
	}
	// The layer keeps what the tools need: the files of data/ and a Unix
	// socket in TMPDIR (go-plugin), the read of the tree.
	if code := isolated(t, isoSpec(t, ws, tool, "write", filepath.Join(ws.DataDir(), "kept"))); code != 0 {
		t.Errorf("write data/ under Landlock: exit %d, want 0", code)
	}
	if err := ws.WriteFile("main.tf", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if code := isolated(t, isoSpec(t, ws, tool, "read", filepath.Join(ws.Dir(), "main.tf"))); code != 0 {
		t.Errorf("read the tree under Landlock: exit %d, want 0", code)
	}
	if code := isolated(t, isoSpec(t, ws, tool, "unixlisten")); code != 0 {
		t.Errorf("listen on a Unix socket in TMPDIR under Landlock: exit %d, want 0", code)
	}
}

// childEnv names the test that a child process reruns (inChild).
const childEnv = "REMPART_TEST_CHILD"

// inChild reports whether this process is the child of the current test. In
// the parent, it runs prepare on an OS thread locked for good (the thread ends
// with its goroutine, and what prepare changed with it), starts from that very
// thread this test binary on the current test only, and asserts that the
// child passed. A session keyring or a mount namespace belongs to one thread:
// the launcher of Run, on another thread, would not inherit it, while every
// thread of the child does. A prepare that fails skips the test (witness).
func inChild(t *testing.T, env []string, prepare func() error) bool {
	t.Helper()
	if os.Getenv(childEnv) == t.Name() {
		return true
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		out       []byte
		err, prep error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread ends with this goroutine
		if err := prepare(); err != nil {
			ch <- result{prep: err}
			return
		}
		cmd := exec.CommandContext(context.Background(), exe, "-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "-test.v", "-test.count=1") //nolint:gosec // G204: this test binary.
		cmd.Env = append(append(os.Environ(), env...), childEnv+"="+t.Name())
		out, err := cmd.CombinedOutput()
		ch <- result{out: out, err: err}
	}()
	r := <-ch
	switch {
	case r.prep != nil:
		t.Skipf("witness: cannot prepare the child process: %v", r.prep)
	case bytes.Contains(r.out, []byte("--- SKIP: "+t.Name()+" ")):
		t.Skipf("the child process skipped:\n%s", r.out)
	case r.err != nil || !bytes.Contains(r.out, []byte("--- PASS: "+t.Name()+" ")):
		t.Fatalf("child process of %s: %v\n%s", t.Name(), r.err, r.out)
	}
	t.Logf("child process:\n%s", r.out)
	return false
}

// joinKeyringWithKey joins, on the calling thread, a new anonymous session
// keyring and adds to it a user key desc holding payload.
func joinKeyringWithKey(desc, payload string) error {
	nr, ok := testKeyctl[runtime.GOARCH]
	if !ok {
		return fmt.Errorf("no keyctl number for %s", runtime.GOARCH)
	}
	if _, _, e := syscall.RawSyscall(nr.keyctl, tkJoinSession, 0, 0); e != 0 {
		return fmt.Errorf("join a session keyring: %w", e)
	}
	typ, d, p := []byte("user\x00"), []byte(desc+"\x00"), []byte(payload)
	//nolint:gosec // G103: add_key takes pointers to its type, description and payload.
	if _, _, e := syscall.Syscall6(nr.addKey, uintptr(unsafe.Pointer(&typ[0])), uintptr(unsafe.Pointer(&d[0])), uintptr(unsafe.Pointer(&p[0])), uintptr(len(p)), tkSpecSession, 0); e != 0 {
		return fmt.Errorf("add_key: %w", e)
	}
	return nil
}

// TestIsolationProcRestricted proves D5 (review of M3-T02b, high finding 1):
// the /proc of the tool shows its PID namespace only (subset=pid), with no
// /proc/sys and no /proc/sysrq-trigger, whatever the uid of the launcher; a
// kernel that refuses subset=pid fails closed, never with a full /proc.
func TestIsolationProcRestricted(t *testing.T) {
	requireIsolation(t)
	tool, ws := selfTool(t), workspace(t)
	for _, p := range []string{"/proc/sys/kernel/core_pattern", "/proc/sys/kernel/modprobe", "/proc/sysrq-trigger", "/proc/kcore"} {
		t.Run(filepath.Base(p), func(t *testing.T) { attack(t, tool, ws, "stat", p) })
	}
	t.Run("subset_refused_fails_closed", func(t *testing.T) {
		marker := filepath.Join(ws.DataDir(), "ran-with-a-full-proc")
		_, err := Run(withTestHooks(context.Background(), testHooks{FailProcSubset: true}), isoSpec(t, ws, tool, "write", marker))
		if !errors.Is(err, ErrIsolationSetup) {
			t.Fatalf("Run with subset=pid refused = %v, want ErrIsolationSetup (never a full /proc)", err)
		}
		if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("the tool ran with a full /proc")
		}
	})
}

// TestIsolationSessionKeyring proves D6 (review of M3-T02b, high finding 2,
// P1): the session keyring of the launcher, that a user namespace does not
// change and Landlock does not filter, is closed to the tool. The test reruns
// itself in a child process started by a thread that joined a session keyring
// holding a key: the child, launcher of the run, holds that keyring on every
// thread, as a process under pam_keyinit does.
func TestIsolationSessionKeyring(t *testing.T) {
	requireIsolation(t)
	const desc, payload = "rempart-witness", "launcher-secret"
	if !inChild(t, nil, func() error { return joinKeyringWithKey(desc, payload) }) {
		return
	}
	tool := selfTool(t)
	if code, out := directOutput(t, context.Background(), tool, "keyring", desc); code != 0 || !bytes.Contains(out, []byte(payload)) {
		t.Fatalf("witness: the key of the session keyring is not readable outside isolation: exit %d, %q", code, bytes.TrimSpace(out))
	}
	for _, m := range layers() {
		t.Run(m.name, func(t *testing.T) {
			res, err := Run(m.ctx, isoSpec(t, workspace(t), tool, "keyring", desc))
			if err != nil {
				t.Fatal(err)
			}
			if res.ExitCode != 1 || bytes.Contains(res.Stdout, []byte(payload)) {
				t.Errorf("keyring under isolation: exit %d, %q; want 1 (the session keyring of the launcher is closed)", res.ExitCode, bytes.TrimSpace(res.Stdout))
			}
		})
	}
}

// inheritableFD duplicates a directory on a descriptor beyond 1023 without
// close-on-exec (Go closes no such descriptor at a fork) until the end of the
// test.
func inheritableFD(t *testing.T) int {
	t.Helper()
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	target := 1500
	if lim.Cur <= uint64(target) {
		if lim.Cur <= 1025 {
			t.Skipf("witness: descriptor limit %d, no descriptor beyond 1023", lim.Cur)
		}
		target = int(lim.Cur) - 1 //nolint:gosec // G115: a descriptor limit above 1025 and under 1501.
	}
	dir, err := syscall.Open(t.TempDir(), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Close(dir) }()
	if err := syscall.Dup3(dir, target, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(target) })
	return target
}

// TestIsolationCredentials proves D3 and D6 (review of M3-T02b, medium
// findings 1 and 4): the tool runs as toolUID mapped to the launcher only,
// setgroups denied, every capability set empty, no_new_privs set, under a
// seccomp filter (amendment 1 of ADR 0015), and it inherits no descriptor but
// 0, 1 and 2, even one beyond 1023.
func TestIsolationCredentials(t *testing.T) {
	requireIsolation(t)
	tool, ws := selfTool(t), workspace(t)
	t.Run("capabilities_and_maps", func(t *testing.T) {
		res, err := Run(context.Background(), isoSpec(t, ws, tool, "creds"))
		if err != nil || res.ExitCode != 0 {
			t.Fatalf("creds: %+v, %v", res, err)
		}
		got := map[string]string{}
		for _, l := range strings.Split(string(res.Stdout), "\n") {
			if k, v, ok := strings.Cut(l, ":"); ok {
				got[k] = strings.TrimSpace(v)
			}
		}
		const none = "0000000000000000"
		want := map[string]string{
			"CapInh": none, "CapPrm": none, "CapEff": none, "CapBnd": none, "CapAmb": none,
			"NoNewPrivs": "1",
			"Seccomp":    "2",
			"uid_map":    fmt.Sprintf("%d %d 1", toolUID, os.Geteuid()),
			"gid_map":    fmt.Sprintf("%d %d 1", toolUID, os.Getegid()),
			"setgroups":  "deny",
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("%s of the tool = %q, want %q", k, got[k], v)
			}
		}
	})
	t.Run("descriptor_beyond_1023", func(t *testing.T) {
		fd := inheritableFD(t)
		if code, out := directOutput(t, context.Background(), tool, "fds"); code != 0 || !bytes.Contains(out, []byte(fmt.Sprintf("fd %d ", fd))) {
			t.Skipf("witness: descriptor %d not inherited outside isolation: %q", fd, out)
		}
		for _, m := range layers() {
			t.Run(m.name, func(t *testing.T) {
				res, err := Run(m.ctx, isoSpec(t, ws, tool, "fds"))
				if err != nil || res.ExitCode != 0 {
					t.Fatalf("fds: %+v, %v", res, err)
				}
				if out := strings.TrimSpace(string(res.Stdout)); out != "" {
					t.Errorf("descriptors inherited by the tool:\n%s\nwant none above 2", out)
				}
			})
		}
	})
}

// TestIsolationDevicesReadOnly proves D5 (review of M3-T02b, medium finding
// 2): the device nodes of the host bound in /dev, and the stdin of the tool,
// are on read-only mounts, so a tool mapped to the owner of these inodes (a
// root launcher) cannot change them on the host; /dev takes no new file;
// writing to /dev/null still works. A chmod to the current mode changes
// nothing even when it succeeds.
func TestIsolationDevicesReadOnly(t *testing.T) {
	requireIsolation(t)
	tool, ws := selfTool(t), workspace(t)
	for _, m := range layers() {
		t.Run(m.name, func(t *testing.T) {
			t.Run("chmod_dev_null", func(t *testing.T) { attackIn(t, m.ctx, tool, ws, "chmodsame", "/dev/null") })
			t.Run("fchmod_stdin", func(t *testing.T) { attackIn(t, m.ctx, tool, ws, "fchmod0same") })
			t.Run("create_in_dev", func(t *testing.T) {
				if code := isolatedIn(t, m.ctx, isoSpec(t, ws, tool, "write", "/dev/planted")); code != 1 {
					t.Errorf("create /dev/planted under isolation: exit %d, want 1", code)
				}
			})
			t.Run("write_dev_null", func(t *testing.T) {
				if code := isolatedIn(t, m.ctx, isoSpec(t, ws, tool, "write", "/dev/null")); code != 0 {
					t.Errorf("write /dev/null under isolation: exit %d, want 0", code)
				}
			})
		})
	}
}

// TestIsolationReadOnlyRecursive proves D5 (review of M3-T02b, medium finding
// 3): a mount under a read-only entry (a submount of /usr, of a private copy)
// is read-only in the tree of the tool too. The submount lives in a private
// mount namespace of a child process (CAP_SYS_ADMIN needed); the run without
// Landlock shows the mounts alone, a chmod is beyond Landlock.
func TestIsolationReadOnlyRecursive(t *testing.T) {
	requireIsolation(t)
	private := os.Getenv("REMPART_TEST_SUBMOUNT")
	if private == "" {
		private = t.TempDir()
	}
	sub := filepath.Join(private, "sub")
	if !inChild(t, []string{"REMPART_TEST_SUBMOUNT=" + private}, func() error {
		if err := os.Mkdir(sub, 0o700); err != nil { //nolint:gosec // G703: under the temporary directory of this test, passed to its child.
			return err
		}
		if err := syscall.Unshare(syscall.CLONE_NEWNS); err != nil {
			return fmt.Errorf("unshare a mount namespace: %w", err)
		}
		if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
			return err
		}
		return syscall.Mount("tmpfs", sub, "tmpfs", 0, "size=64k,mode=0700")
	}) {
		return
	}
	tool, ws := selfTool(t), workspace(t)
	if code := direct(t, tool, "write", filepath.Join(sub, "witness")); code != 0 {
		t.Fatalf("witness: the submount is not writable outside isolation (exit %d)", code)
	}
	for _, m := range layers() {
		t.Run(m.name, func(t *testing.T) {
			for _, action := range [][]string{{"write", filepath.Join(sub, "planted")}, {"chmodsame", sub}} {
				s := isoSpec(t, ws, tool, action[0], action[1:]...)
				s.ReadOnly = []string{private}
				if code := isolatedIn(t, m.ctx, s); code != 1 {
					t.Errorf("%v on a submount of a read-only entry: exit %d, want 1", action, code)
				}
			}
		})
	}
}

// TestIsolationTestHooksRefused proves that the test hooks exist in this test
// binary only: a configuration that carries them is invalid wherever
// testHooksAllowed is false (every other binary), and Run does not send them
// from there.
func TestIsolationTestHooksRefused(t *testing.T) {
	saved := testHooksAllowed
	t.Cleanup(func() { testHooksAllowed = saved })
	testHooksAllowed = false
	cfg := helperConfig{Probe: true, Root: "/r", Tree: "/t", PathDir: "/p", Home: "/h", Tmp: "/x", Test: &testHooks{NoLandlock: true}}
	if cfg.valid() {
		t.Fatal("a configuration with test hooks is valid outside the tests")
	}
	cfg.Test = nil
	if !cfg.valid() {
		t.Fatal("control: the same configuration without hooks is invalid")
	}
	t.Run("not_sent", func(t *testing.T) {
		requireIsolation(t)
		// The helper, this test binary, would honor the hook: a run that
		// succeeds proves that the launcher did not send it.
		res, err := Run(withTestHooks(context.Background(), testHooks{FailProcSubset: true}), isoSpec(t, workspace(t), selfTool(t), "noop"))
		if err != nil || res.ExitCode != 0 {
			t.Fatalf("Run with hooks refused by the launcher = %+v, %v; want a plain run", res, err)
		}
	})
}

// ringWithKey joins, on the calling thread, a new anonymous session keyring,
// adds to it a keyring ring with the rights of a user keyring (0x1f3f0000:
// the possessor all but setattr, the user all) and, in ring, a user key desc
// holding payload.
func ringWithKey(ring, desc, payload string) error {
	nr, ok := testKeyctl[runtime.GOARCH]
	if !ok {
		return fmt.Errorf("no keyctl number for %s", runtime.GOARCH)
	}
	if _, _, e := syscall.RawSyscall(nr.keyctl, tkJoinSession, 0, 0); e != 0 {
		return fmt.Errorf("join a session keyring: %w", e)
	}
	kt, r := []byte("keyring\x00"), []byte(ring+"\x00")
	//nolint:gosec // G103: add_key takes pointers to its type and description.
	id, _, e := syscall.Syscall6(nr.addKey, uintptr(unsafe.Pointer(&kt[0])), uintptr(unsafe.Pointer(&r[0])), 0, 0, tkSpecSession, 0)
	if e != 0 {
		return fmt.Errorf("add_key keyring: %w", e)
	}
	if _, _, e := syscall.RawSyscall(nr.keyctl, tkSetPerm, id, 0x1f3f0000); e != 0 {
		return fmt.Errorf("setperm: %w", e)
	}
	typ, d, p := []byte("user\x00"), []byte(desc+"\x00"), []byte(payload)
	//nolint:gosec // G103: add_key takes pointers to its type, description and payload.
	if _, _, e := syscall.Syscall6(nr.addKey, uintptr(unsafe.Pointer(&typ[0])), uintptr(unsafe.Pointer(&d[0])), uintptr(unsafe.Pointer(&p[0])), uintptr(len(p)), id, 0); e != 0 {
		return fmt.Errorf("add_key user: %w", e)
	}
	return nil
}

// TestIsolationKeysBySerial proves amendment 1 of ADR 0015 (second pass of
// the review of M3-T02b, T170): a keyring of the launcher whose "user" rights
// are open (as the user keyring of the initial namespace) stays out of reach
// of the tool even by its serial number, which a search over 2^31 numbers
// finds in minutes: the test hands the number to the tool, the worst case.
// add_key, which would exhaust the key quota of the uid, is refused too.
func TestIsolationKeysBySerial(t *testing.T) {
	requireIsolation(t)
	const ring, desc, payload = "rempart-witness-ring", "rempart-witness", "user-keyring-secret"
	if !inChild(t, nil, func() error { return ringWithKey(ring, desc, payload) }) {
		return
	}
	nr, ok := testKeyctl[runtime.GOARCH]
	if !ok {
		t.Fatalf("no keyctl number for %s", runtime.GOARCH)
	}
	kt, r := []byte("keyring\x00"), []byte(ring+"\x00")
	//nolint:gosec // G103: keyctl takes pointers to NUL-terminated strings.
	id, _, e := syscall.Syscall6(nr.keyctl, tkSearch, tkSpecSession, uintptr(unsafe.Pointer(&kt[0])), uintptr(unsafe.Pointer(&r[0])), 0, 0)
	if e != 0 {
		t.Fatalf("the witness keyring is not in the session keyring of the child: %v", e)
	}
	serial := strconv.FormatUint(uint64(id), 10)
	tool := selfTool(t)
	if code, out := directOutput(t, context.Background(), tool, "keylink", serial, desc); code != 0 || !bytes.Contains(out, []byte(payload)) {
		t.Fatalf("witness: link by serial number outside isolation: exit %d, %q", code, bytes.TrimSpace(out))
	}
	for _, m := range layers() {
		t.Run(m.name, func(t *testing.T) {
			res, err := Run(m.ctx, isoSpec(t, workspace(t), tool, "keylink", serial, desc))
			if err != nil {
				t.Fatal(err)
			}
			if res.ExitCode != 1 || bytes.Contains(res.Stdout, []byte(payload)) {
				t.Errorf("keylink under isolation: exit %d, %q; want 1 (no key system call for the tool)", res.ExitCode, bytes.TrimSpace(res.Stdout))
			}
			attackIn(t, m.ctx, tool, workspace(t), "addkey")
		})
	}
}
