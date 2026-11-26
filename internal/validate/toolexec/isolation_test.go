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
	res, err := Run(context.Background(), s)
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
	cmd := exec.CommandContext(context.Background(), tool.Path, append([]string{fakeToolArg, action}, args...)...) //nolint:gosec // G204: the fake tool.
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ee):
		t.Logf("direct %s: %s", action, bytes.TrimSpace(out))
		return ee.ExitCode()
	}
	t.Fatalf("direct %s: %v", action, err)
	return -1
}

// attack asserts the witness (direct run succeeds) then the isolated failure.
func attack(t *testing.T, tool Tool, ws *Workspace, action string, args ...string) {
	t.Helper()
	if code := direct(t, tool, action, args...); code != 0 {
		t.Skipf("witness: %s %v fails outside isolation (code %d): the environment already blocks it", action, args, code)
	}
	if code := isolated(t, isoSpec(t, ws, tool, action, args...)); code != 1 {
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
	t.Run("tcp", func(t *testing.T) {
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
		attack(t, tool, ws, "tcp", l.Addr().String())
	})
	t.Run("udp", func(t *testing.T) {
		pc, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = pc.Close() }()
		attack(t, tool, ws, "udp", pc.LocalAddr().String(), "token")
	})
	t.Run("abstract_unix", func(t *testing.T) {
		name := fmt.Sprintf("@rempart-test-%d", os.Getpid())
		l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", name)
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
		attack(t, tool, ws, "unix", name)
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
	t.Run("root_closed_list", func(t *testing.T) {
		res, err := Run(context.Background(), isoSpec(t, ws, tool, "ls", "/"))
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
		attack(t, tool, ws, "read", secret)
	})
	t.Run("unix_pathname", func(t *testing.T) {
		sock := filepath.Join(t.TempDir(), "docker.sock")
		l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
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
		attack(t, tool, ws, "unix", sock)
	})
	t.Run("tree_read_only", func(t *testing.T) {
		attack(t, tool, ws, "write", filepath.Join(ws.Dir(), "dropped.trivyignore"))
	})
	t.Run("root_read_only", func(t *testing.T) {
		if code := isolated(t, isoSpec(t, ws, tool, "write", "/dropped")); code != 1 {
			t.Errorf("write / under isolation: exit %d, want 1", code)
		}
	})
	t.Run("nested_user_namespace", func(t *testing.T) {
		attack(t, tool, ws, "userns")
	})
	t.Run("data_writable_when_asked", func(t *testing.T) {
		if code := isolated(t, isoSpec(t, ws, tool, "write", filepath.Join(ws.DataDir(), "plan.bin"))); code != 0 {
			t.Fatalf("write data/ with WriteData: exit %d, want 0", code)
		}
		s := isoSpec(t, ws, tool, "write", filepath.Join(ws.DataDir(), "other"))
		s.WriteData = false
		if code := isolated(t, s); code != 1 {
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
	write := isoSpec(t, ws, tool, "write", filepath.Join(private, "planted-2"))
	write.ReadOnly = []string{private}
	if code := isolated(t, write); code != 1 {
		t.Errorf("write in a ReadOnly entry under isolation: exit %d, want 1", code)
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
	attack(t, tool, ws, "kill0", strconv.Itoa(victim.Process.Pid))
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
