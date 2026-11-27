package toolexec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// ADR 0015 option (c): the launcher re-executes this very binary as a helper
// in new user, mount, network, PID, IPC, UTS and cgroup namespaces; the
// helper builds the closed tree of the tool (D5), pivots into it, hardens
// (D6) and executes the tool, which becomes PID 1 of its namespace.

// helperArg0 is argv[0] of the helper; MaybeHelper recognizes it.
const helperArg0 = "rempart-toolexec-helper"

// toolUID is the uid and gid of the tool inside its user namespace (D3): not
// zero, so that the tool loses every capability at its exec.
const toolUID = 1000

// Descriptors of the helper: 3 its configuration, 4 the status channel
// (closed at the exec of the tool), 5 the sealed binary of the tool.
const (
	fdConfig = 3
	fdStatus = 4
	fdBinary = 5
)

// Status bytes of the helper: statusReady before any mount, statusProbeOK at
// the end of a probe; any other byte is the fixed code of the failed step.
const (
	statusReady   = 'R'
	statusProbeOK = 'K'
)

// sysMemfdCreate is memfd_create(2) by architecture: the repository has no
// build constraint (rule no-build-constraint); another architecture fails
// closed.
var sysMemfdCreate = map[string]uintptr{"amd64": 319, "arm64": 279}

// sysKeyctl is keyctl(2) by architecture; another architecture fails closed.
var sysKeyctl = map[string]uintptr{"amd64": 250, "arm64": 219}

// startMu serializes the start of helpers: the launcher is dumpable only for
// the time of Start (F10).
var startMu sync.Mutex

const (
	prSetNoNewPrivs = 38
	prCapAmbient    = 47
	prCapAmbientAll = 4
	memfdCloexec    = 0x1
	memfdSealing    = 0x2
	fAddSeals       = 1033
	sealAll         = 0x1 | 0x2 | 0x4 | 0x8 // seal, shrink, grow, write
	capVersion3     = 0x20080522
	prCapbsetRead   = 23

	keyctlJoinSessionKeyring = 1
	sysCloseRange            = 436 // the same on every architecture
	closeRangeCloexec        = 1 << 2

	sysMountSetattr = 442 // the same on every architecture
	atRecursive     = 0x8000
	mountAttrRdonly = 0x1
	mountAttrNosuid = 0x2
	mountAttrNodev  = 0x4
	mountAttrNoexec = 0x8
)

func prctl(op, a, b, c uintptr) error {
	if _, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, op, a, b, c, 0, 0); e != 0 {
		return e
	}
	return nil
}

// setDumpable sets PR_SET_DUMPABLE of the process (D2).
func setDumpable(v int) { _ = prctl(syscall.PR_SET_DUMPABLE, uintptr(v), 0, 0) }

// sealedCopy checks that no one else can change the binary of t (obligation
// (hi)), then copies it into a sealed memfd, hashing what it copies: the
// helper executes that copy, so a change of the file after the check has no
// effect (obligation (ht)).
func sealedCopy(t Tool) (*os.File, error) {
	if dir, err := os.Lstat(filepath.Dir(t.Path)); err != nil || !dir.IsDir() || !ownedPrivate(dir, 0o022) {
		return nil, invalid("tool directory writable by another user")
	}
	f, err := os.OpenFile(t.Path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, invalid("tool is not a regular file")
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, invalid("tool is not a regular file")
	}
	if !ownedPrivate(info, 0o222) {
		return nil, invalid("tool writable, or owned by another user")
	}
	nr, ok := sysMemfdCreate[runtime.GOARCH]
	if !ok {
		return nil, ErrIsolationUnavailable
	}
	name := []byte("rempart-tool\x00")
	//nolint:gosec // G103: memfd_create takes a pointer to its NUL-terminated name.
	fd, _, e := syscall.Syscall(nr, uintptr(unsafe.Pointer(&name[0])), memfdCloexec|memfdSealing, 0)
	if e != 0 {
		return nil, fmt.Errorf("toolexec: sealed copy: %w", e)
	}
	mem := os.NewFile(fd, "memfd:rempart-tool")
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(mem, h), f); err != nil {
		_ = mem.Close()
		return nil, invalid("tool unreadable")
	}
	if hex.EncodeToString(h.Sum(nil)) != t.SHA256 {
		_ = mem.Close()
		return nil, ErrChecksum
	}
	if _, _, e := syscall.Syscall(syscall.SYS_FCNTL, fd, fAddSeals, sealAll); e != 0 {
		_ = mem.Close()
		return nil, fmt.Errorf("toolexec: sealed copy: %w", e)
	}
	return mem, nil
}

// realProbe runs the helper once in probe mode on an empty workspace.
func realProbe(ctx context.Context) Isolation {
	ws, err := NewWorkspace()
	if err != nil {
		return Isolation{Reason: "probe workspace"}
	}
	defer func() { _ = ws.Close() }()
	scratch, err := os.MkdirTemp("", "rempart-probe-")
	if err != nil {
		return Isolation{Reason: "probe scratch directory"}
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	for _, d := range []string{"root", "home", "tmp"} {
		if err := os.Mkdir(filepath.Join(scratch, d), 0o700); err != nil {
			return Isolation{Reason: "probe scratch directory"}
		}
	}
	cfg := helperConfig{
		Probe: true, Root: filepath.Join(scratch, "root"), Tree: ws.Dir(), PathDir: ws.pathDir(), Data: ws.DataDir(),
		Home: filepath.Join(scratch, "home"), Tmp: filepath.Join(scratch, "tmp"),
	}
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var out bytes.Buffer
	state, err := launch(pctx, cfg, nil, &out, &out)
	switch {
	case errors.Is(err, errHelperStart):
		return Isolation{Reason: "helper start refused: namespaces unavailable"}
	case err != nil:
		return Isolation{Reason: "helper setup failed"}
	case !state.Exited() || state.ExitCode() != 0:
		return Isolation{Reason: "helper probe did not complete"}
	}
	return Isolation{Level: LevelFull, LandlockABI: landlockABI()}
}

// landlockABI is the Landlock ABI of the kernel, 0 when absent (D7).
func landlockABI() int {
	const createRulesetVersion = 1
	v, _, e := syscall.Syscall(444 /* landlock_create_ruleset */, 0, 0, createRulesetVersion)
	if e != 0 || int(v) < 0 {
		return 0
	}
	return int(v)
}

// errHelperStart: the kernel refused to create the helper (namespaces).
var errHelperStart = errors.New("toolexec: helper start refused")

// errSetup carries the code of the failed step of the helper.
type errSetup struct{ code byte }

func (e errSetup) Error() string { return fmt.Sprintf("%v (step %q)", ErrIsolationSetup, e.code) }
func (e errSetup) Unwrap() error { return ErrIsolationSetup }

// launch starts the helper with cfg (bin on fdBinary when not a probe), waits
// for it, and returns its state; a failed setup is an errSetup. Start and Wait
// run on one locked OS thread, so that Pdeathsig follows the launcher (F4).
func launch(ctx context.Context, cfg helperConfig, bin *os.File, stdout, stderr io.Writer) (*os.ProcessState, error) {
	cfgR, cfgW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("toolexec: helper pipe: %w", err)
	}
	defer func() { _ = cfgR.Close(); _ = cfgW.Close() }()
	stR, stW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("toolexec: helper pipe: %w", err)
	}
	defer func() { _ = stR.Close(); _ = stW.Close() }()
	extra := []*os.File{cfgR, stW}
	if bin != nil {
		extra = append(extra, bin)
	}
	cmd := exec.CommandContext(ctx, "/proc/self/exe")
	cmd.Args = []string{helperArg0}
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.ExtraFiles = extra
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET | syscall.CLONE_NEWPID |
			syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS | syscall.CLONE_NEWCGROUP,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: toolUID, HostID: os.Geteuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: toolUID, HostID: os.Getegid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
		Setsid:                     true,
		Pdeathsig:                  syscall.SIGKILL,
		// The helper runs as toolUID: these capabilities survive its own exec
		// (F11), and it drops them all before the exec of the tool.
		AmbientCaps: []uintptr{8 /* CAP_SETPCAP */, 21 /* CAP_SYS_ADMIN */, 24 /* CAP_SYS_RESOURCE */},
	}
	killGroup := func() {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
	}
	cmd.Cancel = func() error { killGroup(); return nil }
	cmd.WaitDelay = 2 * time.Second

	started := make(chan error, 1)
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		startMu.Lock()
		setDumpable(1)
		err := cmd.Start()
		setDumpable(0)
		startMu.Unlock()
		started <- err
		if err == nil {
			done <- cmd.Wait()
		}
	}()
	if err := <-started; err != nil {
		var errno syscall.Errno
		if errors.As(err, &errno) && (errno == syscall.EPERM || errno == syscall.EACCES || errno == syscall.ENOSPC || errno == syscall.EINVAL || errno == syscall.ENOSYS) {
			return nil, errHelperStart
		}
		return nil, fmt.Errorf("%w: %w", errHelperStart, err)
	}
	_ = cfgR.Close()
	_ = stW.Close()
	raw, err := json.Marshal(cfg)
	if err == nil {
		_, err = cfgW.Write(raw)
	}
	_ = cfgW.Close()
	if err != nil {
		killGroup()
	}

	// The status channel: statusReady within 2 seconds, then the end of file
	// at the exec of the tool, or a fixed code.
	status := make(chan []byte, 1)
	go func() {
		var b []byte
		buf := make([]byte, 8)
		_ = stR.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := stR.Read(buf[:1])
		b = append(b, buf[:n]...)
		_ = stR.SetReadDeadline(time.Time{})
		if n == 1 && buf[0] == statusReady {
			rest, _ := io.ReadAll(io.LimitReader(stR, 64))
			b = append(b, rest...)
		} else {
			killGroup()
		}
		status <- b
	}()
	waitErr := <-done
	killGroup()
	st := <-status
	switch {
	case len(st) == 0 || st[0] != statusReady:
		return cmd.ProcessState, errSetup{code: '?'}
	case cfg.Probe && (len(st) != 2 || st[1] != statusProbeOK):
		return cmd.ProcessState, errSetup{code: last(st)}
	case !cfg.Probe && len(st) != 1:
		return cmd.ProcessState, errSetup{code: last(st)}
	}
	var exitErr *exec.ExitError
	if waitErr != nil && !errors.As(waitErr, &exitErr) && !errors.Is(waitErr, exec.ErrWaitDelay) {
		return cmd.ProcessState, fmt.Errorf("toolexec: helper: %w", waitErr)
	}
	return cmd.ProcessState, nil
}

func last(b []byte) byte {
	if len(b) == 0 {
		return '?'
	}
	return b[len(b)-1]
}

// MaybeHelper must be the first statement of main and TestMain in every
// binary that links toolexec (rule toolexec-helper-first). In the helper
// process it builds the tree of the tool and executes it, never returning;
// elsewhere it returns at once.
func MaybeHelper() {
	if len(os.Args) == 0 || os.Args[0] != helperArg0 {
		return
	}
	runtime.LockOSThread()
	os.Exit(helperMain())
}

// helperMain is the helper: it never reads anything but its configuration,
// opens no connection and grants no right its launcher does not hold (D4).
func helperMain() int {
	status := os.NewFile(fdStatus, "status")
	fail := func(code byte) int {
		_, _ = status.Write([]byte{code})
		return 127
	}
	if _, err := status.Write([]byte{statusReady}); err != nil {
		return 127
	}
	if _, _, e := syscall.RawSyscall(syscall.SYS_FCNTL, fdStatus, syscall.F_SETFD, syscall.FD_CLOEXEC); e != 0 {
		return fail('f')
	}
	var cfg helperConfig
	dec := json.NewDecoder(io.LimitReader(os.NewFile(fdConfig, "config"), 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil || !cfg.valid() {
		return fail('C')
	}
	if code := buildTree(&cfg); code != 0 {
		return fail(code)
	}
	if code := harden(&cfg); code != 0 {
		return fail(code)
	}
	if code := landlock(&cfg); code != 0 {
		return fail(code)
	}
	if cfg.Probe {
		_, _ = status.Write([]byte{statusProbeOK})
		return 0
	}
	_ = syscall.Exec(cfg.Tool, cfg.Args, cfg.Env) //nolint:gosec // G204: the sealed copy of a locked tool, arguments as an array (ADR 0015 D6).
	return fail('x')
}

// valid checks that every path of the configuration is absolute and clean.
func (c *helperConfig) valid() bool {
	if c.Test != nil && !testHooksAllowed {
		return false
	}
	paths := append([]string{c.Root, c.Tree, c.PathDir, c.Home, c.Tmp}, c.ReadOnly...)
	if c.Data != "" {
		paths = append(paths, c.Data)
	}
	if !c.Probe {
		paths = append(paths, c.Tool)
		if len(c.Args) == 0 {
			return false
		}
	}
	for _, p := range paths {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
			return false
		}
	}
	return true
}

// setAttr sets attr on the mount at path and on every mount below it
// (mount_setattr with AT_RECURSIVE): a remount changes the top mount only, so
// a submount of a read-only entry would stay writable (review of M3-T02b).
// It sets and never clears: the atime flags and the flags of the host that a
// user namespace locks are kept (F12). A kernel without mount_setattr (before
// 5.12) fails closed.
func setAttr(path string, attr uint64) error {
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return err
	}
	a := struct{ set, clr, propagation, userns uint64 }{set: attr}
	fdcwd := -100 // AT_FDCWD
	//nolint:gosec // G103: mount_setattr takes pointers to its path and attributes.
	if _, _, e := syscall.Syscall6(sysMountSetattr, uintptr(fdcwd), uintptr(unsafe.Pointer(p)), atRecursive, uintptr(unsafe.Pointer(&a)), unsafe.Sizeof(a), 0); e != 0 {
		return e
	}
	return nil
}

// bind mounts the directory src at root+src with its submounts, then sets
// nosuid, nodev and attr (mountAttrRdonly for a read-only entry) on all of
// them.
func bind(root, src string, attr uint64) error {
	dst := root + src
	if err := os.MkdirAll(dst, 0o750); err != nil {
		return err
	}
	if err := syscall.Mount(src, dst, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return err
	}
	return setAttr(dst, mountAttrNosuid|mountAttrNodev|attr)
}

// buildTree mounts the closed tree of D5 at cfg.Root and pivots into it.
func buildTree(cfg *helperConfig) byte {
	r := cfg.Root
	if syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, "") != nil {
		return 'm'
	}
	if syscall.Mount("tmpfs", r, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "mode=0755,size=1m") != nil {
		return 'r'
	}
	for _, d := range systemDirs {
		fi, err := os.Lstat(d)
		switch {
		case err != nil:
			continue
		case fi.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(d)
			if err != nil || os.Symlink(target, r+d) != nil {
				return 's'
			}
		case bind(r, d, mountAttrRdonly) != nil:
			return 's'
		}
	}
	if os.Mkdir(r+"/etc", 0o750) != nil {
		return 'e'
	}
	uid := fmt.Sprint(toolUID)
	for name, data := range map[string]string{
		"passwd": "tool:x:" + uid + ":" + uid + "::/nonexistent:/nonexistent\n", "group": "tool:x:" + uid + ":\n",
		"hosts": "127.0.0.1 localhost\n", "resolv.conf": "",
	} {
		if os.WriteFile(r+"/etc/"+name, []byte(data), 0o644) != nil { //nolint:gosec // G306: synthetic, world-readable /etc of the tool.
			return 'e'
		}
	}
	if os.Mkdir(r+"/dev", 0o750) != nil || syscall.Mount("tmpfs", r+"/dev", "tmpfs", syscall.MS_NOSUID|syscall.MS_NOEXEC, "mode=0755,size=64k") != nil {
		return 'd'
	}
	for _, n := range []string{"null", "zero", "full", "random", "urandom"} {
		if os.WriteFile(r+"/dev/"+n, nil, 0o666) != nil || syscall.Mount("/dev/"+n, r+"/dev/"+n, "", syscall.MS_BIND, "") != nil { //nolint:gosec // G306: mount point of a device node.
			return 'd'
		}
	}
	// /dev and the device nodes of the host read-only: a tool mapped to the
	// owner of these inodes (a root launcher) cannot change them, and /dev
	// takes no file (review of M3-T02b). Writing to a device stays possible.
	if setAttr(r+"/dev", mountAttrRdonly|mountAttrNosuid|mountAttrNoexec) != nil {
		return 'd'
	}
	for _, p := range append([]string{cfg.PathDir}, cfg.ReadOnly...) {
		if bind(r, p, mountAttrRdonly) != nil {
			return 'o'
		}
	}
	if bind(r, cfg.Tree, mountAttrRdonly|mountAttrNoexec) != nil {
		return 't'
	}
	for _, p := range []string{cfg.Home, cfg.Tmp} {
		if bind(r, p, mountAttrNoexec) != nil {
			return 'w'
		}
	}
	if cfg.Data != "" && bind(r, cfg.Data, 0) != nil {
		return 'w'
	}
	if !cfg.Probe {
		if code := mountTool(cfg); code != 0 {
			return code
		}
	}
	// Nested user namespaces off, before the /proc of the PID namespace hides
	// /proc/sys (D6).
	if os.WriteFile("/proc/sys/user/max_user_namespaces", []byte("0"), 0) != nil {
		return 'u'
	}
	if os.Mkdir(r+"/proc", 0o550) != nil {
		return 'p'
	}
	// subset=pid or nothing: a full /proc opens /proc/sys and
	// /proc/sysrq-trigger to a tool mapped to the owner of their inodes (a
	// root launcher), core_pattern leading to the root of the host (review of
	// M3-T02b). A kernel that refuses the option (before 5.8) fails closed,
	// and a kernel that would ignore it too.
	if cfg.Test != nil && cfg.Test.FailProcSubset ||
		syscall.Mount("proc", r+"/proc", "proc", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "subset=pid") != nil {
		return 'p'
	}
	if _, err := os.Lstat(r + "/proc/sys"); !errors.Is(err, os.ErrNotExist) {
		return 'p'
	}
	if os.Mkdir(r+"/.old", 0o700) != nil || syscall.PivotRoot(r, r+"/.old") != nil || syscall.Chdir("/") != nil {
		return 'v'
	}
	if syscall.Unmount("/.old", syscall.MNT_DETACH) != nil || os.Remove("/.old") != nil {
		return 'v'
	}
	if syscall.Mount("", "/", "", syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV, "") != nil {
		return 'v'
	}
	return 0
}

// mountTool copies the sealed binary into a tmpfs of the mount namespace of
// the tool, on the directory of the tool, then read-only (ht): a stable path
// for a tool that re-executes itself, the content checked by the launcher.
func mountTool(cfg *helperConfig) byte {
	dir := cfg.Root + filepath.Dir(cfg.Tool)
	var st syscall.Stat_t
	if os.MkdirAll(dir, 0o750) != nil || syscall.Fstat(fdBinary, &st) != nil {
		return 'b'
	}
	if syscall.Mount("tmpfs", dir, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, fmt.Sprintf("mode=0755,size=%d", st.Size+1<<20)) != nil {
		return 'b'
	}
	dst, err := os.OpenFile(cfg.Root+cfg.Tool, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o500) //nolint:gosec // G302,G304: the tool in its own tmpfs.
	if err != nil {
		return 'b'
	}
	_, err = io.Copy(dst, io.NewSectionReader(os.NewFile(fdBinary, "binary"), 0, st.Size))
	if cerr := dst.Close(); err != nil || cerr != nil {
		return 'b'
	}
	if syscall.Mount("", dir, "", syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV, "") != nil {
		return 'b'
	}
	return 0
}

// harden sets the host name and the working directory, gives the tool a
// stdin of its own tree, leaves the session keyring of the launcher, closes
// every descriptor at the exec but stdin, stdout and stderr, and drops every
// privilege (D6). It runs on the locked thread that executes the tool.
func harden(cfg *helperConfig) byte {
	if syscall.Sethostname([]byte("rempart-tool")) != nil {
		return 'h'
	}
	if syscall.Chdir(cfg.Tree) != nil {
		return 'c'
	}
	// The stdin of the launcher is the /dev/null of the host, an inode that a
	// tool mapped to its owner could change through fchmod; this one is on the
	// read-only /dev of the tree (review of M3-T02b).
	null, err := syscall.Open("/dev/null", syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return 'i'
	}
	if syscall.Dup3(null, 0, 0) != nil || syscall.Close(null) != nil {
		return 'i'
	}
	// A fresh anonymous session keyring: the one of the launcher (Kerberos,
	// aws-vault, fscrypt keys) crosses user namespaces, and Landlock does not
	// filter keyctl (review of M3-T02b). A kernel without keys has none.
	nr, ok := sysKeyctl[runtime.GOARCH]
	if !ok {
		return 'y'
	}
	if _, _, e := syscall.RawSyscall(nr, keyctlJoinSessionKeyring, 0, 0); e != 0 && e != syscall.ENOSYS {
		return 'y'
	}
	// Every descriptor above 2 closed at the exec, whatever its number: Go
	// closes none at a fork, and an ancestor may pass one beyond 1023 that
	// opens the host (review of M3-T02b). Then checked.
	if _, _, e := syscall.RawSyscall(sysCloseRange, 3, uintptr(^uint32(0)), closeRangeCloexec); e != 0 || !onlyStdio() {
		return 'q'
	}
	if prctl(prSetNoNewPrivs, 1, 0, 0) != nil {
		return 'k'
	}
	for c := uintptr(0); c <= 63; c++ {
		err := prctl(syscall.PR_CAPBSET_DROP, c, 0, 0)
		if errors.Is(err, syscall.EINVAL) {
			break // past the last capability of the kernel
		}
		if err != nil {
			return 'k'
		}
	}
	for c := uintptr(0); c <= 63; c++ {
		v, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, prCapbsetRead, c, 0, 0, 0, 0)
		if e != 0 {
			break
		}
		if v != 0 {
			return 'k'
		}
	}
	// Inheritable set emptied (F11), then the ambient set.
	type capHeader struct {
		version uint32
		pid     int32
	}
	type capData struct{ effective, permitted, inheritable uint32 }
	hdr := capHeader{version: capVersion3}
	var data [2]capData
	//nolint:gosec // G103: capget takes pointers to its header and data.
	if _, _, e := syscall.RawSyscall(syscall.SYS_CAPGET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		return 'k'
	}
	data[0].inheritable, data[1].inheritable = 0, 0
	//nolint:gosec // G103: capset takes pointers to its header and data.
	if _, _, e := syscall.RawSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		return 'k'
	}
	if prctl(prCapAmbient, prCapAmbientAll, 0, 0) != nil {
		return 'k'
	}
	return 0
}

// onlyStdio reports whether every open descriptor above 2 is closed at the
// exec, read from the /proc of the tool.
func onlyStdio() bool {
	dir, err := syscall.Open("/proc/self/fd", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer func() { _ = syscall.Close(dir) }()
	buf := make([]byte, 4096)
	for {
		n, err := syscall.ReadDirent(dir, buf)
		if err != nil {
			return false
		}
		if n == 0 {
			return true
		}
		_, _, names := syscall.ParseDirent(buf[:n], -1, nil)
		for _, name := range names {
			fd, err := strconv.Atoi(name)
			if err != nil {
				return false
			}
			if fd <= 2 {
				continue
			}
			flags, _, e := syscall.RawSyscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
			if e != 0 || flags&syscall.FD_CLOEXEC == 0 {
				return false
			}
		}
	}
}

// Landlock access rights (D7), by ABI.
const (
	llExecute   = 1 << 0
	llWriteFile = 1 << 1
	llReadFile  = 1 << 2
	llReadDir   = 1 << 3
	llMakeChar  = 1 << 6
	llMakeBlock = 1 << 11
	llFSABI1    = 1<<13 - 1 // execute to make_sym
	llRefer     = 1 << 13   // ABI 2
	llTruncate  = 1 << 14   // ABI 3
	llIoctlDev  = 1 << 15   // ABI 5
	llNetTCP    = 1<<0 | 1<<1
	llScopes    = 1<<0 | 1<<1 // abstract Unix sockets, signals (ABI 6)

	sysLandlockCreateRuleset = 444
	sysLandlockAddRule       = 445
	sysLandlockRestrictSelf  = 446
	landlockRulePathBeneath  = 1
	oPath                    = 0x200000 // O_PATH, the same on amd64 and arm64
)

// landlock adds, on a kernel with Landlock, a domain that allows the closed
// tree of D5 only, with the rights of each entry, refuses every TCP bind and
// connect (ABI 4) and scopes abstract Unix sockets and signals (ABI 6). A
// layer on top of the namespaces (D7): an ABI 0 is no failure, a failure to
// apply an announced ABI is.
func landlock(cfg *helperConfig) byte {
	abi := landlockABI()
	if abi < 1 || cfg.Test != nil && cfg.Test.NoLandlock {
		return 0
	}
	fsAll := uint64(llFSABI1)
	if abi >= 2 {
		fsAll |= llRefer
	}
	if abi >= 3 {
		fsAll |= llTruncate
	}
	if abi >= 5 {
		fsAll |= llIoctlDev
	}
	attr := struct{ fs, net, scoped uint64 }{fs: fsAll}
	size := uintptr(8)
	if abi >= 4 {
		attr.net, size = llNetTCP, 16
	}
	if abi >= 6 {
		attr.scoped, size = llScopes, 24
	}
	//nolint:gosec // G103: landlock_create_ruleset takes a pointer to its attributes.
	rfd, _, e := syscall.RawSyscall(sysLandlockCreateRuleset, uintptr(unsafe.Pointer(&attr)), size, 0)
	if e != 0 {
		return 'l'
	}
	defer func() { _ = syscall.Close(int(rfd)) }()
	roExec := uint64(llReadFile | llReadDir | llExecute)
	ro := uint64(llReadFile | llReadDir)
	rules := []struct {
		path   string
		access uint64
	}{
		{"/", llReadDir},
		{"/usr", roExec},
		{"/etc", ro},
		{"/proc", ro},
		{"/dev", fsAll & (llReadFile | llWriteFile | llReadDir | llTruncate | llIoctlDev)},
		{cfg.Tree, ro},
		{cfg.PathDir, llReadDir},
		{cfg.Home, fsAll &^ (llExecute | llMakeChar | llMakeBlock)},
		{cfg.Tmp, fsAll &^ (llExecute | llMakeChar | llMakeBlock)},
	}
	for _, d := range cfg.ReadOnly {
		rules = append(rules, struct {
			path   string
			access uint64
		}{d, roExec})
	}
	if cfg.Data != "" {
		rules = append(rules, struct {
			path   string
			access uint64
		}{cfg.Data, fsAll &^ (llMakeChar | llMakeBlock)})
	}
	if !cfg.Probe {
		rules = append(rules, struct {
			path   string
			access uint64
		}{filepath.Dir(cfg.Tool), roExec})
	}
	for _, r := range rules {
		fd, err := syscall.Open(r.path, oPath|syscall.O_CLOEXEC|syscall.O_DIRECTORY, 0)
		if err != nil {
			return 'l'
		}
		beneath := struct {
			allowed uint64
			parent  int32
		}{allowed: r.access, parent: int32(fd)} //nolint:gosec // G115: a file descriptor fits an int32.
		//nolint:gosec // G103: landlock_add_rule takes a pointer to its rule.
		_, _, e := syscall.RawSyscall6(sysLandlockAddRule, rfd, landlockRulePathBeneath, uintptr(unsafe.Pointer(&beneath)), 0, 0, 0)
		_ = syscall.Close(fd)
		if e != 0 {
			return 'l'
		}
	}
	if _, _, e := syscall.RawSyscall(sysLandlockRestrictSelf, rfd, 0, 0); e != 0 {
		return 'l'
	}
	return 0
}
