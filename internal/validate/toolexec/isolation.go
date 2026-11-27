package toolexec

import (
	"context"
	"errors"
	"strings"
	"sync"
)

// Level is the isolation level of a run (ADR 0015 D1): LevelFull, or empty
// when the kernel does not offer it.
type Level string

// LevelFull is the only level of ADR 0015: namespaces, closed tree, hardening.
const LevelFull Level = "full"

// Isolation is what Probe measured once per process, by a real helper run.
type Isolation struct {
	Level       Level  // LevelFull, or "" when unavailable
	LandlockABI int    // 0 when Landlock is absent (D7)
	Reason      string // fixed text when Level is ""
}

// Errors of the isolation. Fixed messages: never an output of the tool.
var (
	// ErrIsolationUnavailable: the full isolation is not offered; returned
	// before any process (D1, fail closed).
	ErrIsolationUnavailable = errors.New("toolexec: tool isolation unavailable")
	// ErrIsolationSetup: the helper failed to build the tree of the tool.
	ErrIsolationSetup = errors.New("toolexec: tool isolation setup failed")
)

var (
	probeOnce   sync.Once
	probeResult Isolation
	// probeFunc is the probe Run consults; a test of this package replaces
	// it to prove the failure closed (TestIsolationFailsClosed).
	probeFunc = func(ctx context.Context) Isolation {
		probeOnce.Do(func() { probeResult = realProbe(ctx) })
		return probeResult
	}
)

// Probe runs the helper once in probe mode (namespaces and tree, no exec)
// and caches the result for the process (D2).
func Probe(ctx context.Context) Isolation { return probeFunc(ctx) }

// systemDirs are mounted read-only from the host, at the same paths (links
// kept as links, merged /usr).
var systemDirs = []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"}

// helperConfig is the configuration of one helper run, sent on fdConfig.
type helperConfig struct {
	Probe    bool       `json:"probe"`
	Root     string     `json:"root"`
	Tool     string     `json:"tool"`
	Args     []string   `json:"args"`
	Env      []string   `json:"env"`
	Tree     string     `json:"tree"`
	PathDir  string     `json:"path_dir"`
	Data     string     `json:"data"`
	Home     string     `json:"home"`
	Tmp      string     `json:"tmp"`
	ReadOnly []string   `json:"read_only"`
	Test     *testHooks `json:"test,omitempty"`
}

// testHooks weaken the helper in a test of this package only: NoLandlock
// leaves out the Landlock layer, so that the namespaces and mounts are proven
// on their own (D7 is a layer, never a substitute); FailProcSubset acts as a
// kernel that refuses the subset=pid option of /proc.
type testHooks struct {
	NoLandlock     bool `json:"no_landlock"`
	FailProcSubset bool `json:"fail_proc_subset"`
}

// testHooksKey carries testHooks in the context of Run.
type testHooksKey struct{}

// testHooksAllowed is set by the test binary of this package only (an init of
// a _test.go file): anywhere else Run never sends hooks and the helper refuses
// a configuration that carries them.
var testHooksAllowed bool

// isSystemPath reports whether p is, or is under, a directory of the closed
// tree that the helper mounts itself (D5, D11).
func isSystemPath(p string) bool {
	for _, d := range append([]string{"/etc", "/dev", "/proc", "/sys"}, systemDirs...) {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}
