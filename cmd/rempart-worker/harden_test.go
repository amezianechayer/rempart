package main

import (
	"bytes"
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// M0-T03b step B, plan docs/plans/M0-pile-dev-harden.md D9 and D10:
// obligations (bg) and (bh), threat T14.

var workerIdentityRe = regexp.MustCompile(`^rempart-worker-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// withoutFlags returns demoArgs without the named flags, then extra appended.
func withoutFlags(names []string, extra ...string) []string {
	args := slices.DeleteFunc(demoArgs(), func(a string) bool {
		return slices.ContainsFunc(names, func(n string) bool { return a == "-"+n || strings.HasPrefix(a, "-"+n+"=") })
	})
	return append(args, extra...)
}

// TestLoadConfigBoolFlagsOnce (bg, D9): -dev and -demo-once are set once, to
// the exact value true or false: a later occurrence must not undo an earlier
// one, and 1, t or TRUE are not read as a boolean.
func TestLoadConfigBoolFlagsOnce(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"dev_twice", append(demoArgs(), "-dev")},
		{"dev_false_then_dev", withFlag("dev", "-dev=false", "-dev")},
		{"dev_then_dev_false", append(demoArgs(), "-dev=false")},
		{"dev_double_dash_repeat", append(demoArgs(), "--dev")},
		{"demo_once_twice", append(demoArgs(), "-demo-once")},
		{"demo_once_then_false", append(demoArgs(), "-demo-once=false")},
		{"dev_one", withFlag("dev", "-dev=1")},
		{"dev_upper_case", withFlag("dev", "-dev=TRUE")},
		{"dev_t", withFlag("dev", "-dev=t")},
		{"dev_empty", withFlag("dev", "-dev=")},
		{"demo_once_zero", withFlag("demo-once", "-demo-once=0")},
		{"demo_once_capitalized", withFlag("demo-once", "-demo-once=True")},
		{"dev_space_value", withFlag("dev", "-dev", "true")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { refused(t, tc.args, ErrConfig) })
	}
	t.Run("explicit_true", func(t *testing.T) {
		cfg, err := LoadConfig(withoutFlags([]string{"dev", "demo-once"}, "-dev=true", "-demo-once=true"))
		if err != nil || cfg != demoConfig() {
			t.Errorf("LoadConfig(-dev=true -demo-once=true) = %+v, %v; want %+v", cfg, err, demoConfig())
		}
	})
	t.Run("explicit_false_is_a_boolean", func(t *testing.T) {
		refused(t, withFlag("dev", "-dev=false"), ErrFakeRequiresDev)
		refused(t, withFlag("demo-once", "-demo-once=false"), ErrDemoOnceRequired)
	})
}

// badTargets: addresses and namespaces LoadConfig refuses; run and
// clientOptions check them again (bh, T14).
func badTargets() []struct{ name, addr, ns string } {
	return []struct{ name, addr, ns string }{
		{"private", "10.0.0.1:7233", demoNS},
		{"hostname", "localhost:7233", demoNS},
		{"unspecified", "0.0.0.0:7233", demoNS},
		{"empty_address", "", demoNS},
		{"port_zero", "127.0.0.1:0", demoNS},
		{"namespace_upper_case", demoAddress, "Rempart"},
		{"namespace_empty", demoAddress, ""},
	}
}

// TestClientOptions (bh, D10, T14): the options of the Temporal client copy
// the checked address and namespace, carry a logger (the SDK default one
// writes to stdout) and an opaque identity, random per call, without host
// name or pid.
func TestClientOptions(t *testing.T) {
	opts, err := clientOptions(demoConfig())
	if err != nil {
		t.Fatalf("clientOptions(demo) = %v", err)
	}
	if opts.HostPort != demoAddress || opts.Namespace != demoNS {
		t.Errorf("HostPort %q, Namespace %q; want %q, %q", opts.HostPort, opts.Namespace, demoAddress, demoNS)
	}
	if opts.Logger == nil {
		t.Error("Logger is nil: the SDK default logger writes to stdout")
	}
	if !workerIdentityRe.MatchString(opts.Identity) {
		t.Errorf("Identity %q, want rempart-worker-<uuid v4>", opts.Identity)
	}
	host, _ := os.Hostname()
	if host != "" && strings.Contains(opts.Identity, host) || strings.Contains(opts.Identity, strconv.Itoa(os.Getpid())+"@") {
		t.Errorf("Identity %q carries the host name or the pid", opts.Identity)
	}
	again, err := clientOptions(demoConfig())
	if err != nil || again.Identity == opts.Identity {
		t.Errorf("second identity %q, %v; want another random identity than %q", again.Identity, err, opts.Identity)
	}
	for _, tc := range badTargets() {
		t.Run(tc.name, func(t *testing.T) {
			cfg := demoConfig()
			cfg.TemporalAddress, cfg.Namespace = tc.addr, tc.ns
			opts, err := clientOptions(cfg)
			if !errors.Is(err, ErrConfig) {
				t.Errorf("clientOptions(%q, %q) = %v, want ErrConfig", tc.addr, tc.ns, err)
			}
			if !reflect.ValueOf(opts).IsZero() {
				t.Errorf("clientOptions returned %+v with its error, want zero options", opts)
			}
			bad := tc.addr
			if bad == demoAddress {
				bad = tc.ns
			}
			if err != nil && bad != "" && strings.Contains(err.Error(), bad) {
				t.Errorf("error %q quotes the refused value %q", err, bad)
			}
		})
	}
}

// TestRunRefusesNonLoopback (bh, D10): run checks the address and namespace
// before any input or output, even when LoadConfig is bypassed. The working
// directory holds no script: an error other than ErrConfig means the check
// came after reading it, or never.
func TestRunRefusesNonLoopback(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, tc := range badTargets() {
		t.Run(tc.name, func(t *testing.T) {
			cfg := demoConfig()
			cfg.TemporalAddress, cfg.Namespace = tc.addr, tc.ns
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			var stdout bytes.Buffer
			if err := run(ctx, cfg, &stdout); !errors.Is(err, ErrConfig) {
				t.Errorf("run(%q, %q) = %v, want ErrConfig before any file or network access", tc.addr, tc.ns, err)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
		})
	}
	t.Run("bad_namespace_no_connection", func(t *testing.T) {
		addr, conns := countingListener(t)
		cfg := demoConfig()
		cfg.TemporalAddress, cfg.Namespace = addr, "Rempart"
		if err := run(t.Context(), cfg, &bytes.Buffer{}); !errors.Is(err, ErrConfig) {
			t.Errorf("run = %v, want ErrConfig", err)
		}
		time.Sleep(50 * time.Millisecond) // let a late accept be counted
		if n := conns.Load(); n != 0 {
			t.Errorf("%d connections, want 0", n)
		}
	})
}

// TestRunDialFailureOpaque (bh, D10, risk R4): a Temporal server that cannot
// be reached gives exactly ErrTemporalUnavailable, whose message quotes
// neither the address nor the cause, within the caller's context.
func TestRunDialFailureOpaque(t *testing.T) {
	t.Chdir("../..")
	const want = "rempart-worker: Temporal unavailable"
	check := func(t *testing.T, ctx context.Context, addr string, limit time.Duration) {
		t.Helper()
		cfg := demoConfig()
		cfg.TemporalAddress = addr
		var stdout bytes.Buffer
		start := time.Now()
		err := run(ctx, cfg, &stdout)
		if d := time.Since(start); d > limit {
			t.Errorf("run returned after %v, want less than %v", d, limit)
		}
		// Exactly the sentinel: it matches, and wraps no cause.
		if !errors.Is(err, ErrTemporalUnavailable) || errors.Unwrap(err) != nil {
			t.Errorf("run = %v (%T), want exactly ErrTemporalUnavailable", err, err)
		}
		if err == nil {
			return
		}
		_, port, _ := net.SplitHostPort(addr)
		if err.Error() != want || strings.Contains(err.Error(), port) {
			t.Errorf("message %q, want exactly %q", err, want)
		}
		if stdout.Len() != 0 {
			t.Errorf("stdout = %q, want empty", stdout.String())
		}
	}
	t.Run("closed_connections", func(t *testing.T) {
		addr, _ := countingListener(t)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		check(t, ctx, addr, 10*time.Second)
	})
	t.Run("canceled_context", func(t *testing.T) {
		addr, _ := countingListener(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		check(t, ctx, addr, 2*time.Second)
	})
}

// TestRealMainDialFailure (criterion 14): the command reports the fixed
// message on one stderr line and exits with 1.
func TestRealMainDialFailure(t *testing.T) {
	t.Chdir("../..")
	addr, _ := countingListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var stdout, stderr bytes.Buffer
	code := realMain(ctx, withFlag("temporal-address", "-temporal-address="+addr), &stdout, &stderr)
	if code != 1 || stderr.String() != "rempart-worker: rempart-worker: Temporal unavailable\n" || stdout.Len() != 0 {
		t.Errorf("realMain = %d, stderr %q, stdout %q; want 1, the fixed message, nothing", code, stderr.String(), stdout.String())
	}
}

// TestRunDialsWithContext (bh, D10): the client is dialed once, with the
// context of run; no call ignores it (Dial, NewClient) or defers the
// connection (NewLazyClient). Static check: the timing of TestRunDialFailureOpaque
// alone cannot tell Dial from DialContext (risk R4).
func TestRunDialsWithContext(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	dials := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		pkgName := ""
		for _, is := range f.Imports {
			if p, _ := strconv.Unquote(is.Path.Value); p == "go.temporal.io/sdk/client" {
				pkgName = "client"
				if is.Name != nil {
					pkgName = is.Name.Name
				}
			}
		}
		if pkgName == "" {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			for _, fn := range []string{"Dial", "NewClient", "NewLazyClient"} {
				if e, ok := n.(ast.Expr); ok && isSelector(e, pkgName, fn) {
					t.Errorf("%s: %s.%s", fset.Position(n.Pos()), pkgName, fn)
				}
			}
			return true
		})
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isSelector(call.Fun, pkgName, "DialContext") {
				return true
			}
			dials++
			if name != "run.go" {
				t.Errorf("%s: DialContext outside run.go", fset.Position(call.Pos()))
			}
			if len(call.Args) != 2 {
				t.Errorf("%s: DialContext with %d arguments", fset.Position(call.Pos()), len(call.Args))
			} else if id, isID := call.Args[0].(*ast.Ident); !isID || id.Name != "ctx" {
				t.Errorf("%s: DialContext first argument is not ctx", fset.Position(call.Pos()))
			}
			return true
		})
	}
	if dials != 1 {
		t.Errorf("%d calls to client.DialContext, want exactly 1", dials)
	}
}

// isSelector reports whether e is pkg.name.
func isSelector(e ast.Expr, pkg, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg
}
