package toolexec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeTool writes an executable shell script under a fresh directory and
// returns the Tool that names it with its exact SHA-256.
func fakeTool(t *testing.T, body string) Tool {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-tool")
	src := []byte("#!/bin/sh\n" + body + "\n")
	if err := os.WriteFile(path, src, 0o700); err != nil { //nolint:gosec // G306: the fake tool must be executable by its owner.
		t.Fatal(err)
	}
	sum := sha256.Sum256(src)
	return Tool{Name: "fake", Version: "1.0.0", Path: path, SHA256: hex.EncodeToString(sum[:])}
}

func spec(t *testing.T, tool Tool, args ...string) Spec {
	t.Helper()
	return Spec{Tool: tool, Args: args, Dir: t.TempDir(), Timeout: 10 * time.Second, MaxStdout: 1 << 20, MaxStderr: 1 << 20}
}

// TestToolexecNoShell proves T8 (D6): the arguments reach the tool as they
// are, one by one, never through a shell: no separator, substitution, glob or
// quote is interpreted, and nothing is run on the side.
func TestToolexecNoShell(t *testing.T) {
	tool := fakeTool(t, `for a in "$@"; do printf '%s\n' "$a"; done`)
	s := spec(t, tool, "a;b", "$(touch PWNED)", "`touch PWNED2`", `"quoted"`, "two words", "*", "x && touch PWNED3")
	res, err := Run(context.Background(), s)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("Run = %+v, %v", res, err)
	}
	got := strings.Split(strings.TrimSuffix(string(res.Stdout), "\n"), "\n")
	if !slices.Equal(got, s.Args) {
		t.Fatalf("arguments seen by the tool = %q, want %q", got, s.Args)
	}
	for _, f := range []string{"PWNED", "PWNED2", "PWNED3"} {
		if _, err := os.Stat(filepath.Join(s.Dir, f)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s exists in the working directory: a shell interpreted an argument", f)
		}
	}
	t.Run("exit_code", func(t *testing.T) {
		res, err := Run(context.Background(), spec(t, fakeTool(t, "exit 3")))
		if err != nil || res.ExitCode != 3 {
			t.Fatalf("Run = %+v, %v; want exit code 3 and no error", res, err)
		}
	})
	t.Run("nul_in_argument", func(t *testing.T) {
		if _, err := Run(context.Background(), spec(t, tool, "a\x00b")); !errors.Is(err, ErrSpec) {
			t.Fatalf("Run with a NUL byte = %v, want ErrSpec", err)
		}
	})
}

// TestToolexecEnvBuilt proves T8 and T142 (D6): the environment of the tool
// is built, never inherited: a canary of the parent and any AWS_*, ARM_*,
// TF_*, KUBECONFIG or proxy variable of the parent are invisible; the proxies
// point to an unreachable local address; HOME and TMPDIR are fresh private
// directories removed after the run; the entries of Spec.Env reach the tool,
// and an entry that would override a forced variable is refused.
func TestToolexecEnvBuilt(t *testing.T) {
	for k, v := range map[string]string{
		"REMPART_CANARY": "canary-7c1f", "AWS_SECRET_ACCESS_KEY": "canary-aws", "ARM_CLIENT_SECRET": "canary-arm",
		"TF_LOG": "TRACE", "TF_CLI_CONFIG_FILE": "/inherited.tfrc", "KUBECONFIG": "/inherited/kubeconfig",
		"HTTPS_PROXY": "http://inherited:3128", "https_proxy": "http://inherited:3128", "NO_PROXY": "*",
		"GOOGLE_APPLICATION_CREDENTIALS": "/inherited/key.json",
	} {
		t.Setenv(k, v)
	}
	tool := fakeTool(t, `env; printf 'home=%s\n' "$HOME"; test -d "$HOME" && test -w "$HOME" && printf 'home_ok\n'; test -d "$TMPDIR" && printf 'tmp_ok\n'`)
	s := spec(t, tool)
	s.Env = []string{"TF_CLI_CONFIG_FILE=/rempart/mirror.tfrc", "CHECKPOINT_DISABLE=1"}
	res, err := Run(context.Background(), s)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("Run = %+v, %v", res, err)
	}
	out := string(res.Stdout)
	for _, leaked := range []string{"canary-7c1f", "canary-aws", "canary-arm", "TF_LOG", "/inherited", "GOOGLE_APPLICATION_CREDENTIALS", "inherited:3128"} {
		if strings.Contains(out, leaked) {
			t.Errorf("inherited value %q visible to the tool:\n%s", leaked, out)
		}
	}
	vars := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			vars[k] = v
		}
	}
	for _, k := range []string{"HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"} {
		if vars[k] != UnreachableProxy {
			t.Errorf("%s = %q, want %q", k, vars[k], UnreachableProxy)
		}
	}
	if v, set := vars["NO_PROXY"]; !set || v != "" {
		t.Errorf("NO_PROXY = %q (set %v), want set and empty", v, set)
	}
	if vars["TF_CLI_CONFIG_FILE"] != "/rempart/mirror.tfrc" || vars["CHECKPOINT_DISABLE"] != "1" {
		t.Errorf("Spec.Env not passed: TF_CLI_CONFIG_FILE=%q CHECKPOINT_DISABLE=%q", vars["TF_CLI_CONFIG_FILE"], vars["CHECKPOINT_DISABLE"])
	}
	home := vars["home"]
	if !strings.Contains(out, "home_ok") || !strings.Contains(out, "tmp_ok") || home == "" || home == os.Getenv("HOME") || vars["TMPDIR"] == home {
		t.Errorf("HOME %q and TMPDIR %q: want two fresh private directories", home, vars["TMPDIR"])
	}
	for _, d := range []string{home, vars["TMPDIR"]} {
		if _, err := os.Stat(d); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("ephemeral directory %q still exists after the run", d)
		}
	}
	for _, forced := range []string{"HOME=/tmp", "TMPDIR=/tmp", "PATH=/evil", "HTTPS_PROXY=http://x", "http_proxy=http://x", "NO_PROXY=*", "not an entry", "=x", "A=B\x00C"} {
		bad := spec(t, tool)
		bad.Env = []string{forced}
		if _, err := Run(context.Background(), bad); !errors.Is(err, ErrSpec) {
			t.Errorf("Spec.Env %q: Run = %v, want ErrSpec", forced, err)
		}
	}
}

// TestToolexecChecksum proves T6 and T143 (D15): the SHA-256 of the binary is
// checked right before it runs; a binary changed after the lock is refused
// and never runs, and so is a malformed hash or a path that is not an
// absolute path to a regular file.
func TestToolexecChecksum(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	tool := fakeTool(t, "touch "+marker)
	if err := os.WriteFile(tool.Path, []byte("#!/bin/sh\ntouch "+marker+"\necho tampered\n"), 0o700); err != nil { //nolint:gosec // G306: test fake.
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), spec(t, tool)); !errors.Is(err, ErrChecksum) {
		t.Fatalf("Run on a changed binary = %v, want ErrChecksum", err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the changed binary ran")
	}
	good := fakeTool(t, "exit 0")
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(good.Path, link); err != nil {
		t.Fatal(err)
	}
	for name, tl := range map[string]Tool{
		"short_hash":    {Name: "fake", Version: "1.0.0", Path: good.Path, SHA256: "abc"},
		"upper_hash":    {Name: "fake", Version: "1.0.0", Path: good.Path, SHA256: strings.ToUpper(good.SHA256)},
		"relative_path": {Name: "fake", Version: "1.0.0", Path: "fake-tool", SHA256: good.SHA256},
		"symlink":       {Name: "fake", Version: "1.0.0", Path: link, SHA256: good.SHA256},
		"directory":     {Name: "fake", Version: "1.0.0", Path: filepath.Dir(good.Path), SHA256: good.SHA256},
		"missing":       {Name: "fake", Version: "1.0.0", Path: filepath.Join(t.TempDir(), "absent"), SHA256: good.SHA256},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Run(context.Background(), spec(t, tl))
			if !errors.Is(err, ErrSpec) && !errors.Is(err, ErrChecksum) {
				t.Fatalf("Run = %v, want ErrSpec or ErrChecksum", err)
			}
		})
	}
	if res, err := Run(context.Background(), spec(t, good)); err != nil || res.ExitCode != 0 {
		t.Fatalf("Run on the locked binary = %+v, %v", res, err)
	}
}

// TestToolexecBounds proves T8 and T145 (D6): a run past its timeout returns
// ErrTimeout and its whole process group is killed (a child started in the
// background never writes its marker); an output past its bound is an error,
// never a truncated output returned as if complete.
func TestToolexecBounds(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "child-survived")
	tool := fakeTool(t, "(sleep 2; touch "+marker+") &\nsleep 30")
	s := spec(t, tool)
	s.Timeout = 300 * time.Millisecond
	start := time.Now()
	res, err := Run(context.Background(), s)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("Run = %+v, %v; want ErrTimeout", res, err)
	}
	if d := time.Since(start); d > 6*time.Second {
		t.Errorf("Run returned after %v, want close to the timeout", d)
	}
	time.Sleep(3 * time.Second)
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Error("a child of the tool survived the timeout: the process group was not killed")
	}

	for name, body := range map[string]string{
		"stdout": "head -c 2097152 /dev/zero",
		"stderr": "head -c 2097152 /dev/zero >&2",
	} {
		t.Run(name+"_too_large", func(t *testing.T) {
			res, err := Run(context.Background(), spec(t, fakeTool(t, body)))
			if !errors.Is(err, ErrOutputTooLarge) {
				t.Fatalf("Run = exit %d, %d stdout bytes, %v; want ErrOutputTooLarge", res.ExitCode, len(res.Stdout), err)
			}
			if len(res.Stdout) != 0 || len(res.Stderr) != 0 {
				t.Errorf("a partial output was returned: %d stdout bytes, %d stderr bytes", len(res.Stdout), len(res.Stderr))
			}
		})
	}
	t.Run("exactly_at_the_bound", func(t *testing.T) {
		res, err := Run(context.Background(), spec(t, fakeTool(t, "head -c 1048576 /dev/zero")))
		if err != nil || len(res.Stdout) != 1<<20 {
			t.Fatalf("Run = %d bytes, %v; want 1 MiB and no error", len(res.Stdout), err)
		}
	})
	t.Run("invalid_bounds", func(t *testing.T) {
		for _, mutate := range []func(*Spec){
			func(s *Spec) { s.Timeout = 0 },
			func(s *Spec) { s.MaxStdout = 0 },
			func(s *Spec) { s.MaxStderr = -1 },
			func(s *Spec) { s.Dir = "relative" },
		} {
			s := spec(t, fakeTool(t, "exit 0"))
			mutate(&s)
			if _, err := Run(context.Background(), s); !errors.Is(err, ErrSpec) {
				t.Errorf("Run = %v, want ErrSpec", err)
			}
		}
	})
}
