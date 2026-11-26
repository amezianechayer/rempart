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

// fakeTool writes a read-only shell script under a fresh private directory
// and returns the Tool that names it with its exact SHA-256. PATH is empty
// for the tool (obligation (hf)): a body names every external command by its
// absolute path.
func fakeTool(t *testing.T, body string) Tool {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-tool")
	src := []byte("#!/bin/sh\n" + body + "\n")
	if err := os.WriteFile(path, src, 0o500); err != nil { //nolint:gosec // G306: the fake tool must be executable by its owner, read-only.
		t.Fatal(err)
	}
	sum := sha256.Sum256(src)
	return Tool{Name: "fake", Version: "1.0.0", Path: path, SHA256: hex.EncodeToString(sum[:])}
}

func workspace(t *testing.T) *Workspace {
	t.Helper()
	ws, err := NewWorkspace()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ws.Close() })
	return ws
}

func spec(t *testing.T, tool Tool, args ...string) Spec {
	t.Helper()
	return Spec{Tool: tool, Args: args, Workspace: workspace(t), Timeout: 10 * time.Second, MaxStdout: 1 << 20, MaxStderr: 1 << 20}
}

// TestToolexecNoShell proves T8 (D6): the arguments reach the tool as they
// are, one by one, never through a shell: no separator, substitution, glob or
// quote is interpreted, and nothing is run on the side.
func TestToolexecNoShell(t *testing.T) {
	tool := fakeTool(t, `for a in "$@"; do printf '%s\n' "$a"; done`)
	s := spec(t, tool, "a;b", "$(/usr/bin/touch PWNED)", "`/usr/bin/touch PWNED2`", `"quoted"`, "two words", "*", "x && /usr/bin/touch PWNED3")
	res, err := Run(context.Background(), s)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("Run = %+v, %v", res, err)
	}
	got := strings.Split(strings.TrimSuffix(string(res.Stdout), "\n"), "\n")
	if !slices.Equal(got, s.Args) {
		t.Fatalf("arguments seen by the tool = %q, want %q", got, s.Args)
	}
	for _, f := range []string{"PWNED", "PWNED2", "PWNED3"} {
		if _, err := os.Stat(filepath.Join(s.Workspace.Dir(), f)); !errors.Is(err, os.ErrNotExist) {
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
	// Obligation (hi): a tool killed by a signal, outside a timeout or an
	// output bound, is an error, never an exit code of -1.
	t.Run("killed_by_a_signal", func(t *testing.T) {
		res, err := Run(context.Background(), spec(t, fakeTool(t, "kill -KILL $$")))
		if !errors.Is(err, ErrKilled) {
			t.Fatalf("Run = %+v, %v; want ErrKilled", res, err)
		}
	})
}

// TestToolexecEnvBuilt proves T8, T142 and T159 (D6, obligation (hf)): the
// environment of the tool is built, never inherited: a canary of the parent
// and any AWS_*, ARM_*, TF_*, KUBECONFIG or proxy variable of the parent are
// invisible; the proxies point to an unreachable local address; HOME and
// TMPDIR are fresh private directories removed after the run; PATH is an
// empty directory; TF_DATA_DIR is a directory of the workspace outside the
// tree, the same for every run of the workspace. Spec.Env admits only the
// names of the allow-list, the AWS keys only as FAKE values.
func TestToolexecEnvBuilt(t *testing.T) {
	for k, v := range map[string]string{
		"REMPART_CANARY": "canary-7c1f", "AWS_SECRET_ACCESS_KEY": "canary-aws", "ARM_CLIENT_SECRET": "canary-arm",
		"TF_LOG": "TRACE", "TF_CLI_CONFIG_FILE": "/inherited.tfrc", "KUBECONFIG": "/inherited/kubeconfig",
		"HTTPS_PROXY": "http://inherited:3128", "https_proxy": "http://inherited:3128", "NO_PROXY": "*",
		"GOOGLE_APPLICATION_CREDENTIALS": "/inherited/key.json", "TF_DATA_DIR": "/inherited/data",
	} {
		t.Setenv(k, v)
	}
	tool := fakeTool(t, `/usr/bin/env; printf 'home=%s\n' "$HOME"; test -d "$HOME" && test -w "$HOME" && printf 'home_ok\n'; test -d "$TMPDIR" && printf 'tmp_ok\n'`)
	s := spec(t, tool)
	s.Env = []string{
		"TF_CLI_CONFIG_FILE=/rempart/mirror.tfrc", "CHECKPOINT_DISABLE=1", "TF_IN_AUTOMATION=1",
		"TFLINT_PLUGIN_DIR=/rempart/plugins", "TF_VAR_region=eu-west-3",
		"AWS_ACCESS_KEY_ID=FAKE-OFFLINE-PLAN", "AWS_SECRET_ACCESS_KEY=FAKE-OFFLINE-PLAN",
	}
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
	for _, e := range s.Env {
		k, v, _ := strings.Cut(e, "=")
		if vars[k] != v {
			t.Errorf("Spec.Env %s not passed: %q", k, vars[k])
		}
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
	// PATH: one empty directory, nothing to find (obligation (hf)).
	if p := vars["PATH"]; !filepath.IsAbs(p) || strings.Contains(p, ":") {
		t.Errorf("PATH = %q, want one absolute empty directory", p)
	} else if entries, err := os.ReadDir(p); err != nil || len(entries) != 0 {
		t.Errorf("PATH %q: %v, %d entries; want an empty directory", p, err, len(entries))
	}
	// TF_DATA_DIR: in the workspace, outside the tree, stable across runs, so
	// that a .terraform/ of the tree is never read (obligation (hf), T159).
	data := vars["TF_DATA_DIR"]
	if !filepath.IsAbs(data) || data == s.Workspace.Dir() || strings.HasPrefix(data, s.Workspace.Dir()+string(filepath.Separator)) {
		t.Errorf("TF_DATA_DIR = %q, want a directory of the workspace outside the tree %q", data, s.Workspace.Dir())
	}
	again, err := Run(context.Background(), s)
	if err != nil || !strings.Contains(string(again.Stdout), "TF_DATA_DIR="+data+"\n") {
		t.Errorf("second run of the workspace: TF_DATA_DIR changed or run failed: %v", err)
	}

	for _, bad := range []string{
		"HOME=/tmp", "TMPDIR=/tmp", "PATH=/evil", "HTTPS_PROXY=http://x", "http_proxy=http://x", "NO_PROXY=*", "not an entry", "=x", "A=B\x00C",
		// Obligation (hf), T159: names outside the allow-list.
		"TF_DATA_DIR=/tree/.terraform", "TF_CLI_ARGS=-plugin-dir=/x", "TF_CLI_ARGS_init=-plugin-dir=/x", "TF_REATTACH_PROVIDERS={}",
		"TF_PLUGIN_CACHE_DIR=/x", "TF_LOG_PATH=/x", "TF_LOG=TRACE", "LD_PRELOAD=/x.so", "LD_LIBRARY_PATH=/x", "GODEBUG=x=1",
		"PYTHONPATH=/x", "KUBECONFIG=/x", "TRIVY_SERVER=http://x", "ARM_CLIENT_SECRET=x",
		// Values outside their form.
		"AWS_ACCESS_KEY_ID=not-a-fake", "AWS_SECRET_ACCESS_KEY=s3cr3t", "TF_CLI_CONFIG_FILE=relative.tfrc", "TFLINT_PLUGIN_DIR=plugins",
		"CHECKPOINT_DISABLE=0", "TF_IN_AUTOMATION=yes", "TF_VAR_Region=x", "TF_VAR_=x",
	} {
		s := spec(t, tool)
		s.Env = []string{bad}
		if _, err := Run(context.Background(), s); !errors.Is(err, ErrSpec) {
			t.Errorf("Spec.Env %q: Run = %v, want ErrSpec", bad, err)
		}
	}
}

// TestToolexecWorkspace proves obligation (hf) (D6, T159): the working
// directory of a tool is a workspace Rempart creates, private, holding only
// the files written through it (os.Root: no path out of the tree, no link
// followed out of it), removed by Close; a spec without a workspace, or with
// a closed one, is refused.
func TestToolexecWorkspace(t *testing.T) {
	ws := workspace(t)
	if !filepath.IsAbs(ws.Dir()) {
		t.Fatalf("Dir = %q, want absolute", ws.Dir())
	}
	if info, err := os.Stat(ws.Dir()); err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("Dir %q: %v, want a private directory", ws.Dir(), err)
	}
	if entries, err := os.ReadDir(ws.Dir()); err != nil || len(entries) != 0 {
		t.Fatalf("new workspace holds %d entries, %v; want none", len(entries), err)
	}
	for rel, data := range map[string]string{"main.tf": "a", "modules/net/main.tf": "b"} {
		if err := ws.WriteFile(rel, []byte(data)); err != nil {
			t.Fatalf("WriteFile(%q): %v", rel, err)
		}
		if b, err := os.ReadFile(filepath.Join(ws.Dir(), filepath.FromSlash(rel))); err != nil || string(b) != data {
			t.Errorf("%s: %q, %v", rel, b, err)
		}
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(ws.Dir(), "link")); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"", ".", "..", "../escape.tf", "/abs.tf", "a/../../escape.tf", "link/escape.tf", "main.tf\x00x"} {
		if err := ws.WriteFile(rel, []byte("x")); !errors.Is(err, ErrSpec) {
			t.Errorf("WriteFile(%q) = %v, want ErrSpec", rel, err)
		}
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Errorf("a write escaped the workspace into %s", outside)
	}
	if err := ws.WriteFile("main.tf", []byte("again")); !errors.Is(err, ErrSpec) {
		t.Errorf("WriteFile over an existing file = %v, want ErrSpec (each file of the tree is written once)", err)
	}

	tool := fakeTool(t, "exit 0")
	if _, err := Run(context.Background(), Spec{Tool: tool, Timeout: time.Second, MaxStdout: 1, MaxStderr: 1}); !errors.Is(err, ErrSpec) {
		t.Errorf("Run without a workspace = %v, want ErrSpec", err)
	}
	closed, err := NewWorkspace()
	if err != nil {
		t.Fatal(err)
	}
	dir := closed.Dir()
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("workspace %q still present after Close: %v", dir, err)
	}
	if _, err := Run(context.Background(), Spec{Tool: tool, Workspace: closed, Timeout: time.Second, MaxStdout: 1, MaxStderr: 1}); !errors.Is(err, ErrSpec) {
		t.Errorf("Run on a closed workspace = %v, want ErrSpec", err)
	}
	if err := closed.WriteFile("main.tf", []byte("x")); !errors.Is(err, ErrSpec) {
		t.Errorf("WriteFile on a closed workspace = %v, want ErrSpec", err)
	}
}

// TestToolexecChecksum proves T6 and T143 (D15): the SHA-256 of the binary is
// checked right before it runs; a binary changed after the lock is refused
// and never runs, and so is a malformed hash or a path that is not an
// absolute path to a regular file. Obligation (hi): the binary is read-only
// and owned by the user, its directory writable by no one else.
func TestToolexecChecksum(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	tool := fakeTool(t, "/usr/bin/touch "+marker)
	if err := os.Chmod(tool.Path, 0o700); err != nil { //nolint:gosec // G302: test fake, made writable to be changed.
		t.Fatal(err)
	}
	if err := os.WriteFile(tool.Path, []byte("#!/bin/sh\n/usr/bin/touch "+marker+"\necho tampered\n"), 0o500); err != nil { //nolint:gosec // G306: test fake.
		t.Fatal(err)
	}
	if err := os.Chmod(tool.Path, 0o500); err != nil { //nolint:gosec // G302: test fake, read-only again.
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
	// Obligation (hi): a binary a third party could change between the check
	// and the run is refused before it is hashed.
	t.Run("writable_binary", func(t *testing.T) {
		tl := fakeTool(t, "exit 0")
		if err := os.Chmod(tl.Path, 0o700); err != nil { //nolint:gosec // G302: test fake.
			t.Fatal(err)
		}
		if _, err := Run(context.Background(), spec(t, tl)); !errors.Is(err, ErrSpec) {
			t.Fatalf("Run on a writable binary = %v, want ErrSpec", err)
		}
	})
	t.Run("shared_directory", func(t *testing.T) {
		tl := fakeTool(t, "exit 0")
		if err := os.Chmod(filepath.Dir(tl.Path), 0o777); err != nil { //nolint:gosec // G302: test directory made writable by all on purpose.
			t.Fatal(err)
		}
		if _, err := Run(context.Background(), spec(t, tl)); !errors.Is(err, ErrSpec) {
			t.Fatalf("Run on a binary in a directory writable by others = %v, want ErrSpec", err)
		}
	})
	t.Run("other_owner", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("changing the owner of a file needs root")
		}
		tl := fakeTool(t, "exit 0")
		if err := os.Chown(tl.Path, 65534, 65534); err != nil {
			t.Fatal(err)
		}
		if _, err := Run(context.Background(), spec(t, tl)); !errors.Is(err, ErrSpec) {
			t.Fatalf("Run on a binary of another user = %v, want ErrSpec", err)
		}
	})
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
	tool := fakeTool(t, "(/usr/bin/sleep 2; /usr/bin/touch "+marker+") &\n/usr/bin/sleep 30")
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
		"stdout": "/usr/bin/head -c 2097152 /dev/zero",
		"stderr": "/usr/bin/head -c 2097152 /dev/zero >&2",
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
		res, err := Run(context.Background(), spec(t, fakeTool(t, "/usr/bin/head -c 1048576 /dev/zero")))
		if err != nil || len(res.Stdout) != 1<<20 {
			t.Fatalf("Run = %d bytes, %v; want 1 MiB and no error", len(res.Stdout), err)
		}
	})
	t.Run("invalid_bounds", func(t *testing.T) {
		for _, mutate := range []func(*Spec){
			func(s *Spec) { s.Timeout = 0 },
			func(s *Spec) { s.MaxStdout = 0 },
			func(s *Spec) { s.MaxStderr = -1 },
			func(s *Spec) { s.Workspace = nil },
		} {
			s := spec(t, fakeTool(t, "exit 0"))
			mutate(&s)
			if _, err := Run(context.Background(), s); !errors.Is(err, ErrSpec) {
				t.Errorf("Run = %v, want ErrSpec", err)
			}
		}
	})
}
