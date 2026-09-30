package main

// Selection changed (D13 to D17), git command shape (D14), plan section 8.2.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// d14Args are the three argument lists of D14 for base.
func d14Args(base string) [][]string {
	return [][]string{
		{"-c", "core.fsmonitor=false", "--no-pager", "merge-base", "--is-ancestor", "--end-of-options", base, "HEAD"},
		{"-c", "core.fsmonitor=false", "--no-pager", "diff", "--no-renames", "--no-ext-diff", "--no-textconv", "--name-only", "-z", "--end-of-options", base, "--"},
		{"-c", "core.fsmonitor=false", "--no-pager", "ls-files", "--others", "--exclude-standard", "-z"},
	}
}

func nul(paths ...string) []byte {
	if len(paths) == 0 {
		return nil
	}
	return []byte(strings.Join(paths, "\x00") + "\x00")
}

func repeatPath(p string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = p
	}
	return out
}

// exactOutput returns NUL-terminated paths under docs/ totalling exactly n bytes
// (n > 216): paths of 108 bytes, the last two sized to fit.
func exactOutput(n int) []byte {
	var b bytes.Buffer
	path := func(size int) { b.WriteString("docs/" + strings.Repeat("a", size-9) + ".md\x00") }
	for n-b.Len() > 216 {
		path(108)
	}
	rest := n - b.Len()
	path(rest / 2)
	path(rest - rest/2)
	return b.Bytes()
}

func TestSuiteChangedSelection(t *testing.T) {
	both := []string{"demo", "other"}
	big := exactOutput(1 << 20)
	if len(big) != 1<<20 || bytes.Count(big, []byte{0}) > maxPathsForTest {
		t.Fatalf("exactOutput: %d bytes, %d paths", len(big), bytes.Count(big, []byte{0}))
	}
	for name, c := range map[string]struct {
		git      *fakeGit
		want     []string
		fallback string
	}{
		"suite_dir":          {&fakeGit{diff: nul("evals/other/cases/other-stub-001.yaml")}, []string{"other"}, ""},
		"watched":            {&fakeGit{diff: nul("internal/loops/x.go")}, []string{"demo"}, ""},
		"unrelated":          {&fakeGit{diff: nul("docs/x.md")}, []string{}, ""},
		"nothing":            {&fakeGit{}, []string{}, ""},
		"core":               {&fakeGit{diff: nul("go.sum")}, both, ""},
		"runner_changed":     {&fakeGit{diff: nul("cmd/rempart-evals/run.go")}, both, ""},
		"untracked_only":     {&fakeGit{others: nul("evals/other/notes.md")}, []string{"other"}, ""},
		"diff_and_untracked": {&fakeGit{diff: nul("docs/x.md", "internal/loops/y.go"), others: nul("cmd/other/z.go")}, both, ""},
		"invalid_path":       {&fakeGit{diff: nul("../x")}, both, ""},
		"newline_path":       {&fakeGit{diff: nul("docs/a\nevals/other/x")}, both, ""},
		"exactly_1_mib":      {&fakeGit{diff: big}, []string{}, ""},
		"exactly_10000":      {&fakeGit{diff: nul(repeatPath("docs/x.md", 10_000)...)}, []string{}, ""},
		// Fail closed (T61, obligation (bs)): any doubt selects every suite.
		"output_1_mib_plus_1":  {&fakeGit{diff: append(bytes.Repeat([]byte("a"), 1<<20), 0)}, both, "diff_too_large"},
		"untracked_too_large":  {&fakeGit{others: append(bytes.Repeat([]byte("a"), 1<<20), 0)}, both, "diff_too_large"},
		"10001_paths":          {&fakeGit{diff: nul(repeatPath("docs/x.md", 10_001)...)}, both, "diff_too_large"},
		"10001_paths_split":    {&fakeGit{diff: nul(repeatPath("docs/x.md", 5_000)...), others: nul(repeatPath("docs/y.md", 5_001)...)}, both, "diff_too_large"},
		"not_ancestor":         {&fakeGit{mergeCode: 1}, both, "base_not_ancestor"},
		"merge_base_failed":    {&fakeGit{mergeCode: 128}, both, "git_failed"},
		"merge_base_error":     {&fakeGit{mergeErr: errors.New("no git")}, both, "git_failed"},
		"diff_failed":          {&fakeGit{diffCode: 128, diff: nul("docs/x.md")}, both, "git_failed"},
		"ls_files_failed":      {&fakeGit{lsCode: 1}, both, "git_failed"},
		"merge_base_code_2":    {&fakeGit{mergeCode: 2}, both, "git_failed"},
		"merge_base_code_neg1": {&fakeGit{mergeCode: -1}, both, "git_failed"},
	} {
		g := c.git
		e := newEnv(t, copyFixture(t, "select"), g.run)
		code, stdout, stderr := runArgs(t, e, "--suite", "changed", "--base", aSHA)
		if code != 0 {
			t.Errorf("%s: code %d, want 0\n%s", name, code, stderr)
			continue
		}
		var s selection
		oneDocument(t, stdout, &s)
		if s.Selection.Mode != "changed" || s.Selection.Fallback != c.fallback || !slices.Equal(s.names(), c.want) || s.Suites == nil {
			t.Errorf("%s: %+v, want %q, fallback %q", name, s, c.want, c.fallback)
		}
		for _, x := range s.Suites {
			if x.Code != 0 || x.Report == nil || x.Report.Model != "stub-v1" {
				t.Errorf("%s: suite %+v", name, x)
			}
		}
		// Every command runs in the repository root, the base right after --end-of-options.
		for _, call := range g.calls {
			i := slices.Index(call.args, aSHA)
			if call.dir != e.repo.Name() || (i >= 0 && (i == 0 || call.args[i-1] != "--end-of-options")) {
				t.Errorf("%s: call %+v", name, call)
			}
		}
	}
	// Local changes: the diff runs against the working tree (O2), untracked files included.
	t.Run("real_repo", func(t *testing.T) {
		if _, err := exec.LookPath("git"); err != nil {
			t.Fatalf("git is required by this test (R2): %v", err)
		}
		dir := t.TempDir()
		git := func(args ...string) string {
			t.Helper()
			//nolint:gosec // G204: test helper, the name is "git" and the args are literals of this test or object names it read.
			cmd := exec.CommandContext(t.Context(), "git", args...)
			cmd.Dir = dir
			cmd.Env = []string{
				"PATH=" + os.Getenv("PATH"), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
				"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid",
			}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("git %q: %v\n%s", args, err, out)
			}
			return strings.TrimSpace(string(out))
		}
		if err := os.CopyFS(dir, os.DirFS("testdata/ok")); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, "go.mod", fixtureGoMod)
		if err := os.CopyFS(filepath.Join(dir, "evals/other"), os.DirFS("testdata/ok/evals/demo")); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, "evals/other/suite.yaml", "name: other\nloop: L0-demo\ntarget: demo\n")
		writeFile(t, dir, "evals/other/old.md", "old notes of the other suite\n")
		writeFile(t, dir, "internal/loops/x.go", "package loops\n")
		writeFile(t, dir, "docs/x.md", "docs\n")
		git("init", "-q", "-b", "main")
		git("add", "-A")
		git("commit", "-q", "-m", "base")
		base := git("rev-parse", "HEAD")
		t.Chdir(dir)
		changed := func(step, ref string, want []string, fallback string) {
			t.Helper()
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), []string{"--suite", "changed", "--base", ref}, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("%s: code %d, want 0\n%s", step, code, stderr.String())
			}
			var s selection
			oneDocument(t, stdout.String(), &s)
			if !slices.Equal(s.names(), want) || s.Selection.Fallback != fallback {
				t.Errorf("%s: %q, fallback %q; want %q, %q", step, s.names(), s.Selection.Fallback, want, fallback)
			}
		}
		changed("clean", base, []string{}, "")
		writeFile(t, dir, "evals/other/notes.md", "untracked\n")
		changed("untracked", base, []string{"other"}, "")
		if err := os.Remove(filepath.Join(dir, "evals/other/notes.md")); err != nil {
			t.Fatal(err)
		}
		// --no-renames: the old path of a moved file is a change too.
		git("mv", "evals/other/old.md", "docs/moved.md")
		changed("rename", base, []string{"other"}, "")
		git("mv", "docs/moved.md", "evals/other/old.md")
		changed("rename_back", base, []string{}, "")
		writeFile(t, dir, "internal/loops/x.go", "package loops\n\nconst X = 1\n")
		changed("modified", base, []string{"demo"}, "")
		git("commit", "-q", "-am", "second")
		changed("committed", base, []string{"demo"}, "")
		changed("head", git("rev-parse", "HEAD"), []string{}, "")
		orphan := git("commit-tree", "-m", "probe", "HEAD^{tree}")
		changed("not_ancestor", orphan, []string{"demo", "other"}, "base_not_ancestor")
		changed("unknown_object", strings.Repeat("1", 40), []string{"demo", "other"}, "git_failed")
		changed("symbolic", "main", []string{"demo", "other"}, "base_invalid")
		changed("absent", "", []string{"demo", "other"}, "base_absent")
	})
}

// maxPathsForTest is the path bound of D14.
const maxPathsForTest = 10_000

func TestRejectsUnsafeGitRef(t *testing.T) {
	hex40 := "0123456789abcdef0123456789abcdef01234567"
	for _, c := range []struct{ ref, fallback string }{
		{"--output=x", "base_invalid"},
		{"--output=/tmp/rempart-evals-x", "base_invalid"},
		{"a;b", "base_invalid"},
		{"$(touch x)", "base_invalid"},
		{"HEAD", "base_invalid"},
		{"HEAD~1", "base_invalid"},
		{"main", "base_invalid"},
		{"origin/main", "base_invalid"},
		{strings.Repeat("0", 40), "base_null"},
		{strings.Repeat("0", 64), "base_null"},
		{hex40[:39], "base_invalid"},
		{hex40 + "8", "base_invalid"},
		{strings.ToUpper(hex40), "base_invalid"},
		{hex40 + "\n", "base_invalid"},
		{" " + hex40, "base_invalid"},
		{"-" + hex40[:39], "base_invalid"},
		{hex40[:39] + "g", "base_invalid"},
		{strings.Repeat("a", 63), "base_invalid"},
		{strings.Repeat("a", 65), "base_invalid"},
		{strings.Repeat("0", 39), "base_invalid"},
		{"", "base_absent"},
	} {
		for _, args := range [][]string{
			{"--suite", "changed", "--base", c.ref},
			{"--suite", "changed", "--base=" + c.ref},
		} {
			g := &fakeGit{}
			code, stdout, stderr := runArgs(t, newEnv(t, copyFixture(t, "select"), g.run), args...)
			if code != 0 {
				t.Errorf("%q: code %d\n%s", c.ref, code, stderr)
				continue
			}
			var s selection
			oneDocument(t, stdout, &s)
			if len(g.calls) != 0 || s.Selection.Fallback != c.fallback || !slices.Equal(s.names(), []string{"demo", "other"}) {
				t.Errorf("%q: %d git calls, %+v; want none, %s, every suite", c.ref, len(g.calls), s, c.fallback)
			}
		}
		if paths, reason, ok := changedPaths(context.Background(), (&fakeGit{}).run, "/r", c.ref); ok || reason != c.fallback || paths != nil {
			t.Errorf("changedPaths %q: %q, %q, %t", c.ref, paths, reason, ok)
		}
	}
	for _, p := range []string{"x", "testdata/select/x", "/tmp/rempart-evals-x"} {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("%s created", p)
		}
	}
	for _, ok := range []string{hex40, strings.Repeat("f", 64), "0000000000000000000000000000000000000001", strings.Repeat("0", 63) + "a"} {
		if !validRef(ok) {
			t.Errorf("validRef(%q) = false", ok)
		}
	}
	for _, bad := range []string{"", strings.Repeat("0", 40), strings.Repeat("0", 64), strings.ToUpper(hex40), hex40[:39], hex40 + "0", "HEAD", "--output=x"} {
		if validRef(bad) {
			t.Errorf("validRef(%q) = true", bad)
		}
	}

	// D12: --base only with changed, and required there.
	for _, args := range [][]string{{"--suite", "demo", "--base", aSHA}, {"--suite", "all", "--base", aSHA}, {"--suite", "changed"}} {
		g := &fakeGit{}
		if code, stdout, _ := runArgs(t, newEnv(t, copyFixture(t, "select"), g.run), args...); code != 2 || stdout != "" || len(g.calls) != 0 {
			t.Errorf("%q: code %d, stdout %q, %d git calls; want 2", args, code, stdout, len(g.calls))
		}
	}

	// D14 (T8, T84): the three command forms, the base after --end-of-options,
	// no shell, an environment reduced to a whitelist.
	base := strings.Repeat("c0ffee", 6) + "abcd"
	g := &fakeGit{diff: nul("docs/x.md"), others: nul("docs/y.md")}
	paths, reason, ok := changedPaths(context.Background(), g.run, "/repo/root", base)
	if !ok || reason != "" || !slices.Equal(paths, []string{"docs/x.md", "docs/y.md"}) {
		t.Fatalf("changedPaths: %q, %q, %t", paths, reason, ok)
	}
	want := d14Args(base)
	if len(g.calls) != len(want) {
		t.Fatalf("%d git calls, want %d: %+v", len(g.calls), len(want), g.calls)
	}
	for i, call := range g.calls {
		if call.dir != "/repo/root" || !slices.Equal(call.args, want[i]) {
			t.Errorf("call %d: %+v, want %q in /repo/root", i, call, want[i])
		}
	}
	if !slices.Contains(g.calls[1].args, "--no-renames") {
		t.Error("diff without --no-renames")
	}

	// T84: nothing of the environment reaches git but PATH.
	t.Setenv("PATH", "/usr/local/bin:/usr/bin:/bin")
	for _, k := range []string{"GIT_DIR", "GIT_WORK_TREE", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_PARAMETERS", "GIT_EXTERNAL_DIFF", "GIT_EXEC_PATH", "GIT_PAGER", "LD_PRELOAD", "HOME"} {
		t.Setenv(k, "/tmp/evil")
	}
	wantEnv := []string{
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_OPTIONAL_LOCKS=0", "GIT_TERMINAL_PROMPT=0", "LC_ALL=C",
		"PATH=/usr/local/bin:/usr/bin:/bin",
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, args := range want {
		cmd := gitCmd(ctx, "/repo/root", "/usr/bin/git", args)
		env := slices.Clone(cmd.Env)
		slices.Sort(env)
		if cmd.Path != "/usr/bin/git" || filepath.Base(cmd.Args[0]) != "git" || !slices.Equal(cmd.Args[1:], args) {
			t.Errorf("command %q %q, want git %q", cmd.Path, cmd.Args, args)
		}
		if !slices.Equal(env, wantEnv) {
			t.Errorf("env %q, want exactly %q", cmd.Env, wantEnv)
		}
		if cmd.Dir != "/repo/root" || cmd.WaitDelay != 5*time.Second || cmd.Cancel == nil || cmd.Stdin != nil || cmd.Process != nil {
			t.Errorf("dir %q, wait delay %v, cancel set %t, stdin %v, started %t", cmd.Dir, cmd.WaitDelay, cmd.Cancel != nil, cmd.Stdin, cmd.Process != nil)
		}
	}
}
