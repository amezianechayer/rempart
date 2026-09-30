package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	maxGitOutput = 1 << 20
	maxPaths     = 10_000
	gitTimeout   = 30 * time.Second
	gitWaitDelay = 5 * time.Second
)

// gitRunner runs git with args in dir: standard output (bounded), exit code.
type gitRunner func(ctx context.Context, dir string, args ...string) (stdout []byte, code int, err error)

// gitCmd builds, without running it, the only command the binary executes (D14).
func gitCmd(ctx context.Context, dir, path string, args []string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, path, args...) //nolint:gosec // G204: fixed argument forms (D14), base checked by validRef (D13), no shell.
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "LC_ALL=C",
	}
	cmd.WaitDelay = gitWaitDelay
	return cmd
}

// boundedBuffer keeps at most limit+1 bytes: more means truncated.
type boundedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if room := b.limit + 1 - b.buf.Len(); room > 0 {
		b.buf.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

// execGit is the real gitRunner: 30 s, standard error discarded.
func execGit(ctx context.Context, dir string, args ...string) ([]byte, int, error) {
	path, err := exec.LookPath("git")
	if err != nil {
		return nil, -1, err
	}
	ctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()
	out := &boundedBuffer{limit: maxGitOutput}
	cmd := gitCmd(ctx, dir, path, args)
	cmd.Stdout = out
	err = cmd.Run()
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		return out.buf.Bytes(), exit.ExitCode(), nil
	case err != nil:
		return nil, -1, err
	}
	return out.buf.Bytes(), 0, nil
}

// validRef: D13, a full lowercase hexadecimal object name, not all zeros.
func validRef(s string) bool {
	return (len(s) == 40 || len(s) == 64) && strings.Trim(s, "0123456789abcdef") == "" && strings.Trim(s, "0") != ""
}

// The three command forms of D14: the base only after --end-of-options.
func mergeBaseArgs(base string) []string {
	return []string{"-c", "core.fsmonitor=false", "--no-pager", "merge-base", "--is-ancestor", "--end-of-options", base, "HEAD"}
}

func diffArgs(base string) []string {
	return []string{"-c", "core.fsmonitor=false", "--no-pager", "diff", "--no-renames", "--no-ext-diff", "--no-textconv", "--name-only", "-z", "--end-of-options", base, "--"}
}

func untrackedArgs() []string {
	return []string{"-c", "core.fsmonitor=false", "--no-pager", "ls-files", "--others", "--exclude-standard", "-z"}
}

// changedPaths returns the changed and untracked paths since base, or
// ok == false with a fallback reason: every suite is then selected.
func changedPaths(ctx context.Context, git gitRunner, dir, base string) (paths []string, reason string, ok bool) {
	switch {
	case base == "":
		return nil, "base_absent", false
	case (len(base) == 40 || len(base) == 64) && strings.Trim(base, "0") == "":
		return nil, "base_null", false
	case !validRef(base):
		return nil, "base_invalid", false
	}
	_, code, err := git(ctx, dir, mergeBaseArgs(base)...)
	switch {
	case err != nil || (code != 0 && code != 1):
		return nil, "git_failed", false
	case code == 1:
		return nil, "base_not_ancestor", false
	}
	for _, a := range [][]string{diffArgs(base), untrackedArgs()} {
		out, code, err := git(ctx, dir, a...)
		switch {
		case err != nil || code != 0:
			return nil, "git_failed", false
		case len(out) > maxGitOutput:
			return nil, "diff_too_large", false
		}
		for p := range strings.SplitSeq(string(out), "\x00") {
			if p != "" {
				paths = append(paths, p)
			}
		}
	}
	if len(paths) > maxPaths {
		return nil, "diff_too_large", false
	}
	return paths, "", true
}
