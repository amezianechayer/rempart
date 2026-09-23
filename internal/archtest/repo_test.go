package archtest

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// modulePath is the only module these tests accept as the repository under test.
const modulePath = "github.com/amezianechayer/rempart"

// repoRoot walks up from the working directory (the package directory during
// go test) to the first directory holding a go.mod file, checks that its module
// line is modulePath and returns that directory with a read-only fs.FS rooted
// there. Every read in these tests goes through fs.ReadFile, fs.Stat or
// fs.ReadDir on the returned file system, with slash-separated relative paths.
func repoRoot(t *testing.T) (dir string, fsys fs.FS) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("cannot read the working directory: %v", err)
	}
	dir = wd
	for {
		fsys = os.DirFS(dir)
		data, readErr := fs.ReadFile(fsys, "go.mod")
		switch {
		case readErr == nil:
			got := moduleDirective(string(data))
			if got != modulePath {
				t.Fatalf("%s: module is %q, want %q (not the Rempart repository)",
					filepath.Join(dir, "go.mod"), got, modulePath)
			}
			return dir, fsys
		case !errors.Is(readErr, fs.ErrNotExist):
			t.Fatalf("%s: %v", filepath.Join(dir, "go.mod"), readErr)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod found in %s or any parent directory", wd)
		}
		dir = parent
	}
}

// moduleDirective returns the path of the first single-line module directive
// of a go.mod file, or "" if there is none. Comments are ignored and a quoted
// path is unquoted.
func moduleDirective(src string) string {
	for _, raw := range strings.Split(src, "\n") {
		line := raw
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "module" {
			continue
		}
		if unquoted, err := strconv.Unquote(fields[1]); err == nil {
			return unquoted
		}
		return fields[1]
	}
	return ""
}

// readRepoFile reads a file of the repository. A missing file yields an error
// that names the file and says it does not exist; hint tells who creates it.
func readRepoFile(fsys fs.FS, name, hint string) (string, error) {
	data, err := fs.ReadFile(fsys, name)
	if errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("%s: file does not exist at repository root (%s)", name, hint)
	}
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	return string(data), nil
}

// problemList accumulates readable problems, each naming the faulty element.
type problemList []string

func (p *problemList) addf(format string, args ...any) {
	*p = append(*p, fmt.Sprintf(format, args...))
}

// reportProblems fails the test once per problem, each message naming the
// faulty element.
func reportProblems(t *testing.T, problems []string) {
	t.Helper()
	for _, p := range problems {
		t.Error(p)
	}
}

// expectProblems checks a negative control. With no wanted substring, the
// checked input must be conforming (no problem at all). Otherwise at least one
// problem must be reported and every wanted substring must appear in at least
// one problem, which proves the check that fired is the one under test.
func expectProblems(t *testing.T, problems, want []string) {
	t.Helper()
	if len(want) == 0 {
		for _, p := range problems {
			t.Errorf("conforming input reported a problem: %s", p)
		}
		return
	}
	if len(problems) == 0 {
		t.Fatalf("no problem reported, want problems mentioning %q", want)
	}
	for _, w := range want {
		found := slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, w) })
		if !found {
			t.Errorf("no problem mentions %q; problems:\n%s", w, strings.Join(problems, "\n"))
		}
	}
}

// expectError checks that a parser rejected its input with an error mentioning want.
func expectError(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("parser accepted the input, want an error mentioning %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not mention %q", err.Error(), want)
	}
}

// mustReplace replaces the single occurrence of old in src. A negative control
// whose mutation does not apply would silently test the conforming input, so a
// missing or repeated occurrence stops the test.
func mustReplace(t *testing.T, src, old, replacement string) string {
	t.Helper()
	if n := strings.Count(src, old); n != 1 {
		t.Fatalf("mutation target %q occurs %d times, want exactly 1", old, n)
	}
	return strings.Replace(src, old, replacement, 1)
}
