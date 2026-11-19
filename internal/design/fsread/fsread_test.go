package fsread_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/amezianechayer/rempart/internal/design/fsread"
)

// TestRegularRefusesFIFO proves obligation (cr) (ADR 0012 D6): a named pipe
// is refused at once, never opened in blocking mode; a directory, a missing
// file and a file over the bound are refused with the fixed error; a regular
// file at the bound is read whole, directly or under a root.
func TestRegularRefusesFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	ok := filepath.Join(dir, "ok.json")
	if err := os.WriteFile(ok, []byte(strings.Repeat("a", 16)), 0o600); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, []byte(strings.Repeat("a", 17)), 0o600); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := fsread.Regular(fifo, 16)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, fsread.ErrRead) {
			t.Fatalf("Regular(fifo) = %v, want ErrRead", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Regular(fifo) blocked: the pipe was opened in blocking mode")
	}

	for name, p := range map[string]string{"directory": dir, "missing": filepath.Join(dir, "missing.json"), "over_bound": big} {
		if _, err := fsread.Regular(p, 16); !errors.Is(err, fsread.ErrRead) {
			t.Errorf("Regular(%s) = %v, want ErrRead", name, err)
		}
	}
	if b, err := fsread.Regular(ok, 16); err != nil || len(b) != 16 {
		t.Errorf("Regular(regular file at the bound) = %d bytes, %v", len(b), err)
	}
	if _, err := fsread.Regular(ok, 0); !errors.Is(err, fsread.ErrRead) {
		t.Errorf("Regular(bound 0) = %v, want ErrRead", err)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if b, err := fsread.RegularIn(root, "ok.json", 16); err != nil || len(b) != 16 {
		t.Errorf("RegularIn(ok.json) = %d bytes, %v", len(b), err)
	}
	go func() {
		_, err := fsread.RegularIn(root, "pipe.json", 16)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, fsread.ErrRead) {
			t.Fatalf("RegularIn(fifo) = %v, want ErrRead", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RegularIn(fifo) blocked")
	}
	if err := os.Symlink(filepath.Join(os.TempDir(), "outside.json"), filepath.Join(dir, "escape.json")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../ok.json", "escape.json", "big.json", "."} {
		if _, err := fsread.RegularIn(root, name, 16); !errors.Is(err, fsread.ErrRead) {
			t.Errorf("RegularIn(%q) = %v, want ErrRead", name, err)
		}
	}
	if strings.Contains(fsread.ErrRead.Error(), dir) {
		t.Errorf("error quotes a path: %v", fsread.ErrRead)
	}
}
