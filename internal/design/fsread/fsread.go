// Package fsread reads a regular file named by a user, bounded and without
// blocking on a named pipe or a device (obligation (cr), ADR 0012 D6): the
// path is checked by Stat before it is opened, opened without blocking, then
// the descriptor is checked to be the same regular file before a bounded read.
package fsread

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"syscall"
)

// ErrRead: missing, not a regular file, too large or unreadable. Fixed
// message: it never quotes the path.
var ErrRead = errors.New("fsread: cannot read the file (missing, not a regular file or too large)")

// Regular reads the regular file path, of at most max bytes.
func Regular(path string, maxBytes int64) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil || !regular(st, maxBytes) {
		return nil, ErrRead
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: the user names the file; regular file only, bounded read.
	if err != nil {
		return nil, ErrRead
	}
	defer func() { _ = f.Close() }()
	return read(f, st, maxBytes)
}

// RegularIn reads the regular file name under root (no link nor path out of
// it), of at most max bytes.
func RegularIn(root *os.Root, name string, maxBytes int64) ([]byte, error) {
	if root == nil {
		return nil, ErrRead
	}
	st, err := root.Stat(name)
	if err != nil || !regular(st, maxBytes) {
		return nil, ErrRead
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrRead
	}
	defer func() { _ = f.Close() }()
	return read(f, st, maxBytes)
}

func regular(st fs.FileInfo, maxBytes int64) bool {
	return maxBytes > 0 && st.Mode().IsRegular() && st.Size() <= maxBytes
}

// read checks that the descriptor is the file checked by Stat (no swap
// between the two calls), then reads at most max bytes.
func read(f *os.File, before fs.FileInfo, maxBytes int64) ([]byte, error) {
	st, err := f.Stat()
	if err != nil || !regular(st, maxBytes) || !os.SameFile(before, st) {
		return nil, ErrRead
	}
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil || int64(len(b)) > maxBytes {
		return nil, ErrRead
	}
	return b, nil
}
