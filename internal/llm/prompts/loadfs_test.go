package prompts

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func writePrompt(t *testing.T, root string, system, schemaRaw []byte) {
	t.Helper()
	dir := filepath.Join(root, fixtureID)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"system.txt": system, "schema.json": schemaRaw} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func wantInvalid(t *testing.T, fsys fs.FS, id string) {
	t.Helper()
	p, err := LoadFS(fsys, id)
	if !errors.Is(err, ErrInvalidPrompt) || p.Schema != nil || p.Hash != "" {
		t.Fatalf("LoadFS = %+v, %v; want ErrInvalidPrompt", p, err)
	}
}

// TestLoadFSRejectsLinks: a link is never followed, file or directory (D5).
func TestLoadFSRejectsLinks(t *testing.T) {
	system, schemaRaw := fixtureFiles(t)
	outside := t.TempDir()
	writePrompt(t, outside, system, schemaRaw)
	mustLoad(t, os.DirFS(outside), fixtureID) // witness: the targets are valid
	link := func(t *testing.T, target, name string) {
		t.Helper()
		if err := os.Symlink(target, name); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("linked directory", func(t *testing.T) {
		root := t.TempDir()
		link(t, filepath.Join(outside, fixtureID), filepath.Join(root, fixtureID))
		wantInvalid(t, os.DirFS(root), fixtureID)
	})
	for _, name := range []string{"system.txt", "schema.json"} {
		t.Run("linked "+name, func(t *testing.T) {
			root := t.TempDir()
			writePrompt(t, root, system, schemaRaw)
			p := filepath.Join(root, fixtureID, name)
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			link(t, filepath.Join(outside, fixtureID, name), p)
			wantInvalid(t, os.DirFS(root), fixtureID)
		})
	}
}

// sizedFS serves m, declares size for name and counts the bytes read from it.
type sizedFS struct {
	m    fstest.MapFS
	name string
	size int64
	read *int
}

func (s sizedFS) Open(name string) (fs.File, error) {
	f, err := s.m.Open(name)
	if err != nil || name != s.name {
		return f, err
	}
	return countingFile{File: f, read: s.read}, nil
}

func (s sizedFS) Lstat(name string) (fs.FileInfo, error) {
	fi, err := s.m.Lstat(name)
	if err != nil || name != s.name {
		return fi, err
	}
	return sizedInfo{FileInfo: fi, size: s.size}, nil
}

func (s sizedFS) ReadLink(name string) (string, error) { return s.m.ReadLink(name) }

type sizedInfo struct {
	fs.FileInfo
	size int64
}

func (i sizedInfo) Size() int64 { return i.size }

type countingFile struct {
	fs.File
	read *int
}

func (f countingFile) Read(p []byte) (int, error) {
	n, err := f.File.Read(p)
	*f.read += n
	return n, err
}

// TestLoadFSBoundedRead: declared size checked before opening, bytes read bounded (D5).
func TestLoadFSBoundedRead(t *testing.T) {
	small := []byte("text\n")
	cases := []struct {
		name, file string
		data       []byte
		declared   int64
		maxRead    int
	}{
		{"system longer than declared", "system.txt", []byte(strings.Repeat("a", MaxSystemBytes+10)), 10, MaxSystemBytes + 1},
		{"system declared too large", "system.txt", small, MaxSystemBytes + 1, 0},
		{"schema longer than declared", "schema.json", []byte(strings.Repeat(" ", 3<<16)), 10, 64<<10 + 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := promptFS("p.v1", small, []byte(smallSchema))
			m["p.v1/"+c.file] = &fstest.MapFile{Data: c.data}
			read := 0
			wantInvalid(t, sizedFS{m: m, name: "p.v1/" + c.file, size: c.declared, read: &read}, "p.v1")
			if read > c.maxRead {
				t.Errorf("%d bytes read, want at most %d", read, c.maxRead)
			}
		})
	}
	read := 0
	m := promptFS("p.v1", small, []byte(smallSchema))
	mustLoad(t, sizedFS{m: m, name: "p.v1/system.txt", size: int64(len(small)), read: &read}, "p.v1")
	if read != len(small) {
		t.Errorf("witness: %d bytes read, want %d", read, len(small))
	}
}

// TestLoadFSNonRegular: only a directory holding two regular files loads (D5).
func TestLoadFSNonRegular(t *testing.T) {
	for _, mode := range []fs.FileMode{fs.ModeDevice, fs.ModeNamedPipe, fs.ModeSocket, fs.ModeIrregular} {
		for _, file := range []string{"system.txt", "schema.json"} {
			m := promptFS("p.v1", []byte("text\n"), []byte(smallSchema))
			m["p.v1/"+file].Mode = mode
			wantInvalid(t, m, "p.v1")
		}
	}
	wantInvalid(t, fstest.MapFS{"p.v1": {Data: []byte("text\n")}}, "p.v1")
}

// TestSystemPromptAdmissionList: the system prompt uses the list of D3.
func TestSystemPromptAdmissionList(t *testing.T) {
	for _, s := range []string{"a\u202eb\n", "a\tb\n", "a\u00a0b\n", "\ufeffa\n", "a\u200bb\n", "a\u2028b\n", "a\x00b\n"} {
		_, err := LoadFS(promptFS("p.v1", []byte(s), []byte(smallSchema)), "p.v1")
		if !errors.Is(err, ErrInvalidPrompt) || strings.ContainsAny(err.Error(), "\u202e\t\u00a0\ufeff\u200b\u2028\x00") {
			t.Errorf("system %q: error %v", s, err)
		}
	}
	mustLoad(t, promptFS("p.v1", []byte("Réponds en français : œ, Ÿ.\n"), []byte(smallSchema)), "p.v1")
}

// lstatErrFS fails every Lstat with a permission error.
type lstatErrFS struct{ fstest.MapFS }

func (lstatErrFS) Lstat(name string) (fs.FileInfo, error) {
	return nil, &fs.PathError{Op: "lstat", Path: name, Err: fs.ErrPermission}
}

func (s lstatErrFS) ReadLink(name string) (string, error) { return s.MapFS.ReadLink(name) }

// TestLoadFSUnreadableEntry: an entry that exists but cannot be examined is an
// invalid prompt, never an unknown one (D5).
func TestLoadFSUnreadableEntry(t *testing.T) {
	m := promptFS("p.v1", []byte("text\n"), []byte(smallSchema))
	wantInvalid(t, lstatErrFS{m}, "p.v1")
	if _, err := LoadFS(lstatErrFS{m}, "p.v1"); errors.Is(err, ErrUnknownPrompt) {
		t.Errorf("LoadFS = %v, want no ErrUnknownPrompt", err)
	}
}
