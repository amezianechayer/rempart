// Package prompts loads versioned, hashed prompts (skill llm-safety, rule 6).
package prompts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"strconv"
	"unicode/utf8"

	"github.com/amezianechayer/rempart/internal/llm/schema"
)

var (
	ErrInvalidPromptID = errors.New("llm: invalid prompt id")
	ErrUnknownPrompt   = errors.New("llm: unknown prompt")
	ErrInvalidPrompt   = errors.New("llm: invalid prompt")
)

const (
	MaxSystemBytes = 64 << 10
	maxIDLen       = 64
	hashDomain     = "rempart-prompt-v1\n"
)

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*\.v([1-9][0-9]{0,5})$`)

type Prompt struct {
	ID      string
	Version int
	System  string
	Schema  *schema.Schema
	Hash    string
}

func LoadFS(fsys fs.FS, id string) (Prompt, error) {
	m := idPattern.FindStringSubmatch(id)
	if m == nil || len(id) > maxIDLen {
		return Prompt{}, ErrInvalidPromptID
	}
	version, err := strconv.Atoi(m[1])
	if err != nil {
		return Prompt{}, ErrInvalidPromptID
	}
	if fsys == nil {
		return Prompt{}, ErrUnknownPrompt
	}
	if _, err := entry(fsys, id, true); err != nil {
		return Prompt{}, err
	}
	system, err := readBounded(fsys, id+"/system.txt", MaxSystemBytes)
	if err != nil {
		return Prompt{}, err
	}
	raw, err := readBounded(fsys, id+"/schema.json", schema.MaxSchemaBytes)
	if err != nil {
		return Prompt{}, err
	}
	if reason := checkSystem(system); reason != "" {
		return Prompt{}, fmt.Errorf("%w: %s", ErrInvalidPrompt, reason)
	}
	s, err := schema.CompileSchema(raw)
	if err != nil {
		return Prompt{}, fmt.Errorf("%w: %w", ErrInvalidPrompt, err)
	}
	return Prompt{ID: id, Version: version, System: string(system), Schema: s, Hash: promptHash(id, system, raw)}, nil
}

func checkSystem(b []byte) string {
	switch {
	case len(b) == 0:
		return "empty system prompt"
	case len(b) > MaxSystemBytes:
		return "system prompt too large"
	case !utf8.Valid(b):
		return "system prompt is not valid UTF-8"
	case bytes.ContainsRune(b, '\r'):
		return "system prompt contains a carriage return"
	case !schema.AdmittedText(string(b)):
		return "system prompt contains a character outside the admission list"
	}
	return ""
}

// entry returns the fs.Lstat information of name, a directory if dir, a
// regular file otherwise; a missing entry is ErrUnknownPrompt. A link is
// never followed (T43).
func entry(fsys fs.FS, name string, dir bool) (fs.FileInfo, error) {
	fi, err := fs.Lstat(fsys, name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, ErrUnknownPrompt
	case err != nil:
		return nil, fmt.Errorf("%w: unreadable entry", ErrInvalidPrompt)
	case dir && !fi.IsDir(), !dir && !fi.Mode().IsRegular():
		return nil, fmt.Errorf("%w: link or unexpected file type", ErrInvalidPrompt)
	}
	return fi, nil
}

// readBounded reads the regular file name: its declared size is checked
// before opening, the bytes read after, never more than limit + 1.
func readBounded(fsys fs.FS, name string, limit int) ([]byte, error) {
	fi, err := entry(fsys, name, false)
	if err != nil {
		return nil, err
	}
	if fi.Size() > int64(limit) {
		return nil, fmt.Errorf("%w: file too large", ErrInvalidPrompt)
	}
	f, err := fsys.Open(name)
	if err != nil {
		return nil, fmt.Errorf("%w: unreadable file", ErrInvalidPrompt)
	}
	b, rerr := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if cerr := f.Close(); rerr != nil || cerr != nil {
		return nil, fmt.Errorf("%w: unreadable file", ErrInvalidPrompt)
	}
	if len(b) > limit {
		return nil, fmt.Errorf("%w: file too large", ErrInvalidPrompt)
	}
	return b, nil
}

func promptHash(id string, system, schemaRaw []byte) string {
	b := []byte(hashDomain)
	for _, part := range [][]byte{[]byte(id), system, schemaRaw} {
		b = strconv.AppendInt(b, int64(len(part)), 10)
		b = append(b, ':')
		b = append(b, part...)
		b = append(b, ',')
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
