// Package prompts loads versioned, hashed prompts (skill llm-safety, rule 6).
package prompts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
	var files [2][]byte
	for i, name := range [2]string{"/system.txt", "/schema.json"} {
		b, err := fs.ReadFile(fsys, id+name)
		if errors.Is(err, fs.ErrNotExist) {
			return Prompt{}, ErrUnknownPrompt
		}
		if err != nil {
			return Prompt{}, fmt.Errorf("%w: unreadable file", ErrInvalidPrompt)
		}
		files[i] = b
	}
	system, raw := files[0], files[1]
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
	}
	return ""
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
