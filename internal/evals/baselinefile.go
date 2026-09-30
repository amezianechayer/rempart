package evals

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/amezianechayer/rempart/internal/llm/schema"
)

// ErrNoBaseline: the baseline file or one of its parent directories is absent.
var ErrNoBaseline = errors.New("evals: no baseline")

// LoadBaseline reads name (slash path from the root of fsys) under the rules of
// a case file (D18). Absent: ErrNoBaseline; otherwise invalid: ErrInvalidBaseline.
// Errors quote no value read.
func LoadBaseline(fsys fs.FS, name string) (Baseline, error) {
	lfs, ok := fsys.(fs.ReadLinkFS)
	if !ok || !fs.ValidPath(name) || name == "." || !strings.HasSuffix(name, ".json") {
		return Baseline{}, fmt.Errorf("%w: file system or name", ErrInvalidBaseline)
	}
	parts := strings.Split(name, "/")
	for i := range parts {
		info, err := lfs.Lstat(strings.Join(parts[:i+1], "/"))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return Baseline{}, ErrNoBaseline
		case err != nil:
			return Baseline{}, fmt.Errorf("%w: unreadable path", ErrInvalidBaseline)
		case i < len(parts)-1 && !info.IsDir():
			return Baseline{}, fmt.Errorf("%w: parent is not a directory", ErrInvalidBaseline)
		}
	}
	data, ok := readRegular(lfs, name)
	if !ok {
		return Baseline{}, fmt.Errorf("%w: file", ErrInvalidBaseline)
	}
	return decodeBaseline(data)
}

// maxLineRunes bounds every line of a baseline file (D18, T64).
const maxLineRunes = 160

// shortLines reports whether every line of data holds at most maxLineRunes
// runes, a carriage return before a line feed excluded.
func shortLines(data []byte) bool {
	for line := range strings.SplitSeq(string(data), "\n") {
		if utf8.RuneCountInString(strings.TrimSuffix(line, "\r")) > maxLineRunes {
			return false
		}
	}
	return true
}

// decodeBaseline applies the content rules of D18 to data.
func decodeBaseline(data []byte) (Baseline, error) {
	if !admitted(data) || !shortLines(data) {
		return Baseline{}, fmt.Errorf("%w: character or line length", ErrInvalidBaseline)
	}
	v, err := schema.DecodeStrict(data)
	if err != nil {
		return Baseline{}, fmt.Errorf("%w: not one strict JSON document", ErrInvalidBaseline)
	}
	if !exactKeys(v, reflect.TypeFor[Baseline]()) {
		return Baseline{}, fmt.Errorf("%w: key", ErrInvalidBaseline)
	}
	var b Baseline
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if dec.Decode(&b) != nil {
		return Baseline{}, fmt.Errorf("%w: number, type or field", ErrInvalidBaseline)
	}
	return b, nil
}

// EncodeBaseline returns the canonical file content of b (D19); it refuses a
// baseline that fails Validate or that LoadBaseline would not read back equal.
func EncodeBaseline(b Baseline) ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("%w: encoding", ErrInvalidBaseline)
	}
	data = append(data, '\n')
	back, err := decodeBaseline(data)
	if err != nil || !reflect.DeepEqual(back, b) {
		return nil, fmt.Errorf("%w: not read back equal", ErrInvalidBaseline)
	}
	return data, nil
}
