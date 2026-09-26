package evals

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"reflect"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	MaxFileBytes = 64 << 10
	InjectionTag = "injection"
	lower        = "abcdefghijklmnopqrstuvwxyz"
	alnum        = lower + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	nameSet      = lower + "0123456789_-"
	loopSet      = alnum + "_-"
)

var (
	ErrInvalidSuite = errors.New("evals: invalid suite")
	ErrInvalidCase  = errors.New("evals: invalid case")
)

type Suite struct {
	Name   string   `json:"name"`
	Loop   string   `json:"loop"`
	Target string   `json:"target"`
	Watch  []string `json:"watch"`
	Cases  []Case   `json:"-"`
}

type Case struct {
	ID     string          `json:"id"`
	Loop   string          `json:"loop"`
	Tags   []string        `json:"tags"`
	Input  json.RawMessage `json:"input"`
	Expect Expect          `json:"expect"`
	Runs   int             `json:"runs"`
}

type Expect struct {
	SchemaValid      *bool       `json:"schema_valid"`
	Escalation       *bool       `json:"escalation"`
	Status           string      `json:"status"`
	MaxIterations    *int        `json:"max_iterations"`
	MaxOpenQuestions *int        `json:"max_open_questions"`
	MustInclude      []PathCheck `json:"must_include"`
	MustNotInclude   []PathCheck `json:"must_not_include"`
}

type PathCheck struct {
	Path     string          `json:"path"`
	Contains json.RawMessage `json:"contains"`
	Equals   json.RawMessage `json:"equals"`
}

func LoadSuite(fsys fs.FS, dir string) (Suite, error) {
	lfs, ok := fsys.(fs.ReadLinkFS)
	if !ok || !validSuiteName(dir) || !realDir(lfs, dir) {
		return Suite{}, fmt.Errorf("%w: file system or directory", ErrInvalidSuite)
	}
	var s Suite
	file, cases := path.Join(dir, "suite.yaml"), path.Join(dir, "cases")
	if err := decodeFile(lfs, file, &s); err != nil {
		return Suite{}, err
	}
	if !validSuiteName(s.Name) || (dir != s.Name && !strings.HasSuffix(dir, "/"+s.Name)) ||
		!token(s.Loop, 32, loopSet) || !token(s.Target, 32, nameSet) || len(s.Watch) > 64 ||
		slices.ContainsFunc(s.Watch, func(p string) bool { return !validPattern(p) }) {
		return Suite{}, invalid(file, "header")
	}
	if !realDir(lfs, cases) {
		return Suite{}, invalid(cases, "not a directory")
	}
	entries, err := fs.ReadDir(lfs, cases)
	if err != nil || len(entries) == 0 || len(entries) > 1000 {
		return Suite{}, invalid(cases, "count")
	}
	for i, e := range entries {
		id, isYAML := strings.CutSuffix(e.Name(), ".yaml")
		if !isYAML || !token(id, 64, lower+"0123456789-") {
			return Suite{}, fmt.Errorf("%w: %s: entry %d: name", ErrInvalidSuite, cases, i)
		}
		name := path.Join(cases, e.Name())
		c := Case{Runs: 1}
		if err := decodeFile(lfs, name, &c); err != nil {
			return Suite{}, err
		}
		if _, _, err := compileCase(c); err != nil {
			return Suite{}, fmt.Errorf("%w: %s: %w", ErrInvalidSuite, name, err)
		}
		if c.ID != id || c.Loop != s.Loop {
			return Suite{}, invalid(name, "id or loop")
		}
		s.Cases = append(s.Cases, c)
	}
	return s, nil
}

func decodeFile(fsys fs.ReadLinkFS, name string, out any) error {
	data, ok := readRegular(fsys, name)
	if !ok {
		return invalid(name, "file")
	}
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if dec.Decode(&doc) != nil || !errors.Is(dec.Decode(new(yaml.Node)), io.EOF) || !plain(&doc, 0) {
		return invalid(name, "not one plain YAML document")
	}
	var v any
	if doc.Decode(&v) != nil {
		return invalid(name, "duplicate key")
	}
	if !exactKeys(v, reflect.TypeOf(out)) {
		return invalid(name, "key")
	}
	js, err := json.Marshal(v)
	strict := json.NewDecoder(bytes.NewReader(js))
	strict.DisallowUnknownFields()
	if err != nil || strict.Decode(out) != nil {
		return invalid(name, "number, type or field")
	}
	return nil
}

func plain(n *yaml.Node, depth int) bool {
	if depth > 32 || n.Kind == yaml.AliasNode || n.Anchor != "" || n.Style&yaml.TaggedStyle != 0 || n.Tag == "!!merge" {
		return false
	}
	return !slices.ContainsFunc(n.Content, func(c *yaml.Node) bool { return !plain(c, depth+1) })
}

func token(s string, limit int, set string) bool {
	return s != "" && len(s) <= limit && strings.Trim(s, set) == "" && strings.Contains(alnum, s[:1])
}

func validSuiteName(s string) bool {
	segs := strings.Split(s, "/")
	return len(s) <= 127 && len(segs) <= 4 && !slices.ContainsFunc(segs, func(g string) bool { return !token(g, 64, nameSet) })
}

func invalid(name, reason string) error {
	return fmt.Errorf("%w: %s: %s", ErrInvalidSuite, name, reason)
}

func realDir(fsys fs.ReadLinkFS, dir string) bool {
	parts := strings.Split(dir, "/")
	for i := range parts {
		if info, err := fsys.Lstat(strings.Join(parts[:i+1], "/")); err != nil || !info.IsDir() {
			return false
		}
	}
	return true
}

func readRegular(fsys fs.ReadLinkFS, name string) ([]byte, bool) {
	if info, err := fsys.Lstat(name); err != nil || !info.Mode().IsRegular() {
		return nil, false
	}
	f, err := fsys.Open(name)
	if err != nil {
		return nil, false
	}
	info, err := f.Stat()
	data, rerr := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	return data, f.Close() == nil && err == nil && info.Mode().IsRegular() && rerr == nil && len(data) <= MaxFileBytes
}

func exactKeys(v any, t reflect.Type) bool {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Slice:
		a, isSlice := v.([]any)
		return !isSlice || !slices.ContainsFunc(a, func(e any) bool { return !exactKeys(e, t.Elem()) })
	case reflect.Struct:
		m, isMap := v.(map[string]any)
		for k, x := range m {
			f, found := jsonField(t, k)
			if !found || !exactKeys(x, f) {
				return false
			}
		}
		return isMap || reflect.ValueOf(v).Kind() != reflect.Map
	}
	return true
}

func jsonField(t reflect.Type, key string) (reflect.Type, bool) {
	for i := range t.NumField() {
		f := t.Field(i)
		if name, _, _ := strings.Cut(f.Tag.Get("json"), ","); f.IsExported() && name != "-" && name != "" && name == key {
			return f.Type, true
		}
	}
	return nil, false
}
