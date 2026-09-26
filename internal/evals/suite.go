package evals

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
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
	var s Suite
	file := path.Join(dir, "suite.yaml")
	if err := decodeFile(fsys, file, &s); err != nil {
		return Suite{}, err
	}
	if !validSuiteName(s.Name) || (dir != s.Name && !strings.HasSuffix(dir, "/"+s.Name)) ||
		!token(s.Loop, 32, loopSet) || !token(s.Target, 32, nameSet) || len(s.Watch) > 64 {
		return Suite{}, invalid(file, "header")
	}
	entries, err := fs.ReadDir(fsys, path.Join(dir, "cases"))
	if err != nil || len(entries) == 0 || len(entries) > 1000 {
		return Suite{}, invalid(dir, "cases")
	}
	for _, e := range entries {
		name := path.Join(dir, "cases", e.Name())
		if !strings.HasSuffix(name, ".yaml") || !e.Type().IsRegular() {
			return Suite{}, invalid(name, "not a regular .yaml file")
		}
		c := Case{Runs: 1}
		if err := decodeFile(fsys, name, &c); err != nil {
			return Suite{}, err
		}
		if _, _, err := compileCase(c); err != nil {
			return Suite{}, fmt.Errorf("%w: %s: %w", ErrInvalidSuite, name, err)
		}
		if c.ID+".yaml" != e.Name() || c.Loop != s.Loop {
			return Suite{}, invalid(name, "id or loop")
		}
		s.Cases = append(s.Cases, c)
	}
	return s, nil
}

func decodeFile(fsys fs.FS, name string, out any) error {
	info, err := fs.Lstat(fsys, name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxFileBytes {
		return invalid(name, "file")
	}
	data, err := fs.ReadFile(fsys, name)
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err != nil || dec.Decode(&doc) != nil || !errors.Is(dec.Decode(new(yaml.Node)), io.EOF) || !plain(&doc, 0) {
		return invalid(name, "not one plain YAML document")
	}
	var v any
	if doc.Decode(&v) != nil {
		return invalid(name, "duplicate key")
	}
	js, err := json.Marshal(v)
	strict := json.NewDecoder(bytes.NewReader(js))
	strict.DisallowUnknownFields()
	if err != nil || strict.Decode(out) != nil {
		return invalid(name, "key, number, type or field")
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
