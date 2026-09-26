package evals

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"path"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

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

// jsonInt is the JSON integer grammar.
var jsonInt = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// ambiguous matches the plain scalars that YAML 1.1 or the core schema read as
// a boolean, a null or a number while yaml v3 reads a string (V6).
var ambiguous = regexp.MustCompile(`(?i)^(y|yes|n|no|on|off|true|false|null|~|[-+]?\.(inf|nan)|[-+]?0[box][0-9a-f_]*|[-+]?\.[0-9.]*|=|` +
	`[-+]?\.?[0-9][0-9_]*(:[0-9_]+)*(\.[0-9_.]*)?(e[-+]?[0-9]+)?)$`)

// zone is where a node sits: a typed field, opaque content that may hold null
// (input, equals) or opaque content that may not (contains).
type zone int

const (
	typed zone = iota
	nullable
	opaque
)

var zones = map[string]zone{"input": nullable, "equals": nullable, "contains": opaque}

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
	if !visible(data) || bytes.HasPrefix(data, []byte("%")) || bytes.Contains(data, []byte("\n%")) {
		return invalid(name, "character or directive")
	}
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if dec.Decode(&doc) != nil || !errors.Is(dec.Decode(new(yaml.Node)), io.EOF) || !plain(&doc, 0, typed, runeLines(data)) {
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

// visible reports whether every rune of data has one visible reading (D16, V8):
// valid UTF-8 and assigned, with no control, format, separator, private use,
// noncharacter, variation selector or default ignorable rune but the space,
// the line feed and a carriage return before a line feed. Unassigned is spelled
// out: since Unicode 17 (Go 1.27) unicode.C also holds the unassigned runes.
func visible(data []byte) bool {
	for i, r := range string(data) {
		if r != ' ' && r != '\n' && (r != '\r' || !bytes.HasPrefix(data[i+1:], []byte("\n"))) &&
			(unicode.In(r, unicode.Cc, unicode.Cf, unicode.Z, unicode.Co, unicode.Noncharacter_Code_Point,
				unicode.Variation_Selector, unicode.Other_Default_Ignorable_Code_Point) ||
				!unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z, unicode.Cc, unicode.Cf, unicode.Co, unicode.Cs)) {
			return false
		}
	}
	return utf8.Valid(data)
}

func runeLines(data []byte) [][]rune {
	var lines [][]rune
	for line := range strings.SplitSeq(string(data), "\n") {
		lines = append(lines, []rune(line))
	}
	return lines
}

// bang reports whether the source text of n starts with the non-specific tag
// "!", which yaml v3 drops (T65); Line and Column count runes from 1.
func bang(n *yaml.Node, src [][]rune) bool {
	return n.Line >= 1 && n.Line <= len(src) && n.Column >= 1 && n.Column <= len(src[n.Line-1]) && src[n.Line-1][n.Column-1] == '!'
}

func plain(n *yaml.Node, depth int, z zone, src [][]rune) bool {
	if depth > 32 || n.Kind == yaml.AliasNode || n.Anchor != "" || n.Style&yaml.TaggedStyle != 0 || n.Tag == "!!merge" ||
		bang(n, src) || !jsonScalar(n, z == nullable) {
		return false
	}
	for i, c := range n.Content {
		cz := z
		if z == typed && n.Kind == yaml.MappingNode && i%2 == 1 {
			cz = zones[n.Content[i-1].Value]
		}
		if (n.Kind == yaml.MappingNode && i%2 == 0 && c.ShortTag() != "!!str") || !plain(c, depth+1, cz, src) {
			return false
		}
	}
	return true
}

// jsonScalar admits unambiguous strings, spelled nulls where allowed, exact booleans
// and numbers that read back exactly as written (D15, V5, V6).
func jsonScalar(n *yaml.Node, nulls bool) bool {
	if n.Kind != yaml.ScalarNode {
		return true
	}
	switch n.ShortTag() {
	case "!!str":
		return n.Style != 0 || !ambiguous.MatchString(n.Value)
	case "!!null":
		return nulls && n.Value == "null"
	case "!!bool":
		return n.Value == "true" || n.Value == "false"
	case "!!int":
		_, err := strconv.ParseInt(n.Value, 10, 64)
		return err == nil && jsonInt.MatchString(n.Value) && n.Value != "-0"
	case "!!float":
		f, err := strconv.ParseFloat(n.Value, 64)
		return err == nil && !math.IsInf(f, 0) && !math.IsNaN(f) && strconv.FormatFloat(f, 'f', -1, 64) == n.Value
	}
	return false
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
