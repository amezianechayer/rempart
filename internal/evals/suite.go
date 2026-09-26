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
var ambiguous = regexp.MustCompile(`(?i)^(y|yes|n|no|on|off|true|false|null|~|[-+]?\.(inf|nan)|[-+]?0[box][0-9a-f_]*|[-+]?\.[0-9.]*(e[-+]?[0-9]+)?|=|` +
	`[-+]?\.?[0-9][0-9_]*(:[0-9_]+)*(\.[0-9_.]*)?(e[-+]?[0-9]+)?)$`)

// tagToken is the grammar of a tag (V10, T66).
var tagToken = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// zone is where a node sits: a typed field or the opaque content of input,
// equals or contains. Null is spelled only in input and equals (V8); equals and
// contains hold no block scalar (V10) and every scalar on one line (V11).
type zone int

const (
	typed zone = iota
	inInput
	inEquals
	inContains
)

var zones = map[string]zone{"input": inInput, "equals": inEquals, "contains": inContains}

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
	if !admitted(data) || bytes.HasPrefix(data, []byte("%")) || bytes.Contains(data, []byte("\n%")) {
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

// admitted reports whether every rune of data is in the closed list of D17:
// printable ASCII, a line feed, a carriage return before a line feed, or a
// French letter (U+00C0 to U+00FF but U+00D7 and U+00F7, U+0152, U+0153,
// U+0178). Invalid UTF-8 decodes to U+FFFD, which is not in the list.
func admitted(data []byte) bool {
	for i, r := range string(data) {
		switch {
		case r >= ' ' && r <= '~', r == '\n', r == '\r' && bytes.HasPrefix(data[i+1:], []byte("\n")):
		case r >= 0xC0 && r <= 0xFF && r != 0xD7 && r != 0xF7, r == 0x152, r == 0x153, r == 0x178:
		default:
			return false
		}
	}
	return true
}

func runeLines(data []byte) [][]rune {
	var lines [][]rune
	for line := range strings.SplitSeq(string(data), "\n") {
		lines = append(lines, []rune(line))
	}
	return lines
}

// source returns the rest of the line of n from its first rune, Line and
// Column counting runes from 1, or nil when n has no position in the text.
func source(n *yaml.Node, src [][]rune) []rune {
	if n.Line < 1 || n.Line > len(src) || n.Column < 1 || n.Column > len(src[n.Line-1]) {
		return nil
	}
	return src[n.Line-1][n.Column-1:]
}

// bang reports whether the source text of n starts with the non-specific tag
// "!", which yaml v3 drops (T65).
func bang(n *yaml.Node, src [][]rune) bool {
	s := source(n, src)
	return len(s) > 0 && s[0] == '!'
}

// escapes reports whether a double-quoted scalar closes on its own line and
// uses only the escapes of D17: \\, \", \n, \t, \u and \U (yaml v3 checks
// their hexadecimal digits).
func escapes(n *yaml.Node, src [][]rune) bool {
	if n.Style&yaml.DoubleQuotedStyle == 0 {
		return true
	}
	s := source(n, src)
	if len(s) == 0 || s[0] != '"' {
		return false
	}
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '"':
			return true
		case '\\':
			i++
			if i == len(s) || !strings.ContainsRune(`\"ntuU`, s[i]) {
				return false
			}
		}
	}
	return false
}

// oneLine reports whether a plain or single-quoted scalar is written on one
// line (V11): its source text, from its first rune, reads back as its value.
// Double-quoted scalars are held to one line by escapes, block scalars are
// refused where oneLine applies.
func oneLine(n *yaml.Node, src [][]rune) bool {
	if n.Kind != yaml.ScalarNode || n.Style&(yaml.DoubleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return true
	}
	want := n.Value
	if n.Style&yaml.SingleQuotedStyle != 0 {
		want = "'" + strings.ReplaceAll(n.Value, "'", "''") + "'"
	}
	s := source(n, src)
	for _, r := range want {
		if len(s) == 0 || s[0] != r {
			return false
		}
		s = s[1:]
	}
	return true
}

func plain(n *yaml.Node, depth int, z zone, src [][]rune) bool {
	if depth > 32 || n.Kind == yaml.AliasNode || n.Anchor != "" || n.Style&yaml.TaggedStyle != 0 || n.Tag == "!!merge" ||
		bang(n, src) || !escapes(n, src) ||
		((z == inEquals || z == inContains) && (n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 || !oneLine(n, src))) ||
		!jsonScalar(n, z == inInput || z == inEquals) {
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
