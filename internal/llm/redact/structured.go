package redact

import (
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// Structured pass of ADR 0007 (M1-T08): JSON documents and fragments of the
// text, and the text as a YAML stream, are walked with their byte offsets.
// A sensitive key masks its whole value; a name/value pair whose name is
// sensitive masks its value; a leaf whose decoded form holds a secret, and
// differs from its raw form (escapes, nested encodings), is masked whole; an
// array of strings whose concatenation holds a secret that no element holds
// masks all its strings. Every bound reached abandons the structured pass:
// the regular expressions still run on the whole text (never fail open).
const (
	MaxStructuredDepth = 64      // nesting of one document
	MaxStructuredNodes = 1 << 16 // tokens or YAML nodes of one document
	maxYAMLDocuments   = 64
	budgetPerByte      = 80 // bytes parsed per byte of input, all attempts together
	budgetBase         = 1 << 16
)

var errBound = errors.New("redact: structured bound reached")

// budget bounds the work of the structured pass on one input, nested
// encodings included (T81).
type budget struct{ left int }

func newBudget(n int) *budget { return &budget{left: budgetPerByte*n + budgetBase} }

func (b *budget) spend(n int) bool {
	b.left -= n
	return b.left >= 0
}

// structuredKey: a key whose value is a secret, whole key, case-insensitive.
var structuredKey = regexp.MustCompile(`(?i)^(?:` + names +
	`|cookie|set-cookie|psk|pre_?shared_?key|tunnel[0-9]_preshared_key|shared_?key|ike_psk` +
	`|client-key-data|(?:ovh_)?(?:application_?key|application_?secret|consumer_?key))$`)

// pskKey: keys whose value is an IPsec pre-shared key.
var pskKey = regexp.MustCompile(`(?i)^(?:psk|pre_?shared_?key|tunnel[0-9]_preshared_key|shared_?key|ike_psk)$`)

// sensitivePairName reports whether the name of a name/value pair, or the
// last segment of its path (SSM parameter), is sensitive.
func sensitivePairName(n string) bool {
	seg := n[strings.LastIndexByte(n, '/')+1:]
	return pairName.MatchString(seg)
}

func keyCandidate(key, value string, start, end int) (candidate, bool) {
	if start >= end || !structuredKey.MatchString(key) || exemptGeneric(key, value) {
		return candidate{}, false
	}
	k := KindSensitiveVar
	if pskKey.MatchString(key) {
		k = KindIPsecPSK
	}
	return candidate{start: start, end: end, prio: prioOf(k)}, true
}

// prioOf returns the priority of the first rule of kind k.
func prioOf(k Kind) int {
	for i, ru := range rules {
		if ru.kind == k {
			return i
		}
	}
	return len(rules) - 1
}

// leafCandidate masks a whole leaf [start, end) of raw form raw (JSON string
// content) and decoded form dec when dec holds a secret that the redaction of
// raw leaves in its decoded form (escapes, nested encodings, T69). The
// regular expressions read raw already: when they suffice, their precise
// masks are kept.
func leafCandidate(raw, dec string, start, end int, b *budget) (candidate, bool) {
	if raw == dec || start >= end || !b.spend(2*len(dec)+len(raw)) {
		return candidate{}, false
	}
	ms := findBudget(dec, b)
	if len(ms) == 0 {
		return candidate{}, false
	}
	whole := candidate{start: start, end: end, prio: prioOf(ms[0].Kind)}
	red, rms := redactBudget(raw, b)
	if len(rms) == 0 {
		return whole, true
	}
	var again string
	if json.Unmarshal([]byte(`"`+red+`"`), &again) != nil || len(findBudget(again, b)) > 0 {
		return whole, true
	}
	return candidate{}, false
}

// redactBudget is Redact under the budget b.
func redactBudget(s string, b *budget) (string, []Match) {
	ms := findBudget(s, b)
	var out strings.Builder
	prev := 0
	for _, m := range ms {
		out.WriteString(s[prev:m.Start])
		out.WriteString(Placeholder(m.Kind))
		prev = m.End
	}
	out.WriteString(s[prev:])
	return out.String(), ms
}

// structured returns the candidates of the structured pass on s.
func structured(s string, b *budget) []candidate {
	out := jsonCandidates(s, b)
	return append(out, yamlCandidates(s, b)...)
}

// jsonLeaf is a string of a JSON document: the bounds of its content (inside
// the quotes), its raw content and its decoded value.
type jsonLeaf struct {
	start, end int
	raw, dec   string
}

type jsonFrame struct {
	obj       bool
	expectKey bool
	key       string
	pairName  string
	hasName   bool
	values    []jsonLeaf
	strs      []jsonLeaf
}

// jsonCandidates tries a JSON value at every '{' or '[' of s that no parsed
// document covers.
func jsonCandidates(s string, b *budget) []candidate {
	var out []candidate
	for i := 0; i < len(s); i++ {
		if s[i] != '{' && s[i] != '[' {
			continue
		}
		cs, end, err := jsonDocument(s, i, b)
		if errors.Is(err, errBound) && b.left < 0 {
			return out
		}
		if err == nil {
			out = append(out, cs...)
			i = end - 1
		}
	}
	return out
}

// jsonDocument walks the JSON value starting at s[at]: its candidates and the
// offset of its end.
func jsonDocument(s string, at int, b *budget) ([]candidate, int, error) {
	dec := json.NewDecoder(strings.NewReader(s[at:]))
	var (
		out   []candidate
		stack []*jsonFrame
		nodes int
	)
	spent := 0
	defer func() { b.spend(spent) }()
	for {
		prev := int(dec.InputOffset())
		tok, err := dec.Token()
		off := int(dec.InputOffset())
		spent = off
		if err != nil {
			var se *json.SyntaxError
			if errors.As(err, &se) {
				spent = int(se.Offset)
			}
			if errors.Is(err, io.EOF) {
				spent = len(s) - at
			}
			return nil, 0, err
		}
		if nodes++; nodes > MaxStructuredNodes || b.left-spent < 0 {
			return nil, 0, errBound
		}
		var top *jsonFrame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				if len(stack) >= MaxStructuredDepth {
					return nil, 0, errBound
				}
				if top != nil && top.obj {
					top.expectKey = true
				}
				stack = append(stack, &jsonFrame{obj: t == '{', expectKey: t == '{'})
			default:
				out = append(out, closeFrame(top, b)...)
				stack = stack[:len(stack)-1]
				if len(stack) == 0 {
					return out, at + off, nil
				}
			}
		case string:
			start := tokenStart(s, at+prev)
			l := jsonLeaf{start: start + 1, end: at + off - 1, dec: t}
			if l.start > l.end {
				return nil, 0, errBound
			}
			l.raw = s[l.start:l.end]
			switch {
			case top == nil:
				return out, at + off, nil
			case top.obj && top.expectKey:
				top.key, top.expectKey = t, false
				continue
			case top.obj:
				if c, ok := keyCandidate(top.key, t, l.start, l.end); ok {
					out = append(out, c)
				}
				switch {
				case strings.EqualFold(top.key, "name") || strings.EqualFold(top.key, "key"):
					top.pairName, top.hasName = t, true
				case strings.EqualFold(top.key, "value"):
					top.values = append(top.values, l)
				}
				top.expectKey = true
			default:
				top.strs = append(top.strs, l)
			}
			if c, ok := leafCandidate(l.raw, l.dec, l.start, l.end, b); ok {
				out = append(out, c)
			}
		default:
			if top == nil {
				return out, at + off, nil
			}
			if top.obj {
				top.expectKey = true
			}
		}
	}
}

// tokenStart returns the first byte at or after i that is not a blank, ':' or
// ',': the start of the next JSON token.
func tokenStart(s string, i int) int {
	for i < len(s) && strings.IndexByte(" \t\r\n:,", s[i]) >= 0 {
		i++
	}
	return i
}

// closeFrame returns the candidates of a closed object (name/value pair) or
// array (secret split between strings).
func closeFrame(f *jsonFrame, b *budget) []candidate {
	var out []candidate
	if f == nil {
		return nil
	}
	if f.obj && f.hasName && sensitivePairName(f.pairName) {
		for _, v := range f.values {
			if !exemptGeneric(f.pairName, v.dec) && v.start < v.end {
				out = append(out, candidate{start: v.start, end: v.end, prio: prioOf(KindSensitiveVar)})
			}
		}
	}
	if len(f.strs) > 1 {
		var cat strings.Builder
		for _, l := range f.strs {
			cat.WriteString(l.dec)
		}
		if b.spend(cat.Len()) {
			if ms := findBudget(cat.String(), b); len(ms) > 0 {
				for _, l := range f.strs {
					if l.start < l.end {
						out = append(out, candidate{start: l.start, end: l.end, prio: prioOf(ms[0].Kind)})
					}
				}
			}
		}
	}
	return out
}

// yamlCandidates walks s as a YAML stream when every document of it has a
// mapping or a sequence at its root.
func yamlCandidates(s string, b *budget) []candidate {
	if strings.TrimSpace(s) == "" || !b.spend(len(s)) {
		return nil
	}
	lines, ascii := lineStarts(s)
	dec := yaml.NewDecoder(strings.NewReader(s))
	var out []candidate
	for range maxYAMLDocuments {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				return out
			}
			return nil
		}
		if len(doc.Content) != 1 || (doc.Content[0].Kind != yaml.MappingNode && doc.Content[0].Kind != yaml.SequenceNode) {
			return nil
		}
		w := yamlWalker{s: s, lines: lines, ascii: ascii, b: b}
		if !w.walk(doc.Content[0], 0) {
			return nil
		}
		out = append(out, w.out...)
	}
	return out
}

type yamlWalker struct {
	s     string
	lines []int
	ascii []bool
	b     *budget
	nodes int
	out   []candidate
}

// walk visits n; false when a bound is reached. Aliases are never followed.
func (w *yamlWalker) walk(n *yaml.Node, depth int) bool {
	if w.nodes++; w.nodes > MaxStructuredNodes || depth > MaxStructuredDepth || w.b.left < 0 {
		return false
	}
	switch n.Kind {
	case yaml.MappingNode:
		name, hasName := "", false
		var values []*yaml.Node
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if v.Kind == yaml.ScalarNode && k.Kind == yaml.ScalarNode {
				if st, en, ok := w.span(v); ok {
					if c, ok := keyCandidate(k.Value, v.Value, st, en); ok {
						w.out = append(w.out, c)
					}
				}
				switch {
				case strings.EqualFold(k.Value, "name") || strings.EqualFold(k.Value, "key"):
					name, hasName = v.Value, true
				case strings.EqualFold(k.Value, "value"):
					values = append(values, v)
				}
			}
			if !w.walk(v, depth+1) {
				return false
			}
		}
		if hasName && sensitivePairName(name) {
			for _, v := range values {
				if st, en, ok := w.span(v); ok && !exemptGeneric(name, v.Value) {
					w.out = append(w.out, candidate{start: st, end: en, prio: prioOf(KindSensitiveVar)})
				}
			}
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if !w.walk(c, depth+1) {
				return false
			}
		}
	case yaml.ScalarNode:
		if st, en, ok := w.span(n); ok {
			if c, ok := leafCandidate(w.s[st:en], n.Value, st, en, w.b); ok {
				w.out = append(w.out, c)
			}
		}
	}
	return true
}

// lineStarts returns the byte offset of the start of every line of s, and
// whether each line is ASCII (a column is then a byte offset).
func lineStarts(s string) ([]int, []bool) {
	starts, ascii := []int{0}, []bool{true}
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\n':
			starts, ascii = append(starts, i+1), append(ascii, true)
		case s[i] >= utf8.RuneSelf:
			ascii[len(ascii)-1] = false
		}
	}
	return starts, ascii
}

// lineEnd returns the offset of the end of line li (0-based), before '\n'.
func (w *yamlWalker) lineEnd(li int) int {
	if li+1 < len(w.lines) {
		return w.lines[li+1] - 1
	}
	return len(w.s)
}

// span returns the bytes of a scalar node: its value for a plain scalar
// written as is, the content between the quotes for a quoted scalar, the
// lines of a block scalar after their indentation; otherwise from its start
// to the end of its line.
func (w *yamlWalker) span(n *yaml.Node) (int, int, bool) {
	if n.Line < 1 || n.Line > len(w.lines) || n.Column < 1 {
		return 0, 0, false
	}
	ls, le := w.lines[n.Line-1], w.lineEnd(n.Line-1)
	start := ls + n.Column - 1
	if !w.ascii[n.Line-1] {
		if !w.b.spend(n.Column) { // a column counts runes: walk the line
			return 0, 0, false
		}
		start = ls
		for range n.Column - 1 {
			if start >= le {
				return 0, 0, false
			}
			_, size := utf8.DecodeRuneInString(w.s[start:])
			start += size
		}
	}
	if start > le {
		return 0, 0, false
	}
	switch {
	case n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) != 0 && start < len(w.s):
		if end, ok := quotedEnd(w.s, start); ok {
			return start + 1, end, start+1 < end
		}
	case n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0:
		return w.block(n.Line)
	case n.Value != "" && strings.HasPrefix(w.s[start:], n.Value):
		return start, start + len(n.Value), true
	}
	end := len(strings.TrimRight(w.s[start:le], " \t\r")) + start
	return start, end, start < end
}

// block returns the content of the block scalar whose indicator is on line
// (1-based): its more indented lines, from the indentation of the first.
func (w *yamlWalker) block(line int) (int, int, bool) {
	start, end, indent := -1, -1, -1
	for li := line; li < len(w.lines); li++ {
		ls, le := w.lines[li], w.lineEnd(li)
		text := w.s[ls:le]
		if strings.TrimSpace(text) == "" {
			continue
		}
		ind := len(text) - len(strings.TrimLeft(text, " \t"))
		if indent < 0 {
			indent, start = ind, ls+ind
		} else if ind < indent {
			break
		}
		end = len(strings.TrimRight(w.s[:le], " \t\r"))
	}
	return start, end, start >= 0 && start < end
}

// quotedEnd returns the offset of the closing quote of the YAML quoted
// scalar that opens at s[start]: '\' escapes in double quotes, ” in single.
func quotedEnd(s string, start int) (int, bool) {
	q := s[start]
	for i := start + 1; i < len(s); i++ {
		switch {
		case q == '"' && s[i] == '\\':
			i++
		case s[i] != q:
		case q == '\'' && i+1 < len(s) && s[i+1] == '\'':
			i++
		default:
			return i, true
		}
	}
	return 0, false
}

// placeholderLike: a placeholder, known kind or not, closed or not.
var placeholderLike = regexp.MustCompile(`\[REDACTED:([^\]\s\x00]{0,64})\]`)

// DisarmPlaceholders rewrites every placeholder of untrusted data so that no
// forged placeholder is taken for an existing redaction (T38): "[REDACTED:k]"
// becomes "(REDACTED:k)", and any other "[REDACTED:" becomes "(REDACTED:".
func DisarmPlaceholders(s string) string {
	if !strings.Contains(s, "[REDACTED:") {
		return s
	}
	s = placeholderLike.ReplaceAllString(s, "(REDACTED:$1)")
	return strings.ReplaceAll(s, "[REDACTED:", "(REDACTED:")
}
