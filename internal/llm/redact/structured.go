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
//   - A sensitive key (the key names of every keyed rule, with their Kind)
//     masks its value; under it, every string of an object or array value.
//   - A name/value pair (name, key, ParameterKey, OptionName) whose name, or
//     the last segment of its path (SSM), is sensitive masks its value.
//   - Typed secrets: the data and stringData of a Kubernetes Secret, the value
//     of an object with "sensitive": true (OpenTofu).
//   - A leaf whose decoded form keeps a secret after the redaction of its raw
//     form (escapes, nested encodings, T69) is masked whole; a placeholder
//     that appears only in the decoded form is disarmed first (T38).
//   - An array of strings whose concatenation holds a secret masks its
//     strings.
//
// Bounds never fail open (T81, T98): the work budget exhausted masks the rest
// of the text; a YAML document deeper than MaxStructuredDepth, or a panic of a
// decoder, masks the whole text. YAML aliases are never followed.
const (
	MaxStructuredDepth = 64 // YAML nesting
	maxYAMLDocuments   = 64
	budgetPerByte      = 80 // work units per byte of input, nested encodings included
	budgetBase         = 1 << 16
	yamlNodeCost       = 16
	// maxNesting: JSON strings decoded inside JSON strings; deeper, a leaf
	// that may hide something is masked whole (T83).
	maxNesting = 2
	// nestedCost: work units per byte of a nested pass (the regular
	// expressions and the structured pass on a decoded leaf).
	nestedCost = 64
	// leafCost: fixed work units of one nested pass (decoders, expressions).
	leafCost = 2048
)

// budget bounds the work of the structured pass on one input (T81).
type budget struct{ left, depth int }

func newBudget(n int) *budget { return &budget{left: budgetPerByte*n + budgetBase} }

func (b *budget) spend(n int) bool {
	b.left -= n
	return b.left >= 0
}

var (
	// extraKeys: keys whose value is a secret, read by no keyed rule.
	extraKeys = regexp.MustCompile(`(?i)^(?:cookie|set-cookie|credentials?|jwt|connection_?string|account_?key` +
		`|(?:primary|secondary)_?(?:readonly_?)?(?:master_?)?key)$`)
	// pairNameKeys, pairValueKeys: the fields of a name/value pair.
	pairNameKeys  = regexp.MustCompile(`(?i)^(?:name|key|parameterkey|optionname)$`)
	pairValueKeys = regexp.MustCompile(`(?i)^(?:value|parametervalue|optionvalue)$`)
	typedKeys     = regexp.MustCompile(`(?i)^(?:data|stringdata)$`)
)

// sensitiveKey returns the Kind of the value of key, and whether key is
// sensitive and not exempt for value.
func sensitiveKey(key, value string) (Kind, bool) {
	for _, ru := range rules {
		if ru.whole == nil || !ru.whole.MatchString(key) {
			continue
		}
		if ru.exempt != nil && ru.exempt(key, value) {
			return "", false
		}
		return ru.kind, true
	}
	if extraKeys.MatchString(key) {
		return KindSensitiveVar, true
	}
	return "", false
}

// sensitivePairName reports whether the name of a name/value pair, or the
// last segment of its path (SSM parameter), is sensitive.
func sensitivePairName(n string) bool {
	for _, seg := range strings.Split(n, "/") {
		if pairName.MatchString(seg) {
			return true
		}
		if _, ok := sensitiveKey(seg, ""); ok {
			return true
		}
	}
	return false
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

func mask(start, end int, k Kind) candidate {
	return candidate{start: start, end: end, prio: prioOf(k)}
}

// safeEscape reports whether the JSON escape that starts at raw[i] ('\\') is
// one the regular expressions read in raw form: quote, backslash, slash,
// tab, line breaks, and the escapes of '<', '>' and '&' of json.Marshal. It
// returns the length of the escape.
func safeEscape(raw string, i int) (int, bool) {
	if i+1 >= len(raw) {
		return 0, false
	}
	switch raw[i+1] {
	case '"', '\\', '/', 't', 'n', 'r':
		return 2, true
	case 'u':
		if i+6 <= len(raw) {
			switch strings.ToLower(raw[i+2 : i+6]) {
			case "003c", "003e", "0026":
				return 6, true
			}
		}
	}
	return 0, false
}

// onlySafeEscapes reports whether every escape of raw is a safe one.
func onlySafeEscapes(raw string) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		n, ok := safeEscape(raw, i)
		if !ok {
			return false
		}
		i += n - 1
	}
	return true
}

// jsonLeafCandidate masks a whole JSON string [start, end) of raw content raw
// and decoded value dec when dec holds a secret the regular expressions on
// raw do not mask (fail closed by default, second review of M1-T08):
//   - a placeholder that appears only in dec was forged by escapes (T38);
//   - with safe escapes only, a value without structure nor line break is
//     read by the regular expressions as is; otherwise raw is redacted, then
//     decoded, and any secret left masks the whole leaf;
//   - with any other escape (\b, \f, \uXXXX), any secret of dec masks the
//     whole leaf.
//
// Nesting or budget exhausted masks the whole leaf (T83).
func jsonLeafCandidate(raw, dec string, start, end int, b *budget) (candidate, bool) {
	if raw == dec || start >= end {
		return candidate{}, false
	}
	whole := mask(start, end, KindSensitiveVar)
	if strings.Count(dec, "[REDACTED:") > strings.Count(raw, "[REDACTED:") {
		return whole, true
	}
	safe := onlySafeEscapes(raw)
	if safe && !strings.ContainsAny(dec, "{[\n\r") && !strings.ContainsAny(raw, "\n\r") {
		return candidate{}, false
	}
	if b.depth >= maxNesting || !b.spend(leafCost+nestedCost*len(raw)) {
		return whole, true
	}
	probe := dec
	if safe {
		if json.Unmarshal([]byte(`"`+redactRules(raw)+`"`), &probe) != nil {
			return whole, true
		}
	}
	return nestedPass(probe, whole, b)
}

// yamlLeafCandidate masks a whole YAML scalar whose source differs from its
// value (escapes, folding, quotes) when the value holds a secret.
func yamlLeafCandidate(raw, dec string, start, end int, b *budget) (candidate, bool) {
	if raw == dec || start >= end {
		return candidate{}, false
	}
	whole := mask(start, end, KindSensitiveVar)
	if strings.Count(dec, "[REDACTED:") > strings.Count(raw, "[REDACTED:") ||
		b.depth >= maxNesting || !b.spend(leafCost+nestedCost*len(raw)) {
		return whole, true
	}
	return nestedPass(dec, whole, b)
}

// nestedPass runs the whole redaction on a decoded leaf: whole if it finds a
// secret.
func nestedPass(s string, whole candidate, b *budget) (candidate, bool) {
	b.depth++
	ms := findBudget(s, b)
	b.depth--
	if len(ms) == 0 {
		return candidate{}, false
	}
	whole.prio = prioOf(ms[0].Kind)
	return whole, true
}

// redactRules is Redact with the regular expressions only.
func redactRules(s string) string {
	s = denul(s)
	ms := findRules(s)
	var out strings.Builder
	prev := 0
	for _, m := range ms {
		out.WriteString(s[prev:m.Start])
		out.WriteString(Placeholder(m.Kind))
		prev = m.End
	}
	out.WriteString(s[prev:])
	return out.String()
}

// structured returns the candidates of the structured pass on s; a panic of a
// decoder masks the whole text.
func structured(s string, b *budget) (out []candidate) {
	defer func() {
		if recover() != nil {
			out = []candidate{mask(0, len(s), KindSensitiveVar)}
		}
	}()
	out = jsonCandidates(s, b)
	out = append(out, yamlCandidates(s, b)...)
	if b.left < 0 { // any bound reached masks, whatever the pass (T81, T98)
		return []candidate{mask(0, len(s), KindSensitiveVar)}
	}
	return out
}

// jsonLeaf is a string value of a JSON document: the bounds of its content
// (inside the quotes) and its decoded value.
type jsonLeaf struct {
	start, end int
	dec        string
}

// leafRange is a range of indexes of jsonWalk.leaves: the string values of a
// subtree, in order.
type leafRange struct{ from, to int }

type jsonFrame struct {
	obj, expectKey bool
	key            string // current key of an object
	parentKey      string // key of this value in its parent object
	sensitive      bool   // every string value below is masked
	kind           Kind
	first          int // index of the first leaf of the subtree
	pairName       string
	hasName        bool
	isSecret       bool // "kind": "Secret"
	sensTrue       bool // "sensitive": true
	values, typed  []leafRange
	strs           []int // direct string elements of an array
}

type jsonWalk struct {
	s      string
	b      *budget
	leaves []jsonLeaf
	out    []candidate
}

// jsonCandidates tries a JSON value at every '{' or '[' of s; after a failure
// the scan resumes at the failure point (the subtrees closed before it were
// read), so that the work is linear in the size of s.
func jsonCandidates(s string, b *budget) []candidate {
	w := &jsonWalk{s: s, b: b}
	for i := 0; i < len(s); i++ {
		if s[i] != '{' && s[i] != '[' {
			continue
		}
		next := w.document(i)
		if b.left < 0 {
			return append(w.out, mask(i, len(s), KindSensitiveVar))
		}
		if next > i+1 {
			i = next - 1
		}
	}
	return w.out
}

// document walks the JSON value at s[at] and returns the offset where the
// scan resumes: its end, or its failure point.
func (w *jsonWalk) document(at int) int {
	dec := json.NewDecoder(strings.NewReader(w.s[at:]))
	var stack []*jsonFrame
	for {
		prev := int(dec.InputOffset())
		tok, err := dec.Token()
		off := int(dec.InputOffset())
		if err != nil {
			// The containers still open are evaluated: their pairs and
			// names were read before the failure.
			for i := len(stack) - 1; i >= 0; i-- {
				w.close(stack[i], stack[:i+1])
			}
			var se *json.SyntaxError
			switch {
			case errors.As(err, &se) && int(se.Offset) > 0:
				off = int(se.Offset) - 1
			case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
				off = len(w.s) - at
			}
			w.b.spend(off)
			return at + max(off, 1)
		}
		if !w.b.spend(off - prev) {
			return at + off
		}
		var top *jsonFrame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		switch t := tok.(type) {
		case json.Delim:
			if t == '{' || t == '[' {
				stack = append(stack, w.open(top, t == '{'))
				continue
			}
			w.close(top, stack)
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return at + off
			}
		case string:
			if top == nil {
				return at + off
			}
			start := tokenStart(w.s, at+prev) + 1
			if top.obj && top.expectKey {
				top.key, top.expectKey = t, false
				if end := at + off - 1; start <= end && end <= len(w.s) {
					if c, ok := jsonLeafCandidate(w.s[start:end], t, start, end, w.b); ok {
						w.out = append(w.out, c)
					}
				}
				continue
			}
			w.value(top, jsonLeaf{start: start, end: at + off - 1, dec: t})
		default:
			if top == nil {
				return at + off
			}
			if top.obj {
				if v, ok := t.(bool); ok && v && strings.EqualFold(top.key, "sensitive") {
					top.sensTrue = true
				}
				top.expectKey = true
			}
		}
	}
}

// open starts a frame below top.
func (w *jsonWalk) open(top *jsonFrame, obj bool) *jsonFrame {
	f := &jsonFrame{obj: obj, expectKey: obj, first: len(w.leaves)}
	if top == nil {
		return f
	}
	f.sensitive, f.kind = top.sensitive, top.kind
	if top.obj {
		f.parentKey = top.key
		if k, ok := sensitiveKey(top.key, ""); ok && !f.sensitive {
			f.sensitive, f.kind = true, k
		}
		top.expectKey = true
	}
	return f
}

// value handles a string value of top.
func (w *jsonWalk) value(top *jsonFrame, l jsonLeaf) {
	if l.start > l.end || l.end > len(w.s) {
		return
	}
	idx := len(w.leaves)
	w.leaves = append(w.leaves, l)
	if top.sensitive && l.start < l.end {
		w.out = append(w.out, mask(l.start, l.end, top.kind))
	}
	if top.obj {
		if k, ok := sensitiveKey(top.key, l.dec); ok && l.start < l.end {
			w.out = append(w.out, mask(l.start, l.end, k))
		}
		switch {
		case pairNameKeys.MatchString(top.key):
			top.pairName, top.hasName = l.dec, true
		case pairValueKeys.MatchString(top.key):
			top.values = append(top.values, leafRange{idx, idx + 1})
		case typedKeys.MatchString(top.key):
			top.typed = append(top.typed, leafRange{idx, idx + 1})
		case strings.EqualFold(top.key, "kind") && l.dec == "Secret":
			top.isSecret = true
		case strings.EqualFold(top.key, "type") && l.dec == "SecureString", strings.EqualFold(top.key, "keyname"):
			top.sensTrue = true // SSM SecureString, Azure listKeys: the value is a secret
		}
		top.expectKey = true
	} else {
		top.strs = append(top.strs, idx)
	}
	if c, ok := jsonLeafCandidate(w.s[l.start:l.end], l.dec, l.start, l.end, w.b); ok {
		w.out = append(w.out, c)
	}
}

// close emits the candidates of a closed frame f and hands its subtree to its
// parent.
func (w *jsonWalk) close(f *jsonFrame, stack []*jsonFrame) {
	emit := func(ranges []leafRange, name string) {
		for _, r := range ranges {
			for _, l := range w.leaves[r.from:r.to] {
				if !w.b.spend(l.end-l.start+1) || l.start >= l.end || exemptGeneric(name, l.dec) {
					continue
				}
				w.out = append(w.out, mask(l.start, l.end, KindSensitiveVar))
			}
		}
	}
	if f.hasName && sensitivePairName(f.pairName) {
		emit(f.values, f.pairName)
	}
	if f.sensTrue {
		emit(f.values, "")
	}
	if f.isSecret {
		emit(f.typed, "")
	}
	if len(f.strs) > 1 {
		var cat strings.Builder
		for _, i := range f.strs {
			cat.WriteString(w.leaves[i].dec)
		}
		if w.b.spend(cat.Len()) {
			if ms := findRules(cat.String()); len(ms) > 0 {
				for _, i := range f.strs {
					if l := w.leaves[i]; l.start < l.end {
						w.out = append(w.out, mask(l.start, l.end, ms[0].Kind))
					}
				}
			}
		}
	}
	if len(stack) < 2 {
		return
	}
	parent, sub := stack[len(stack)-2], leafRange{f.first, len(w.leaves)}
	switch {
	case !parent.obj:
	case pairValueKeys.MatchString(f.parentKey):
		parent.values = append(parent.values, sub)
	case typedKeys.MatchString(f.parentKey):
		parent.typed = append(parent.typed, sub)
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

// yamlCandidates walks s as a YAML stream when its documents have a mapping
// or a sequence at their root. Any bound reached, and any position that does
// not match the source, masks the whole text (fail closed, T98).
func yamlCandidates(s string, b *budget) []candidate {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	if !b.spend(len(s)) {
		return []candidate{mask(0, len(s), KindSensitiveVar)}
	}
	lines := newLines(s)
	dec := yaml.NewDecoder(strings.NewReader(s))
	var out []candidate
	for docs := 0; ; docs++ {
		if docs == maxYAMLDocuments {
			return []candidate{mask(0, len(s), KindSensitiveVar)}
		}
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			return out // io.EOF, or not YAML: the other passes read the text
		}
		if len(doc.Content) != 1 || (doc.Content[0].Kind != yaml.MappingNode && doc.Content[0].Kind != yaml.SequenceNode) {
			return out
		}
		w := yamlWalker{s: s, l: lines, b: b}
		if !w.walk(doc.Content[0], 0, "", -1) {
			return []candidate{mask(0, len(s), KindSensitiveVar)}
		}
		out = append(out, w.out...)
	}
}

// yamlLines splits the text like the YAML decoder: line breaks "\r\n", "\r",
// "\n", U+0085, U+2028, U+2029; a leading byte order mark is not a column.
type yamlLines struct {
	starts, ends []int
	ascii        []bool // a column is then a byte offset
}

const byteOrderMark = "\xef\xbb\xbf"

func newLines(s string) yamlLines {
	l := yamlLines{starts: []int{0}, ascii: []bool{true}}
	if strings.HasPrefix(s, byteOrderMark) {
		l.starts[0] = len(byteOrderMark)
	}
	for i := l.starts[0]; i < len(s); {
		n := lineBreak(s, i)
		if n == 0 {
			if s[i] >= utf8.RuneSelf {
				l.ascii[len(l.ascii)-1] = false
			}
			i++
			continue
		}
		l.ends = append(l.ends, i)
		i += n
		l.starts, l.ascii = append(l.starts, i), append(l.ascii, true)
	}
	l.ends = append(l.ends, len(s))
	return l
}

// lineBreak returns the length of the YAML line break at s[i], 0 if none.
func lineBreak(s string, i int) int {
	switch {
	case strings.HasPrefix(s[i:], "\r\n"), strings.HasPrefix(s[i:], "\xc2\x85"):
		return 2
	case s[i] == '\r', s[i] == '\n':
		return 1
	case strings.HasPrefix(s[i:], "\xe2\x80\xa8"), strings.HasPrefix(s[i:], "\xe2\x80\xa9"):
		return 3
	}
	return 0
}

// indent returns the indentation of line li (0-based).
func (l yamlLines) indent(s string, li int) int {
	text := s[l.starts[li]:l.ends[li]]
	return len(text) - len(strings.TrimLeft(text, " \t"))
}

// trimmedEnd returns the end of line li without trailing blanks.
func (l yamlLines) trimmedEnd(s string, li int) int {
	return len(strings.TrimRight(s[:l.ends[li]], " \t"))
}

type yamlWalker struct {
	s   string
	l   yamlLines
	b   *budget
	out []candidate
}

// walk visits n; sens is the Kind every scalar below is masked as ("" for
// none), ref the indentation of the line of its key (-1 for none). It returns
// false when a bound is reached or a position does not match the source.
// Aliases are never followed; the anchor of a scalar alias under a sensitive
// key is masked where it is defined.
func (w *yamlWalker) walk(n *yaml.Node, depth int, sens Kind, ref int) bool {
	if depth > MaxStructuredDepth || !w.b.spend(yamlNodeCost) {
		return false
	}
	switch n.Kind {
	case yaml.MappingNode:
		var name string
		var hasName, isSecret, sensTrue bool
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if v.Kind != yaml.ScalarNode {
				continue
			}
			switch {
			case pairNameKeys.MatchString(k.Value):
				name, hasName = v.Value, true
			case strings.EqualFold(k.Value, "kind") && v.Value == "Secret":
				isSecret = true
			case strings.EqualFold(k.Value, "sensitive") && v.Tag == "!!bool" && strings.EqualFold(v.Value, "true"),
				strings.EqualFold(k.Value, "type") && v.Value == "SecureString", strings.EqualFold(k.Value, "keyname"):
				sensTrue = true
			}
		}
		pair := hasName && sensitivePairName(name)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			keyRef := -1
			if k.Kind == yaml.ScalarNode {
				if !w.scalar(k, "", -1) {
					return false
				}
				if k.Line >= 1 && k.Line <= len(w.l.starts) {
					keyRef = w.l.indent(w.s, k.Line-1)
				}
			}
			child := sens
			if kind, ok := sensitiveKey(k.Value, v.Value); ok && child == "" {
				child = kind
			}
			switch {
			case child != "":
			case pairValueKeys.MatchString(k.Value) && (sensTrue || pair && !exemptGeneric(name, v.Value)):
				child = KindSensitiveVar
			case typedKeys.MatchString(k.Value) && isSecret:
				child = KindSensitiveVar
			}
			if !w.walk(v, depth+1, child, keyRef) {
				return false
			}
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if !w.walk(c, depth+1, sens, -1) {
				return false
			}
		}
	case yaml.AliasNode:
		if a := n.Alias; sens != "" && a != nil && a.Kind == yaml.ScalarNode {
			return w.scalar(a, sens, -1)
		}
	case yaml.ScalarNode:
		return w.scalar(n, sens, ref)
	}
	return true
}

// scalar masks the scalar n as sens (if any) and checks its value as a leaf.
func (w *yamlWalker) scalar(n *yaml.Node, sens Kind, ref int) bool {
	st, en, status := w.span(n, ref)
	switch status {
	case spanBad:
		return false
	case spanEmpty:
		return true
	}
	if sens != "" {
		w.out = append(w.out, mask(st, en, sens))
	}
	leaf := yamlLeafCandidate
	if n.Style&yaml.DoubleQuotedStyle != 0 {
		leaf = jsonLeafCandidate // JSON escapes are YAML double-quoted escapes: same reading
	}
	if c, ok := leaf(w.s[st:en], n.Value, st, en, w.b); ok {
		w.out = append(w.out, c)
	}
	return true
}

const (
	spanOK = iota
	spanEmpty
	spanBad // the position does not match the source: mask the whole text
)

// column returns the offset of the 1-based column col of line li.
func (w *yamlWalker) column(li, col int) (int, bool) {
	ls, le := w.l.starts[li], w.l.ends[li]
	if w.l.ascii[li] {
		return ls + col - 1, ls+col-1 <= le
	}
	if !w.b.spend(col) { // a column counts runes: walk the line
		return 0, false
	}
	start := ls
	for range col - 1 {
		if start >= le {
			return 0, false
		}
		_, size := utf8.DecodeRuneInString(w.s[start:le])
		start += size
	}
	return start, true
}

// span returns the bytes of a scalar node, checked against the source: the
// content between the quotes of a quoted scalar, the content lines of a
// block scalar, the value of a plain scalar, continued on the following
// lines more indented than ref (or than its own line) when it is folded.
func (w *yamlWalker) span(n *yaml.Node, ref int) (int, int, int) {
	li := n.Line - 1
	if li < 0 || li >= len(w.l.starts) || n.Column < 1 {
		return 0, 0, spanBad
	}
	start, ok := w.column(li, n.Column)
	if !ok {
		return 0, 0, spanBad
	}
	// Tags and anchors before the value ("!!str", "&a"), perhaps alone on
	// their line.
	for start < w.l.ends[li] && (w.s[start] == '!' || w.s[start] == '&') {
		for start < w.l.ends[li] && w.s[start] != ' ' && w.s[start] != '\t' && w.s[start] != '"' && w.s[start] != '\'' {
			start++
		}
		start = afterBlanks(w.s[:w.l.ends[li]], start)
		for start >= w.l.ends[li] && li+1 < len(w.l.starts) {
			li++
			start = w.l.starts[li] + w.l.indent(w.s, li)
		}
	}
	quoted := n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) != 0
	block := n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0
	switch {
	case quoted:
		q := byte('"')
		if n.Style&yaml.SingleQuotedStyle != 0 {
			q = '\''
		}
		if start >= len(w.s) || w.s[start] != q {
			return 0, 0, spanBad
		}
		end, ok := quotedEnd(w.s, start)
		if !ok {
			return 0, 0, spanBad
		}
		if start+1 == end {
			return 0, 0, spanEmpty
		}
		return start + 1, end, spanOK
	case block:
		if start >= len(w.s) || (w.s[start] != '|' && w.s[start] != '>') {
			return 0, 0, spanBad
		}
		st, en, ok := w.block(li, ref)
		if !ok {
			return 0, 0, spanEmpty
		}
		return st, en, spanOK
	case n.Value == "":
		return 0, 0, spanEmpty
	case start >= len(w.s) || w.s[start] != n.Value[0]:
		return 0, 0, spanBad
	case strings.HasPrefix(w.s[start:w.l.ends[li]], n.Value):
		return start, start + len(n.Value), spanOK
	}
	return start, max(w.continued(li, ref), start+1), spanOK
}

// continued returns the end of a folded plain scalar that starts on line li
// (0-based): the following lines more indented than ref (or than line li).
func (w *yamlWalker) continued(li, ref int) int {
	indent := ref
	if indent < 0 {
		indent = w.l.indent(w.s, li)
	}
	end := w.l.trimmedEnd(w.s, li)
	for lj := li + 1; lj < len(w.l.starts); lj++ {
		if strings.TrimSpace(w.s[w.l.starts[lj]:w.l.ends[lj]]) == "" {
			continue
		}
		if w.l.indent(w.s, lj) <= indent {
			break
		}
		end = w.l.trimmedEnd(w.s, lj)
	}
	return end
}

// block returns the content of the block scalar whose indicator is on line
// li (0-based): the following lines more indented than ref (or than line li),
// from the indentation of the first.
func (w *yamlWalker) block(li, ref int) (int, int, bool) {
	keyIndent := ref
	if keyIndent < 0 {
		keyIndent = w.l.indent(w.s, li)
	}
	start, end, indent := -1, -1, -1
	for lj := li + 1; lj < len(w.l.starts); lj++ {
		if strings.TrimSpace(w.s[w.l.starts[lj]:w.l.ends[lj]]) == "" {
			continue
		}
		ind := w.l.indent(w.s, lj)
		if ind <= keyIndent || indent >= 0 && ind < indent {
			break // content is more indented than the line of its key
		}
		if indent < 0 {
			indent, start = ind, w.l.starts[lj]+ind
		}
		end = w.l.trimmedEnd(w.s, lj)
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

// placeholderLike: a placeholder, known kind or not, closed.
var placeholderLike = regexp.MustCompile(`\[REDACTED:([^\]\s\x00]{0,64})\]`)

// DisarmPlaceholders rewrites every placeholder of untrusted data so that no
// forged placeholder is taken for an existing redaction (T38): "[REDACTED:k]"
// becomes "(REDACTED:k)" (same length), and any other "[REDACTED:" becomes
// "(REDACTED:".
func DisarmPlaceholders(s string) string {
	if !strings.Contains(s, "[REDACTED:") {
		return s
	}
	s = placeholderLike.ReplaceAllString(s, "(REDACTED:$1)")
	return strings.ReplaceAll(s, "[REDACTED:", "(REDACTED:")
}
