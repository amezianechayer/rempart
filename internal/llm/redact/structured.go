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

// leafCandidate masks a whole leaf [start, end) of raw form raw and decoded
// form dec when dec holds a secret that the redaction of raw leaves in its
// decoded form. When the regular expressions on raw suffice, their precise
// masks are kept.
//
// The regular expressions read the JSON escapes of raw ("\n", "\t", "\"",
// "\\"): a leaf is decoded again only when it may hide something they
// cannot read (a structure, a "\u" or "\/" escape). A placeholder that
// appears only in the decoded form was forged by escapes (T38): the leaf is
// masked whole, as when the nesting or the budget is exhausted (T83).
func leafCandidate(raw, dec string, start, end int, b *budget) (candidate, bool) {
	if raw == dec || start >= end {
		return candidate{}, false
	}
	forged := strings.Count(dec, "[REDACTED:") > strings.Count(raw, "[REDACTED:")
	if !forged && !strings.ContainsAny(dec, "{[") && !strings.Contains(raw, `\u`) && !strings.Contains(raw, `\/`) {
		return candidate{}, false
	}
	whole := mask(start, end, KindSensitiveVar)
	if forged || b.depth >= maxNesting || !b.spend(nestedCost*len(raw)) {
		return whole, true
	}
	var again string
	if json.Unmarshal([]byte(`"`+redactRules(raw)+`"`), &again) != nil {
		return whole, true
	}
	b.depth++
	ms := findBudget(again, b)
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
	return append(out, yamlCandidates(s, b)...)
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
			if top.obj && top.expectKey {
				top.key, top.expectKey = t, false
				continue
			}
			start := tokenStart(w.s, at+prev) + 1
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
	if c, ok := leafCandidate(w.s[l.start:l.end], l.dec, l.start, l.end, w.b); ok {
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

// yamlCandidates walks s as a YAML stream when every document of it has a
// mapping or a sequence at its root. A bound reached masks the whole text.
func yamlCandidates(s string, b *budget) []candidate {
	if strings.TrimSpace(s) == "" || !b.spend(len(s)) {
		return nil
	}
	lines, ascii := lineStarts(s)
	dec := yaml.NewDecoder(strings.NewReader(s))
	var out []candidate
	for docs := 0; ; docs++ {
		if docs == maxYAMLDocuments { // a bound reached masks the whole text
			return []candidate{mask(0, len(s), KindSensitiveVar)}
		}
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
		if !w.walk(doc.Content[0], 0, "") {
			return []candidate{mask(0, len(s), KindSensitiveVar)}
		}
		out = append(out, w.out...)
	}
}

type yamlWalker struct {
	s     string
	lines []int
	ascii []bool
	b     *budget
	out   []candidate
}

// walk visits n; sens is the Kind every scalar below is masked as ("" for
// none). It returns false when a bound is reached. Aliases are never followed.
func (w *yamlWalker) walk(n *yaml.Node, depth int, sens Kind) bool {
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
			if !w.walk(v, depth+1, child) {
				return false
			}
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if !w.walk(c, depth+1, sens) {
				return false
			}
		}
	case yaml.AliasNode:
		// The anchor of an alias under a sensitive key is masked where it is
		// defined: the model could resolve the alias.
		if a := n.Alias; sens != "" && a != nil && a.Kind == yaml.ScalarNode {
			if st, en, ok := w.span(a); ok {
				w.out = append(w.out, mask(st, en, sens))
			}
		}
	case yaml.ScalarNode:
		st, en, ok := w.span(n)
		if !ok {
			return true
		}
		if sens != "" {
			w.out = append(w.out, mask(st, en, sens))
		}
		if c, ok := leafCandidate(w.s[st:en], n.Value, st, en, w.b); ok {
			w.out = append(w.out, c)
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
	// Tags and anchors before the value ("!!str", "&a").
	for start < le && (w.s[start] == '!' || w.s[start] == '&') {
		for start < le && w.s[start] != ' ' && w.s[start] != '\t' {
			start++
		}
		start = afterBlanks(w.s[:le], start)
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
	case n.Style == 0:
		return start, w.continued(n.Line, start), true
	}
	end := len(strings.TrimRight(w.s[start:le], " \t\r")) + start
	return start, end, start < end
}

// continued returns the end of a plain scalar that starts at start on line
// (1-based) and continues on the following lines more indented than that
// line.
func (w *yamlWalker) continued(line, start int) int {
	head := w.s[w.lines[line-1]:w.lineEnd(line-1)]
	indent := len(head) - len(strings.TrimLeft(head, " \t"))
	end := len(strings.TrimRight(w.s[:w.lineEnd(line-1)], " \t\r"))
	for li := line; li < len(w.lines); li++ {
		text := w.s[w.lines[li]:w.lineEnd(li)]
		if strings.TrimSpace(text) == "" {
			continue
		}
		if len(text)-len(strings.TrimLeft(text, " \t")) <= indent {
			break
		}
		end = len(strings.TrimRight(w.s[:w.lineEnd(li)], " \t\r"))
	}
	return max(end, start)
}

// block returns the content of the block scalar whose indicator is on line
// (1-based): the following lines more indented than that line, from the
// indentation of the first.
func (w *yamlWalker) block(line int) (int, int, bool) {
	head := w.s[w.lines[line-1]:w.lineEnd(line-1)]
	keyIndent := len(head) - len(strings.TrimLeft(head, " \t"))
	start, end, indent := -1, -1, -1
	for li := line; li < len(w.lines); li++ {
		ls, le := w.lines[li], w.lineEnd(li)
		text := w.s[ls:le]
		if strings.TrimSpace(text) == "" {
			continue
		}
		ind := len(text) - len(strings.TrimLeft(text, " \t"))
		if ind <= keyIndent || indent >= 0 && ind < indent {
			break // content is more indented than the line of its indicator
		}
		if indent < 0 {
			indent, start = ind, ls+ind
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
