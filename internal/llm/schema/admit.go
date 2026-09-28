package schema

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
)

const maxTexts = 1 << 16

// AdmittedText reports whether every rune of s is in the closed list of T43:
// printable ASCII, a line feed, or a French letter (U+00C0 to U+00FF but
// U+00D7 and U+00F7, U+0152, U+0153, U+0178). Invalid UTF-8 decodes to
// U+FFFD, which is not in the list.
func AdmittedText(s string) bool {
	for _, r := range s {
		switch {
		case r >= ' ' && r <= '~', r == '\n':
		case r >= 0xC0 && r <= 0xFF && r != 0xD7 && r != 0xF7, r == 0x152, r == 0x153, r == 0x178:
		default:
			return false
		}
	}
	return true
}

// admittedRaw reports whether the raw bytes of a schema are the text the model
// reads: every byte is admitted, so no tab or carriage return between tokens,
// and the only JSON escapes are \", \\ and \n, so that no text hides behind an
// escape from a reviewer or a secret scanner (a secret written \u0041KIA...).
func admittedRaw(raw []byte) bool {
	if !AdmittedText(string(raw)) {
		return false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if i == len(raw) || raw[i] != '"' && raw[i] != '\\' && raw[i] != 'n' {
			return false
		}
		if raw[i] == '\\' && i+2 < len(raw) && escapeLike(raw[i+1], raw[i+2]) {
			return false
		}
	}
	return true
}

// escapeLike reports whether a decoded backslash followed by c and d reads
// as an escape of another text (\u0041, \x41, \U0001F600, \x{41}): a model
// could read the character, a reviewer or a secret scanner does not (V2).
func escapeLike(c, d byte) bool {
	isHex := d >= '0' && d <= '9' || d >= 'a' && d <= 'f' || d >= 'A' && d <= 'F'
	return (c == 'u' || c == 'U' || c == 'x') && (isHex || d == '{') || c >= '0' && c <= '9'
}

// Texts returns the texts that the model reads in the decoded schema raw:
// every key, every string, and "key: value" for every member whose value is
// a string, so that a secret split by an escape (\", \n) or between a key and
// its value is visible to a secret scanner (T44, V2). A const, enum or
// pattern under a property or definition name, through items, anyOf, oneOf
// and $ref, is also read as "name: value", and a value starting with blanks
// also without them (D8). raw is decoded as CompileSchema decodes it; more
// than maxTexts texts, or any other error, wraps ErrInvalidSchema.
func Texts(raw json.RawMessage) ([]string, error) {
	if len(raw) > MaxSchemaBytes {
		return nil, fmt.Errorf("%w: too large", ErrInvalidSchema)
	}
	doc, reason := decodeStrict(raw)
	if reason != "" {
		return nil, fmt.Errorf("%w: %s", ErrInvalidSchema, reason)
	}
	var texts []string
	full := func() bool { return len(texts) > maxTexts } // stop early: the fan out through $ref is multiplicative
	add := func(k, s string) {
		texts = append(texts, k+": "+s)
		if t := strings.TrimLeft(s, " \n"); t != s {
			texts = append(texts, k+": "+t)
		}
	}
	root, _ := doc.(map[string]any)
	defs, _ := root["$defs"].(map[string]any)
	seen := map[[2]string]bool{}
	var named func(name string, v any)
	named = func(name string, v any) {
		n, ok := v.(map[string]any)
		if !ok || full() {
			return
		}
		if s, ok := n["const"].(string); ok {
			add(name, s)
		}
		if list, ok := n["enum"].([]any); ok {
			for _, e := range list {
				if s, ok := e.(string); ok {
					add(name, s)
				}
			}
		}
		if p, ok := n["pattern"].(string); ok {
			add(name, p)
			add(name, strings.TrimSuffix(strings.TrimPrefix(p, "^"), "$"))
		}
		if ref, ok := n["$ref"].(string); ok {
			if d, ok := strings.CutPrefix(ref, "#/$defs/"); ok && !seen[[2]string{name, d}] {
				seen[[2]string{name, d}] = true
				named(name, defs[d])
			}
		}
		named(name, n["items"])
		for _, k := range []string{"anyOf", "oneOf"} {
			if list, ok := n[k].([]any); ok {
				for _, e := range list {
					named(name, e)
				}
			}
		}
	}
	var walk func(v any)
	walk = func(v any) {
		if full() {
			return
		}
		switch x := v.(type) {
		case string:
			texts = append(texts, x)
		case map[string]any:
			for _, k := range []string{"properties", "$defs"} {
				if m, ok := x[k].(map[string]any); ok {
					for _, name := range slices.Sorted(maps.Keys(m)) {
						named(name, m[name])
					}
				}
			}
			for _, k := range slices.Sorted(maps.Keys(x)) {
				texts = append(texts, k)
				if s, ok := x[k].(string); ok {
					add(k, s)
				}
				walk(x[k])
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(doc)
	if len(texts) > maxTexts {
		return nil, fmt.Errorf("%w: too many texts", ErrInvalidSchema)
	}
	return texts, nil
}
