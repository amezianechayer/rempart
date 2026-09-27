package schema

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
)

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
	return (c == 'u' || c == 'U' || c == 'x') && (isHex || d == '{')
}

// Texts returns the texts that the model reads in the decoded schema raw:
// every key, every string, and "key: value" for every member whose value is
// a string, so that a secret split by an escape (\", \n) or between a key and
// its value is visible to a secret scanner (T44, V2). raw is decoded as
// CompileSchema decodes it; an error wraps ErrInvalidSchema.
func Texts(raw json.RawMessage) ([]string, error) {
	if len(raw) > MaxSchemaBytes {
		return nil, fmt.Errorf("%w: too large", ErrInvalidSchema)
	}
	doc, reason := decodeStrict(raw)
	if reason != "" {
		return nil, fmt.Errorf("%w: %s", ErrInvalidSchema, reason)
	}
	var texts []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			texts = append(texts, x)
		case map[string]any:
			for _, k := range slices.Sorted(maps.Keys(x)) {
				texts = append(texts, k)
				if s, ok := x[k].(string); ok {
					texts = append(texts, k+": "+s)
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
	return texts, nil
}
