package schema

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
	}
	return true
}
