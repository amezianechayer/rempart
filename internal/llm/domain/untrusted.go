package domain

import "strings"

const (
	untrustedOpenPrefix = "<DONNÉES_NON_FIABLES id=\""
	untrustedClose      = "</DONNÉES_NON_FIABLES>"
	maxSourceIDLen      = 128
)

// untrustedEscaper removes every character able to open or close a tag.
var untrustedEscaper = strings.NewReplacer(
	"&", "&amp;", "<", "&lt;", ">", "&gt;",
	"＜", "&#xFF1C;", "＞", "&#xFF1E;",
	"﹤", "&#xFE64;", "﹥", "&#xFE65;",
)

// RenderUntrusted is the only rendering of untrusted data, shared by all
// adapters: the content can hold no tag at all and the source id is filtered.
func RenderUntrusted(b UntrustedBlock) string {
	content := untrustedEscaper.Replace(strings.ToValidUTF8(b.Content, "�"))
	return untrustedOpenPrefix + sanitizeSourceID(b.SourceID) + "\">\n" + content + "\n" + untrustedClose
}

func sanitizeSourceID(s string) string {
	if len(s) > maxSourceIDLen {
		s = s[:maxSourceIDLen]
	}
	if s == "" {
		return "_"
	}
	out := []byte(s)
	for i, c := range out {
		if !isSourceIDByte(c) {
			out[i] = '_'
		}
	}
	return string(out)
}

func isSourceIDByte(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
		c == '-' || c == '_' || c == '.' || c == ':' || c == '/'
}
