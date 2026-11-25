package domain

import (
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
)

// Source restrictions (review of the M1 milestone, T102, ADR 0006 amendment
// A2). An empty allowed_sources means all of Internet, the least protective
// value: a restriction written by the user may never vanish from the draft.

// isAddrRune: the runes of an IPv4 or IPv6 address or prefix; any other rune
// cuts a token, so a value glued to a key (source=203.0.113.10) is found.
func isAddrRune(r rune) bool {
	return r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r == '.' || r == ':' || r == '/'
}

// writtenPrefixes returns the canonical prefixes of the addresses and
// prefixes of s: an address A as A/32 or A/128, a prefix masked.
func writtenPrefixes(s string) map[netip.Prefix]bool {
	out, _ := readAddresses(s)
	return out
}

// Obligation (ez): an address written with a dot look-alike or in a defanged
// notation is read as the address. rearm rewrites the separators: the dot
// look-alikes U+2024, U+FF0E, U+00B7, U+3002, U+FE52, the defanged forms
// [.], (.), {.}, [:], a dot surrounded by blanks between two digits, and the
// commas of four groups of one to three digits.
var (
	defanged = strings.NewReplacer(
		"\u2024", ".", "\uFF0E", ".", "\u00B7", ".", "\u3002", ".", "\uFE52", ".",
		"[.]", ".", "(.)", ".", "{.}", ".", "[:]", ":", "(:)", ":",
	)
	// review of M2-T01: blanks on both sides of the dot (never a sentence
	// end), four groups outside any number (never the tail of an address).
	spacedDot  = regexp.MustCompile(`([0-9])[ \t]+\.[ \t]+([0-9])`)
	commaQuads = regexp.MustCompile(`(^|[^0-9.,])([0-9]{1,3}),([0-9]{1,3}),([0-9]{1,3}),([0-9]{1,3})([^0-9.,]|$)`)
	// Obligation (fb): four groups right after the word port or ports are a
	// port list ("ports 22,80,110,143"), never an address.
	portWord = regexp.MustCompile(`(?i)\bports?[ \t]*:?[ \t]*$`)
)

func rearm(s string) string {
	s = defanged.Replace(s)
	for prev := ""; prev != s; {
		prev = s
		s = spacedDot.ReplaceAllString(s, "$1.$2")
	}
	var b strings.Builder
	last := 0
	for _, m := range commaQuads.FindAllStringSubmatchIndex(s, -1) {
		b.WriteString(s[last:m[0]])
		last = m[1]
		if portWord.MatchString(s[:m[3]]) {
			b.WriteString(s[m[0]:m[1]])
			continue
		}
		b.WriteString(s[m[2]:m[3]])
		b.WriteString(strings.Join([]string{s[m[4]:m[5]], s[m[6]:m[7]], s[m[8]:m[9]], s[m[10]:m[11]]}, "."))
		b.WriteString(s[m[12]:m[13]])
	}
	b.WriteString(s[last:])
	return b.String()
}

// readAddresses reads the addresses and prefixes of s, and returns apart the
// tokens that look like an address but stay unreadable (second review pass
// of T102: fail closed instead of chasing every notation).
// A rereading never removes a reading (review of M2-T01): the addresses of
// the original text and of the rearmed text are joined, and so are the
// unreadable tokens (fail closed).
func readAddresses(s string) (map[netip.Prefix]bool, []string) {
	out, unreadable := readTokens(s)
	if r := rearm(s); r != s {
		more, bad := readTokens(r)
		maps.Copy(out, more)
		for _, tok := range bad {
			if !slices.Contains(unreadable, tok) {
				unreadable = append(unreadable, tok)
			}
		}
	}
	return out, unreadable
}

func readTokens(s string) (map[netip.Prefix]bool, []string) {
	out, unreadable := map[netip.Prefix]bool{}, []string{}
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool { return !isAddrRune(r) }) {
		tok = strings.TrimLeft(strings.TrimRight(tok, ".:/"), ".")
		if !strings.ContainsAny(tok, "0123456789") {
			continue
		}
		if p, ok := readAddress(tok); ok {
			out[p] = true
		} else if addressLike(tok) {
			unreadable = append(unreadable, tok)
		}
	}
	return out, unreadable
}

// readAddress reads tok as is, then after the retouches of glued forms: a
// key glued by a single ':' (never '::', "ce:203.0.113.10" from "source:"),
// the port of an IPv4 address ("203.0.113.10:443").
func readAddress(tok string) (netip.Prefix, bool) {
	cands := []string{tok}
	if i := strings.Index(tok, ":"); i >= 0 && !strings.HasPrefix(tok[i:], "::") {
		cands = append(cands, tok[i+1:])
	}
	for _, c := range cands {
		if j := strings.LastIndex(c, ":"); j > 0 && strings.Count(c[:j], ".") == 3 && digits(c[j+1:]) {
			cands = append(cands, c[:j])
		}
	}
	for _, c := range cands {
		if strings.Contains(c, "/") {
			if p, err := netip.ParsePrefix(c); err == nil {
				return p.Masked(), true
			}
		} else if a, err := netip.ParseAddr(c); err == nil {
			return netip.PrefixFrom(a, a.BitLen()), true
		}
	}
	return netip.Prefix{}, false
}

func digits(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}

// addressLike: three dots, a "::", or two ':' with a group that is not a
// two-digit number (an hour hh:mm:ss is not an address).
func addressLike(tok string) bool {
	if strings.Count(tok, ".") >= 3 || strings.Contains(tok, "::") {
		return true
	}
	if strings.Count(tok, ":") < 2 {
		return false
	}
	for _, g := range strings.Split(tok, ":") {
		if len(g) > 2 || !digits(g) && g != "" {
			return true
		}
	}
	return false
}

// canonicalSource parses an allowed source; only a masked prefix is admitted.
func canonicalSource(s string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(s)
	return p, err == nil && p.Masked() == p
}

// sourceWritten reports whether the allowed source s is a canonical prefix
// written in the text, directly or as the address of a /32 or /128.
func sourceWritten(written map[netip.Prefix]bool, s string) bool {
	p, ok := canonicalSource(s)
	return ok && written[p]
}

// checkSources: every address or prefix of the whole text (never a sentence,
// T85c) is an allowed source of an exposure or is captured in
// explicit_overrides, and every token that looks like an address but stays
// unreadable is quoted verbatim in explicit_overrides; otherwise
// INTENT-EXPOSURE-SOURCES-OMITTED.
func checkSources(text string, d Draft) []loopsdomain.Finding {
	kept := map[netip.Prefix]bool{}
	for _, e := range d.Exposure {
		for _, s := range e.AllowedSources {
			if p, ok := canonicalSource(s); ok {
				kept[p] = true
			}
		}
	}
	quoted := func(tok string) bool {
		for _, o := range d.ExplicitOverrides {
			if strings.Contains(rearm(o.Statement), tok) {
				return true
			}
		}
		return false
	}
	for _, o := range d.ExplicitOverrides {
		for p := range writtenPrefixes(o.Statement) {
			kept[p] = true
		}
	}
	written, unreadable := readAddresses(text)
	for p := range written {
		if !kept[p] {
			return []loopsdomain.Finding{finding(codeExposureSourcesOmitted, "exposure")}
		}
	}
	for _, tok := range unreadable {
		if !quoted(tok) {
			return []loopsdomain.Finding{finding(codeExposureSourcesOmitted, "exposure")}
		}
	}
	return nil
}

// CitesAddress reports whether s cites an address or a prefix, by the reader
// of exposure sources (rearmed forms included), or an address-like token that
// stays unreadable (fail closed). L2 reads explicit overrides with it only to
// block (obligation (ey), ADR 0012 D4), never to relax a control.
func CitesAddress(s string) bool {
	addrs, unreadable := readAddresses(s)
	return len(addrs) > 0 || len(unreadable) > 0
}
