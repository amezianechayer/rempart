package domain

import (
	"net/netip"
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
	out := map[netip.Prefix]bool{}
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool { return !isAddrRune(r) }) {
		tok = strings.TrimLeft(strings.TrimRight(tok, ".:/"), ".")
		if !strings.ContainsAny(tok, "0123456789") {
			continue
		}
		if strings.Contains(tok, "/") {
			if p, err := netip.ParsePrefix(tok); err == nil {
				out[p.Masked()] = true
			}
		} else if a, err := netip.ParseAddr(tok); err == nil {
			out[netip.PrefixFrom(a, a.BitLen())] = true
		}
	}
	return out
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
// explicit_overrides; otherwise INTENT-EXPOSURE-SOURCES-OMITTED.
func checkSources(text string, d Draft) []loopsdomain.Finding {
	kept := map[netip.Prefix]bool{}
	for _, e := range d.Exposure {
		for _, s := range e.AllowedSources {
			if p, ok := canonicalSource(s); ok {
				kept[p] = true
			}
		}
	}
	for _, o := range d.ExplicitOverrides {
		for p := range writtenPrefixes(o.Statement) {
			kept[p] = true
		}
	}
	for p := range writtenPrefixes(text) {
		if !kept[p] {
			return []loopsdomain.Finding{finding(codeExposureSourcesOmitted, "exposure")}
		}
	}
	return nil
}
