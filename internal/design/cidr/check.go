package cidr

import (
	"net/netip"
	"slices"
	"strconv"

	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
)

// This file shares no function with allocate.go (plan P7, threat T87): only the
// types of types.go are common to the allocator and the verifier.

const checkSource = "cidr_check"

// Codes of cidr_check.py.
const (
	CodeInvalid            = "CIDR_INVALID"
	CodeNotPrivate         = "CIDR_NOT_PRIVATE"
	CodeOutsideSuperblock  = "CIDR_OUTSIDE_SUPERBLOCK"
	CodeUnknownParent      = "CIDR_UNKNOWN_PARENT"
	CodeOutsideParent      = "CIDR_OUTSIDE_PARENT"
	CodeOverlap            = "CIDR_OVERLAP"
	CodeOverlapExternal    = "CIDR_OVERLAP_EXTERNAL"
	superblockResourceName = "superblock"
)

// checkNet is one network as the verifier sees it; valid is false for a CIDR
// that does not parse, is not IPv4 or has host bits set.
type checkNet struct {
	name, parent string
	hasParent    bool
	prefix       netip.Prefix
	valid        bool
}

type checkExt struct {
	name   string
	prefix netip.Prefix
	valid  bool
}

// privateRanges are the RFC 1918 ranges. Stricter than Python's is_private,
// which also accepts special ranges such as 192.0.2.0/24 (plan P7).
var privateRanges = [3]netip.Prefix{
	netip.PrefixFrom(netip.AddrFrom4([4]byte{10}), 8),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{172, 16}), 12),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168}), 16),
}

func finding(code string, sev loopsdomain.Severity, resource, message string) loopsdomain.Finding {
	return loopsdomain.Finding{Code: code, Source: checkSource, Severity: sev, Resource: resource, Message: message}
}

func checkValid(p netip.Prefix) bool {
	return p.IsValid() && p.Addr().Is4() && !p.Addr().Is4In6() && p == p.Masked()
}

// within reports whether inner is a subnet of outer (both valid IPv4).
func within(inner, outer netip.Prefix) bool {
	return inner.Bits() >= outer.Bits() && outer.Contains(inner.Addr())
}

func private(p netip.Prefix) bool {
	for _, r := range privateRanges {
		if within(p, r) {
			return true
		}
	}
	return false
}

// Check applies the rules of cidr_check.py to p (plan P7). The reserved ranges
// are named "reserved-1", "reserved-2", ... in the order of p.External, as in
// ReferenceJSON. Findings are sorted by loopsdomain.Sort.
func Check(p Plan) []loopsdomain.Finding {
	nets := make([]checkNet, 0, len(p.Networks))
	for _, n := range p.Networks {
		nets = append(nets, checkNet{name: n.Name, parent: n.Parent, hasParent: n.Parent != "", prefix: n.Prefix, valid: checkValid(n.Prefix)})
	}
	exts := make([]checkExt, 0, len(p.External))
	for i, e := range p.External {
		exts = append(exts, checkExt{name: "reserved-" + strconv.Itoa(i+1), prefix: e, valid: checkValid(e)})
	}
	return check(p.Superblock, checkValid(p.Superblock), nets, exts)
}

func check(sb netip.Prefix, sbValid bool, list []checkNet, exts []checkExt) []loopsdomain.Finding {
	if !sbValid {
		return []loopsdomain.Finding{finding(CodeInvalid, loopsdomain.SeverityCritical, superblockResourceName, "invalid superblock")}
	}
	var out []loopsdomain.Finding
	// Like the Python dictionary: the last network of a name wins.
	nets := map[string]checkNet{}
	for _, n := range list {
		if !n.valid {
			out = append(out, finding(CodeInvalid, loopsdomain.SeverityCritical, n.name, "invalid CIDR"))
			continue
		}
		nets[n.name] = n
	}
	var ext []checkExt
	for _, e := range exts {
		if !e.valid {
			out = append(out, finding(CodeInvalid, loopsdomain.SeverityCritical, e.name, "invalid external CIDR"))
			continue
		}
		ext = append(ext, e)
	}
	names := make([]string, 0, len(nets))
	for name := range nets {
		names = append(names, name)
	}
	slices.Sort(names)

	for _, name := range names {
		n := nets[name]
		if !private(n.prefix) {
			out = append(out, finding(CodeNotPrivate, loopsdomain.SeverityHigh, name, "range is not RFC 1918 private"))
		}
		if !n.hasParent {
			if !within(n.prefix, sb) {
				out = append(out, finding(CodeOutsideSuperblock, loopsdomain.SeverityHigh, name, "range outside the superblock"))
			}
			continue
		}
		parent, ok := nets[n.parent]
		switch {
		case !ok:
			out = append(out, finding(CodeUnknownParent, loopsdomain.SeverityCritical, name, "unknown parent"))
		case !within(n.prefix, parent.prefix):
			out = append(out, finding(CodeOutsideParent, loopsdomain.SeverityCritical, name, "range outside its parent"))
		}
	}
	for i, a := range names {
		na := nets[a]
		for _, b := range names[i+1:] {
			nb := nets[b]
			if na.hasParent == nb.hasParent && na.parent == nb.parent && na.prefix.Overlaps(nb.prefix) {
				out = append(out, finding(CodeOverlap, loopsdomain.SeverityCritical, a+"|"+b, "sibling ranges overlap"))
			}
		}
		if !na.hasParent {
			for _, e := range ext {
				if na.prefix.Overlaps(e.prefix) {
					out = append(out, finding(CodeOverlapExternal, loopsdomain.SeverityCritical, a+"|"+e.name, "range overlaps an external range"))
				}
			}
		}
	}
	return loopsdomain.Sort(out)
}
