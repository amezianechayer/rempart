package reach

import (
	"net/netip"
	"slices"
)

// SubsetOf reports whether r permits nothing that o does not (ADR 0010, D3):
// (1) every tuple of r (source, destination, protocol, port, and the address
// for a hop from internet) is a tuple of o, computed exactly by port ranges
// and by address intervals, including when an address of r is covered only by
// the union of prefixes of o carried by distinct hops; (2) every target of r
// is a target of o and every step of its path is a hop of o, any protocol.
func (r Result) SubsetOf(o Result) bool {
	type pair struct{ src, dst string }
	internal := map[triple][]PortRange{}
	steps := map[pair]bool{}
	type group struct{ r, o []Hop }
	fromNet := map[triple]*group{}
	for _, h := range o.Hops {
		steps[pair{h.Src, h.Dst}] = true
		k := triple{h.Src, h.Dst, h.Proto}
		if h.Src != Internet {
			internal[k] = append(internal[k], h.Ports...)
			continue
		}
		if fromNet[k] == nil {
			fromNet[k] = &group{}
		}
		fromNet[k].o = append(fromNet[k].o, h)
	}
	for _, h := range r.Hops {
		k := triple{h.Src, h.Dst, h.Proto}
		if h.Src != Internet {
			if !covered(normalize(h.Ports), normalize(internal[k])) {
				return false
			}
			continue
		}
		if fromNet[k] == nil {
			fromNet[k] = &group{}
		}
		fromNet[k].r = append(fromNet[k].r, h)
	}
	for _, g := range fromNet {
		if len(g.r) > 0 && !addressesCovered(g.r, g.o) {
			return false
		}
	}
	targets := make(map[string]bool, len(o.FromInternet))
	for _, p := range o.FromInternet {
		targets[p.Target] = true
	}
	for _, p := range r.FromInternet {
		if !targets[p.Target] {
			return false
		}
		for i := 1; i < len(p.Nodes); i++ {
			if !steps[pair{p.Nodes[i-1], p.Nodes[i]}] {
				return false
			}
		}
	}
	return true
}

// addressesCovered checks, for hops from internet of one destination and
// protocol, that the ports r permits from each address are permitted by o.
// Membership in every prefix of both sides is constant on each elementary
// interval between the boundaries of these prefixes, so checking the first
// address of every interval of both families is exact.
func addressesCovered(r, o []Hop) bool {
	points := []netip.Addr{netip.IPv4Unspecified(), netip.IPv6Unspecified()}
	for _, h := range slices.Concat(r, o) {
		for _, p := range h.Sources {
			points = append(points, p.Masked().Addr())
			if next := lastAddr(p).Next(); next.IsValid() {
				points = append(points, next)
			}
		}
	}
	slices.SortFunc(points, netip.Addr.Compare)
	points = slices.Compact(points)
	permitted := func(hops []Hop, a netip.Addr) PortSet {
		var ports []PortRange
		for _, h := range hops {
			if h.World || slices.ContainsFunc(h.Sources, func(p netip.Prefix) bool { return p.Contains(a) }) {
				ports = append(ports, h.Ports...)
			}
		}
		return normalize(ports)
	}
	for _, a := range points {
		if !covered(permitted(r, a), permitted(o, a)) {
			return false
		}
	}
	return true
}

// lastAddr returns the last address of p.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}
