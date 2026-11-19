package reach

import (
	"cmp"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// triple keys the hops of one source, destination and protocol.
type triple struct {
	src, dst string
	proto    Proto
}

// Compute checks the limits and the model, then returns the hops "allow minus
// deny" and the shortest path from internet to every node reached (D1). It is
// deterministic: no output depends on the order of the inputs or of a map.
// Beyond a bound: ErrGraphTooLarge, never a partial result (D4).
func Compute(m Model, l Limits) (Result, error) {
	if l.MaxNodes <= 0 || l.MaxRules <= 0 || l.MaxDepth <= 0 || l.MaxPaths <= 0 {
		return Result{}, ErrInvalidModel
	}
	// Both size checks precede any allocation proportional to the input.
	if len(m.Nodes) > l.MaxNodes {
		return Result{}, ErrGraphTooLarge
	}
	pairs := 0
	for _, r := range m.Rules {
		pairs += max(1, len(r.Sources))
		if pairs > l.MaxRules {
			return Result{}, ErrGraphTooLarge
		}
	}
	nodes := make(map[string]bool, len(m.Nodes))
	for _, n := range m.Nodes {
		if n == "" || n == Internet || n == Any || nodes[n] {
			return Result{}, ErrInvalidModel
		}
		nodes[n] = true
	}
	for _, r := range m.Rules {
		if !validRule(r, nodes) {
			return Result{}, ErrInvalidModel
		}
	}
	hops := computeHops(m.Rules)
	paths, err := pathsFromInternet(hops, l)
	if err != nil {
		return Result{}, err
	}
	return Result{Hops: hops, FromInternet: paths}, nil
}

func validRule(r Rule, nodes map[string]bool) bool {
	if (r.Proto != TCP && r.Proto != UDP) || r.Ports.From < 1 || r.Ports.From > r.Ports.To || r.Src == r.Dst {
		return false
	}
	switch r.Action {
	case Allow:
		if (r.Src != Internet && !nodes[r.Src]) || !nodes[r.Dst] || (len(r.Sources) > 0 && r.Src != Internet) {
			return false
		}
		for _, p := range r.Sources {
			if !canonicalPrefix(p) {
				return false
			}
		}
		return true
	case Deny:
		return (r.Src == Internet || r.Src == Any || nodes[r.Src]) && (r.Dst == Any || nodes[r.Dst]) && len(r.Sources) == 0
	}
	return false
}

// canonicalPrefix: valid, host bits zero, no zone, no IPv4 mapped in IPv6.
func canonicalPrefix(p netip.Prefix) bool {
	return p.IsValid() && p == p.Masked() && p.Addr().Zone() == "" && !p.Addr().Is4In6()
}

// computeHops applies D1: for each triple, the ports of the allow rules minus
// the ports of every deny rule that matches it (Any matching every node and
// internet); from internet, per source key, then keys of equal port sets
// grouped and their prefixes aggregated.
func computeHops(rules []Rule) []Hop {
	internal := map[triple][]PortRange{}
	fromNet := map[triple]map[netip.Prefix][]PortRange{} // the zero Prefix is the key "whole Internet"
	denied := map[triple][]PortRange{}
	for _, r := range rules {
		k := triple{r.Src, r.Dst, r.Proto}
		switch {
		case r.Action == Deny:
			denied[k] = append(denied[k], r.Ports)
		case r.Src != Internet:
			internal[k] = append(internal[k], r.Ports)
		default:
			if fromNet[k] == nil {
				fromNet[k] = map[netip.Prefix][]PortRange{}
			}
			if len(r.Sources) == 0 {
				fromNet[k][netip.Prefix{}] = append(fromNet[k][netip.Prefix{}], r.Ports)
			}
			for _, p := range r.Sources {
				fromNet[k][p] = append(fromNet[k][p], r.Ports)
			}
		}
	}
	denyOf := func(k triple) PortSet {
		var d []PortRange
		for _, src := range []string{k.src, Any} {
			for _, dst := range []string{k.dst, Any} {
				d = append(d, denied[triple{src, dst, k.proto}]...)
			}
		}
		return normalize(d)
	}

	hops := []Hop{}
	for k, ports := range internal {
		if p := subtract(normalize(ports), denyOf(k)); len(p) > 0 {
			hops = append(hops, Hop{Src: k.src, Dst: k.dst, Proto: k.proto, Ports: p})
		}
	}
	for k, keys := range fromNet {
		d := denyOf(k)
		groups := map[string]*Hop{}
		prefixes := map[string][]netip.Prefix{}
		for src, ports := range keys {
			p := subtract(normalize(ports), d)
			if len(p) == 0 {
				continue
			}
			id := portsKey(p)
			h, ok := groups[id]
			if !ok {
				h = &Hop{Src: k.src, Dst: k.dst, Proto: k.proto, Ports: p}
				groups[id] = h
			}
			if src.IsValid() {
				prefixes[id] = append(prefixes[id], src)
			} else {
				h.World = true
			}
		}
		for id, h := range groups {
			if !h.World {
				h.Sources = aggregate(prefixes[id])
				if coversBothFamilies(h.Sources) {
					h.World, h.Sources = true, nil
				}
			}
			hops = append(hops, *h)
		}
	}
	slices.SortFunc(hops, compareHops)
	return hops
}

// compareHops is the total order of D1: Src, Dst, Proto, World first, first
// source, then the port set (two hops of one triple never share it).
func compareHops(a, b Hop) int {
	if c := cmp.Or(cmp.Compare(a.Src, b.Src), cmp.Compare(a.Dst, b.Dst), cmp.Compare(a.Proto, b.Proto)); c != 0 {
		return c
	}
	if a.World != b.World {
		if a.World {
			return -1
		}
		return 1
	}
	if len(a.Sources) > 0 && len(b.Sources) > 0 {
		if c := a.Sources[0].Compare(b.Sources[0]); c != 0 {
			return c
		}
	}
	return slices.CompareFunc(a.Ports, b.Ports, func(x, y PortRange) int {
		return cmp.Or(cmp.Compare(x.From, y.From), cmp.Compare(x.To, y.To))
	})
}

func portsKey(p PortSet) string {
	var b strings.Builder
	for _, r := range p {
		b.WriteString(strconv.Itoa(int(r.From)))
		b.WriteByte('-')
		b.WriteString(strconv.Itoa(int(r.To)))
		b.WriteByte(',')
	}
	return b.String()
}

// normalize sorts and merges ranges (overlapping or adjacent).
func normalize(rs []PortRange) PortSet {
	if len(rs) == 0 {
		return nil
	}
	s := slices.Clone(rs)
	slices.SortFunc(s, func(a, b PortRange) int { return cmp.Or(cmp.Compare(a.From, b.From), cmp.Compare(a.To, b.To)) })
	out := PortSet{s[0]}
	for _, r := range s[1:] {
		last := &out[len(out)-1]
		if uint32(r.From) <= uint32(last.To)+1 {
			last.To = max(last.To, r.To)
			continue
		}
		out = append(out, r)
	}
	return out
}

// subtract returns a minus b, both normalized.
func subtract(a, b PortSet) PortSet {
	var out PortSet
	for _, r := range a {
		from := uint32(r.From)
		for _, d := range b {
			if uint32(d.To) < from || d.From > r.To {
				continue
			}
			if uint32(d.From) > from {
				out = append(out, PortRange{From: uint16(from), To: d.From - 1}) //nolint:gosec // from <= 65535
			}
			from = uint32(d.To) + 1
		}
		if from <= uint32(r.To) {
			out = append(out, PortRange{From: uint16(from), To: r.To}) //nolint:gosec // from <= r.To <= 65535
		}
	}
	return out
}

// covered reports whether a is included in b, both normalized: b is merged,
// so each range of a lies within one range of b.
func covered(a, b PortSet) bool {
	j := 0
	for _, r := range a {
		for j < len(b) && b[j].To < r.From {
			j++
		}
		if j == len(b) || b[j].From > r.From || b[j].To < r.To {
			return false
		}
	}
	return true
}

// aggregate returns the canonical aggregation of canonical prefixes: no
// duplicate, no prefix inside another, siblings merged into their parent,
// sorted by netip.Prefix.Compare.
func aggregate(ps []netip.Prefix) []netip.Prefix {
	s := slices.Clone(ps)
	slices.SortFunc(s, func(a, b netip.Prefix) int {
		return cmp.Or(a.Addr().Compare(b.Addr()), cmp.Compare(a.Bits(), b.Bits()))
	})
	var stack []netip.Prefix
	for _, p := range s {
		if n := len(stack); n > 0 && stack[n-1].Bits() <= p.Bits() && stack[n-1].Contains(p.Addr()) {
			continue
		}
		stack = append(stack, p)
		for n := len(stack); n >= 2; n = len(stack) {
			a, b := stack[n-2], stack[n-1]
			if a.Bits() != b.Bits() || a.Bits() == 0 {
				break
			}
			parent, _ := a.Addr().Prefix(a.Bits() - 1)
			if !parent.Contains(b.Addr()) {
				break
			}
			stack = append(stack[:n-2], parent)
		}
	}
	slices.SortFunc(stack, netip.Prefix.Compare)
	return stack
}

// coversBothFamilies: the aggregation is the whole Internet. Covering one
// family only is not World: an IPv4-only list never permits an IPv6 address
// (exact semantics, required by the monotonicity of D3).
func coversBothFamilies(ps []netip.Prefix) bool {
	v4, v6 := false, false
	for _, p := range ps {
		v4 = v4 || (p.Bits() == 0 && p.Addr().Is4())
		v6 = v6 || (p.Bits() == 0 && p.Addr().Is6())
	}
	return v4 && v6
}

// pathsFromInternet runs the breadth-first search of D1 over the hops, any
// protocol and source: a predecessor is the smallest identifier among the
// nodes at minimal depth, since each frontier is visited in sorted order.
func pathsFromInternet(hops []Hop, l Limits) ([]Path, error) {
	adj := map[string][]string{}
	for _, h := range hops { // sorted by Src then Dst: each list is sorted
		if a := adj[h.Src]; len(a) == 0 || a[len(a)-1] != h.Dst {
			adj[h.Src] = append(a, h.Dst)
		}
	}
	parent := map[string]string{Internet: ""}
	var reached []string
	frontier := []string{Internet}
	for depth := 1; len(frontier) > 0; depth++ {
		var next []string
		for _, u := range frontier {
			for _, v := range adj[u] {
				if _, seen := parent[v]; !seen {
					parent[v] = u
					next = append(next, v)
				}
			}
		}
		if len(next) > 0 && depth > l.MaxDepth {
			return nil, ErrGraphTooLarge
		}
		if len(reached)+len(next) > l.MaxPaths {
			return nil, ErrGraphTooLarge
		}
		slices.Sort(next)
		reached = append(reached, next...)
		frontier = next
	}
	slices.Sort(reached)
	paths := make([]Path, 0, len(reached))
	for _, t := range reached {
		var rev []string
		for n := t; n != ""; n = parent[n] {
			rev = append(rev, n)
		}
		slices.Reverse(rev)
		paths = append(paths, Path{Target: t, Nodes: rev})
	}
	return paths, nil
}
