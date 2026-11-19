package reach_test

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"

	"pgregory.net/rapid"

	"github.com/amezianechayer/rempart/internal/graph/reach"
)

// maxTestPort bounds the ports drawn by the generators: the oracle enumerates
// every port from 1 to maxTestPort.
const maxTestPort = 64

// sourcePool holds nested, adjacent (siblings that merge into their parent),
// whole-family and single-address prefixes of both families (ADR 0010, D3).
var sourcePool = []string{
	"0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1",
	"10.0.0.0/8", "10.0.0.0/9", "10.128.0.0/9", "10.1.0.0/16",
	"192.0.2.0/24", "192.0.3.0/24", "198.51.100.7/32",
	"::/0", "2001:db8::/32", "2001:db8::/33", "2001:db8:8000::/33",
}

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// lastAddr is the last address of p.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	host := len(b)*8 - p.Bits()
	for i := len(b) - 1; i >= 0 && host > 0; i-- {
		n := min(host, 8)
		b[i] |= byte(1<<n - 1)
		host -= n
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// probes are the first address of each family and, for every prefix of the
// pool, its first and last addresses and their neighbours. Membership in every
// pool prefix is constant between two consecutive probes, so the oracle sees
// every class of source addresses.
var probes = func() []netip.Addr {
	set := map[netip.Addr]bool{
		netip.MustParseAddr("0.0.0.0"): true, netip.MustParseAddr("255.255.255.255"): true,
		netip.MustParseAddr("::"): true, netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"): true,
	}
	for _, s := range sourcePool {
		p := mustPrefix(s)
		first, last := p.Masked().Addr(), lastAddr(p)
		for _, a := range []netip.Addr{first, first.Prev(), last, last.Next()} {
			if a.IsValid() {
				set[a] = true
			}
		}
	}
	out := make([]netip.Addr, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out
}()

// tuple is one permitted flow; addr is the zero Addr unless src is internet.
type tuple struct {
	src, dst string
	proto    reach.Proto
	port     uint16
	addr     netip.Addr
}

// world is the naive view of a model: every permitted tuple on ports 1 to
// maxTestPort and every probe, and the depth of every node reached from
// internet. Written without reach: allow covers, deny removes, no order.
type world struct {
	tuples map[tuple]bool
	depth  map[string]int // internet at 0
	edges  map[[2]string]bool
}

func covers(r reach.Rule, src, dst string, proto reach.Proto, port uint16) bool {
	return r.Proto == proto && r.Ports.From <= port && port <= r.Ports.To &&
		(r.Src == src || (r.Action == reach.Deny && r.Src == reach.Any)) &&
		(r.Dst == dst || (r.Action == reach.Deny && r.Dst == reach.Any))
}

func oracle(m reach.Model) world {
	w := world{tuples: map[tuple]bool{}, depth: map[string]int{reach.Internet: 0}, edges: map[[2]string]bool{}}
	for _, r := range m.Rules {
		if r.Action != reach.Allow {
			continue
		}
		for port := r.Ports.From; port >= r.Ports.From && port <= r.Ports.To && port <= maxTestPort; port++ {
			denied := slices.ContainsFunc(m.Rules, func(d reach.Rule) bool {
				return d.Action == reach.Deny && covers(d, r.Src, r.Dst, r.Proto, port)
			})
			if denied {
				continue
			}
			if r.Src != reach.Internet {
				w.tuples[tuple{r.Src, r.Dst, r.Proto, port, netip.Addr{}}] = true
				w.edges[[2]string{r.Src, r.Dst}] = true
				continue
			}
			for _, a := range probes {
				if len(r.Sources) == 0 || slices.ContainsFunc(r.Sources, func(p netip.Prefix) bool { return p.Contains(a) }) {
					w.tuples[tuple{r.Src, r.Dst, r.Proto, port, a}] = true
					w.edges[[2]string{r.Src, r.Dst}] = true
				}
			}
		}
	}
	frontier := []string{reach.Internet}
	for d := 1; len(frontier) > 0; d++ {
		var next []string
		for _, u := range frontier {
			for e := range w.edges {
				if e[0] == u {
					if _, seen := w.depth[e[1]]; !seen {
						w.depth[e[1]] = d
						next = append(next, e[1])
					}
				}
			}
		}
		frontier = next
	}
	return w
}

// includes reports whether every tuple and reached node of a is in b.
func (a world) includedIn(b world) bool {
	for t := range a.tuples {
		if !b.tuples[t] {
			return false
		}
	}
	for n := range a.depth {
		if _, ok := b.depth[n]; !ok {
			return false
		}
	}
	return true
}

// tuplesOf expands the hops of r on ports 1 to maxTestPort and on the probes.
func tuplesOf(t rapidT, r reach.Result) map[tuple]bool {
	out := map[tuple]bool{}
	for _, h := range r.Hops {
		for _, pr := range h.Ports {
			if pr.To > maxTestPort {
				t.Fatalf("hop %v carries port %d, never drawn: Compute invented ports", h, pr.To)
			}
			for port := pr.From; port <= pr.To; port++ {
				if h.Src != reach.Internet {
					out[tuple{h.Src, h.Dst, h.Proto, port, netip.Addr{}}] = true
					continue
				}
				for _, a := range probes {
					if h.World || slices.ContainsFunc(h.Sources, func(p netip.Prefix) bool { return p.Contains(a) }) {
						out[tuple{h.Src, h.Dst, h.Proto, port, a}] = true
					}
				}
			}
		}
	}
	return out
}

// rapidT is the part of *testing.T and *rapid.T the checks use.
type rapidT interface {
	Helper()
	Fatalf(format string, args ...any)
	Errorf(format string, args ...any)
}

func hopOrder(a, b reach.Hop) int {
	c := cmp.Or(cmp.Compare(a.Src, b.Src), cmp.Compare(a.Dst, b.Dst), cmp.Compare(a.Proto, b.Proto))
	if c != 0 {
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
	// Then the whole port set: two hops of one triple never share it (D1).
	return slices.CompareFunc(a.Ports, b.Ports, func(x, y reach.PortRange) int {
		return cmp.Or(cmp.Compare(x.From, y.From), cmp.Compare(x.To, y.To))
	})
}

// checkCanonical checks the canonical form of D1: total order of hops, ports
// sorted and merged, sources aggregated, World without sources.
func checkCanonical(t rapidT, r reach.Result) {
	t.Helper()
	if r.Hops == nil || r.FromInternet == nil {
		t.Fatalf("nil list in a successful result: %+v", r)
	}
	for i, h := range r.Hops {
		if i > 0 && hopOrder(r.Hops[i-1], h) >= 0 {
			t.Fatalf("hops %v and %v out of the total order of D1", r.Hops[i-1], h)
		}
		if len(h.Ports) == 0 {
			t.Fatalf("hop %v without ports", h)
		}
		for j, p := range h.Ports {
			if p.From < 1 || p.From > p.To || (j > 0 && uint32(h.Ports[j-1].To)+1 >= uint32(p.From)) {
				t.Fatalf("ports of %v not sorted and merged", h)
			}
		}
		switch {
		case h.Src != reach.Internet && (h.World || len(h.Sources) != 0):
			t.Fatalf("internal hop %v with World or sources", h)
		case h.Src == reach.Internet && h.World && len(h.Sources) != 0:
			t.Fatalf("hop %v: World with sources", h)
		case h.Src == reach.Internet && !h.World && len(h.Sources) == 0:
			t.Fatalf("hop %v from internet without World nor sources", h)
		}
		for j, p := range h.Sources {
			if p != p.Masked() || p.Addr().Is4In6() || p.Addr().Zone() != "" {
				t.Fatalf("hop %v: source %v not canonical", h, p)
			}
			for _, q := range h.Sources[:j] {
				if q.Compare(p) >= 0 || q.Overlaps(p) {
					t.Fatalf("hop %v: sources %v and %v not sorted (netip.Prefix.Compare) or overlapping", h, q, p)
				}
				if q.Bits() == p.Bits() && q.Bits() > 0 {
					parent, _ := q.Addr().Prefix(q.Bits() - 1)
					if parent.Contains(p.Addr()) {
						t.Fatalf("hop %v: siblings %v and %v not merged", h, q, p)
					}
				}
			}
		}
		fam4, fam6 := false, false
		for _, p := range h.Sources {
			fam4 = fam4 || (p.Bits() == 0 && p.Addr().Is4())
			fam6 = fam6 || (p.Bits() == 0 && p.Addr().Is6())
		}
		if fam4 && fam6 {
			t.Fatalf("hop %v covers both families without World", h)
		}
	}
	for i, p := range r.FromInternet {
		if i > 0 && r.FromInternet[i-1].Target >= p.Target {
			t.Fatalf("paths not sorted by target: %v", r.FromInternet)
		}
	}
}

// agree checks that Compute and the oracle see the same tuples, the same
// reached nodes, and that each path is a shortest one made of hops, its last
// step from the smallest predecessor at minimal depth (D1).
func agree(t rapidT, r reach.Result, w world) {
	t.Helper()
	checkCanonical(t, r)
	got := tuplesOf(t, r)
	for k := range w.tuples {
		if !got[k] {
			t.Fatalf("oracle permits %+v, Compute does not", k)
		}
	}
	for k := range got {
		if !w.tuples[k] {
			t.Fatalf("Compute permits %+v, the oracle does not", k)
		}
	}
	if len(r.FromInternet) != len(w.depth)-1 {
		t.Fatalf("%d paths, oracle reaches %d nodes besides internet", len(r.FromInternet), len(w.depth)-1)
	}
	byTarget := map[string][]string{}
	for _, p := range r.FromInternet {
		byTarget[p.Target] = p.Nodes
	}
	for _, p := range r.FromInternet {
		d, ok := w.depth[p.Target]
		if !ok || p.Target == reach.Internet {
			t.Fatalf("path to %s, unreached by the oracle", p.Target)
		}
		if len(p.Nodes) != d+1 || p.Nodes[0] != reach.Internet || p.Nodes[d] != p.Target {
			t.Fatalf("path %v: want %d hops from internet to %s", p.Nodes, d, p.Target)
		}
		for i := 1; i < len(p.Nodes); i++ {
			if !w.edges[[2]string{p.Nodes[i-1], p.Nodes[i]}] {
				t.Fatalf("path %v: step %s -> %s is no hop", p.Nodes, p.Nodes[i-1], p.Nodes[i])
			}
		}
		pred := p.Nodes[d-1]
		for u, du := range w.depth {
			if du == d-1 && u < pred && w.edges[[2]string{u, p.Target}] {
				t.Fatalf("path %v: predecessor %s, want the smallest %s", p.Nodes, pred, u)
			}
		}
		if d > 1 && !slices.Equal(byTarget[pred], p.Nodes[:d]) {
			t.Fatalf("path %v does not extend the path of its predecessor %v", p.Nodes, byTarget[pred])
		}
	}
}

// Generators.

func nodeIDs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("n%02d", i)
	}
	return out
}

func genSources(t *rapid.T, label string) []netip.Prefix {
	ss := rapid.SliceOfN(rapid.SampledFrom(sourcePool), 1, 3).Draw(t, label)
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = mustPrefix(s)
	}
	return out
}

func genPorts(t *rapid.T, label string) reach.PortRange {
	from := rapid.IntRange(1, maxTestPort).Draw(t, label+"_from")
	to := rapid.IntRange(from, maxTestPort).Draw(t, label+"_to")
	return reach.PortRange{From: uint16(from), To: uint16(to)} //nolint:gosec // bounded by maxTestPort
}

// genRule draws a valid rule of the given action between nodes.
func genRule(t *rapid.T, action string, nodes []string) reach.Rule {
	r := reach.Rule{Action: action, Proto: rapid.SampledFrom([]reach.Proto{reach.TCP, reach.UDP}).Draw(t, "proto")}
	dsts := nodes
	if action == reach.Deny {
		dsts = append(slices.Clone(nodes), reach.Any)
	}
	r.Dst = rapid.SampledFrom(dsts).Draw(t, "dst")
	srcs := []string{reach.Internet}
	if action == reach.Deny {
		srcs = append(srcs, reach.Any)
	}
	srcs = append(srcs, nodes...)
	srcs = slices.DeleteFunc(srcs, func(s string) bool { return s == r.Dst })
	if action == reach.Allow && rapid.IntRange(0, 2).Draw(t, "from_internet") == 0 {
		r.Src = reach.Internet
	} else {
		r.Src = rapid.SampledFrom(srcs).Draw(t, "src")
	}
	r.Ports = genPorts(t, "ports")
	if action == reach.Allow && r.Src == reach.Internet && rapid.Bool().Draw(t, "restricted") {
		r.Sources = genSources(t, "sources")
	}
	return r
}

func genModel(t *rapid.T) reach.Model {
	nodes := nodeIDs(rapid.IntRange(2, 12).Draw(t, "nodes"))
	rules := make([]reach.Rule, rapid.IntRange(0, 40).Draw(t, "rules"))
	for i := range rules {
		action := reach.Allow
		if rapid.IntRange(0, 9).Draw(t, "action") >= 7 {
			action = reach.Deny
		}
		rules[i] = genRule(t, action, nodes)
	}
	return reach.Model{Nodes: nodes, Rules: rules}
}

func cloneModel(m reach.Model) reach.Model {
	c := reach.Model{Nodes: slices.Clone(m.Nodes), Rules: slices.Clone(m.Rules)}
	for i := range c.Rules {
		c.Rules[i].Sources = slices.Clone(c.Rules[i].Sources)
	}
	return c
}
