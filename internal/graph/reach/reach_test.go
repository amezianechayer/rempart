package reach_test

import (
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/amezianechayer/rempart/internal/graph/reach"
)

func compute(t rapidT, m reach.Model) reach.Result {
	t.Helper()
	r, err := reach.Compute(m, reach.DefaultLimits)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	return r
}

// checkNarrowing checks lemma D3 of ADR 0010 for a model narrow whose allowed
// tuples are included in those of wide and whose denied tuples include them:
// both results agree with the oracle, the oracle sees an inclusion, and
// SubsetOf agrees with the oracle in both directions.
func checkNarrowing(t *rapid.T, wide, narrow reach.Model) {
	rw, rn := compute(t, wide), compute(t, narrow)
	ow, on := oracle(wide), oracle(narrow)
	agree(t, rw, ow)
	agree(t, rn, on)
	if !on.includedIn(ow) {
		t.Fatalf("the narrowed model permits a tuple or reaches a node the original does not")
	}
	for n, d := range on.depth {
		if ow.depth[n] > d {
			t.Fatalf("%s at depth %d after narrowing, %d before", n, d, ow.depth[n])
		}
	}
	if !rn.SubsetOf(rw) {
		t.Fatalf("SubsetOf(narrowed, original) = false")
	}
	if got, want := rw.SubsetOf(rn), ow.includedIn(on); got != want {
		t.Fatalf("SubsetOf(original, narrowed) = %v, oracle says %v", got, want)
	}
	if !rw.SubsetOf(rw) || !rn.SubsetOf(rn) {
		t.Fatalf("SubsetOf is not reflexive")
	}
}

// TestDenyNeverAddsPath proves criterion C3 of prompts/M2.md (ADR 0010, D3,
// P1): adding a deny rule, at any position, never adds a hop, a tuple or a
// path, against a naive oracle.
func TestDenyNeverAddsPath(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		m := genModel(t)
		d := genRule(t, reach.Deny, m.Nodes)
		n := cloneModel(m)
		at := rapid.IntRange(0, len(n.Rules)).Draw(t, "position")
		n.Rules = slices.Insert(n.Rules, at, d)
		checkNarrowing(t, m, n)
	})
}

// TestRemoveAllowNeverAddsPath proves P2 and P3 of ADR 0010, D3: removing an
// allow rule, or narrowing its ports or its sources (sources added to an empty
// list, removed from a list that stays non-empty, replaced by a contained
// prefix), never adds a hop, a tuple or a path.
func TestRemoveAllowNeverAddsPath(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		m := genModel(t)
		if !slices.ContainsFunc(m.Rules, func(r reach.Rule) bool { return r.Action == reach.Allow }) {
			m.Rules = append(m.Rules, genRule(t, reach.Allow, m.Nodes))
		}
		var allows []int
		for i, r := range m.Rules {
			if r.Action == reach.Allow {
				allows = append(allows, i)
			}
		}
		i := rapid.SampledFrom(allows).Draw(t, "rule")
		n := cloneModel(m)
		r := &n.Rules[i]
		switch op := rapid.SampledFrom([]string{"remove", "ports", "sources"}).Draw(t, "op"); {
		case op == "remove":
			n.Rules = slices.Delete(n.Rules, i, i+1)
		case op == "sources" && r.Src == reach.Internet:
			switch {
			case len(r.Sources) == 0:
				r.Sources = genSources(t, "added")
			case len(r.Sources) > 1:
				j := rapid.IntRange(0, len(r.Sources)-1).Draw(t, "removed")
				r.Sources = slices.Delete(r.Sources, j, j+1)
			default:
				var inner []netip.Prefix
				for _, s := range sourcePool {
					if p := mustPrefix(s); p.Bits() >= r.Sources[0].Bits() && r.Sources[0].Contains(p.Addr()) {
						inner = append(inner, p)
					}
				}
				r.Sources = []netip.Prefix{rapid.SampledFrom(inner).Draw(t, "contained")}
			}
		default:
			from := rapid.IntRange(int(r.Ports.From), int(r.Ports.To)).Draw(t, "narrow_from")
			to := rapid.IntRange(from, int(r.Ports.To)).Draw(t, "narrow_to")
			r.Ports = reach.PortRange{From: uint16(from), To: uint16(to)} //nolint:gosec // within the drawn range
		}
		checkNarrowing(t, m, n)
	})
}

func hop(src, dst string, proto reach.Proto, ports ...uint16) reach.Hop {
	h := reach.Hop{Src: src, Dst: dst, Proto: proto}
	for i := 0; i+1 < len(ports); i += 2 {
		h.Ports = append(h.Ports, reach.PortRange{From: ports[i], To: ports[i+1]})
	}
	return h
}

func allow(src, dst string, proto reach.Proto, from, to uint16, sources ...string) reach.Rule {
	r := reach.Rule{Action: reach.Allow, Src: src, Dst: dst, Proto: proto, Ports: reach.PortRange{From: from, To: to}}
	for _, s := range sources {
		r.Sources = append(r.Sources, mustPrefix(s))
	}
	return r
}

func deny(src, dst string, proto reach.Proto, from, to uint16) reach.Rule {
	return reach.Rule{Action: reach.Deny, Src: src, Dst: dst, Proto: proto, Ports: reach.PortRange{From: from, To: to}}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestReachDenyOverridesAllow pins the semantics of D1 on fixed cases: no
// order between rules, deny always wins, * matches every node and internet,
// a deny of part of a range splits it, adjacent ranges merge.
func TestReachDenyOverridesAllow(t *testing.T) {
	nodes := []string{"a", "b", "c"}
	world := func(dst string, proto reach.Proto, ports ...uint16) reach.Hop {
		h := hop(reach.Internet, dst, proto, ports...)
		h.World = true
		return h
	}
	cases := []struct {
		name  string
		rules []reach.Rule
		hops  []reach.Hop
		paths [][]string
	}{
		{
			"deny_after_allow",
			[]reach.Rule{allow("a", "b", reach.TCP, 1, 100), deny("a", "b", reach.TCP, 50, 60)},
			[]reach.Hop{hop("a", "b", reach.TCP, 1, 49, 61, 100)},
			nil,
		},
		{
			"deny_before_allow",
			[]reach.Rule{deny("a", "b", reach.TCP, 50, 60), allow("a", "b", reach.TCP, 1, 100)},
			[]reach.Hop{hop("a", "b", reach.TCP, 1, 49, 61, 100)},
			nil,
		},
		{
			"deny_whole_range",
			[]reach.Rule{allow("a", "b", reach.TCP, 80, 80), deny("a", "b", reach.TCP, 1, 65535)},
			[]reach.Hop{},
			nil,
		},
		{
			"deny_other_proto",
			[]reach.Rule{allow("a", "b", reach.TCP, 80, 80), deny("a", "b", reach.UDP, 1, 65535)},
			[]reach.Hop{hop("a", "b", reach.TCP, 80, 80)},
			nil,
		},
		{
			"deny_any_src",
			[]reach.Rule{allow("a", "b", reach.TCP, 80, 80), allow("c", "b", reach.UDP, 53, 53), deny(reach.Any, "b", reach.TCP, 1, 65535)},
			[]reach.Hop{hop("c", "b", reach.UDP, 53, 53)},
			nil,
		},
		{
			"deny_any_dst",
			[]reach.Rule{allow("a", "b", reach.TCP, 22, 22), allow("a", "c", reach.TCP, 22, 22), allow("b", "c", reach.TCP, 22, 22), deny("a", reach.Any, reach.TCP, 1, 65535)},
			[]reach.Hop{hop("b", "c", reach.TCP, 22, 22)},
			nil,
		},
		{
			"deny_any_src_covers_internet",
			[]reach.Rule{allow(reach.Internet, "a", reach.TCP, 443, 443), deny(reach.Any, "a", reach.TCP, 443, 443)},
			[]reach.Hop{},
			[][]string{},
		},
		{
			"deny_internet",
			[]reach.Rule{allow(reach.Internet, "a", reach.TCP, 80, 443), deny(reach.Internet, "a", reach.TCP, 81, 442)},
			[]reach.Hop{world("a", reach.TCP, 80, 80, 443, 443)},
			[][]string{{reach.Internet, "a"}},
		},
		{
			"denied_step_cuts_path",
			[]reach.Rule{allow(reach.Internet, "a", reach.TCP, 443, 443), allow("a", "b", reach.TCP, 5432, 5432), deny("a", "b", reach.TCP, 5432, 5432)},
			[]reach.Hop{world("a", reach.TCP, 443, 443)},
			[][]string{{reach.Internet, "a"}},
		},
		{
			"adjacent_and_overlapping_merge",
			[]reach.Rule{allow("a", "b", reach.TCP, 1, 10), allow("a", "b", reach.TCP, 11, 20), allow("a", "b", reach.TCP, 15, 30)},
			[]reach.Hop{hop("a", "b", reach.TCP, 1, 30)},
			nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := reach.Compute(reach.Model{Nodes: nodes, Rules: c.rules}, reach.DefaultLimits)
			if err != nil {
				t.Fatalf("Compute: %v", err)
			}
			checkCanonical(t, r)
			if got, want := mustJSON(t, r.Hops), mustJSON(t, c.hops); got != want {
				t.Fatalf("hops %s, want %s", got, want)
			}
			if c.paths != nil {
				var got [][]string
				for _, p := range r.FromInternet {
					got = append(got, p.Nodes)
				}
				if mustJSON(t, got) != mustJSON(t, c.paths) && (len(got) != 0 || len(c.paths) != 0) {
					t.Fatalf("paths %v, want %v", got, c.paths)
				}
			}
			rev := slices.Clone(c.rules)
			slices.Reverse(rev)
			r2, err := reach.Compute(reach.Model{Nodes: nodes, Rules: rev}, reach.DefaultLimits)
			if err != nil || mustJSON(t, r2) != mustJSON(t, r) {
				t.Fatalf("reversed rules give %s, %v; want %s", mustJSON(t, r2), err, mustJSON(t, r))
			}
		})
	}

	t.Run("sources_grouped_by_ports", func(t *testing.T) {
		r, err := reach.Compute(reach.Model{Nodes: nodes, Rules: []reach.Rule{
			allow(reach.Internet, "a", reach.TCP, 443, 443, "192.0.3.0/24"),
			allow(reach.Internet, "a", reach.TCP, 443, 443, "192.0.2.0/24", "10.1.0.0/16"),
			allow(reach.Internet, "a", reach.TCP, 443, 443, "10.0.0.0/8"),
			allow(reach.Internet, "a", reach.TCP, 22, 22, "198.51.100.7/32"),
			allow(reach.Internet, "a", reach.TCP, 80, 80),
			allow(reach.Internet, "b", reach.TCP, 443, 443, "0.0.0.0/1", "128.0.0.0/1"),
			allow(reach.Internet, "c", reach.TCP, 443, 443, "0.0.0.0/0", "::/0"),
		}}, reach.DefaultLimits)
		if err != nil {
			t.Fatalf("Compute: %v", err)
		}
		checkCanonical(t, r)
		want := `[{"src":"internet","dst":"a","proto":"tcp","ports":[{"from":80,"to":80}],"world":true},` +
			`{"src":"internet","dst":"a","proto":"tcp","ports":[{"from":443,"to":443}],"world":false,"sources":["10.0.0.0/8","192.0.2.0/23"]},` +
			`{"src":"internet","dst":"a","proto":"tcp","ports":[{"from":22,"to":22}],"world":false,"sources":["198.51.100.7/32"]},` +
			`{"src":"internet","dst":"b","proto":"tcp","ports":[{"from":443,"to":443}],"world":false,"sources":["0.0.0.0/0"]},` +
			`{"src":"internet","dst":"c","proto":"tcp","ports":[{"from":443,"to":443}],"world":true}]`
		if got := mustJSON(t, r.Hops); got != want {
			t.Fatalf("hops\n%s\nwant\n%s", got, want)
		}
	})
}

// TestReachDeterministic proves D1: the result does not depend on the order
// of nodes, rules or sources, nor on map iteration; equal JSON bytes.
func TestReachDeterministic(t *testing.T) {
	t.Run("encoding", func(t *testing.T) {
		r, err := reach.Compute(reach.Model{Nodes: []string{"lb", "app"}, Rules: []reach.Rule{
			allow("lb", "app", reach.TCP, 8080, 8080),
			allow(reach.Internet, "lb", reach.TCP, 443, 443),
		}}, reach.DefaultLimits)
		if err != nil {
			t.Fatal(err)
		}
		want := `{"hops":[{"src":"internet","dst":"lb","proto":"tcp","ports":[{"from":443,"to":443}],"world":true},` +
			`{"src":"lb","dst":"app","proto":"tcp","ports":[{"from":8080,"to":8080}],"world":false}],` +
			`"from_internet":[{"target":"app","nodes":["internet","lb","app"]},{"target":"lb","nodes":["internet","lb"]}]}`
		if got := mustJSON(t, r); got != want {
			t.Fatalf("result\n%s\nwant\n%s", got, want)
		}
		empty, err := reach.Compute(reach.Model{Nodes: []string{"a"}}, reach.DefaultLimits)
		if err != nil || mustJSON(t, empty) != `{"hops":[],"from_internet":[]}` {
			t.Fatalf("empty model: %s, %v", mustJSON(t, empty), err)
		}
	})

	rapid.Check(t, func(t *rapid.T) {
		m := genModel(t)
		first := compute(t, m)
		want, err := json.Marshal(first)
		if err != nil {
			t.Fatal(err)
		}
		p := cloneModel(m)
		p.Nodes = rapid.Permutation(p.Nodes).Draw(t, "nodes_order")
		p.Rules = rapid.Permutation(p.Rules).Draw(t, "rules_order")
		for i := range p.Rules {
			if len(p.Rules[i].Sources) > 0 {
				p.Rules[i].Sources = rapid.Permutation(p.Rules[i].Sources).Draw(t, "sources_order")
			}
		}
		for _, mm := range []reach.Model{m, p} {
			got, err := json.Marshal(compute(t, mm))
			if err != nil || string(got) != string(want) {
				t.Fatalf("result %s, want %s", got, want)
			}
		}
	})
}

// TestReachLimits proves D4 (T24): every bound refuses with ErrGraphTooLarge,
// never a partial or truncated result; a bound reached exactly passes; a null
// or negative bound and a model outside the domain of D1 give ErrInvalidModel,
// with fixed messages.
func TestReachLimits(t *testing.T) {
	chain := func(n int) reach.Model {
		m := reach.Model{Nodes: nodeIDs(n), Rules: []reach.Rule{allow(reach.Internet, "n00", reach.TCP, 443, 443)}}
		for i := 1; i < n; i++ {
			m.Rules = append(m.Rules, allow(m.Nodes[i-1], m.Nodes[i], reach.TCP, 22, 22))
		}
		return m
	}
	lim := func(nodes, rules, depth, paths int) reach.Limits {
		return reach.Limits{MaxNodes: nodes, MaxRules: rules, MaxDepth: depth, MaxPaths: paths}
	}
	sourced := reach.Model{Nodes: []string{"a"}, Rules: []reach.Rule{
		allow(reach.Internet, "a", reach.TCP, 443, 443, "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"),
	}}
	cases := []struct {
		name string
		m    reach.Model
		l    reach.Limits
		err  error
	}{
		{"nodes_at_limit", chain(5), lim(5, 5, 5, 5), nil},
		{"nodes_over", chain(5), lim(4, 100, 100, 100), reach.ErrGraphTooLarge},
		{"rules_at_limit", chain(5), lim(5, 5, 5, 5), nil},
		{"rules_over", chain(5), lim(5, 4, 100, 100), reach.ErrGraphTooLarge},
		{"rule_sources_counted", sourced, lim(1, 2, 1, 1), reach.ErrGraphTooLarge},
		{"rule_sources_at_limit", sourced, lim(1, 3, 1, 1), nil},
		{"depth_over", chain(5), lim(5, 5, 4, 5), reach.ErrGraphTooLarge},
		{"paths_over", chain(5), lim(5, 5, 5, 4), reach.ErrGraphTooLarge},
		{"default_limits", chain(32), reach.DefaultLimits, nil},
		{"default_depth_over", chain(33), reach.DefaultLimits, reach.ErrGraphTooLarge},
		{"zero_nodes", chain(2), lim(0, 5, 5, 5), reach.ErrInvalidModel},
		{"zero_rules", chain(2), lim(5, 0, 5, 5), reach.ErrInvalidModel},
		{"zero_depth", chain(2), lim(5, 5, 0, 5), reach.ErrInvalidModel},
		{"negative_paths", chain(2), lim(5, 5, 5, -1), reach.ErrInvalidModel},
	}
	if reach.DefaultLimits != lim(10000, 50000, 32, 10000) {
		t.Fatalf("DefaultLimits = %+v, want ADR 0010 D4", reach.DefaultLimits)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := reach.Compute(c.m, c.l)
			if !errors.Is(err, c.err) || (c.err == nil) != (err == nil) {
				t.Fatalf("Compute = %v, want %v", err, c.err)
			}
			if err != nil && (r.Hops != nil || r.FromInternet != nil) {
				t.Fatalf("partial result with %v: %+v", err, r)
			}
		})
	}

	marker := "n-marker-7f3a"
	base := []string{"a", "b"}
	invalid := []struct {
		name  string
		nodes []string
		rule  reach.Rule
	}{
		{"action", base, reach.Rule{Action: "permit", Src: "a", Dst: "b", Proto: reach.TCP, Ports: reach.PortRange{From: 1, To: 2}}},
		{"proto", base, reach.Rule{Action: reach.Allow, Src: "a", Dst: "b", Proto: "icmp", Ports: reach.PortRange{From: 1, To: 2}}},
		{"port_zero", base, allow("a", "b", reach.TCP, 0, 2)},
		{"ports_reversed", base, allow("a", "b", reach.TCP, 9, 2)},
		{"unknown_src", base, allow(marker, "b", reach.TCP, 1, 2)},
		{"unknown_dst", base, deny("a", marker, reach.TCP, 1, 2)},
		{"dst_internet", base, allow("a", reach.Internet, reach.TCP, 1, 2)},
		{"deny_dst_internet", base, deny("a", reach.Internet, reach.TCP, 1, 2)},
		{"src_equals_dst", base, allow("a", "a", reach.TCP, 1, 2)},
		{"deny_any_any", base, deny(reach.Any, reach.Any, reach.TCP, 1, 2)},
		{"allow_any_src", base, allow(reach.Any, "b", reach.TCP, 1, 2)},
		{"allow_any_dst", base, allow("a", reach.Any, reach.TCP, 1, 2)},
		{"sources_not_from_internet", base, allow("a", "b", reach.TCP, 1, 2, "192.0.2.0/24")},
		{"source_host_bits", base, reach.Rule{Action: reach.Allow, Src: reach.Internet, Dst: "b", Proto: reach.TCP, Ports: reach.PortRange{From: 1, To: 2}, Sources: []netip.Prefix{netip.PrefixFrom(netip.MustParseAddr("10.0.0.1"), 8)}}},
		{"source_4in6", base, allow(reach.Internet, "b", reach.TCP, 1, 2, "::ffff:10.0.0.0/104")},
		{"source_invalid", base, reach.Rule{Action: reach.Allow, Src: reach.Internet, Dst: "b", Proto: reach.TCP, Ports: reach.PortRange{From: 1, To: 2}, Sources: []netip.Prefix{{}}}},
		{"deny_sources", base, reach.Rule{Action: reach.Deny, Src: reach.Internet, Dst: "b", Proto: reach.TCP, Ports: reach.PortRange{From: 1, To: 2}, Sources: []netip.Prefix{mustPrefix("192.0.2.0/24")}}},
		{"node_empty", []string{"a", "b", ""}, allow("a", "b", reach.TCP, 1, 2)},
		{"node_duplicate", []string{"a", "b", "a"}, allow("a", "b", reach.TCP, 1, 2)},
		{"node_internet", []string{"a", "b", reach.Internet}, allow("a", "b", reach.TCP, 1, 2)},
		{"node_any", []string{"a", "b", reach.Any}, allow("a", "b", reach.TCP, 1, 2)},
	}
	for _, c := range invalid {
		t.Run("invalid_"+c.name, func(t *testing.T) {
			r, err := reach.Compute(reach.Model{Nodes: c.nodes, Rules: []reach.Rule{c.rule}}, reach.DefaultLimits)
			if !errors.Is(err, reach.ErrInvalidModel) {
				t.Fatalf("Compute = %v, want ErrInvalidModel", err)
			}
			if r.Hops != nil || r.FromInternet != nil || strings.Contains(err.Error(), marker) {
				t.Fatalf("partial result or message quoting the model: %+v, %q", r, err)
			}
		})
	}
	_, err := reach.Compute(reach.Model{Nodes: []string{marker}}, lim(0, 1, 1, 1))
	if err == nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("message %v quotes the model", err)
	}
}

// BenchmarkReachAtLimits measures D4 at the default limits (recorded in
// docs/STATUS.md, no blocking threshold): 10 000 nodes in 31 layers, 50 000
// rules, sources on the entry rules.
func BenchmarkReachAtLimits(b *testing.B) {
	l := reach.DefaultLimits
	rng := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // reproducible benchmark input
	nodes := nodeIDs(l.MaxNodes)
	const layers = 31
	per := l.MaxNodes / layers
	layer := func(i int) []string { return nodes[min(i*per, len(nodes)):min((i+1)*per, len(nodes))] }
	var rules []reach.Rule
	pairs := 0
	for _, n := range layer(0)[:50] {
		r := allow(reach.Internet, n, reach.TCP, 443, 443, "192.0.2.0/24", "198.51.100.0/24")
		rules = append(rules, r)
		pairs += len(r.Sources)
	}
	for pairs+len(rules)-50 < l.MaxRules {
		i := rng.IntN(layers - 1)
		from, to := layer(i), layer(i+1)
		if len(from) == 0 || len(to) == 0 {
			continue
		}
		lo := uint16(1 + rng.IntN(60000)) //nolint:gosec // bounded
		span := uint16(rng.IntN(100))     //nolint:gosec // bounded
		r := allow(from[rng.IntN(len(from))], to[rng.IntN(len(to))], reach.TCP, lo, lo+span)
		if rng.IntN(10) == 0 {
			r = deny(r.Src, r.Dst, reach.TCP, lo, lo)
		}
		rules = append(rules, r)
	}
	m := reach.Model{Nodes: nodes, Rules: rules}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		r, err := reach.Compute(m, l)
		if err != nil {
			b.Fatal(err)
		}
		_ = r
	}
	b.ReportMetric(float64(len(rules)), "rules")
}
