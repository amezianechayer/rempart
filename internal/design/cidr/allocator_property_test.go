package cidr_test

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"

	"pgregory.net/rapid"

	"github.com/amezianechayer/rempart/internal/design/cidr"
)

// Closed value sets of plan P6, used by the generators.
var (
	genClouds  = []string{"aws", "azure", "scaleway", "ovhcloud"}
	genRegions = []string{"eu-west-3", "francecentral", "fr-par", "gra", "eu-central-1"}
	genEnvs    = []string{"dev", "staging", "prod"}
	allTiers   = []cidr.Tier{cidr.TierPublic, cidr.TierApp, cidr.TierData, cidr.TierMgmt}
)

// genSuperblock draws an RFC 1918 superblock of length /8 to /12.
func genSuperblock(t *rapid.T) netip.Prefix {
	if rapid.Bool().Draw(t, "sb_172") {
		return netip.MustParsePrefix("172.16.0.0/12")
	}
	bits := rapid.IntRange(8, 12).Draw(t, "sb_bits")
	second := rapid.Byte().Draw(t, "sb_second")
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{10, second, 0, 0}), bits).Masked()
}

// genReserved draws a canonical /16 to /24 range. Most ranges sit in the
// first blocks of the superblock, where the allocator places its first VPCs,
// so that ignoring them is caught; the others lie outside the superblock.
func genReserved(t *rapid.T, sb netip.Prefix, i int) netip.Prefix {
	bits := rapid.IntRange(16, 24).Draw(t, fmt.Sprintf("res%d_bits", i))
	if rapid.IntRange(0, 3).Draw(t, fmt.Sprintf("res%d_outside", i)) == 0 {
		third := rapid.Byte().Draw(t, fmt.Sprintf("res%d_third", i))
		return netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, third, 0}), bits).Masked()
	}
	index := rapid.Uint32Range(0, 7).Draw(t, fmt.Sprintf("res%d_index", i))
	base := sb.Addr().As4()
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], binary.BigEndian.Uint32(base[:])+index<<(32-bits))
	return netip.PrefixFrom(netip.AddrFrom4(a), bits).Masked()
}

// genRequest draws a request feasible by construction: at most 8 VPCs of at
// most /17 in a superblock of at least /12, beside at most 4 ranges of /16 or smaller.
func genRequest(t *rapid.T) cidr.Request {
	sb := genSuperblock(t)
	nRes := rapid.IntRange(0, 4).Draw(t, "n_reserved")
	var reserved []netip.Prefix
	for i := range nRes {
		reserved = append(reserved, genReserved(t, sb, i))
	}
	type triplet struct{ cloud, region, env string }
	keys := rapid.SliceOfNDistinct(rapid.Custom(func(t *rapid.T) triplet {
		return triplet{
			cloud:  rapid.SampledFrom(genClouds).Draw(t, "cloud"),
			region: rapid.SampledFrom(genRegions).Draw(t, "region"),
			env:    rapid.SampledFrom(genEnvs).Draw(t, "env"),
		}
	}), 1, 8, func(k triplet) triplet { return k }).Draw(t, "needs")
	needs := make([]cidr.Need, 0, len(keys))
	for i, k := range keys {
		tiers := rapid.SliceOfNDistinct(rapid.SampledFrom(allTiers), 1, 4, func(x cidr.Tier) cidr.Tier { return x }).
			Draw(t, fmt.Sprintf("need%d_tiers", i))
		tn := make([]cidr.TierNeed, 0, len(tiers))
		for j, tier := range tiers {
			tn = append(tn, cidr.TierNeed{Tier: tier, Hosts: rapid.IntRange(1, 256).Draw(t, fmt.Sprintf("need%d_hosts%d", i, j))})
		}
		needs = append(needs, cidr.Need{Cloud: k.cloud, Region: k.region, Env: k.env, Tiers: tn})
	}
	return cidr.Request{
		Superblock: sb,
		Reserved:   reserved,
		Needs:      needs,
		Growth:     rapid.IntRange(0, 4).Draw(t, "growth"),
	}
}

func size(p netip.Prefix) int { return 1 << (32 - p.Bits()) }

// planViolations checks plan against req with the test's own rules, without cidr.Check.
func planViolations(req cidr.Request, plan cidr.Plan) []string {
	var out []string
	add := func(format string, a ...any) { out = append(out, fmt.Sprintf(format, a...)) }
	growth := req.Growth
	if growth == 0 {
		growth = cidr.DefaultGrowth
	}
	if plan.Growth != growth {
		add("plan growth %d, want %d", plan.Growth, growth)
	}
	if plan.Superblock != req.Superblock {
		add("plan superblock %s, want %s", plan.Superblock, req.Superblock)
	}
	byName := map[string]cidr.Network{}
	for _, n := range plan.Networks {
		if _, dup := byName[n.Name]; dup {
			add("duplicate network name %s", n.Name)
		}
		byName[n.Name] = n
		if !n.Prefix.IsValid() || !n.Prefix.Addr().Is4() || n.Prefix != n.Prefix.Masked() {
			add("%s: prefix %s is not a canonical IPv4 prefix", n.Name, n.Prefix)
		}
	}
	for i, a := range plan.Networks {
		for _, b := range plan.Networks[i+1:] {
			if a.Parent == b.Parent && a.Prefix.Overlaps(b.Prefix) {
				add("siblings %s and %s overlap", a.Name, b.Name)
			}
		}
		for _, r := range req.Reserved {
			if a.Prefix.Overlaps(r) {
				add("%s (%s) overlaps reserved %s", a.Name, a.Prefix, r)
			}
		}
	}
	childSizes := map[string]int{}
	for _, n := range plan.Networks {
		if n.Parent == "" {
			if !req.Superblock.Contains(n.Prefix.Addr()) || n.Prefix.Bits() < req.Superblock.Bits() {
				add("VPC %s (%s) outside superblock %s", n.Name, n.Prefix, req.Superblock)
			}
			if n.Prefix.Bits() < cidr.MaxVPCBits {
				add("VPC %s (%s) larger than /%d", n.Name, n.Prefix, cidr.MaxVPCBits)
			}
			continue
		}
		parent, ok := byName[n.Parent]
		if !ok {
			add("%s: unknown parent %s", n.Name, n.Parent)
			continue
		}
		if !parent.Prefix.Contains(n.Prefix.Addr()) || n.Prefix.Bits() < parent.Prefix.Bits() {
			add("%s (%s) outside parent %s (%s)", n.Name, n.Prefix, parent.Name, parent.Prefix)
		}
		usable := size(n.Prefix) - cidr.ReservedPerSubnet
		if usable < n.Hosts*growth {
			add("%s: usable %d < hosts %d x growth %d", n.Name, usable, n.Hosts, growth)
		}
		if n.Prefix.Bits() > cidr.MinSubnetBits {
			add("%s: /%d smaller than /%d", n.Name, n.Prefix.Bits(), cidr.MinSubnetBits)
		}
		childSizes[n.Parent] += size(n.Prefix)
	}
	for name, sum := range childSizes {
		if got := size(byName[name].Prefix); got < growth*sum {
			add("VPC %s: size %d < growth %d x children %d", name, got, growth, sum)
		}
	}
	wantCount := 0
	for _, need := range req.Needs {
		vpc := need.Cloud + "-" + need.Region + "-" + need.Env
		v, ok := byName[vpc]
		wantCount++
		if !ok || v.Parent != "" || v.Tier != "" {
			add("need %s: no VPC of that name", vpc)
			continue
		}
		for _, tn := range need.Tiers {
			wantCount++
			s, ok := byName[vpc+"-"+string(tn.Tier)]
			switch {
			case !ok:
				add("need %s: tier %s missing", vpc, tn.Tier)
			case s.Parent != vpc || s.Tier != tn.Tier || s.Hosts != tn.Hosts:
				add("need %s: subnet %s is %+v", vpc, s.Name, s)
			}
		}
	}
	if len(plan.Networks) != wantCount {
		add("%d networks, want %d (one VPC per need, one subnet per tier)", len(plan.Networks), wantCount)
	}
	return out
}

// TestAllocatorProperty proves criterion C2: on random feasible requests, the
// plan is allocated, has no overlap, no subnet outside its parent, no VPC
// outside the superblock, no network on a reserved range, and keeps the margin.
func TestAllocatorProperty(t *testing.T) {
	var plans, allocated, violations int
	rapid.Check(t, func(t *rapid.T) {
		req := genRequest(t)
		plans++
		plan, err := cidr.Allocate(req)
		if err != nil {
			t.Fatalf("Allocate(%+v): %v (the request is feasible by construction)", req, err)
		}
		allocated++
		if f := cidr.Check(plan); len(f) != 0 {
			violations++
			t.Fatalf("Check found %d findings on an allocated plan: %+v", len(f), f)
		}
		if v := planViolations(req, plan); len(v) != 0 {
			violations++
			t.Fatalf("plan violates %d invariants: %q\nrequest: %+v\nplan: %+v", len(v), v, req, plan)
		}
	})
	t.Logf("plans=%d allocated=%d violations=%d", plans, allocated, violations)
	if allocated != plans || violations != 0 {
		t.Fatalf("plans=%d allocated=%d violations=%d", plans, allocated, violations)
	}
}
