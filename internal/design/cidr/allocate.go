package cidr

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"math/bits"
	"net/netip"
	"regexp"
	"slices"
)

var (
	regionPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}[a-z0-9]$`)
	allocClouds   = []string{"aws", "azure", "scaleway", "ovhcloud"}
	allocEnvs     = []string{"dev", "staging", "prod"}
	tierOrder     = map[Tier]int{TierPublic: 0, TierApp: 1, TierData: 2, TierMgmt: 3}
	rfc1918       = []netip.Prefix{
		netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, 0, 0}), 8),
		netip.PrefixFrom(netip.AddrFrom4([4]byte{172, 16, 0, 0}), 12),
		netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, 0, 0}), 16),
	}
)

// block is a half-open range [start, end) of the IPv4 space.
type block struct{ start, end uint64 }

type subnetPlan struct {
	tier  Tier
	hosts int
	size  uint64
}

type vpcPlan struct {
	name  string
	hosts int
	size  uint64
	subs  []subnetPlan
	start uint64
}

func invalid(reason string) error { return fmt.Errorf("%w: %s", ErrInvalidRequest, reason) }

func canonicalV4(p netip.Prefix) bool {
	return p.IsValid() && p.Addr().Is4() && p == p.Masked()
}

func validate(r Request) error {
	if !canonicalV4(r.Superblock) {
		return invalid("superblock is not a canonical IPv4 prefix")
	}
	if b := r.Superblock.Bits(); b < 8 || b > 24 {
		return invalid("superblock length outside /8 to /24")
	}
	if !slices.ContainsFunc(rfc1918, func(p netip.Prefix) bool {
		return p.Contains(r.Superblock.Addr()) && r.Superblock.Bits() >= p.Bits()
	}) {
		return invalid("superblock outside RFC 1918")
	}
	if len(r.Reserved) > MaxReserved {
		return invalid("too many reserved ranges")
	}
	for _, p := range r.Reserved {
		if !canonicalV4(p) {
			return invalid("reserved range is not a canonical IPv4 prefix")
		}
	}
	if r.Growth < 0 || r.Growth > 16 {
		return invalid("growth outside 0 to 16")
	}
	if len(r.Needs) == 0 || len(r.Needs) > MaxNeeds {
		return invalid("number of needs outside 1 to 64")
	}
	seen := map[[3]string]bool{}
	for _, n := range r.Needs {
		k := [3]string{n.Cloud, n.Region, n.Env}
		if seen[k] {
			return invalid("duplicate need")
		}
		seen[k] = true
		if !slices.Contains(allocClouds, n.Cloud) || !slices.Contains(allocEnvs, n.Env) || !regionPattern.MatchString(n.Region) {
			return invalid("unknown cloud, region or environment")
		}
		if len(n.Tiers) == 0 || len(n.Tiers) > len(tierOrder) {
			return invalid("number of tiers outside 1 to 4")
		}
		tiers := map[Tier]bool{}
		for _, t := range n.Tiers {
			if _, ok := tierOrder[t.Tier]; !ok || tiers[t.Tier] {
				return invalid("unknown or duplicate tier")
			}
			tiers[t.Tier] = true
			if t.Hosts < 1 || t.Hosts > MaxHosts {
				return invalid("hosts outside 1 to 16384")
			}
		}
	}
	return nil
}

// ceilPow2 returns the smallest power of two >= n (n >= 1).
func ceilPow2(n uint64) uint64 {
	if n <= 1 {
		return 1
	}
	return uint64(1) << bits.Len64(n-1)
}

func addrToUint(a netip.Addr) uint64 {
	b := a.As4()
	return uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])
}

func uintToPrefix(start, size uint64) netip.Prefix {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], start)
	a := netip.AddrFrom4([4]byte(b[4:]))
	return netip.PrefixFrom(a, 32-(bits.Len64(size)-1))
}

func toBlock(p netip.Prefix) block {
	s := addrToUint(p.Addr())
	return block{start: s, end: s + uint64(1)<<(32-p.Bits())}
}

func alignUp(x, size uint64) uint64 { return (x + size - 1) / size * size }

// Allocate plans the needs of r (plans P1 to P6): same set of needs, same plan,
// to the byte, whatever their order.
func Allocate(r Request) (Plan, error) {
	if err := validate(r); err != nil {
		return Plan{}, err
	}
	growth := r.Growth
	if growth == 0 {
		growth = DefaultGrowth
	}
	g := uint64(growth)

	vpcs := make([]vpcPlan, 0, len(r.Needs))
	for _, n := range r.Needs {
		v := vpcPlan{name: n.Cloud + "-" + n.Region + "-" + n.Env}
		var sum uint64
		for _, t := range n.Tiers {
			size := max(ceilPow2(uint64(t.Hosts)*g+ReservedPerSubnet), uint64(1)<<(32-MinSubnetBits)) //nolint:gosec // G115: Hosts checked in 1..MaxHosts by validate.
			v.subs = append(v.subs, subnetPlan{tier: t.Tier, hosts: t.Hosts, size: size})
			v.hosts += t.Hosts
			sum += size
		}
		v.size = ceilPow2(g * ceilPow2(sum))
		if v.size > uint64(1)<<(32-MaxVPCBits) {
			return Plan{}, invalid("VPC larger than /16")
		}
		// Subnets: size descending, then tier order (plan P4).
		slices.SortStableFunc(v.subs, func(a, b subnetPlan) int {
			return cmp.Or(cmp.Compare(b.size, a.size), cmp.Compare(tierOrder[a.tier], tierOrder[b.tier]))
		})
		vpcs = append(vpcs, v)
	}
	// VPCs: size descending, then name (plan P4); names are unique.
	slices.SortStableFunc(vpcs, func(a, b vpcPlan) int {
		return cmp.Or(cmp.Compare(b.size, a.size), cmp.Compare(a.name, b.name))
	})

	sb := toBlock(r.Superblock)
	occupied := make([]block, 0, len(r.Reserved)+len(vpcs))
	for _, p := range r.Reserved {
		occupied = append(occupied, toBlock(p))
	}
	for i := range vpcs {
		v := &vpcs[i]
		cand := alignUp(sb.start, v.size)
		for {
			if cand+v.size > sb.end {
				return Plan{}, ErrExhausted
			}
			j := slices.IndexFunc(occupied, func(o block) bool { return o.start < cand+v.size && cand < o.end })
			if j < 0 {
				break
			}
			cand = alignUp(occupied[j].end, v.size)
		}
		v.start = cand
		occupied = append(occupied, block{start: cand, end: cand + v.size})
	}

	plan := Plan{Superblock: r.Superblock, Growth: growth, Networks: []Network{}, External: []netip.Prefix{}}
	for _, v := range vpcs {
		plan.Networks = append(plan.Networks, Network{Name: v.name, Prefix: uintToPrefix(v.start, v.size), Hosts: v.hosts})
		at := v.start
		for _, s := range v.subs {
			plan.Networks = append(plan.Networks, Network{
				Name: v.name + "-" + string(s.tier), Parent: v.name, Tier: s.tier,
				Prefix: uintToPrefix(at, s.size), Hosts: s.hosts,
			})
			at += s.size
		}
	}
	slices.SortStableFunc(plan.Networks, func(a, b Network) int {
		return cmp.Or(a.Prefix.Addr().Compare(b.Prefix.Addr()), cmp.Compare(a.Prefix.Bits(), b.Prefix.Bits()))
	})
	plan.External = append(plan.External, r.Reserved...)
	slices.SortFunc(plan.External, func(a, b netip.Prefix) int {
		return cmp.Or(a.Addr().Compare(b.Addr()), cmp.Compare(a.Bits(), b.Bits()))
	})
	plan.External = slices.Compact(plan.External)
	return plan, nil
}
