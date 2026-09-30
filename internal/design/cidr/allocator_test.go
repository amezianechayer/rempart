package cidr_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"github.com/amezianechayer/rempart/internal/design/cidr"
)

// referenceRequest holds the needs of the reference scenario (plan section 7):
// public 8 and app 96 on AWS, data 3 on Azure, default superblock and growth.
func referenceRequest() cidr.Request {
	return cidr.Request{
		Superblock: netip.MustParsePrefix("10.0.0.0/8"),
		Needs: []cidr.Need{
			{Cloud: "aws", Region: "eu-west-3", Env: "staging", Tiers: []cidr.TierNeed{
				{Tier: cidr.TierPublic, Hosts: 8},
				{Tier: cidr.TierApp, Hosts: 96},
			}},
			{Cloud: "azure", Region: "francecentral", Env: "staging", Tiers: []cidr.TierNeed{
				{Tier: cidr.TierData, Hosts: 3},
			}},
		},
	}
}

// referenceNetworks is the table of plan section 7, in plan order.
var referenceNetworks = []cidr.Network{
	{Name: "aws-eu-west-3-staging", Prefix: netip.MustParsePrefix("10.0.0.0/20"), Hosts: 104},
	{Name: "aws-eu-west-3-staging-app", Parent: "aws-eu-west-3-staging", Tier: cidr.TierApp, Prefix: netip.MustParsePrefix("10.0.0.0/23"), Hosts: 96},
	{Name: "aws-eu-west-3-staging-public", Parent: "aws-eu-west-3-staging", Tier: cidr.TierPublic, Prefix: netip.MustParsePrefix("10.0.2.0/26"), Hosts: 8},
	{Name: "azure-francecentral-staging", Prefix: netip.MustParsePrefix("10.0.16.0/25"), Hosts: 3},
	{Name: "azure-francecentral-staging-data", Parent: "azure-francecentral-staging", Tier: cidr.TierData, Prefix: netip.MustParsePrefix("10.0.16.0/27"), Hosts: 3},
}

func mustAllocate(t *testing.T, r cidr.Request) cidr.Plan {
	t.Helper()
	p, err := cidr.Allocate(r)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	return p
}

func mustReferenceJSON(t *testing.T, p cidr.Plan) []byte {
	t.Helper()
	b, err := cidr.ReferenceJSON(p)
	if err != nil {
		t.Fatalf("ReferenceJSON: %v", err)
	}
	return b
}

func decodeJSON(t *testing.T, raw []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode %q: %v", raw, err)
	}
	return v
}

// TestAllocatorDeterministic proves plan P5: the reference request gives the
// table of plan section 7, the same bytes twice, and the same plan whatever
// the order of the needs and of their tiers.
func TestAllocatorDeterministic(t *testing.T) {
	req := referenceRequest()
	plan := mustAllocate(t, req)
	if plan.Superblock != req.Superblock || plan.Growth != cidr.DefaultGrowth {
		t.Fatalf("plan superblock %s growth %d, want %s growth %d", plan.Superblock, plan.Growth, req.Superblock, cidr.DefaultGrowth)
	}
	if !reflect.DeepEqual(plan.Networks, referenceNetworks) {
		t.Fatalf("networks:\n got %+v\nwant %+v", plan.Networks, referenceNetworks)
	}
	if len(plan.External) != 0 {
		t.Fatalf("external %v, want none", plan.External)
	}

	first := mustReferenceJSON(t, plan)
	if second := mustReferenceJSON(t, mustAllocate(t, referenceRequest())); !bytes.Equal(first, second) {
		t.Fatalf("ReferenceJSON differs between two calls:\n%s\n%s", first, second)
	}
	// The reference format of plan section 7 is the golden valid_reference case.
	golden := readGolden(t, "valid_reference.plan.json")
	if got, want := decodeJSON(t, first), decodeJSON(t, golden); !reflect.DeepEqual(got, want) {
		t.Fatalf("ReferenceJSON:\n got %s\nwant %s", first, golden)
	}

	rng := rand.New(rand.NewPCG(20260930, 4)) //nolint:gosec // G404: fixed seed for reproducible permutations, not a secret.
	for i := range 20 {
		perm := referenceRequest()
		rng.Shuffle(len(perm.Needs), func(a, b int) { perm.Needs[a], perm.Needs[b] = perm.Needs[b], perm.Needs[a] })
		for j := range perm.Needs {
			tiers := perm.Needs[j].Tiers
			rng.Shuffle(len(tiers), func(a, b int) { tiers[a], tiers[b] = tiers[b], tiers[a] })
		}
		got := mustAllocate(t, perm)
		if !reflect.DeepEqual(got, plan) {
			t.Fatalf("permutation %d (%+v): plan\n %+v\nwant\n %+v", i, perm.Needs, got, plan)
		}
		if b := mustReferenceJSON(t, got); !bytes.Equal(b, first) {
			t.Fatalf("permutation %d: ReferenceJSON differs", i)
		}
	}
}

// boundNeed gives a VPC of exactly /20 at the default growth: one app subnet
// of 200 hosts needs 805 addresses, a /22, and the VPC 4 x 1024 addresses.
func boundNeed(env string) cidr.Need {
	return cidr.Need{Cloud: "aws", Region: "eu-west-3", Env: env, Tiers: []cidr.TierNeed{{Tier: cidr.TierApp, Hosts: 200}}}
}

// TestAllocatorExhausted proves the bounds of plans P3, P4 and P6: a VPC that
// exactly fills the superblock fits, one more does not, a reserved range can
// take the whole superblock, and every invalid request is refused.
func TestAllocatorExhausted(t *testing.T) {
	sb20 := netip.MustParsePrefix("10.0.0.0/20")

	t.Run("exact_fit", func(t *testing.T) {
		p := mustAllocate(t, cidr.Request{Superblock: sb20, Needs: []cidr.Need{boundNeed("prod")}})
		vpcs := slices.DeleteFunc(slices.Clone(p.Networks), func(n cidr.Network) bool { return n.Parent != "" })
		if len(vpcs) != 1 || vpcs[0].Prefix != sb20 {
			t.Fatalf("VPCs %+v, want one VPC equal to %s", vpcs, sb20)
		}
	})

	t.Run("second_need_exhausts", func(t *testing.T) {
		p, err := cidr.Allocate(cidr.Request{Superblock: sb20, Needs: []cidr.Need{boundNeed("prod"), boundNeed("dev")}})
		if !errors.Is(err, cidr.ErrExhausted) {
			t.Fatalf("Allocate = %+v, %v; want ErrExhausted", p, err)
		}
	})

	t.Run("reserved_takes_superblock", func(t *testing.T) {
		p, err := cidr.Allocate(cidr.Request{Superblock: sb20, Reserved: []netip.Prefix{sb20}, Needs: []cidr.Need{boundNeed("prod")}})
		if !errors.Is(err, cidr.ErrExhausted) {
			t.Fatalf("Allocate = %+v, %v; want ErrExhausted", p, err)
		}
	})

	valid := func() cidr.Request {
		return cidr.Request{Superblock: netip.MustParsePrefix("10.0.0.0/8"), Needs: []cidr.Need{boundNeed("prod")}}
	}
	invalid := []struct {
		name   string
		mutate func(r *cidr.Request)
	}{
		{"invalid_public_superblock", func(r *cidr.Request) { r.Superblock = netip.MustParsePrefix("8.0.0.0/8") }},
		{"invalid_non_canonical_superblock", func(r *cidr.Request) {
			r.Superblock = netip.PrefixFrom(netip.MustParseAddr("10.0.0.1"), 8)
		}},
		{"invalid_ipv6_superblock", func(r *cidr.Request) { r.Superblock = netip.MustParsePrefix("fd00::/8") }},
		{"invalid_zero_superblock", func(r *cidr.Request) { r.Superblock = netip.Prefix{} }},
		{"invalid_duplicate_need", func(r *cidr.Request) { r.Needs = append(r.Needs, boundNeed("prod")) }},
		{"invalid_hosts_zero", func(r *cidr.Request) { r.Needs[0].Tiers[0].Hosts = 0 }},
		{"invalid_hosts_above_max", func(r *cidr.Request) { r.Needs[0].Tiers[0].Hosts = cidr.MaxHosts + 1 }},
		{"invalid_vpc_beyond_16", func(r *cidr.Request) { r.Needs[0].Tiers[0].Hosts = cidr.MaxHosts }},
		{"invalid_region_EU_WEST", func(r *cidr.Request) { r.Needs[0].Region = "EU_WEST" }},
		{"invalid_no_need", func(r *cidr.Request) { r.Needs = nil }},
		{"invalid_growth_17", func(r *cidr.Request) { r.Growth = 17 }},
		{"invalid_non_canonical_reserved", func(r *cidr.Request) {
			r.Reserved = []netip.Prefix{netip.PrefixFrom(netip.MustParseAddr("192.168.1.1"), 16)}
		}},
	}
	for _, c := range invalid {
		t.Run(c.name, func(t *testing.T) {
			r := valid()
			c.mutate(&r)
			p, err := cidr.Allocate(r)
			if !errors.Is(err, cidr.ErrInvalidRequest) {
				t.Fatalf("Allocate = %+v, %v; want ErrInvalidRequest", p, err)
			}
			if errors.Is(err, cidr.ErrExhausted) {
				t.Fatalf("error %v is also ErrExhausted", err)
			}
		})
	}
	// Control: the valid request of the invalid_* subtests is accepted.
	if _, err := cidr.Allocate(valid()); err != nil {
		t.Fatalf("valid request refused: %v", err)
	}
}
