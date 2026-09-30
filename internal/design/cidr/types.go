// Package cidr plans CIDR ranges with a deterministic allocator in pure code
// and checks every plan with an independent verifier, a port of
// .claude/skills/multicloud-networking/scripts/cidr_check.py. No model ever
// chooses a range.
package cidr

import (
	"errors"
	"net/netip"
)

// Tier is the closed tier of a subnet.
type Tier string

const (
	TierPublic Tier = "public"
	TierApp    Tier = "app"
	TierData   Tier = "data"
	TierMgmt   Tier = "mgmt"
)

const (
	DefaultGrowth     = 4
	ReservedPerSubnet = 5
	MinSubnetBits     = 28 // longest subnet prefix
	MaxVPCBits        = 16 // shortest VPC prefix
	MaxNeeds          = 64
	MaxReserved       = 64
	MaxHosts          = 16384
)

// TierNeed is the number of hosts of one tier.
type TierNeed struct {
	Tier  Tier
	Hosts int
}

// Need is the need of one VPC: a (cloud, region, environment) triplet.
type Need struct {
	Cloud, Region, Env string
	Tiers              []TierNeed
}

// Request is the input of Allocate.
type Request struct {
	Superblock netip.Prefix
	Reserved   []netip.Prefix
	Needs      []Need
	Growth     int // 0: DefaultGrowth
}

// Network is a VPC (empty Parent and Tier, Hosts the sum of its tiers) or a
// subnet. Name: "<cloud>-<region>-<env>" for a VPC, "<vpc>-<tier>" for a subnet.
type Network struct {
	Name, Parent string
	Tier         Tier
	Prefix       netip.Prefix
	Hosts        int
}

// Plan is an allocated CIDR plan.
type Plan struct {
	Superblock netip.Prefix
	Growth     int
	Networks   []Network      // sorted by (address, length): a parent precedes its children
	External   []netip.Prefix // reserved ranges, sorted
}

var (
	ErrInvalidRequest = errors.New("cidr: invalid request")
	ErrExhausted      = errors.New("cidr: superblock exhausted")
)
