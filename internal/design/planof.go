package design

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"

	"github.com/amezianechayer/rempart/internal/design/cidr"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
)

// PlanOf reads back the CIDR plan of a graph (ADR 0012 D4): its Network
// nodes, their parent by MEMBER_OF between networks, tier and prefix, on the
// default superblock of Build (10.0.0.0/8), without reserved range. An
// unreadable prefix stays invalid, for cidr.Check to report it.
func PlanOf(f graphdomain.FactsGraph) (cidr.Plan, error) {
	kinds := make(map[string]graphdomain.NodeKind, len(f.Nodes))
	for _, n := range f.Nodes {
		kinds[n.ID] = n.Kind
	}
	parent := map[string]string{}
	for _, e := range f.Edges {
		if e.Type == graphdomain.EdgeMemberOf && kinds[e.Src] == graphdomain.KindNetwork && kinds[e.Dst] == graphdomain.KindNetwork {
			parent[e.Src] = strings.TrimPrefix(e.Dst, "net:")
		}
	}
	p := cidr.Plan{Superblock: netip.PrefixFrom(netip.AddrFrom4([4]byte{10}), 8), Networks: []cidr.Network{}, External: []netip.Prefix{}}
	for _, n := range f.Nodes {
		if n.Kind != graphdomain.KindNetwork {
			continue
		}
		w := cidr.Network{Name: strings.TrimPrefix(n.ID, "net:"), Parent: parent[n.ID]}
		if n.Attrs.Tier != nil {
			w.Tier = cidr.Tier(*n.Attrs.Tier)
		}
		if n.Attrs.CIDR != nil {
			if pr, err := netip.ParsePrefix(*n.Attrs.CIDR); err == nil {
				w.Prefix = pr
			}
		}
		p.Networks = append(p.Networks, w)
	}
	slices.SortStableFunc(p.Networks, func(a, b cidr.Network) int {
		return cmp.Or(a.Prefix.Addr().Compare(b.Prefix.Addr()), cmp.Compare(a.Prefix.Bits(), b.Prefix.Bits()), strings.Compare(a.Name, b.Name))
	})
	return p, nil
}
