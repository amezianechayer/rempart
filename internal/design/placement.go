package design

import (
	"github.com/amezianechayer/rempart/internal/design/cidr"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	intentdomain "github.com/amezianechayer/rempart/internal/intent/domain"
)

// Closed placement table of plan section 6.2.
const (
	k8sAddressesPerNode = 32 // one address per pod with the AWS VPC CNI (skill multicloud-networking)
	lbHosts             = 8
	defaultK8sNodes     = 3
	defaultVMs          = 1
	defaultDBNodes      = 2
)

// placement is where a workload goes: its node kind and subtype, its tier and
// its hosts (tier "" and hosts 0: no subnet).
type placement struct {
	kind    graphdomain.NodeKind
	subtype string
	tier    cidr.Tier
	hosts   int
	onK8s   bool // K8sWorkload, MEMBER_OF its cluster
}

func count(w intentdomain.Workload, def int) int {
	if w.Size != nil && w.Size.Count != nil {
		return *w.Size.Count
	}
	return def
}

// place applies the table of plan section 6.2; sensitive hosts go to the data
// tier (plan P8). ok is false for an unknown kind.
func place(w intentdomain.Workload, sensitiveHost bool) (placement, bool) {
	var p placement
	switch w.Kind {
	case "k8s_cluster":
		p = placement{kind: graphdomain.KindK8sCluster, tier: cidr.TierApp, hosts: count(w, defaultK8sNodes) * k8sAddressesPerNode}
	case "vm_group":
		p = placement{kind: graphdomain.KindCompute, subtype: "vm", tier: cidr.TierApp, hosts: count(w, defaultVMs)}
	case "managed_db":
		p = placement{kind: graphdomain.KindDataStore, subtype: "managed_db", tier: cidr.TierData, hosts: count(w, defaultDBNodes)}
	case "object_storage":
		return placement{kind: graphdomain.KindDataStore, subtype: "object_storage"}, true
	case "load_balancer":
		p = placement{kind: graphdomain.KindLoadBalancer, tier: cidr.TierPublic, hosts: lbHosts}
	case "observability_stack", "gitops_controller":
		if w.RunsOn != nil {
			return placement{kind: graphdomain.KindK8sWorkload, onK8s: true}, true
		}
		p = placement{kind: graphdomain.KindCompute, subtype: "vm", tier: cidr.TierApp, hosts: count(w, defaultVMs)}
	default:
		return placement{}, false
	}
	if sensitiveHost {
		p.tier = cidr.TierData
	}
	return p, true
}
