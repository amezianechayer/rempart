package domain

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
)

// Structural errors of Validate. Fixed messages: they never quote the graph.
var (
	ErrVersion         = errors.New("graph: unknown version")
	ErrSource          = errors.New("graph: unknown source")
	ErrTenant          = errors.New("graph: missing tenant")
	ErrDuplicateNode   = errors.New("graph: duplicate node id")
	ErrNodeKind        = errors.New("graph: unknown node kind")
	ErrDuplicateEdge   = errors.New("graph: duplicate edge id")
	ErrEdgeType        = errors.New("graph: unknown edge type")
	ErrDanglingEdge    = errors.New("graph: edge to an unknown node")
	ErrReachPath       = errors.New("graph: CAN_REACH without a path of Network nodes")
	ErrExposedDataTier = errors.New("graph: EXPOSES from a member of a data tier subnet")
	// ADR 0010, D6.
	ErrIDPrefix     = errors.New("graph: node id prefix does not match the node kind")
	ErrEndpointKind = errors.New("graph: edge between nodes of the wrong kinds")
	ErrPortRange    = errors.New("graph: port_from greater than port_to")
	ErrLoadBalancer = errors.New("graph: load balancer public flag or listeners inconsistent with its EXPOSES edges")
	ErrAPISources   = errors.New("graph: api_allowed_sources without a public API")
	ErrSourceCIDR   = errors.New("graph: source is not a canonical IPv4 prefix")
	ErrAttrKind     = errors.New("graph: attribute on a node or edge of another kind")
)

var (
	nodeKinds = map[NodeKind]bool{
		KindInternet: true, KindNetwork: true, KindCompute: true, KindK8sCluster: true,
		KindK8sWorkload: true, KindLoadBalancer: true, KindDataStore: true,
		KindIdentity: true, KindAccount: true,
	}
	edgeTypes = map[EdgeType]bool{
		EdgeMemberOf: true, EdgeExposes: true, EdgeCanReach: true, EdgeStores: true,
		EdgeRunsAs: true, EdgeHasPermission: true,
	}
	// endpoints are the kinds allowed at each end of the typed edges of D6.
	endpoints = map[EdgeType][2]map[NodeKind]bool{
		EdgeRunsAs:        {{KindCompute: true, KindK8sCluster: true, KindK8sWorkload: true}, {KindIdentity: true}},
		EdgeHasPermission: {{KindIdentity: true}, {KindDataStore: true, KindAccount: true, KindK8sCluster: true}},
		EdgeExposes:       {{KindLoadBalancer: true, KindCompute: true}, {KindInternet: true}},
	}
)

// Validate checks the structural invariants of g: unique identifiers, closed
// kinds and types, identifier prefixes matching the kind, edges between
// existing nodes of the allowed kinds, security attributes only where they
// apply, canonical sources, CAN_REACH with a non-empty path of Network nodes,
// no EXPOSES edge from a member of a data tier subnet, load balancers whose
// public flag and listeners match their EXPOSES edges.
func Validate(g Graph) error {
	if g.Version != GraphVersion {
		return ErrVersion
	}
	if g.Source != SourceDesign && g.Source != SourceObserved {
		return ErrSource
	}
	if g.TenantID == "" {
		return ErrTenant
	}
	nodes := make(map[string]Node, len(g.Nodes))
	for _, n := range g.Nodes {
		if _, dup := nodes[n.ID]; dup {
			return ErrDuplicateNode
		}
		if !nodeKinds[n.Kind] {
			return ErrNodeKind
		}
		if err := checkNode(n); err != nil {
			return err
		}
		nodes[n.ID] = n
	}
	edges := make(map[string]bool, len(g.Edges))
	dataMember := map[string]bool{}
	exposes := map[string][]Edge{}
	for _, e := range g.Edges {
		if edges[e.ID] {
			return ErrDuplicateEdge
		}
		edges[e.ID] = true
		if !edgeTypes[e.Type] {
			return ErrEdgeType
		}
		src, srcOK := nodes[e.Src]
		dst, dstOK := nodes[e.Dst]
		if !srcOK || !dstOK {
			return ErrDanglingEdge
		}
		if err := checkEdge(e, src, dst); err != nil {
			return err
		}
		if e.Type == EdgeMemberOf && dst.Kind == KindNetwork && dst.Attrs.Tier != nil && *dst.Attrs.Tier == "data" {
			dataMember[e.Src] = true
		}
		if e.Type == EdgeExposes {
			exposes[e.Src] = append(exposes[e.Src], e)
		}
		if e.Type == EdgeCanReach {
			if len(e.Attrs.Path) == 0 {
				return ErrReachPath
			}
			for _, id := range e.Attrs.Path {
				if n, ok := nodes[id]; !ok || n.Kind != KindNetwork {
					return ErrReachPath
				}
			}
		}
	}
	for _, e := range g.Edges {
		if e.Type == EdgeExposes && dataMember[e.Src] {
			return ErrExposedDataTier
		}
	}
	for _, n := range g.Nodes {
		if n.Kind == KindLoadBalancer && !loadBalancerConsistent(n, exposes[n.ID]) {
			return ErrLoadBalancer
		}
	}
	return nil
}

// checkNode checks the identifier prefix and the security attributes of n:
// each applies to one kind only, so no fact escapes reach.FromGraph (T116).
func checkNode(n Node) error {
	if (n.ID == "internet") != (n.Kind == KindInternet) ||
		strings.HasPrefix(n.ID, "id:") != (n.Kind == KindIdentity) ||
		strings.HasPrefix(n.ID, "acct:") != (n.Kind == KindAccount) {
		return ErrIDPrefix
	}
	a := n.Attrs
	only := []struct {
		set  bool
		kind NodeKind
	}{
		{a.PublicIP != nil, KindCompute},
		{a.PublicAccess != nil, KindDataStore},
		{a.Credential != nil, KindIdentity},
		{a.Public != nil || a.Listeners != nil, KindLoadBalancer},
		{a.APIPublic != nil || a.APIAllowedSources != nil || a.AuditLog != nil || a.SecretsEncryption != nil ||
			a.NetworkPolicyDefaultDeny != nil || a.AdmissionPolicy != nil || a.WorkloadIdentity != nil, KindK8sCluster},
	}
	for _, o := range only {
		if o.set && n.Kind != o.kind {
			return ErrAttrKind
		}
	}
	if len(a.APIAllowedSources) > 0 && (a.APIPublic == nil || !*a.APIPublic) {
		return ErrAPISources
	}
	return checkSources(a.APIAllowedSources)
}

// checkEdge checks the kinds at both ends, the attributes and the port range of e.
func checkEdge(e Edge, src, dst Node) error {
	if ends, typed := endpoints[e.Type]; typed && (!ends[0][src.Kind] || !ends[1][dst.Kind]) {
		return ErrEndpointKind
	}
	a := e.Attrs
	if a.Actions != nil && e.Type != EdgeHasPermission {
		return ErrAttrKind
	}
	if a.AllowedSources != nil && e.Type != EdgeExposes && (e.Type != EdgeCanReach || src.Kind != KindInternet) {
		return ErrAttrKind
	}
	if a.PortFrom != nil && a.PortTo != nil && *a.PortFrom > *a.PortTo {
		return ErrPortRange
	}
	return checkSources(a.AllowedSources)
}

// checkSources requires canonical IPv4 prefixes of length 1 to 32: the whole
// Internet is written only as an empty list (ADR 0010, D6).
func checkSources(sources []string) error {
	for _, s := range sources {
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() < 1 || p.String() != s {
			return ErrSourceCIDR
		}
	}
	return nil
}

// loadBalancerConsistent: public if and only if an EXPOSES edge leaves the
// load balancer, and one EXPOSES edge of the same protocol and single port per
// listener, and conversely; otherwise a public listener would escape row R1
// of reach.FromGraph.
func loadBalancerConsistent(n Node, exposes []Edge) bool {
	public := n.Attrs.Public != nil && *n.Attrs.Public
	if public != (len(exposes) > 0) {
		return false
	}
	listeners := map[string]bool{}
	if n.Attrs.Listeners != nil {
		for _, l := range *n.Attrs.Listeners {
			listeners[l.Protocol+"/"+strconv.Itoa(l.Port)] = true
		}
	}
	exposed := map[string]bool{}
	for _, e := range exposes {
		a := e.Attrs
		if a.Protocol == nil || a.PortFrom == nil || a.PortTo == nil || *a.PortFrom != *a.PortTo {
			return false
		}
		k := *a.Protocol + "/" + strconv.Itoa(*a.PortFrom)
		if !listeners[k] {
			return false
		}
		exposed[k] = true
	}
	return len(exposed) == len(listeners)
}
