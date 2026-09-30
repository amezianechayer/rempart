package domain

import "errors"

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
)

var (
	nodeKinds = map[NodeKind]bool{
		KindInternet: true, KindNetwork: true, KindCompute: true, KindK8sCluster: true,
		KindK8sWorkload: true, KindLoadBalancer: true, KindDataStore: true,
	}
	edgeTypes = map[EdgeType]bool{EdgeMemberOf: true, EdgeExposes: true, EdgeCanReach: true, EdgeStores: true}
)

// Validate checks the structural invariants of g: unique identifiers, closed
// kinds and types, edges between existing nodes, CAN_REACH with a non-empty
// path of Network nodes, no EXPOSES edge from a member of a data tier subnet.
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
		nodes[n.ID] = n
	}
	edges := make(map[string]bool, len(g.Edges))
	dataMember := map[string]bool{}
	for _, e := range g.Edges {
		if edges[e.ID] {
			return ErrDuplicateEdge
		}
		edges[e.ID] = true
		if !edgeTypes[e.Type] {
			return ErrEdgeType
		}
		_, srcOK := nodes[e.Src]
		dst, dstOK := nodes[e.Dst]
		if !srcOK || !dstOK {
			return ErrDanglingEdge
		}
		if e.Type == EdgeMemberOf && dst.Kind == KindNetwork && dst.Attrs.Tier != nil && *dst.Attrs.Tier == "data" {
			dataMember[e.Src] = true
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
	return nil
}
