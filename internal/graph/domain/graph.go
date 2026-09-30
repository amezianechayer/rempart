// Package domain holds the pure model of the architecture and security graph,
// common to the designed graph (loop L2) and the observed graph (loop L6):
// nodes, edges, closed attributes, free text confined to untrusted_text.
package domain

// GraphVersion is the version of schemas/graph/v1.json.
const GraphVersion = "1"

// Sources of a graph.
const (
	SourceDesign   = "design"
	SourceObserved = "observed"
)

// NodeKind is the closed kind of a node.
type NodeKind string

const (
	KindInternet     NodeKind = "Internet"
	KindNetwork      NodeKind = "Network"
	KindCompute      NodeKind = "Compute"
	KindK8sCluster   NodeKind = "K8sCluster"
	KindK8sWorkload  NodeKind = "K8sWorkload"
	KindLoadBalancer NodeKind = "LoadBalancer"
	KindDataStore    NodeKind = "DataStore"
)

// EdgeType is the closed type of an edge.
type EdgeType string

const (
	EdgeMemberOf EdgeType = "MEMBER_OF"
	EdgeExposes  EdgeType = "EXPOSES"
	EdgeCanReach EdgeType = "CAN_REACH"
	EdgeStores   EdgeType = "STORES"
)

// Graph is a graph of schemas/graph/v1.json.
type Graph struct {
	Version  string    `json:"version"`
	TenantID string    `json:"tenant_id"`
	Source   string    `json:"source"`
	Nodes    []Node    `json:"nodes"`
	Edges    []Edge    `json:"edges"`
	Text     GraphText `json:"untrusted_text"`
}

// Node is one node. Attrs holds facts only; Text holds the free text.
type Node struct {
	ID    string    `json:"id"`
	Kind  NodeKind  `json:"kind"`
	Attrs NodeAttrs `json:"attrs"`
	Text  NodeText  `json:"untrusted_text"`
}

// Edge is one directed edge. Attrs holds facts only; Text holds the free text.
type Edge struct {
	ID    string    `json:"id"`
	Type  EdgeType  `json:"type"`
	Src   string    `json:"src"`
	Dst   string    `json:"dst"`
	Attrs EdgeAttrs `json:"attrs"`
	Text  EdgeText  `json:"untrusted_text"`
}

// Listener is one listener of a load balancer.
type Listener struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

// NodeAttrs are the closed attributes of a node (schemas/graph/v1.json,
// $defs/node_attrs). No field holds free text.
type NodeAttrs struct {
	Cloud          *string     `json:"cloud,omitempty"`
	Region         *string     `json:"region,omitempty"`
	Env            *string     `json:"env,omitempty"`
	Subtype        *string     `json:"subtype,omitempty"`
	CIDR           *string     `json:"cidr,omitempty"`
	Tier           *string     `json:"tier,omitempty"`
	Count          *int        `json:"count,omitempty"`
	OS             *string     `json:"os,omitempty"`
	Public         *bool       `json:"public,omitempty"`
	Listeners      *[]Listener `json:"listeners,omitempty"`
	Behind         []string    `json:"behind,omitempty"`
	Classification *string     `json:"classification,omitempty"`
	Regulation     []string    `json:"regulation,omitempty"`
	Residency      *string     `json:"residency,omitempty"`
	Encrypted      *bool       `json:"encrypted,omitempty"`
	PublicAccess   *bool       `json:"public_access,omitempty"`
	APIPublic      *bool       `json:"api_public,omitempty"`
}

// EdgeAttrs are the closed attributes of an edge ($defs/edge_attrs).
type EdgeAttrs struct {
	Protocol       *string  `json:"protocol,omitempty"`
	PortFrom       *int     `json:"port_from,omitempty"`
	PortTo         *int     `json:"port_to,omitempty"`
	Via            *string  `json:"via,omitempty"`
	Path           []string `json:"path,omitempty"`
	AllowedSources []string `json:"allowed_sources,omitempty"`
}

// GraphText is the free text of the graph.
type GraphText struct {
	Summary *FreeText `json:"summary,omitempty"`
}

// NodeText is the free text of a node.
type NodeText struct {
	Notes         *FreeText `json:"notes,omitempty"`
	Justification *FreeText `json:"justification,omitempty"`
}

// EdgeText is the free text of an edge.
type EdgeText struct {
	Purpose       *FreeText `json:"purpose,omitempty"`
	Justification *FreeText `json:"justification,omitempty"`
}
