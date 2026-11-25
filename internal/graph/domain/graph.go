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
	KindIdentity     NodeKind = "Identity" // workload identity (ADR 0010, D6)
	KindAccount      NodeKind = "Account"  // cloud account or subscription
)

// EdgeType is the closed type of an edge.
type EdgeType string

const (
	EdgeMemberOf EdgeType = "MEMBER_OF"
	EdgeExposes  EdgeType = "EXPOSES"
	EdgeCanReach EdgeType = "CAN_REACH"
	EdgeStores   EdgeType = "STORES"
	// EdgeRunsAs: Compute, K8sCluster or K8sWorkload to its Identity.
	EdgeRunsAs EdgeType = "RUNS_AS"
	// EdgeHasPermission: Identity to DataStore, Account or K8sCluster, with
	// abstract actions (ADR 0010, D8).
	EdgeHasPermission EdgeType = "HAS_PERMISSION"
)

// Abstract permissions of HAS_PERMISSION (ADR 0010, D8): never a concrete IAM
// action before L3.
const (
	ActionRead  = "read"  // data plane read
	ActionWrite = "write" // data plane write and delete
	ActionAdmin = "admin" // control plane: configuration, access policy, grants
	ActionAll   = "*"     // any present or future action: describes a trap, never built
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
	// ADR 0010, D6.
	Credential               *string  `json:"credential,omitempty"`
	PublicIP                 *bool    `json:"public_ip,omitempty"`
	APIAllowedSources        []string `json:"api_allowed_sources,omitempty"`
	AuditLog                 *bool    `json:"audit_log,omitempty"`
	SecretsEncryption        *bool    `json:"secrets_encryption,omitempty"`
	NetworkPolicyDefaultDeny *bool    `json:"network_policy_default_deny,omitempty"`
	AdmissionPolicy          *bool    `json:"admission_policy,omitempty"`
	WorkloadIdentity         *bool    `json:"workload_identity,omitempty"`
}

// EdgeAttrs are the closed attributes of an edge ($defs/edge_attrs).
type EdgeAttrs struct {
	Protocol *string `json:"protocol,omitempty"`
	PortFrom *int    `json:"port_from,omitempty"`
	PortTo   *int    `json:"port_to,omitempty"`
	Via      *string `json:"via,omitempty"`
	// Path of a CAN_REACH is descriptive, never normative (obligation (fv),
	// T116): besides the structural check of Validate (Network nodes), no
	// finding and no reach reads it, Derives refuses a rewritten path, a
	// revision may leave it citing a former subnet, and L3 recomputes paths
	// from the memberships.
	Path           []string `json:"path,omitempty"`
	AllowedSources []string `json:"allowed_sources,omitempty"`
	Actions        []string `json:"actions,omitempty"`
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
