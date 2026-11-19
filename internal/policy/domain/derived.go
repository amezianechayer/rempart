package domain

// Workload roles of the IR that the graph does not carry (K8S-050).
const (
	RoleGitOpsController   = "gitops_controller"
	RoleObservabilityStack = "observability_stack"
)

// Constraints of the IR read by the policies; an empty list sets no constraint.
type Constraints struct {
	AllowedRegions  []string `json:"allowed_regions"`
	ForbiddenClouds []string `json:"forbidden_clouds"`
}

// Observability declared by the IR; absent means false.
type Observability struct {
	Metrics bool `json:"metrics"`
	Logs    bool `json:"logs"`
}

// Derived are the facts computed in Go for the policies (ADR 0011 D5): no free
// text, identifiers checked against the graph.
type Derived struct {
	Jurisdiction         map[string]Zone   `json:"jurisdiction"`
	UnconfirmedExposures []string          `json:"unconfirmed_exposures"`
	SourcesUnresolved    []string          `json:"sources_unresolved"`
	Constraints          Constraints       `json:"constraints"`
	Environment          string            `json:"environment"`
	Observability        Observability     `json:"observability"`
	WorkloadRoles        map[string]string `json:"workload_roles"`
	// WorldSources are the EXPOSES edges, the CAN_REACH edges leaving the
	// Internet and the K8sCluster nodes whose sources cover the whole Internet
	// once merged (absent or empty included), sorted (obligation (fg), T102).
	WorldSources []string `json:"world_sources"`
}
