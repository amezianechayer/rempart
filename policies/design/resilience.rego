package rempart.design.resilience

# observed: metrics and logs both declared.
observed if {
	input.derived.observability.metrics == true
	input.derived.observability.logs == true
}

replicated(n) if n.attrs.count >= 2

highly_available(n) if n.attrs.count >= 3

# METADATA
# title: Production sans métriques ou sans journaux
# custom:
#   control_id: OBS-001
#   severity: medium
#   remediation: advisory
#   frameworks: {}
deny contains f if {
	input.derived.environment == "prod"
	not observed
	some n in input.graph.nodes
	n.kind in {"Compute", "K8sCluster"}
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": n.id}
}

# METADATA
# title: Base de données de production sur un seul nœud
# custom:
#   control_id: AVL-001
#   severity: medium
#   remediation: advisory
#   frameworks: {}
deny contains f if {
	input.derived.environment == "prod"
	some n in input.graph.nodes
	n.kind == "DataStore"
	n.attrs.subtype == "managed_db"
	not replicated(n)
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": n.id}
}

# METADATA
# title: Cluster de production à moins de trois nœuds
# custom:
#   control_id: AVL-002
#   severity: low
#   remediation: advisory
#   frameworks: {}
deny contains f if {
	input.derived.environment == "prod"
	some n in input.graph.nodes
	n.kind == "K8sCluster"
	not highly_available(n)
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": n.id}
}
