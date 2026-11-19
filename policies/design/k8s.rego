package rempart.design.kubernetes

import data.rempart.design.lib

# Design controls on Kubernetes; policies/k8s/ takes the same control_id at
# the manifest level in M3 (D13 of docs/plans/M2-overview.md).

clusters contains n if {
	some n in input.graph.nodes
	n.kind == "K8sCluster"
}

# METADATA
# title: API du cluster publique sans restriction de source
# custom:
#   control_id: K8S-001
#   severity: critical
#   remediation: make_private
#   frameworks: {}
deny contains f if {
	some n in clusters
	not n.attrs.api_public == false
	count(object.get(n.attrs, "api_allowed_sources", [])) == 0
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": n.id}
}

# METADATA
# title: Journal d'audit du cluster désactivé
# custom:
#   control_id: K8S-002
#   severity: high
#   remediation: enable_audit_log
#   frameworks: {}
deny contains f if {
	some n in clusters
	not n.attrs.audit_log == true
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": n.id}
}

# METADATA
# title: Secrets du cluster non chiffrés par une clé KMS
# custom:
#   control_id: K8S-003
#   severity: high
#   remediation: enable_secrets_encryption
#   frameworks: {}
deny contains f if {
	some n in clusters
	not n.attrs.secrets_encryption == true
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": n.id}
}

# METADATA
# title: API du cluster publique, restreinte à des sources
# custom:
#   control_id: K8S-004
#   severity: medium
#   remediation: advisory
#   frameworks: {}
deny contains f if {
	some n in clusters
	n.attrs.api_public == true
	count(object.get(n.attrs, "api_allowed_sources", [])) > 0
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": n.id}
}

# METADATA
# title: Politique d'admission absente
# custom:
#   control_id: K8S-010
#   severity: high
#   remediation: enable_admission
#   frameworks: {}
deny contains f if {
	some n in clusters
	not n.attrs.admission_policy == true
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": n.id}
}

# METADATA
# title: NetworkPolicy refus par défaut absente
# custom:
#   control_id: K8S-020
#   severity: high
#   remediation: default_deny_netpol
#   frameworks: {}
deny contains f if {
	some n in clusters
	not n.attrs.network_policy_default_deny == true
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": n.id}
}

# METADATA
# title: Compte de service avec droit d'administration ou « * »
# custom:
#   control_id: K8S-030
#   severity: critical
#   remediation: least_privilege
#   frameworks: {}
deny contains f if {
	some e in input.graph.edges
	e.type == "HAS_PERMISSION"
	lib.nodes[e.src].kind == "Identity"
	not lib.nodes[e.src].attrs.subtype == "role"
	some a in lib.actions(e)
	a in {"admin", "*"}
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": e.id}
}

# METADATA
# title: Identités de workload désactivées sur le cluster
# custom:
#   control_id: K8S-040
#   severity: high
#   remediation: use_workload_identity
#   frameworks: {}
deny contains f if {
	some n in clusters
	not n.attrs.workload_identity == true
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": n.id}
}

# METADATA
# title: Contrôleur GitOps exposé à Internet
# custom:
#   control_id: K8S-050
#   severity: high
#   remediation: remove_exposure
#   frameworks: {}
deny contains f if {
	some w, role in input.derived.workload_roles
	role == "gitops_controller"
	lib.exposed(w)
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": w}
}
