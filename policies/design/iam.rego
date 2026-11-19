package rempart.design.iam

import data.rempart.design.lib

# dedicated: exactly one identity, run by this workload only.
dedicated(w) if {
	ids := lib.identities(w)
	count(ids) == 1
	some i in ids
	count(lib.runners(i)) == 1
}

# justified: a runner of the identity hosts or reaches the data store.
justified(e) if {
	some w in lib.runners(e.src)
	some x in input.graph.edges
	x.type in {"STORES", "CAN_REACH"}
	x.src == w
	x.dst == e.dst
}

# METADATA
# title: Permission « * » (toute action)
# custom:
#   control_id: IAM-001
#   severity: critical
#   remediation: least_privilege
#   frameworks: {}
deny contains f if {
	some e in input.graph.edges
	e.type == "HAS_PERMISSION"
	"*" in lib.actions(e)
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": e.id}
}

# METADATA
# title: Écriture ou administration sur un compte entier
# custom:
#   control_id: IAM-002
#   severity: critical
#   remediation: least_privilege
#   frameworks: {}
deny contains f if {
	some e in input.graph.edges
	e.type == "HAS_PERMISSION"
	lib.nodes[e.dst].kind == "Account"
	some a in lib.actions(e)
	a in {"write", "admin", "*"}
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": e.id}
}

# METADATA
# title: Identité partagée entre tiers
# custom:
#   control_id: IAM-003
#   severity: high
#   remediation: dedicated_identity
#   frameworks: {}
deny contains f if {
	some n in input.graph.nodes
	n.kind == "Identity"
	count({lib.tiers(w) | some w in lib.runners(n.id)}) > 1
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": n.id}
}

# METADATA
# title: Workload exposé avec un droit d'administration
# custom:
#   control_id: IAM-004
#   severity: high
#   remediation: least_privilege
#   frameworks: {}
deny contains f if {
	some e in input.graph.edges
	e.type == "HAS_PERMISSION"
	some a in lib.actions(e)
	a in {"admin", "*"}
	some w in lib.runners(e.src)
	lib.exposed(w)
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": e.id}
}

# METADATA
# title: Identifiant statique au lieu d'une identité de workload
# custom:
#   control_id: IAM-005
#   severity: high
#   remediation: use_workload_identity
#   frameworks: {}
deny contains f if {
	some n in input.graph.nodes
	n.kind == "Identity"
	not n.attrs.credential == "workload_identity"
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": n.id}
}

# METADATA
# title: Workload sans identité dédiée
# custom:
#   control_id: IAM-006
#   severity: medium
#   remediation: advisory
#   frameworks: {}
deny contains f if {
	some n in input.graph.nodes
	n.kind in lib.workload_kinds
	not dedicated(n.id)
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": n.id}
}

# METADATA
# title: Permission sur une donnée ni hébergée ni atteinte
# custom:
#   control_id: IAM-007
#   severity: high
#   remediation: least_privilege
#   frameworks: {}
deny contains f if {
	some e in input.graph.edges
	e.type == "HAS_PERMISSION"
	lib.nodes[e.dst].kind == "DataStore"
	not justified(e)
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": e.id}
}
