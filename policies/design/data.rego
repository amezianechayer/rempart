package rempart.design.data

import data.rempart.design.lib

rank := {"public": 1, "internal": 2, "confidential": 3, "regulated": 4}

# A data store is non public unless it is classified public and carries no
# regulation (T139, obligation (gr)).
non_public(n) if not n.attrs.classification == "public"

non_public(n) if lib.sensitive_data(n)

# METADATA
# title: Accès public sur une donnée non publique
# custom:
#   control_id: DATA-001
#   severity: critical
#   remediation: make_private
#   frameworks: {}
deny contains f if {
	some n in input.graph.nodes
	n.kind == "DataStore"
	not n.attrs.public_access == false
	non_public(n)
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": n.id}
}

# METADATA
# title: Donnée confidentielle ou réglementée non chiffrée
# custom:
#   control_id: DATA-002
#   severity: high
#   remediation: enable_encryption
#   frameworks: {}
deny contains f if {
	some n in input.graph.nodes
	lib.sensitive_data(n)
	not n.attrs.encrypted == true
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": n.id}
}

# METADATA
# title: Donnée interne non chiffrée
# custom:
#   control_id: DATA-003
#   severity: medium
#   remediation: advisory
#   frameworks: {}
deny contains f if {
	some n in input.graph.nodes
	n.kind == "DataStore"
	n.attrs.classification == "internal"
	not lib.sensitive_data(n) # regulated: DATA-002 (high) applies
	not n.attrs.encrypted == true
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": n.id}
}

# METADATA
# title: Hôte classé en dessous de la donnée qu'il stocke
# custom:
#   control_id: DATA-004
#   severity: high
#   remediation: escalate
#   frameworks: {}
deny contains f if {
	some e in input.graph.edges
	e.type == "STORES"
	h := lib.nodes[e.src]
	h.kind == "DataStore"
	object.get(rank, object.get(h.attrs, "classification", ""), 0) < object.get(rank, object.get(lib.nodes[e.dst].attrs, "classification", ""), 4)
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": h.id}
}

# METADATA
# title: Donnée réglementée classée publique ou interne
# custom:
#   control_id: DATA-005
#   severity: high
#   remediation: escalate
#   frameworks: {}
deny contains f if {
	some n in input.graph.nodes
	n.kind == "DataStore"
	count(object.get(n.attrs, "regulation", [])) > 0
	object.get(n.attrs, "classification", "") in {"public", "internal"}
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": n.id}
}
