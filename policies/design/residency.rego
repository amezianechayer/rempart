package rempart.design.residency

import data.rempart.design.lib

# eu_bound: data whose residency is the EU, or regulated data.
eu_bound(d) if d.attrs.residency == "eu"

eu_bound(d) if lib.regulated(d)

# eu_regulated: regulated data whose residency is the EU.
eu_regulated(d) if {
	d.attrs.residency == "eu"
	lib.regulated(d)
}

# eu_regulated_target: such data, or its host.
eu_regulated_target(t) if eu_regulated(lib.nodes[t])

eu_regulated_target(t) if {
	some s in input.graph.edges
	s.type == "STORES"
	s.src == t
	eu_regulated(lib.nodes[s.dst])
}

# METADATA
# title: Donnée à résidence UE ou réglementée sur un hôte localisé hors UE
# custom:
#   control_id: RES-001
#   severity: critical
#   remediation: escalate
#   frameworks: {}
deny contains f if {
	some e in input.graph.edges
	e.type == "STORES"
	eu_bound(lib.nodes[e.dst])
	lib.zone(e.src) == "non_eu"
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": e.src}
}

# METADATA
# title: Donnée à résidence France sur un hôte localisé hors de France
# custom:
#   control_id: RES-002
#   severity: critical
#   remediation: escalate
#   frameworks: {}
deny contains f if {
	some e in input.graph.edges
	e.type == "STORES"
	lib.nodes[e.dst].attrs.residency == "fr"
	lib.zone(e.src) in {"eu", "non_eu"}
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": e.src}
}

# METADATA
# title: Région hors des régions admises par les contraintes
# custom:
#   control_id: RES-003
#   severity: high
#   remediation: escalate
#   frameworks: {}
deny contains f if {
	allowed := input.derived.constraints.allowed_regions
	count(allowed) > 0
	some n in input.graph.nodes
	n.kind != "Network"
	region := n.attrs.region
	not region in allowed
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": n.id}
}

# METADATA
# title: Cloud interdit par les contraintes
# custom:
#   control_id: RES-004
#   severity: high
#   remediation: escalate
#   frameworks: {}
deny contains f if {
	some n in input.graph.nodes
	not n.kind in {"Network", "Identity"}
	n.attrs.cloud in input.derived.constraints.forbidden_clouds
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": n.id}
}

# METADATA
# title: Localisation inconnue pour l'hôte d'une donnée sensible
# custom:
#   control_id: RES-005
#   severity: high
#   remediation: escalate
#   frameworks: {}
deny contains f if {
	some id in lib.sensitive_placed
	lib.zone(id) == "unknown"
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": id}
}

# METADATA
# title: Flux d'un workload localisé hors UE vers une donnée réglementée à résidence UE
# custom:
#   control_id: RES-006
#   severity: high
#   remediation: escalate
#   frameworks: {}
deny contains f if {
	some e in input.graph.edges
	e.type == "CAN_REACH"
	lib.zone(e.src) == "non_eu"
	eu_regulated_target(e.dst)
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": e.id}
}

# METADATA
# title: Localisation inconnue d'un composant sans donnée sensible
# custom:
#   control_id: RES-007
#   severity: medium
#   remediation: advisory
#   frameworks: {}
deny contains f if {
	some n in input.graph.nodes
	not n.kind in {"Network", "Identity", "Account", "Internet"}
	n.attrs.cloud
	lib.zone(n.id) == "unknown"
	not n.id in lib.sensitive_placed
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": n.id}
}
