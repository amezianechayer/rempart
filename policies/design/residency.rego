package rempart.design.residency

import data.rempart.design.lib

# eu_bound: data whose residency is the EU or France (fr is inside eu, ADR
# 0011 D7), or regulated data whatever its residency.
eu_bound(d) if d.attrs.residency in {"eu", "fr"}

eu_bound(d) if lib.regulated(d)

# eu_bound_target: such data, or its host.
eu_bound_target(t) if eu_bound(lib.nodes[t])

eu_bound_target(t) if {
	some s in input.graph.edges
	s.type == "STORES"
	s.src == t
	eu_bound(lib.nodes[s.dst])
}

# outside_eu: located outside the EU, or of unknown zone (fail closed).
outside_eu(id) if lib.zone(id) in {"non_eu", "unknown"}

# transfer: a flow between EU-bound data (or its host) and a component outside
# the EU, in either direction: the host opening a flow outward transfers too.
transfer(e) if {
	outside_eu(e.src)
	eu_bound_target(e.dst)
}

transfer(e) if {
	outside_eu(e.dst)
	eu_bound_target(e.src)
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
# title: Flux entre une donnée liée à l'UE et un composant localisé hors UE ou inconnu
# custom:
#   control_id: RES-006
#   severity: high
#   remediation: escalate
#   frameworks: {}
deny contains f if {
	some e in input.graph.edges
	e.type == "CAN_REACH"
	transfer(e)
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
