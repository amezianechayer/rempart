package rempart.design.network

import data.rempart.design.lib

admin_ports := {22, 3389, 5985, 5986}

db_ports := {1433, 1521, 3306, 5432, 6379, 9042, 9200, 11211, 27017}

# METADATA
# title: Donnée sensible ou son hôte atteignable directement depuis Internet
# custom:
#   control_id: NET-001
#   severity: critical
#   remediation: make_private
#   frameworks: {}
deny contains f if {
	some h in lib.internet_hops
	lib.sensitive(h.dst)
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": h.dst}
}

# METADATA
# title: Exposition non confirmée par un humain
# custom:
#   control_id: NET-002
#   severity: high
#   remediation: escalate
#   frameworks: {}
deny contains f if {
	some id in input.derived.unconfirmed_exposures
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": id}
}

# METADATA
# title: Port d'administration atteignable depuis Internet
# custom:
#   control_id: NET-003
#   severity: critical
#   remediation: remove_exposure
#   frameworks: {}
deny contains f if {
	some h in lib.internet_hops
	some p in admin_ports
	lib.hop_port(h, p)
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": h.dst}
}

# METADATA
# title: Port de base de données ou de cache atteignable depuis Internet
# custom:
#   control_id: NET-004
#   severity: critical
#   remediation: remove_exposure
#   frameworks: {}
deny contains f if {
	some h in lib.internet_hops
	some p in db_ports
	lib.hop_port(h, p)
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": h.dst}
}

# METADATA
# title: Exposition sans source alors qu'une dérogation cite une adresse
# custom:
#   control_id: NET-005
#   severity: high
#   remediation: escalate
#   frameworks: {}
deny contains f if {
	some id in input.derived.sources_unresolved
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": id}
}

# METADATA
# title: Flux tcp ou udp brut ouvert à tout Internet
# custom:
#   control_id: NET-006
#   severity: high
#   remediation: escalate
#   frameworks: {}
deny contains f if {
	some e in lib.internet_flows
	not e.attrs.protocol in {"http", "https"}
	count(object.get(e.attrs, "allowed_sources", [])) == 0
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": e.id}
}

# METADATA
# title: Exposition en http clair
# custom:
#   control_id: NET-007
#   severity: high
#   remediation: https_only
#   frameworks: {}
deny contains f if {
	some e in lib.internet_flows
	e.attrs.protocol == "http"
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": e.id}
}

# METADATA
# title: Équilibreur de charge relié directement à une base sans tier applicatif
# custom:
#   control_id: NET-008
#   severity: high
#   remediation: escalate
#   frameworks: {}
deny contains f if {
	some e in input.graph.edges
	e.type == "CAN_REACH"
	lib.nodes[e.src].kind == "LoadBalancer"
	lib.nodes[e.dst].kind == "DataStore"
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": e.id}
}

# METADATA
# title: Flux de plus de 100 ports
# custom:
#   control_id: NET-009
#   severity: high
#   remediation: escalate
#   frameworks: {}
deny contains f if {
	some e in input.graph.edges
	e.type in {"CAN_REACH", "EXPOSES"}
	not lib.bounded_flow(e)
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": e.id}
}

# METADATA
# title: Adresse IP publique hors du tier public
# custom:
#   control_id: NET-010
#   severity: high
#   remediation: make_private
#   frameworks: {}
deny contains f if {
	some n in input.graph.nodes
	n.kind == "Compute"
	not n.attrs.public_ip == false
	lib.tiers(n.id) != {"public"}
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": n.id}
}

# METADATA
# title: Flux entre clouds hors VPN site à site ou lien privé
# custom:
#   control_id: NET-011
#   severity: high
#   remediation: encrypt_transit
#   frameworks: {}
deny contains f if {
	some e in input.graph.edges
	e.type == "CAN_REACH"
	lib.nodes[e.src].attrs.cloud != lib.nodes[e.dst].attrs.cloud
	not e.attrs.via in {"vpn_site_to_site", "private_link"}
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": e.id}
}

# METADATA
# title: Hôte de donnée sensible hors du tier data
# custom:
#   control_id: NET-012
#   severity: high
#   remediation: move_to_data_tier
#   frameworks: {}
deny contains f if {
	some h in lib.sensitive_hosts
	not lib.nodes[h].attrs.subtype == "object_storage"
	lib.tiers(h) != {"data"}
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": h}
}

# METADATA
# title: Exposition sans WAF sur un chemin vers une donnée sensible
# custom:
#   control_id: NET-013
#   severity: medium
#   remediation: advisory
#   frameworks: {}
deny contains f if {
	some e in input.graph.edges
	e.type == "EXPOSES"
	not "waf" in object.get(lib.nodes[e.src].attrs, "behind", [])
	some p in input.reach.from_internet
	count(p.nodes) > 1
	p.nodes[1] == e.src
	lib.sensitive(p.target)
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": e.id}
}

# METADATA
# title: Tier d'administration atteignable depuis Internet
# custom:
#   control_id: NET-014
#   severity: high
#   remediation: remove_exposure
#   frameworks: {}
deny contains f if {
	some h in lib.internet_hops
	"mgmt" in lib.tiers(h.dst)
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": h.dst}
}

# METADATA
# title: Exposition d'un hôte de donnée sensible
# custom:
#   control_id: NET-015
#   severity: high
#   remediation: escalate
#   frameworks: {}
deny contains f if {
	some e in input.graph.edges
	e.type == "EXPOSES"
	some t in lib.exposure_targets(e)
	lib.sensitive(t)
	meta := rego.metadata.rule()
	f := {"control_id": meta.custom.control_id, "resource": e.id}
}
