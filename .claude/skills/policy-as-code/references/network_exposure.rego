package rempart.design.network

# Entrée attendue (graphe d'architecture enrichi par Go) :
# {
#   "nodes": [{"id": "db1", "kind": "DataStore", "classification": "regulated"}, ...],
#   "reachability": [{"from": "internet", "to": "db1", "port": 5432, "path": ["internet", "lb1", "db1"]}, ...],
#   "exposure_justifications": {"web1": "application publique"}
# }

sensitive := {"confidential", "regulated"}

# METADATA
# title: Données sensibles non atteignables depuis Internet
# description: Aucun magasin de données confidentiel ou réglementé ne doit être atteignable depuis Internet.
# custom:
#   control_id: NET-001
#   severity: critical
#   frameworks:
#     iso27001: ["A.8.20"]
#   remediation_hint: placer la ressource dans le tier data sans route Internet et passer par la couche applicative
deny contains finding if {
	some node in input.nodes
	node.kind == "DataStore"
	node.classification in sensitive
	some r in input.reachability
	r.from == "internet"
	r.to == node.id
	meta := rego.metadata.rule()
	finding := {
		"control_id": meta.custom.control_id,
		"severity": meta.custom.severity,
		"resource": node.id,
		"message": sprintf("%s (%s) est atteignable depuis Internet sur le port %d", [node.id, node.classification, r.port]),
		"evidence": {"path": r.path},
		"remediation_hint": meta.custom.remediation_hint,
	}
}

# METADATA
# title: Toute exposition Internet est justifiée
# custom:
#   control_id: NET-002
#   severity: high
#   frameworks: {}
#   remediation_hint: ajouter une justification dans l'intention ou retirer l'exposition
deny contains finding if {
	some r in input.reachability
	r.from == "internet"
	some node in input.nodes
	node.id == r.to
	node.kind != "DataStore"
	not input.exposure_justifications[node.id]
	meta := rego.metadata.rule()
	finding := {
		"control_id": meta.custom.control_id,
		"severity": meta.custom.severity,
		"resource": node.id,
		"message": sprintf("%s est exposé à Internet sans justification", [node.id]),
		"evidence": {"path": r.path},
		"remediation_hint": meta.custom.remediation_hint,
	}
}
