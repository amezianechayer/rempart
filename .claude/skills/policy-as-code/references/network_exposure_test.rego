package rempart.design.network_test

import data.rempart.design.network

base_nodes := [
	{"id": "lb1", "kind": "LoadBalancer"},
	{"id": "app1", "kind": "Compute"},
	{"id": "db1", "kind": "DataStore", "classification": "regulated"},
]

test_db_non_exposee_conforme if {
	count(network.deny) == 0 with input as {
		"nodes": base_nodes,
		"reachability": [
			{"from": "internet", "to": "lb1", "port": 443, "path": ["internet", "lb1"]},
			{"from": "app1", "to": "db1", "port": 5432, "path": ["app1", "db1"]},
		],
		"exposure_justifications": {"lb1": "application publique"},
	}
}

test_db_exposee_detectee if {
	findings := network.deny with input as {
		"nodes": base_nodes,
		"reachability": [{"from": "internet", "to": "db1", "port": 5432, "path": ["internet", "db1"]}],
		"exposure_justifications": {},
	}
	some f in findings
	f.control_id == "NET-001"
	f.severity == "critical"
	f.resource == "db1"
	f.evidence.path == ["internet", "db1"]
}

test_donnee_publique_exposee_non_signalee_par_net001 if {
	findings := network.deny with input as {
		"nodes": [{"id": "s3pub", "kind": "DataStore", "classification": "public"}],
		"reachability": [{"from": "internet", "to": "s3pub", "port": 443, "path": ["internet", "s3pub"]}],
		"exposure_justifications": {},
	}
	not any_control(findings, "NET-001")
}

test_exposition_non_justifiee_detectee if {
	findings := network.deny with input as {
		"nodes": base_nodes,
		"reachability": [{"from": "internet", "to": "lb1", "port": 443, "path": ["internet", "lb1"]}],
		"exposure_justifications": {},
	}
	any_control(findings, "NET-002")
}

test_entree_vide_conforme if {
	count(network.deny) == 0 with input as {"nodes": [], "reachability": [], "exposure_justifications": {}}
}

any_control(findings, id) if {
	some f in findings
	f.control_id == id
}
