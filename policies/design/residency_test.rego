package rempart.design_test.residency

import data.rempart.design_test.lib

zones(z) := lib.with_derived(lib.base, {"jurisdiction": {"wl:db": z, "wl:web": z, "lb:web-443": z}})

# RES-001: data with an EU residency or regulated on a host outside the EU.
test_res_001_ok if lib.ok("RES-001", lib.base)

test_res_001_ko if lib.ko("RES-001", zones("non_eu"))

test_res_001_ko_regulated_any_residency if {
	inp := lib.set_node(zones("non_eu"), "data:customers", {"residency": "any"})
	lib.ko("RES-001", inp)
}

test_res_001_ok_public_any if {
	inp := lib.set_node(zones("non_eu"), "data:customers", {"residency": "any", "regulation": [], "classification": "public"})
	lib.ok("RES-001", inp)
}

# RES-002: data with a French residency outside France.
test_res_002_ok if lib.ok("RES-002", lib.set_node(lib.base, "data:customers", {"residency": "fr"}))

test_res_002_ko_eu if lib.ko("RES-002", lib.set_node(zones("eu"), "data:customers", {"residency": "fr"}))

test_res_002_ko_non_eu if lib.ko("RES-002", lib.set_node(zones("non_eu"), "data:customers", {"residency": "fr"}))

# RES-003: region outside constraints.allowed_regions.
test_res_003_ok_no_constraint if lib.ok("RES-003", lib.base)

test_res_003_ok if lib.ok("RES-003", lib.with_derived(lib.base, {"constraints": {"allowed_regions": ["eu-west-3"]}}))

test_res_003_ko if lib.ko("RES-003", lib.with_derived(lib.base, {"constraints": {"allowed_regions": ["francecentral"]}}))

# RES-004: cloud forbidden by the constraints.
test_res_004_ok if lib.ok("RES-004", lib.with_derived(lib.base, {"constraints": {"forbidden_clouds": ["azure"]}}))

test_res_004_ko if lib.ko("RES-004", lib.with_derived(lib.base, {"constraints": {"forbidden_clouds": ["aws"]}}))

# RES-005: unknown jurisdiction for a host of sensitive data.
test_res_005_ok if lib.ok("RES-005", lib.base)

test_res_005_ko if lib.ko("RES-005", zones("unknown"))

test_res_005_ko_absent if {
	d := {k: v | some k, v in lib.base.derived; k != "jurisdiction"}
	inp := {"graph": lib.base.graph, "reach": lib.base.reach, "derived": object.union(d, {"jurisdiction": {"wl:web": "fr"}})}
	lib.ko("RES-005", inp)
}

# RES-006: flow from a workload outside the EU to regulated EU data.
test_res_006_ok if lib.ok("RES-006", lib.base)

test_res_006_ko if lib.ko("RES-006", lib.with_derived(lib.base, {"jurisdiction": {"wl:web": "non_eu"}}))

# Review of M2-T03 (high): fr is inside eu (ADR 0011 D7), and regulated data is
# tied to the EU whatever its residency (as RES-001).
non_eu_web := lib.with_derived(lib.base, {"jurisdiction": {"wl:web": "non_eu"}})

test_res_006_ko_fr_regulated if lib.ko("RES-006", lib.set_node(non_eu_web, "data:customers", {"residency": "fr"}))

test_res_006_ko_fr_unregulated if lib.ko("RES-006", lib.set_node(non_eu_web, "data:customers", {"residency": "fr", "regulation": [], "classification": "confidential"}))

test_res_006_ko_regulated_any_residency if lib.ko("RES-006", lib.set_node(non_eu_web, "data:customers", {"residency": "any"}))

test_res_006_ok_no_eu_tie if {
	inp := lib.set_node(non_eu_web, "data:customers", {"residency": "any", "regulation": [], "classification": "confidential"})
	lib.ok("RES-006", inp)
}

# RES-007: unknown jurisdiction without sensitive data.
test_res_007_ok if lib.ok("RES-007", lib.base)

test_res_007_ko if lib.ko("RES-007", lib.with_derived(lib.base, {"jurisdiction": {"wl:web": "unknown"}}))

test_res_007_ok_sensitive_host if lib.ok("RES-007", lib.with_derived(lib.base, {"jurisdiction": {"wl:db": "unknown"}}))

# Security recheck of M2-T03 (high): the host of EU-bound data opening a flow
# towards a workload outside the EU transfers it as well; a zone unknown at
# either end is read outside the EU (fail closed).
us_vm := lib.node("wl:us", "Compute", {"subtype": "vm", "cloud": "aws", "region": "us-east-1", "count": 1, "public_ip": false})

us := lib.with_derived(lib.with_nodes(lib.base, [us_vm]), {"jurisdiction": {"wl:us": "non_eu"}})

test_res_006_ko_reverse if lib.ko("RES-006", lib.with_edges(us, [lib.edge("CAN_REACH", "wl:db", "wl:us", {"protocol": "tcp", "port_from": 443, "port_to": 443, "via": "vpn_site_to_site", "path": ["net:vpc-data"]})]))

test_res_006_ko_unknown_source if lib.ko("RES-006", lib.with_derived(lib.base, {"jurisdiction": {"wl:web": "unknown"}}))

test_res_006_ok_eu_to_eu if lib.ok("RES-006", lib.with_edges(lib.base, [lib.edge("CAN_REACH", "wl:db", "wl:web", {"protocol": "tcp", "port_from": 443, "port_to": 443, "via": "internal", "path": ["net:vpc-data"]})]))

# Obligation (fh) (T115, T119): an absent region or cloud on a placed
# component is outside the constraints; a dataset is placed by its host.
test_res_003_ko_region_absent if {
	inp := lib.without_attr(lib.base, "wl:web", "region")
	lib.ko("RES-003", lib.with_derived(inp, {"constraints": {"allowed_regions": ["eu-west-3"]}}))
}

test_res_004_ko_cloud_absent if {
	inp := lib.without_attr(lib.base, "wl:web", "cloud")
	lib.ko("RES-004", lib.with_derived(inp, {"constraints": {"forbidden_clouds": ["azure"]}}))
}

# Obligation (fi) (T110): data with an EU or French residency, sensitive or
# not, on a host of unknown zone is RES-005 (blocking), not RES-007 alone.
internal_data(residency) := lib.set_node(lib.base, "data:customers", {"classification": "internal", "regulation": [], "residency": residency})

unknown_db(inp) := lib.with_derived(inp, {"jurisdiction": {"wl:db": "unknown"}})

test_res_005_ko_eu_residency_internal if lib.ko("RES-005", unknown_db(internal_data("eu")))

test_res_005_ko_fr_residency_internal if lib.ko("RES-005", unknown_db(internal_data("fr")))

test_res_007_ok_eu_residency_internal if lib.ok("RES-007", unknown_db(internal_data("eu")))

test_res_005_ok_any_residency_internal if lib.ok("RES-005", unknown_db(internal_data("any")))

test_res_007_ko_any_residency_internal if lib.ko("RES-007", unknown_db(internal_data("any")))

# Obligation (fm) (T114): French data is transferred by a flow, in either
# direction, with a component located outside France, even inside the EU.
fr_data := lib.set_node(lib.base, "data:customers", {"residency": "fr"})

eu_vm := lib.node("wl:de", "Compute", {"subtype": "vm", "cloud": "aws", "region": "eu-central-1", "count": 1, "public_ip": false})

test_res_006_ok_fr_in_fr if lib.ok("RES-006", fr_data)

test_res_006_ko_fr_data_eu_source if lib.ko("RES-006", lib.with_derived(fr_data, {"jurisdiction": {"wl:web": "eu"}}))

test_res_006_ko_fr_host_to_eu if {
	inp := lib.with_derived(lib.with_nodes(fr_data, [eu_vm]), {"jurisdiction": {"wl:de": "eu"}})
	lib.ko("RES-006", lib.with_edges(inp, [lib.edge("CAN_REACH", "wl:db", "wl:de", {"protocol": "tcp", "port_from": 443, "port_to": 443, "via": "internal", "path": ["net:vpc-data"]})]))
}

test_res_006_ok_eu_data_eu_source if lib.ok("RES-006", lib.with_derived(lib.base, {"jurisdiction": {"wl:web": "eu"}}))
