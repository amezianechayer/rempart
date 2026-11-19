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
