package rempart.design_test.data

import data.rempart.design_test.lib

store(id, attrs) := lib.node(id, "DataStore", object.union({"subtype": "dataset", "classification": "confidential", "encrypted": true, "public_access": false}, attrs))

# DATA-001: public access on data that is not public.
test_data_001_ok if lib.ok("DATA-001", lib.base)

test_data_001_ko if lib.ko("DATA-001", lib.set_node(lib.base, "data:customers", {"public_access": true}))

test_data_001_ko_absent if lib.ko("DATA-001", lib.with_nodes(lib.base, [lib.node("data:hr", "DataStore", {"subtype": "dataset", "classification": "internal", "encrypted": true})]))

# The base store is gdpr-regulated: public access stays a finding (T139),
# see test_data_001_ko_public_regulated and test_data_001_ok_public_unregulated.
test_data_001_ko_public_base_regulated if lib.ko("DATA-001", lib.set_node(lib.base, "data:customers", {"classification": "public", "public_access": true}))

# DATA-002: confidential or regulated data not encrypted.
test_data_002_ok if lib.ok("DATA-002", lib.base)

test_data_002_ko if lib.ko("DATA-002", lib.set_node(lib.base, "data:customers", {"encrypted": false}))

test_data_002_ko_regulated_absent if lib.ko("DATA-002", lib.with_nodes(lib.base, [lib.node("data:pay", "DataStore", {"subtype": "dataset", "classification": "regulated", "public_access": false})]))

test_data_002_ok_internal if lib.ok("DATA-002", lib.with_nodes(lib.base, [store("data:logs", {"classification": "internal", "encrypted": false})]))

# DATA-003: internal data not encrypted.
test_data_003_ok if lib.ok("DATA-003", lib.base)

test_data_003_ko if lib.ko("DATA-003", lib.with_nodes(lib.base, [store("data:logs", {"classification": "internal", "encrypted": false})]))

test_data_003_ok_confidential if lib.ok("DATA-003", lib.set_node(lib.base, "data:customers", {"encrypted": false}))

# DATA-004: host classified below the data it stores.
test_data_004_ok if lib.ok("DATA-004", lib.base)

test_data_004_ko if {
	bucket := store("wl:bucket", {"subtype": "object_storage", "classification": "internal", "cloud": "aws", "region": "eu-west-3"})
	lib.ko("DATA-004", lib.with_edges(lib.with_nodes(lib.base, [bucket]), [lib.edge("STORES", "wl:bucket", "data:customers", {})]))
}

test_data_004_ok_same_class if {
	bucket := store("wl:bucket", {"subtype": "object_storage", "classification": "confidential", "cloud": "aws", "region": "eu-west-3"})
	lib.ok("DATA-004", lib.with_edges(lib.with_nodes(lib.base, [bucket]), [lib.edge("STORES", "wl:bucket", "data:customers", {})]))
}

# Closing review of M2 (high, T139): regulated data classified internal is
# sensitive: DATA-002 (high) applies, DATA-003 (advisory) does not repeat it.
test_data_002_ko_regulated_internal if lib.ko("DATA-002", lib.with_nodes(lib.base, [store("data:health", {"classification": "internal", "regulation": ["health"], "encrypted": false})]))

test_data_003_ok_regulated_internal if lib.ok("DATA-003", lib.with_nodes(lib.base, [store("data:health", {"classification": "internal", "regulation": ["health"], "encrypted": false})]))

# DATA-005 (closing review of M2, T139): a regulation contradicts a public or
# internal classification; the human decides, never the classification chosen
# by the model.
test_data_005_ok if lib.ok("DATA-005", lib.base)

test_data_005_ko_internal if lib.ko("DATA-005", lib.set_node(lib.base, "data:customers", {"classification": "internal", "regulation": ["health"]}))

test_data_005_ko_public if lib.ko("DATA-005", lib.set_node(lib.base, "data:customers", {"classification": "public", "regulation": ["gdpr"]}))

test_data_005_ok_internal_unregulated if lib.ok("DATA-005", lib.set_node(lib.base, "data:customers", {"classification": "internal", "regulation": []}))

# Obligation (gr): public access on data classified public but regulated.
test_data_001_ko_public_regulated if lib.ko("DATA-001", lib.set_node(lib.base, "data:customers", {"classification": "public", "regulation": ["gdpr"], "public_access": true}))

test_data_001_ok_public_unregulated if lib.ok("DATA-001", lib.set_node(lib.base, "data:customers", {"classification": "public", "regulation": [], "public_access": true}))
