package rempart.design_test.iam

import data.rempart.design_test.lib

perm := "has_permission|id:db|data:customers"

acct := lib.node("acct:main", "Account", {"cloud": "aws"})

# IAM-001: action "*".
test_iam_001_ok if lib.ok("IAM-001", lib.base)

test_iam_001_ko if lib.ko("IAM-001", lib.set_edge(lib.base, perm, {"actions": ["*"]}))

test_iam_001_ko_absent if lib.ko("IAM-001", lib.with_edges(lib.base, [lib.edge("HAS_PERMISSION", "id:web", "data:customers", {})]))

# IAM-002: write or admin on a whole account.
test_iam_002_ok_read if lib.ok("IAM-002", lib.with_edges(lib.with_nodes(lib.base, [acct]), [lib.edge("HAS_PERMISSION", "id:db", "acct:main", {"actions": ["read"]})]))

test_iam_002_ko if lib.ko("IAM-002", lib.with_edges(lib.with_nodes(lib.base, [acct]), [lib.edge("HAS_PERMISSION", "id:db", "acct:main", {"actions": ["write"]})]))

# IAM-003: identity shared between tiers.
test_iam_003_ok if lib.ok("IAM-003", lib.base)

test_iam_003_ko if lib.ko("IAM-003", lib.with_edges(lib.base, [lib.edge("RUNS_AS", "wl:web", "id:db", {})]))

# IAM-004: exposed workload with admin rights.
test_iam_004_ok if lib.ok("IAM-004", lib.base)

test_iam_004_ko if lib.ko("IAM-004", lib.with_edges(lib.base, [lib.edge("HAS_PERMISSION", "id:web", "data:customers", {"actions": ["admin"]})]))

test_iam_004_ok_not_exposed if lib.ok("IAM-004", lib.set_edge(lib.base, perm, {"actions": ["admin"]}))

# IAM-005: static key.
test_iam_005_ok if lib.ok("IAM-005", lib.base)

test_iam_005_ko if lib.ko("IAM-005", lib.set_node(lib.base, "id:web", {"credential": "static_key"}))

# IAM-006: workload without a dedicated identity.
test_iam_006_ok if lib.ok("IAM-006", lib.base)

test_iam_006_ko_none if lib.ko("IAM-006", lib.without_edge(lib.base, "runs_as|wl:web|id:web"))

test_iam_006_ko_shared if {
	inp := lib.with_edges(lib.without_edge(lib.base, "runs_as|wl:web|id:web"), [lib.edge("RUNS_AS", "wl:web", "id:db", {})])
	lib.ko("IAM-006", inp)
}

# IAM-007: permission on a data store neither hosted nor reached.
test_iam_007_ok if lib.ok("IAM-007", lib.base)

test_iam_007_ko if lib.ko("IAM-007", lib.with_edges(lib.base, [lib.edge("HAS_PERMISSION", "id:web", "data:customers", {"actions": ["read"]})]))
