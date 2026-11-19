package rempart.design_test.resilience

import data.rempart.design_test.lib

pg(count) := lib.with_nodes(lib.base, [lib.node("wl:pg", "DataStore", {"subtype": "managed_db", "classification": "internal", "encrypted": true, "public_access": false, "cloud": "aws", "region": "eu-west-3", "count": count})])

k8s(count) := lib.with_nodes(lib.base, [lib.node("wl:k8s", "K8sCluster", {"cloud": "aws", "region": "eu-west-3", "count": count})])

# OBS-001: production without metrics or logs.
test_obs_001_ok if lib.ok("OBS-001", lib.base)

test_obs_001_ko if lib.ko("OBS-001", lib.with_derived(lib.base, {"observability": {"metrics": false, "logs": false}}))

test_obs_001_ko_no_logs if lib.ko("OBS-001", lib.with_derived(lib.base, {"observability": {"metrics": true, "logs": false}}))

test_obs_001_ok_dev if lib.ok("OBS-001", lib.with_derived(lib.base, {"environment": "dev", "observability": {"metrics": false, "logs": false}}))

# AVL-001: production database on one node.
test_avl_001_ok if lib.ok("AVL-001", pg(2))

test_avl_001_ko if lib.ko("AVL-001", pg(1))

test_avl_001_ok_staging if lib.ok("AVL-001", lib.with_derived(pg(1), {"environment": "staging"}))

# AVL-002: production cluster below 3 nodes.
test_avl_002_ok if lib.ok("AVL-002", k8s(3))

test_avl_002_ko if lib.ko("AVL-002", k8s(2))
