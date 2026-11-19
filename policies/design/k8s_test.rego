package rempart.design_test.k8s

import data.rempart.design_test.lib

safe := {
	"cloud": "aws", "region": "eu-west-3", "count": 3, "api_public": false,
	"audit_log": true, "secrets_encryption": true, "network_policy_default_deny": true,
	"admission_policy": true, "workload_identity": true,
}

cluster(attrs) := lib.with_edges(
	lib.with_nodes(lib.base, [lib.node("wl:k8s", "K8sCluster", object.union(safe, attrs))]),
	[lib.member("wl:k8s", "net:vpc-app")],
)

ok_cluster := cluster({})

# K8S-001: public API without source.
test_k8s_001_ok if lib.ok("K8S-001", ok_cluster)

test_k8s_001_ko if lib.ko("K8S-001", cluster({"api_public": true}))

test_k8s_001_ok_restricted if lib.ok("K8S-001", cluster({"api_public": true, "api_allowed_sources": ["203.0.113.0/24"]}))

# K8S-002: audit log off.
test_k8s_002_ok if lib.ok("K8S-002", ok_cluster)

test_k8s_002_ko if lib.ko("K8S-002", cluster({"audit_log": false}))

# K8S-003: secrets not encrypted.
test_k8s_003_ok if lib.ok("K8S-003", ok_cluster)

test_k8s_003_ko if lib.ko("K8S-003", cluster({"secrets_encryption": false}))

# K8S-004: public API restricted to sources.
test_k8s_004_ok if lib.ok("K8S-004", ok_cluster)

test_k8s_004_ko if lib.ko("K8S-004", cluster({"api_public": true, "api_allowed_sources": ["203.0.113.0/24"]}))

# K8S-010: no admission policy.
test_k8s_010_ok if lib.ok("K8S-010", ok_cluster)

test_k8s_010_ko if lib.ko("K8S-010", cluster({"admission_policy": false}))

test_k8s_010_ko_absent if lib.ko("K8S-010", lib.with_nodes(lib.base, [lib.node("wl:k8s2", "K8sCluster", {"cloud": "aws", "region": "eu-west-3", "count": 3})]))

# K8S-020: no default deny NetworkPolicy.
test_k8s_020_ok if lib.ok("K8S-020", ok_cluster)

test_k8s_020_ko if lib.ko("K8S-020", cluster({"network_policy_default_deny": false}))

# K8S-030: service account with admin or "*".
sa := lib.node("id:ci", "Identity", {"subtype": "k8s_service_account", "cloud": "aws", "credential": "workload_identity"})

test_k8s_030_ok if {
	inp := lib.with_edges(lib.with_nodes(ok_cluster, [sa]), [lib.edge("HAS_PERMISSION", "id:ci", "wl:k8s", {"actions": ["read"]})])
	lib.ok("K8S-030", inp)
}

test_k8s_030_ko if {
	inp := lib.with_edges(lib.with_nodes(ok_cluster, [sa]), [lib.edge("HAS_PERMISSION", "id:ci", "wl:k8s", {"actions": ["admin"]})])
	lib.ko("K8S-030", inp)
}

# K8S-040: workload identities off.
test_k8s_040_ok if lib.ok("K8S-040", ok_cluster)

test_k8s_040_ko if lib.ko("K8S-040", cluster({"workload_identity": false}))

# K8S-050: GitOps controller exposed to the Internet.
gitops := lib.with_edges(
	lib.with_nodes(ok_cluster, [lib.node("wl:argo", "K8sWorkload", {"cloud": "aws", "region": "eu-west-3"})]),
	[lib.member("wl:argo", "wl:k8s")],
)

test_k8s_050_ok if lib.ok("K8S-050", lib.with_derived(gitops, {"workload_roles": {"wl:argo": "gitops_controller"}}))

test_k8s_050_ko if {
	inp := lib.with_derived(gitops, {"workload_roles": {"wl:argo": "gitops_controller"}})
	lib.ko("K8S-050", lib.with_hops(inp, [lib.hop_world("wl:argo", "tcp", 443, 443)]))
}

test_k8s_050_ok_other_role if {
	inp := lib.with_derived(gitops, {"workload_roles": {"wl:argo": "observability_stack"}})
	lib.ok("K8S-050", lib.with_hops(inp, [lib.hop_world("wl:argo", "tcp", 443, 443)]))
}
