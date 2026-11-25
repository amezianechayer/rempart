package rempart.design_test.network

import data.rempart.design_test.lib

exposes := "exposes|lb:web-443|internet|https/443"

flow := "can_reach|wl:web|wl:db|tcp/5432"

vm(id, attrs) := lib.node(id, "Compute", object.union({"subtype": "vm", "cloud": "aws", "region": "eu-west-3", "count": 1, "public_ip": false}, attrs))

# NET-001: sensitive data directly reachable from the Internet.
test_net_001_ok if lib.ok("NET-001", lib.base)

test_net_001_ko_dataset if lib.ko("NET-001", lib.with_hops(lib.base, [lib.hop_world("data:customers", "tcp", 443, 443)]))

test_net_001_ko_host if lib.ko("NET-001", lib.with_hops(lib.base, [lib.hop_world("wl:db", "tcp", 5432, 5432)]))

test_net_001_ok_public_data if {
	inp := lib.set_node(lib.base, "data:customers", {"classification": "public", "regulation": []})
	lib.ok("NET-001", lib.with_hops(inp, [lib.hop_world("wl:db", "tcp", 5432, 5432)]))
}

# NET-002: exposure not confirmed by a human.
test_net_002_ok if lib.ok("NET-002", lib.base)

test_net_002_ko if lib.ko("NET-002", lib.with_derived(lib.base, {"unconfirmed_exposures": [exposes]}))

# NET-003: administration port reachable from the Internet.
test_net_003_ok if lib.ok("NET-003", lib.base)

test_net_003_ok_near_port if lib.ok("NET-003", lib.with_hops(lib.base, [lib.hop_world("wl:web", "tcp", 2222, 2222)]))

test_net_003_ko_ssh if lib.ko("NET-003", lib.with_hops(lib.base, [lib.hop_world("wl:web", "tcp", 22, 22)]))

test_net_003_ko_rdp_udp if lib.ko("NET-003", lib.with_hops(lib.base, [lib.hop_world("wl:web", "udp", 3389, 3389)]))

test_net_003_ko_all_ports if lib.ko("NET-003", lib.with_hops(lib.base, [lib.hop_world("wl:web", "tcp", 1, 65535)]))

test_net_003_ko_restricted_sources if {
	h := object.union(lib.hop_world("wl:web", "tcp", 5985, 5986), {"world": false, "sources": ["203.0.113.0/24"]})
	lib.ko("NET-003", lib.with_hops(lib.base, [h]))
}

# NET-004: database or cache port reachable from the Internet.
test_net_004_ok if lib.ok("NET-004", lib.base)

test_net_004_ok_near_port if lib.ok("NET-004", lib.with_hops(lib.base, [lib.hop_world("wl:web", "tcp", 5433, 5433)]))

test_net_004_ko_postgres if lib.ko("NET-004", lib.with_hops(lib.base, [lib.hop_world("wl:web", "tcp", 5432, 5432)]))

test_net_004_ko_range if lib.ko("NET-004", lib.with_hops(lib.base, [lib.hop_world("wl:web", "tcp", 27000, 28000)]))

# NET-005: exposure without source while an override quotes an address.
test_net_005_ok if lib.ok("NET-005", lib.base)

test_net_005_ko if lib.ko("NET-005", lib.with_derived(lib.base, {"sources_unresolved": [exposes]}))

# NET-006: raw tcp or udp open to the whole Internet.
test_net_006_ok if lib.ok("NET-006", lib.base)

test_net_006_ko_tcp if lib.ko("NET-006", lib.set_edge(lib.base, exposes, {"protocol": "tcp"}))

test_net_006_ko_udp_empty_sources if lib.ko("NET-006", lib.set_edge(lib.base, exposes, {"protocol": "udp", "allowed_sources": []}))

test_net_006_ok_restricted if lib.ok("NET-006", lib.set_edge(lib.base, exposes, {"protocol": "tcp", "allowed_sources": ["203.0.113.0/24"]}))

# NET-007: exposure in clear http.
test_net_007_ok if lib.ok("NET-007", lib.base)

test_net_007_ko if lib.ko("NET-007", lib.set_edge(lib.base, exposes, {"protocol": "http", "port_from": 80, "port_to": 80}))

# NET-008: load balancer straight to a data store.
test_net_008_ok if lib.ok("NET-008", lib.base)

test_net_008_ko if {
	db := lib.node("wl:pg", "DataStore", {"subtype": "managed_db", "classification": "internal", "encrypted": true, "public_access": false})
	e := lib.edge("CAN_REACH", "lb:web-443", "wl:pg", {"protocol": "tcp", "port_from": 5432, "port_to": 5432, "via": "load_balancer", "path": ["net:vpc-public", "net:vpc-data"]})
	lib.ko("NET-008", lib.with_edges(lib.with_nodes(lib.base, [db]), [e]))
}

# NET-009: flow of more than 100 ports.
test_net_009_ok if lib.ok("NET-009", lib.base)

test_net_009_ok_100 if lib.ok("NET-009", lib.set_edge(lib.base, flow, {"port_from": 1000, "port_to": 1099}))

test_net_009_ko_101 if lib.ko("NET-009", lib.set_edge(lib.base, flow, {"port_from": 1000, "port_to": 1100}))

test_net_009_ko_ports_absent if lib.ko("NET-009", lib.with_edges(lib.base, [lib.edge("CAN_REACH", "wl:db", "wl:web", {"protocol": "tcp", "via": "internal", "path": ["net:vpc-data"]})]))

# NET-010: public IP outside the public tier.
test_net_010_ok if lib.ok("NET-010", lib.base)

test_net_010_ko if lib.ko("NET-010", lib.set_node(lib.base, "wl:web", {"public_ip": true}))

test_net_010_ko_absent if {
	n := lib.node("wl:tool", "Compute", {"subtype": "vm", "cloud": "aws", "region": "eu-west-3", "count": 1})
	lib.ko("NET-010", lib.with_edges(lib.with_nodes(lib.base, [n]), [lib.member("wl:tool", "net:vpc-app")]))
}

test_net_010_ok_public_tier if {
	inp := lib.with_nodes(lib.base, [vm("wl:bastion", {"public_ip": true})])
	lib.ok("NET-010", lib.with_edges(inp, [lib.member("wl:bastion", "net:vpc-public")]))
}

# NET-011: flow between clouds outside a VPN or private link.
az := vm("wl:az", {"cloud": "azure", "region": "francecentral"})

test_net_011_ok if lib.ok("NET-011", lib.base)

test_net_011_ko_peering if {
	e := lib.edge("CAN_REACH", "wl:web", "wl:az", {"protocol": "tcp", "port_from": 443, "port_to": 443, "via": "peering", "path": ["net:vpc-app"]})
	lib.ko("NET-011", lib.with_edges(lib.with_nodes(lib.base, [az]), [e]))
}

test_net_011_ok_vpn if {
	e := lib.edge("CAN_REACH", "wl:web", "wl:az", {"protocol": "tcp", "port_from": 443, "port_to": 443, "via": "vpn_site_to_site", "path": ["net:vpc-app"]})
	lib.ok("NET-011", lib.with_edges(lib.with_nodes(lib.base, [az]), [e]))
}

# NET-012: host of sensitive data outside the data tier.
test_net_012_ok if lib.ok("NET-012", lib.base)

test_net_012_ko if {
	inp := lib.with_nodes(lib.base, [vm("wl:legacy", {})])
	lib.ko("NET-012", lib.with_edges(inp, [lib.member("wl:legacy", "net:vpc-app"), lib.edge("STORES", "wl:legacy", "data:customers", {})]))
}

test_net_012_ko_no_network if {
	inp := lib.with_nodes(lib.base, [vm("wl:legacy", {})])
	lib.ko("NET-012", lib.with_edges(inp, [lib.edge("STORES", "wl:legacy", "data:customers", {})]))
}

test_net_012_ok_object_storage if {
	bucket := lib.node("wl:bucket", "DataStore", {"subtype": "object_storage", "classification": "confidential", "encrypted": true, "public_access": false, "cloud": "aws", "region": "eu-west-3"})
	lib.ok("NET-012", lib.with_edges(lib.with_nodes(lib.base, [bucket]), [lib.edge("STORES", "wl:bucket", "data:customers", {})]))
}

test_net_012_ok_public_data if {
	inp := lib.set_node(lib.with_nodes(lib.base, [vm("wl:legacy", {})]), "data:customers", {"classification": "public", "regulation": []})
	lib.ok("NET-012", lib.with_edges(inp, [lib.member("wl:legacy", "net:vpc-app"), lib.edge("STORES", "wl:legacy", "data:customers", {})]))
}

# NET-013: exposure on a path to sensitive data without a WAF.
test_net_013_ok if lib.ok("NET-013", lib.base)

test_net_013_ko if lib.ko("NET-013", lib.set_node(lib.base, "lb:web-443", {"behind": ["load_balancer"]}))

test_net_013_ok_no_sensitive_path if {
	inp := lib.set_node(lib.base, "lb:web-443", {"behind": ["load_balancer"]})
	lib.ok("NET-013", lib.set_node(inp, "data:customers", {"classification": "public", "regulation": []}))
}

# NET-014: management tier reachable from the Internet.
test_net_014_ok if lib.ok("NET-014", lib.base)

test_net_014_ko if {
	inp := lib.with_edges(lib.with_nodes(lib.base, [vm("wl:bastion", {})]), [lib.member("wl:bastion", "net:vpc-mgmt")])
	lib.ko("NET-014", lib.with_hops(inp, [lib.hop_world("wl:bastion", "tcp", 443, 443)]))
}

test_net_014_ok_unreached if lib.ok("NET-014", lib.with_edges(lib.with_nodes(lib.base, [vm("wl:bastion", {})]), [lib.member("wl:bastion", "net:vpc-mgmt")]))

# NET-015: exposure of a host of sensitive data.
test_net_015_ok if lib.ok("NET-015", lib.base)

test_net_015_ko_behind_lb if {
	lb := lib.node("lb:db-5432", "LoadBalancer", {"cloud": "aws", "region": "eu-west-3", "public": true, "listeners": [{"protocol": "tcp", "port": 5432}]})
	es := [
		lib.edge("EXPOSES", "lb:db-5432", "internet", {"protocol": "tcp", "port_from": 5432, "port_to": 5432, "allowed_sources": ["203.0.113.0/24"]}),
		lib.edge("CAN_REACH", "lb:db-5432", "wl:db", {"protocol": "tcp", "port_from": 5432, "port_to": 5432, "via": "load_balancer", "path": ["net:vpc-public", "net:vpc-data"]}),
	]
	lib.ko("NET-015", lib.with_edges(lib.with_nodes(lib.base, [lb]), es))
}

test_net_015_ko_direct if lib.ko("NET-015", lib.with_edges(lib.base, [lib.edge("EXPOSES", "wl:db", "internet", {"protocol": "https", "port_from": 443, "port_to": 443})]))

# Obligation (fg) (T102): sources that cover the whole Internet, as computed
# in Go into derived.world_sources, are the world even when listed.
halves := ["0.0.0.0/1", "128.0.0.0/1"]

test_net_006_ko_world_cover if {
	inp := lib.set_edge(lib.base, exposes, {"protocol": "tcp", "allowed_sources": halves})
	lib.ko("NET-006", lib.with_derived(inp, {"world_sources": [exposes]}))
}

test_net_006_ok_restricted_not_world if {
	inp := lib.set_edge(lib.base, exposes, {"protocol": "tcp", "allowed_sources": ["203.0.113.0/24"]})
	lib.ok("NET-006", lib.with_derived(inp, {"world_sources": []}))
}

# Obligation (fh) (T119): an absent cloud is not the same cloud (NET-011), an
# absent attrs object is not behind a WAF (NET-013).
test_net_011_ko_cloud_absent if lib.ko("NET-011", lib.without_attr(lib.base, "wl:db", "cloud"))

test_net_011_ko_cloud_absent_source if lib.ko("NET-011", lib.without_attr(lib.base, "wl:web", "cloud"))

test_net_013_ko_attrs_absent if lib.ko("NET-013", lib.without_attrs(lib.base, "lb:web-443"))

# Closing review of M2 (high, T139): a regulation makes data sensitive,
# whatever its classification.
test_net_001_ko_regulated_internal if {
	inp := lib.set_node(lib.base, "data:customers", {"classification": "internal", "regulation": ["health"]})
	lib.ko("NET-001", lib.with_hops(inp, [lib.hop_world("wl:db", "tcp", 5432, 5432)]))
}

test_net_001_ok_internal_unregulated if {
	inp := lib.set_node(lib.base, "data:customers", {"classification": "internal", "regulation": []})
	lib.ok("NET-001", lib.with_hops(inp, [lib.hop_world("wl:db", "tcp", 5432, 5432)]))
}

test_net_012_ko_regulated_internal if {
	inp := lib.set_node(lib.with_nodes(lib.base, [vm("wl:legacy", {})]), "data:customers", {"classification": "internal", "regulation": ["health"]})
	lib.ko("NET-012", lib.with_edges(inp, [lib.member("wl:legacy", "net:vpc-app"), lib.edge("STORES", "wl:legacy", "data:customers", {})]))
}
