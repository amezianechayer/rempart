package rempart.design_test.lib

# Helpers of the design pack tests (ADR 0011 D4). The tests live outside
# rempart.design: the query data.rempart.design[_].deny[_] never sees them.

# findings is the union of the outputs of every control of the pack.
findings contains f if {
	some f in data.rempart.design[_].deny
}

# ko(id, inp): the control id fires on inp.
ko(id, inp) if {
	fs := findings with input as inp
	some f in fs
	f.control_id == id
}

# ok(id, inp): the control id does not fire on inp.
ok(id, inp) if not ko(id, inp)

# base is a compliant graph: a load balancer behind a WAF exposes a web tier
# on HTTPS; the web tier reaches a database host in the data tier, which
# stores confidential data; each workload has its own identity.
base := {
	"graph": {
		"version": "1",
		"tenant_id": "3f6c2a9e-8b1d-4c7a-9e2f-5d4b3a2c1e0f",
		"source": "design",
		"nodes": [
			{"id": "internet", "kind": "Internet", "attrs": {}},
			{"id": "net:vpc", "kind": "Network", "attrs": {"subtype": "vpc", "cloud": "aws", "region": "eu-west-3", "env": "prod", "cidr": "10.0.0.0/20"}},
			{"id": "net:vpc-public", "kind": "Network", "attrs": {"subtype": "subnet", "tier": "public", "cloud": "aws", "region": "eu-west-3", "env": "prod", "cidr": "10.0.0.0/26"}},
			{"id": "net:vpc-app", "kind": "Network", "attrs": {"subtype": "subnet", "tier": "app", "cloud": "aws", "region": "eu-west-3", "env": "prod", "cidr": "10.0.1.0/24"}},
			{"id": "net:vpc-data", "kind": "Network", "attrs": {"subtype": "subnet", "tier": "data", "cloud": "aws", "region": "eu-west-3", "env": "prod", "cidr": "10.0.2.0/24"}},
			{"id": "net:vpc-mgmt", "kind": "Network", "attrs": {"subtype": "subnet", "tier": "mgmt", "cloud": "aws", "region": "eu-west-3", "env": "prod", "cidr": "10.0.3.0/24"}},
			{"id": "lb:web-443", "kind": "LoadBalancer", "attrs": {"cloud": "aws", "region": "eu-west-3", "public": true, "listeners": [{"protocol": "https", "port": 443}], "behind": ["waf", "load_balancer"]}},
			{"id": "wl:web", "kind": "Compute", "attrs": {"subtype": "vm", "cloud": "aws", "region": "eu-west-3", "count": 2, "public_ip": false}},
			{"id": "wl:db", "kind": "Compute", "attrs": {"subtype": "vm", "cloud": "aws", "region": "eu-west-3", "count": 2, "public_ip": false}},
			{"id": "data:customers", "kind": "DataStore", "attrs": {"subtype": "dataset", "classification": "confidential", "encrypted": true, "public_access": false, "residency": "eu", "regulation": ["gdpr"]}},
			{"id": "id:web", "kind": "Identity", "attrs": {"subtype": "role", "cloud": "aws", "credential": "workload_identity"}},
			{"id": "id:db", "kind": "Identity", "attrs": {"subtype": "role", "cloud": "aws", "credential": "workload_identity"}},
		],
		"edges": [
			{"id": "member_of|net:vpc-public|net:vpc", "type": "MEMBER_OF", "src": "net:vpc-public", "dst": "net:vpc", "attrs": {}},
			{"id": "member_of|net:vpc-app|net:vpc", "type": "MEMBER_OF", "src": "net:vpc-app", "dst": "net:vpc", "attrs": {}},
			{"id": "member_of|net:vpc-data|net:vpc", "type": "MEMBER_OF", "src": "net:vpc-data", "dst": "net:vpc", "attrs": {}},
			{"id": "member_of|net:vpc-mgmt|net:vpc", "type": "MEMBER_OF", "src": "net:vpc-mgmt", "dst": "net:vpc", "attrs": {}},
			{"id": "member_of|lb:web-443|net:vpc-public", "type": "MEMBER_OF", "src": "lb:web-443", "dst": "net:vpc-public", "attrs": {}},
			{"id": "member_of|wl:web|net:vpc-app", "type": "MEMBER_OF", "src": "wl:web", "dst": "net:vpc-app", "attrs": {}},
			{"id": "member_of|wl:db|net:vpc-data", "type": "MEMBER_OF", "src": "wl:db", "dst": "net:vpc-data", "attrs": {}},
			{"id": "exposes|lb:web-443|internet|https/443", "type": "EXPOSES", "src": "lb:web-443", "dst": "internet", "attrs": {"protocol": "https", "port_from": 443, "port_to": 443}},
			{"id": "can_reach|lb:web-443|wl:web|https/443", "type": "CAN_REACH", "src": "lb:web-443", "dst": "wl:web", "attrs": {"protocol": "https", "port_from": 443, "port_to": 443, "via": "load_balancer", "path": ["net:vpc-public", "net:vpc-app"]}},
			{"id": "can_reach|wl:web|wl:db|tcp/5432", "type": "CAN_REACH", "src": "wl:web", "dst": "wl:db", "attrs": {"protocol": "tcp", "port_from": 5432, "port_to": 5432, "via": "internal", "path": ["net:vpc-app", "net:vpc-data"]}},
			{"id": "stores|wl:db|data:customers", "type": "STORES", "src": "wl:db", "dst": "data:customers", "attrs": {}},
			{"id": "runs_as|wl:web|id:web", "type": "RUNS_AS", "src": "wl:web", "dst": "id:web", "attrs": {}},
			{"id": "runs_as|wl:db|id:db", "type": "RUNS_AS", "src": "wl:db", "dst": "id:db", "attrs": {}},
			{"id": "has_permission|id:db|data:customers", "type": "HAS_PERMISSION", "src": "id:db", "dst": "data:customers", "attrs": {"actions": ["read", "write"]}},
		],
	},
	"reach": {
		"hops": [
			{"src": "internet", "dst": "lb:web-443", "proto": "tcp", "ports": [{"from": 443, "to": 443}], "world": true},
			{"src": "lb:web-443", "dst": "wl:web", "proto": "tcp", "ports": [{"from": 443, "to": 443}], "world": false},
			{"src": "wl:web", "dst": "wl:db", "proto": "tcp", "ports": [{"from": 5432, "to": 5432}], "world": false},
		],
		"from_internet": [
			{"target": "lb:web-443", "nodes": ["internet", "lb:web-443"]},
			{"target": "wl:db", "nodes": ["internet", "lb:web-443", "wl:web", "wl:db"]},
			{"target": "wl:web", "nodes": ["internet", "lb:web-443", "wl:web"]},
		],
	},
	"derived": {
		"jurisdiction": {
			"lb:web-443": "fr", "wl:web": "fr", "wl:db": "fr", "net:vpc": "fr",
			"net:vpc-public": "fr", "net:vpc-app": "fr", "net:vpc-data": "fr", "net:vpc-mgmt": "fr",
		},
		"unconfirmed_exposures": [],
		"sources_unresolved": [],
		"constraints": {"allowed_regions": [], "forbidden_clouds": []},
		"environment": "prod",
		"observability": {"metrics": true, "logs": true},
		"workload_roles": {},
	},
}

# Builders. object.union merges objects recursively and replaces arrays.

with_nodes(inp, ns) := object.union(inp, {"graph": {"nodes": array.concat(inp.graph.nodes, ns)}})

with_edges(inp, es) := object.union(inp, {"graph": {"edges": array.concat(inp.graph.edges, es)}})

with_hops(inp, hs) := object.union(inp, {"reach": {"hops": array.concat(inp.reach.hops, hs)}})

with_paths(inp, ps) := object.union(inp, {"reach": {"from_internet": array.concat(inp.reach.from_internet, ps)}})

with_derived(inp, d) := object.union(inp, {"derived": d})

# set_node merges attrs into the attributes of node id.
set_node(inp, id, attrs) := object.union(inp, {"graph": {"nodes": [patched(n, id, attrs) | some n in inp.graph.nodes]}})

# set_edge merges attrs into the attributes of edge id.
set_edge(inp, id, attrs) := object.union(inp, {"graph": {"edges": [patched(e, id, attrs) | some e in inp.graph.edges]}})

# without_edge removes edge id.
without_edge(inp, id) := object.union(inp, {"graph": {"edges": [e | some e in inp.graph.edges; e.id != id]}})

patched(x, id, attrs) := object.union(x, {"attrs": attrs}) if x.id == id

patched(x, id, _) := x if x.id != id

node(id, kind, attrs) := {"id": id, "kind": kind, "attrs": attrs}

edge(typ, src, dst, attrs) := {"id": concat("|", [typ, src, dst]), "type": typ, "src": src, "dst": dst, "attrs": attrs}

member(src, dst) := edge("MEMBER_OF", src, dst, {})

# hop_world is a hop from the whole Internet.
hop_world(dst, proto, from, to) := {"src": "internet", "dst": dst, "proto": proto, "ports": [{"from": from, "to": to}], "world": true}

# The helpers are not a no-op: base is compliant for a control that fires
# on a variant, so ok and ko disagree on them.
test_helpers_disagree if {
	inp := set_node(base, "data:customers", {"public_access": true})
	ko("DATA-001", inp)
	ok("DATA-001", base)
	not ko("DATA-001", base)
}
