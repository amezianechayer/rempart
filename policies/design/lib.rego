package rempart.design.lib

# Shared predicates of the design pack (ADR 0011 D4): no metadata, no deny.
# Every security attribute is read on the safe side: an absent attribute is
# the value that fires the control.

# nodes maps each identifier to its node.
nodes := {n.id: n | some n in input.graph.nodes}

# internet_hops are the hops from the whole Internet or from listed sources.
internet_hops contains h if {
	some h in input.reach.hops
	h.src == "internet"
}

# hop_port: h permits port p.
hop_port(h, p) if {
	some r in h.ports
	r.from <= p
	p <= r.to
}

# sensitive_data: a confidential or regulated data store (absent: sensitive),
# or a data store under any regulation, whatever its classification (closing
# review of M2, T139; FactNode.SensitiveData in Go).
sensitive_data(n) if {
	n.kind == "DataStore"
	not n.attrs.classification in {"public", "internal"}
}

sensitive_data(n) if {
	n.kind == "DataStore"
	count(object.get(n.attrs, "regulation", [])) > 0
}

# sensitive_hosts host sensitive data (source of a STORES edge).
sensitive_hosts contains e.src if {
	some e in input.graph.edges
	e.type == "STORES"
	sensitive_data(nodes[e.dst])
}

# sensitive: sensitive data or its host.
sensitive(id) if sensitive_data(nodes[id])

sensitive(id) if id in sensitive_hosts

# subnet_tiers are the tiers of the subnets id is a member of.
subnet_tiers(id) := {t |
	some e in input.graph.edges
	e.type == "MEMBER_OF"
	e.src == id
	n := nodes[e.dst]
	n.kind == "Network"
	t := n.attrs.tier
}

# clusters are the clusters id runs on.
clusters(id) := {e.dst |
	some e in input.graph.edges
	e.type == "MEMBER_OF"
	e.src == id
	nodes[e.dst].kind == "K8sCluster"
}

# tiers of id: its subnets, or the subnets of its cluster.
tiers(id) := subnet_tiers(id) | {t | some c in clusters(id); some t in subnet_tiers(c)}

# internet_flows: EXPOSES edges and CAN_REACH edges leaving the Internet node.
internet_flows contains e if {
	some e in input.graph.edges
	e.type == "EXPOSES"
}

internet_flows contains e if {
	some e in input.graph.edges
	e.type == "CAN_REACH"
	nodes[e.src].kind == "Internet"
}

# exposure_targets: what an EXPOSES edge opens, the targets of its load
# balancer, or the exposed node itself.
exposure_targets(e) := {c.dst |
	some c in input.graph.edges
	c.type == "CAN_REACH"
	c.src == e.src
} if {
	nodes[e.src].kind == "LoadBalancer"
}

exposure_targets(e) := {e.src} if {
	not nodes[e.src].kind == "LoadBalancer"
}

# port_count: ports of a flow; undefined when a bound is absent (widest).
port_count(e) := (e.attrs.port_to - e.attrs.port_from) + 1

# bounded_flow: at most 100 ports, both bounds present. Negate this predicate,
# never a call nested in not: OPA moves the call out of the negation and an
# absent bound would then silence the rule (T119).
bounded_flow(e) if port_count(e) <= 100

# open_to_world: the sources of a flow or of a cluster API are the whole
# Internet: absent or empty, or covering 0.0.0.0/0 once merged, as computed in
# Go into derived.world_sources (obligation (fg), T102).
open_to_world(id, _) if id in input.derived.world_sources

open_to_world(_, sources) if count(sources) == 0

# placed: a component with a location of its own (a dataset is placed by its
# host); a data store without subtype is placed (safe side).
placed(n) if n.kind in {"Compute", "K8sCluster", "K8sWorkload", "LoadBalancer"}

placed(n) if {
	n.kind == "DataStore"
	not n.attrs.subtype == "dataset"
}

# zone of a node (ADR 0011 D7); absent from the jurisdiction map: unknown.
zone(id) := object.get(input.derived.jurisdiction, id, "unknown")

# regulated: classification regulated or a regulation listed.
regulated(d) if d.attrs.classification == "regulated"

regulated(d) if count(object.get(d.attrs, "regulation", [])) > 0

# sensitive_placed: hosts of sensitive data and sensitive data stores with a
# placement of their own (every subtype but a dataset).
sensitive_placed contains id if some id in sensitive_hosts

sensitive_placed contains n.id if {
	some n in input.graph.nodes
	sensitive_data(n)
	not n.attrs.subtype == "dataset"
}

# exposed: reached directly from the Internet, or opened by an exposure.
exposed(id) if {
	some h in internet_hops
	h.dst == id
}

exposed(id) if {
	some e in input.graph.edges
	e.type == "EXPOSES"
	id in exposure_targets(e)
}

# identities of a workload, runners of an identity (RUNS_AS).
identities(w) := {e.dst |
	some e in input.graph.edges
	e.type == "RUNS_AS"
	e.src == w
}

runners(i) := {e.src |
	some e in input.graph.edges
	e.type == "RUNS_AS"
	e.dst == i
}

# actions of a permission; absent: every action (widest).
actions(e) := object.get(e.attrs, "actions", ["*"])

workload_kinds := {"Compute", "K8sCluster", "K8sWorkload"}
