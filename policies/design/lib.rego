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

# sensitive_data: a confidential or regulated data store (absent: sensitive).
sensitive_data(n) if {
	n.kind == "DataStore"
	not n.attrs.classification in {"public", "internal"}
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
