package reach

import (
	"net/netip"
	"slices"

	"github.com/amezianechayer/rempart/internal/graph/domain"
)

// Classes of the facts of schemas/graph/v1.json for FromGraph (ADR 0010, D2):
// the row R1 to R6 that reads the fact, or NonNetwork. A fact added to the
// schema without a class fails TestGraphSchemaExtension (T116).
const NonNetwork = "non_network"

var (
	edgeClasses = map[domain.EdgeType]string{
		domain.EdgeExposes: "R1", domain.EdgeCanReach: "R2", domain.EdgeMemberOf: "R6",
		domain.EdgeStores: NonNetwork, domain.EdgeRunsAs: NonNetwork, domain.EdgeHasPermission: NonNetwork,
	}
	boolAttrClasses = map[string]string{
		"public":                      "R1", // public if and only if an EXPOSES edge leaves the load balancer (domain.Validate)
		"public_access":               "R3",
		"api_public":                  "R4",
		"public_ip":                   "R5",
		"network_policy_default_deny": "R6",
		"encrypted":                   NonNetwork,
		"audit_log":                   NonNetwork,
		"secrets_encryption":          NonNetwork,
		"admission_policy":            NonNetwork,
		"workload_identity":           NonNetwork,
	}
)

// EdgeClass returns the class of an edge type, "" if unclassified.
func EdgeClass(t domain.EdgeType) string { return edgeClasses[t] }

// BoolAttrClass returns the class of a boolean attribute, "" if unclassified.
func BoolAttrClass(name string) string { return boolAttrClasses[name] }

var allPorts = PortRange{From: 1, To: 65535}

// FromGraph maps the facts of a graph to a model by the closed table of D2,
// allow rules only (no implicit deny in M2). It reads a FactsGraph, never a
// Graph: no free text can enter. Model nodes are every node but Internet,
// Network, Identity and Account, sorted. An absent attribute is read at its
// widest; a fact it cannot read (unknown endpoint, protocol, port range or
// source) gives ErrInvalidModel, never a dropped hop.
func FromGraph(g domain.FactsGraph) (Model, error) {
	kinds := make(map[string]domain.NodeKind, len(g.Nodes))
	attrs := make(map[string]domain.NodeAttrs, len(g.Nodes))
	m := Model{Nodes: []string{}, Rules: []Rule{}}
	for _, n := range g.Nodes {
		kinds[n.ID], attrs[n.ID] = n.Kind, n.Attrs
		if inModel(n.Kind) {
			m.Nodes = append(m.Nodes, n.ID)
		}
	}
	slices.Sort(m.Nodes)
	endpoint := func(id string) (string, bool) {
		k, ok := kinds[id]
		switch {
		case !ok:
			return "", false
		case k == domain.KindInternet:
			return Internet, true
		default:
			return id, inModel(k)
		}
	}
	add := func(src, dst string, protos []Proto, ports PortRange, sources []netip.Prefix) {
		for _, p := range protos {
			m.Rules = append(m.Rules, Rule{Action: Allow, Src: src, Dst: dst, Proto: p, Ports: ports, Sources: sources})
		}
	}
	tcp, both := []Proto{TCP}, []Proto{TCP, UDP}

	for _, n := range g.Nodes {
		a := n.Attrs
		switch n.Kind {
		case domain.KindDataStore: // R3
			if open(a.PublicAccess) {
				ports := allPorts
				if a.Subtype != nil && (*a.Subtype == "object_storage" || *a.Subtype == "dataset") {
					ports = PortRange{From: 443, To: 443}
				}
				add(Internet, n.ID, tcp, ports, nil)
			}
		case domain.KindK8sCluster: // R4
			if open(a.APIPublic) {
				sources, err := parseSources(a.APIAllowedSources)
				if err != nil {
					return Model{}, err
				}
				add(Internet, n.ID, tcp, PortRange{From: 443, To: 443}, sources)
			}
		case domain.KindCompute: // R5
			if open(a.PublicIP) {
				add(Internet, n.ID, both, allPorts, nil)
			}
		}
	}

	for _, e := range g.Edges {
		switch e.Type {
		case domain.EdgeExposes, domain.EdgeCanReach: // R1, R2
			src, okS := endpoint(e.Src)
			dst, okD := endpoint(e.Dst)
			if e.Type == domain.EdgeExposes {
				// Read at its widest: Internet towards the source, whatever the destination.
				src, dst, okS, okD = Internet, src, true, okS && src != Internet
			}
			if !okS || !okD {
				return Model{}, ErrInvalidModel
			}
			if dst == Internet {
				continue // egress: no inbound path (M6, threat I)
			}
			protos, ports, err := flow(e.Attrs)
			if err != nil {
				return Model{}, err
			}
			sources, err := parseSources(e.Attrs.AllowedSources)
			if err != nil || (len(sources) > 0 && src != Internet) {
				return Model{}, ErrInvalidModel
			}
			add(src, dst, protos, ports, sources)
		case domain.EdgeMemberOf: // R6
			if kinds[e.Src] == domain.KindK8sWorkload && kinds[e.Dst] == domain.KindK8sCluster &&
				open(negate(attrs[e.Dst].NetworkPolicyDefaultDeny)) {
				add(e.Dst, e.Src, both, allPorts, nil)
				add(e.Src, e.Dst, both, allPorts, nil)
			}
		}
	}
	return m, nil
}

func inModel(k domain.NodeKind) bool {
	return k != domain.KindInternet && k != domain.KindNetwork && k != domain.KindIdentity && k != domain.KindAccount
}

// open reads a boolean that opens a flow at its widest: absent means true.
func open(b *bool) bool { return b == nil || *b }

// negate maps "default deny not true" to an opening flag: absent stays absent.
func negate(b *bool) *bool {
	if b == nil {
		return nil
	}
	v := !*b
	return &v
}

// flow reads the protocol and ports of an EXPOSES or CAN_REACH edge: http and
// https are tcp; an absent protocol is tcp and udp, absent ports 1 to 65535.
func flow(a domain.EdgeAttrs) ([]Proto, PortRange, error) {
	var protos []Proto
	switch {
	case a.Protocol == nil:
		protos = []Proto{TCP, UDP}
	case *a.Protocol == "tcp" || *a.Protocol == "http" || *a.Protocol == "https":
		protos = []Proto{TCP}
	case *a.Protocol == "udp":
		protos = []Proto{UDP}
	default:
		return nil, PortRange{}, ErrInvalidModel
	}
	from, to := 1, 65535
	if a.PortFrom != nil {
		from = *a.PortFrom
	}
	if a.PortTo != nil {
		to = *a.PortTo
	}
	if from < 1 || from > to || to > 65535 {
		return nil, PortRange{}, ErrInvalidModel
	}
	return protos, PortRange{From: uint16(from), To: uint16(to)}, nil
}

// parseSources reads canonical prefixes; empty means the whole Internet.
func parseSources(ss []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil || !canonicalPrefix(p) {
			return nil, ErrInvalidModel
		}
		out = append(out, p)
	}
	return out, nil
}
