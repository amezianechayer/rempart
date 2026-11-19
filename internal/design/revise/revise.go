// Package revise is the deterministic proposer of L2 (ADR 0012 D1): a closed
// table of remediations that only restrict, applied to the resources of the
// findings, each kept only if the graph stays valid. It never relocates,
// allocates, reclassifies, changes a port, adds a node or an edge other than a
// membership moved to the data tier; dedicated_identity, escalate and advisory
// are never applied in M2.
package revise

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"

	"github.com/amezianechayer/rempart/internal/graph"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
	policydomain "github.com/amezianechayer/rempart/internal/policy/domain"
)

// Applied is one remediation that changed the graph.
type Applied struct {
	ControlID   string                   `json:"control_id"`
	Resource    string                   `json:"resource"`
	Remediation policydomain.Remediation `json:"remediation"`
}

// ErrRevise: an input graph outside its schema or invariants. Fixed message.
var ErrRevise = errors.New("revise: invalid graph")

// Revise applies, in the order of the findings, the remediation of the control
// of each (read in controls, never in the message) to its resource. A
// remediation that changes nothing or leaves an invalid graph is dropped. The
// input is never modified; with no revision, g itself is returned.
func Revise(g graphdomain.Graph, findings []loopsdomain.Finding, controls []policydomain.Control) (graphdomain.Graph, []Applied, error) {
	if !valid(g) {
		return graphdomain.Graph{}, nil, ErrRevise
	}
	rem := make(map[string]policydomain.Remediation, len(controls))
	for _, c := range controls {
		rem[c.ID] = c.Remediation
	}
	cur, err := clone(g)
	if err != nil {
		return graphdomain.Graph{}, nil, ErrRevise
	}
	applied := []Applied{}
	seen := map[[2]string]bool{}
	for _, f := range findings {
		k := [2]string{f.Code, f.Resource}
		r, known := rem[f.Code]
		if seen[k] || !known {
			continue
		}
		seen[k] = true
		next, err := clone(cur)
		if err != nil {
			return graphdomain.Graph{}, nil, ErrRevise
		}
		apply(&next, r, f.Resource)
		if reflect.DeepEqual(next, cur) || !valid(next) {
			continue
		}
		cur = next
		applied = append(applied, Applied{ControlID: f.Code, Resource: f.Resource, Remediation: r})
	}
	if len(applied) == 0 {
		return g, applied, nil
	}
	return cur, applied, nil
}

func valid(g graphdomain.Graph) bool {
	return graph.ValidateSchema(g) == nil && graphdomain.Validate(g) == nil
}

func clone(g graphdomain.Graph) (graphdomain.Graph, error) {
	raw, err := json.Marshal(g)
	if err != nil {
		return graphdomain.Graph{}, err
	}
	var out graphdomain.Graph
	return out, json.Unmarshal(raw, &out)
}

func falseP() *bool { v := false; return &v }

func trueP() *bool { v := true; return &v }

func str(s string) *string { return &s }

// apply edits g in place; the caller compares and validates.
func apply(g *graphdomain.Graph, r policydomain.Remediation, res string) {
	n := node(g, res)
	switch r {
	case policydomain.RemediationMakePrivate:
		if n != nil {
			makePrivate(n)
		}
	case policydomain.RemediationRemoveExposure:
		removeExposure(g, res)
	case policydomain.RemediationHTTPSOnly:
		httpsOnly(g, res)
	case policydomain.RemediationEncryptTransit:
		if e := edge(g, res); e != nil && e.Type == graphdomain.EdgeCanReach {
			e.Attrs.Via = str("vpn_site_to_site")
		}
	case policydomain.RemediationMoveToDataTier:
		moveToDataTier(g, res)
	case policydomain.RemediationEnableEncryption:
		if n != nil && n.Kind == graphdomain.KindDataStore {
			n.Attrs.Encrypted = trueP()
		}
	case policydomain.RemediationLeastPrivilege:
		leastPrivilege(g, res)
	case policydomain.RemediationUseWorkloadIdentity:
		switch {
		case n != nil && n.Kind == graphdomain.KindIdentity:
			n.Attrs.Credential = str("workload_identity")
		case n != nil && n.Kind == graphdomain.KindK8sCluster:
			n.Attrs.WorkloadIdentity = trueP()
		}
	case policydomain.RemediationEnableAuditLog, policydomain.RemediationEnableSecretsEncryption,
		policydomain.RemediationEnableAdmission, policydomain.RemediationDefaultDenyNetpol:
		if n != nil && n.Kind == graphdomain.KindK8sCluster {
			*map[policydomain.Remediation]**bool{
				policydomain.RemediationEnableAuditLog:          &n.Attrs.AuditLog,
				policydomain.RemediationEnableSecretsEncryption: &n.Attrs.SecretsEncryption,
				policydomain.RemediationEnableAdmission:         &n.Attrs.AdmissionPolicy,
				policydomain.RemediationDefaultDenyNetpol:       &n.Attrs.NetworkPolicyDefaultDeny,
			}[r] = trueP()
		}
	}
}

func node(g *graphdomain.Graph, id string) *graphdomain.Node {
	for i := range g.Nodes {
		if g.Nodes[i].ID == id {
			return &g.Nodes[i]
		}
	}
	return nil
}

func edge(g *graphdomain.Graph, id string) *graphdomain.Edge {
	for i := range g.Edges {
		if g.Edges[i].ID == id {
			return &g.Edges[i]
		}
	}
	return nil
}

func makePrivate(n *graphdomain.Node) {
	switch n.Kind {
	case graphdomain.KindDataStore:
		n.Attrs.PublicAccess = falseP()
	case graphdomain.KindCompute:
		n.Attrs.PublicIP = falseP()
	case graphdomain.KindK8sCluster:
		n.Attrs.APIPublic, n.Attrs.APIAllowedSources = falseP(), nil
	}
}

// removeExposure removes an EXPOSES edge, or every exposure of a node: its
// EXPOSES edges, the CAN_REACH edges from the Internet to it, its public
// flags; a load balancer left without exposure is private, without listener.
func removeExposure(g *graphdomain.Graph, res string) {
	kinds := map[string]graphdomain.NodeKind{}
	for _, n := range g.Nodes {
		kinds[n.ID] = n.Kind
	}
	lbs := map[string]bool{}
	g.Edges = slices.DeleteFunc(g.Edges, func(e graphdomain.Edge) bool {
		gone := (e.Type == graphdomain.EdgeExposes && (e.ID == res || e.Src == res)) ||
			(e.Type == graphdomain.EdgeCanReach && kinds[e.Src] == graphdomain.KindInternet && e.Dst == res)
		if gone && e.Type == graphdomain.EdgeExposes && kinds[e.Src] == graphdomain.KindLoadBalancer {
			lbs[e.Src] = true
		}
		return gone
	})
	if n := node(g, res); n != nil {
		makePrivate(n)
	}
	for id := range lbs {
		syncListeners(g, id)
	}
}

// syncListeners keeps the listeners of a load balancer that an EXPOSES edge
// still opens; without one, the load balancer is private.
func syncListeners(g *graphdomain.Graph, id string) {
	n := node(g, id)
	if n == nil {
		return
	}
	open := map[graphdomain.Listener]bool{}
	for _, e := range g.Edges {
		if e.Type == graphdomain.EdgeExposes && e.Src == id && e.Attrs.Protocol != nil && e.Attrs.PortFrom != nil {
			open[graphdomain.Listener{Protocol: *e.Attrs.Protocol, Port: *e.Attrs.PortFrom}] = true
		}
	}
	kept := []graphdomain.Listener{}
	if n.Attrs.Listeners != nil {
		for _, l := range *n.Attrs.Listeners {
			if open[l] {
				kept = append(kept, l)
			}
		}
	}
	n.Attrs.Listeners = &kept
	if len(open) == 0 {
		n.Attrs.Public = falseP()
	}
}

// httpsOnly turns http into https on the same port (same tcp tuple for
// reach): an EXPOSES or Internet CAN_REACH edge, or every exposure of a load
// balancer and its listeners. Identifiers follow the protocol.
func httpsOnly(g *graphdomain.Graph, res string) {
	lbs := map[string]bool{}
	for i := range g.Edges {
		e := &g.Edges[i]
		named := e.ID == res || (e.Type == graphdomain.EdgeExposes && e.Src == res)
		if e.Attrs.Protocol == nil || *e.Attrs.Protocol != "http" || !named {
			continue
		}
		if e.Type != graphdomain.EdgeExposes && e.Type != graphdomain.EdgeCanReach {
			continue
		}
		e.Attrs.Protocol = str("https")
		e.ID = strings.Replace(e.ID, "|http/", "|https/", 1)
		if e.Type == graphdomain.EdgeExposes {
			lbs[e.Src] = true
		}
	}
	for id := range lbs {
		n := node(g, id)
		if n == nil || n.Kind != graphdomain.KindLoadBalancer || n.Attrs.Listeners == nil {
			continue
		}
		ls := slices.Clone(*n.Attrs.Listeners)
		for i := range ls {
			if ls[i].Protocol == "http" && hasExposure(g, id, "https", ls[i].Port) {
				ls[i].Protocol = "https"
			}
		}
		n.Attrs.Listeners = &ls
	}
}

func hasExposure(g *graphdomain.Graph, src, proto string, port int) bool {
	for _, e := range g.Edges {
		a := e.Attrs
		if e.Type == graphdomain.EdgeExposes && e.Src == src && a.Protocol != nil && *a.Protocol == proto && a.PortFrom != nil && *a.PortFrom == port {
			return true
		}
	}
	return false
}

// moveToDataTier moves the membership of a host from its subnet to the data
// subnet of the same VPC, if there is one.
func moveToDataTier(g *graphdomain.Graph, res string) {
	tier := map[string]string{}
	vpcOf := map[string]string{}
	for _, n := range g.Nodes {
		if n.Kind == graphdomain.KindNetwork && n.Attrs.Tier != nil {
			tier[n.ID] = *n.Attrs.Tier
		}
	}
	for _, e := range g.Edges {
		if e.Type == graphdomain.EdgeMemberOf && tier[e.Src] != "" {
			vpcOf[e.Src] = e.Dst
		}
	}
	for i := range g.Edges {
		e := &g.Edges[i]
		if e.Type != graphdomain.EdgeMemberOf || e.Src != res || tier[e.Dst] == "" || tier[e.Dst] == "data" {
			continue
		}
		for subnet, t := range tier {
			if t == "data" && vpcOf[subnet] == vpcOf[e.Dst] && vpcOf[subnet] != "" {
				e.Dst = subnet
				e.ID = "member_of|" + res + "|" + subnet
				break
			}
		}
	}
}

// leastPrivilege reduces the permissions of an identity, or one permission:
// towards an account, or a data store its workloads neither host nor reach,
// the permission is removed; otherwise its actions become the closure of its
// actions (ADR 0010 D8) restricted to read and write.
func leastPrivilege(g *graphdomain.Graph, res string) {
	kinds := map[string]graphdomain.NodeKind{}
	for _, n := range g.Nodes {
		kinds[n.ID] = n.Kind
	}
	target := func(e graphdomain.Edge) bool {
		return e.Type == graphdomain.EdgeHasPermission && (e.ID == res || (e.Src == res && kinds[res] == graphdomain.KindIdentity))
	}
	used := func(identity, data string) bool {
		runners := map[string]bool{}
		hosts := map[string]bool{}
		for _, e := range g.Edges {
			switch e.Type {
			case graphdomain.EdgeRunsAs:
				if e.Dst == identity {
					runners[e.Src] = true
				}
			case graphdomain.EdgeStores:
				if e.Dst == data {
					hosts[e.Src] = true
				}
			}
		}
		for _, e := range g.Edges {
			if runners[e.Src] && ((e.Type == graphdomain.EdgeStores && e.Dst == data) || (e.Type == graphdomain.EdgeCanReach && hosts[e.Dst])) {
				return true
			}
		}
		for r := range runners {
			if hosts[r] {
				return true
			}
		}
		return false
	}
	var keep []graphdomain.Edge
	for _, e := range g.Edges {
		if !target(e) {
			keep = append(keep, e)
			continue
		}
		if kinds[e.Dst] == graphdomain.KindAccount || (kinds[e.Dst] == graphdomain.KindDataStore && !used(e.Src, e.Dst)) {
			continue
		}
		c := closure(e.Attrs.Actions)
		var actions []string
		for _, a := range []string{"read", "write"} {
			if c[a] {
				actions = append(actions, a)
			}
		}
		if len(actions) == 0 {
			continue
		}
		e.Attrs.Actions = actions
		keep = append(keep, e)
	}
	g.Edges = keep
}

// closure of abstract actions (ADR 0010 D8); absent: every action.
func closure(actions []string) map[string]bool {
	if actions == nil {
		actions = []string{"*"}
	}
	out := map[string]bool{}
	for _, a := range actions {
		switch a {
		case "admin":
			out["read"], out["write"], out["admin"] = true, true, true
		case "*":
			out["read"], out["write"], out["admin"], out["*"] = true, true, true, true
		default:
			out[a] = true
		}
	}
	return out
}
