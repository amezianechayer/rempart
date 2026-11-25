package verify

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"

	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	"github.com/amezianechayer/rempart/internal/graph/reach"
)

// ErrNotDerived: the candidate does not derive from the initial candidate by
// the closed table of revisions of ADR 0012 D1. Fixed message.
var ErrNotDerived = errors.New("verify: candidate not derived from the subject")

// Derives returns ErrNotDerived unless cand derives from initial by the
// closed table of revisions of ADR 0012 D1 (obligation (fp), T110, T122):
// same header and free text; same nodes, of the same kind, whose attributes
// change only towards the restriction (public flags off, protections on,
// workload identity, sources of a public API dropped with it, listeners
// narrowed or moved to https); edges kept with the same ends, free text and
// attributes but a via moved to vpn_site_to_site and actions whose closure
// shrinks; an exposure or a flow from the Internet renamed from http to
// https on the same ports; a membership moved to the data subnet of the same
// VPC; removals only among exposures, flows from the Internet, permissions
// and moved memberships; and a reachability included in the initial one.
func Derives(initial, cand graphdomain.Graph) error {
	if initial.Version != cand.Version || initial.TenantID != cand.TenantID || initial.Source != cand.Source ||
		!sameJSON(initial.Text, cand.Text) || len(initial.Nodes) != len(cand.Nodes) {
		return ErrNotDerived
	}
	before := make(map[string]graphdomain.Node, len(initial.Nodes))
	for _, n := range initial.Nodes {
		before[n.ID] = n
	}
	kinds := map[string]graphdomain.NodeKind{}
	tiers := map[string]string{}
	for _, n := range cand.Nodes {
		o, ok := before[n.ID]
		if _, dup := kinds[n.ID]; !ok || dup || o.Kind != n.Kind || !sameJSON(o.Text, n.Text) || !nodeDerives(o.Attrs, n.Attrs) {
			return ErrNotDerived
		}
		kinds[n.ID] = n.Kind
		if n.Attrs.Tier != nil {
			tiers[n.ID] = *n.Attrs.Tier
		}
	}
	if !edgesDerive(initial.Edges, cand.Edges, kinds, tiers) {
		return ErrNotDerived
	}
	r0, err0 := reachOf(initial)
	r1, err1 := reachOf(cand)
	if err0 != nil || err1 != nil || !r1.SubsetOf(r0) {
		return ErrNotDerived
	}
	return nil
}

func edgesDerive(initial, cand []graphdomain.Edge, kinds map[string]graphdomain.NodeKind, tiers map[string]string) bool {
	old := make(map[string]graphdomain.Edge, len(initial))
	vpcOf := map[string]string{}
	for _, e := range initial {
		if _, dup := old[e.ID]; dup {
			return false
		}
		old[e.ID] = e
		if e.Type == graphdomain.EdgeMemberOf && tiers[e.Src] != "" {
			vpcOf[e.Src] = e.Dst
		}
	}
	used := map[string]bool{}
	movedTo := map[string]graphdomain.Edge{} // host -> its membership moved to a data subnet
	for _, e := range cand {
		id, renamed := e.ID, false
		if _, kept := old[id]; !kept {
			_, twice := movedTo[e.Src]
			switch {
			case (e.Type == graphdomain.EdgeExposes || e.Type == graphdomain.EdgeCanReach) && strings.Contains(id, "|https/"):
				id, renamed = strings.Replace(id, "|https/", "|http/", 1), true
			case e.Type == graphdomain.EdgeMemberOf && kinds[e.Dst] == graphdomain.KindNetwork && tiers[e.Dst] == "data" &&
				e.ID == "member_of|"+e.Src+"|"+e.Dst && !twice && kinds[e.Src] != "":
				movedTo[e.Src] = e
				continue
			default:
				return false
			}
		}
		o, ok := old[id]
		if !ok || used[id] || o.Type != e.Type || o.Src != e.Src || o.Dst != e.Dst || !sameJSON(o.Text, e.Text) ||
			!edgeAttrsDerive(o.Attrs, e.Attrs, e.Type, renamed) {
			return false
		}
		used[id] = true
	}
	moved := map[string]int{}
	for _, o := range initial {
		if used[o.ID] {
			continue
		}
		switch {
		case o.Type == graphdomain.EdgeExposes, o.Type == graphdomain.EdgeHasPermission:
		case o.Type == graphdomain.EdgeCanReach && kinds[o.Src] == graphdomain.KindInternet:
		case o.Type == graphdomain.EdgeMemberOf && movedFrom(o, movedTo, tiers, vpcOf):
			moved[o.Src]++
		default:
			return false
		}
	}
	for host := range movedTo {
		if moved[host] != 1 {
			return false
		}
	}
	return true
}

// movedFrom: o is the membership of a host to a subnet of a tier other than
// data, moved, attributes and free text kept, to the data subnet of the same
// VPC.
func movedFrom(o graphdomain.Edge, movedTo map[string]graphdomain.Edge, tiers, vpcOf map[string]string) bool {
	m, ok := movedTo[o.Src]
	return ok && tiers[o.Dst] != "" && tiers[o.Dst] != "data" && vpcOf[o.Dst] != "" && vpcOf[o.Dst] == vpcOf[m.Dst] &&
		sameJSON(o.Attrs, m.Attrs) && sameJSON(o.Text, m.Text)
}

// nodeDerives: every attribute equal, or changed towards the restriction.
func nodeDerives(o, n graphdomain.NodeAttrs) bool {
	a, b, ok := fieldsOf(o, n)
	if !ok {
		return false
	}
	for k := range union(a, b) {
		x, y := a[k], b[k]
		if reflect.DeepEqual(x, y) {
			continue
		}
		switch k {
		case "public_access", "public_ip", "api_public", "public":
			if y != false {
				return false
			}
		case "encrypted", "audit_log", "secrets_encryption", "network_policy_default_deny", "admission_policy", "workload_identity":
			if y != true {
				return false
			}
		case "credential":
			if y != "workload_identity" {
				return false
			}
		case "api_allowed_sources":
			if _, kept := b[k]; kept || b["api_public"] != false {
				return false
			}
		case "listeners":
			if !listenersNarrow(o.Listeners, n.Listeners) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// listenersNarrow: each listener of n is a distinct listener of o on the
// same port, of the same protocol or moved from http to https.
func listenersNarrow(o, n *[]graphdomain.Listener) bool {
	var before, after []graphdomain.Listener
	if o != nil {
		before = *o
	}
	if n != nil {
		after = *n
	}
	used := make([]bool, len(before))
	for _, l := range after {
		found := false
		for i, m := range before {
			if !used[i] && m.Port == l.Port && (m.Protocol == l.Protocol || (m.Protocol == "http" && l.Protocol == "https")) {
				used[i], found = true, true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// edgeAttrsDerive: every attribute equal, but a via moved to
// vpn_site_to_site, actions whose closure shrinks, and the protocol of an
// exposure or a flow moved from http to https, required when the identifier
// was renamed with it. The identifier of an edge is not tied to its protocol
// by the schema: https_only keeps an identifier without "|http/" (review of
// M2-T08, medium).
func edgeAttrsDerive(o, n graphdomain.EdgeAttrs, typ graphdomain.EdgeType, renamed bool) bool {
	a, b, ok := fieldsOf(o, n)
	https := a["protocol"] == "http" && b["protocol"] == "https" &&
		(typ == graphdomain.EdgeExposes || typ == graphdomain.EdgeCanReach)
	if !ok || (renamed && !https) {
		return false
	}
	for k := range union(a, b) {
		x, y := a[k], b[k]
		if reflect.DeepEqual(x, y) {
			continue
		}
		switch k {
		case "protocol":
			if !https {
				return false
			}
		case "via":
			if y != "vpn_site_to_site" {
				return false
			}
		case "actions":
			before := closure(o.Actions)
			for act := range closure(n.Actions) {
				if !before[act] {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

// closure of abstract actions (ADR 0010 D8); absent or empty, which the
// JSON encoding omits: every action (review of M2-T08, low).
func closure(actions []string) map[string]bool {
	if len(actions) == 0 {
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

func reachOf(g graphdomain.Graph) (reach.Result, error) {
	m, err := reach.FromGraph(graphdomain.FactsOf(g))
	if err != nil {
		return reach.Result{}, err
	}
	return reach.Compute(m, reach.DefaultLimits)
}

// fieldsOf reads two values as JSON objects.
func fieldsOf(x, y any) (map[string]any, map[string]any, bool) {
	a, b := asMap(x), asMap(y)
	return a, b, a != nil && b != nil
}

func asMap(v any) map[string]any {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return nil
	}
	return m
}

func union(a, b map[string]any) map[string]bool {
	out := make(map[string]bool, len(a)+len(b))
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}

func sameJSON(a, b any) bool {
	x, errX := json.Marshal(a)
	y, errY := json.Marshal(b)
	return errX == nil && errY == nil && bytes.Equal(x, y)
}
