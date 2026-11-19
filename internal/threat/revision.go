package threat

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
)

// Revision is the SHA-256, lowercase hexadecimal, of the RFC 8785 (JCS) form
// of the facts of g (ADR 0010 D10): nodes and edges sorted by id, attribute
// sets sorted without duplicates (behind, regulation, allowed_sources,
// api_allowed_sources, actions, listeners by protocol then port), path kept in
// order. version, tenant_id and source are included; free text cannot be (a
// FactsGraph carries none). On this subset (ASCII strings of closed grammars,
// integers, booleans), JCS is the JSON of encoding/json with keys sorted and
// no HTML escaping.
func Revision(g graphdomain.FactsGraph) (string, error) {
	c := graphdomain.FactsGraph{
		Version: g.Version, TenantID: g.TenantID, Source: g.Source,
		Nodes: make([]graphdomain.FactNode, 0, len(g.Nodes)), Edges: make([]graphdomain.FactEdge, 0, len(g.Edges)),
	}
	for _, n := range g.Nodes {
		a := n.Attrs
		a.Behind, a.Regulation, a.APIAllowedSources = set(a.Behind), set(a.Regulation), set(a.APIAllowedSources)
		if a.Listeners != nil {
			l := slices.Clone(*a.Listeners)
			slices.SortFunc(l, func(x, y graphdomain.Listener) int {
				return cmp.Or(strings.Compare(x.Protocol, y.Protocol), cmp.Compare(x.Port, y.Port))
			})
			l = slices.Compact(l)
			a.Listeners = &l
		}
		c.Nodes = append(c.Nodes, graphdomain.FactNode{ID: n.ID, Kind: n.Kind, Attrs: a})
	}
	for _, e := range g.Edges {
		a := e.Attrs
		a.AllowedSources, a.Actions = set(a.AllowedSources), set(a.Actions)
		c.Edges = append(c.Edges, graphdomain.FactEdge{ID: e.ID, Type: e.Type, Src: e.Src, Dst: e.Dst, Attrs: a})
	}
	slices.SortFunc(c.Nodes, func(x, y graphdomain.FactNode) int { return strings.Compare(x.ID, y.ID) })
	slices.SortFunc(c.Edges, func(x, y graphdomain.FactEdge) int { return strings.Compare(x.ID, y.ID) })

	raw, err := json.Marshal(c)
	if err != nil {
		return "", ErrInvalidInput
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return "", ErrInvalidInput
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil { // maps: keys sorted
		return "", ErrInvalidInput
	}
	sum := sha256.Sum256(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
	return hex.EncodeToString(sum[:]), nil
}

// set sorts and deduplicates; nil stays nil (an absent attribute).
func set(xs []string) []string {
	if xs == nil {
		return nil
	}
	out := slices.Clone(xs)
	slices.Sort(out)
	return slices.Compact(out)
}
