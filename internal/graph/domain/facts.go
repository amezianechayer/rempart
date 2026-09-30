package domain

import "encoding/json"

// FactsGraph is the projection of a Graph without any free text: the only view
// meant for policies and for the model. No type reachable from it holds a FreeText.
type FactsGraph struct {
	Version  string     `json:"version"`
	TenantID string     `json:"tenant_id"`
	Source   string     `json:"source"`
	Nodes    []FactNode `json:"nodes"`
	Edges    []FactEdge `json:"edges"`
}

// FactNode is a node without its free text.
type FactNode struct {
	ID    string    `json:"id"`
	Kind  NodeKind  `json:"kind"`
	Attrs NodeAttrs `json:"attrs"`
}

// FactEdge is an edge without its free text.
type FactEdge struct {
	ID    string    `json:"id"`
	Type  EdgeType  `json:"type"`
	Src   string    `json:"src"`
	Dst   string    `json:"dst"`
	Attrs EdgeAttrs `json:"attrs"`
}

// Facts returns the JSON of the FactsGraph projection of g.
func Facts(g Graph) ([]byte, error) {
	f := FactsGraph{
		Version: g.Version, TenantID: g.TenantID, Source: g.Source,
		Nodes: make([]FactNode, 0, len(g.Nodes)),
		Edges: make([]FactEdge, 0, len(g.Edges)),
	}
	for _, n := range g.Nodes {
		f.Nodes = append(f.Nodes, FactNode{ID: n.ID, Kind: n.Kind, Attrs: n.Attrs})
	}
	for _, e := range g.Edges {
		f.Edges = append(f.Edges, FactEdge{ID: e.ID, Type: e.Type, Src: e.Src, Dst: e.Dst, Attrs: e.Attrs})
	}
	return json.Marshal(f)
}
