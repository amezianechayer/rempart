package domain

import (
	"encoding/json"
	"slices"
)

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

// Facts returns the JSON of FactsOf(g).
func Facts(g Graph) ([]byte, error) { return json.Marshal(FactsOf(g)) }

// FactsOf returns the projection of g without any free text: the only input of
// reach.FromGraph, of the graph revision and of the policies (ADR 0010, D2, D12).
// It is a deep copy: editing the facts never changes g.
func FactsOf(g Graph) FactsGraph {
	f := FactsGraph{
		Version: g.Version, TenantID: g.TenantID, Source: g.Source,
		Nodes: make([]FactNode, 0, len(g.Nodes)),
		Edges: make([]FactEdge, 0, len(g.Edges)),
	}
	for _, n := range g.Nodes {
		f.Nodes = append(f.Nodes, FactNode{ID: n.ID, Kind: n.Kind, Attrs: n.Attrs.clone()})
	}
	for _, e := range g.Edges {
		f.Edges = append(f.Edges, FactEdge{ID: e.ID, Type: e.Type, Src: e.Src, Dst: e.Dst, Attrs: e.Attrs.clone()})
	}
	return f
}

func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func (a NodeAttrs) clone() NodeAttrs {
	c := NodeAttrs{
		Cloud: clonePtr(a.Cloud), Region: clonePtr(a.Region), Env: clonePtr(a.Env), Subtype: clonePtr(a.Subtype),
		CIDR: clonePtr(a.CIDR), Tier: clonePtr(a.Tier), Count: clonePtr(a.Count), OS: clonePtr(a.OS),
		Public: clonePtr(a.Public), Behind: slices.Clone(a.Behind), Classification: clonePtr(a.Classification),
		Regulation: slices.Clone(a.Regulation), Residency: clonePtr(a.Residency), Encrypted: clonePtr(a.Encrypted),
		PublicAccess: clonePtr(a.PublicAccess), APIPublic: clonePtr(a.APIPublic),
		Credential: clonePtr(a.Credential), PublicIP: clonePtr(a.PublicIP), APIAllowedSources: slices.Clone(a.APIAllowedSources),
		AuditLog: clonePtr(a.AuditLog), SecretsEncryption: clonePtr(a.SecretsEncryption),
		NetworkPolicyDefaultDeny: clonePtr(a.NetworkPolicyDefaultDeny), AdmissionPolicy: clonePtr(a.AdmissionPolicy),
		WorkloadIdentity: clonePtr(a.WorkloadIdentity),
	}
	if a.Listeners != nil {
		l := slices.Clone(*a.Listeners)
		c.Listeners = &l
	}
	return c
}

func (a EdgeAttrs) clone() EdgeAttrs {
	return EdgeAttrs{
		Protocol: clonePtr(a.Protocol), PortFrom: clonePtr(a.PortFrom), PortTo: clonePtr(a.PortTo), Via: clonePtr(a.Via),
		Path: slices.Clone(a.Path), AllowedSources: slices.Clone(a.AllowedSources), Actions: slices.Clone(a.Actions),
	}
}
