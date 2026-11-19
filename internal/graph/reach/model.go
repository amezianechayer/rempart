// Package reach computes the reachability of ADR 0010 (D1 to D4): a set of hops
// "allow minus deny" without any order between rules (deny always wins), and
// the shortest path from internet to every node it reaches, by a bounded
// breadth-first search. One implementation for L2, L5 and L6 (skill
// multicloud-networking). Imports: the standard library and internal/graph only.
package reach

import (
	"errors"
	"net/netip"
)

// Proto is the transport protocol of a rule or a hop.
type Proto string

// Protocols (http and https are read as tcp by FromGraph).
const (
	TCP Proto = "tcp"
	UDP Proto = "udp"
)

// Actions of a rule.
const (
	Allow = "allow"
	Deny  = "deny"
)

// Internet is the implicit source node, never listed in Model.Nodes; Any
// matches every node and internet, in a deny rule only.
const (
	Internet = "internet"
	Any      = "*"
)

// PortRange is the closed range From to To, 1 <= From <= To <= 65535.
type PortRange struct {
	From uint16 `json:"from"`
	To   uint16 `json:"to"`
}

// PortSet is a list of ranges, sorted and merged (adjacent ranges joined).
type PortSet []PortRange

// Rule is one unordered rule of the model.
//
//   - allow: Src is a node or internet, Dst a node; Sources only from internet,
//     canonical prefixes, empty meaning the whole Internet.
//   - deny: Src is a node, internet or Any, Dst a node or Any; no Sources (a
//     deny holds for every source address in M2).
type Rule struct {
	Action  string
	Src     string
	Dst     string
	Proto   Proto
	Ports   PortRange
	Sources []netip.Prefix
}

// Model is the input of Compute.
type Model struct {
	Nodes []string
	Rules []Rule
}

// Limits bound the computation (T24); every bound must be strictly positive.
type Limits struct {
	MaxNodes int // nodes of the model
	MaxRules int // (rule, source) pairs, a rule without source counting one
	MaxDepth int // hops of a path
	MaxPaths int // nodes reached from internet (one path each)
}

// DefaultLimits are the limits of ADR 0010, D4 (the schema maxima for nodes
// and rules).
var DefaultLimits = Limits{MaxNodes: 10000, MaxRules: 50000, MaxDepth: 32, MaxPaths: 10000}

// Hop is one permitted flow, in the canonical form of D1. A hop from internet
// permits Ports from every address when World is true, otherwise from the
// addresses of Sources; the hops of one triple (Src, Dst, Proto) are united.
type Hop struct {
	Src     string         `json:"src"`
	Dst     string         `json:"dst"`
	Proto   Proto          `json:"proto"`
	Ports   PortSet        `json:"ports"`
	World   bool           `json:"world"`
	Sources []netip.Prefix `json:"sources,omitempty"`
}

// Path is the shortest path from internet to Target: Nodes starts with
// internet and ends with Target. A path of more than one hop assumes every
// intermediate node can pivot: a hypothesis, never a fact of compromise.
type Path struct {
	Target string   `json:"target"`
	Nodes  []string `json:"nodes"`
}

// Result is the output of Compute: hops in their total order, paths sorted by
// target. Never partial.
type Result struct {
	Hops         []Hop  `json:"hops"`
	FromInternet []Path `json:"from_internet"`
}

// Errors of Compute and FromGraph. Fixed messages: they never quote the model.
var (
	// ErrGraphTooLarge: a bound of Limits is exceeded. Never a partial result;
	// never a proof that no path exists.
	ErrGraphTooLarge = errors.New("reach: graph too large for the limits")
	// ErrInvalidModel: a rule, a node or a limit outside the domain of D1.
	ErrInvalidModel = errors.New("reach: invalid model")
)
