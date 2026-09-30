package design

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/amezianechayer/rempart/internal/design/cidr"
	"github.com/amezianechayer/rempart/internal/graph"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	"github.com/amezianechayer/rempart/internal/intent"
	intentdomain "github.com/amezianechayer/rempart/internal/intent/domain"
)

// Options are the technical choices of Build, never taken from the IR.
type Options struct {
	Superblock netip.Prefix // zero: 10.0.0.0/8
	Reserved   []netip.Prefix
	Growth     int // 0: 4
}

// ErrDesignRefused wraps a cause with a fixed message.
var ErrDesignRefused = errors.New("design: refused")

func refused(reason string) error { return fmt.Errorf("%w: %s", ErrDesignRefused, reason) }

const internetID = "internet"

func ptr[T any](v T) *T { return &v }

// wl is one workload of the IR with its placement.
type wl struct {
	w      intentdomain.Workload
	p      placement
	vpc    string // "" without subnet
	subnet string // "" without subnet
	tier   cidr.Tier
}

type needKey struct{ cloud, region, env string }

// Build turns a validated IR into a graph and a CIDR plan: ValidateIR, needs by
// the table of plan section 6.2, cidr.Allocate, cidr.Check (empty required),
// graph, graph.ValidateSchema. No model, no input or output, no global state.
func Build(ir intentdomain.IR, o Options) (graphdomain.Graph, cidr.Plan, error) {
	if err := intent.ValidateIR(ir); err != nil {
		return graphdomain.Graph{}, cidr.Plan{}, err
	}
	env := ir.Environment
	if env == "" {
		env = "dev"
	}
	sb := o.Superblock
	if !sb.IsValid() {
		sb = netip.PrefixFrom(netip.AddrFrom4([4]byte{10}), 8)
	}

	// Hosts of sensitive data (plan P8).
	sensitive := map[string]bool{}
	for _, d := range ir.Data {
		if d.Classification != "public" {
			for _, h := range d.StoredIn {
				sensitive[h] = true
			}
		}
	}
	wls := map[string]*wl{}
	var order []string
	for _, w := range ir.Workloads {
		if _, dup := wls[w.ID]; dup {
			return fail(refused("duplicate workload id"))
		}
		p, ok := place(w, sensitive[w.ID])
		if !ok {
			return fail(refused("unknown workload kind"))
		}
		wls[w.ID] = &wl{w: w, p: p, tier: p.tier}
		order = append(order, w.ID)
	}
	slices.Sort(order)
	// References and K8s workloads.
	for _, id := range order {
		x := wls[id]
		if x.p.onK8s {
			c, ok := wls[*x.w.RunsOn]
			if !ok || c.w.Kind != "k8s_cluster" {
				return fail(refused("runs_on is not a k8s_cluster of the IR"))
			}
		}
	}
	for _, d := range ir.Data {
		for _, h := range d.StoredIn {
			if _, ok := wls[h]; !ok {
				return fail(refused("stored_in names an unknown workload"))
			}
		}
	}

	needs := map[needKey]map[cidr.Tier]int{}
	addNeed := func(w intentdomain.Workload, t cidr.Tier, hosts int) string {
		k := needKey{w.Cloud, w.Region, env}
		if needs[k] == nil {
			needs[k] = map[cidr.Tier]int{}
		}
		needs[k][t] += hosts
		return w.Cloud + "-" + w.Region + "-" + env
	}
	for _, id := range order {
		x := wls[id]
		if x.p.tier != "" {
			x.vpc = addNeed(x.w, x.p.tier, x.p.hosts)
			x.subnet = x.vpc + "-" + string(x.p.tier)
		}
	}
	for _, id := range order {
		x := wls[id]
		if x.p.onK8s {
			c := wls[*x.w.RunsOn]
			x.vpc, x.subnet, x.tier = c.vpc, c.subnet, c.tier
		}
	}

	// Exposures.
	type exposure struct {
		e        intentdomain.Exposure
		target   *wl
		port     int
		lbID     string
		lbSubnet string
		sources  []string
	}
	var exps []exposure
	lbIDs := map[string]bool{}
	for _, e := range ir.Exposure {
		x, ok := wls[e.Workload]
		if !ok {
			return fail(refused("exposure names an unknown workload"))
		}
		if x.subnet == "" || x.tier == cidr.TierData {
			return fail(refused("exposure of a data tier workload or of object storage"))
		}
		var port int
		switch {
		case e.Port != nil:
			port = *e.Port
		case e.Protocol == "https":
			port = 443
		case e.Protocol == "http":
			port = 80
		default:
			return fail(refused("tcp or udp exposure without port"))
		}
		var sources []string
		for _, s := range e.AllowedSources {
			p, err := netip.ParsePrefix(s)
			if err != nil || !p.Addr().Is4() || p != p.Masked() {
				return fail(refused("allowed source is not a canonical IPv4 CIDR"))
			}
			sources = append(sources, p.String())
		}
		ex := exposure{e: e, target: x, port: port, lbID: "lb:" + x.w.ID + "-" + strconv.Itoa(port), sources: sources}
		if lbIDs[ex.lbID] {
			return fail(refused("duplicate exposure"))
		}
		lbIDs[ex.lbID] = true
		host := x.w
		if x.p.onK8s {
			host = wls[*x.w.RunsOn].w
		}
		ex.lbSubnet = addNeed(host, cidr.TierPublic, lbHosts) + "-" + string(cidr.TierPublic)
		exps = append(exps, ex)
	}

	// CIDR plan.
	keys := make([]needKey, 0, len(needs))
	for k := range needs {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b needKey) int {
		return cmp.Or(cmp.Compare(a.cloud, b.cloud), cmp.Compare(a.region, b.region), cmp.Compare(a.env, b.env))
	})
	req := cidr.Request{Superblock: sb, Reserved: o.Reserved, Growth: o.Growth}
	vpcOf := map[string]needKey{}
	for _, k := range keys {
		n := cidr.Need{Cloud: k.cloud, Region: k.region, Env: k.env}
		for _, t := range []cidr.Tier{cidr.TierPublic, cidr.TierApp, cidr.TierData, cidr.TierMgmt} {
			if h, ok := needs[k][t]; ok {
				n.Tiers = append(n.Tiers, cidr.TierNeed{Tier: t, Hosts: h})
			}
		}
		req.Needs = append(req.Needs, n)
		vpcOf[k.cloud+"-"+k.region+"-"+k.env] = k
	}
	plan, err := cidr.Allocate(req)
	if err != nil {
		return fail(err)
	}
	if f := cidr.Check(plan); len(f) != 0 {
		return fail(refused("CIDR plan rejected by the verifier"))
	}

	g := graphdomain.Graph{
		Version: graphdomain.GraphVersion, TenantID: ir.TenantID, Source: graphdomain.SourceDesign,
		Nodes: []graphdomain.Node{{ID: internetID, Kind: graphdomain.KindInternet}},
		Edges: []graphdomain.Edge{},
	}
	if ir.Summary != "" {
		g.Text.Summary = ptr(graphdomain.NewFreeText(ir.Summary))
	}
	addEdge := func(t graphdomain.EdgeType, src, dst string, a graphdomain.EdgeAttrs, text graphdomain.EdgeText) {
		id := strings.ToLower(string(t)) + "|" + src + "|" + dst
		if a.Protocol != nil && a.PortFrom != nil {
			id += "|" + *a.Protocol + "/" + portRange(*a.PortFrom, *a.PortTo)
		}
		g.Edges = append(g.Edges, graphdomain.Edge{ID: id, Type: t, Src: src, Dst: dst, Attrs: a, Text: text})
	}

	for _, n := range plan.Networks {
		vpcName := n.Name
		if n.Parent != "" {
			vpcName = n.Parent
		}
		k := vpcOf[vpcName]
		a := graphdomain.NodeAttrs{Cloud: ptr(k.cloud), Region: ptr(k.region), Env: ptr(k.env), CIDR: ptr(n.Prefix.String()), Subtype: ptr("vpc")}
		if n.Parent != "" {
			a.Subtype, a.Tier = ptr("subnet"), ptr(string(n.Tier))
			addEdge(graphdomain.EdgeMemberOf, "net:"+n.Name, "net:"+n.Parent, graphdomain.EdgeAttrs{}, graphdomain.EdgeText{})
		}
		g.Nodes = append(g.Nodes, graphdomain.Node{ID: "net:" + n.Name, Kind: graphdomain.KindNetwork, Attrs: a})
	}

	dataClass := map[string]string{}
	for _, d := range ir.Data {
		for _, h := range d.StoredIn {
			if classRank(d.Classification) > classRank(dataClass[h]) {
				dataClass[h] = d.Classification
			}
		}
	}
	for _, id := range order {
		x := wls[id]
		node := graphdomain.Node{ID: "wl:" + id, Kind: x.p.kind}
		if x.w.Notes != nil {
			node.Text.Notes = ptr(graphdomain.NewFreeText(*x.w.Notes))
		}
		a := graphdomain.NodeAttrs{Cloud: ptr(x.w.Cloud), Region: ptr(x.w.Region)}
		switch x.p.kind {
		case graphdomain.KindK8sCluster:
			a.Count, a.APIPublic = ptr(count(x.w, defaultK8sNodes)), ptr(false)
		case graphdomain.KindCompute:
			a.Subtype, a.Count = ptr(x.p.subtype), ptr(count(x.w, defaultVMs))
			if x.w.Size != nil && x.w.Size.OS != nil {
				a.OS = ptr(*x.w.Size.OS)
			}
		case graphdomain.KindDataStore:
			class := cmp.Or(dataClass[id], "internal")
			a.Subtype, a.Classification, a.Encrypted, a.PublicAccess = ptr(x.p.subtype), ptr(class), ptr(true), ptr(false)
		case graphdomain.KindLoadBalancer:
			a.Public, a.Listeners = ptr(false), &[]graphdomain.Listener{}
		}
		node.Attrs = a
		g.Nodes = append(g.Nodes, node)
		switch {
		case x.p.onK8s:
			addEdge(graphdomain.EdgeMemberOf, "wl:"+id, "wl:"+*x.w.RunsOn, graphdomain.EdgeAttrs{}, graphdomain.EdgeText{})
		case x.subnet != "":
			addEdge(graphdomain.EdgeMemberOf, "wl:"+id, "net:"+x.subnet, graphdomain.EdgeAttrs{}, graphdomain.EdgeText{})
		}
	}

	for _, d := range ir.Data {
		a := graphdomain.NodeAttrs{
			Subtype: ptr("dataset"), Classification: ptr(d.Classification),
			Encrypted: ptr(true), PublicAccess: ptr(false), Regulation: slices.Clone(d.Regulation),
		}
		if d.Residency != nil {
			a.Residency = ptr(*d.Residency)
		}
		g.Nodes = append(g.Nodes, graphdomain.Node{ID: "data:" + d.ID, Kind: graphdomain.KindDataStore, Attrs: a})
		for _, h := range slices.Compact(slices.Sorted(slices.Values(d.StoredIn))) {
			addEdge(graphdomain.EdgeStores, "wl:"+h, "data:"+d.ID, graphdomain.EdgeAttrs{}, graphdomain.EdgeText{})
		}
	}

	for _, ex := range exps {
		just := ptr(graphdomain.NewFreeText(ex.e.Justification))
		host := ex.target.w
		lb := graphdomain.NodeAttrs{
			Cloud: ptr(host.Cloud), Region: ptr(host.Region), Public: ptr(true),
			Listeners: &[]graphdomain.Listener{{Protocol: ex.e.Protocol, Port: ex.port}},
			Behind:    slices.Clone(ex.e.Behind),
		}
		g.Nodes = append(g.Nodes, graphdomain.Node{ID: ex.lbID, Kind: graphdomain.KindLoadBalancer, Attrs: lb, Text: graphdomain.NodeText{Justification: just}})
		addEdge(graphdomain.EdgeMemberOf, ex.lbID, "net:"+ex.lbSubnet, graphdomain.EdgeAttrs{}, graphdomain.EdgeText{})
		addEdge(graphdomain.EdgeExposes, ex.lbID, internetID, graphdomain.EdgeAttrs{
			Protocol: ptr(ex.e.Protocol), PortFrom: ptr(ex.port), PortTo: ptr(ex.port), AllowedSources: ex.sources,
		}, graphdomain.EdgeText{Justification: just})
		addEdge(graphdomain.EdgeCanReach, ex.lbID, "wl:"+ex.target.w.ID, graphdomain.EdgeAttrs{
			Protocol: ptr(ex.e.Protocol), PortFrom: ptr(ex.port), PortTo: ptr(ex.port), Via: ptr("load_balancer"),
			Path: compactPath("net:"+ex.lbSubnet, "net:"+ex.target.subnet),
		}, graphdomain.EdgeText{})
	}

	for _, l := range ir.Connectivity {
		from, okF := wls[l.From]
		to, okT := wls[l.To]
		if !okF || !okT {
			return fail(refused("connectivity names an unknown workload"))
		}
		if from.subnet == "" || to.subnet == "" {
			return fail(refused("connectivity endpoint without network"))
		}
		var text graphdomain.EdgeText
		if l.Purpose != nil {
			text.Purpose = ptr(graphdomain.NewFreeText(*l.Purpose))
		}
		for _, spec := range l.Ports {
			proto, lo, hi, ok := parsePorts(spec)
			if !ok {
				return fail(refused("invalid port"))
			}
			a := graphdomain.EdgeAttrs{
				Protocol: ptr(proto), PortFrom: ptr(lo), PortTo: ptr(hi), Via: ptr(l.Kind),
				Path: compactPath("net:"+from.subnet, "net:"+from.vpc, "net:"+to.vpc, "net:"+to.subnet),
			}
			addEdge(graphdomain.EdgeCanReach, "wl:"+from.w.ID, "wl:"+to.w.ID, a, text)
			if l.Bidirectional != nil && *l.Bidirectional {
				b := a
				b.Path = compactPath("net:"+to.subnet, "net:"+to.vpc, "net:"+from.vpc, "net:"+from.subnet)
				addEdge(graphdomain.EdgeCanReach, "wl:"+to.w.ID, "wl:"+from.w.ID, b, text)
			}
		}
	}

	slices.SortFunc(g.Nodes, func(a, b graphdomain.Node) int { return cmp.Compare(a.ID, b.ID) })
	slices.SortFunc(g.Edges, func(a, b graphdomain.Edge) int {
		return cmp.Or(cmp.Compare(a.Type, b.Type), cmp.Compare(a.Src, b.Src), cmp.Compare(a.Dst, b.Dst),
			cmp.Compare(deref(a.Attrs.Protocol), deref(b.Attrs.Protocol)),
			cmp.Compare(derefInt(a.Attrs.PortFrom), derefInt(b.Attrs.PortFrom)),
			cmp.Compare(derefInt(a.Attrs.PortTo), derefInt(b.Attrs.PortTo)))
	})
	for i := 1; i < len(g.Edges); i++ {
		if g.Edges[i].ID == g.Edges[i-1].ID {
			return fail(refused("duplicate edge"))
		}
	}
	if err := graph.ValidateSchema(g); err != nil {
		return fail(fmt.Errorf("%w: %w", ErrDesignRefused, err))
	}
	return g, plan, nil
}

func fail(err error) (graphdomain.Graph, cidr.Plan, error) {
	return graphdomain.Graph{}, cidr.Plan{}, err
}

func classRank(c string) int {
	return map[string]int{"public": 1, "internal": 2, "confidential": 3, "regulated": 4}[c]
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

func portRange(lo, hi int) string {
	if lo == hi {
		return strconv.Itoa(lo)
	}
	return strconv.Itoa(lo) + "-" + strconv.Itoa(hi)
}

// parsePorts parses "tcp/5432" or "tcp/1000-2000" (pattern of the IR schema).
func parsePorts(spec string) (proto string, lo, hi int, ok bool) {
	proto, rng, found := strings.Cut(spec, "/")
	if !found || (proto != "tcp" && proto != "udp") {
		return "", 0, 0, false
	}
	a, b, isRange := strings.Cut(rng, "-")
	lo, errA := strconv.Atoi(a)
	hi = lo
	var errB error
	if isRange {
		hi, errB = strconv.Atoi(b)
	}
	if errA != nil || errB != nil || lo < 1 || hi > 65535 || lo > hi {
		return "", 0, 0, false
	}
	return proto, lo, hi, true
}

// compactPath drops consecutive duplicates (same VPC or same subnet).
func compactPath(ids ...string) []string { return slices.Compact(ids) }
