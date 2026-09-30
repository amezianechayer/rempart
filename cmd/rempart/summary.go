package main

import (
	"bytes"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/amezianechayer/rempart/internal/design/cidr"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	intentdomain "github.com/amezianechayer/rempart/internal/intent/domain"
)

// summary renders the readable output: facts only (closed values or values
// constrained by a pattern), never a free text, so no terminal escape sequence
// of the IR reaches the terminal.
func summary(ir intentdomain.IR, g graphdomain.Graph, plan cidr.Plan) ([]byte, error) {
	var buf bytes.Buffer
	env := ir.Environment
	if env == "" {
		env = "dev"
	}
	reserved := "none: declare on-premise and existing ranges with --reserve"
	if len(plan.External) > 0 {
		parts := make([]string, 0, len(plan.External))
		for _, p := range plan.External {
			parts = append(parts, p.String())
		}
		reserved = strings.Join(parts, ", ")
	}
	kv := func(k, v string) { _, _ = fmt.Fprintf(&buf, "%-13s%s\n", k, v) }
	buf.WriteString("rempart design: deterministic plan, no LLM\n")
	kv("tenant", g.TenantID)
	kv("environment", env)
	kv("superblock", fmt.Sprintf("%s (growth x%d)", plan.Superblock, plan.Growth))
	kv("reserved", reserved)
	buf.WriteString("\n")

	nw := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(nw, "NETWORK\tCIDR\tTIER\tHOSTS  USABLE")
	subnetTier := map[string]string{}
	for _, n := range plan.Networks {
		if n.Parent == "" {
			_, _ = fmt.Fprintf(nw, "%s\t%s\tvpc\t%5s  %6s\n", n.Name, n.Prefix, "-", "-")
			continue
		}
		subnetTier[n.Name] = string(n.Tier)
		_, _ = fmt.Fprintf(nw, "%s\t%s\t%s\t%5d  %6d\n", n.Name, n.Prefix, n.Tier, n.Hosts, 1<<(32-n.Prefix.Bits())-cidr.ReservedPerSubnet)
	}
	if err := nw.Flush(); err != nil {
		return nil, err
	}
	buf.WriteString("\n")

	placement := map[string]string{}
	for _, e := range g.Edges {
		if e.Type != graphdomain.EdgeMemberOf || !strings.HasPrefix(e.Src, "wl:") {
			continue
		}
		src := strings.TrimPrefix(e.Src, "wl:")
		switch {
		case strings.HasPrefix(e.Dst, "net:"):
			placement[src] = strings.TrimPrefix(e.Dst, "net:")
		case strings.HasPrefix(e.Dst, "wl:"):
			placement[src] = "runs on " + strings.TrimPrefix(e.Dst, "wl:")
		}
	}
	ww := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(ww, "WORKLOAD\tKIND\tPLACEMENT")
	wls := slices.Clone(ir.Workloads)
	slices.SortFunc(wls, func(a, b intentdomain.Workload) int { return strings.Compare(a.ID, b.ID) })
	for _, w := range wls {
		p, ok := placement[w.ID]
		if !ok {
			p = "no network"
		}
		_, _ = fmt.Fprintf(ww, "%s\t%s\t%s\n", w.ID, w.Kind, p)
	}
	if err := ww.Flush(); err != nil {
		return nil, err
	}
	buf.WriteString("\n")

	for _, e := range g.Edges {
		if e.Type != graphdomain.EdgeExposes {
			continue
		}
		for _, r := range g.Edges {
			if r.Type == graphdomain.EdgeCanReach && r.Src == e.Src {
				kv("exposure", fmt.Sprintf("internet -> %s %s -> %s", e.Src, proto(e.Attrs), strings.TrimPrefix(r.Dst, "wl:")))
			}
		}
	}
	for _, e := range g.Edges {
		if e.Type == graphdomain.EdgeCanReach && strings.HasPrefix(e.Src, "wl:") && e.Attrs.Via != nil {
			kv("flow", fmt.Sprintf("%s -> %s %s via %s", strings.TrimPrefix(e.Src, "wl:"), strings.TrimPrefix(e.Dst, "wl:"), proto(e.Attrs), *e.Attrs.Via))
		}
	}
	for _, d := range ir.Data {
		hosts := slices.Compact(slices.Sorted(slices.Values(d.StoredIn)))
		parts := make([]string, 0, len(hosts))
		for _, h := range hosts {
			tier := subnetTier[placement[h]]
			if tier == "" {
				tier = "none"
			}
			parts = append(parts, fmt.Sprintf("%s (tier %s)", h, tier))
		}
		kv("data", fmt.Sprintf("%s %s on %s", d.ID, d.Classification, strings.Join(parts, ", ")))
	}
	kv("graph", fmt.Sprintf("%d nodes, %d edges", len(g.Nodes), len(g.Edges)))
	kv("cidr check", strconv.Itoa(len(cidr.Check(plan)))+" findings")
	return buf.Bytes(), nil
}

func proto(a graphdomain.EdgeAttrs) string {
	if a.Protocol == nil || a.PortFrom == nil || a.PortTo == nil {
		return "-"
	}
	if *a.PortFrom == *a.PortTo {
		return fmt.Sprintf("%s/%d", *a.Protocol, *a.PortFrom)
	}
	return fmt.Sprintf("%s/%d-%d", *a.Protocol, *a.PortFrom, *a.PortTo)
}
