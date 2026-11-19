package confirm_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/amezianechayer/rempart/internal/design"
	"github.com/amezianechayer/rempart/internal/design/confirm"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	"github.com/amezianechayer/rempart/internal/graph/reach"
	"github.com/amezianechayer/rempart/internal/intent"
	intentdomain "github.com/amezianechayer/rempart/internal/intent/domain"
)

const referenceIR = "../../intent/testdata/reference-ir.json"

func loadIR(t *testing.T) intentdomain.IR {
	t.Helper()
	raw, err := os.ReadFile(referenceIR)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := intent.ParseIR(raw)
	if err != nil {
		t.Fatal(err)
	}
	return ir
}

func loadGraph(t *testing.T) graphdomain.Graph {
	t.Helper()
	g, _, err := design.Build(loadIR(t), design.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func ptr[T any](v T) *T { return &v }

func setNode(g *graphdomain.Graph, id string, edit func(a *graphdomain.NodeAttrs)) {
	for i := range g.Nodes {
		if g.Nodes[i].ID == id {
			edit(&g.Nodes[i].Attrs)
		}
	}
}

func targets(keys []confirm.ExposureKey) []string {
	var out []string
	for _, k := range keys {
		out = append(out, k.Target)
	}
	return out
}

func confirmAll(d confirm.Digest) confirm.Confirmation {
	return confirm.Confirmation{Subject: d.Subject, SubjectSHA256: d.SubjectSHA256, Exposures: slices.Clone(d.Exposures), ConfirmedBy: "alice@example.org"}
}

// TestL2EveryExposureInDigest proves obligations (cn) and (ev) and ADR 0012
// D3 (T107): the keys of the digest are every hop from the Internet of the
// subject, implicit exposures included (public data store, public address,
// public cluster API with or without sources), a key without source being the
// whole Internet; the confirmation must name keys of the subject and its
// exact document; an unconfirmed key is a fact, not a refusal; the coverage of
// a candidate is judged hop by hop.
func TestL2EveryExposureInDigest(t *testing.T) {
	ir := loadIR(t)
	d, err := confirm.DigestOfIR(ir)
	if err != nil {
		t.Fatal(err)
	}
	want := []confirm.ExposureKey{{Target: "lb:app-cluster-443", Proto: "tcp", Ports: reach.PortSet{{From: 443, To: 443}}, World: true, Sources: []string{}}}
	if d.Subject != confirm.SubjectIR || len(d.SubjectSHA256) != 64 || !keysEqual(d.Exposures, want) {
		t.Fatalf("digest of the reference IR = %+v, want subject ir and keys %+v", d, want)
	}
	if d.Overrides == nil || d.Sensitive == nil {
		t.Errorf("digest lists written null: overrides %v, sensitive %v", d.Overrides, d.Sensitive)
	}
	if len(d.Sensitive) == 0 || d.Sensitive[0].Data == "" || len(d.Sensitive[0].Hosts) == 0 {
		t.Errorf("sensitive data of the reference missing from the digest: %+v", d.Sensitive)
	}

	t.Run("implicit_exposures", func(t *testing.T) {
		g := loadGraph(t)
		setNode(&g, "data:customer-db", func(a *graphdomain.NodeAttrs) { a.PublicAccess = ptr(true) })
		setNode(&g, "wl:legacy-vms", func(a *graphdomain.NodeAttrs) { a.PublicIP = ptr(true) })
		setNode(&g, "wl:app-cluster", func(a *graphdomain.NodeAttrs) {
			a.APIPublic, a.APIAllowedSources = ptr(true), []string{"203.0.113.0/24"}
		})
		gd, err := confirm.DigestOfGraph(g)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"lb:app-cluster-443", "data:customer-db", "wl:legacy-vms", "wl:app-cluster"} {
			if !slices.Contains(targets(gd.Exposures), id) {
				t.Errorf("implicit exposure of %s missing from the digest: %v", id, targets(gd.Exposures))
			}
		}
		for _, k := range gd.Exposures {
			if k.World != (len(k.Sources) == 0) || k.Sources == nil {
				t.Errorf("key %+v: sources empty if and only if the whole Internet, never null", k)
			}
			if k.Target == "wl:app-cluster" && (k.World || !slices.Equal(k.Sources, []string{"203.0.113.0/24"})) {
				t.Errorf("restricted cluster API = %+v, want its source", k)
			}
		}
		if gd.Subject != confirm.SubjectGraph {
			t.Errorf("subject %q, want graph", gd.Subject)
		}
	})

	t.Run("check", func(t *testing.T) {
		c := confirmAll(d)
		if un, err := confirm.Check(d, c); err != nil || un == nil || len(un) != 0 {
			t.Fatalf("Check(all keys) = %v, %v; want an empty, non-nil list", un, err)
		}
		partial := c
		partial.Exposures = []confirm.ExposureKey{}
		if un, err := confirm.Check(d, partial); err != nil || !keysEqual(un, d.Exposures) {
			t.Fatalf("Check(no key) = %v, %v; want every key unconfirmed, no error", un, err)
		}
		forged := func(edit func(c *confirm.Confirmation)) confirm.Confirmation {
			x := confirmAll(d)
			edit(&x)
			return x
		}
		for name, bad := range map[string]confirm.Confirmation{
			"other_subject": forged(func(c *confirm.Confirmation) { c.Subject = confirm.SubjectGraph }),
			"other_digest":  forged(func(c *confirm.Confirmation) { c.SubjectSHA256 = strings.Repeat("0", 64) }),
			"port_changed":  forged(func(c *confirm.Confirmation) { c.Exposures[0].Ports = reach.PortSet{{From: 1, To: 65535}} }),
			"sources_added": forged(func(c *confirm.Confirmation) {
				c.Exposures[0].World, c.Exposures[0].Sources = false, []string{"0.0.0.0/1"}
			}),
			"forged_target": forged(func(c *confirm.Confirmation) { c.Exposures[0].Target = "data:customer-db" }),
			"duplicate":     forged(func(c *confirm.Confirmation) { c.Exposures = append(c.Exposures, c.Exposures[0]) }),
			"confirmed_by":  forged(func(c *confirm.Confirmation) { c.ConfirmedBy = "Alice\u202e" }),
			"no_author":     forged(func(c *confirm.Confirmation) { c.ConfirmedBy = "" }),
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := confirm.Check(d, bad); !errors.Is(err, confirm.ErrNotConfirmed) {
					t.Fatalf("Check = %v, want ErrNotConfirmed", err)
				}
			})
		}
		// The digest covers the whole document: one byte of free text changed
		// after the confirmation is refused.
		ir2 := ir
		ir2.ExplicitOverrides = append(slices.Clone(ir.ExplicitOverrides), intentdomain.Override{Statement: "garder le port 22 ouvert", Affects: "network"})
		d2, err := confirm.DigestOfIR(ir2)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := confirm.Check(d2, c); !errors.Is(err, confirm.ErrNotConfirmed) || d2.SubjectSHA256 == d.SubjectSHA256 {
			t.Fatalf("a changed override kept the confirmation: %v", err)
		}
	})

	t.Run("uncovered", func(t *testing.T) {
		world443 := reach.Hop{Src: reach.Internet, Dst: "lb:app-cluster-443", Proto: "tcp", Ports: reach.PortSet{{From: 443, To: 443}}, World: true}
		office := reach.Hop{Src: reach.Internet, Dst: "lb:app-cluster-443", Proto: "tcp", Ports: reach.PortSet{{From: 443, To: 443}}, Sources: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}
		ssh := reach.Hop{Src: reach.Internet, Dst: "wl:legacy-vms", Proto: "tcp", Ports: reach.PortSet{{From: 22, To: 22}}, World: true}
		wider := reach.Hop{Src: reach.Internet, Dst: "lb:app-cluster-443", Proto: "tcp", Ports: reach.PortSet{{From: 443, To: 444}}, World: true}
		internal := reach.Hop{Src: "lb:app-cluster-443", Dst: "wl:app-cluster", Proto: "tcp", Ports: reach.PortSet{{From: 443, To: 443}}}
		got := confirm.Uncovered([]reach.Hop{world443, office, ssh, wider, internal}, d.Exposures)
		if len(got) != 2 || got[0].Dst != "lb:app-cluster-443" || got[1].Dst != "wl:legacy-vms" {
			t.Fatalf("Uncovered = %+v, want the wider port range and the SSH hop only", got)
		}
		restricted := []confirm.ExposureKey{{Target: "lb:app-cluster-443", Proto: "tcp", Ports: reach.PortSet{{From: 443, To: 443}}, Sources: []string{"203.0.113.0/24"}}}
		if got := confirm.Uncovered([]reach.Hop{world443}, restricted); len(got) != 1 {
			t.Errorf("a hop from the whole Internet covered by a key of one office: %+v", got)
		}
		if got := confirm.Uncovered([]reach.Hop{office}, restricted); got == nil || len(got) != 0 {
			t.Errorf("Uncovered(office, office key) = %#v, want an empty, non-nil list", got)
		}
	})
}

func keysEqual(a, b []confirm.ExposureKey) bool {
	ra, errA := json.Marshal(a)
	rb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ra, rb)
}

// TestDigestEscapesUntrusted proves obligation (co) and ADR 0012 D3 (T2,
// T121): an override that carries a C1 control (U+009B, CSI), a bidirectional
// override (U+202E), a line separator or a backslash reaches the digest
// escaped as \uXXXX, so a terminal or a reviewer never renders it; any other
// text is kept as is.
func TestDigestEscapesUntrusted(t *testing.T) {
	cases := map[string]string{
		"csi \u009b31m":       `csi \u009b31m`,
		"rtl \u202egnp.exe":   `rtl \u202egnp.exe`,
		"line\u2028break":     `line\u2028break`,
		"nul\x00bell\x07":     `nul\u0000bell\u0007`,
		`a\u202e`:             `a\u005cu202e`,
		"tag \U000E0041":      `tag \udb40\udc41`,
		"zero\u200bwidth":     `zero\u200bwidth`,
		"Accès réseau 443":    "Accès réseau 443",
		"plain ascii, 1.2.3.": "plain ascii, 1.2.3.",
	}
	for in, want := range cases {
		if got := confirm.Escape(in); got != want {
			t.Errorf("Escape(%q) = %q, want %q", in, got, want)
		}
	}

	ir := loadIR(t)
	ir.ExplicitOverrides = []intentdomain.Override{{Statement: "exposer \u009b[2J la base \u202e443", Affects: "network"}}
	d, err := confirm.DigestOfIR(ir)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{"\u009b", "\u202e"} {
		if bytes.Contains(raw, []byte(r)) {
			t.Errorf("digest carries %U unescaped: %s", []rune(r)[0], raw)
		}
	}
	if len(d.Overrides) != 1 || d.Overrides[0] != `exposer \u009b[2J la base \u202e443` {
		t.Errorf("overrides of the digest = %q", d.Overrides)
	}
}
