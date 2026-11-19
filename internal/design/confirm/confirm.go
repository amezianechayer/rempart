// Package confirm is the human confirmation at the entry of L2 (ADR 0012 D3):
// the digest of a subject (IR or candidate graph) shows every exposure, as the
// hops from the Internet computed by reach, its overrides escaped and its
// sensitive data; a confirmation names the exact document and the exposure
// keys a human accepted. The confirming identity is declared, never
// authenticated before M4 (T107).
package confirm

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf16"

	"github.com/amezianechayer/rempart/internal/design"
	"github.com/amezianechayer/rempart/internal/graph"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	"github.com/amezianechayer/rempart/internal/graph/reach"
	intentdomain "github.com/amezianechayer/rempart/internal/intent/domain"
)

// Subjects of a digest and of a confirmation.
const (
	SubjectIR    = "ir"
	SubjectGraph = "graph"
)

// Errors. Fixed messages: never a value of the subject or of the confirmation.
var (
	ErrNotConfirmed = errors.New("confirm: confirmation of another subject, document or exposure")
	ErrDigest       = errors.New("confirm: cannot compute the digest of the subject")
)

var confirmedByRe = regexp.MustCompile(`^[a-z0-9._@-]{1,64}$`)

// ExposureKey is the projection of one hop from the Internet: its target,
// protocol, ports, and its sources, empty if and only if World (the whole
// Internet).
type ExposureKey struct {
	Target  string        `json:"target"`
	Proto   reach.Proto   `json:"proto"`
	Ports   reach.PortSet `json:"ports"`
	World   bool          `json:"world"`
	Sources []string      `json:"sources"`
}

// Confirmation is declared by a human: the subject, the SHA-256 of its exact
// document and the keys accepted. ConfirmedBy is never read by a decision.
type Confirmation struct {
	Subject       string        `json:"subject"`
	SubjectSHA256 string        `json:"subject_sha256"`
	Exposures     []ExposureKey `json:"exposures"`
	ConfirmedBy   string        `json:"confirmed_by"`
}

// Placement is where a host of sensitive data runs.
type Placement struct {
	Host   string `json:"host"`
	Cloud  string `json:"cloud"`
	Region string `json:"region"`
}

// SensitiveData is a confidential, regulated or unclassified data store and
// its hosts.
type SensitiveData struct {
	Data           string      `json:"data"`
	Classification string      `json:"classification"`
	Hosts          []Placement `json:"hosts"`
}

// Digest is what a human reads before confirming: no list written null,
// overrides escaped by Escape.
type Digest struct {
	Subject       string          `json:"subject"`
	SubjectSHA256 string          `json:"subject_sha256"`
	Exposures     []ExposureKey   `json:"exposures"`
	Overrides     []string        `json:"overrides"`
	Sensitive     []SensitiveData `json:"sensitive"`
}

// DigestOfIR builds the IR with the default options of L2 and digests it.
func DigestOfIR(ir intentdomain.IR) (Digest, error) {
	g, _, err := design.Build(ir, design.Options{})
	if err != nil {
		return Digest{}, err
	}
	overrides := make([]string, 0, len(ir.ExplicitOverrides))
	for _, o := range ir.ExplicitOverrides {
		overrides = append(overrides, Escape(o.Statement))
	}
	return digestOf(SubjectIR, ir, g, overrides)
}

// DigestOfGraph digests a candidate graph, valid against its schema.
func DigestOfGraph(g graphdomain.Graph) (Digest, error) {
	if err := graph.ValidateSchema(g); err != nil {
		return Digest{}, ErrDigest
	}
	return digestOf(SubjectGraph, g, g, []string{})
}

// SubjectSHA256 is the SHA-256 of the netstring of the subject followed by the
// JSON of its document (ADR 0012 D3): free text and overrides included.
func SubjectSHA256(subject string, doc any) (string, error) {
	raw, err := json.Marshal(doc)
	if err != nil {
		return "", ErrDigest
	}
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%d:%s,", len(subject), subject)
	_, _ = h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func digestOf(subject string, doc any, g graphdomain.Graph, overrides []string) (Digest, error) {
	sum, err := SubjectSHA256(subject, doc)
	if err != nil {
		return Digest{}, err
	}
	f := graphdomain.FactsOf(g)
	m, err := reach.FromGraph(f)
	if err != nil {
		return Digest{}, ErrDigest
	}
	r, err := reach.Compute(m, reach.DefaultLimits)
	if err != nil {
		return Digest{}, err
	}
	return Digest{Subject: subject, SubjectSHA256: sum, Exposures: KeysOf(r), Overrides: overrides, Sensitive: sensitive(f)}, nil
}

// KeysOf projects the hops from the Internet of r, in the order of r.
func KeysOf(r reach.Result) []ExposureKey {
	keys := []ExposureKey{}
	for _, h := range r.Hops {
		if h.Src != reach.Internet {
			continue
		}
		k := ExposureKey{Target: h.Dst, Proto: h.Proto, Ports: slices.Clone(h.Ports), World: h.World, Sources: []string{}}
		if !h.World {
			for _, p := range h.Sources {
				k.Sources = append(k.Sources, p.String())
			}
		}
		keys = append(keys, k)
	}
	return keys
}

func sensitive(f graphdomain.FactsGraph) []SensitiveData {
	nodes := make(map[string]graphdomain.FactNode, len(f.Nodes))
	for _, n := range f.Nodes {
		nodes[n.ID] = n
	}
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	out := []SensitiveData{}
	for _, n := range f.Nodes {
		c := n.Attrs.Classification
		if n.Kind != graphdomain.KindDataStore || (c != nil && (*c == "public" || *c == "internal")) {
			continue
		}
		d := SensitiveData{Data: n.ID, Classification: cmp.Or(str(c), "absent"), Hosts: []Placement{}}
		for _, e := range f.Edges {
			if e.Type == graphdomain.EdgeStores && e.Dst == n.ID {
				h := nodes[e.Src]
				d.Hosts = append(d.Hosts, Placement{Host: e.Src, Cloud: str(h.Attrs.Cloud), Region: str(h.Attrs.Region)})
			}
		}
		if len(d.Hosts) == 0 && n.Attrs.Cloud != nil {
			d.Hosts = append(d.Hosts, Placement{Host: n.ID, Cloud: str(n.Attrs.Cloud), Region: str(n.Attrs.Region)})
		}
		slices.SortFunc(d.Hosts, func(a, b Placement) int { return strings.Compare(a.Host, b.Host) })
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b SensitiveData) int { return strings.Compare(a.Data, b.Data) })
	return out
}

// canon is the comparison form of a key: an absent source list is empty.
func canon(k ExposureKey) string {
	if k.Sources == nil {
		k.Sources = []string{}
	}
	raw, err := json.Marshal(k)
	if err != nil {
		return ""
	}
	return string(raw)
}

// Check refuses a confirmation of another subject or document, a key that is
// not a key of the subject (forged, ports or sources changed), a key named
// twice or a confirming identity outside its grammar. It returns the keys of
// the subject left unconfirmed: a fact for the verifier, never a refusal.
func Check(d Digest, c Confirmation) ([]ExposureKey, error) {
	if c.Subject != d.Subject || c.SubjectSHA256 != d.SubjectSHA256 || len(d.SubjectSHA256) != 64 || !confirmedByRe.MatchString(c.ConfirmedBy) {
		return nil, ErrNotConfirmed
	}
	subject := make(map[string]bool, len(d.Exposures))
	for _, k := range d.Exposures {
		subject[canon(k)] = true
	}
	seen := make(map[string]bool, len(c.Exposures))
	for _, k := range c.Exposures {
		s := canon(k)
		if s == "" || seen[s] || !subject[s] {
			return nil, ErrNotConfirmed
		}
		seen[s] = true
	}
	unconfirmed := []ExposureKey{}
	for _, k := range d.Exposures {
		if !seen[canon(k)] {
			unconfirmed = append(unconfirmed, k)
		}
	}
	return unconfirmed, nil
}

// Uncovered returns the hops from the Internet of hops that the union of the
// confirmed keys does not cover, port by port and address by address
// (reach.Result.SubsetOf), sorted by target then protocol; never nil. A key
// with an unreadable source covers nothing.
func Uncovered(hops []reach.Hop, confirmed []ExposureKey) []reach.Hop {
	var allowed []reach.Hop
	for _, k := range confirmed {
		h := reach.Hop{Src: reach.Internet, Dst: k.Target, Proto: k.Proto, Ports: k.Ports, World: k.World}
		ok := k.World == (len(k.Sources) == 0)
		for _, s := range k.Sources {
			p, err := netip.ParsePrefix(s)
			ok = ok && err == nil
			h.Sources = append(h.Sources, p)
		}
		if ok {
			allowed = append(allowed, h)
		}
	}
	out := []reach.Hop{}
	for _, h := range hops {
		if h.Src == reach.Internet && !(reach.Result{Hops: []reach.Hop{h}}).SubsetOf(reach.Result{Hops: allowed}) {
			out = append(out, h)
		}
	}
	slices.SortStableFunc(out, func(a, b reach.Hop) int {
		return cmp.Or(strings.Compare(a.Dst, b.Dst), strings.Compare(string(a.Proto), string(b.Proto)))
	})
	return out
}

// Escape writes as \uXXXX (UTF-16, surrogate pairs beyond the basic plane)
// every control (Cc: C0 and C1, CSI U+009B included), every format character
// (Cf: bidirectional overrides and isolates, zero width), the line and
// paragraph separators, and the backslash itself, so an escaped text never
// reads as another one (obligation (co), T121).
func Escape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r != '\\' && r != '\u2028' && r != '\u2029' && !unicode.Is(unicode.Cc, r) && !unicode.Is(unicode.Cf, r) {
			b.WriteRune(r)
			continue
		}
		if r > 0xFFFF {
			r1, r2 := utf16.EncodeRune(r)
			_, _ = fmt.Fprintf(&b, `\u%04x\u%04x`, r1, r2)
			continue
		}
		_, _ = fmt.Fprintf(&b, `\u%04x`, r)
	}
	return b.String()
}
