package cidr

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"

	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
)

// MaxReferenceBytes bounds the input of CheckReference.
const MaxReferenceBytes = 1 << 20

// ErrReferenceInvalid: the input is not a document of the cidr_check.py format.
var ErrReferenceInvalid = errors.New("cidr: invalid reference document")

type refNetwork struct {
	Name   string `json:"name"`
	CIDR   string `json:"cidr"`
	Parent string `json:"parent,omitempty"`
}

type refExternal struct {
	Name string `json:"name"`
	CIDR string `json:"cidr"`
}

type refDocument struct {
	Superblock string        `json:"superblock"`
	Networks   []refNetwork  `json:"networks"`
	External   []refExternal `json:"external"`
}

// ReferenceJSON renders p in the input format of cidr_check.py: no "parent" key
// for a VPC, reserved ranges named "reserved-1", "reserved-2", ... in the order
// of p.External.
func ReferenceJSON(p Plan) ([]byte, error) {
	doc := refDocument{Superblock: p.Superblock.String(), Networks: []refNetwork{}, External: []refExternal{}}
	for _, n := range p.Networks {
		doc.Networks = append(doc.Networks, refNetwork{Name: n.Name, CIDR: n.Prefix.String(), Parent: n.Parent})
	}
	for i, e := range p.External {
		doc.External = append(doc.External, refExternal{Name: "reserved-" + strconv.Itoa(i+1), CIDR: e.String()})
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// Input of CheckReference: pointers tell a missing key from an empty value.
type refInNetwork struct {
	Name   *string `json:"name"`
	CIDR   *string `json:"cidr"`
	Parent *string `json:"parent"`
}

type refInExternal struct {
	Name *string `json:"name"`
	CIDR *string `json:"cidr"`
}

type refInDocument struct {
	Superblock *string         `json:"superblock"`
	Networks   []refInNetwork  `json:"networks"`
	External   []refInExternal `json:"external"`
}

func parseRef(s *string) (netip.Prefix, bool) {
	if s == nil {
		return netip.Prefix{}, false
	}
	p, err := netip.ParsePrefix(*s)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p, checkValid(p)
}

func nameOr(s *string) string {
	if s == nil {
		return "?"
	}
	return *s
}

// CheckReference decodes a document of the cidr_check.py format (at most
// MaxReferenceBytes, unknown keys refused) and applies the rules of Check,
// with the names of the document. A CIDR that does not parse, is not IPv4 or
// has host bits set gives CIDR_INVALID.
func CheckReference(raw []byte) ([]loopsdomain.Finding, error) {
	if len(raw) > MaxReferenceBytes {
		return nil, fmt.Errorf("%w: too large", ErrReferenceInvalid)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc refInDocument
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: decoding", ErrReferenceInvalid)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing data", ErrReferenceInvalid)
	}
	sbText := "10.0.0.0/8"
	if doc.Superblock != nil {
		sbText = *doc.Superblock
	}
	sb, sbValid := parseRef(&sbText)
	nets := make([]checkNet, 0, len(doc.Networks))
	for _, n := range doc.Networks {
		p, ok := parseRef(n.CIDR)
		ok = ok && n.Name != nil
		cn := checkNet{name: nameOr(n.Name), prefix: p, valid: ok}
		if n.Parent != nil {
			cn.parent, cn.hasParent = *n.Parent, true
		}
		nets = append(nets, cn)
	}
	exts := make([]checkExt, 0, len(doc.External))
	for _, e := range doc.External {
		p, ok := parseRef(e.CIDR)
		exts = append(exts, checkExt{name: nameOr(e.Name), prefix: p, valid: ok && e.Name != nil})
	}
	return check(sb, sbValid, nets, exts), nil
}
