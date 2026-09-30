package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"

	"github.com/amezianechayer/rempart/internal/design"
	"github.com/amezianechayer/rempart/internal/design/cidr"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	"github.com/amezianechayer/rempart/internal/intent"
	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
)

const designPrefix = "rempart design: "

// Fixed messages: they never quote the file or its content.
const (
	msgRead    = "cannot read the IR file (missing, not a regular file or larger than 1 MiB)"
	msgIR      = "invalid IR"
	msgRefused = "design refused"
	msgRequest = "invalid CIDR request (superblock, reserved ranges, growth or needs)"
	msgFull    = "superblock exhausted"
	msgOutput  = "cannot encode the output"
)

var errFileRead = errors.New("rempart: cannot read file")

type prefixList []netip.Prefix

func (l *prefixList) String() string { return fmt.Sprint(*l) }

func (l *prefixList) Set(s string) error {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return errors.New("invalid CIDR")
	}
	*l = append(*l, p)
	return nil
}

func fail(stderr io.Writer, code int, msg string) int {
	_, _ = fmt.Fprintln(stderr, designPrefix+msg)
	return code
}

func runDesign(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("design", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	asJSON := fs.Bool("json", false, "JSON output")
	cidrOnly := fs.Bool("cidr-only", false, "CIDR plan in the cidr_check.py format")
	superblock := fs.String("superblock", "", "superblock (default 10.0.0.0/8)")
	growth := fs.Int("growth", 0, "growth factor (default 4)")
	var reserved prefixList
	fs.Var(&reserved, "reserve", "reserved range, repeatable")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 || (*asJSON && *cidrOnly) {
		return fail(stderr, exitUsage, usage)
	}
	opts := design.Options{Reserved: reserved, Growth: *growth}
	if *superblock != "" {
		p, err := netip.ParsePrefix(*superblock)
		if err != nil {
			return fail(stderr, exitUsage, usage)
		}
		opts.Superblock = p
	}

	raw, err := readIR(fs.Arg(0))
	if err != nil {
		return fail(stderr, exitRefused, msgRead)
	}
	ir, err := intent.ParseIR(raw)
	if err != nil {
		return fail(stderr, exitRefused, msgIR)
	}
	g, plan, err := design.Build(ir, opts)
	switch {
	case errors.Is(err, intent.ErrIRInvalid):
		return fail(stderr, exitRefused, msgIR)
	case errors.Is(err, cidr.ErrInvalidRequest):
		return fail(stderr, exitRefused, msgRequest)
	case errors.Is(err, cidr.ErrExhausted):
		return fail(stderr, exitRefused, msgFull)
	case err != nil:
		return fail(stderr, exitRefused, msgRefused)
	}

	var out []byte
	switch {
	case *cidrOnly:
		out, err = cidr.ReferenceJSON(plan)
	case *asJSON:
		out, err = designJSON(g, plan)
	default:
		out, err = summary(ir, g, plan)
	}
	if err != nil {
		return fail(stderr, exitRefused, msgOutput)
	}
	if _, err := stdout.Write(out); err != nil {
		return exitRefused
	}
	return exitOK
}

// readIR reads a regular file of at most intent.MaxIRBytes.
func readIR(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the user names the IR file on the command line; regular file only, bounded read.
	if err != nil {
		return nil, errFileRead
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > intent.MaxIRBytes {
		return nil, errFileRead
	}
	raw, err := io.ReadAll(io.LimitReader(f, intent.MaxIRBytes+1))
	if err != nil || len(raw) > intent.MaxIRBytes {
		return nil, errFileRead
	}
	return raw, nil
}

type jsonNetwork struct {
	Name   string `json:"name"`
	CIDR   string `json:"cidr"`
	Parent string `json:"parent,omitempty"`
	Tier   string `json:"tier,omitempty"`
	Hosts  int    `json:"hosts"`
	Usable int    `json:"usable"`
}

type jsonExternal struct {
	Name string `json:"name"`
	CIDR string `json:"cidr"`
}

type jsonPlan struct {
	Superblock string         `json:"superblock"`
	Growth     int            `json:"growth"`
	Networks   []jsonNetwork  `json:"networks"`
	External   []jsonExternal `json:"external"`
}

type jsonDesign struct {
	Version      string                `json:"version"`
	Graph        graphdomain.Graph     `json:"graph"`
	CIDRPlan     jsonPlan              `json:"cidr_plan"`
	CIDRFindings []loopsdomain.Finding `json:"cidr_findings"`
}

func usable(p netip.Prefix) int { return 1<<(32-p.Bits()) - cidr.ReservedPerSubnet }

func designJSON(g graphdomain.Graph, plan cidr.Plan) ([]byte, error) {
	d := jsonDesign{
		Version: "1", Graph: g,
		CIDRPlan: jsonPlan{
			Superblock: plan.Superblock.String(), Growth: plan.Growth,
			Networks: []jsonNetwork{}, External: []jsonExternal{},
		},
		CIDRFindings: append([]loopsdomain.Finding{}, cidr.Check(plan)...),
	}
	for _, n := range plan.Networks {
		d.CIDRPlan.Networks = append(d.CIDRPlan.Networks, jsonNetwork{
			Name: n.Name, CIDR: n.Prefix.String(), Parent: n.Parent, Tier: string(n.Tier), Hosts: n.Hosts, Usable: usable(n.Prefix),
		})
	}
	for i, e := range plan.External {
		d.CIDRPlan.External = append(d.CIDRPlan.External, jsonExternal{Name: fmt.Sprintf("reserved-%d", i+1), CIDR: e.String()})
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(d); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
