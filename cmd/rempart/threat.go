package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/amezianechayer/rempart/internal/graph"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	"github.com/amezianechayer/rempart/internal/graph/reach"
	"github.com/amezianechayer/rempart/internal/policy"
	"github.com/amezianechayer/rempart/internal/policy/adapters/opa"
	"github.com/amezianechayer/rempart/internal/threat"
)

// Subcommand threat (M2-T04, ADR 0010 D9 to D11):
// rempart threat model <graph.json> writes the STRIDE model of one graph;
// rempart threat diff <before.json> <after.json> writes the delta of two.
// A graph is the "graph" object of rempart design --json, read strictly.

const threatPrefix = "rempart threat: "

const threatUsage = "usage: rempart threat model <graph.json> | rempart threat diff <before.graph.json> <after.graph.json>"

// Fixed messages: never a path, a tenant or a byte of the input.
const (
	msgGraphRead    = "cannot read the graph file (missing, not a regular file or larger than 16 MiB)"
	msgGraphInvalid = "invalid graph (not strict JSON or outside schemas/graph/v1.json)"
	msgGraphLarge   = "graph too large for the bounds of the analysis"
	msgPolicy       = "policy evaluation failed"
	msgAnalysis     = "threat analysis failed"
	msgTenants      = "the two graphs belong to different tenants"
	msgMismatch     = "the two models do not share a catalog and a policy pack"
)

var errGraphInvalid = errors.New("rempart: invalid graph")

func threatFail(stderr io.Writer, code int, msg string) int {
	_, _ = fmt.Fprintln(stderr, threatPrefix+msg)
	return code
}

func runThreat(args []string, stdout, stderr io.Writer) int {
	switch {
	case len(args) == 2 && args[0] == "model":
	case len(args) == 3 && args[0] == "diff":
	default:
		return threatFail(stderr, exitUsage, threatUsage)
	}
	e, err := opa.NewDesign()
	if err != nil {
		return threatFail(stderr, exitRefused, msgPolicy)
	}
	models := make([]threat.Model, 0, 2)
	for _, path := range args[1:] {
		m, msg := modelOf(e, path)
		if msg != "" {
			return threatFail(stderr, exitRefused, msg)
		}
		models = append(models, m)
	}
	var doc any = models[0]
	if args[0] == "diff" {
		d, err := threat.Diff(models[0], models[1])
		switch {
		case errors.Is(err, threat.ErrTenantMismatch):
			return threatFail(stderr, exitRefused, msgTenants)
		case err != nil:
			return threatFail(stderr, exitRefused, msgMismatch)
		}
		doc = d
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return threatFail(stderr, exitRefused, msgAnalysis)
	}
	if _, err := stdout.Write(append(out, '\n')); err != nil {
		return exitRefused
	}
	return exitOK
}

// modelOf reads one graph, evaluates the design pack on its facts and applies
// stride-v1. It returns a fixed message on refusal.
func modelOf(e *opa.Engine, path string) (threat.Model, string) {
	g, err := readGraph(path)
	switch {
	case errors.Is(err, errFileRead):
		return threat.Model{}, msgGraphRead
	case err != nil:
		return threat.Model{}, msgGraphInvalid
	}
	f := graphdomain.FactsOf(g)
	rm, err := reach.FromGraph(f)
	if err != nil {
		return threat.Model{}, msgGraphInvalid
	}
	r, err := reach.Compute(rm, reach.DefaultLimits)
	if errors.Is(err, reach.ErrGraphTooLarge) {
		return threat.Model{}, msgGraphLarge
	} else if err != nil {
		return threat.Model{}, msgGraphInvalid
	}
	in, err := policy.NewDesignInput(f, r, policy.DesignContext{})
	if err != nil {
		return threat.Model{}, msgGraphInvalid
	}
	findings, err := e.Evaluate(context.Background(), in)
	if err != nil {
		return threat.Model{}, msgPolicy
	}
	controls := e.Controls()
	p := threat.Pack{Digest: e.Digest(), Controls: make([]string, 0, len(controls))}
	for _, c := range controls {
		p.Controls = append(p.Controls, c.ID)
	}
	m, err := threat.Analyze(f, findings, p)
	switch {
	case errors.Is(err, reach.ErrGraphTooLarge):
		return threat.Model{}, msgGraphLarge
	case err != nil:
		return threat.Model{}, msgAnalysis
	}
	return m, ""
}

// readGraph reads a regular file of at most threat.MaxDecodeBytes holding one
// graph: unknown keys and trailing data refused, then schemas/graph/v1.json.
func readGraph(path string) (graphdomain.Graph, error) {
	fh, err := os.Open(path) //nolint:gosec // G304: the user names the graph file on the command line; regular file only, bounded read.
	if err != nil {
		return graphdomain.Graph{}, errFileRead
	}
	defer func() { _ = fh.Close() }()
	st, err := fh.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > threat.MaxDecodeBytes {
		return graphdomain.Graph{}, errFileRead
	}
	raw, err := io.ReadAll(io.LimitReader(fh, threat.MaxDecodeBytes+1))
	if err != nil || len(raw) > threat.MaxDecodeBytes {
		return graphdomain.Graph{}, errFileRead
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var g graphdomain.Graph
	if err := dec.Decode(&g); err != nil {
		return graphdomain.Graph{}, errGraphInvalid
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return graphdomain.Graph{}, errGraphInvalid
	}
	if err := graph.ValidateSchema(g); err != nil {
		return graphdomain.Graph{}, errGraphInvalid
	}
	return g, nil
}
