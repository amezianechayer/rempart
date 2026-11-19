// Package activities are the activities of L2-design (docs/loops/L2.md, ADR
// 0012): Prepare refuses or escalates before the loop, Propose returns the
// initial candidate then revises it, Verify runs the verifier of the core and
// the pack, Finalize replays the verifier, computes the threat models and the
// explanation. No model, no free text read but the address reader on
// overrides, only to block.
package activities

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"unicode/utf8"

	"go.temporal.io/sdk/temporal"

	"github.com/amezianechayer/rempart/internal/design/cidr"
	"github.com/amezianechayer/rempart/internal/design/confirm"
	"github.com/amezianechayer/rempart/internal/design/revise"
	"github.com/amezianechayer/rempart/internal/design/verify"
	"github.com/amezianechayer/rempart/internal/graph"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	"github.com/amezianechayer/rempart/internal/graph/reach"
	intentdomain "github.com/amezianechayer/rempart/internal/intent/domain"
	"github.com/amezianechayer/rempart/internal/intent/irvalid"
	"github.com/amezianechayer/rempart/internal/loops"
	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
	"github.com/amezianechayer/rempart/internal/policy"
	policydomain "github.com/amezianechayer/rempart/internal/policy/domain"
	"github.com/amezianechayer/rempart/internal/tenancy"
	"github.com/amezianechayer/rempart/internal/threat"
)

// Names and bounds.
const (
	StrategyCatalog       = "catalog"
	ErrTypeInvalidL2Input = "InvalidL2Input"
	MaxExplanations       = 20
)

// Activities: Tenant comes from the worker configuration, never from an
// input (rule 9, T3); Policy is the design pack compiled at start.
type Activities struct {
	Tenant tenancy.ID
	Policy policy.Evaluator
}

// Input carries exactly one subject: an IR or a candidate graph.
type Input struct {
	IR           *intentdomain.IR     `json:"ir,omitempty"`
	Graph        *graphdomain.Graph   `json:"graph,omitempty"`
	Confirmation confirm.Confirmation `json:"confirmation"`
}

// Candidate is what the loop iterates on: the graph and the revisions that
// led to it.
type Candidate struct {
	Graph   graphdomain.Graph `json:"graph"`
	Applied []revise.Applied  `json:"applied"`
}

// designContext is the context of the IR given to the pack (ADR 0012 D7).
type designContext struct {
	AllowedRegions  []string          `json:"allowed_regions"`
	ForbiddenClouds []string          `json:"forbidden_clouds"`
	Environment     string            `json:"environment"`
	Metrics         bool              `json:"metrics"`
	Logs            bool              `json:"logs"`
	WorkloadRoles   map[string]string `json:"workload_roles"`
}

// payload is built by Prepare alone and decoded strictly by every activity.
type payload struct {
	Subject              string                `json:"subject"`
	Initial              Candidate             `json:"initial"`
	Confirmed            []confirm.ExposureKey `json:"confirmed"`
	OverridesCiteAddress bool                  `json:"overrides_cite_address"`
	Context              designContext         `json:"context"`
}

// Prepared is the payload of the loop, or an escalation decided before it.
type Prepared struct {
	Subject    string          `json:"subject"`
	Payload    json.RawMessage `json:"payload,omitempty"`
	Escalation []Explanation   `json:"escalation,omitempty"`
}

// FinalizeRequest: the payload, the best candidate of the loop (never
// returned when escalated) and its remaining findings.
type FinalizeRequest struct {
	Payload   json.RawMessage       `json:"payload"`
	Best      json.RawMessage       `json:"best,omitempty"`
	Converged bool                  `json:"converged"`
	Remaining []loopsdomain.Finding `json:"remaining"`
}

// Finalized is the result of Finalize: graph and threat models only when
// converged, explanation only when escalated.
type Finalized struct {
	Graph           *graphdomain.Graph    `json:"graph,omitempty"`
	Applied         []revise.Applied      `json:"applied"`
	InitialFindings []loopsdomain.Finding `json:"initial_findings"`
	Advisories      []loopsdomain.Finding `json:"advisories"`
	Threats         *threat.Model         `json:"threats,omitempty"`
	ThreatDelta     *threat.Delta         `json:"threat_delta,omitempty"`
	Explanation     []Explanation         `json:"explanation,omitempty"`
}

func refuse(msg, errType string) error {
	return temporal.NewNonRetryableApplicationError(msg, errType, nil)
}

func invalidInput() error { return refuse("invalid L2 input", ErrTypeInvalidL2Input) }

func (a *Activities) ready() error {
	if a == nil || a.Policy == nil {
		return refuse("L2 activities not configured", loops.ErrTypePolicyViolation)
	}
	if id, err := tenancy.ParseID(string(a.Tenant)); err != nil || id == tenancy.System {
		return refuse("L2 tenant refused", loops.ErrTypePolicyViolation)
	}
	return nil
}

// Prepare refuses (InvalidL2Input, no activity of the loop) zero or two
// subjects, a subject of another tenant or outside its schema, a confirmation
// of another subject or document, a forged key; it escalates before the loop
// when Build refuses the IR or the subject exceeds the bounds of the loop.
func (a *Activities) Prepare(_ context.Context, in Input) (Prepared, error) {
	if err := a.ready(); err != nil {
		return Prepared{}, err
	}
	if (in.IR == nil) == (in.Graph == nil) {
		return Prepared{}, invalidInput()
	}
	p := payload{Context: designContext{AllowedRegions: []string{}, ForbiddenClouds: []string{}, WorkloadRoles: map[string]string{}}}
	var doc any
	if in.IR != nil {
		ir := *in.IR
		if ir.TenantID != string(a.Tenant) || irvalid.ValidateIR(ir) != nil {
			return Prepared{}, invalidInput()
		}
		p.Subject, doc, p.Context = confirm.SubjectIR, ir, contextOf(ir)
		for _, o := range ir.ExplicitOverrides {
			p.OverridesCiteAddress = p.OverridesCiteAddress || intentdomain.CitesAddress(o.Statement)
		}
	} else {
		g := *in.Graph
		if g.TenantID != string(a.Tenant) || g.Source != "design" || graph.ValidateSchema(g) != nil || graphdomain.Validate(g) != nil {
			return Prepared{}, invalidInput()
		}
		p.Subject, doc = confirm.SubjectGraph, g
	}
	sum, err := confirm.SubjectSHA256(p.Subject, doc)
	c := in.Confirmation
	if err != nil || c.Subject != p.Subject || c.SubjectSHA256 != sum {
		return Prepared{}, invalidInput()
	}

	var d confirm.Digest
	var g graphdomain.Graph
	if in.IR != nil {
		if d, g, err = digestOfIR(*in.IR); err != nil {
			return escalated(p.Subject, err), nil
		}
	} else if g = *in.Graph; true {
		if d, err = confirm.DigestOfGraph(g); err != nil {
			return escalated(p.Subject, err), nil
		}
	}
	if _, err := confirm.Check(d, c); err != nil {
		return Prepared{}, invalidInput()
	}
	p.Confirmed = slices.Clone(c.Exposures)
	p.Initial = Candidate{Graph: g, Applied: []revise.Applied{}}
	cand, err := json.Marshal(p.Initial)
	if err != nil {
		return Prepared{}, refuse("L2 candidate not encodable", loops.ErrTypeValidation)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return Prepared{}, refuse("L2 payload not encodable", loops.ErrTypeValidation)
	}
	if encodedLen(cand) > loops.MaxCandidateBytes || encodedLen(raw) > loops.MaxPayloadBytes {
		return escalated(p.Subject, reach.ErrGraphTooLarge), nil
	}
	return Prepared{Subject: p.Subject, Payload: raw}, nil
}

// digestOfIR builds the IR once, with the default options of L2.
func digestOfIR(ir intentdomain.IR) (confirm.Digest, graphdomain.Graph, error) {
	d, err := confirm.DigestOfIR(ir)
	if err != nil {
		return confirm.Digest{}, graphdomain.Graph{}, err
	}
	g, err := buildDefault(ir)
	return d, g, err
}

// escalated codes an escalation of Prepare: the planner, the bounds, or any
// other refusal of Build.
func escalated(subject string, err error) Prepared {
	code := CodeManualFixRequired
	switch {
	case errors.Is(err, cidr.ErrInvalidRequest), errors.Is(err, cidr.ErrExhausted):
		code = CodeCIDRConflict
	case errors.Is(err, reach.ErrGraphTooLarge):
		code = CodePayloadTooLarge
	}
	return Prepared{Subject: subject, Escalation: []Explanation{explain(code, "", subject)}}
}

func contextOf(ir intentdomain.IR) designContext {
	c := designContext{
		AllowedRegions: slices.Clone(ir.Constraints.AllowedRegions), ForbiddenClouds: slices.Clone(ir.Constraints.ForbiddenClouds),
		Environment: ir.Environment, WorkloadRoles: map[string]string{},
	}
	if c.AllowedRegions == nil {
		c.AllowedRegions = []string{}
	}
	if c.ForbiddenClouds == nil {
		c.ForbiddenClouds = []string{}
	}
	if o := ir.Observability; o != nil {
		c.Metrics = o.Metrics != nil && *o.Metrics != "" && *o.Metrics != "none"
		c.Logs = o.Logs != nil && *o.Logs != "" && *o.Logs != "none"
	}
	for _, w := range ir.Workloads {
		if w.Kind == policydomain.RoleGitOpsController || w.Kind == policydomain.RoleObservabilityStack {
			c.WorkloadRoles["wl:"+w.ID] = w.Kind
		}
	}
	return c
}

func (c designContext) design() policy.DesignContext {
	return policy.DesignContext{
		Constraints:   policydomain.Constraints{AllowedRegions: c.AllowedRegions, ForbiddenClouds: c.ForbiddenClouds},
		Environment:   c.Environment,
		Observability: policydomain.Observability{Metrics: c.Metrics, Logs: c.Logs},
		WorkloadRoles: c.WorkloadRoles,
	}
}

func (p payload) verifyContext() verify.Context {
	return verify.Context{Confirmed: p.Confirmed, OverridesCiteAddress: p.OverridesCiteAddress, Base: p.Context.design()}
}

// decodeStrict reads one JSON value into out, unknown fields refused.
func decodeStrict(raw []byte, out any) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(out) != nil {
		return false
	}
	_, err := dec.Token()
	return errors.Is(err, io.EOF)
}

func decodePayload(raw json.RawMessage) (payload, bool) {
	var p payload
	ok := decodeStrict(raw, &p) && (p.Subject == confirm.SubjectIR || p.Subject == confirm.SubjectGraph)
	return p, ok
}

// Propose returns the initial candidate when there is no best yet, then the
// best candidate revised on the findings of the last one (ADR 0012 D1).
func (a *Activities) Propose(_ context.Context, req loops.ProposeRequest) (loops.ProposeResponse, error) {
	if err := a.ready(); err != nil {
		return loops.ProposeResponse{}, err
	}
	p, ok := decodePayload(req.Payload)
	if !ok || req.Strategy != StrategyCatalog {
		return loops.ProposeResponse{}, refuse("invalid propose request", loops.ErrTypeValidation)
	}
	cand := p.Initial
	if len(req.Best) > 0 {
		if !decodeStrict(req.Best, &cand) {
			return loops.ProposeResponse{}, refuse("invalid best candidate", loops.ErrTypeValidation)
		}
		controls := append(a.Policy.Controls(), verify.CoreControls()...)
		g, applied, err := revise.Revise(cand.Graph, req.Findings, controls)
		if err != nil {
			return loops.ProposeResponse{}, refuse("L2 reviser refused", loops.ErrTypePolicyViolation)
		}
		cand.Graph = g
		for _, x := range applied {
			if !slices.Contains(cand.Applied, x) {
				cand.Applied = append(cand.Applied, x)
			}
		}
	}
	raw, err := json.Marshal(cand)
	if err != nil {
		return loops.ProposeResponse{}, refuse("L2 candidate not encodable", loops.ErrTypeValidation)
	}
	return loops.ProposeResponse{Candidate: raw, Tokens: 0}, nil
}

// Verify runs the verifier on the candidate and returns its critical and high
// findings, the 100 gravest; medium and low never block (ADR 0012 D4). Any
// error is non-retryable.
func (a *Activities) Verify(ctx context.Context, req loops.VerifyRequest) (loops.VerifyResult, error) {
	if err := a.ready(); err != nil {
		return loops.VerifyResult{}, err
	}
	p, ok := decodePayload(req.Payload)
	var cand Candidate
	if !ok || !decodeStrict(req.Candidate, &cand) {
		return loops.VerifyResult{}, refuse("invalid verify request", loops.ErrTypeValidation)
	}
	fs, err := verify.Candidate(ctx, a.Policy, cand.Graph, string(a.Tenant), p.verifyContext())
	if err != nil {
		return loops.VerifyResult{}, refuse("L2 verification failed", loops.ErrTypePolicyViolation)
	}
	b := loopsdomain.Top(blocking(fs), loops.MaxFindings)
	if b == nil {
		b = []loopsdomain.Finding{}
	}
	return loops.VerifyResult{OK: len(b) == 0, Findings: b}, nil
}

func blocking(fs []loopsdomain.Finding) []loopsdomain.Finding {
	var out []loopsdomain.Finding
	for _, f := range fs {
		if f.Severity == loopsdomain.SeverityCritical || f.Severity == loopsdomain.SeverityHigh {
			out = append(out, f)
		}
	}
	return out
}

func minor(fs []loopsdomain.Finding) []loopsdomain.Finding {
	out := []loopsdomain.Finding{}
	for _, f := range fs {
		if f.Severity != loopsdomain.SeverityCritical && f.Severity != loopsdomain.SeverityHigh {
			out = append(out, f)
		}
	}
	return out
}

// Finalize replays the verifier on the initial candidate and, when converged,
// on the final one (a critical or high finding refuses: never an unverified
// graph); it returns the threat models and their delta when converged, the
// coded explanation when escalated.
func (a *Activities) Finalize(ctx context.Context, req FinalizeRequest) (Finalized, error) {
	if err := a.ready(); err != nil {
		return Finalized{}, err
	}
	p, ok := decodePayload(req.Payload)
	if !ok {
		return Finalized{}, refuse("invalid finalize request", loops.ErrTypeValidation)
	}
	vc := p.verifyContext()
	initial, err := verify.Candidate(ctx, a.Policy, p.Initial.Graph, string(a.Tenant), vc)
	if err != nil {
		return Finalized{}, refuse("L2 verification failed", loops.ErrTypePolicyViolation)
	}
	out := Finalized{Applied: []revise.Applied{}, InitialFindings: initial, Advisories: []loopsdomain.Finding{}}
	var best Candidate
	haveBest := len(req.Best) > 0 && decodeStrict(req.Best, &best)
	if haveBest && best.Applied != nil {
		out.Applied = best.Applied
	}
	if !req.Converged {
		out.Explanation = explainAll(req.Remaining, p)
		return out, nil
	}
	if !haveBest {
		return Finalized{}, refuse("invalid final candidate", loops.ErrTypeValidation)
	}
	final, err := verify.Candidate(ctx, a.Policy, best.Graph, string(a.Tenant), vc)
	if err != nil || len(blocking(final)) > 0 {
		return Finalized{}, refuse("L2 final candidate refused", loops.ErrTypePolicyViolation)
	}
	pack := a.pack()
	before, err := threat.Analyze(graphdomain.FactsOf(p.Initial.Graph), initial, pack)
	if err != nil {
		return Finalized{}, refuse("L2 threat analysis failed", loops.ErrTypeValidation)
	}
	after, err := threat.Analyze(graphdomain.FactsOf(best.Graph), final, pack)
	if err != nil {
		return Finalized{}, refuse("L2 threat analysis failed", loops.ErrTypeValidation)
	}
	delta, err := threat.Diff(before, after)
	if err != nil {
		return Finalized{}, refuse("L2 threat delta failed", loops.ErrTypeValidation)
	}
	g := best.Graph
	out.Graph, out.Threats, out.ThreatDelta, out.Advisories = &g, &after, &delta, minor(final)
	return out, nil
}

// pack: the controls evaluated for a candidate (ADR 0010 D12): the design
// pack, the invariants of the core and the CIDR codes.
func (a *Activities) pack() threat.Pack {
	var ids []string
	for _, c := range a.Policy.Controls() {
		ids = append(ids, c.ID)
	}
	for _, c := range verify.CoreControls() {
		ids = append(ids, c.ID)
	}
	ids = append(ids, cidr.CodeInvalid, cidr.CodeNotPrivate, cidr.CodeOutsideSuperblock, cidr.CodeUnknownParent,
		cidr.CodeOutsideParent, cidr.CodeOverlap, cidr.CodeOverlapExternal)
	slices.Sort(ids)
	return threat.Pack{Digest: a.Policy.Digest(), Controls: ids}
}

// encodedLen bounds the encoding/json length of raw as loops.RunLoop counts
// it: 6 for a control byte, <, > and &; 2 for ", \ and multi-byte rune
// bytes; else 1. Invalid UTF-8 counts beyond any bound.
func encodedLen(raw []byte) int {
	if !utf8.Valid(raw) {
		return loops.MaxPayloadBytes + 1
	}
	n := 0
	for _, b := range raw {
		switch {
		case b < 0x20 || b == '<' || b == '>' || b == '&':
			n += 6
		case b == '"' || b == '\\' || b >= utf8.RuneSelf:
			n += 2
		default:
			n++
		}
	}
	return n
}
