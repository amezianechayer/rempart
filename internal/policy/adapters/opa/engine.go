// Package opa is the only importer of Open Policy Agent and of the embedded
// policy packs (rule opa-confined, ADR 0011). It compiles the design pack once,
// with capabilities restricted to pure builtins, Rego v1 in strict mode and the
// input schema, verifies its metadata, then evaluates it in memory, without
// any process, network access, store or state between evaluations.
package opa

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"

	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
	"github.com/amezianechayer/rempart/internal/policy"
	policydomain "github.com/amezianechayer/rempart/internal/policy/domain"
	"github.com/amezianechayer/rempart/policies"
	"github.com/amezianechayer/rempart/schemas"
)

// Options bound an evaluation (ADR 0011 D3, T24); every bound is strictly positive.
type Options struct {
	Timeout       time.Duration
	MaxInputBytes int
	MaxFindings   int
}

// DefaultOptions are the bounds of ADR 0011 D3.
var DefaultOptions = Options{Timeout: 10 * time.Second, MaxInputBytes: 8 << 20, MaxFindings: 10000}

// Errors of the engine. Fixed messages: never an input value.
var (
	ErrPackInvalid   = errors.New("opa: invalid policy pack")
	ErrEvaluation    = errors.New("opa: policy evaluation failed")
	ErrPolicyOutput  = errors.New("opa: policy output outside the closed form")
	ErrInputTooLarge = errors.New("opa: policy input too large")
)

// Source of the findings of the design pack.
const Source = "policy:design"

const query = "data.rempart.design[_].deny[_]"

var (
	controlIDRe  = regexp.MustCompile(`^[A-Z0-9]{2,5}-[0-9]{3}$`)
	packageRe    = regexp.MustCompile(`^[a-z_]+$`)
	customKeys   = []string{"control_id", "frameworks", "remediation", "severity"}
	severities   = []loopsdomain.Severity{loopsdomain.SeverityCritical, loopsdomain.SeverityHigh, loopsdomain.SeverityMedium, loopsdomain.SeverityLow}
	metadataCall = ast.Ref{ast.VarTerm("rego"), ast.StringTerm("metadata"), ast.StringTerm("rule")}
)

// Engine is a compiled pack, immutable and safe for concurrent use.
type Engine struct {
	pq       rego.PreparedEvalQuery
	controls map[string]policydomain.Control
	sorted   []policydomain.Control
	digest   string
	opts     Options
}

var _ policy.Evaluator = (*Engine)(nil)

// NewDesign compiles the embedded design pack with DefaultOptions.
func NewDesign() (*Engine, error) { return newEngine(policies.Design, DefaultOptions) }

func invalid(reason string) error { return fmt.Errorf("%w: %s", ErrPackInvalid, reason) }

// newEngine compiles the pack: the files of design/ but the tests, every one a
// .rego file of package rempart.design.<name>.
func newEngine(pack fs.FS, o Options) (*Engine, error) {
	if o.Timeout <= 0 || o.MaxInputBytes <= 0 || o.MaxFindings <= 0 {
		return nil, invalid("options")
	}
	files, err := readPack(pack)
	if err != nil {
		return nil, err
	}
	caps := capabilities()
	h := sha256.New()
	modules := make(map[string]*ast.Module, len(files))
	for _, f := range files {
		_, _ = fmt.Fprintf(h, "%d:%s,%d:%s,", len(f.path), f.path, len(f.src), f.src)
		m, err := ast.ParseModuleWithOpts(f.path, string(f.src), ast.ParserOptions{
			ProcessAnnotation: true, RegoVersion: ast.RegoV1, Capabilities: caps,
		})
		if err != nil {
			return nil, invalid("parse: " + err.Error())
		}
		if err := checkModule(m); err != nil {
			return nil, err
		}
		modules[f.path] = m
	}

	ss, err := inputSchema()
	if err != nil {
		return nil, err
	}
	c := ast.NewCompiler().WithStrict(true).WithCapabilities(caps).WithEnablePrintStatements(false).WithSchemas(ss)
	if c.Compile(modules); c.Failed() {
		return nil, invalid("compile: " + c.Errors.Error())
	}
	if err := checkCompiledDataRefs(c); err != nil {
		return nil, err
	}
	controls, err := verifyMetadata(c)
	if err != nil {
		return nil, err
	}
	pq, err := rego.New(rego.Compiler(c), rego.Query(query), rego.StrictBuiltinErrors(true)).PrepareForEval(context.Background())
	if err != nil {
		return nil, invalid("prepare")
	}
	e := &Engine{pq: pq, controls: controls, digest: hex.EncodeToString(h.Sum(nil)), opts: o}
	for _, ctl := range controls {
		e.sorted = append(e.sorted, ctl)
	}
	slices.SortFunc(e.sorted, func(a, b policydomain.Control) int { return strings.Compare(a.ID, b.ID) })
	return e, nil
}

type packFile struct {
	path string
	src  []byte
}

// readPack reads design/: .rego files only (a data file would be read by opa
// test and ignored by the engine), tests excluded, sorted by path.
func readPack(pack fs.FS) ([]packFile, error) {
	var files []packFile
	err := fs.WalkDir(pack, ".", func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir():
			if p != "." && p != "design" {
				return invalid("directory outside design/")
			}
			return nil
		case !strings.HasPrefix(p, "design/") || !strings.HasSuffix(p, ".rego"):
			return invalid("file other than design/*.rego")
		case strings.HasSuffix(p, "_test.rego"):
			return nil
		}
		src, err := fs.ReadFile(pack, p)
		if err != nil {
			return err
		}
		files = append(files, packFile{path: p, src: src})
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrPackInvalid) {
			return nil, err
		}
		return nil, invalid("read")
	}
	if len(files) == 0 {
		return nil, invalid("empty pack")
	}
	slices.SortFunc(files, func(a, b packFile) int { return strings.Compare(a.path, b.path) })
	return files, nil
}

// checkModule is the barrier applied before compilation (ADR 0011 D3): package
// rempart.design.<name>, no builtin outside the capabilities (print included,
// which the compiler would erase silently), no with modifier.
func checkModule(m *ast.Module) error {
	p := m.Package.Path
	if len(p) != 4 || !p[0].Equal(ast.DefaultRootDocument) || !p[1].Equal(ast.StringTerm("rempart")) || !p[2].Equal(ast.StringTerm("design")) {
		return invalid("package outside rempart.design")
	}
	if name, ok := p[3].Value.(ast.String); !ok || !packageRe.MatchString(string(name)) {
		return invalid("package name")
	}
	var bad error
	check := func(op ast.Ref) {
		name := op.String()
		if _, builtin := ast.BuiltinMap[name]; (builtin || name == "print") && !slices.Contains(allowedBuiltins, name) && bad == nil {
			bad = invalid("builtin outside the capabilities")
		}
	}
	ast.NewGenericVisitor(func(x any) bool {
		switch v := x.(type) {
		case *ast.Expr:
			if len(v.With) > 0 && bad == nil {
				bad = invalid("with modifier")
			}
			if v.IsCall() {
				check(v.Operator())
			}
		case ast.Call:
			if len(v) > 0 {
				if r, ok := v[0].Value.(ast.Ref); ok {
					check(r)
				}
			}
		}
		return false
	}).Walk(m)
	if bad != nil {
		return bad
	}
	if err := checkDataRefs(m); err != nil {
		return err
	}
	// Obligation (fe) (T108, T120): no string of the grammar of a control_id
	// anywhere in a module, so a rule cannot emit the identifier of another.
	ast.NewGenericVisitor(func(x any) bool {
		if t, ok := x.(*ast.Term); ok {
			if str, isStr := t.Value.(ast.String); isStr && controlIDRe.MatchString(string(str)) && bad == nil {
				bad = invalid("control_id literal")
			}
		}
		return false
	}).Walk(m)
	if bad != nil {
		return bad
	}
	// Before compilation: the compiler replaces rego.metadata.rule() by the
	// annotations of the rule.
	for _, r := range m.Rules {
		if head := r.Head.Ref(); len(head) > 0 && head[0].Equal(ast.VarTerm("deny")) {
			if err := checkDeny(r); err != nil {
				return err
			}
		}
	}
	return nil
}

// packRoot is the document of the compiled pack: data.rempart.design.
var packRoot = ast.Ref{ast.DefaultRootDocument, ast.StringTerm("rempart"), ast.StringTerm("design")}

// checkDataRefs: obligation (fk) (ADR 0011 D3, T109). Every reference to data,
// in a package, an import, a rule head or body, a comprehension, an every
// domain or an index, starts with packRoot: no bare data, no index on data or
// on rempart, no other pack, no test package.
func checkDataRefs(m *ast.Module) error {
	var bad error
	var visit func(x any) bool
	visit = func(x any) bool {
		if bad != nil {
			return true
		}
		switch v := x.(type) {
		case ast.Ref:
			if len(v) > 0 && v[0].Equal(ast.DefaultRootDocument) && !v.HasPrefix(packRoot) {
				bad = invalid("data reference outside the pack")
				return true
			}
			// A head that is a variable is checked above; any other head (array,
			// object, set, comprehension, call) is walked like the indexes
			// (review of M3-T01, T108).
			terms := v
			if len(v) > 0 {
				if _, isVar := v[0].Value.(ast.Var); isVar {
					terms = v[1:]
				}
			}
			for _, t := range terms {
				ast.NewGenericVisitor(visit).Walk(t)
			}
			return true
		case ast.Var:
			if v.Equal(ast.DefaultRootDocument.Value) {
				bad = invalid("data reference outside the pack")
			}
		}
		return false
	}
	ast.NewGenericVisitor(visit).Walk(m)
	return bad
}

// checkCompiledDataRefs is the second barrier of obligation (fk) (review of
// M3-T01, defense in depth): on the compiled modules, imports resolved and
// comprehensions rewritten, every reference whose head is data starts with
// packRoot.
func checkCompiledDataRefs(c *ast.Compiler) error {
	var bad error
	for _, m := range c.Modules {
		ast.NewGenericVisitor(func(x any) bool {
			if r, ok := x.(ast.Ref); ok && bad == nil && len(r) > 0 && r[0].Equal(ast.DefaultRootDocument) && !r.HasPrefix(packRoot) {
				bad = invalid("data reference outside the pack")
			}
			return bad != nil
		}).Walk(m)
	}
	return bad
}

// checkDeny admits a rule named deny only in the form of ADR 0011 D4, checked
// on its syntax (obligation (fe)): deny contains <f> if { ... }, where the body
// binds <m> := rego.metadata.rule() once and <f> once, to an object literal of
// exactly control_id and resource whose control_id is the term
// <m>.custom.control_id. A rule can then emit only its own control.
func checkDeny(r *ast.Rule) error {
	h := r.Head
	if h.Key == nil { // deny := ..., default deny := ...: no key (obligation (fr))
		return invalid("deny rule outside the form deny contains <var>")
	}
	f, isVar := h.Key.Value.(ast.Var)
	if !isVar || h.Value != nil || len(h.Args) > 0 || r.Else != nil || r.Default ||
		!h.Ref().Equal(ast.Ref{ast.VarTerm("deny")}) || !callsMetadata(r) {
		return invalid("deny rule outside the form deny contains <var>")
	}
	var meta ast.Var
	metas, outputs := 0, 0
	var out *ast.Term
	for _, e := range r.Body {
		if !e.IsAssignment() && !e.IsEquality() {
			continue
		}
		lhs, rhs := e.Operand(0), e.Operand(1)
		for _, side := range [][2]*ast.Term{{lhs, rhs}, {rhs, lhs}} {
			v, ok := side[0].Value.(ast.Var)
			if !ok {
				continue
			}
			if call, isCall := side[1].Value.(ast.Call); isCall && len(call) == 1 && call[0].Value.Compare(metadataCall) == 0 {
				meta = v
				metas++
			}
			if v.Equal(f) {
				out = side[1]
				outputs++
			}
		}
	}
	if metas != 1 || outputs != 1 {
		return invalid("deny rule without one metadata binding and one output binding")
	}
	obj, ok := out.Value.(ast.Object)
	if !ok || obj.Len() != 2 || obj.Get(ast.StringTerm("resource")) == nil {
		return invalid("deny output outside {control_id, resource}")
	}
	id := obj.Get(ast.StringTerm("control_id"))
	want := ast.Ref{ast.NewTerm(meta), ast.StringTerm("custom"), ast.StringTerm("control_id")}
	if id == nil || id.Value.Compare(want) != 0 {
		return invalid("deny output control_id other than <m>.custom.control_id")
	}
	return nil
}

// inputSchema reads schemas/policy/design-input-v1.json for the type checker.
func inputSchema() (*ast.SchemaSet, error) {
	raw, err := schemas.FS.ReadFile(schemas.PolicyDesignInput)
	if err != nil {
		return nil, invalid("input schema")
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, invalid("input schema")
	}
	ss := ast.NewSchemaSet()
	ss.Put(ast.SchemaRootRef, doc)
	return ss, nil
}

// verifyMetadata applies D4: one METADATA block of scope rule on every deny
// rule (a multi-value rule calling rego.metadata.rule), and on deny rules only;
// closed custom keys and values; unique control_id; no schema override.
func verifyMetadata(c *ast.Compiler) (map[string]policydomain.Control, error) {
	as := c.GetAnnotationSet()
	controls := map[string]policydomain.Control{}
	for _, m := range c.Modules {
		for _, a := range m.Annotations {
			if len(a.Schemas) > 0 {
				return nil, invalid("schema annotation")
			}
			if _, ok := a.Custom["control_id"]; ok && a.Scope != "rule" {
				return nil, invalid("control outside a rule scope")
			}
		}
		for _, r := range m.Rules {
			anns := as.GetRuleScope(r)
			isDeny := r.Head.Ref().Equal(ast.Ref{ast.VarTerm("deny")})
			if !isDeny {
				if len(anns) > 0 {
					return nil, invalid("metadata on a rule other than deny")
				}
				continue
			}
			if r.Head.RuleKind() != ast.MultiValue || len(anns) != 1 || r.Default {
				return nil, invalid("deny rule without its metadata block")
			}
			ctl, err := control(anns[0])
			if err != nil {
				return nil, err
			}
			if _, dup := controls[ctl.ID]; dup {
				return nil, invalid("control_id twice")
			}
			controls[ctl.ID] = ctl
		}
	}
	if len(controls) == 0 {
		return nil, invalid("no control")
	}
	return controls, nil
}

func control(a *ast.Annotations) (policydomain.Control, error) {
	t := a.Title
	if t == "" || len(t) > 120 || strings.IndexFunc(t, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) }) >= 0 {
		return policydomain.Control{}, invalid("title")
	}
	keys := make([]string, 0, len(a.Custom))
	for k := range a.Custom {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, customKeys) {
		return policydomain.Control{}, invalid("custom keys")
	}
	id, _ := a.Custom["control_id"].(string)
	sev, _ := a.Custom["severity"].(string)
	rem, _ := a.Custom["remediation"].(string)
	fw, isMap := a.Custom["frameworks"].(map[string]any)
	switch {
	case !controlIDRe.MatchString(id):
		return policydomain.Control{}, invalid("control_id")
	case !slices.Contains(severities, loopsdomain.Severity(sev)):
		return policydomain.Control{}, invalid("severity")
	case !slices.Contains(policydomain.Remediations(), policydomain.Remediation(rem)):
		return policydomain.Control{}, invalid("remediation")
	case !isMap || len(fw) != 0:
		return policydomain.Control{}, invalid("frameworks")
	}
	advisory := rem == string(policydomain.RemediationAdvisory)
	low := sev == string(loopsdomain.SeverityMedium) || sev == string(loopsdomain.SeverityLow)
	if advisory != low {
		return policydomain.Control{}, invalid("advisory if and only if medium or low")
	}
	return policydomain.Control{ID: id, Title: t, Severity: loopsdomain.Severity(sev), Remediation: policydomain.Remediation(rem)}, nil
}

func callsMetadata(r *ast.Rule) bool {
	found := false
	ast.NewGenericVisitor(func(x any) bool {
		if e, ok := x.(*ast.Expr); ok && e.IsCall() && e.Operator().Equal(metadataCall) {
			found = true
		}
		if c, ok := x.(ast.Call); ok && len(c) > 0 {
			if ref, isRef := c[0].Value.(ast.Ref); isRef && ref.Equal(metadataCall) {
				found = true
			}
		}
		return found
	}).Walk(r.Body)
	return found
}

// Evaluate evaluates the pack on in (ADR 0011 D3, D4).
func (e *Engine) Evaluate(ctx context.Context, in policy.DesignInput) ([]loopsdomain.Finding, error) {
	if err := in.Check(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return nil, ErrEvaluation
	}
	if len(raw) > e.opts.MaxInputBytes {
		return nil, ErrInputTooLarge
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, ErrEvaluation
	}
	value, err := ast.InterfaceToValue(doc)
	if err != nil {
		return nil, ErrEvaluation
	}
	ids := make(map[string]bool, len(in.Graph.Nodes)+len(in.Graph.Edges))
	for _, n := range in.Graph.Nodes {
		ids[n.ID] = true
	}
	for _, x := range in.Graph.Edges {
		ids[x.ID] = true
	}

	ctx, cancel := context.WithTimeout(ctx, e.opts.Timeout)
	defer cancel()
	if ctx.Err() != nil {
		return nil, ErrEvaluation
	}
	rs, err := e.pq.Eval(ctx, rego.EvalParsedInput(value))
	if err != nil || ctx.Err() != nil {
		return nil, ErrEvaluation
	}
	if len(rs) > e.opts.MaxFindings {
		return nil, ErrPolicyOutput
	}
	seen := map[[2]string]bool{}
	out := []loopsdomain.Finding{}
	for _, r := range rs {
		if len(r.Expressions) != 1 {
			return nil, ErrPolicyOutput
		}
		obj, ok := r.Expressions[0].Value.(map[string]any)
		if !ok || len(obj) != 2 {
			return nil, ErrPolicyOutput
		}
		id, okID := obj["control_id"].(string)
		res, okRes := obj["resource"].(string)
		ctl, known := e.controls[id]
		if !okID || !okRes || !known || !ids[res] {
			return nil, ErrPolicyOutput
		}
		if seen[[2]string{id, res}] {
			continue
		}
		seen[[2]string{id, res}] = true
		out = append(out, loopsdomain.Finding{Code: id, Source: Source, Severity: ctl.Severity, Resource: res, Message: ctl.Title})
	}
	return loopsdomain.Sort(out), nil
}

// Controls returns the controls of the pack, sorted by control_id.
func (e *Engine) Controls() []policydomain.Control { return slices.Clone(e.sorted) }

// Digest returns the SHA-256, lowercase hexadecimal, of the netstrings (path
// relative to policies/, content) of the compiled files sorted by path.
func (e *Engine) Digest() string { return e.digest }
