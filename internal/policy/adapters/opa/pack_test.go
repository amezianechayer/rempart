package opa

import (
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode"

	opaast "github.com/open-policy-agent/opa/v1/ast"

	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
	policydomain "github.com/amezianechayer/rempart/internal/policy/domain"
)

// catalog freezes the controls of the pack (fiche M2-T03): control_id,
// severity, remediation. Lowering a severity changes this test file, frozen in
// the impl phase (T108). M2-T03a: network and data; M2-T03b adds the rest.
var catalog = []struct {
	id  string
	sev loopsdomain.Severity
	rem policydomain.Remediation
}{
	{"DATA-001", "critical", "make_private"},
	{"DATA-002", "high", "enable_encryption"},
	{"DATA-003", "medium", "advisory"},
	{"DATA-004", "high", "escalate"},
	{"NET-001", "critical", "make_private"},
	{"NET-002", "high", "escalate"},
	{"NET-003", "critical", "remove_exposure"},
	{"NET-004", "critical", "remove_exposure"},
	{"NET-005", "high", "escalate"},
	{"NET-006", "high", "escalate"},
	{"NET-007", "high", "https_only"},
	{"NET-008", "high", "escalate"},
	{"NET-009", "high", "escalate"},
	{"NET-010", "high", "make_private"},
	{"NET-011", "high", "encrypt_transit"},
	{"NET-012", "high", "move_to_data_tier"},
	{"NET-013", "medium", "advisory"},
	{"NET-014", "high", "remove_exposure"},
	{"NET-015", "high", "escalate"},
}

// packFiles returns the paths of the pack under policies/, tests apart.
func packFiles(t *testing.T) (rules, tests []string) {
	t.Helper()
	err := fs.WalkDir(os.DirFS(repo+"policies"), "design", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
		case strings.HasSuffix(p, "_test.rego"):
			tests = append(tests, p)
		case strings.HasSuffix(p, ".rego"):
			rules = append(rules, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return rules, tests
}

// TestPolicyMetadataComplete proves the metadata of ADR 0011 D4 on the
// embedded pack (C1, T108): each control has a title, a unique control_id of
// the closed pattern, a closed severity, a remediation of the vocabulary
// (advisory if and only if medium or low), the frozen catalog; the source
// files declare exactly these control_id, in packages rempart.design.<name>.
func TestPolicyMetadataComplete(t *testing.T) {
	e, err := NewDesign()
	if err != nil {
		t.Fatalf("NewDesign: %v", err)
	}
	idRe := regexp.MustCompile(`^[A-Z0-9]{2,5}-[0-9]{3}$`)
	controls := e.Controls()
	if len(controls) != len(catalog) {
		t.Errorf("%d controls, want the %d of the frozen catalog", len(controls), len(catalog))
	}
	for i, c := range controls {
		if !idRe.MatchString(c.ID) {
			t.Errorf("control_id %q outside the pattern", c.ID)
		}
		if c.Title == "" || len(c.Title) > 120 || strings.IndexFunc(c.Title, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) }) >= 0 {
			t.Errorf("%s: title %q empty, too long or with a control character", c.ID, c.Title)
		}
		if !slices.Contains(policydomain.Remediations(), c.Remediation) {
			t.Errorf("%s: remediation %q outside the vocabulary", c.ID, c.Remediation)
		}
		advisory := c.Remediation == policydomain.RemediationAdvisory
		low := c.Severity == loopsdomain.SeverityMedium || c.Severity == loopsdomain.SeverityLow
		if advisory != low {
			t.Errorf("%s: remediation %q with severity %q (advisory if and only if medium or low)", c.ID, c.Remediation, c.Severity)
		}
		if i < len(catalog) {
			w := catalog[i]
			if c.ID != w.id || c.Severity != w.sev || c.Remediation != w.rem {
				t.Errorf("control %d = (%s, %s, %s), want (%s, %s, %s)", i, c.ID, c.Severity, c.Remediation, w.id, w.sev, w.rem)
			}
		}
	}

	rules, _ := packFiles(t)
	idLine := regexp.MustCompile(`(?m)^#[[:space:]]*control_id:[[:space:]]*(\S+)$`)
	pkgLine := regexp.MustCompile(`(?m)^package rempart\.design\.([a-z_]+)$`)
	var ids []string
	for _, p := range rules {
		raw, err := os.ReadFile(repo + "policies/" + p) //nolint:gosec // G304: a file of the pack listed by WalkDir under the repository
		if err != nil {
			t.Fatal(err)
		}
		if !pkgLine.Match(raw) {
			t.Errorf("%s: no package rempart.design.<name>", p)
		}
		for _, m := range idLine.FindAllSubmatch(raw, -1) {
			ids = append(ids, string(m[1]))
		}
	}
	slices.Sort(ids)
	var want []string
	for _, c := range catalog {
		want = append(want, c.id)
	}
	if !slices.Equal(ids, want) {
		t.Errorf("control_id lines of the sources %q, want %q (unique, as the catalog)", ids, want)
	}
}

// okKoCalls collects the first argument of every call to ok or ko (any
// package prefix) in a parsed test module.
func okKoCalls(m *opaast.Module) (ok, ko []string) {
	opaast.WalkExprs(m, func(x *opaast.Expr) bool {
		terms, isCall := x.Terms.([]*opaast.Term)
		if !isCall || len(terms) < 2 {
			return false
		}
		ref, isRef := terms[0].Value.(opaast.Ref)
		id, isStr := terms[1].Value.(opaast.String)
		if !isRef || !isStr || len(ref) == 0 {
			return false
		}
		last := ref[len(ref)-1].Value
		switch {
		case last.Compare(opaast.String("ok")) == 0 || last.Compare(opaast.Var("ok")) == 0:
			ok = append(ok, string(id))
		case last.Compare(opaast.String("ko")) == 0 || last.Compare(opaast.Var("ko")) == 0:
			ko = append(ko, string(id))
		}
		return false
	})
	return ok, ko
}

// TestEveryControlHasOkAndKo proves C1 of prompts/M2.md: every control of the
// pack has at least one compliant (ok) and one non-compliant (ko) case in the
// Rego tests, read from their syntax tree; the tests live outside the queried
// packages (rempart.design_test.*) and the helpers are not a no-op.
func TestEveryControlHasOkAndKo(t *testing.T) {
	e, err := NewDesign()
	if err != nil {
		t.Fatalf("NewDesign: %v", err)
	}
	_, tests := packFiles(t)
	if !slices.Contains(tests, "design/lib_test.rego") {
		t.Fatalf("design/lib_test.rego missing (helpers ok and ko)")
	}
	okSet, koSet := map[string]bool{}, map[string]bool{}
	for _, p := range tests {
		raw, err := os.ReadFile(repo + "policies/" + p) //nolint:gosec // G304: a file of the pack listed by WalkDir under the repository
		if err != nil {
			t.Fatal(err)
		}
		m, err := opaast.ParseModuleWithOpts(p, string(raw), opaast.ParserOptions{RegoVersion: opaast.RegoV1})
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if !strings.HasPrefix(m.Package.Path.String(), "data.rempart.design_test.") {
			t.Errorf("%s: package %s, want rempart.design_test.<name> (outside the queried packages)", p, m.Package.Path)
		}
		ok, ko := okKoCalls(m)
		for _, id := range ok {
			okSet[id] = true
		}
		for _, id := range ko {
			koSet[id] = true
		}
	}
	for _, c := range e.Controls() {
		if !okSet[c.ID] {
			t.Errorf("%s: no compliant case ok(%q, ...)", c.ID, c.ID)
		}
		if !koSet[c.ID] {
			t.Errorf("%s: no non-compliant case ko(%q, ...)", c.ID, c.ID)
		}
	}
	for id := range koSet {
		if !slices.ContainsFunc(e.Controls(), func(c policydomain.Control) bool { return c.ID == id }) {
			t.Errorf("ko(%q, ...) names no control of the pack", id)
		}
	}
	if len(okSet) == 0 || len(koSet) == 0 {
		t.Fatalf("no ok or ko call found: the walk saw nothing")
	}
}
