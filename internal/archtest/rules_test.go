package archtest

import (
	"bytes"
	"io/fs"
	"os"
	"slices"
	"strings"
	"testing"
)

// fixtureDir holds the go list fixtures of the import rules, relative to the
// package directory (the working directory during go test).
const fixtureDir = "testdata/golist"

// Fixture file suffixes: every rule has one violating and one conforming graph.
const (
	violationSuffix  = ".violation.json"
	conformingSuffix = ".conforming.json"
)

// loadFixture decodes a go list fixture with the production decoder, so that
// fixtures and the real go list output go through the same code.
func loadFixture(t *testing.T, name string) []Package {
	t.Helper()
	data, err := fs.ReadFile(os.DirFS(fixtureDir), name)
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	pkgs, err := decodePackages(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("fixture %s: decodePackages: %v", name, err)
	}
	return pkgs
}

// expectViolations compares violations exactly, order included.
func expectViolations(t *testing.T, got, want []Violation) {
	t.Helper()
	if slices.Equal(got, want) {
		return
	}
	t.Errorf("violations:\n%s\nwant:\n%s", formatViolations(got), formatViolations(want))
}

func formatViolations(vs []Violation) string {
	if vs == nil {
		return "  (nil)"
	}
	lines := make([]string, 0, len(vs))
	for _, v := range vs {
		lines = append(lines, "  "+v.Rule+": "+v.Importer+" imports "+v.Imported)
	}
	if len(lines) == 0 {
		return "  (empty, non-nil)"
	}
	return strings.Join(lines, "\n")
}

// rulePatterns returns every pattern of a rule, whatever its role.
func rulePatterns(r Rule) []string {
	return slices.Concat(r.From, r.Targets, r.AllowedFrom, r.AllowedTargets)
}

func TestMatch(t *testing.T) {
	const m = modulePath
	cases := []struct {
		name, pattern, path string
		want                bool
	}{
		// Exact patterns, compared segment by segment.
		{"exact_equal", "a.com/x/y", "a.com/x/y", true},
		{"exact_longer_path", "a.com/x/y", "a.com/x/y/z", false},
		{"exact_shorter_path", "a.com/x/y", "a.com/x", false},
		{"exact_segment_prefix", "a.com/x/y", "a.com/x/yz", false},
		// "/..." suffix: the path itself and its subtree, never a sibling prefix.
		{"suffix_matches_root", "a.com/x/...", "a.com/x", true},
		{"suffix_matches_subtree", "a.com/x/...", "a.com/x/y/z", true},
		{"suffix_not_sibling_prefix", "a.com/x/...", "a.com/xy", false},
		{"suffix_temporal_sibling", "go.temporal.io/sdk/...", "go.temporal.io/sdkx", false},
		{"suffix_temporal_subpackage", "go.temporal.io/sdk/...", "go.temporal.io/sdk/workflow", true},
		{"suffix_not_parent", "a.com/x/...", "a.com", false},
		// "*" is exactly one non-empty segment.
		{"star_one_segment", m + "/internal/*/domain", m + "/internal/llm/domain", true},
		{"star_not_two_segments", m + "/internal/*/domain", m + "/internal/llm/sub/domain", false},
		{"star_not_zero_segment", m + "/internal/*/domain", m + "/internal/domain", false},
		{"star_with_suffix_subtree", m + "/internal/*/domain/...", m + "/internal/llm/domain/x", true},
		{"star_with_suffix_root", m + "/internal/*/domain/...", m + "/internal/llm/domain", true},
		{"star_with_suffix_other_leaf", m + "/internal/*/domain/...", m + "/internal/llm/domainx", false},
		{"star_other_module", m + "/internal/*/domain", "example.com/m/internal/llm/domain", false},
		// Reserved patterns.
		{"std_fmt", "std", "fmt", true},
		{"std_net_http", "std", "net/http", true},
		{"std_cgo", "std", "C", true},
		{"std_not_third_party", "std", "github.com/x/y", false},
		{"std_not_module", "std", m + "/internal/llm", false},
		{"all_stdlib", "...", "fmt", true},
		{"all_third_party", "...", "github.com/x", true},
		// Invalid patterns and malformed paths never match.
		{"empty_pattern", "", "a.com/x", false},
		{"empty_pattern_empty_path", "", "", false},
		{"ellipsis_not_last", "a/.../b", "a/x/b", false},
		{"ellipsis_inside_segment", "a/x...", "a/xy", false},
		{"star_inside_segment", "l*/b", "lx/b", false},
		{"double_star_segment", "a/**/b", "a/x/b", false},
		{"leading_slash", "/a", "/a", false},
		{"trailing_slash", "a/", "a/", false},
		{"empty_segment", "a//b", "a//b", false},
		{"empty_path_all", "...", "", false},
		{"empty_path_std", "std", "", false},
		{"malformed_path_star", m + "/internal/*/domain", m + "/internal//domain", false},
		{"malformed_path_trailing_slash", "a.com/x/...", "a.com/x/", false},
		{"malformed_path_all", "...", "a.com//x", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Match(c.pattern, c.path); got != c.want {
				t.Errorf("Match(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
			}
		})
	}
}

func TestStdlibDetection(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"fmt", true},
		{"net/http", true},
		{"crypto/sha256", true},
		{"database/sql", true},
		{"C", true},
		{"github.com/x/y", false},
		{"go.temporal.io/sdk", false},
		{"golang.org/x/vuln", false},
		{"example.com", false},
		{modulePath, false},
		{modulePath + "/internal/llm", false},
		{"", false},
	}
	t.Run("is_stdlib", func(t *testing.T) {
		for _, c := range cases {
			if got := isStdlib(c.path); got != c.want {
				t.Errorf("isStdlib(%q) = %v, want %v", c.path, got, c.want)
			}
		}
	})
	t.Run("std_pattern_agrees", func(t *testing.T) {
		for _, c := range cases {
			if got, std := Match("std", c.path), isStdlib(c.path); got != std {
				t.Errorf("Match(\"std\", %q) = %v, isStdlib = %v", c.path, got, std)
			}
		}
	})
	t.Run("dotless_module_rejected", func(t *testing.T) {
		// A dotless module would make its own packages look like the standard
		// library: Check must fail closed instead of evaluating the rules.
		rules := []Rule{{
			Name: "confine-secret", Kind: Confine,
			Targets:     []string{"corp/mod/secret"},
			AllowedFrom: []string{"corp/mod/ok"},
		}}
		pkgs := []Package{{ImportPath: "corp/mod/bad", Imports: []string{"corp/mod/secret"}}}
		got := Check("corp/mod", pkgs, rules)
		expectViolations(t, got, []Violation{{Rule: "(module)", Importer: "(invalid)", Imported: "corp/mod"}})
	})
}

func TestCheck(t *testing.T) {
	const mod = "example.com/m"
	confineSecret := Rule{
		Name: "confine-secret", Kind: Confine,
		Targets:     []string{mod + "/secret/..."},
		AllowedFrom: []string{mod + "/vault/..."},
	}
	restrictCore := Rule{
		Name: "restrict-core", Kind: Restrict,
		From:           []string{mod + "/core/..."},
		AllowedTargets: []string{mod + "/core/...", mod + "/model"},
	}
	cases := []struct {
		name   string
		module string
		pkgs   []Package
		rules  []Rule
		want   []Violation
	}{
		{
			name:   "confine_violation",
			module: mod,
			pkgs: []Package{
				{ImportPath: mod + "/api", Imports: []string{"fmt", mod + "/secret/store"}},
			},
			rules: []Rule{confineSecret},
			want:  []Violation{{Rule: "confine-secret", Importer: mod + "/api", Imported: mod + "/secret/store"}},
		},
		{
			name:   "confine_allowed_importer",
			module: mod,
			pkgs: []Package{
				{ImportPath: mod + "/vault", Imports: []string{mod + "/secret"}},
				{ImportPath: mod + "/vault/sub", Imports: []string{mod + "/secret/store"}},
			},
			rules: []Rule{confineSecret},
			want:  nil,
		},
		{
			name:   "restrict_default_scope_is_module",
			module: mod,
			pkgs: []Package{
				{ImportPath: mod + "/core", Imports: []string{
					"fmt", "github.com/x/y", mod + "/core/inner", mod + "/model", mod + "/web",
				}},
			},
			rules: []Rule{restrictCore},
			want:  []Violation{{Rule: "restrict-core", Importer: mod + "/core", Imported: mod + "/web"}},
		},
		{
			name:   "restrict_scope_includes_module_root",
			module: mod,
			pkgs: []Package{
				{ImportPath: mod + "/core", Imports: []string{mod, "example.com/mx"}},
			},
			rules: []Rule{restrictCore},
			want:  []Violation{{Rule: "restrict-core", Importer: mod + "/core", Imported: mod}},
		},
		{
			name:   "restrict_explicit_scope_all",
			module: mod,
			pkgs: []Package{
				{ImportPath: mod + "/core", Imports: []string{"fmt", "github.com/x/y", mod + "/model", "net/http"}},
			},
			rules: []Rule{{
				Name: "pure-core", Kind: Restrict,
				From:           []string{mod + "/core"},
				Targets:        []string{"..."},
				AllowedTargets: []string{"std", mod + "/model"},
			}},
			want: []Violation{{Rule: "pure-core", Importer: mod + "/core", Imported: "github.com/x/y"}},
		},
		{
			name:   "restrict_explicit_scope_narrow",
			module: mod,
			pkgs: []Package{
				{ImportPath: mod + "/core", Imports: []string{"github.com/x/y", "github.com/z/w", mod + "/web"}},
			},
			rules: []Rule{{
				Name: "no-x", Kind: Restrict,
				From:    []string{mod + "/core"},
				Targets: []string{"github.com/x/..."},
			}},
			want: []Violation{{Rule: "no-x", Importer: mod + "/core", Imported: "github.com/x/y"}},
		},
		{
			name:   "restrict_importer_not_in_from",
			module: mod,
			pkgs: []Package{
				{ImportPath: mod + "/web", Imports: []string{mod + "/secret", "github.com/x/y"}},
			},
			rules: []Rule{restrictCore},
			want:  nil,
		},
		{
			name:   "out_of_module_importer_ignored",
			module: mod,
			pkgs: []Package{
				{ImportPath: "github.com/other/pkg", Imports: []string{mod + "/secret"}},
				{ImportPath: "example.com/mx", Imports: []string{mod + "/secret"}},
				{ImportPath: "example.com", Imports: []string{mod + "/secret"}},
				{ImportPath: mod, Imports: []string{mod + "/secret"}},
			},
			rules: []Rule{confineSecret},
			want:  []Violation{{Rule: "confine-secret", Importer: mod, Imported: mod + "/secret"}},
		},
		{
			name:   "duplicate_import_reported_once",
			module: mod,
			pkgs: []Package{
				{ImportPath: mod + "/api", Imports: []string{mod + "/secret", mod + "/secret"}},
				{ImportPath: mod + "/api", Imports: []string{mod + "/secret"}},
			},
			rules: []Rule{confineSecret, confineSecret},
			want:  []Violation{{Rule: "confine-secret", Importer: mod + "/api", Imported: mod + "/secret"}},
		},
		{
			name:   "output_sorted",
			module: mod,
			pkgs: []Package{
				{ImportPath: mod + "/web", Imports: []string{mod + "/secret/b", mod + "/secret/a"}},
				{ImportPath: mod + "/core", Imports: []string{mod + "/web"}},
				{ImportPath: mod + "/api", Imports: []string{mod + "/secret/b"}},
			},
			rules: []Rule{restrictCore, confineSecret},
			want: []Violation{
				{Rule: "confine-secret", Importer: mod + "/api", Imported: mod + "/secret/b"},
				{Rule: "confine-secret", Importer: mod + "/web", Imported: mod + "/secret/a"},
				{Rule: "confine-secret", Importer: mod + "/web", Imported: mod + "/secret/b"},
				{Rule: "restrict-core", Importer: mod + "/core", Imported: mod + "/web"},
			},
		},
		{
			name:   "stricter_rule_wins",
			module: mod,
			pkgs: []Package{
				// Allowed by restrict-core (core imports model), forbidden by the confine rule.
				{ImportPath: mod + "/core", Imports: []string{mod + "/model"}},
			},
			rules: []Rule{
				restrictCore,
				{
					Name: "confine-model", Kind: Confine,
					Targets:     []string{mod + "/model"},
					AllowedFrom: []string{mod + "/api"},
				},
			},
			want: []Violation{{Rule: "confine-model", Importer: mod + "/core", Imported: mod + "/model"}},
		},
		{
			name:   "no_violation_returns_nil",
			module: mod,
			pkgs: []Package{
				{ImportPath: mod + "/core", Imports: []string{"fmt", mod + "/model"}},
				{ImportPath: mod + "/vault", Imports: []string{mod + "/secret"}},
				{ImportPath: mod + "/model"},
			},
			rules: []Rule{restrictCore, confineSecret},
			want:  nil,
		},
		{
			name:   "no_package_returns_nil",
			module: mod,
			pkgs:   nil,
			rules:  []Rule{restrictCore, confineSecret},
			want:   nil,
		},
		{
			name:   "invalid_kind",
			module: mod,
			pkgs:   []Package{{ImportPath: mod + "/api", Imports: []string{mod + "/secret"}}},
			rules: []Rule{{
				Name: "bad-kind", Kind: RuleKind(7),
				Targets:     []string{mod + "/secret"},
				AllowedFrom: []string{mod + "/vault"},
			}},
			want: []Violation{{Rule: "bad-kind", Importer: "(invalid)", Imported: ""}},
		},
		{
			name:   "invalid_pattern",
			module: mod,
			pkgs:   []Package{{ImportPath: mod + "/a/x/b", Imports: []string{mod + "/secret"}}},
			rules: []Rule{{
				Name: "bad-pattern", Kind: Confine,
				Targets:     []string{mod + "/secret"},
				AllowedFrom: []string{"a/.../b"},
			}},
			want: []Violation{{Rule: "bad-pattern", Importer: "(invalid)", Imported: ""}},
		},
		{
			name:   "invalid_pattern_in_allowed_targets",
			module: mod,
			pkgs:   []Package{{ImportPath: mod + "/core", Imports: []string{mod + "/web"}}},
			rules: []Rule{{
				Name: "bad-allowed", Kind: Restrict,
				From:           []string{mod + "/core"},
				AllowedTargets: []string{mod + "/w*"},
			}},
			want: []Violation{{Rule: "bad-allowed", Importer: "(invalid)", Imported: ""}},
		},
		{
			name:   "empty_rule_name",
			module: mod,
			pkgs:   []Package{{ImportPath: mod + "/api", Imports: []string{mod + "/secret"}}},
			rules: []Rule{{
				Name: "", Kind: Confine,
				Targets:     []string{mod + "/secret"},
				AllowedFrom: []string{mod + "/vault"},
			}},
			want: []Violation{{Rule: "", Importer: "(invalid)", Imported: ""}},
		},
		{
			name:   "confine_without_targets",
			module: mod,
			pkgs:   []Package{{ImportPath: mod + "/api", Imports: []string{mod + "/secret"}}},
			rules:  []Rule{{Name: "no-targets", Kind: Confine, AllowedFrom: []string{mod + "/vault"}}},
			want:   []Violation{{Rule: "no-targets", Importer: "(invalid)", Imported: ""}},
		},
		{
			name:   "restrict_without_from",
			module: mod,
			pkgs:   []Package{{ImportPath: mod + "/core", Imports: []string{mod + "/web"}}},
			rules:  []Rule{{Name: "no-from", Kind: Restrict, AllowedTargets: []string{mod + "/model"}}},
			want:   []Violation{{Rule: "no-from", Importer: "(invalid)", Imported: ""}},
		},
		{
			name:   "invalid_rule_does_not_hide_valid_rule",
			module: mod,
			pkgs:   []Package{{ImportPath: mod + "/api", Imports: []string{mod + "/secret"}}},
			rules: []Rule{
				{Name: "no-targets", Kind: Confine, AllowedFrom: []string{mod + "/vault"}},
				confineSecret,
			},
			want: []Violation{
				{Rule: "confine-secret", Importer: mod + "/api", Imported: mod + "/secret"},
				{Rule: "no-targets", Importer: "(invalid)", Imported: ""},
			},
		},
		{
			name:   "empty_module",
			module: "",
			pkgs:   []Package{{ImportPath: mod + "/api", Imports: []string{mod + "/secret"}}},
			rules:  []Rule{confineSecret},
			want:   []Violation{{Rule: "(module)", Importer: "(invalid)", Imported: ""}},
		},
		{
			name:   "module_with_wildcard",
			module: "example.com/*",
			pkgs:   []Package{{ImportPath: mod + "/api", Imports: []string{mod + "/secret"}}},
			rules:  []Rule{confineSecret},
			want:   []Violation{{Rule: "(module)", Importer: "(invalid)", Imported: "example.com/*"}},
		},
		{
			name:   "module_with_ellipsis",
			module: "example.com/m/...",
			pkgs:   []Package{{ImportPath: mod + "/api", Imports: []string{mod + "/secret"}}},
			rules:  []Rule{confineSecret},
			want:   []Violation{{Rule: "(module)", Importer: "(invalid)", Imported: "example.com/m/..."}},
		},
		{
			name:   "module_trailing_slash",
			module: "example.com/m/",
			pkgs:   []Package{{ImportPath: mod + "/api", Imports: []string{mod + "/secret"}}},
			rules:  []Rule{confineSecret},
			want:   []Violation{{Rule: "(module)", Importer: "(invalid)", Imported: "example.com/m/"}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Check(c.module, c.pkgs, c.rules)
			expectViolations(t, got, c.want)
			if c.want == nil && got != nil {
				t.Errorf("Check returned a non-nil empty slice, want nil")
			}
		})
	}
}

// defaultRuleNames is the expected content of DefaultRules, in order.
func defaultRuleNames() []string {
	return []string{
		"domain-pure", "adapters-edge", "sdk-confine-anthropic", "sdk-confine-temporal",
		"sdk-confine-sql", "loops-agnostic", "fakes-wired-in-cmd",
	}
}

func TestDefaultRules(t *testing.T) {
	const m = modulePath
	rules := DefaultRules(m)
	byName := func(t *testing.T, name string) Rule {
		t.Helper()
		for _, r := range rules {
			if r.Name == name {
				return r
			}
		}
		t.Fatalf("DefaultRules has no rule named %q", name)
		return Rule{}
	}

	t.Run("names_and_kinds", func(t *testing.T) {
		kinds := []RuleKind{Restrict, Confine, Confine, Confine, Confine, Restrict, Confine}
		names := defaultRuleNames()
		if len(rules) != len(names) {
			t.Fatalf("DefaultRules returned %d rules, want %d (%q)", len(rules), len(names), names)
		}
		for i, r := range rules {
			if r.Name != names[i] || r.Kind != kinds[i] {
				t.Errorf("rule %d is %q (kind %d), want %q (kind %d)", i, r.Name, r.Kind, names[i], kinds[i])
			}
		}
		if Confine == Restrict {
			t.Errorf("Confine and Restrict have the same value %d", Confine)
		}
	})

	t.Run("all_rules_valid", func(t *testing.T) {
		if got := Check(m, nil, rules); got != nil {
			t.Errorf("Check on DefaultRules reports invalid rules:\n%s", formatViolations(got))
		}
		for _, r := range rules {
			for _, p := range rulePatterns(r) {
				if !validPattern(p) {
					t.Errorf("rule %s: pattern %q is not valid", r.Name, p)
				}
			}
		}
	})

	t.Run("critical_patterns", func(t *testing.T) {
		// Criterion 9 of prompts/M0.md: only the Anthropic adapter imports the SDK.
		sdk := byName(t, "sdk-confine-anthropic")
		if sdk.Kind != Confine {
			t.Errorf("sdk-confine-anthropic: kind %d, want Confine", sdk.Kind)
		}
		if want := []string{"github.com/anthropics/anthropic-sdk-go/..."}; !slices.Equal(sdk.Targets, want) {
			t.Errorf("sdk-confine-anthropic: Targets %q, want %q", sdk.Targets, want)
		}
		if want := []string{m + "/internal/llm/adapters/anthropic/..."}; !slices.Equal(sdk.AllowedFrom, want) {
			t.Errorf("sdk-confine-anthropic: AllowedFrom %q, want %q", sdk.AllowedFrom, want)
		}
		// Second half of criterion 9: no domain imports an adapter.
		edge := byName(t, "adapters-edge")
		if edge.Kind != Confine {
			t.Errorf("adapters-edge: kind %d, want Confine", edge.Kind)
		}
		if !slices.Contains(edge.Targets, m+"/internal/*/adapters/...") {
			t.Errorf("adapters-edge: Targets %q lack %q", edge.Targets, m+"/internal/*/adapters/...")
		}
		allowed := []string{m + "/cmd/...", m + "/internal/*/adapters/..."}
		for _, p := range edge.AllowedFrom {
			if !slices.Contains(allowed, p) {
				t.Errorf("adapters-edge: AllowedFrom has %q, only %q are permitted", p, allowed)
			}
		}
		// The loops trap of prompts/M0.md: internal/loops never imports a domain.
		loops := byName(t, "loops-agnostic")
		if loops.Kind != Restrict || len(loops.Targets) != 0 {
			t.Errorf("loops-agnostic: kind %d with Targets %q, want Restrict with module scope", loops.Kind, loops.Targets)
		}
		for _, forbidden := range []string{m + "/internal/llm", m + "/internal/graph", m + "/internal/llm/domain"} {
			for _, p := range loops.AllowedTargets {
				if Match(p, forbidden) {
					t.Errorf("loops-agnostic: allowed target %q lets internal/loops import %s", p, forbidden)
				}
			}
		}
	})

	t.Run("module_parameter", func(t *testing.T) {
		const other = "example.com/other"
		otherRules := DefaultRules(other)
		if len(otherRules) != len(defaultRuleNames()) {
			t.Fatalf("DefaultRules(%q) returned %d rules, want %d", other, len(otherRules), len(defaultRuleNames()))
		}
		thirdParty := []string{"std", "...", "github.com/", "go.temporal.io/", "database/sql/..."}
		for _, r := range otherRules {
			for _, p := range rulePatterns(r) {
				if strings.Contains(p, "amezianechayer") {
					t.Errorf("rule %s: pattern %q is bound to the real module", r.Name, p)
				}
				if strings.Contains(p, "/internal/") || strings.Contains(p, "/cmd/") {
					if !strings.HasPrefix(p, other+"/") {
						t.Errorf("rule %s: internal pattern %q does not start with %s/", r.Name, p, other)
					}
					continue
				}
				if !slices.ContainsFunc(thirdParty, func(prefix string) bool { return strings.HasPrefix(p, prefix) }) {
					t.Errorf("rule %s: pattern %q is neither internal nor a known external target", r.Name, p)
				}
			}
		}
	})
}

func TestRuleFixturesCoverDefaultRules(t *testing.T) {
	entries, err := fs.ReadDir(os.DirFS(fixtureDir), ".")
	if err != nil {
		t.Fatalf("%s: %v", fixtureDir, err)
	}
	violating := map[string]bool{}
	conforming := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		switch {
		case e.IsDir():
			t.Errorf("%s/%s: unexpected directory", fixtureDir, name)
		case strings.HasSuffix(name, violationSuffix):
			violating[strings.TrimSuffix(name, violationSuffix)] = true
		case strings.HasSuffix(name, conformingSuffix):
			conforming[strings.TrimSuffix(name, conformingSuffix)] = true
		default:
			t.Errorf("%s/%s: unexpected file (want <rule>%s or <rule>%s)", fixtureDir, name, violationSuffix, conformingSuffix)
		}
	}
	var names []string
	for _, r := range DefaultRules(modulePath) {
		names = append(names, r.Name)
		if !violating[r.Name] {
			t.Errorf("rule %s: missing fixture %s%s", r.Name, r.Name, violationSuffix)
		}
		if !conforming[r.Name] {
			t.Errorf("rule %s: missing fixture %s%s", r.Name, r.Name, conformingSuffix)
		}
	}
	if len(names) == 0 {
		t.Fatalf("DefaultRules(%q) is empty", modulePath)
	}
	for _, set := range []map[string]bool{violating, conforming} {
		for name := range set {
			if !slices.Contains(names, name) {
				t.Errorf("fixture for %q matches no rule of DefaultRules", name)
			}
		}
	}
}

func TestRuleDetectsViolation(t *testing.T) {
	const m = modulePath
	v := func(rule, importer, imported string) Violation {
		return Violation{Rule: rule, Importer: importer, Imported: imported}
	}
	// The list is coded here, never taken from DefaultRules: an empty rule list
	// must not make this test empty.
	cases := []struct {
		rule string
		want []Violation
	}{
		{"domain-pure", []Violation{
			v("domain-pure", m+"/internal/llm/domain", m+"/internal/tenancy"),
			v("domain-pure", m+"/internal/llm/domain", "github.com/santhosh-tekuri/jsonschema/v6"),
		}},
		{"adapters-edge", []Violation{
			v("adapters-edge", m+"/internal/llm", m+"/internal/llm/adapters/anthropic"),
			v("adapters-edge", m+"/internal/loops/demo", m+"/internal/secrets/adapters/openbao"),
		}},
		{"sdk-confine-anthropic", []Violation{
			v("sdk-confine-anthropic", m+"/cmd/rempart-worker", "github.com/anthropics/anthropic-sdk-go/option"),
			v("sdk-confine-anthropic", m+"/internal/llm", "github.com/anthropics/anthropic-sdk-go"),
		}},
		{"sdk-confine-temporal", []Violation{
			v("sdk-confine-temporal", m+"/internal/evals", "go.temporal.io/sdk/testsuite"),
			v("sdk-confine-temporal", m+"/internal/llm", "go.temporal.io/sdk/activity"),
			v("sdk-confine-temporal", m+"/internal/secrets/adapters/openbao", "go.temporal.io/api/common/v1"),
		}},
		{"sdk-confine-sql", []Violation{
			v("sdk-confine-sql", m+"/cmd/rempartd", "github.com/lib/pq"),
			v("sdk-confine-sql", m+"/internal/evidence/domain", "database/sql"),
			v("sdk-confine-sql", m+"/internal/graph", "github.com/jackc/pgx/v5/pgxpool"),
		}},
		{"loops-agnostic", []Violation{
			v("loops-agnostic", m+"/internal/loops", m+"/internal/llm"),
			v("loops-agnostic", m+"/internal/loops/codec", m+"/internal/graph"),
			v("loops-agnostic", m+"/internal/loops/domain", m+"/internal/llm/domain"),
		}},
		{"fakes-wired-in-cmd", []Violation{
			v("fakes-wired-in-cmd", m+"/internal/llm", m+"/internal/llm/fake"),
			v("fakes-wired-in-cmd", m+"/internal/loops/demo", m+"/internal/loops/fake"),
		}},
	}
	if len(cases) != len(defaultRuleNames()) {
		t.Fatalf("%d rule cases, want %d", len(cases), len(defaultRuleNames()))
	}
	rules := DefaultRules(m)
	for _, c := range cases {
		t.Run(c.rule, func(t *testing.T) {
			t.Run("violation", func(t *testing.T) {
				got := Check(m, loadFixture(t, c.rule+violationSuffix), rules)
				expectViolations(t, got, c.want)
				for _, g := range got {
					if g.Rule != c.rule {
						t.Errorf("fixture %s%s triggers rule %s, want only %s", c.rule, violationSuffix, g.Rule, c.rule)
					}
				}
			})
			t.Run("conforming", func(t *testing.T) {
				got := Check(m, loadFixture(t, c.rule+conformingSuffix), rules)
				if got != nil {
					t.Errorf("fixture %s%s: want no violation (nil), got:\n%s", c.rule, conformingSuffix, formatViolations(got))
				}
			})
		})
	}
}
