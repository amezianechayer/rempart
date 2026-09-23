package archtest

import (
	"cmp"
	"slices"
	"strings"
)

// RuleKind is the kind of an import rule.
type RuleKind int

const (
	Confine  RuleKind = iota // only importers matching AllowedFrom may import a path matching Targets
	Restrict                 // importers matching From may import, among in-scope paths, only AllowedTargets
)

// Rule is an import rule. Patterns: exact path, "/..." suffix, "*" for exactly
// one segment, and the reserved patterns "std" (standard library) and "..."
// (any path). For a Restrict rule, Targets sets the controlled scope; empty,
// the scope is the module.
type Rule struct {
	Name                                       string
	Kind                                       RuleKind
	From, Targets, AllowedFrom, AllowedTargets []string
}

// Violation is one forbidden import. Importer "(invalid)" reports an invalid
// rule or module: a mistyped rule never silently checks nothing.
type Violation struct{ Rule, Importer, Imported string }

const (
	patternStd = "std"
	patternAll = "..."
	invalid    = "(invalid)"
)

// Match reports whether importPath matches pattern. An invalid pattern or a
// malformed path never matches.
func Match(pattern, importPath string) bool {
	if !validPattern(pattern) || !wellFormed(importPath) {
		return false
	}
	switch pattern {
	case patternStd:
		return isStdlib(importPath)
	case patternAll:
		return true
	}
	ps := strings.Split(pattern, "/")
	is := strings.Split(importPath, "/")
	subtree := ps[len(ps)-1] == patternAll
	if subtree {
		ps = ps[:len(ps)-1]
		if len(is) < len(ps) {
			return false
		}
	} else if len(is) != len(ps) {
		return false
	}
	for i, seg := range ps {
		if seg != "*" && seg != is[i] {
			return false
		}
	}
	return true
}

// Check returns the violations of rules by the in-module packages of pkgs,
// deduplicated and sorted by rule, importer and imported path; nil if none.
func Check(module string, pkgs []Package, rules []Rule) []Violation {
	if !validModule(module) {
		return []Violation{{Rule: "(module)", Importer: invalid, Imported: module}}
	}
	seen := map[Violation]bool{}
	var out []Violation
	add := func(v Violation) {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	var valid []Rule
	for _, r := range rules {
		if !validRule(r) {
			add(Violation{Rule: r.Name, Importer: invalid})
			continue
		}
		valid = append(valid, r)
	}
	for _, p := range pkgs {
		if !inModule(module, p.ImportPath) {
			continue
		}
		for _, imp := range p.Imports {
			for _, r := range valid {
				if violates(module, r, p.ImportPath, imp) {
					add(Violation{Rule: r.Name, Importer: p.ImportPath, Imported: imp})
				}
			}
		}
	}
	slices.SortFunc(out, func(a, b Violation) int {
		return cmp.Or(cmp.Compare(a.Rule, b.Rule), cmp.Compare(a.Importer, b.Importer), cmp.Compare(a.Imported, b.Imported))
	})
	return out
}

func violates(module string, r Rule, importer, imported string) bool {
	switch r.Kind {
	case Confine:
		return matchAny(r.Targets, imported) && !matchAny(r.AllowedFrom, importer)
	case Restrict:
		if !matchAny(r.From, importer) {
			return false
		}
		inScope := inModule(module, imported)
		if len(r.Targets) > 0 {
			inScope = matchAny(r.Targets, imported)
		}
		return inScope && !matchAny(r.AllowedTargets, imported)
	}
	return false
}

func matchAny(patterns []string, importPath string) bool {
	return slices.ContainsFunc(patterns, func(p string) bool { return Match(p, importPath) })
}

// DefaultRules returns the dependency rules R1 to R5 of docs/plans/M0-overview.md
// section 5.2, R3 split into one rule per SDK (docs/plans/M0-archtest-imports.md).
func DefaultRules(module string) []Rule {
	m := func(p string) string { return module + "/" + p }
	return []Rule{
		{ // R1
			Name: "domain-pure", Kind: Restrict,
			From:           []string{m("internal/*/domain/...")},
			Targets:        []string{patternAll},
			AllowedTargets: []string{patternStd, m("internal/*/domain/...")},
		},
		{ // R2
			Name: "adapters-edge", Kind: Confine,
			Targets:     []string{m("internal/*/adapters/...")},
			AllowedFrom: []string{m("cmd/..."), m("internal/*/adapters/...")},
		},
		{ // R3, criterion 9 of prompts/M0.md (ADR 0002)
			Name: "sdk-confine-anthropic", Kind: Confine,
			Targets:     []string{"github.com/anthropics/anthropic-sdk-go/..."},
			AllowedFrom: []string{m("internal/llm/adapters/anthropic/...")},
		},
		{ // R3
			Name: "sdk-confine-temporal", Kind: Confine,
			Targets:     []string{"go.temporal.io/sdk/...", "go.temporal.io/api/..."},
			AllowedFrom: []string{m("internal/loops/..."), m("cmd/...")},
		},
		{ // R3: every SQL access goes through an adapter (threat T23)
			Name: "sdk-confine-sql", Kind: Confine,
			Targets: []string{
				"database/sql/...", "github.com/jackc/pgx/...",
				"github.com/jackc/pgconn/...", "github.com/lib/pq/...",
			},
			AllowedFrom: []string{m("internal/*/adapters/...")},
		},
		{ // R4
			Name: "loops-agnostic", Kind: Restrict,
			From: []string{
				m("internal/loops"), m("internal/loops/domain/..."),
				m("internal/loops/codec/..."), m("internal/loops/fake/..."),
			},
			AllowedTargets: []string{
				m("internal/loops"), m("internal/loops/domain/..."),
				m("internal/loops/codec/..."), m("internal/loops/fake/..."),
				m("internal/tenancy"), m("internal/secrets/secret"),
				m("internal/secrets/ports"), m("internal/secrets/envelope"),
			},
		},
		{ // R5
			Name: "fakes-wired-in-cmd", Kind: Confine,
			Targets:     []string{m("internal/*/fake/...")},
			AllowedFrom: []string{m("cmd/...")},
		},
	}
}

// isStdlib reports whether the first path segment is non-empty and has no dot.
func isStdlib(importPath string) bool {
	first, _, _ := strings.Cut(importPath, "/")
	return first != "" && !strings.Contains(first, ".")
}

// inModule reports whether importPath is module or one of its packages.
func inModule(module, importPath string) bool {
	return importPath == module || strings.HasPrefix(importPath, module+"/")
}

// validPattern reports whether p is "std", "...", or a well-formed path whose
// wildcard segments are exactly "*", with "..." only as the last segment.
func validPattern(p string) bool {
	if p == patternStd || p == patternAll {
		return true
	}
	if !wellFormed(p) {
		return false
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if strings.Contains(s, "*") && s != "*" {
			return false
		}
		if strings.Contains(s, patternAll) && (s != patternAll || i != len(segs)-1) {
			return false
		}
	}
	return true
}

// wellFormed: non-empty, no leading or trailing slash, no empty segment.
func wellFormed(p string) bool {
	return p != "" && !slices.Contains(strings.Split(p, "/"), "")
}

// validModule: well-formed, no wildcard, and a dot in the first segment, so that
// no package of the module is ever taken for the standard library.
func validModule(module string) bool {
	if !wellFormed(module) || strings.Contains(module, "*") || strings.Contains(module, patternAll) {
		return false
	}
	return !isStdlib(module)
}

func validRule(r Rule) bool {
	if r.Name == "" {
		return false
	}
	switch r.Kind {
	case Confine:
		if len(r.Targets) == 0 {
			return false
		}
	case Restrict:
		if len(r.From) == 0 {
			return false
		}
	default:
		return false
	}
	for _, list := range [][]string{r.From, r.Targets, r.AllowedFrom, r.AllowedTargets} {
		if !slices.ContainsFunc(list, func(p string) bool { return !validPattern(p) }) {
			continue
		}
		return false
	}
	return true
}
