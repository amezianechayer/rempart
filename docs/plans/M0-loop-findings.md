# M0-T13 `loop-findings` : findings normalisés, empreinte, score

2026-09-24, `architect`, proposé. Fiche `docs/plans/M0-overview.md` (M0-T13). Aucun ADR.

## 0. Amendements

- V1 (2026-09-24, `test-author`, étape A2) : mutations M6 et M10 réécrites pour compiler, même sens : M6 `NEW` = `_ = strconv.AppendInt` (T3, T4 échouent), M10 `NEW` = `_ = x; total++` (T5, T6 échouent). `findings.go` et les tests inchangés ; 10 mutations sur 10 détectées.

## 1. Objet
Fonctions pures de `normalized-findings.md` (skill `loop-engineering`), base de la stagnation de T14. Fichiers : `internal/loops/domain/{findings.go,findings_test.go}`, `docs/STATUS.md`. `internal/loops/` ne contient que `doc.go`. R1 ne contrôle que les imports non test : `rapid` permis en test.

## 2. Décisions
| # | Décision |
|---|---|
| D1 | `Weight` : 100, 20, 5, 1, 0 ; toute autre valeur (`""`, `CRITICAL`) : 100. |
| D2 | `Sort` : copie. Clés : poids décroissant, puis `Severity`, `File`, `Line`, `Code`, `Resource`, `Source`, `Message` croissants : ordre total, indépendant de l'entrée. |
| D3 | `Top` : `nil` si `n <= 0`, sinon `Sort(f)[:min(n, len(f))]`. |
| D4 | `Fingerprint` : couples (`Code`, `Resource`) de poids `>= 5` (inconnue comprise), triés, **dédoublonnés** : un doublon instable (Checkov et Trivy) ne masque pas la stagnation. |
| D5 | Encodage netstring `<longueur>:<octets>,` (code puis ressource), SHA-256 hex : aucun `\|`, `,` ni saut de ligne ne forge de frontière. `int64(len)` évite G115. |
| D6 | Aucun couple : SHA-256 de l'entrée vide (`e3b0c442...b855`). |
| D7 | `Score` : somme, doublons compris ; poids de 0 à 100 : débordement d'`int` 64 bits au-delà de 9e16 findings, impossible en mémoire. |

## 3. Code de référence (normatif ; ancres de la section 6 au caractère près)
`internal/loops/domain/findings.go` :
```go
// Package domain holds the pure types of the generic loop engine: normalized
// findings, their fingerprint and their score.
package domain

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
)

// Severity is a normalized severity; any other value weighs as critical.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Finding is one normalized verifier finding. Every field is untrusted.
type Finding struct {
	Code     string   `json:"code"`
	Source   string   `json:"source"`
	Severity Severity `json:"severity"`
	Resource string   `json:"resource"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Message  string   `json:"message"`
}

// Weight returns the score weight of s.
func (s Severity) Weight() int {
	switch s {
	case SeverityCritical:
		return 100
	case SeverityHigh:
		return 20
	case SeverityMedium:
		return 5
	case SeverityLow:
		return 1
	case SeverityInfo:
		return 0
	default:
		return 100 // unknown severity: fail safe
	}
}

// Sort returns a sorted copy of f under a total order (weight descending).
func Sort(f []Finding) []Finding {
	out := slices.Clone(f)
	slices.SortFunc(out, compareFindings)
	return out
}

func compareFindings(a, b Finding) int {
	return cmp.Or(
		cmp.Compare(b.Severity.Weight(), a.Severity.Weight()),
		cmp.Compare(a.Severity, b.Severity),
		cmp.Compare(a.File, b.File),
		cmp.Compare(a.Line, b.Line),
		cmp.Compare(a.Code, b.Code),
		cmp.Compare(a.Resource, b.Resource),
		cmp.Compare(a.Source, b.Source),
		cmp.Compare(a.Message, b.Message),
	)
}

// Top returns the first n findings of Sort(f), none if n <= 0.
func Top(f []Finding, n int) []Finding {
	if n <= 0 {
		return nil
	}
	s := Sort(f)
	return s[:min(n, len(s))]
}

// Score returns the sum of the weights of f, duplicates included.
func Score(f []Finding) int {
	total := 0
	for _, x := range f {
		total += x.Severity.Weight()
	}
	return total
}

// Fingerprint returns the hex SHA-256 of the sorted distinct (code, resource)
// netstrings of the findings weighing at least medium.
func Fingerprint(f []Finding) string {
	type couple struct{ code, resource string }
	var cs []couple
	for _, x := range f {
		if x.Severity.Weight() >= SeverityMedium.Weight() {
			cs = append(cs, couple{x.Code, x.Resource})
		}
	}
	slices.SortFunc(cs, func(a, b couple) int {
		return cmp.Or(cmp.Compare(a.code, b.code), cmp.Compare(a.resource, b.resource))
	})
	cs = slices.Compact(cs)
	var buf []byte
	for _, c := range cs {
		buf = appendNetstring(appendNetstring(buf, c.code), c.resource)
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}

func appendNetstring(buf []byte, s string) []byte {
	buf = strconv.AppendInt(buf, int64(len(s)), 10)
	buf = append(buf, ':')
	buf = append(buf, s...)
	return append(buf, ',')
}
```

## 4. Tests (`test-author`, `findings_test.go`, T1 à T8 dans l'ordre)
```go
package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"regexp"
	"slices"
	"testing"

	"pgregory.net/rapid"
)

const emptyFP = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func genFinding() *rapid.Generator[Finding] {
	return rapid.Custom(func(rt *rapid.T) Finding {
		pick := func(l string, vs ...string) string { return rapid.SampledFrom(vs).Draw(rt, l) }
		return Finding{
			Code:     pick("code", "A", "B", "A|B", "1:a,"),
			Source:   pick("source", "checkov", "trivy"),
			Severity: Severity(pick("sev", "critical", "high", "medium", "low", "info", "", "urgent")),
			Resource: pick("resource", "r1", "r2", "r|1", "r\n2"),
			File:     pick("file", "a.tf", "b.tf"),
			Line:     rapid.IntRange(0, 3).Draw(rt, "line"),
			Message:  pick("message", "m", "n"),
		}
	})
}

func high(pairs ...string) []Finding {
	var f []Finding
	for i := 0; i+1 < len(pairs); i += 2 {
		f = append(f, Finding{Code: pairs[i], Resource: pairs[i+1], Severity: SeverityHigh})
	}
	return f
}

func TestFingerprintOrderIndependent(t *testing.T) {
	a := Finding{Code: "A", Resource: "r1", Severity: SeverityHigh}
	b := Finding{Code: "B", Resource: "r2", Severity: SeverityMedium}
	if Fingerprint([]Finding{a, b}) != Fingerprint([]Finding{b, a}) ||
		Fingerprint([]Finding{a, b, a}) != Fingerprint([]Finding{a, b}) {
		t.Fatal("order or duplicates matter")
	}
	rapid.Check(t, func(rt *rapid.T) {
		f := rapid.SliceOfN(genFinding(), 0, 12).Draw(rt, "f")
		want := Fingerprint(f)
		if Fingerprint(rapid.Permutation(f).Draw(rt, "perm")) != want {
			rt.Fatal("permutation changed it")
		}
		o := slices.Clone(f)
		for i := range o {
			o[i].Source, o[i].File, o[i].Line, o[i].Message = "x", "x", 9, "x"
			if o[i].Severity.Weight() >= 5 {
				o[i].Severity = SeverityCritical
			}
		}
		if len(f) > 0 {
			o = append(o, o[rapid.IntRange(0, len(f)-1).Draw(rt, "dup")])
		}
		if Fingerprint(o) != want {
			rt.Fatal("duplicate or non-key field changed it")
		}
	})
}

func TestFingerprintIgnoresLowAndInfo(t *testing.T) {
	base := []Finding{{Code: "CKV_AWS_20", Resource: "aws_s3_bucket.logs", Severity: SeverityMedium}}
	want := Fingerprint(base)
	if want == emptyFP {
		t.Fatal("medium must count")
	}
	noise := []Finding{{Code: "L", Resource: "r", Severity: SeverityLow}, {Code: "I", Severity: SeverityInfo}}
	if Fingerprint(append(slices.Clone(base), noise...)) != want {
		t.Error("low or info changed it")
	}
	for _, f := range [][]Finding{nil, {}, noise} {
		if got := Fingerprint(f); got != emptyFP {
			t.Errorf("Fingerprint(%v) = %s, want %s", f, got, emptyFP)
		}
	}
}

func TestFingerprintChangesWithCodeOrResource(t *testing.T) {
	cases := [][2][]Finding{
		{high("c1", "r"), high("c2", "r")},
		{high("c", "r1"), high("c", "r2")},
		{high("a", "b"), high("b", "a")},
		{high("ab", "c"), high("a", "bc")},
		{high("a|b", "c"), high("a", "b|c")},
		{high("a", "b\na|c"), high("a", "b", "a", "c")},
		{high("a", "b,:c,:d"), high("a", "b", "c", "d")},
		{high("a", "b"), high("a", "b", "a", "c")},
		{nil, high("", "")},
	}
	for i, c := range cases {
		if Fingerprint(c[0]) == Fingerprint(c[1]) {
			t.Errorf("case %d: collision", i)
		}
	}
}

func TestFingerprintFormat(t *testing.T) {
	sum := func(s string) string {
		h := sha256.Sum256([]byte(s))
		return hex.EncodeToString(h[:])
	}
	one := []Finding{{Code: "a", Resource: "b", Severity: SeverityCritical}}
	two := append(slices.Clone(one), Finding{Code: "c", Severity: SeverityMedium})
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for _, c := range []struct {
		f    []Finding
		want string
	}{{nil, emptyFP}, {one, sum("1:a,1:b,")}, {two, sum("1:a,1:b,1:c,0:,")}} {
		if got := Fingerprint(c.f); !hex64.MatchString(got) || got != c.want {
			t.Errorf("Fingerprint(%v) = %q, want %q", c.f, got, c.want)
		}
	}
}

func TestScoreWeights(t *testing.T) {
	want := map[Severity]int{SeverityCritical: 100, SeverityHigh: 20, SeverityMedium: 5, SeverityLow: 1, SeverityInfo: 0}
	var all []Finding
	for s, w := range want {
		if s.Weight() != w {
			t.Errorf("%q.Weight() = %d, want %d", s, s.Weight(), w)
		}
		all = append(all, Finding{Severity: s})
	}
	if Score(nil) != 0 || Score(all) != 126 || Score(high("a", "r", "a", "r")) != 40 {
		t.Error("Score is not the sum of weights")
	}
}

func TestUnknownSeverityCountsAsCritical(t *testing.T) {
	crit := []Finding{{Code: "a", Resource: "r", Severity: SeverityCritical}}
	for _, s := range []Severity{"", "urgent", "CRITICAL", "High", "medium "} {
		f := []Finding{{Code: "a", Resource: "r", Severity: s}}
		if s.Weight() != 100 || Score(f) != 100 || Fingerprint(f) != Fingerprint(crit) {
			t.Errorf("%q does not count as critical", s)
		}
		if Sort(append(f, high("b", "r")...))[0].Severity != s {
			t.Errorf("%q sorted after high", s)
		}
	}
}

func TestSortOrder(t *testing.T) {
	c, h := SeverityCritical, SeverityHigh
	want := []Finding{
		{Code: "C", Severity: c, File: "a.tf", Line: 1},
		{Code: "C", Severity: c, File: "a.tf", Line: 2},
		{Code: "C", Severity: c, File: "b.tf", Line: 1},
		{Code: "U", Severity: "urgent", File: "a.tf", Line: 1},
		{Code: "H1", Severity: h, File: "a.tf"},
		{Code: "H2", Severity: h, File: "a.tf"},
		{Code: "H2", Severity: h, File: "a.tf", Resource: "r"},
		{Code: "H2", Severity: h, File: "a.tf", Resource: "r", Source: "s"},
		{Code: "H2", Severity: h, File: "a.tf", Resource: "r", Source: "s", Message: "m"},
		{Code: "M", Severity: SeverityMedium, File: "a.tf"},
		{Code: "L", Severity: SeverityLow},
		{Code: "I", Severity: SeverityInfo, File: "a.tf"},
	}
	in := slices.Clone(want)
	slices.Reverse(in)
	snapshot := slices.Clone(in)
	if got := Sort(in); !slices.Equal(got, want) {
		t.Errorf("Sort = %v, want %v", got, want)
	}
	if !slices.Equal(in, snapshot) {
		t.Error("Sort modified its input")
	}
	rapid.Check(t, func(rt *rapid.T) {
		f := rapid.SliceOfN(genFinding(), 0, 12).Draw(rt, "f")
		s := Sort(f)
		if !slices.Equal(Sort(rapid.Permutation(f).Draw(rt, "perm")), s) {
			rt.Fatal("order is not total")
		}
		for i := 1; i < len(s); i++ {
			if s[i-1].Severity.Weight() < s[i].Severity.Weight() {
				rt.Fatalf("weight increases at %d", i)
			}
		}
	})
}

func TestTopN(t *testing.T) {
	f := []Finding{
		{Code: "L", Severity: SeverityLow},
		{Code: "C", Severity: SeverityCritical},
		{Code: "M", Severity: SeverityMedium},
		{Code: "H", Severity: SeverityHigh},
	}
	snapshot := slices.Clone(f)
	sorted := Sort(f)
	for _, c := range []struct{ n, want int }{{-1, 0}, {0, 0}, {1, 1}, {2, 2}, {4, 4}, {5, 4}, {math.MaxInt, 4}} {
		if got := Top(f, c.n); !slices.Equal(got, sorted[:c.want]) {
			t.Errorf("Top(f, %d) = %v, want %v", c.n, got, sorted[:c.want])
		}
	}
	if len(Top(nil, 3)) != 0 {
		t.Error("Top(nil, 3) not empty")
	}
	top := Top(f, 1)
	top[0].Code = "X"
	if !slices.Equal(f, snapshot) || top[0].Code != "X" {
		t.Error("Top modified or aliased its input")
	}
}
```

## 5. Critères d'acceptation
| # | Commande | Attendu |
|---|---|---|
| 1 | `go test ./internal/loops/domain/ -count=1 -v 2>&1 \| grep -cE '^--- PASS: Test'` ; idem `grep -cE -- '--- (FAIL\|SKIP)'` | `8` ; `0` |
| 2 | `go test ./internal/loops/domain/ -count=1 -race -rapid.checks=2000; echo rc=$?` | `rc=0` |
| 3 | `go list -f '{{join .Imports " "}}' ./internal/loops/domain` | `cmp crypto/sha256 encoding/hex slices strconv` |
| 4 | `golangci-lint run ./internal/loops/domain/...; echo rc=$?` | `rc=0` |
| 5 | `grep -rnE 'panic\(\|func init\(\|nolint\|#nosec' internal/loops/domain \| wc -l` | `0` |
| 6 | `go test ./internal/archtest/ -count=1 -run TestRepositoryConforms; echo rc=$?` | `rc=0` |
| 7 | `make verify-quick; echo rc=$?` | `rc=0` |

## 6. Mutations sur copie
Script de `docs/plans/M0-tenancy.md` 8.3 sur `findings.go` ; `OLD` présent une fois ; Tn en `--- FAIL`.

| # | `OLD` | `NEW` | Tn |
|---|---|---|---|
| M1 | `return 100 // unknown severity: fail safe` | `return 0` | T6 |
| M2 | `if x.Severity.Weight() >= SeverityMedium.Weight() {` | `>` au lieu de `>=` | T2 |
| M3 | idem | `SeverityLow` au lieu de `SeverityMedium` | T2 |
| M4 | `cs = slices.Compact(cs)` | vide | T1 |
| M5 | `return cmp.Or(cmp.Compare(a.code, b.code), cmp.Compare(a.resource, b.resource))` | `return 0` | T1 |
| M6 | `buf = strconv.AppendInt(buf, int64(len(s)), 10)` | vide | T3, T4 |
| M7 | `out := slices.Clone(f)` | `out := f` | T7 |
| M8 | `cmp.Compare(a.Code, b.Code),` | vide | T7 |
| M9 | `if n <= 0 {` | `if false {` | T8 (panique) |
| M10 | `total += x.Severity.Weight()` | `total++` | T5 |

## 7. Risques, menaces, obligations
Risques : gravité hors empreinte (conforme au skill ; T14 croise avec `Score`) ; empreinte vide répétée sur un échec sans finding medium : stagnation en T14 (échec sûr, à tester) ; changer l'encodage casse le rejeu Temporal.

Menaces : aucune nouvelle ; T10 renforcé (doublon instable, séparateur forgé, gravité inconnue : T1, T3, T6).

`docs/STATUS.md` : pour T14, D4, D6, recalcul par `RunLoop` ; pour T19, compléter `normalized-findings.md` (netstring, dédoublonnage, ordre total, gravité inconnue), modification de skill signalée.

## 8. Tâches ordonnées
| # | Tâche | Qui | Vérification |
|---|---|---|---|
| A1 | `phase tests`, `findings_test.go` (section 4) | `test-author` | `go vet` : `undefined:` ou `no non-test Go files` seulement |
| A2 | Copie : section 3, critères 1 à 5, M1 à M10 | `test-author` | vert, 10 détectées ; sinon amendement section 0 |
| A3 | `git add internal/loops/domain/`, `phase impl` | principal | `Phase : tests -> impl` |
| I1 | `findings.go` (section 3) | principal | critères 1 à 7 |
| F1 | M1 à M10 sur copie finale, `acceptance-verifier` | principal, subagent | PASS |
| F2 | `docs/STATUS.md`, `phase free`, commit `feat(loops): normalized findings fingerprint and score (M0-T13)` | principal | `git status --porcelain` vide |
