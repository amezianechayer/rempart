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
