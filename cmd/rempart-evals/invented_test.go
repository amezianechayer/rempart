package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	intentdomain "github.com/amezianechayer/rempart/internal/intent/domain"
)

// Review of M1-T06 (high): invented_values is measured on the delivered IR by
// an oracle of the evaluation command (CODEOWNERS), independent of the checks
// of internal/intent that let the IR through.

func referenceIRFor(t *testing.T) intentdomain.IR {
	t.Helper()
	var ir intentdomain.IR
	if err := json.Unmarshal(intentFixture(t, "reference-ir.json"), &ir); err != nil {
		t.Fatal(err)
	}
	return ir
}

// TestInventedOracle: the reference IR has no invented value; a count, a
// region, a classification, a budget or an environment that the user never
// wrote is counted, unless an assumption declares it.
func TestInventedOracle(t *testing.T) {
	request := string(intentFixture(t, "reference-request.txt"))
	if n := inventedValues(request, referenceIRFor(t)); n != 0 {
		t.Fatalf("reference IR: %d invented values, want 0", n)
	}
	cases := map[string]func(*intentdomain.IR){
		"node_count": func(ir *intentdomain.IR) { seven := 7; ir.Workloads[0].Size.Count = &seven },
		"region": func(ir *intentdomain.IR) {
			ir.Workloads[0].Region = "eu-central-1"
		},
		"classification": func(ir *intentdomain.IR) { ir.Data[0].Classification = "internal" },
		"budget":         func(ir *intentdomain.IR) { b := 9999.0; ir.Constraints.MonthlyBudgetEUR = &b },
		"environment": func(ir *intentdomain.IR) {
			ir.Environment = "prod"
		},
		"cloud":      func(ir *intentdomain.IR) { ir.Workloads[0].Cloud = "scaleway" },
		"port":       func(ir *intentdomain.IR) { ir.Connectivity[0].Ports = []string{"tcp/22"} },
		"compliance": func(ir *intentdomain.IR) { ir.Compliance = append(ir.Compliance, "dora") },
	}
	for name, edit := range cases {
		ir := referenceIRFor(t)
		edit(&ir)
		if n := inventedValues(request, ir); n < 1 {
			t.Errorf("%s: %d invented values, want at least 1", name, n)
		}
	}
	declared := referenceIRFor(t)
	seven := 7
	declared.Workloads[0].Size.Count = &seven
	declared.Assumptions = append(declared.Assumptions, intentdomain.Assumption{Field: "workloads[app-cluster].size.count", Value: "7", Rationale: "x"})
	if n := inventedValues(request, declared); n != 0 {
		t.Errorf("value declared in assumptions: %d invented values, want 0", n)
	}
	asked := referenceIRFor(t)
	asked.Environment = "prod"
	asked.OpenQuestions = []intentdomain.Question{{Field: "environment", Question: "?", Default: "prod"}}
	if n := inventedValues(request, asked); n != 0 {
		t.Errorf("value asked as an open question: %d invented values, want 0", n)
	}
	src, err := os.ReadFile("invented.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"intentdomain.Check", "intent.ParseDraft", "InventedValues(", "controlledValues"} {
		if strings.Contains(string(src), banned) {
			t.Errorf("invented.go uses %s: the oracle must not reuse the checks it measures", banned)
		}
	}
}

// TestInventedOracleSources (review of the M1 milestone, T102): an allowed
// source is stated when the request writes the prefix, or the address of a
// /32 or /128; another address or prefix is invented.
func TestInventedOracleSources(t *testing.T) {
	request := string(intentFixture(t, "reference-request.txt")) +
		" Accès depuis 203.0.113.10, 2001:db8::10 et 198.51.100.0/24 seulement (source=192.0.2.7)."
	for sources, want := range map[string]int{
		"203.0.113.10/32":                 0,
		"2001:db8::10/128":                0,
		"198.51.100.0/24":                 0,
		"192.0.2.7/32":                    0,
		"203.0.113.11/32":                 1,
		"203.0.113.0/24":                  1,
		"198.51.100.0/25":                 1,
		"203.0.113.1/32":                  1,
		"203.0.113.10/32 198.51.100.7/32": 1,
		"2001:db8::/32":                   1,
	} {
		ir := referenceIRFor(t)
		ir.Exposure[0].AllowedSources = strings.Fields(sources)
		if n := inventedValues(request, ir); n != want {
			t.Errorf("sources %q: %d invented values, want %d", sources, n, want)
		}
	}
}
