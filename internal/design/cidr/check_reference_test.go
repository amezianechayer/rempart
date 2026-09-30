package cidr_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/amezianechayer/rempart/internal/design/cidr"
	loopsdomain "github.com/amezianechayer/rempart/internal/loops/domain"
)

// goldenCases are the cases of plan section 9. Each <case>.want.json is the
// output of the reference script, never written by hand. Regenerate with
// (Python 3.11.15, 2026-09-30), from internal/design/cidr/testdata/golden:
//
//	python3 ../../../../../.claude/skills/multicloud-networking/scripts/cidr_check.py <case>.plan.json > <case>.want.json
//
// (exit status 0 without finding, 1 otherwise).
var goldenCases = []string{
	"valid_reference",
	"valid_nested",
	"overlap_siblings",
	"duplicate_sibling",
	"child_overlaps_parent_only",
	"outside_parent",
	"unknown_parent",
	"outside_superblock",
	"not_private",
	"overlap_external",
	"invalid_host_bits",
}

// key is the part of a finding compared with the reference script: messages
// are free text and differ by language.
type key struct{ Code, Severity, Resource, Source string }

func keys(f []loopsdomain.Finding) []key {
	out := make([]key, 0, len(f))
	for _, x := range f {
		out = append(out, key{x.Code, string(x.Severity), x.Resource, x.Source})
	}
	slices.SortFunc(out, func(a, b key) int { return strings.Compare(fmt.Sprint(a), fmt.Sprint(b)) })
	return out
}

func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := fs.ReadFile(os.DirFS(filepath.Join("testdata", "golden")), name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestCheckMatchesReference proves plan P7: the Go verifier reports the same
// findings as .claude/skills/multicloud-networking/scripts/cidr_check.py on
// every golden case, and is stricter on the two documented divergences.
func TestCheckMatchesReference(t *testing.T) {
	for _, name := range goldenCases {
		t.Run(name, func(t *testing.T) {
			var want []loopsdomain.Finding
			if err := json.Unmarshal(readGolden(t, name+".want.json"), &want); err != nil {
				t.Fatalf("decode want: %v", err)
			}
			got, err := cidr.CheckReference(readGolden(t, name+".plan.json"))
			if err != nil {
				t.Fatalf("CheckReference: %v", err)
			}
			if g, w := keys(got), keys(want); !slices.Equal(g, w) {
				t.Fatalf("findings (code, severity, resource, source):\n got %v\nwant %v", g, w)
			}
			if !slices.Equal(got, loopsdomain.Sort(got)) {
				t.Fatalf("findings not sorted by loopsdomain.Sort: %+v", got)
			}
		})
	}

	// Plan P7: Go accepts RFC 1918 only (Python's is_private also accepts
	// special ranges such as 192.0.2.0/24) and refuses IPv6.
	t.Run("divergence", func(t *testing.T) {
		raw := []byte(`{"superblock": "10.0.0.0/8", "networks": [
			{"name": "vpc-a", "cidr": "10.1.0.0/16"},
			{"name": "test-net", "cidr": "192.0.2.0/24"},
			{"name": "ula", "cidr": "fd00::/8"}
		], "external": []}`)
		got, err := cidr.CheckReference(raw)
		if err != nil {
			t.Fatalf("CheckReference: %v", err)
		}
		k := keys(got)
		for _, w := range []key{
			{"CIDR_NOT_PRIVATE", "high", "test-net", "cidr_check"},
			{"CIDR_INVALID", "critical", "ula", "cidr_check"},
		} {
			if !slices.Contains(k, w) {
				t.Errorf("missing %v in %v", w, k)
			}
		}
		for _, x := range got {
			if x.Resource == "vpc-a" {
				t.Errorf("finding on the valid network vpc-a: %+v", x)
			}
		}
	})

	// The Plan entry point reports the same rule on the same kind of plan.
	t.Run("plan_overlap_external", func(t *testing.T) {
		p, err := cidr.Allocate(referenceRequest())
		if err != nil {
			t.Fatal(err)
		}
		if f := cidr.Check(p); len(f) != 0 {
			t.Fatalf("Check(reference plan) = %+v, want none", f)
		}
		p.External = append(p.External, p.Networks[0].Prefix)
		if k := keys(cidr.Check(p)); !slices.Contains(k, key{"CIDR_OVERLAP_EXTERNAL", "critical", p.Networks[0].Name + "|reserved-1", "cidr_check"}) {
			t.Fatalf("Check with a reserved range on the first VPC: %v", k)
		}
	})

	t.Run("malformed_input_refused", func(t *testing.T) {
		for name, raw := range map[string][]byte{
			"unknown_key": []byte(`{"superblock": "10.0.0.0/8", "networks": [], "external": [], "extra": 1}`),
			"not_json":    []byte(`{"superblock": `),
			"oversized":   append([]byte(`{"superblock": "10.0.0.0/8", "networks": [], "external": []}`), bytes.Repeat([]byte(" "), 1<<20)...),
		} {
			if f, err := cidr.CheckReference(raw); err == nil {
				t.Errorf("%s: CheckReference = %+v, nil; want an error", name, f)
			}
		}
	})
}
