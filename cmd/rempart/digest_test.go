package main

import (
	"encoding/json"
	"testing"

	"github.com/amezianechayer/rempart/internal/design/confirm"
)

// TestDesignDigestCommand proves ADR 0012 D3 (verifications 6 and 7): rempart
// design --digest writes the confirmation digest of an IR, built with the
// default options of L2, the same bytes from one run to the next; an option
// of the plan or another output mode with --digest is a usage error.
func TestDesignDigestCommand(t *testing.T) {
	r := runCLI("design", "--digest", referenceIRPath)
	if r.code != 0 {
		t.Fatalf("design --digest: code %d, stderr %q", r.code, r.stderr)
	}
	var d confirm.Digest
	if err := json.Unmarshal([]byte(r.stdout), &d); err != nil {
		t.Fatalf("output %q: %v", r.stdout, err)
	}
	if d.Subject != "ir" || len(d.SubjectSHA256) != 64 || len(d.Exposures) != 1 || d.Exposures[0].Target != "lb:app-cluster-443" || !d.Exposures[0].World {
		t.Fatalf("digest %+v", d)
	}
	if again := runCLI("design", "--digest", referenceIRPath); again.stdout != r.stdout {
		t.Errorf("two runs differ")
	}
	for _, args := range [][]string{
		{"design", "--digest", "--superblock", "10.0.0.0/8", referenceIRPath},
		{"design", "--digest", "--reserve", "10.1.0.0/16", referenceIRPath},
		{"design", "--digest", "--growth", "2", referenceIRPath},
		{"design", "--digest", "--json", referenceIRPath},
		{"design", "--digest", "--cidr-only", referenceIRPath},
	} {
		if r := runCLI(args...); r.code != 2 || r.stdout != "" {
			t.Errorf("%v: code %d, stdout %q; want 2 (usage)", args, r.code, r.stdout)
		}
	}
}
