package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// TestRealMainExitCodes (risk 1, criterion 10): a refused command line exits
// with 2, reports on stderr only, and writes nothing on stdout.
func TestRealMainExitCodes(t *testing.T) {
	cases := []struct {
		name       string
		args       []string
		wantStderr string
	}{
		{"no_argument", nil, ""},
		{"fake_without_dev", []string{"-demo-once", "-llm=fake"}, "rempart-worker: -llm=fake requires -dev"},
		{"anthropic", []string{"-dev", "-demo-once", "-llm=anthropic"}, ""},
		{"unknown_flag", append(demoArgs(), "-anthropic-key=x"), ""},
		{"positional", append(demoArgs(), "x"), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := realMain(context.Background(), tc.args, &stdout, &stderr)
			if code != 2 {
				t.Errorf("realMain(%q) = %d, want 2", tc.args, code)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
			got := stderr.String()
			if got == "" || strings.Count(strings.TrimSuffix(got, "\n"), "\n") != 0 {
				t.Errorf("stderr = %q, want exactly one line", got)
			}
			if tc.wantStderr != "" && !strings.Contains(got, tc.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", got, tc.wantStderr)
			}
		})
	}
}
