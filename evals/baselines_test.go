package evals_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/amezianechayer/rempart/evals"
	"github.com/amezianechayer/rempart/internal/llm"
	"github.com/amezianechayer/rempart/internal/llm/domain"
)

// TestValidatedPairs (D8): the registry is read from the embedded baselines,
// per suite; an unknown suite has no pair; an invalid suite name is refused.
func TestValidatedPairs(t *testing.T) {
	got, err := evals.ValidatedPairs("demo")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(got, llm.Pair{Platform: domain.PlatformFake, Model: "fake-model-v1"}) {
		t.Errorf("demo pairs %+v, want the fake baseline", got)
	}
	if got, err := evals.ValidatedPairs("intent"); err != nil || !slices.Contains(got, llm.Pair{Platform: domain.PlatformFake, Model: "fake-model-v1"}) {
		t.Errorf("intent pairs %+v, %v; want the fake baseline committed by the human (H3-intent)", got, err)
	}
	if got, err := evals.RealPairs("intent"); err != nil || slices.ContainsFunc(got, func(p llm.Pair) bool { return p.Platform == domain.PlatformFake }) {
		t.Errorf("intent real pairs %+v, %v; want the validated pairs without the fake route", got, err)
	}
	if got, err := evals.ValidatedPairs("nosuchsuite"); err != nil || len(got) != 0 {
		t.Errorf("unknown suite pairs %+v, %v; want none", got, err)
	}
	for _, bad := range []string{"", "..", "demo/baseline", "Demo"} {
		if _, err := evals.ValidatedPairs(bad); !errors.Is(err, evals.ErrInvalidSuite) {
			t.Errorf("suite %q: %v, want ErrInvalidSuite", bad, err)
		}
	}
}

// TestDecodeBaselinePath: a path is admitted only if evals.BaselinePath gives
// it back for the decoded model (encoding of ':', '@' and '/').
func TestDecodeBaselinePath(t *testing.T) {
	cases := []struct {
		path string
		want llm.Pair
		ok   bool
	}{
		{"intent/baseline/openrouter/deepseek%2fdeepseek-chat.json", llm.Pair{Platform: domain.PlatformOpenRouter, Model: "deepseek/deepseek-chat"}, true},
		{"intent/baseline/selfhosted/qwen2.5%40r1.json", llm.Pair{Platform: domain.PlatformSelfHosted, Model: "qwen2.5@r1"}, true},
		{"intent/baseline/openrouter/deepseek/deepseek-chat.json", llm.Pair{}, false},
		{"intent/baseline/fake/Upper.json", llm.Pair{}, false},
		{"intent/baseline/fake/m.txt", llm.Pair{}, false},
		{"intent/baseline/fake/m%2fx.json", llm.Pair{}, false},
	}
	for _, tc := range cases {
		got, err := evals.DecodeBaselinePath(tc.path)
		if tc.ok != (err == nil) || got != tc.want {
			t.Errorf("%s: %+v, %v; want %+v, ok %v", tc.path, got, err, tc.want, tc.ok)
		}
	}
}
