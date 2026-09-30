package llm

import (
	"errors"
	"math"
	"testing"

	"pgregory.net/rapid"

	"github.com/amezianechayer/rempart/internal/llm/domain"
)

// M0-T03b step B, plan docs/plans/M0-pile-dev-harden.md D8, obligation (be),
// threat T10: the usage a provider declares is untrusted. A negative count
// would lower the bound a loop budget charges, an oversized one would
// overflow it; either fails the call as a provider failure, charged like a
// failed call (MaxTokens plus the request bytes), the declared counts dropped.

// maxReported is MaxReportedTokens of the plan (1 << 24), written here as a
// literal so that the other tests of the package run before the constant exists.
const maxReported = 1 << 24

// wantInvalidUsage checks the failure of a call whose last declared usage is
// invalid: ErrProviderFailed with its fixed message, the usage of the previous
// calls only, Bound = prior + MaxTokens + request bytes of the last call.
func wantInvalidUsage(t *testing.T, e env, o outcome, calls int, prior domain.Usage) {
	t.Helper()
	assertFailed(t, o, ErrProviderFailed)
	ue := usageErr(t, o.err, ErrProviderFailed)
	if got := o.err.Error(); got != "llm: provider call failed" {
		t.Errorf("message %q, want %q", got, "llm: provider call failed")
	}
	reqs := e.fake.Requests()
	if len(reqs) != calls || e.fake.Invocations() != calls {
		t.Fatalf("%d requests, %d invocations; want %d provider calls", len(reqs), e.fake.Invocations(), calls)
	}
	if ue.Usage != prior {
		t.Errorf("Usage = %+v, want %+v (the invalid counts are not added)", ue.Usage, prior)
	}
	if want := prior.InputTokens + prior.OutputTokens + 256 + wantRequestBytes(reqs[calls-1]); ue.Bound != want {
		t.Errorf("Bound = %d, want %d (prior usage + MaxTokens 256 + request bytes)", ue.Bound, want)
	}
}

func TestUsageRejectsInvalidCounts(t *testing.T) {
	oneCorrection := Config{MaxCorrections: 1, MaxTokensPerCall: 256, AllowFakeRoute: true}
	invalid := func(t *testing.T, m method, in, out int) {
		t.Helper()
		e := newEnv(t, oneCorrection, policyPA(), usageStep(string(valueV), modelV1, in, out))
		o := m.run(e.c, ctxFor(t, tenantA), call0(t))
		wantInvalidUsage(t, e, o, 1, domain.Usage{})
	}

	t.Run("negative_usage", func(t *testing.T) {
		for _, m := range bothMethods() {
			t.Run(m.name, func(t *testing.T) {
				t.Run("input", func(t *testing.T) { invalid(t, m, -1, 5) })
				t.Run("output", func(t *testing.T) { invalid(t, m, 5, -1) })
				t.Run("both", func(t *testing.T) { invalid(t, m, -1, -1) })
				t.Run("min_int", func(t *testing.T) { invalid(t, m, math.MinInt, 0) })
			})
		}
	})

	t.Run("oversized", func(t *testing.T) {
		for _, m := range bothMethods() {
			t.Run(m.name, func(t *testing.T) {
				t.Run("input", func(t *testing.T) { invalid(t, m, maxReported+1, 0) })
				t.Run("output", func(t *testing.T) { invalid(t, m, 0, maxReported+1) })
				t.Run("max_int", func(t *testing.T) { invalid(t, m, math.MaxInt, math.MaxInt) })
			})
		}
	})

	t.Run("at_cap", func(t *testing.T) {
		for _, u := range []domain.Usage{{InputTokens: maxReported}, {OutputTokens: maxReported}, {InputTokens: maxReported, OutputTokens: maxReported}} {
			e := newEnv(t, oneCorrection, policyPA(), usageStep(string(valueV), modelV1, u.InputTokens, u.OutputTokens))
			o := structuredM().run(e.c, ctxFor(t, tenantA), call0(t))
			assertOK(t, o)
			if o.res.Trace.Usage != u {
				t.Errorf("Trace.Usage = %+v, want %+v", o.res.Trace.Usage, u)
			}
		}
	})

	t.Run("negative_after_correction", func(t *testing.T) {
		e := newEnv(t, oneCorrection, policyPA(),
			usageStep(`{"greeting":1}`, modelV1, 10, 5), usageStep(string(valueV), modelV1, -1, 0))
		o := structuredM().run(e.c, ctxFor(t, tenantA), call0(t))
		wantInvalidUsage(t, e, o, 2, domain.Usage{InputTokens: 10, OutputTokens: 5})
	})

	// The usage check comes before the model check: a negative count under a
	// foreign model must not lower the bound through ErrModelMismatch.
	t.Run("negative_with_model_mismatch", func(t *testing.T) {
		e := newEnv(t, oneCorrection, policyPA(), usageStep(string(valueV), "fake-model-other", -1000, 5))
		o := structuredM().run(e.c, ctxFor(t, tenantA), call0(t))
		wantInvalidUsage(t, e, o, 1, domain.Usage{})
	})

	// Property: whatever the declared counts, the call succeeds with exactly
	// those counts if both are in [0, maxReported], and otherwise fails as a
	// provider failure with a bound at least MaxTokens; the bound is never
	// negative.
	t.Run("property", func(t *testing.T) {
		count := rapid.OneOf(
			rapid.IntRange(-3, 3), rapid.IntRange(maxReported-2, maxReported+2),
			rapid.Just(math.MinInt), rapid.Just(math.MaxInt), rapid.Int(),
		)
		rapid.Check(t, func(rt *rapid.T) {
			in, out := count.Draw(rt, "input"), count.Draw(rt, "output")
			e := newEnv(t, oneCorrection, policyPA(), usageStep(string(valueV), modelV1, in, out))
			o := structuredM().run(e.c, ctxFor(t, tenantA), call0(t))
			valid := in >= 0 && out >= 0 && in <= maxReported && out <= maxReported
			switch {
			case valid && o.err != nil:
				rt.Fatalf("usage (%d, %d) refused: %v", in, out, o.err)
			case valid && o.res.Trace.Usage != (domain.Usage{InputTokens: in, OutputTokens: out}):
				rt.Fatalf("usage (%d, %d) traced as %+v", in, out, o.res.Trace.Usage)
			case !valid && o.err == nil:
				rt.Fatalf("usage (%d, %d) accepted", in, out)
			case !valid:
				var ue *UsageError
				if !errors.As(o.err, &ue) || ue.Bound < 256 || ue.Usage != (domain.Usage{}) {
					rt.Fatalf("usage (%d, %d): error %v, UsageError %+v; want Bound >= 256 and no usage", in, out, o.err, ue)
				}
			}
		})
	})
}
