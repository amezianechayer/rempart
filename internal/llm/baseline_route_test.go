package llm

import (
	"errors"
	"testing"

	"github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

// realPolicy is a real route admitted by CheckPolicy: OpenRouter, synthetic
// data only (ADR 0008).
func realPolicy() domain.TenantPolicy {
	return domain.TenantPolicy{
		Route:     domain.Route{Platform: domain.PlatformOpenRouter, Model: "openai/gpt-4o-2024-08-06"},
		Residency: domain.ResidencyNone, Retention: domain.RetentionStandard,
	}
}

// TestRouteWithoutBaselineRejected (D8, ADR 0006): a real route absent from
// Config.ValidatedPairs is refused before any provider call; listed, it
// reaches the provider. The fake route stays under AllowFakeRoute only.
func TestRouteWithoutBaselineRejected(t *testing.T) {
	pol := realPolicy()
	pair := Pair{Platform: pol.Route.Platform, Model: pol.Route.Model}
	for name, pairs := range map[string][]Pair{
		"no_registry":    nil,
		"other_model":    {{Platform: domain.PlatformOpenRouter, Model: "anthropic/claude-sonnet-4.5"}},
		"other_platform": {{Platform: domain.PlatformAnthropic, Model: pol.Route.Model}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t, stepV())
			rr := countingStatic(t, map[tenancy.ID]domain.TenantPolicy{tenantA: pol})
			cfg := configK()
			cfg.ValidatedPairs = pairs
			c := mustClient(t, f, rr, cfg)
			o := structuredM().run(c, ctxFor(t, tenantA), call0(t))
			if !errors.Is(o.err, ErrRouteWithoutBaseline) || f.Invocations() != 0 {
				t.Errorf("error %v with %d provider calls, want ErrRouteWithoutBaseline and none", o.err, f.Invocations())
			}
		})
	}
	t.Run("listed", func(t *testing.T) {
		f := newFake(t, stepV())
		rr := countingStatic(t, map[tenancy.ID]domain.TenantPolicy{tenantA: pol})
		cfg := configK()
		cfg.ValidatedPairs = []Pair{pair}
		c := mustClient(t, f, rr, cfg)
		o := structuredM().run(c, ctxFor(t, tenantA), call0(t))
		if errors.Is(o.err, ErrRouteWithoutBaseline) || f.Invocations() != 1 {
			t.Errorf("error %v with %d provider calls, want the provider reached", o.err, f.Invocations())
		}
	})
	t.Run("fake_route_unchanged", func(t *testing.T) {
		e := newEnv(t, configK(), policyPA(), stepV())
		if o := structuredM().run(e.c, ctxFor(t, tenantA), call0(t)); o.err != nil {
			t.Errorf("fake route with AllowFakeRoute: %v", o.err)
		}
	})
	t.Run("invalid_pair", func(t *testing.T) {
		cfg := configK()
		cfg.ValidatedPairs = []Pair{{Platform: domain.PlatformFake, Model: modelV1}}
		if _, err := NewClient(newFake(t), countingStatic(t, nil), promptFS(), cfg); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("NewClient with a fake pair: %v, want ErrInvalidConfig", err)
		}
		cfg.ValidatedPairs = []Pair{{Platform: domain.PlatformOpenRouter}}
		if _, err := NewClient(newFake(t), countingStatic(t, nil), promptFS(), cfg); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("NewClient with an empty model: %v, want ErrInvalidConfig", err)
		}
	})
}
