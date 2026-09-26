package fake

import (
	"context"
	"errors"
	"testing"

	"github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

const (
	tenantA tenancy.ID = "0f8fad5b-d9cb-469f-a165-70867728950e"
	tenantB tenancy.ID = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
	tenantC tenancy.ID = "1b4e28ba-2fa1-41d2-883f-0016d3cca427"
)

func policyA() domain.TenantPolicy {
	return domain.TenantPolicy{Route: fakeRoute(), Residency: domain.ResidencyEU, Retention: domain.RetentionZero}
}

func policyB() domain.TenantPolicy {
	return domain.TenantPolicy{
		Route:     domain.Route{Platform: domain.PlatformAnthropic, Model: "claude-sonnet-4-20250514"},
		Residency: domain.ResidencyNone,
		Retention: domain.RetentionStandard,
	}
}

func mustResolver(t *testing.T, policies map[tenancy.ID]domain.TenantPolicy) *StaticResolver {
	t.Helper()
	r, err := NewStaticResolver(policies)
	if err != nil {
		t.Fatalf("NewStaticResolver: %v", err)
	}
	if r == nil {
		t.Fatal("NewStaticResolver: nil resolver without error")
	}
	return r
}

func assertNoRoute(t *testing.T, pol domain.TenantPolicy, err error, also ...error) {
	t.Helper()
	if !errors.Is(err, domain.ErrNoRoute) {
		t.Errorf("error = %v, want ErrNoRoute", err)
	}
	for _, w := range also {
		if !errors.Is(err, w) {
			t.Errorf("error = %v, want it to match %v too", err, w)
		}
	}
	if pol != (domain.TenantPolicy{}) {
		t.Errorf("policy = %+v with an error, want zero", pol)
	}
}

// Test 7.
func TestStaticResolverUnknownTenant(t *testing.T) {
	ctx := context.Background()
	source := map[tenancy.ID]domain.TenantPolicy{tenantA: policyA(), tenantB: policyB()}
	r := mustResolver(t, source)

	t.Run("each tenant gets its own policy", func(t *testing.T) {
		pol, err := r.Resolve(ctx, tenantA)
		if err != nil || pol != policyA() {
			t.Errorf("Resolve(A) = %+v, %v, want policy A", pol, err)
		}
		pol, err = r.Resolve(ctx, tenantB)
		if err != nil || pol != policyB() {
			t.Errorf("Resolve(B) = %+v, %v, want policy B", pol, err)
		}
	})

	t.Run("absent tenant", func(t *testing.T) {
		pol, err := r.Resolve(ctx, tenantC)
		assertNoRoute(t, pol, err)
	})

	t.Run("nil map", func(t *testing.T) {
		pol, err := mustResolver(t, nil).Resolve(ctx, tenantA)
		assertNoRoute(t, pol, err)
	})

	t.Run("nil receiver", func(t *testing.T) {
		var nilResolver *StaticResolver
		pol, err := nilResolver.Resolve(ctx, tenantA)
		assertNoRoute(t, pol, err)
	})

	invalid := map[string]tenancy.ID{
		"empty":           "",
		"upper-case UUID": "0F8FAD5B-D9CB-469F-A165-70867728950E",
	}
	for name, id := range invalid {
		t.Run("invalid tenant "+name, func(t *testing.T) {
			pol, err := r.Resolve(ctx, id)
			assertNoRoute(t, pol, err, tenancy.ErrInvalidTenant)
		})
	}

	t.Run("source map mutation has no effect", func(t *testing.T) {
		source[tenantA] = policyB()
		delete(source, tenantB)
		source[tenantC] = policyA()
		pol, err := r.Resolve(ctx, tenantA)
		if err != nil || pol != policyA() {
			t.Errorf("Resolve(A) = %+v, %v, want the original policy A", pol, err)
		}
		pol, err = r.Resolve(ctx, tenantB)
		if err != nil || pol != policyB() {
			t.Errorf("Resolve(B) = %+v, %v, want policy B still there", pol, err)
		}
		pol, err = r.Resolve(ctx, tenantC)
		assertNoRoute(t, pol, err)
	})

	t.Run("cancelled context", func(t *testing.T) {
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		pol, err := r.Resolve(cancelled, tenantA)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error = %v, want context.Canceled", err)
		}
		if pol != (domain.TenantPolicy{}) {
			t.Errorf("policy = %+v on a cancelled context, want zero", pol)
		}
	})
}

// Test 8.
func TestNewStaticResolverValidatesKeys(t *testing.T) {
	keys := map[string]tenancy.ID{
		"not a UUID": "tenant-a",
		"empty":      "",
		"nil UUID":   "00000000-0000-0000-0000-000000000000",
	}
	for name, id := range keys {
		t.Run(name, func(t *testing.T) {
			r, err := NewStaticResolver(map[tenancy.ID]domain.TenantPolicy{tenantA: policyA(), id: policyB()})
			if !errors.Is(err, ErrInvalidOptions) || !errors.Is(err, tenancy.ErrInvalidTenant) {
				t.Errorf("error = %v, want ErrInvalidOptions and tenancy.ErrInvalidTenant", err)
			}
			if r != nil {
				t.Error("resolver returned with an error")
			}
		})
	}

	t.Run("system tenant accepted", func(t *testing.T) {
		r := mustResolver(t, map[tenancy.ID]domain.TenantPolicy{tenancy.System: policyA()})
		pol, err := r.Resolve(context.Background(), tenancy.System)
		if err != nil || pol != policyA() {
			t.Errorf("Resolve(System) = %+v, %v, want policy A", pol, err)
		}
	})
}
