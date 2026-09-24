package llm

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

// Test 7.
func TestNoRouteNoCall(t *testing.T) {
	for _, m := range bothMethods() {
		t.Run("tenant without route, "+m.name, func(t *testing.T) {
			e := newEnv(t, configK(), policyPA(), stepV())
			assertNoCall(t, e, m.run(e.c, ctxFor(t, tenantC), call0(t)), domain.ErrNoRoute)
		})
	}
	t.Run("resolver failure is opaque", func(t *testing.T) {
		cause := errors.New("resolver down")
		rr := countingFunc(func(context.Context, tenancy.ID) (domain.TenantPolicy, error) {
			return domain.TenantPolicy{}, cause
		})
		f := newFake(t, stepV())
		e := env{fake: f, rr: rr, c: mustClient(t, f, rr, configK())}
		o := structuredM().run(e.c, ctxFor(t, tenantA), call0(t))
		assertNoCall(t, e, o, domain.ErrNoRoute, cause)
		if o.err != nil && o.err.Error() != domain.ErrNoRoute.Error() {
			t.Errorf("error message = %q, want %q", o.err.Error(), domain.ErrNoRoute.Error())
		}
	})
	t.Run("resolver failure with a policy", func(t *testing.T) {
		rr := countingFunc(func(context.Context, tenancy.ID) (domain.TenantPolicy, error) {
			return policyPA(), errors.New("partial answer")
		})
		f := newFake(t, stepV())
		e := env{fake: f, rr: rr, c: mustClient(t, f, rr, configK())}
		assertNoCall(t, e, structuredM().run(e.c, ctxFor(t, tenantA), call0(t)), domain.ErrNoRoute)
	})
	t.Run("zero policy without error", func(t *testing.T) {
		rr := countingFunc(func(context.Context, tenancy.ID) (domain.TenantPolicy, error) {
			return domain.TenantPolicy{}, nil
		})
		f := newFake(t, stepV())
		e := env{fake: f, rr: rr, c: mustClient(t, f, rr, configK())}
		o := structuredM().run(e.c, ctxFor(t, tenantA), call0(t))
		assertNoCall(t, e, o)
		domainErrs := []error{domain.ErrResidency, domain.ErrRetention, domain.ErrInvalidRoute, domain.ErrModelNotPinned}
		matched := false
		for _, d := range domainErrs {
			matched = matched || errors.Is(o.err, d)
		}
		if !matched {
			t.Errorf("error = %v, want a policy error of domain", o.err)
		}
	})
	t.Run("resolver sees the tenant of the context", func(t *testing.T) {
		var seen []tenancy.ID
		var mu sync.Mutex
		rr := countingFunc(func(_ context.Context, id tenancy.ID) (domain.TenantPolicy, error) {
			mu.Lock()
			defer mu.Unlock()
			seen = append(seen, id)
			return policyPA(), nil
		})
		f := newFake(t, stepV())
		assertOK(t, structuredM().run(mustClient(t, f, rr, configK()), ctxFor(t, tenantB), call0(t)))
		mu.Lock()
		defer mu.Unlock()
		if !reflect.DeepEqual(seen, []tenancy.ID{tenantB}) {
			t.Errorf("Resolve tenants = %v, want [%s]", seen, tenantB)
		}
	})
}

// Test 8.
func TestRetentionZeroRejectsRetentionModel(t *testing.T) {
	refused := map[string]domain.TenantPolicy{
		"model requiring retention": fakePolicy(modelRetain, domain.RetentionZero),
		"unknown model":             fakePolicy("fake-model-unknown", domain.RetentionZero),
	}
	for name, pol := range refused {
		for _, m := range bothMethods() {
			t.Run(name+", "+m.name, func(t *testing.T) {
				e := newEnv(t, configK(), pol, step(string(valueV), pol.Route.Model))
				assertNoCall(t, e, m.run(e.c, ctxFor(t, tenantA), call0(t)), domain.ErrRetention)
			})
		}
	}
	t.Run("standard retention accepts it", func(t *testing.T) {
		pol := fakePolicy(modelRetain, domain.RetentionStandard)
		e := newEnv(t, configK(), pol, step(string(valueV), modelRetain))
		o := structuredM().run(e.c, ctxFor(t, tenantA), call0(t))
		assertOK(t, o)
		if o.res.Trace.Model != modelRetain {
			t.Errorf("Trace.Model = %q, want %q", o.res.Trace.Model, modelRetain)
		}
	})
}

// Test 9.
func TestModelMismatchRejected(t *testing.T) {
	for _, declared := range []string{"fake-model-v2", "", "Fake-model-v1", modelV1 + " ", modelRetain} {
		for _, m := range bothMethods() {
			t.Run("declared "+declared+", "+m.name, func(t *testing.T) {
				cfg := configK()
				cfg.MaxCorrections = 3
				e := newEnv(t, cfg, policyPA(), repeatStep(step(string(valueV), declared), 4)...)
				assertFailed(t, m.run(e.c, ctxFor(t, tenantA), call0(t)), ErrModelMismatch)
				if n := e.fake.Invocations(); n != 1 {
					t.Errorf("provider invocations = %d, want 1 (no correction)", n)
				}
			})
		}
	}
}

// Test 10 (threat T3): run under -race.
func TestCrossTenantRouteIsolation(t *testing.T) {
	routes := map[tenancy.ID]domain.Route{
		tenantA: {Platform: domain.PlatformFake, Model: "fake-model-a"},
		tenantB: {Platform: domain.PlatformFake, Model: "fake-model-b"},
	}
	policies := map[tenancy.ID]domain.TenantPolicy{}
	for id, r := range routes {
		policies[id] = domain.TenantPolicy{Route: r, Residency: domain.ResidencyEU, Retention: domain.RetentionZero}
	}
	s := &spy{}
	c := mustClient(t, s, countingStatic(t, policies), configK())

	const n = 64
	tenants := make([]tenancy.ID, n)
	results := make([]outcome, n)
	call := call0(t)
	var wg sync.WaitGroup
	for i := range n {
		tenants[i] = tenantA
		if i%2 == 1 {
			tenants[i] = tenantB
		}
		ctx := ctxFor(t, tenants[i])
		wg.Add(1)
		go func() {
			defer wg.Done()
			m := structuredM()
			if i%4 >= 2 {
				m = withToolsM([]domain.ToolSpec{toolT()})
			}
			results[i] = m.run(c, ctx, call)
		}()
	}
	wg.Wait()

	for i, o := range results {
		if o.err != nil {
			t.Errorf("call %d: unexpected error %v", i, o.err)
			continue
		}
		want := routes[tenants[i]]
		if o.res.Trace.Tenant != tenants[i] || o.res.Trace.Model != want.Model || o.res.Trace.Platform != want.Platform {
			t.Errorf("call %d: trace = %+v, want tenant %s and model %s", i, o.res.Trace, tenants[i], want.Model)
		}
	}
	perModel := map[string]int{}
	for _, sc := range s.Calls() {
		if want, ok := routes[sc.tenant]; !ok || sc.route != want {
			t.Errorf("provider got route %+v under tenant %q, want the route of that tenant", sc.route, sc.tenant)
		}
		perModel[sc.route.Model]++
	}
	if perModel["fake-model-a"] != n/2 || perModel["fake-model-b"] != n/2 || len(perModel) != 2 {
		t.Errorf("calls per model = %v, want %d each", perModel, n/2)
	}
}

// Test 11.
func TestTraceCarriesRoute(t *testing.T) {
	if got := reflect.TypeFor[Trace]().NumField(); got != 10 {
		t.Errorf("Trace has %d fields, want exactly 10", got)
	}
	for _, m := range bothMethods() {
		t.Run(m.name, func(t *testing.T) {
			s := &spy{}
			rr := countingStatic(t, map[tenancy.ID]domain.TenantPolicy{tenantA: policyB3()})
			c := mustClient(t, s, rr, Config{MaxTokensPerCall: 256})
			o := m.run(c, ctxFor(t, tenantA), call0(t))
			assertOK(t, o)
			want := Trace{
				Tenant:     tenantA,
				Platform:   domain.PlatformBedrock,
				Region:     "eu-west-3",
				Model:      modelB3,
				PromptID:   greetingID,
				PromptHash: hashH(t),
				RequestID:  "spy-req-1",
				Attempts:   1,
				Redactions: 0,
				Usage:      domain.Usage{InputTokens: 12, OutputTokens: 5},
			}
			if o.res.Trace != want {
				t.Errorf("trace = %+v, want %+v", o.res.Trace, want)
			}
			calls := s.Calls()
			if len(calls) != 1 {
				t.Fatalf("provider saw %d calls, want 1", len(calls))
			}
			rh := domain.RequestHash(calls[0].req)
			if o.res.Trace.RequestID == rh || o.res.Trace.PromptHash == rh {
				t.Errorf("trace carries the request hash %s", rh)
			}
			v := reflect.ValueOf(o.res.Trace)
			for i := range v.NumField() {
				if f := v.Field(i); f.Kind() == reflect.String && f.String() == rh {
					t.Errorf("trace field %s carries the request hash", v.Type().Field(i).Name)
				}
			}
			if calls[0].req.PromptHash != hashH(t) || calls[0].req.PromptID != greetingID {
				t.Errorf("request = %+v, want prompt %s pinned to H", calls[0].req, greetingID)
			}
		})
	}
}

// Test 12 (threat T40).
func TestServicePassesCheckedRoute(t *testing.T) {
	t.Run("the checked route is the one called, at every attempt", func(t *testing.T) {
		seq := &seqResolver{pols: []domain.TenantPolicy{
			policyPA(),
			fakePolicy(modelRetain, domain.RetentionZero),
		}}
		rr := &countingResolver{inner: seq}
		f := newFake(t, step(`{"greeting":1}`, modelV1), stepV(), stepV())
		cfg := configK()
		cfg.MaxCorrections = 1
		c := mustClient(t, f, rr, cfg)

		assertOK(t, structuredM().run(c, ctxFor(t, tenantA), call0(t)))
		if n := rr.Count(); n != 1 {
			t.Errorf("Resolve count = %d for one service call, want 1", n)
		}
		calls := f.Calls()
		if len(calls) != 2 {
			t.Fatalf("provider saw %d calls, want 2", len(calls))
		}
		for i, fc := range calls {
			if fc.Route != policyPA().Route {
				t.Errorf("attempt %d: route = %+v, want %+v", i+1, fc.Route, policyPA().Route)
			}
		}

		o := structuredM().run(c, ctxFor(t, tenantA), call0(t))
		assertFailed(t, o, domain.ErrRetention)
		if n := f.Invocations(); n != 2 {
			t.Errorf("provider invocations = %d after a refused route, want still 2", n)
		}
		if n := rr.Count(); n != 2 {
			t.Errorf("Resolve count = %d after two service calls, want 2", n)
		}
	})
	t.Run("a resolver changing its answer cannot redirect the call", func(t *testing.T) {
		seq := &seqResolver{pols: []domain.TenantPolicy{
			policyB3(),
			{Route: domain.Route{Platform: domain.PlatformAnthropic, Model: "claude-sonnet-4-20250514"}, Residency: domain.ResidencyNone, Retention: domain.RetentionStandard},
		}}
		s := &spy{}
		cfg := configK()
		cfg.MaxCorrections = 3
		c := mustClient(t, s, seq, cfg)
		assertOK(t, structuredM().run(c, ctxFor(t, tenantA), call0(t)))
		for _, sc := range s.Calls() {
			if sc.route != routeB3() {
				t.Errorf("route = %+v, want %+v", sc.route, routeB3())
			}
		}
	})
	for _, m := range bothMethods() {
		t.Run("spy, B3, "+m.name, func(t *testing.T) {
			s := &spy{}
			rr := countingStatic(t, map[tenancy.ID]domain.TenantPolicy{tenantA: policyB3()})
			assertOK(t, m.run(mustClient(t, s, rr, configK()), ctxFor(t, tenantA), call0(t)))
			calls := s.Calls()
			if len(calls) != 1 {
				t.Fatalf("provider saw %d calls, want 1", len(calls))
			}
			got, want := calls[0].route, routeB3()
			if got.Platform != want.Platform || got.Region != want.Region || got.Model != want.Model {
				t.Errorf("route = %+v, want %+v field by field", got, want)
			}
			if calls[0].tenant != tenantA {
				t.Errorf("provider context tenant = %q, want %q", calls[0].tenant, tenantA)
			}
		})
	}
}

// Test 13 (threat T41).
func TestFakeRouteRefusedByDefault(t *testing.T) {
	noFake := Config{MaxTokensPerCall: 256}
	for _, m := range bothMethods() {
		t.Run("fake route refused, "+m.name, func(t *testing.T) {
			e := newEnv(t, noFake, policyPA(), stepV())
			assertNoCall(t, e, m.run(e.c, ctxFor(t, tenantA), call0(t)), ErrFakeRouteRefused)
		})
		t.Run("fake route with a region refused, "+m.name, func(t *testing.T) {
			pol := policyPA()
			pol.Route.Region = "eu-west-3"
			e := newEnv(t, noFake, pol, stepV())
			assertNoCall(t, e, m.run(e.c, ctxFor(t, tenantA), call0(t)), ErrFakeRouteRefused)
		})
		t.Run("real route accepted without the option, "+m.name, func(t *testing.T) {
			s := &spy{}
			rr := countingStatic(t, map[tenancy.ID]domain.TenantPolicy{tenantA: policyB3()})
			assertOK(t, m.run(mustClient(t, s, rr, noFake), ctxFor(t, tenantA), call0(t)))
			if n := len(s.Calls()); n != 1 {
				t.Errorf("provider saw %d calls, want 1", n)
			}
		})
		t.Run("fake route accepted with the option, "+m.name, func(t *testing.T) {
			e := newEnv(t, configK(), policyPA(), stepV())
			assertOK(t, m.run(e.c, ctxFor(t, tenantA), call0(t)))
			if n := e.fake.Invocations(); n != 1 {
				t.Errorf("provider invocations = %d, want 1", n)
			}
		})
	}
	t.Run("the option lifts no other check", func(t *testing.T) {
		e := newEnv(t, configK(), fakePolicy(modelRetain, domain.RetentionZero), step(string(valueV), modelRetain))
		assertNoCall(t, e, structuredM().run(e.c, ctxFor(t, tenantA), call0(t)), domain.ErrRetention)
		pol := policyPA()
		pol.Residency = ""
		e = newEnv(t, configK(), pol, stepV())
		assertNoCall(t, e, structuredM().run(e.c, ctxFor(t, tenantA), call0(t)), domain.ErrResidency)
	})
}
