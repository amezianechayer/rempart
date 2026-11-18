package calibration_test

import (
	"context"
	"errors"
	"testing"
	"testing/fstest"

	"github.com/amezianechayer/rempart/internal/llm"
	"github.com/amezianechayer/rempart/internal/llm/calibration"
	"github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/llm/fake"
	"github.com/amezianechayer/rempart/internal/llm/prompts"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

const (
	tenant   tenancy.ID = "0f8fad5b-d9cb-469f-a165-70867728950e"
	promptID string     = "test.calibration.v1"
)

var promptFS = fstest.MapFS{
	promptID + "/system.txt":  {Data: []byte("Reply with a JSON greeting.\n")},
	promptID + "/schema.json": {Data: []byte(`{"type":"object","properties":{"greeting":{"type":"string"}},"required":["greeting"],"additionalProperties":false}`)},
}

// reached reports whether a call on c, for a tenant routed to r, reached the
// provider, and the error.
func reached(t *testing.T, cfg llm.Config, calibrated, r domain.Route) (bool, error) {
	t.Helper()
	p, err := prompts.LoadFS(promptFS, promptID)
	if err != nil {
		t.Fatal(err)
	}
	f, err := fake.New(fake.Options{})
	if err != nil {
		t.Fatal(err)
	}
	rr, err := fake.NewStaticResolver(map[tenancy.ID]domain.TenantPolicy{tenant: {Route: r, Residency: domain.ResidencyNone, Retention: domain.RetentionStandard}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := calibration.NewClient(f, rr, promptFS, cfg, calibrated)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, err := tenancy.WithTenant(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Structured(ctx, llm.Call{PromptID: promptID, PromptHash: p.Hash, MaxTokens: 16, Messages: []domain.Message{{
		Role: domain.RoleUser, Parts: []domain.Part{{Text: "hello"}},
	}}})
	return f.Invocations() > 0, err
}

// TestCalibrationAllowsOnlyItsRoute (D10): the calibrated route reaches the
// provider; any other route without baseline stays refused; the fake route is
// never calibrated; the registry of the configuration is kept.
func TestCalibrationAllowsOnlyItsRoute(t *testing.T) {
	cfg := llm.Config{MaxTokensPerCall: 16}
	calibrated := domain.Route{Platform: domain.PlatformOpenRouter, Model: "openai/gpt-4o-2024-08-06"}
	other := domain.Route{Platform: domain.PlatformOpenRouter, Model: "anthropic/claude-sonnet-4.5"}
	if ok, err := reached(t, cfg, calibrated, calibrated); !ok || errors.Is(err, llm.ErrRouteWithoutBaseline) {
		t.Errorf("calibrated route: reached %v, %v", ok, err)
	}
	if ok, err := reached(t, cfg, calibrated, other); ok || !errors.Is(err, llm.ErrRouteWithoutBaseline) {
		t.Errorf("other route: reached %v, %v; want ErrRouteWithoutBaseline", ok, err)
	}
	withOther := cfg
	withOther.ValidatedPairs = []llm.Pair{{Platform: other.Platform, Model: other.Model}}
	if ok, err := reached(t, withOther, calibrated, other); !ok || errors.Is(err, llm.ErrRouteWithoutBaseline) {
		t.Errorf("route of the registry: reached %v, %v", ok, err)
	}
	f, err := fake.New(fake.Options{})
	if err != nil {
		t.Fatal(err)
	}
	rr, err := fake.NewStaticResolver(map[tenancy.ID]domain.TenantPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	for name, r := range map[string]domain.Route{
		"fake":         {Platform: domain.PlatformFake, Model: "fake-model-v1"},
		"empty_model":  {Platform: domain.PlatformOpenRouter},
		"unwired":      {Platform: domain.PlatformOpenAI, Model: "gpt-4o-2024-08-06"},
		"with_region":  {Platform: domain.PlatformOpenRouter, Region: "eu-west-3", Model: "openai/gpt-4o-2024-08-06"},
		"empty_route":  {},
		"unknown_kind": {Platform: "mystery", Model: "m"},
	} {
		if _, err := calibration.NewClient(f, rr, promptFS, cfg, r); !errors.Is(err, calibration.ErrRouteRefused) {
			t.Errorf("%s: NewClient = %v, want ErrRouteRefused", name, err)
		}
	}
}
