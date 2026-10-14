package domain

import (
	"errors"
	"testing"
)

// Tests of ADR 0008 (M1-T09): the openrouter platform, its closed list of
// models (D4, O1), its processing location (D2).

func orPolicy(model string, res Residency) TenantPolicy {
	return TenantPolicy{Route: Route{Platform: PlatformOpenRouter, Model: model}, Residency: res, Retention: RetentionStandard}
}

// TestOpenRouterClosedList (T21, T92): a listed model is admitted in residency
// none only; variants, the auto router, a changed case and an unlisted model
// are refused; the region stays empty.
func TestOpenRouterClosedList(t *testing.T) {
	caps := Capabilities{NativeStructuredOutput: true, RequiresRetention: true}
	listed := OpenRouterModels()
	if len(listed) == 0 {
		t.Fatal("empty closed list")
	}
	for _, m := range listed {
		if err := CheckPolicy(orPolicy(m, ResidencyNone), caps); err != nil {
			t.Errorf("%s in residency none: %v", m, err)
		}
		if err := CheckPolicy(orPolicy(m, ResidencyEU), caps); !errors.Is(err, ErrResidency) {
			t.Errorf("%s in residency eu: %v, want ErrResidency", m, err)
		}
		if slug, ok := OpenRouterProvider(m); !ok || slug == "" {
			t.Errorf("%s: no final provider", m)
		}
		for _, bad := range []string{m + ":free", m + ":nitro", m + ":online", m + ":thinking", m + ":floor"} {
			if err := CheckPolicy(orPolicy(bad, ResidencyNone), caps); !errors.Is(err, ErrModelNotPinned) {
				t.Errorf("variant %s: %v, want ErrModelNotPinned", bad, err)
			}
		}
	}
	for _, bad := range []string{"openrouter/auto", "DeepSeek/DeepSeek-Chat", "deepseek/deepseek-chat-v9", "", "anthropic/claude-latest"} {
		if err := CheckPolicy(orPolicy(bad, ResidencyNone), caps); err == nil {
			t.Errorf("model %q admitted", bad)
		}
	}
	p := orPolicy(listed[0], ResidencyNone)
	p.Route.Region = "eu"
	if err := CheckPolicy(p, caps); !errors.Is(err, ErrInvalidRoute) {
		t.Errorf("openrouter with a region: %v, want ErrInvalidRoute", err)
	}
	if err := CheckPolicy(TenantPolicy{Route: p.Route, Residency: ResidencyNone, Retention: RetentionZero}, caps); !errors.Is(err, ErrRetention) && !errors.Is(err, ErrInvalidRoute) {
		t.Errorf("openrouter with zero retention: %v, want a refusal", err)
	}
	if _, ok := OpenRouterProvider("openrouter/auto"); ok {
		t.Error("openrouter/auto has a final provider")
	}
}

// TestProcessingLocation (T19, D2): a coded table; an unknown couple fails
// closed; no platform but the fake and the EU routes of Bedrock and Vertex is
// in the eu location.
func TestProcessingLocation(t *testing.T) {
	for _, c := range []struct {
		route Route
		want  Location
	}{
		{Route{Platform: PlatformOpenRouter, Model: "x"}, LocationGlobal},
		{Route{Platform: PlatformAnthropic, Model: "x"}, LocationUS},
		{Route{Platform: PlatformOpenAI, Model: "x"}, LocationUS},
		{Route{Platform: PlatformDeepSeek, Model: "x"}, LocationCN},
		{Route{Platform: PlatformFake, Model: "x"}, LocationInProcess},
		{Route{Platform: PlatformBedrock, Region: "eu-west-3", Model: "x"}, LocationEU},
		{Route{Platform: PlatformVertex, Region: "europe-west1", Model: "x"}, LocationEU},
		{Route{Platform: PlatformBedrock, Region: "us-east-1", Model: "x"}, LocationUS},
	} {
		got, err := ProcessingLocation(c.route)
		if err != nil || got != c.want {
			t.Errorf("ProcessingLocation(%+v) = %q, %v; want %q", c.route, got, err, c.want)
		}
	}
	for _, r := range []Route{{Platform: "unknown"}, {Platform: PlatformQwen, Region: "mars-1"}} {
		if _, err := ProcessingLocation(r); !errors.Is(err, ErrUnknownLocation) {
			t.Errorf("ProcessingLocation(%+v): %v, want ErrUnknownLocation", r, err)
		}
	}
}
