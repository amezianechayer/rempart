package domain

import (
	"errors"
	"slices"
)

// Location is where a route processes the data (ADR 0008 D2).
type Location string

const (
	LocationEU         Location = "eu"
	LocationUS         Location = "us"
	LocationCN         Location = "cn"
	LocationSG         Location = "sg"
	LocationGlobal     Location = "global" // a gateway whose final provider varies
	LocationSelfHosted Location = "selfhosted"
	LocationInProcess  Location = "in-process"
)

var ErrUnknownLocation = errors.New("llm: unknown processing location")

// openRouterModels: ADR 0008 D4 (O1, option (a)), the closed list of exact
// OpenRouter model ids and the single final provider of each (the slug sent
// in provider.order). Unverified at the source on 2026-10-13 (F7, F8): an
// entry changes by an amendment of ADR 0008 only.
var openRouterModels = map[string]string{
	"anthropic/claude-sonnet-4.5": "anthropic",
	"deepseek/deepseek-chat":      "deepseek",
	"openai/gpt-4o-2024-08-06":    "openai",
}

// OpenRouterModels returns the closed list, sorted.
func OpenRouterModels() []string {
	out := make([]string, 0, len(openRouterModels))
	for m := range openRouterModels {
		out = append(out, m)
	}
	slices.Sort(out)
	return out
}

// OpenRouterProvider returns the final provider of a listed model.
func OpenRouterProvider(model string) (string, bool) {
	p, ok := openRouterModels[model]
	return p, ok
}

// ProcessingLocation is a coded table (ADR 0008 D2); a couple absent from it
// fails closed. Facts of the platforms not wired in M1 are unverified (F10).
func ProcessingLocation(r Route) (Location, error) {
	switch r.Platform {
	case PlatformFake:
		return LocationInProcess, nil
	case PlatformOpenRouter:
		return LocationGlobal, nil
	case PlatformAnthropic, PlatformOpenAI:
		return LocationUS, nil
	case PlatformDeepSeek:
		return LocationCN, nil
	case PlatformQwen:
		switch r.Region {
		case "cn-beijing", "cn-hangzhou":
			return LocationCN, nil
		case "ap-southeast-1", "intl":
			return LocationSG, nil
		}
	case PlatformBedrock:
		switch {
		case bedrockEURegion(r.Region):
			return LocationEU, nil
		case len(r.Region) > 3 && r.Region[:3] == "us-":
			return LocationUS, nil
		}
	case PlatformVertex:
		switch {
		case vertexEURegion(r.Region):
			return LocationEU, nil
		case len(r.Region) > 3 && r.Region[:3] == "us-":
			return LocationUS, nil
		}
	case PlatformSelfHosted:
		return LocationSelfHosted, nil
	}
	return "", ErrUnknownLocation
}
