package domain

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

type Residency string

const (
	ResidencyEU   Residency = "eu"
	ResidencyNone Residency = "none"
)

type Retention string

const (
	RetentionZero     Retention = "zero"
	RetentionStandard Retention = "standard"
)

type TenantPolicy struct {
	Route     Route
	Residency Residency
	Retention Retention
}

const maxRegionLen = 32

// undatedModels: models of anthropic-sdk-go v1.75.0 (message.go) published
// without a dated snapshot, 2026-09-28. Any other model needs its date (T51).
var undatedModels = [...]string{
	"claude-fable-5", "claude-fable-5-1", "claude-mythos-5", "claude-mythos-5-1",
	"claude-opus-4-6", "claude-opus-4-7", "claude-opus-4-8", "claude-opus-5",
	"claude-opus-5-5", "claude-sonnet-4-6", "claude-sonnet-5",
}

const (
	family = `claude-(?:opus|sonnet|haiku)-[0-9]{1,2}(?:-[0-9]{1,2})?`
	dated  = `(?P<date>20[0-9]{6})`
)

var (
	regionPattern  = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	anthropicModel = regexp.MustCompile(`^` + family + `-` + dated + `$`)
	bedrockModel   = regexp.MustCompile(`^(?:(?:eu|us|apac|global)\.)?anthropic\.` + family + `-` + dated + `-v[0-9]+:[0-9]+$`)
	vertexModel    = regexp.MustCompile(`^` + family + `@` + dated + `$`)
	genericModel   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$`)
)

// CheckPolicy is the deterministic route check run on every call (ADR 0002).
// It returns the first failure in the order of plan M0-T08, P9.
func CheckPolicy(p TenantPolicy, caps Capabilities) error {
	switch p.Residency {
	case ResidencyEU, ResidencyNone:
	default:
		return fmt.Errorf("%w: unknown or empty residency", ErrResidency)
	}
	switch p.Retention {
	case RetentionZero, RetentionStandard:
	default:
		return fmt.Errorf("%w: unknown or empty retention", ErrRetention)
	}
	if reason := routeShapeError(p.Route); reason != "" {
		return fmt.Errorf("%w: %s", ErrInvalidRoute, reason)
	}
	if !modelPinned(p.Route) {
		return ErrModelNotPinned
	}
	if p.Residency == ResidencyEU && !residentInEU(p.Route) {
		return fmt.Errorf("%w: platform and region not allowed for eu", ErrResidency)
	}
	if p.Retention == RetentionZero && caps.RequiresRetention {
		return fmt.Errorf("%w: model requires data retention", ErrRetention)
	}
	return nil
}

func routeShapeError(r Route) string {
	switch r.Platform {
	case PlatformAnthropic, PlatformFake:
		if r.Region != "" {
			return "region must be empty for this platform"
		}
	case PlatformBedrock, PlatformVertex:
		if !validRegion(r.Region) {
			return "region is missing or malformed"
		}
	case PlatformSelfHosted:
		if r.Region != "" && !validRegion(r.Region) {
			return "region is malformed"
		}
	default:
		return "unknown platform"
	}
	return ""
}

func validRegion(s string) bool {
	return len(s) <= maxRegionLen && regionPattern.MatchString(s)
}

func modelPinned(r Route) bool {
	lower := strings.ToLower(r.Model)
	for _, tok := range [...]string{"latest", "stable", "default", "current", "preview", "beta", "experimental"} {
		if strings.Contains(lower, tok) {
			return false
		}
	}
	switch r.Platform {
	case PlatformAnthropic:
		return slices.Contains(undatedModels[:], r.Model) || datedMatch(anthropicModel, r.Model)
	case PlatformBedrock:
		return datedMatch(bedrockModel, r.Model)
	case PlatformVertex:
		return datedMatch(vertexModel, r.Model)
	default:
		return genericModel.MatchString(r.Model)
	}
}

// datedMatch: s matches re and its date group is a real calendar day.
func datedMatch(re *regexp.Regexp, s string) bool {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	_, err := time.Parse("20060102", m[re.SubexpIndex("date")])
	return err == nil
}

// residentInEU: Anthropic direct has no EU inference_geo; self-hosted has no
// endpoint allowlist yet (T22); the fake never leaves the process.
func residentInEU(r Route) bool {
	switch r.Platform {
	case PlatformBedrock:
		geoOK := strings.HasPrefix(r.Model, "anthropic.") || strings.HasPrefix(r.Model, "eu.anthropic.")
		return geoOK && bedrockEURegion(r.Region)
	case PlatformVertex:
		return vertexEURegion(r.Region)
	case PlatformFake:
		return true
	default:
		return false
	}
}

func bedrockEURegion(s string) bool {
	switch s {
	case "eu-central-1", "eu-north-1", "eu-south-1", "eu-south-2", "eu-west-1", "eu-west-3":
		return true
	}
	return false
}

func vertexEURegion(s string) bool {
	switch s {
	case "eu", "europe-west1", "europe-west4":
		return true
	}
	return false
}
