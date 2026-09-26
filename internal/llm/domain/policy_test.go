package domain

import (
	"strings"
	"testing"
)

const (
	modelA = "claude-sonnet-4-5-20250929"
	modelB = "anthropic.claude-sonnet-4-5-20250929-v1:0"
	modelV = "claude-sonnet-4-5@20250929"
)

type policyCase struct {
	name string
	p    TenantPolicy
	caps Capabilities
	want error
}

func runPolicyCases(t *testing.T, cases []policyCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checkErr(t, tc.name, CheckPolicy(tc.p, tc.caps), tc.want)
		})
	}
}

func pol(platform Platform, region, model string, res Residency) TenantPolicy {
	return TenantPolicy{
		Route:     Route{Platform: platform, Region: region, Model: model},
		Residency: res,
		Retention: RetentionStandard,
	}
}

func TestCheckPolicyResidencyEU(t *testing.T) {
	eu, none := ResidencyEU, ResidencyNone
	runPolicyCases(t, []policyCase{
		{name: "anthropic_direct", p: pol(PlatformAnthropic, "", modelA, eu), want: ErrResidency},
		{name: "anthropic_direct_none", p: pol(PlatformAnthropic, "", modelA, none), want: nil},
		{name: "bedrock_eu_west_3", p: pol(PlatformBedrock, "eu-west-3", modelB, eu), want: nil},
		{name: "bedrock_eu_central_1", p: pol(PlatformBedrock, "eu-central-1", modelB, eu), want: nil},
		{name: "bedrock_eu_profile", p: pol(PlatformBedrock, "eu-west-3", "eu."+modelB, eu), want: nil},
		{name: "bedrock_global_profile", p: pol(PlatformBedrock, "eu-west-3", "global."+modelB, eu), want: ErrResidency},
		{name: "bedrock_global_profile_none", p: pol(PlatformBedrock, "eu-west-3", "global."+modelB, none), want: nil},
		{name: "bedrock_us_profile", p: pol(PlatformBedrock, "eu-west-3", "us."+modelB, eu), want: ErrResidency},
		{name: "bedrock_us_east_1", p: pol(PlatformBedrock, "us-east-1", modelB, eu), want: ErrResidency},
		{name: "bedrock_us_east_1_none", p: pol(PlatformBedrock, "us-east-1", modelB, none), want: nil},
		{name: "bedrock_london", p: pol(PlatformBedrock, "eu-west-2", modelB, eu), want: ErrResidency},
		{name: "bedrock_zurich", p: pol(PlatformBedrock, "eu-central-2", modelB, eu), want: ErrResidency},
		{name: "vertex_eu", p: pol(PlatformVertex, "eu", modelV, eu), want: nil},
		{name: "vertex_europe_west1", p: pol(PlatformVertex, "europe-west1", modelV, eu), want: nil},
		{name: "vertex_europe_west4", p: pol(PlatformVertex, "europe-west4", modelV, eu), want: nil},
		{name: "vertex_london", p: pol(PlatformVertex, "europe-west2", modelV, eu), want: ErrResidency},
		{name: "vertex_zurich", p: pol(PlatformVertex, "europe-west6", modelV, eu), want: ErrResidency},
		{name: "vertex_global", p: pol(PlatformVertex, "global", modelV, eu), want: ErrResidency},
		{name: "vertex_global_none", p: pol(PlatformVertex, "global", modelV, none), want: nil},
		{name: "vertex_us_east5", p: pol(PlatformVertex, "us-east5", modelV, eu), want: ErrResidency},
		{name: "selfhosted", p: pol(PlatformSelfHosted, "", "mistral-large-2411", eu), want: ErrResidency},
		{name: "selfhosted_none", p: pol(PlatformSelfHosted, "", "mistral-large-2411", none), want: nil},
		{name: "fake", p: pol(PlatformFake, "", "fake-model-v1", eu), want: nil},
	})
}

func TestCheckPolicyRetentionZero(t *testing.T) {
	with := Capabilities{RequiresRetention: true}
	without := Capabilities{}
	bedrock := func(region, model string, res Residency, ret Retention) TenantPolicy {
		return TenantPolicy{
			Route:     Route{Platform: PlatformBedrock, Region: region, Model: model},
			Residency: res,
			Retention: ret,
		}
	}
	anthropicNoneZero := TenantPolicy{
		Route:     Route{Platform: PlatformAnthropic, Model: modelA},
		Residency: ResidencyNone,
		Retention: RetentionZero,
	}
	runPolicyCases(t, []policyCase{
		{name: "zero_requires_retention", p: bedrock("eu-west-3", modelB, ResidencyEU, RetentionZero), caps: with, want: ErrRetention},
		{name: "zero_without_retention", p: bedrock("eu-west-3", modelB, ResidencyEU, RetentionZero), caps: without, want: nil},
		{name: "standard_requires_retention", p: bedrock("eu-west-3", modelB, ResidencyEU, RetentionStandard), caps: with, want: nil},
		{name: "standard_without_retention", p: bedrock("eu-west-3", modelB, ResidencyEU, RetentionStandard), caps: without, want: nil},
		{name: "anthropic_none_zero", p: anthropicNoneZero, caps: with, want: ErrRetention},
		{name: "model_before_retention", p: bedrock("eu-west-3", "", ResidencyEU, RetentionZero), caps: with, want: ErrModelNotPinned},
		{name: "residency_before_retention", p: bedrock("us-east-1", modelB, ResidencyEU, RetentionZero), caps: with, want: ErrResidency},
	})
}

func TestCheckPolicyModelPinned(t *testing.T) {
	regions := map[Platform]string{
		PlatformAnthropic:  "",
		PlatformBedrock:    "eu-west-3",
		PlatformVertex:     "eu",
		PlatformSelfHosted: "",
		PlatformFake:       "",
	}
	type modelCase struct {
		name     string
		platform Platform
		model    string
		ok       bool
	}
	models := []modelCase{
		// anthropic (13)
		{"anthropic_sonnet", PlatformAnthropic, modelA, true},
		{"anthropic_haiku", PlatformAnthropic, "claude-haiku-4-5-20251001", true},
		{"anthropic_empty", PlatformAnthropic, "", false},
		{"anthropic_undated", PlatformAnthropic, "claude-sonnet-4-5", true},
		{"anthropic_preview", PlatformAnthropic, "claude-mythos-preview", false},
		{"anthropic_three_digits", PlatformAnthropic, "claude-opus-5-100", false},
		{"anthropic_latest_alias", PlatformAnthropic, "claude-3-5-sonnet-latest", false},
		{"anthropic_latest_suffix", PlatformAnthropic, "claude-sonnet-4-5-latest", false},
		{"anthropic_capitalized", PlatformAnthropic, "Claude-Sonnet-4-5-20250929", false},
		{"anthropic_leading_space", PlatformAnthropic, " " + modelA, false},
		{"anthropic_trailing_newline", PlatformAnthropic, modelA + "\n", false},
		{"anthropic_short_date", PlatformAnthropic, "claude-sonnet-4-5-2025092", false},
		{"anthropic_bedrock_id", PlatformAnthropic, modelB, false},
		// bedrock (9)
		{"bedrock_regional", PlatformBedrock, modelB, true},
		{"bedrock_eu_profile", PlatformBedrock, "eu." + modelB, true},
		{"bedrock_undated", PlatformBedrock, "anthropic.claude-sonnet-4-5", true},
		{"bedrock_eu_undated", PlatformBedrock, "eu.anthropic.claude-opus-5", true},
		{"bedrock_undated_revision", PlatformBedrock, "anthropic.claude-opus-4-6-v1", true},
		{"bedrock_no_revision", PlatformBedrock, "anthropic.claude-sonnet-4-5-20250929-v1", false},
		{"bedrock_anthropic_id", PlatformBedrock, modelA, false},
		{"bedrock_unknown_geo", PlatformBedrock, "fr." + modelB, false},
		{"bedrock_arn", PlatformBedrock, "arn:aws:bedrock:eu-west-3::foundation-model/" + modelB, false},
		// vertex (5)
		{"vertex_pinned", PlatformVertex, modelV, true},
		{"vertex_undated", PlatformVertex, "claude-sonnet-4-5", true},
		{"vertex_latest", PlatformVertex, "claude-sonnet-4-5@latest", false},
		{"vertex_short_date", PlatformVertex, "claude-sonnet-4-5@2025092", false},
		{"vertex_anthropic_id", PlatformVertex, modelA, false},
		// selfhosted (11)
		{"selfhosted_mistral", PlatformSelfHosted, "mistral-large-2411", true},
		{"selfhosted_path_version", PlatformSelfHosted, "org/model:v1.2", true},
		{"selfhosted_empty", PlatformSelfHosted, "", false},
		{"selfhosted_latest", PlatformSelfHosted, "model-latest", false},
		{"selfhosted_latest_upper", PlatformSelfHosted, "LATEST", false},
		{"selfhosted_stable", PlatformSelfHosted, "stable", false},
		{"selfhosted_default", PlatformSelfHosted, "my-default-model", false},
		{"selfhosted_current", PlatformSelfHosted, "current", false},
		{"selfhosted_space", PlatformSelfHosted, "bad model", false},
		{"selfhosted_too_long", PlatformSelfHosted, strings.Repeat("a", 129), false},
		{"selfhosted_leading_dash", PlatformSelfHosted, "-model", false},
		// fake (3)
		{"fake_pinned", PlatformFake, "fake-model-v1", true},
		{"fake_empty", PlatformFake, "", false},
		{"fake_latest", PlatformFake, "fake-latest", false},
	}
	cases := make([]policyCase, 0, len(models))
	for _, m := range models {
		var want error
		if !m.ok {
			want = ErrModelNotPinned
		}
		cases = append(cases, policyCase{
			name: m.name,
			p:    pol(m.platform, regions[m.platform], m.model, ResidencyNone),
			want: want,
		})
	}
	runPolicyCases(t, cases)
}

func TestCheckPolicyRejectsEmptyResidency(t *testing.T) {
	bedrock := func(res Residency, ret Retention) TenantPolicy {
		return TenantPolicy{
			Route:     Route{Platform: PlatformBedrock, Region: "eu-west-3", Model: modelB},
			Residency: res,
			Retention: ret,
		}
	}
	var cases []policyCase
	residencies := []struct {
		name string
		v    Residency
	}{
		{"residency_empty", ""},
		{"residency_upper", "EU"},
		{"residency_mixed_case", "Eu"},
		{"residency_leading_space", " eu"},
		{"residency_trailing_space", "eu "},
		{"residency_country", "fr"},
		{"residency_none_trailing_space", "none "},
		{"residency_none_upper", "NONE"},
		{"residency_any", "any"},
	}
	for _, r := range residencies {
		cases = append(cases, policyCase{name: r.name, p: bedrock(r.v, RetentionStandard), want: ErrResidency})
	}
	retentions := []struct {
		name string
		v    Retention
	}{
		{"retention_empty", ""},
		{"retention_upper", "ZERO"},
		{"retention_mixed_case", "Zero"},
		{"retention_digit", "0"},
		{"retention_none", "none"},
		{"retention_leading_space", " zero"},
		{"retention_trailing_space", "standard "},
	}
	for _, r := range retentions {
		cases = append(cases, policyCase{name: r.name, p: bedrock(ResidencyEU, r.v), want: ErrRetention})
	}
	cases = append(cases,
		policyCase{name: "both_empty", p: bedrock("", ""), want: ErrResidency},
		policyCase{name: "zero_value_policy", p: TenantPolicy{}, want: ErrResidency},
		policyCase{
			name: "empty_residency_on_anthropic",
			p:    pol(PlatformAnthropic, "", modelA, ""),
			want: ErrResidency,
		},
	)
	runPolicyCases(t, cases)
}

func TestCheckPolicyRouteShape(t *testing.T) {
	none := ResidencyNone
	runPolicyCases(t, []policyCase{
		{name: "platform_empty", p: pol("", "", modelA, none), want: ErrInvalidRoute},
		{name: "platform_unknown", p: pol("openai", "", modelA, none), want: ErrInvalidRoute},
		{name: "platform_capitalized", p: pol("Bedrock", "eu-west-3", modelB, none), want: ErrInvalidRoute},
		{name: "anthropic_with_region", p: pol(PlatformAnthropic, "eu", modelA, none), want: ErrInvalidRoute},
		{name: "fake_with_region", p: pol(PlatformFake, "local", "fake-model-v1", none), want: ErrInvalidRoute},
		{name: "bedrock_without_region", p: pol(PlatformBedrock, "", modelB, none), want: ErrInvalidRoute},
		{name: "vertex_without_region", p: pol(PlatformVertex, "", modelV, none), want: ErrInvalidRoute},
		{name: "bedrock_region_upper", p: pol(PlatformBedrock, "EU-WEST-3", modelB, none), want: ErrInvalidRoute},
		{name: "bedrock_region_trailing_space", p: pol(PlatformBedrock, "eu-west-3 ", modelB, none), want: ErrInvalidRoute},
		{name: "bedrock_region_host_injection", p: pol(PlatformBedrock, "eu-west-3.evil.example", modelB, none), want: ErrInvalidRoute},
		{name: "bedrock_region_path_injection", p: pol(PlatformBedrock, "eu-west-3/x", modelB, none), want: ErrInvalidRoute},
		{name: "bedrock_region_too_long", p: pol(PlatformBedrock, strings.Repeat("a", 33), modelB, none), want: ErrInvalidRoute},
		{name: "bedrock_region_leading_dash", p: pol(PlatformBedrock, "-eu", modelB, none), want: ErrInvalidRoute},
		{name: "route_before_model", p: pol("openai", "", "", none), want: ErrInvalidRoute},
		{name: "bedrock_region_max_length", p: pol(PlatformBedrock, strings.Repeat("a", 32), modelB, none), want: nil},
		{name: "selfhosted_with_region", p: pol(PlatformSelfHosted, "eu-west-3", "mistral-large-2411", none), want: nil},
		{name: "residency_before_route", p: pol("openai", "", modelA, ""), want: ErrResidency},
	})
}

func TestCheckPolicyErrorsDoNotEchoInput(t *testing.T) {
	cases := []struct {
		name string
		p    TenantPolicy
	}{
		{name: "residency", p: TenantPolicy{
			Route:     Route{Platform: PlatformBedrock, Region: "eu-west-3", Model: modelB},
			Residency: "CANARY", Retention: RetentionStandard,
		}},
		{name: "retention", p: TenantPolicy{
			Route:     Route{Platform: PlatformBedrock, Region: "eu-west-3", Model: modelB},
			Residency: ResidencyEU, Retention: "CANARY",
		}},
		{name: "region", p: pol(PlatformBedrock, "CANARY", modelB, ResidencyNone)},
		{name: "model", p: pol(PlatformSelfHosted, "", "CANARY-latest", ResidencyNone)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckPolicy(tc.p, Capabilities{})
			if err == nil {
				t.Fatalf("%s: CheckPolicy accepted a policy holding CANARY", tc.name)
			}
			msg := err.Error()
			if strings.Contains(strings.ToLower(msg), "canary") {
				t.Fatalf("%s: error message echoes the input: %q", tc.name, msg)
			}
			if len(msg) >= 128 {
				t.Fatalf("%s: error message is %d bytes, want less than 128", tc.name, len(msg))
			}
		})
	}
}
