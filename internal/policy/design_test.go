package policy_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/amezianechayer/rempart/internal/design"
	graphdomain "github.com/amezianechayer/rempart/internal/graph/domain"
	"github.com/amezianechayer/rempart/internal/graph/reach"
	"github.com/amezianechayer/rempart/internal/intent"
	"github.com/amezianechayer/rempart/internal/policy"
	policydomain "github.com/amezianechayer/rempart/internal/policy/domain"
	"github.com/amezianechayer/rempart/schemas"
)

const (
	referenceIR = "../intent/testdata/reference-ir.json"
	canariesIR  = "../design/testdata/reference-canaries.json"
)

func facts(t *testing.T, path string) (graphdomain.FactsGraph, reach.Result) {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // G304: constant paths of the repository test data
	if err != nil {
		t.Fatal(err)
	}
	ir, err := intent.ParseIR(raw)
	if err != nil {
		t.Fatal(err)
	}
	g, _, err := design.Build(ir, design.Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	f := graphdomain.FactsOf(g)
	m, err := reach.FromGraph(f)
	if err != nil {
		t.Fatal(err)
	}
	r, err := reach.Compute(m, reach.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	return f, r
}

func reachesFreeText(typ reflect.Type, path string, seen map[reflect.Type]bool) string {
	if typ == reflect.TypeFor[graphdomain.FreeText]() {
		return path
	}
	switch typ.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return reachesFreeText(typ.Elem(), path+"[]", seen)
	case reflect.Map:
		if p := reachesFreeText(typ.Key(), path+"{key}", seen); p != "" {
			return p
		}
		return reachesFreeText(typ.Elem(), path+"{}", seen)
	case reflect.Struct:
		if seen[typ] {
			return ""
		}
		seen[typ] = true
		for i := range typ.NumField() {
			if p := reachesFreeText(typ.Field(i).Type, path+"."+typ.Field(i).Name, seen); p != "" {
				return p
			}
		}
	case reflect.Interface:
		return path + " (interface)"
	}
	return ""
}

func validate(t *testing.T, raw []byte) error {
	t.Helper()
	s, err := schemas.Compile(schemas.PolicyDesignInput)
	if err != nil {
		t.Fatalf("Compile(%s): %v", schemas.PolicyDesignInput, err)
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return s.Validate(v)
}

// TestEngineInputHasNoFreeText proves ADR 0011 D5 (T2, T111): the input of the
// policies holds no free text (no FreeText reachable from its types, no canary
// of the IR in its JSON), matches schemas/policy/design-input-v1.json, carries
// the derived facts of D5 with lists written [] and never null, and
// NewDesignInput refuses a context it cannot check, with a fixed message.
func TestEngineInputHasNoFreeText(t *testing.T) {
	seen := map[reflect.Type]bool{}
	if p := reachesFreeText(reflect.TypeFor[policy.DesignInput](), "DesignInput", seen); p != "" {
		t.Fatalf("FreeText reachable from the policy input at %s", p)
	}
	for _, typ := range []reflect.Type{reflect.TypeFor[graphdomain.FactNode](), reflect.TypeFor[reach.Hop](), reflect.TypeFor[policydomain.Derived]()} {
		if !seen[typ] {
			t.Errorf("walk of DesignInput never reached %s: the walk is blind", typ)
		}
	}

	f, r := facts(t, canariesIR)
	in, err := policy.NewDesignInput(f, r, policy.DesignContext{
		Constraints: policydomain.Constraints{AllowedRegions: []string{"francecentral", "eu-west-3", "eu-west-3"}},
		Environment: "staging",
	})
	if err != nil {
		t.Fatalf("NewDesignInput: %v", err)
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"CANARY-", "untrusted_text", "pwned", "ignore previous"} {
		if bytes.Contains(raw, []byte(c)) {
			t.Errorf("policy input contains %q", c)
		}
	}
	if err := validate(t, raw); err != nil {
		t.Fatalf("policy input does not match %s: %v", schemas.PolicyDesignInput, err)
	}
	for _, want := range []string{
		`"unconfirmed_exposures":[]`, `"sources_unresolved":[]`, `"forbidden_clouds":[]`,
		`"allowed_regions":["eu-west-3","francecentral"]`, `"environment":"staging"`, `"workload_roles":{}`,
	} {
		if !bytes.Contains(raw, []byte(want)) {
			t.Errorf("policy input lacks %s:\n%s", want, raw)
		}
	}

	t.Run("jurisdiction", func(t *testing.T) {
		f, r := facts(t, referenceIR)
		in, err := policy.NewDesignInput(f, r, policy.DesignContext{})
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]policydomain.Zone{
			"wl:app-cluster": policydomain.ZoneFR, "wl:legacy-vms": policydomain.ZoneFR,
			"wl:obs": policydomain.ZoneFR, "wl:gitops": policydomain.ZoneFR, "lb:app-cluster-443": policydomain.ZoneFR,
		}
		for id, z := range want {
			if got := in.Derived.Jurisdiction[id]; got != z {
				t.Errorf("jurisdiction of %s = %q, want %q", id, got, z)
			}
		}
		for _, id := range []string{"data:customer-db", "internet", "id:legacy-vms"} {
			if z, ok := in.Derived.Jurisdiction[id]; ok {
				t.Errorf("jurisdiction of %s = %q, want absent (no cloud and region)", id, z)
			}
		}
		if in.Derived.Environment != "staging" {
			t.Errorf("environment %q, want staging (most demanding of the networks)", in.Derived.Environment)
		}
		empty, err := policy.NewDesignInput(graphdomain.FactsGraph{Version: "1", TenantID: f.TenantID, Source: "design"}, reach.Result{}, policy.DesignContext{})
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(empty)
		if empty.Derived.Environment != "prod" || bytes.Contains(raw, []byte("null")) {
			t.Errorf("empty input: environment %q (want prod), JSON %s (want no null)", empty.Derived.Environment, raw)
		}
		if err := validate(t, raw); err != nil {
			t.Errorf("empty input does not match the schema: %v", err)
		}
	})

	t.Run("context_refused", func(t *testing.T) {
		f, r := facts(t, referenceIR)
		const marker = "x-marker-7f3a"
		for name, c := range map[string]policy.DesignContext{
			"unconfirmed_not_exposes":   {UnconfirmedExposures: []string{"can_reach|lb:app-cluster-443|wl:app-cluster|https/443"}},
			"unconfirmed_unknown":       {UnconfirmedExposures: []string{marker}},
			"unresolved_unknown":        {SourcesUnresolved: []string{marker}},
			"region_grammar":            {Constraints: policydomain.Constraints{AllowedRegions: []string{"EU West " + marker}}},
			"cloud_unknown":             {Constraints: policydomain.Constraints{ForbiddenClouds: []string{"gcp"}}},
			"environment_unknown":       {Environment: "qa"},
			"role_unknown":              {WorkloadRoles: map[string]string{"wl:gitops": "admin"}},
			"role_on_unknown_node":      {WorkloadRoles: map[string]string{marker: "gitops_controller"}},
			"role_on_non_workload_node": {WorkloadRoles: map[string]string{"data:customer-db": "gitops_controller"}},
		} {
			t.Run(name, func(t *testing.T) {
				_, err := policy.NewDesignInput(f, r, c)
				if !errors.Is(err, policy.ErrDesignInput) {
					t.Fatalf("NewDesignInput = %v, want ErrDesignInput", err)
				}
				if strings.Contains(err.Error(), marker) {
					t.Fatalf("message quotes the context: %q", err)
				}
			})
		}
		exposes := ""
		for _, e := range f.Edges {
			if e.Type == graphdomain.EdgeExposes {
				exposes = e.ID
			}
		}
		in, err := policy.NewDesignInput(f, r, policy.DesignContext{
			UnconfirmedExposures: []string{exposes, exposes}, WorkloadRoles: map[string]string{"wl:gitops": "gitops_controller"},
		})
		if err != nil || len(in.Derived.UnconfirmedExposures) != 1 || in.Derived.WorkloadRoles["wl:gitops"] != "gitops_controller" {
			t.Fatalf("valid context: %v, %+v", err, in.Derived)
		}
	})
}
