package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/amezianechayer/rempart/internal/tenancy"
)

// Configuration of make demo (docs/plans/M0-worker-demo.md section 4.4).
const (
	demoTenant  = "0d3e0000-0000-4000-8000-000000000001"
	demoAddress = "127.0.0.1:7233"
	demoNS      = "rempart"
	demoScript  = "internal/loops/demo/testdata/scripts/converge.json"
	canary      = "sk-ant-api03-EXAMPLEEXAMPLE"
)

// demoArgs returns the command line of make demo.
func demoArgs() []string {
	return []string{
		"-dev", "-demo-once", "-llm=fake", "-tenant=" + demoTenant,
		"-temporal-address=" + demoAddress, "-namespace=" + demoNS, "-fake-script=" + demoScript,
	}
}

func demoConfig() Config {
	return Config{
		TemporalAddress: demoAddress, Namespace: demoNS, LLMProvider: "fake", FakeScript: demoScript,
		Dev: true, DemoOnce: true, Tenant: tenancy.ID(demoTenant),
	}
}

// withFlag returns demoArgs with the flag name removed, then extra appended.
func withFlag(name string, extra ...string) []string {
	args := slices.DeleteFunc(demoArgs(), func(a string) bool { return a == "-"+name || strings.HasPrefix(a, "-"+name+"=") })
	return append(args, extra...)
}

// refused runs LoadConfig on args and checks it fails with want and a zero
// Config, without quoting quoted.
func refused(t *testing.T, args []string, want error, quoted ...string) {
	t.Helper()
	cfg, err := LoadConfig(args)
	if !errors.Is(err, want) {
		t.Fatalf("LoadConfig(%q) = %+v, %v; want %v", args, cfg, err, want)
	}
	if cfg != (Config{}) {
		t.Errorf("LoadConfig(%q) returned %+v with its error, want a zero Config", args, cfg)
	}
	for _, q := range quoted {
		if q != "" && strings.Contains(err.Error(), q) {
			t.Errorf("error %q quotes %q", err, q)
		}
	}
}

// TestLoadConfigRequiresLLMProvider (D2): -llm has no default; only the exact
// value fake is known in M0.
func TestLoadConfigRequiresLLMProvider(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"absent", withFlag("llm")},
		{"empty", withFlag("llm", "-llm=")},
		{"openai", withFlag("llm", "-llm=openai")},
		{"upper_case", withFlag("llm", "-llm=FAKE")},
		{"padded", withFlag("llm", "-llm= fake")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { refused(t, tc.args, ErrConfig, "openai", "FAKE") })
	}
}

// TestLoadConfigFakeRequiresDev (D3, threat T41): the fake model is reachable
// only behind -dev, with a fixed message.
func TestLoadConfigFakeRequiresDev(t *testing.T) {
	for _, args := range [][]string{withFlag("dev"), withFlag("dev", "-dev=false")} {
		refused(t, args, ErrFakeRequiresDev)
		_, err := LoadConfig(args)
		if err == nil || err.Error() != "rempart-worker: -llm=fake requires -dev" {
			t.Errorf("LoadConfig(%q) error = %v, want exactly \"rempart-worker: -llm=fake requires -dev\"", args, err)
		}
	}
}

// TestLoadConfigAnthropicRefusedM0 (A1, threat T36): the Anthropic adapter is
// not wired before M1, with or without -dev, whatever the other flags.
func TestLoadConfigAnthropicRefusedM0(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"demo_flags", withFlag("llm", "-llm=anthropic")},
		{"without_dev", slices.DeleteFunc(withFlag("llm", "-llm=anthropic"), func(a string) bool { return a == "-dev" })},
		{"alone", []string{"-llm=anthropic"}},
		{"dev_demo_once", []string{"-dev", "-demo-once", "-llm=anthropic"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { refused(t, tc.args, ErrProviderRefused) })
	}
}

// TestLoadConfigDemoTenantValidated (D6, threats T34, T75): the tenant is a
// canonical version 4 UUID of a customer, never System; the error never quotes it.
func TestLoadConfigDemoTenantValidated(t *testing.T) {
	cases := []struct{ name, tenant string }{
		{"upper_case", strings.ToUpper(demoTenant)},
		{"nil_uuid", "00000000-0000-0000-0000-000000000000"},
		{"system", string(tenancy.System)},
		{"uuid_v1", "6ba7b810-9dad-11d1-80b4-00c04fd430c8"},
		{"braced", "{" + demoTenant + "}"},
	}
	t.Run("absent", func(t *testing.T) { refused(t, withFlag("tenant"), ErrConfig) })
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { refused(t, withFlag("tenant", "-tenant="+tc.tenant), ErrConfig, tc.tenant) })
	}
}

// TestLoadConfigStrictFlags (D2, D5, T18, T36): no positional argument, no
// repeated flag, no unknown flag (no secret by flag), -demo-once required, a
// literal loopback address, a lower-case namespace, a relative .json script
// that stays under the working directory.
func TestLoadConfigStrictFlags(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want error
	}{
		{"positional", append(demoArgs(), "extra"), ErrConfig},
		{"positional_after_dashdash", append(demoArgs(), "--", "x"), ErrConfig},
		{"llm_repeated", append(demoArgs(), "-llm=fake"), ErrConfig},
		{"tenant_repeated", append(demoArgs(), "-tenant="+demoTenant), ErrConfig},
		{"address_repeated", append(demoArgs(), "-temporal-address="+demoAddress), ErrConfig},
		{"anthropic_key", append(demoArgs(), "-anthropic-key=x"), ErrConfig},
		{"bao_token", append(demoArgs(), "-bao-token=x"), ErrConfig},
		{"help", append(demoArgs(), "-help"), ErrConfig},
		{"bool_garbage", withFlag("dev", "-dev=maybe"), ErrConfig},
		{"without_demo_once", withFlag("demo-once"), ErrDemoOnceRequired},
		{"demo_once_false", withFlag("demo-once", "-demo-once=false"), ErrDemoOnceRequired},
		{"address_absent", withFlag("temporal-address"), ErrConfig},
		{"address_private", withFlag("temporal-address", "-temporal-address=10.0.0.1:7233"), ErrConfig},
		{"address_unspecified", withFlag("temporal-address", "-temporal-address=0.0.0.0:7233"), ErrConfig},
		{"address_hostname", withFlag("temporal-address", "-temporal-address=localhost:7233"), ErrConfig},
		{"address_no_port", withFlag("temporal-address", "-temporal-address=127.0.0.1"), ErrConfig},
		{"port_zero", withFlag("temporal-address", "-temporal-address=127.0.0.1:0"), ErrConfig},
		{"port_leading_zero", withFlag("temporal-address", "-temporal-address=127.0.0.1:07233"), ErrConfig},
		{"port_too_large", withFlag("temporal-address", "-temporal-address=127.0.0.1:65536"), ErrConfig},
		{"port_named", withFlag("temporal-address", "-temporal-address=127.0.0.1:http"), ErrConfig},
		{"namespace_absent", withFlag("namespace"), ErrConfig},
		{"namespace_upper_case", withFlag("namespace", "-namespace=Rempart"), ErrConfig},
		{"namespace_too_long", withFlag("namespace", "-namespace="+strings.Repeat("a", 64)), ErrConfig},
		{"namespace_dot", withFlag("namespace", "-namespace=rempart.prod"), ErrConfig},
		{"script_absent", withFlag("fake-script"), ErrConfig},
		{"script_absolute", withFlag("fake-script", "-fake-script=/etc/x.json"), ErrConfig},
		{"script_parent", withFlag("fake-script", "-fake-script=../x.json"), ErrConfig},
		{"script_inner_parent", withFlag("fake-script", "-fake-script=internal/../../x.json"), ErrConfig},
		{"script_yaml", withFlag("fake-script", "-fake-script=x.yaml"), ErrConfig},
		{"script_dot_element", withFlag("fake-script", "-fake-script=./x.json"), ErrConfig},
		{"script_bare_extension", withFlag("fake-script", "-fake-script=.json/x"), ErrConfig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { refused(t, tc.args, tc.want) })
	}
}

// TestLoadConfigValid: the command line of make demo gives exactly its
// configuration, whatever the order of the flags; other literal loopback
// addresses and a 63-byte namespace are accepted.
func TestLoadConfigValid(t *testing.T) {
	cfg, err := LoadConfig(demoArgs())
	if err != nil {
		t.Fatalf("LoadConfig(make demo) = %v", err)
	}
	if cfg != demoConfig() {
		t.Errorf("LoadConfig(make demo) = %+v, want %+v", cfg, demoConfig())
	}
	reversed := demoArgs()
	slices.Reverse(reversed)
	if cfg, err := LoadConfig(reversed); err != nil || cfg != demoConfig() {
		t.Errorf("LoadConfig(reversed) = %+v, %v; want %+v", cfg, err, demoConfig())
	}
	for _, tc := range []struct{ flag, value string }{
		{"temporal-address", "[::1]:7233"},
		{"temporal-address", "127.0.0.2:1"},
		{"temporal-address", "127.0.0.1:65535"},
		{"namespace", strings.Repeat("a", 63)},
		{"namespace", "rempart-dev-2"},
		{"fake-script", "x.json"},
	} {
		cfg, err := LoadConfig(withFlag(tc.flag, "-"+tc.flag+"="+tc.value))
		if err != nil {
			t.Errorf("LoadConfig(-%s=%s) = %v, want a configuration", tc.flag, tc.value, err)
			continue
		}
		got := map[string]string{"temporal-address": cfg.TemporalAddress, "namespace": cfg.Namespace, "fake-script": cfg.FakeScript}[tc.flag]
		if got != tc.value {
			t.Errorf("-%s=%s read as %q", tc.flag, tc.value, got)
		}
	}
}

// captureStderr runs f with os.Stderr redirected and returns what was written
// there (the flag package writes to os.Stderr unless its output is set).
func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = w
	done := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(r)
		done <- b
	}()
	defer func() {
		os.Stderr = saved
	}()
	f()
	os.Stderr = saved
	_ = w.Close()
	return string(<-done)
}

// TestConfigNeverPrintsSecrets (D1, threat T36): LoadConfig reads no
// environment variable; a value given on the command line is never quoted by
// an error, by the flag package or by realMain; Config holds no secret field.
func TestConfigNeverPrintsSecrets(t *testing.T) {
	t.Run("environment_ignored", func(t *testing.T) {
		env := []string{"ANTHROPIC_API_KEY", "OPENBAO_DEV_ROOT_TOKEN", "TEMPORAL_ADDRESS", "TEMPORAL_NAMESPACE", "REMPART_LLM", "REMPART_TENANT"}
		for _, k := range env {
			t.Setenv(k, "FAKE")
		}
		if cfg, err := LoadConfig(demoArgs()); err != nil || cfg != demoConfig() {
			t.Errorf("LoadConfig with FAKE environment = %+v, %v; want %+v", cfg, err, demoConfig())
		}
		refused(t, withFlag("temporal-address"), ErrConfig)
		refused(t, withFlag("llm"), ErrConfig)
	})

	t.Run("canary_never_quoted", func(t *testing.T) {
		var lines [][]string
		for _, name := range []string{"temporal-address", "namespace", "llm", "fake-script", "tenant", "dev", "demo-once"} {
			lines = append(lines, withFlag(name, "-"+name+"="+canary))
		}
		lines = append(lines,
			append(demoArgs(), canary),
			append(demoArgs(), "-anthropic-key="+canary),
			append(demoArgs(), "-llm="+canary),
			append(demoArgs(), "-tenant="+canary),
			append(demoArgs(), "-"+canary),
		)
		for _, args := range lines {
			var errText string
			printed := captureStderr(t, func() {
				_, err := LoadConfig(args)
				if err == nil {
					t.Errorf("LoadConfig(%q) accepted the canary", args)
					return
				}
				errText = err.Error()
			})
			if strings.Contains(errText, canary) || strings.Contains(printed, canary) {
				t.Errorf("LoadConfig(%q): canary in error %q or on stderr %q", args, errText, printed)
			}
			if printed != "" {
				t.Errorf("LoadConfig(%q) wrote %q on the process stderr, want nothing", args, printed)
			}
			var stdout, stderr bytes.Buffer
			code := realMain(context.Background(), args, &stdout, &stderr)
			if code != 2 || stdout.Len() != 0 {
				t.Errorf("realMain(%q) = %d, stdout %q; want 2 and an empty stdout", args, code, stdout.String())
			}
			if strings.Contains(stderr.String(), canary) {
				t.Errorf("realMain(%q): canary on stderr %q", args, stderr.String())
			}
		}
	})

	t.Run("config_fields", func(t *testing.T) {
		want := []string{
			"TemporalAddress string", "Namespace string", "LLMProvider string", "FakeScript string",
			"Dev bool", "DemoOnce bool", "Tenant tenancy.ID",
		}
		typ := reflect.TypeFor[Config]()
		var got []string
		for i := range typ.NumField() {
			f := typ.Field(i)
			got = append(got, f.Name+" "+f.Type.String())
		}
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("Config fields = %q, want exactly %q (no secret, no key, no token)", got, want)
		}
	})
}

// TestProductionConfigHasNoFake (D3, threat T41): among every combination of
// -dev, -demo-once and -llm, only -dev -demo-once -llm=fake is accepted.
func TestProductionConfigHasNoFake(t *testing.T) {
	rest := []string{"-tenant=" + demoTenant, "-temporal-address=" + demoAddress, "-namespace=" + demoNS, "-fake-script=" + demoScript}
	accepted := 0
	for _, dev := range []string{"", "-dev", "-dev=false"} {
		for _, once := range []string{"", "-demo-once", "-demo-once=false"} {
			for _, llm := range []string{"", "-llm=fake", "-llm=anthropic", "-llm=openai"} {
				args := slices.DeleteFunc([]string{dev, once, llm}, func(s string) bool { return s == "" })
				args = append(args, rest...)
				cfg, err := LoadConfig(args)
				ok := dev == "-dev" && once == "-demo-once" && llm == "-llm=fake"
				switch {
				case ok && (err != nil || cfg != demoConfig()):
					t.Errorf("LoadConfig(%q) = %+v, %v; want the demo configuration", args, cfg, err)
				case !ok && (err == nil || cfg != Config{}):
					t.Errorf("LoadConfig(%q) = %+v, %v; want a refusal", args, cfg, err)
				case err == nil:
					accepted++
				}
				if err == nil && cfg.LLMProvider == "fake" && (!cfg.Dev || !cfg.DemoOnce) {
					t.Errorf("LoadConfig(%q): fake model without -dev -demo-once", args)
				}
			}
		}
	}
	if accepted != 1 {
		t.Errorf("%d combinations accepted, want exactly 1", accepted)
	}
}
