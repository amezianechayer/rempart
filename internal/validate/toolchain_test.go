package validate

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestTofuCLIConfigMirrorOnly proves D15 and T143: the OpenTofu CLI
// configuration installs providers from the file mirror only, for the
// hashicorp namespace of registry.opentofu.org, with neither direct
// installation, network mirror, credentials nor plugin cache; a mirror path
// that is relative or that could escape the HCL string is refused.
func TestTofuCLIConfigMirrorOnly(t *testing.T) {
	got, err := TofuCLIConfig("/var/cache/rempart/mirror")
	if err != nil {
		t.Fatal(err)
	}
	want := "provider_installation {\n  filesystem_mirror {\n    path    = \"/var/cache/rempart/mirror\"\n" +
		"    include = [\"registry.opentofu.org/hashicorp/*\"]\n  }\n}\n"
	if string(got) != want {
		t.Fatalf("TofuCLIConfig =\n%s\nwant\n%s", got, want)
	}
	for _, forbidden := range []string{"direct", "network_mirror", "credentials", "plugin_cache_dir", "host ", "exclude"} {
		if strings.Contains(string(got), forbidden) {
			t.Errorf("configuration contains %q", forbidden)
		}
	}
	for _, bad := range []string{"", "relative/mirror", "/m\"irror", "/m\\irror", "/m${x}", "/m%{x}", "/m\nirror", "/a/../b"} {
		if _, err := TofuCLIConfig(bad); !errors.Is(err, ErrToolchain) {
			t.Errorf("TofuCLIConfig(%q) = %v, want ErrToolchain", bad, err)
		}
	}
}

// fixtureH1 is the dirhash Hash1 ("h1:", the hash OpenTofu records in a
// .terraform.lock.hcl) of the fixture provider zip: one member
// terraform-provider-aws_v6.72.0_x5 holding "provider". Computed outside Go
// (an independent Python implementation of dirhash.Hash1, checked against the
// h1 OpenTofu 1.13.2 writes for the real helm 3.3.0 package).
const fixtureH1 = "h1:iXZnduFQyKroXFMinTur9F2KMpPFxE9M/KjsaeZNE44="

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// fixture is a lock and a cache built by hand, in the layout of
// scripts/iac-tools.sh: tools/<name>/<version>/<binary>,
// tflint-plugins/<source>/<version>/<binary>, mirror/<source>/<zip>.
type fixture struct {
	cache string
	lock  map[string]any
	bin   map[string][]byte
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	cache := t.TempDir()
	tofu := []byte("#!/bin/sh\necho tofu\n")
	plugin := []byte("#!/bin/sh\necho plugin\n")
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	w, err := zw.Create("terraform-provider-aws_v6.72.0_x5")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("provider")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	write := func(rel string, b []byte) {
		p := filepath.Join(cache, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o500); err != nil { //nolint:gosec // G306: a cached binary is executable by its owner.
			t.Fatal(err)
		}
	}
	write("tools/tofu/1.13.2/tofu", tofu)
	write("tflint-plugins/github.com/terraform-linters/tflint-ruleset-aws/0.50.0/tflint-ruleset-aws", plugin)
	write("mirror/registry.opentofu.org/hashicorp/aws/terraform-provider-aws_6.72.0_linux_amd64.zip", zbuf.Bytes())
	gpg := map[string]any{"kind": "gpg", "key": strings.Repeat("A", 40), "checked": "2026-11-26", "note": ""}
	lock := map[string]any{
		"lock_version": 1, "date": "2026-11-26", "min_age_days": 14, "platform": "linux_amd64",
		"hosts": []any{"github.com", "releases.hashicorp.com"},
		"tools": []any{
			map[string]any{
				"name": "tofu", "kind": "tool", "version": "1.13.2", "published": "2026-10-21",
				"url":    "https://github.com/opentofu/opentofu/releases/download/v1.13.2/tofu_1.13.2_linux_amd64.zip",
				"sha256": strings.Repeat("0", 64), "archive": "zip", "binary": "tofu", "binary_sha256": hexSum(tofu), "signature": gpg,
			},
			map[string]any{
				"name": "tflint-ruleset-aws", "kind": "tflint-plugin", "plugin_source": "github.com/terraform-linters/tflint-ruleset-aws",
				"version": "0.50.0", "published": "2026-10-23",
				"url":    "https://github.com/terraform-linters/tflint-ruleset-aws/releases/download/v0.50.0/tflint-ruleset-aws_linux_amd64.zip",
				"sha256": strings.Repeat("1", 64), "archive": "zip", "binary": "tflint-ruleset-aws", "binary_sha256": hexSum(plugin), "signature": gpg,
			},
		},
		"providers": []any{
			map[string]any{
				"source": "registry.opentofu.org/hashicorp/aws", "version": "6.72.0", "published": "2026-11-04",
				"url":    "https://releases.hashicorp.com/terraform-provider-aws/6.72.0/terraform-provider-aws_6.72.0_linux_amd64.zip",
				"sha256": hexSum(zbuf.Bytes()), "h1": fixtureH1, "signature": gpg,
			},
		},
	}
	return fixture{cache: cache, lock: lock, bin: map[string][]byte{"tofu": tofu, "plugin": plugin}}
}

func (f fixture) json(t *testing.T) []byte {
	t.Helper()
	b, err := json.Marshal(f.lock)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func provider0(f fixture) map[string]any {
	providers, _ := f.lock["providers"].([]any)
	p, _ := providers[0].(map[string]any)
	return p
}

func tool0(f fixture) map[string]any {
	tools, _ := f.lock["tools"].([]any)
	t, _ := tools[0].(map[string]any)
	return t
}

// TestLoadToolchain proves D15 (T6, T143): LoadToolchain checks every binary,
// plugin and provider of the lock in the cache, and runs nothing from the
// cache itself: each tool and plugin is a private read-only copy, checked
// again, removed by Close. A changed or missing artifact, and a lock outside
// its closed form, are refused.
func TestLoadToolchain(t *testing.T) {
	f := newFixture(t)
	tc, err := LoadToolchain(f.json(t), f.cache)
	if err != nil {
		t.Fatalf("LoadToolchain: %v", err)
	}
	tofu, ok := tc.Tool("tofu")
	if !ok || tofu.Version != "1.13.2" || tofu.SHA256 != hexSum(f.bin["tofu"]) {
		t.Fatalf("Tool(tofu) = %+v, %v", tofu, ok)
	}
	if strings.HasPrefix(tofu.Path, f.cache) || !filepath.IsAbs(tofu.Path) {
		t.Errorf("tofu runs from %q: want a private copy outside the cache", tofu.Path)
	}
	info, err := os.Stat(tofu.Path)
	if err != nil || info.Mode().Perm()&0o222 != 0 {
		t.Errorf("private copy %q: %v, mode %v; want read-only", tofu.Path, err, info.Mode())
	}
	if b, err := os.ReadFile(tofu.Path); err != nil || hexSum(b) != tofu.SHA256 {
		t.Errorf("private copy differs from the locked binary: %v", err)
	}
	plugin := filepath.Join(tc.PluginDir(), "github.com/terraform-linters/tflint-ruleset-aws/0.50.0/tflint-ruleset-aws")
	if b, err := os.ReadFile(plugin); err != nil || !bytes.Equal(b, f.bin["plugin"]) || strings.HasPrefix(tc.PluginDir(), f.cache) { //nolint:gosec // G304: test path.
		t.Errorf("plugin copy %q: %v", plugin, err)
	}
	// T156: OpenTofu reads a private mirror holding exactly the locked zips,
	// copied and checked, never the mirror of the cache.
	if strings.HasPrefix(tc.MirrorDir(), f.cache) || !filepath.IsAbs(tc.MirrorDir()) {
		t.Errorf("MirrorDir = %q: want a private copy outside the cache", tc.MirrorDir())
	}
	var mirrored []string
	if err := filepath.WalkDir(tc.MirrorDir(), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(tc.MirrorDir(), p)
		mirrored = append(mirrored, filepath.ToSlash(rel))
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o222 != 0 {
			t.Errorf("private mirror entry %q: %v, want a read-only regular file", rel, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"registry.opentofu.org/hashicorp/aws/terraform-provider-aws_6.72.0_linux_amd64.zip"}; !slices.Equal(mirrored, want) {
		t.Errorf("private mirror holds %q, want exactly %q", mirrored, want)
	}
	if _, ok := tc.Tool("trivy"); ok {
		t.Error("Tool(trivy) found: not in the lock")
	}
	private := filepath.Dir(tofu.Path)
	if err := tc.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(private); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("private copies still present after Close: %v", err)
	}

	tamper := func(rel string) func(t *testing.T, f fixture) {
		return func(t *testing.T, f fixture) {
			p := filepath.Join(f.cache, filepath.FromSlash(rel))
			if err := os.Chmod(p, 0o700); err != nil { //nolint:gosec // G302: the fake cached binary stays executable by its owner.
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte("tampered"), 0o700); err != nil { //nolint:gosec // G306: test fake.
				t.Fatal(err)
			}
		}
	}
	remove := func(rel string) func(t *testing.T, f fixture) {
		return func(t *testing.T, f fixture) {
			if err := os.Remove(filepath.Join(f.cache, filepath.FromSlash(rel))); err != nil {
				t.Fatal(err)
			}
		}
	}
	set := func(key string, v any) func(t *testing.T, f fixture) {
		return func(_ *testing.T, f fixture) { tool0(f)[key] = v }
	}
	setProvider := func(key string, v any) func(t *testing.T, f fixture) {
		return func(_ *testing.T, f fixture) { provider0(f)[key] = v }
	}
	plant := func(rel string) func(t *testing.T, f fixture) {
		return func(t *testing.T, f fixture) {
			p := filepath.Join(f.cache, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte("#!/bin/sh\necho planted\n"), 0o700); err != nil { //nolint:gosec // G306: a planted fake provider.
				t.Fatal(err)
			}
		}
	}
	refused := map[string]func(t *testing.T, f fixture){
		"binary_tampered":   tamper("tools/tofu/1.13.2/tofu"),
		"plugin_tampered":   tamper("tflint-plugins/github.com/terraform-linters/tflint-ruleset-aws/0.50.0/tflint-ruleset-aws"),
		"provider_tampered": tamper("mirror/registry.opentofu.org/hashicorp/aws/terraform-provider-aws_6.72.0_linux_amd64.zip"),
		"binary_missing":    remove("tools/tofu/1.13.2/tofu"),
		"provider_missing":  remove("mirror/registry.opentofu.org/hashicorp/aws/terraform-provider-aws_6.72.0_linux_amd64.zip"),
		"unknown_field":     set("extra", "x"),
		"http_url":          set("url", "http://github.com/opentofu/opentofu/releases/download/v1.13.2/tofu_1.13.2_linux_amd64.zip"),
		"host_not_listed":   set("url", "https://example.com/tofu.zip"),
		"loose_version":     set("version", "1.13"),
		"upper_hash":        set("binary_sha256", strings.ToUpper(hexSum(f.bin["tofu"]))),
		"binary_with_slash": set("binary", "../tofu"),
		"name_with_dots":    set("name", "../tofu"),
		"unknown_kind":      set("kind", "script"),
		"unknown_archive":   set("archive", "rar"),
		"duplicate_tool": func(_ *testing.T, f fixture) {
			tools, _ := f.lock["tools"].([]any)
			f.lock["tools"] = append(tools, tools[0])
		},
		"other_platform": func(_ *testing.T, f fixture) { f.lock["platform"] = "darwin_arm64" },
		// T156: an entry of the mirror that the lock does not name.
		"planted_unpacked_package": plant("mirror/registry.opentofu.org/hashicorp/aws/6.72.0/linux_amd64/terraform-provider-aws_v6.72.0_x5"),
		"planted_other_version":    plant("mirror/registry.opentofu.org/hashicorp/aws/terraform-provider-aws_6.73.0_linux_amd64.zip"),
		"planted_other_provider":   plant("mirror/registry.opentofu.org/hashicorp/evil/terraform-provider-evil_1.0.0_linux_amd64.zip"),
		"planted_mirror_link": func(t *testing.T, f fixture) {
			if err := os.Symlink("/tmp", filepath.Join(f.cache, "mirror", "registry.opentofu.org", "hashicorp", "link")); err != nil {
				t.Fatal(err)
			}
		},
		// T156: the h1 of the lock is the one of the checked zip.
		"provider_h1_mismatch":  setProvider("h1", "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
		"provider_h1_missing":   func(_ *testing.T, f fixture) { delete(provider0(f), "h1") },
		"provider_h1_malformed": setProvider("h1", "zh:"+strings.Repeat("0", 64)),
		// Repository of each tool frozen (owner and name on github.com).
		"tool_other_repository": set("url", "https://github.com/evil/opentofu/releases/download/v1.13.2/tofu_1.13.2_linux_amd64.zip"),
		"tool_unknown_name":     set("name", "evil"),
		"lock_version_2":        func(_ *testing.T, f fixture) { f.lock["lock_version"] = 2 },
	}
	for name, mutate := range refused {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			mutate(t, f)
			tc, err := LoadToolchain(f.json(t), f.cache)
			if !errors.Is(err, ErrToolchain) {
				if tc != nil {
					_ = tc.Close()
				}
				t.Fatalf("LoadToolchain = %v, want ErrToolchain", err)
			}
		})
	}
	t.Run("relative_cache", func(t *testing.T) {
		f := newFixture(t)
		if _, err := LoadToolchain(f.json(t), "relative/cache"); !errors.Is(err, ErrToolchain) {
			t.Fatalf("LoadToolchain = %v, want ErrToolchain", err)
		}
	})
	t.Run("trailing_data", func(t *testing.T) {
		f := newFixture(t)
		if _, err := LoadToolchain(append(f.json(t), []byte(" {}")...), f.cache); !errors.Is(err, ErrToolchain) {
			t.Fatalf("LoadToolchain = %v, want ErrToolchain", err)
		}
	})
}

// TestProviderLockFile proves D15 against T156: the .terraform.lock.hcl of a
// root is rendered from the lock, with the h1 hash of the package (which
// OpenTofu checks against an unpacked package of the mirror) and the zh hash
// of the zip; init then runs with -lockfile=readonly. A source the lock does
// not name, no source, or a repeated source is refused.
func TestProviderLockFile(t *testing.T) {
	f := newFixture(t)
	tc, err := LoadToolchain(f.json(t), f.cache)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tc.Close() })
	got, err := tc.ProviderLockFile("registry.opentofu.org/hashicorp/aws")
	if err != nil {
		t.Fatal(err)
	}
	want := "# Rendered by Rempart from scripts/iac-tools.lock.json (ADR 0014 D15): never edited, never written by tofu.\n\n" +
		"provider \"registry.opentofu.org/hashicorp/aws\" {\n" +
		"  version     = \"6.72.0\"\n" +
		"  constraints = \"6.72.0\"\n" +
		"  hashes = [\n" +
		"    \"" + fixtureH1 + "\",\n" +
		"    \"zh:" + hexSum(mustZip(t, f)) + "\",\n" +
		"  ]\n" +
		"}\n"
	if string(got) != want {
		t.Fatalf("ProviderLockFile =\n%s\nwant\n%s", got, want)
	}
	for name, sources := range map[string][]string{
		"none":     nil,
		"unknown":  {"registry.opentofu.org/hashicorp/azurerm"},
		"repeated": {"registry.opentofu.org/hashicorp/aws", "registry.opentofu.org/hashicorp/aws"},
		"injected": {"registry.opentofu.org/hashicorp/aws\" {}\nprovider \"x"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := tc.ProviderLockFile(sources...); !errors.Is(err, ErrToolchain) {
				t.Fatalf("ProviderLockFile(%q) = %v, want ErrToolchain", sources, err)
			}
		})
	}
}

// mustZip reads the fixture provider zip of the cache.
func mustZip(t *testing.T, f fixture) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.cache, "mirror", "registry.opentofu.org", "hashicorp", "aws", "terraform-provider-aws_6.72.0_linux_amd64.zip"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
