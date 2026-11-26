package validate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/amezianechayer/rempart/internal/validate/toolexec"
)

// ErrToolchain: the lock or the cache of the IaC toolchain is refused (ADR
// 0014 D15). Fixed messages: never a value read from the lock or the cache.
var ErrToolchain = errors.New("validate: invalid toolchain")

func toolchainErr(reason string) error { return fmt.Errorf("%w: %s", ErrToolchain, reason) }

// Layout of the cache, shared with scripts/iac-tools.sh.
const (
	cacheTools   = "tools"          // tools/<name>/<version>/<binary>
	cachePlugins = "tflint-plugins" // tflint-plugins/<plugin_source>/<version>/<binary>
	cacheMirror  = "mirror"         // mirror/<source>/terraform-provider-<type>_<version>_linux_amd64.zip
)

type lockSignature struct {
	Kind     string `json:"kind"`
	Key      string `json:"key"`
	Identity string `json:"identity"`
	Issuer   string `json:"issuer"`
	Checked  string `json:"checked"`
	Note     string `json:"note"`
}

type lockTool struct {
	Name         string        `json:"name"`
	Kind         string        `json:"kind"`
	PluginSource string        `json:"plugin_source,omitempty"`
	Version      string        `json:"version"`
	Published    string        `json:"published"`
	URL          string        `json:"url"`
	SHA256       string        `json:"sha256"`
	Archive      string        `json:"archive"`
	Binary       string        `json:"binary"`
	BinarySHA256 string        `json:"binary_sha256"`
	Signature    lockSignature `json:"signature"`
}

type lockProvider struct {
	Source    string        `json:"source"`
	Version   string        `json:"version"`
	Published string        `json:"published"`
	URL       string        `json:"url"`
	SHA256    string        `json:"sha256"`
	Signature lockSignature `json:"signature"`
}

type lockFile struct {
	LockVersion int            `json:"lock_version"`
	Date        string         `json:"date"`
	MinAgeDays  int            `json:"min_age_days"`
	Platform    string         `json:"platform"`
	Hosts       []string       `json:"hosts"`
	Tools       []lockTool     `json:"tools"`
	Providers   []lockProvider `json:"providers"`
}

var (
	semverRe    = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	sha256Re    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	toolNameRe  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	pluginSrcRe = regexp.MustCompile(`^github\.com/terraform-linters/tflint-ruleset-[a-z0-9]+$`)
	providerRe  = regexp.MustCompile(`^registry\.opentofu\.org/hashicorp/([a-z0-9-]+)$`)
	lockHosts   = []string{"github.com", "releases.hashicorp.com"}
)

// Toolchain is the toolchain of the lock, checked in the cache: every tool
// and tflint plugin runs from a private read-only copy (D15: no window
// between the check and the run on a file a third party can change); the
// provider archives stay in the mirror of the cache, checked.
type Toolchain struct {
	tools   map[string]toolexec.Tool
	private string
	mirror  string
}

func parseLock(lock []byte) (lockFile, error) {
	var lf lockFile
	dec := json.NewDecoder(bytes.NewReader(lock))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&lf); err != nil {
		return lockFile{}, toolchainErr("lock decoding")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return lockFile{}, toolchainErr("data after the lock")
	}
	if lf.LockVersion != 1 || lf.Platform != "linux_amd64" {
		return lockFile{}, toolchainErr("lock version or platform")
	}
	for _, h := range lf.Hosts {
		if !slices.Contains(lockHosts, h) {
			return lockFile{}, toolchainErr("lock host")
		}
	}
	httpsOn := func(raw string) bool {
		u, err := url.Parse(raw)
		return err == nil && u.Scheme == "https" && slices.Contains(lf.Hosts, u.Host) && u.User == nil && u.RawQuery == "" && u.Fragment == ""
	}
	seen := map[string]bool{}
	for _, t := range lf.Tools {
		switch {
		case !toolNameRe.MatchString(t.Name) || seen[t.Name]:
			return lockFile{}, toolchainErr("tool name")
		case t.Kind != "tool" && t.Kind != "tflint-plugin":
			return lockFile{}, toolchainErr("tool kind")
		case (t.Kind == "tflint-plugin") != (t.PluginSource != ""),
			t.PluginSource != "" && (!pluginSrcRe.MatchString(t.PluginSource) || !strings.HasSuffix(t.PluginSource, "/"+t.Name)):
			return lockFile{}, toolchainErr("plugin source")
		case !semverRe.MatchString(t.Version) || !httpsOn(t.URL):
			return lockFile{}, toolchainErr("tool version or url")
		case !sha256Re.MatchString(t.SHA256) || !sha256Re.MatchString(t.BinarySHA256):
			return lockFile{}, toolchainErr("tool hash")
		case t.Archive != "zip" && t.Archive != "tar.gz":
			return lockFile{}, toolchainErr("tool archive")
		case !toolNameRe.MatchString(t.Binary):
			return lockFile{}, toolchainErr("tool binary")
		}
		seen[t.Name] = true
	}
	seenP := map[string]bool{}
	for _, p := range lf.Providers {
		m := providerRe.FindStringSubmatch(p.Source)
		if m == nil || seenP[p.Source] || !semverRe.MatchString(p.Version) || !sha256Re.MatchString(p.SHA256) {
			return lockFile{}, toolchainErr("provider")
		}
		if p.URL != "https://releases.hashicorp.com/terraform-provider-"+m[1]+"/"+p.Version+"/"+providerZip(m[1], p.Version) || !httpsOn(p.URL) {
			return lockFile{}, toolchainErr("provider url")
		}
		seenP[p.Source] = true
	}
	return lf, nil
}

func providerZip(typ, version string) string {
	return "terraform-provider-" + typ + "_" + version + "_linux_amd64.zip"
}

// hashFile hashes the regular file at path (never through a link).
func hashFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", toolchainErr("artifact missing or not a regular file")
	}
	f, err := os.Open(path) //nolint:gosec // G304: a path of the cache layout, checked by its hash.
	if err != nil {
		return "", toolchainErr("artifact unreadable")
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", toolchainErr("artifact unreadable")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// copyChecked copies the regular file src to dst (created, 0700), hashing
// what it copies, and makes dst read-only when the hash is want.
func copyChecked(src, dst, want string) error {
	info, err := os.Lstat(src) //nolint:gosec // G703: a path of the cache layout, built from names the lock grammar admits.
	if err != nil || !info.Mode().IsRegular() {
		return toolchainErr("binary missing or not a regular file")
	}
	in, err := os.Open(src) //nolint:gosec // G304: a path of the cache layout, checked by its hash.
	if err != nil {
		return toolchainErr("binary unreadable")
	}
	defer func() { _ = in.Close() }()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return fmt.Errorf("validate: private copy: %w", err)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700) //nolint:gosec // G302,G304: private directory of this process.
	if err != nil {
		return fmt.Errorf("validate: private copy: %w", err)
	}
	h := sha256.New()
	_, cerr := io.Copy(io.MultiWriter(out, h), in)
	if err := out.Close(); cerr == nil {
		cerr = err
	}
	if cerr != nil {
		return fmt.Errorf("validate: private copy: %w", cerr)
	}
	if hex.EncodeToString(h.Sum(nil)) != want {
		return toolchainErr("binary hash mismatch")
	}
	return os.Chmod(dst, 0o500) //nolint:gosec // G302: a tool must stay executable by its owner; read-only.
}

// LoadToolchain checks the lock (closed form) and, in cacheDir laid out by
// scripts/iac-tools.sh, every artifact it names: each tool and tflint plugin
// is copied, hash checked, to a private read-only directory it then runs
// from; each provider archive of the mirror is hash checked. Close removes
// the private copies.
func LoadToolchain(lock []byte, cacheDir string) (*Toolchain, error) {
	if !filepath.IsAbs(cacheDir) {
		return nil, toolchainErr("cache directory is not absolute")
	}
	lf, err := parseLock(lock)
	if err != nil {
		return nil, err
	}
	private, err := os.MkdirTemp("", "rempart-toolchain-")
	if err != nil {
		return nil, fmt.Errorf("validate: private directory: %w", err)
	}
	tc := &Toolchain{tools: map[string]toolexec.Tool{}, private: private, mirror: filepath.Join(cacheDir, cacheMirror)}
	fail := func(err error) (*Toolchain, error) {
		_ = tc.Close()
		return nil, err
	}
	for _, t := range lf.Tools {
		if t.Kind == "tflint-plugin" {
			rel := filepath.Join(filepath.FromSlash(t.PluginSource), t.Version, t.Binary)
			if err := copyChecked(filepath.Join(cacheDir, cachePlugins, rel), filepath.Join(tc.PluginDir(), rel), t.BinarySHA256); err != nil {
				return fail(err)
			}
			continue
		}
		dst := filepath.Join(private, "bin", t.Name)
		if err := copyChecked(filepath.Join(cacheDir, cacheTools, t.Name, t.Version, t.Binary), dst, t.BinarySHA256); err != nil {
			return fail(err)
		}
		tc.tools[t.Name] = toolexec.Tool{Name: t.Name, Version: t.Version, Path: dst, SHA256: t.BinarySHA256}
	}
	for _, p := range lf.Providers {
		typ := providerRe.FindStringSubmatch(p.Source)[1]
		got, err := hashFile(filepath.Join(tc.mirror, filepath.FromSlash(p.Source), providerZip(typ, p.Version)))
		if err != nil {
			return fail(err)
		}
		if got != p.SHA256 {
			return fail(toolchainErr("provider hash mismatch"))
		}
	}
	return tc, nil
}

// Tool returns the locked tool name, run from its private copy.
func (tc *Toolchain) Tool(name string) (toolexec.Tool, bool) {
	t, ok := tc.tools[name]
	return t, ok
}

// PluginDir is the private copy of the tflint plugins (TFLINT_PLUGIN_DIR).
func (tc *Toolchain) PluginDir() string { return filepath.Join(tc.private, "plugins") }

// MirrorDir is the provider mirror of the cache, for TofuCLIConfig.
func (tc *Toolchain) MirrorDir() string { return tc.mirror }

// Close removes the private copies.
func (tc *Toolchain) Close() error {
	if tc == nil || tc.private == "" {
		return nil
	}
	return os.RemoveAll(tc.private) //nolint:gosec // G703: the private directory this process created with os.MkdirTemp.
}

// TofuCLIConfig is the OpenTofu CLI configuration of D15: providers of the
// hashicorp namespace from the file mirror only, no direct installation, no
// network mirror, no credentials. The mirror path is absolute, clean, and
// holds nothing that could leave or expand inside the HCL string.
func TofuCLIConfig(mirror string) ([]byte, error) {
	if !filepath.IsAbs(mirror) || filepath.Clean(mirror) != mirror || strings.ContainsAny(mirror, "\"\\$%") {
		return nil, toolchainErr("mirror path")
	}
	for _, r := range mirror {
		if r < 0x20 || r == 0x7f {
			return nil, toolchainErr("mirror path")
		}
	}
	return []byte("provider_installation {\n  filesystem_mirror {\n    path    = \"" + mirror + "\"\n" +
		"    include = [\"registry.opentofu.org/hashicorp/*\"]\n  }\n}\n"), nil
}
