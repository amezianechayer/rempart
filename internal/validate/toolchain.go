package validate

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
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
	H1        string        `json:"h1"`
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
	h1Re        = regexp.MustCompile(`^h1:[A-Za-z0-9+/]{43}=$`)
	lockHosts   = []string{"github.com", "releases.hashicorp.com"}
	// toolRepos freezes the github.com repository of each tool: a tool of
	// another owner under the same name, or an unknown tool, is refused.
	toolRepos = map[string]string{
		"tofu":                   "opentofu/opentofu",
		"tflint":                 "terraform-linters/tflint",
		"tflint-ruleset-aws":     "terraform-linters/tflint-ruleset-aws",
		"tflint-ruleset-azurerm": "terraform-linters/tflint-ruleset-azurerm",
		"trivy":                  "aquasecurity/trivy",
	}
)

// Toolchain is the toolchain of the lock, checked in the cache: every tool,
// tflint plugin and provider archive is a private read-only copy, hashed as
// it is copied (D15: no window between the check and the use of a file a
// third party can change). OpenTofu reads the private mirror, which holds the
// locked zips and nothing else (T156).
type Toolchain struct {
	tools     map[string]toolexec.Tool
	providers map[string]lockProvider
	private   string
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
		case toolRepos[t.Name] == "" || !strings.HasPrefix(t.URL, "https://github.com/"+toolRepos[t.Name]+"/releases/download/v"+t.Version+"/"):
			return lockFile{}, toolchainErr("tool repository")
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
		if m == nil || seenP[p.Source] || !semverRe.MatchString(p.Version) || !sha256Re.MatchString(p.SHA256) || !h1Re.MatchString(p.H1) {
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

// copyChecked copies the regular file src to dst (created, 0700), hashing
// what it copies, and gives dst the read-only mode when the hash is want.
func copyChecked(src, dst, want string, mode os.FileMode) error {
	info, err := os.Lstat(src) //nolint:gosec // G703: a path of the cache layout, built from names the lock grammar admits.
	if err != nil || !info.Mode().IsRegular() {
		return toolchainErr("artifact missing or not a regular file")
	}
	in, err := os.Open(src) //nolint:gosec // G304: a path of the cache layout, checked by its hash.
	if err != nil {
		return toolchainErr("artifact unreadable")
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
		return toolchainErr("artifact hash mismatch")
	}
	return os.Chmod(dst, mode)
}

// checkMirror refuses, in the provider mirror of the cache, any entry the lock
// does not name (T156): an unpacked package, another version or another
// provider of the namespace, a link. OpenTofu prefers what it finds there.
func checkMirror(mirror string, zips []string) error {
	info, err := os.Lstat(mirror) //nolint:gosec // G703: the mirror of the cache layout, under an absolute cache directory.
	switch {
	case errors.Is(err, fs.ErrNotExist) && len(zips) == 0:
		return nil
	case err != nil || !info.IsDir():
		return toolchainErr("provider mirror missing or not a directory")
	}
	files, dirs := map[string]bool{}, map[string]bool{}
	for _, z := range zips {
		files[z] = true
		for d := path.Dir(z); d != "."; d = path.Dir(d) {
			dirs[d] = true
		}
	}
	walk := func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return toolchainErr("provider mirror unreadable")
		}
		rel, err := filepath.Rel(mirror, p)
		if err != nil {
			return toolchainErr("provider mirror unreadable")
		}
		rel = filepath.ToSlash(rel)
		switch {
		case rel == ".":
			return nil
		case d.IsDir() && dirs[rel], d.Type().IsRegular() && files[rel]:
			return nil
		default:
			return toolchainErr("entry of the provider mirror not named by the lock")
		}
	}
	return filepath.WalkDir(mirror, walk) //nolint:gosec // G703: the mirror of the cache layout, walked without following links.
}

// hash1Zip is the dirhash Hash1 of the members of the zip at p: the "h1:"
// hash OpenTofu records in a .terraform.lock.hcl and checks against an
// unpacked package (golang.org/x/mod/sumdb/dirhash, HashZip).
func hash1Zip(p string) (string, error) {
	z, err := zip.OpenReader(p)
	if err != nil {
		return "", toolchainErr("provider archive unreadable")
	}
	defer func() { _ = z.Close() }()
	byName := map[string]*zip.File{}
	var names []string
	for _, f := range z.File {
		if strings.Contains(f.Name, "\n") || byName[f.Name] != nil {
			return "", toolchainErr("provider archive member name")
		}
		byName[f.Name] = f
		names = append(names, f.Name)
	}
	slices.Sort(names)
	summary := sha256.New()
	for _, n := range names {
		r, err := byName[n].Open()
		if err != nil {
			return "", toolchainErr("provider archive unreadable")
		}
		h := sha256.New()
		_, err = io.Copy(h, r)
		_ = r.Close()
		if err != nil {
			return "", toolchainErr("provider archive unreadable")
		}
		_, _ = fmt.Fprintf(summary, "%x  %s\n", h.Sum(nil), n)
	}
	return "h1:" + base64.StdEncoding.EncodeToString(summary.Sum(nil)), nil
}

// LoadToolchain checks the lock (closed form) and, in cacheDir laid out by
// scripts/iac-tools.sh, every artifact it names: each tool, tflint plugin and
// provider archive is copied, hash checked, to a private read-only directory
// it is then used from; the mirror of the cache holds nothing the lock does
// not name, and the h1 hash of each provider is the one of its checked zip.
// Close removes the private copies.
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
	tc := &Toolchain{tools: map[string]toolexec.Tool{}, providers: map[string]lockProvider{}, private: private}
	fail := func(err error) (*Toolchain, error) {
		_ = tc.Close()
		return nil, err
	}
	for _, t := range lf.Tools {
		if t.Kind == "tflint-plugin" {
			rel := filepath.Join(filepath.FromSlash(t.PluginSource), t.Version, t.Binary)
			if err := copyChecked(filepath.Join(cacheDir, cachePlugins, rel), filepath.Join(tc.PluginDir(), rel), t.BinarySHA256, 0o500); err != nil {
				return fail(err)
			}
			continue
		}
		dst := filepath.Join(private, "bin", t.Name)
		if err := copyChecked(filepath.Join(cacheDir, cacheTools, t.Name, t.Version, t.Binary), dst, t.BinarySHA256, 0o500); err != nil {
			return fail(err)
		}
		tc.tools[t.Name] = toolexec.Tool{Name: t.Name, Version: t.Version, Path: dst, SHA256: t.BinarySHA256}
	}
	zips := make([]string, 0, len(lf.Providers))
	for _, p := range lf.Providers {
		zips = append(zips, p.Source+"/"+providerZip(providerRe.FindStringSubmatch(p.Source)[1], p.Version))
	}
	if err := checkMirror(filepath.Join(cacheDir, cacheMirror), zips); err != nil {
		return fail(err)
	}
	for i, p := range lf.Providers {
		rel := filepath.FromSlash(zips[i])
		dst := filepath.Join(tc.MirrorDir(), rel)
		if err := copyChecked(filepath.Join(cacheDir, cacheMirror, rel), dst, p.SHA256, 0o400); err != nil {
			return fail(err)
		}
		h1, err := hash1Zip(dst)
		if err != nil {
			return fail(err)
		}
		if h1 != p.H1 {
			return fail(toolchainErr("provider h1 mismatch"))
		}
		tc.providers[p.Source] = p
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

// MirrorDir is the private provider mirror, for TofuCLIConfig: the locked
// zips, copied and checked, and nothing else.
func (tc *Toolchain) MirrorDir() string { return filepath.Join(tc.private, "mirror") }

// ProviderLockFile renders the .terraform.lock.hcl of a root that requires
// sources, each pinned exactly in its required_providers: for each, the
// locked version, and the h1 hash of the package (which OpenTofu checks
// against an unpacked package of the mirror, T156) and zh hash of the zip.
// The chain writes it before tofu init -lockfile=readonly; it is never taken
// from the root itself. A source the lock does not name, or repeated, is
// refused; every value comes from the closed grammar of the lock.
func (tc *Toolchain) ProviderLockFile(sources ...string) ([]byte, error) {
	if len(sources) == 0 {
		return nil, toolchainErr("no provider for the lock file")
	}
	var b strings.Builder
	b.WriteString("# Rendered by Rempart from scripts/iac-tools.lock.json (ADR 0014 D15): never edited, never written by tofu.\n")
	seen := map[string]bool{}
	for _, s := range sources {
		p, ok := tc.providers[s]
		if !ok || seen[s] {
			return nil, toolchainErr("provider not in the lock, or repeated")
		}
		seen[s] = true
		b.WriteString("\nprovider \"" + p.Source + "\" {\n" +
			"  version     = \"" + p.Version + "\"\n" +
			"  constraints = \"" + p.Version + "\"\n" +
			"  hashes = [\n" +
			"    \"" + p.H1 + "\",\n" +
			"    \"zh:" + p.SHA256 + "\",\n" +
			"  ]\n}\n")
	}
	return []byte(b.String()), nil
}

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
