//go:build integration

package validate

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/amezianechayer/rempart/internal/validate/toolexec"
)

// Integration tests of M3-T02 ("Outils": make -f Makefile iac-tools first).
// They need the toolchain of scripts/iac-tools.lock.json in the cache
// (REMPART_IAC_CACHE, or ~/.cache/rempart/iac-tools): an absent toolchain
// fails them, it never passes them.

func loadRepoToolchain(t *testing.T) *Toolchain {
	t.Helper()
	lock, err := os.ReadFile("../../scripts/iac-tools.lock.json")
	if err != nil {
		t.Fatal(err)
	}
	cache := os.Getenv("REMPART_IAC_CACHE")
	if cache == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		cache = filepath.Join(home, ".cache", "rempart", "iac-tools")
	}
	tc, err := LoadToolchain(lock, cache)
	if err != nil {
		t.Fatalf("LoadToolchain(%s): %v (run make -f Makefile iac-tools)", cache, err)
	}
	t.Cleanup(func() { _ = tc.Close() })
	return tc
}

// probeSources is the provider of each probe root.
var probeSources = map[string]string{
	"aws":     "registry.opentofu.org/hashicorp/aws",
	"azurerm": "registry.opentofu.org/hashicorp/azurerm",
	"helm":    "registry.opentofu.org/hashicorp/helm",
}

// probeRoot copies testdata/probe/<name> to a fresh directory, writes its
// .terraform.lock.hcl rendered from the lock (T156), and writes the
// mirror-only CLI configuration next to it.
func probeRoot(t *testing.T, tc *Toolchain, name string) (ws *toolexec.Workspace, env []string) {
	t.Helper()
	return probeRootMirror(t, tc, name, tc.MirrorDir())
}

func probeRootMirror(t *testing.T, tc *Toolchain, name, mirror string) (ws *toolexec.Workspace, env []string) {
	t.Helper()
	ws, err := toolexec.NewWorkspace()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ws.Close() })
	src := filepath.Join("testdata", "probe", name)
	err = filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		b, err := os.ReadFile(p) //nolint:gosec // G304: testdata of this package.
		if err != nil {
			return err
		}
		return ws.WriteFile(filepath.ToSlash(rel), b)
	})
	if err != nil {
		t.Fatal(err)
	}
	lockHCL, err := tc.ProviderLockFile(probeSources[name])
	if err != nil {
		t.Fatal(err)
	}
	if err := ws.WriteFile(".terraform.lock.hcl", lockHCL); err != nil {
		t.Fatal(err)
	}
	cfg, err := TofuCLIConfig(mirror)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(t.TempDir(), "mirror.tfrc")
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	return ws, []string{"TF_CLI_CONFIG_FILE=" + cfgPath, "CHECKPOINT_DISABLE=1", "TF_IN_AUTOMATION=1"}
}

func tofu(t *testing.T, tc *Toolchain, ws *toolexec.Workspace, env []string, args ...string) toolexec.Result {
	t.Helper()
	bin, ok := tc.Tool("tofu")
	if !ok {
		t.Fatal("tofu absent from the toolchain")
	}
	res, err := toolexec.Run(context.Background(), toolexec.Spec{
		Tool: bin, Args: args, Workspace: ws, Env: env,
		Timeout: 5 * time.Minute, MaxStdout: 64 << 20, MaxStderr: 8 << 20,
	})
	if err != nil {
		t.Fatalf("tofu %v: %v", args, err)
	}
	return res
}

// TestOfflineInitFromMirror proves D15 (T143, T156): tofu init installs every
// provider of the probe roots from the private file mirror alone, network
// cut, with no registry, against the .terraform.lock.hcl rendered from the
// lock (h1 and zh), in readonly mode: the lock file is left as rendered.
func TestOfflineInitFromMirror(t *testing.T) {
	tc := loadRepoToolchain(t)
	for root, source := range probeSources {
		t.Run(root, func(t *testing.T) {
			ws, env := probeRoot(t, tc, root)
			rendered, err := tc.ProviderLockFile(source)
			if err != nil {
				t.Fatal(err)
			}
			res := tofu(t, tc, ws, env, "init", "-input=false", "-no-color", "-lockfile=readonly")
			if res.ExitCode != 0 {
				t.Fatalf("tofu init: exit %d\n%s", res.ExitCode, res.Stderr)
			}
			if _, err := os.Stat(filepath.Join(ws.Dir(), ".terraform")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("tofu wrote .terraform in the tree: TF_DATA_DIR is not the one of the workspace (obligation (hf))")
			}
			lock, err := os.ReadFile(filepath.Join(ws.Dir(), ".terraform.lock.hcl"))
			if err != nil || string(lock) != string(rendered) {
				t.Fatalf("lock file changed by init: %v\n%s", err, lock)
			}
		})
	}
}

// TestOfflineInitRefusesPlantedPackage proves the second barrier of D15
// against T156, independent of the private mirror: next to the locked helm
// zip, a mirror holds an unpacked package of the same version (a script);
// with the .terraform.lock.hcl rendered from the lock, tofu init refuses it
// (its h1 matches no recorded checksum). Reproduces the review of M3-T02,
// where a lock file with zh hashes only let the planted package in.
func TestOfflineInitRefusesPlantedPackage(t *testing.T) {
	tc := loadRepoToolchain(t)
	mirror := t.TempDir()
	const helm = "registry.opentofu.org/hashicorp/helm"
	zipName := "terraform-provider-helm_3.3.0_linux_amd64.zip"
	b, err := os.ReadFile(filepath.Join(tc.MirrorDir(), filepath.FromSlash(helm), zipName))
	if err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(mirror, filepath.FromSlash(helm), "3.3.0", "linux_amd64")
	if err := os.MkdirAll(planted, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mirror, filepath.FromSlash(helm), zipName), b, 0o600); err != nil { //nolint:gosec // G703: temporary directory of this test.
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(planted, "terraform-provider-helm_v3.3.0_x5"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { //nolint:gosec // G306,G703: the planted fake provider.
		t.Fatal(err)
	}
	ws, env := probeRootMirror(t, tc, "helm", mirror)
	res := tofu(t, tc, ws, env, "init", "-input=false", "-no-color", "-lockfile=readonly")
	// tofu wraps its diagnostics: compare on the text with collapsed spaces.
	if msg := strings.Join(strings.Fields(string(res.Stderr)), " "); res.ExitCode == 0 || !strings.Contains(msg, "doesn't match any of the checksums previously recorded") {
		t.Fatalf("tofu init with a planted package: exit %d, want a checksum refusal\n%s", res.ExitCode, res.Stderr)
	}
}

// TestOfflinePlanProbe freezes the result of the probe of ADR 0014 (section
// "Résultat de la sonde", branch of Q2): with no credential and the network
// cut, aws plans (with its offline settings, the injected aws_iam_user in the
// plan) and helm plans, while azurerm cannot (it asks a token of
// login.microsoftonline.com when the provider is configured). If a provider
// changes behavior, this test fails and the branch of D8 is reconsidered.
func TestOfflinePlanProbe(t *testing.T) {
	tc := loadRepoToolchain(t)
	plan := func(t *testing.T, root string) (toolexec.Result, *toolexec.Workspace, []string) {
		ws, env := probeRoot(t, tc, root)
		if res := tofu(t, tc, ws, env, "init", "-input=false", "-no-color", "-lockfile=readonly"); res.ExitCode != 0 {
			t.Fatalf("tofu init: exit %d\n%s", res.ExitCode, res.Stderr)
		}
		return tofu(t, tc, ws, env, "plan", "-refresh=false", "-lock=false", "-input=false", "-no-color", "-out=plan.bin"), ws, env
	}
	addresses := func(t *testing.T, ws *toolexec.Workspace, env []string) []string {
		res := tofu(t, tc, ws, env, "show", "-json", "plan.bin")
		var p struct {
			ResourceChanges []struct{ Address string } `json:"resource_changes"`
		}
		if res.ExitCode != 0 || json.Unmarshal(res.Stdout, &p) != nil {
			t.Fatalf("tofu show: exit %d\n%s", res.ExitCode, res.Stderr)
		}
		var out []string
		for _, rc := range p.ResourceChanges {
			out = append(out, rc.Address)
		}
		slices.Sort(out)
		return out
	}
	t.Run("aws_feasible_with_settings", func(t *testing.T) {
		res, ws, env := plan(t, "aws")
		if res.ExitCode != 0 {
			t.Fatalf("tofu plan: exit %d\n%s", res.ExitCode, res.Stderr)
		}
		got := addresses(t, ws, env)
		want := []string{"aws_eks_cluster.c", "aws_iam_role.eks", "aws_iam_user.injected", "aws_kms_key.k", "aws_security_group.sg", "aws_subnet.a", "aws_subnet.b", "aws_vpc.v"}
		if !slices.Equal(got, want) {
			t.Fatalf("planned resources %q, want %q", got, want)
		}
	})
	t.Run("helm_feasible", func(t *testing.T) {
		res, ws, env := plan(t, "helm")
		if res.ExitCode != 0 {
			t.Fatalf("tofu plan: exit %d\n%s", res.ExitCode, res.Stderr)
		}
		if got := addresses(t, ws, env); !slices.Equal(got, []string{"helm_release.r"}) {
			t.Fatalf("planned resources %q", got)
		}
	})
	t.Run("azurerm_impossible", func(t *testing.T) {
		res, _, _ := plan(t, "azurerm")
		if res.ExitCode == 0 || !strings.Contains(string(res.Stderr), "login.microsoftonline.com") {
			t.Fatalf("tofu plan: exit %d, want a failure on the token request\n%s", res.ExitCode, res.Stderr)
		}
	})
}
