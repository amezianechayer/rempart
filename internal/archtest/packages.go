package archtest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Package is one package of `go list -json` output, reduced to the fields the
// import rules need. The JSON names are those of cmd/go, not snake_case.
type Package struct {
	ImportPath string   `json:"ImportPath"`
	Imports    []string `json:"Imports"` // non-test imports only; omitted by go list when empty
}

var (
	ErrModuleDir  = errors.New("archtest: empty module directory")
	ErrGoList     = errors.New("archtest: go list failed")
	ErrDecode     = errors.New("archtest: invalid go list output")
	ErrNoPackages = errors.New("archtest: go list returned no package")
)

// maxStderrTail bounds the part of go list's standard error kept in an error.
const maxStderrTail = 2048

// LoadPackages runs `go list -json ./...` in moduleDir, without a shell, and
// decodes its output. Test files are not listed: their imports are not subject
// to the rules.
func LoadPackages(ctx context.Context, moduleDir string) ([]Package, error) {
	if moduleDir == "" {
		return nil, ErrModuleDir
	}
	out, err := goListCmd(ctx, moduleDir, os.Environ()).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			tail := exitErr.Stderr
			if len(tail) > maxStderrTail {
				tail = tail[len(tail)-maxStderrTail:]
			}
			return nil, fmt.Errorf("%w: %w: %s", ErrGoList, err, strings.TrimSpace(string(tail)))
		}
		return nil, fmt.Errorf("%w: %w", ErrGoList, err)
	}
	return decodePackages(bytes.NewReader(out))
}

// goListCmd builds, without running it, the only command this package executes.
// The arguments are string literals written in the call: no shell, no
// caller-controlled argument.
func goListCmd(ctx context.Context, moduleDir string, environ []string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "go", "list", "-json", "./...")
	cmd.Dir = moduleDir
	cmd.Env = goListEnv(environ)
	cmd.WaitDelay = 10 * time.Second
	return cmd
}

// goListEnv returns environ without GOFLAGS and GOWORK entries, followed by
// "GOFLAGS=-mod=readonly" and "GOWORK=off": go list never rewrites go.mod and
// a go.work file in a parent directory cannot change the analysed module.
func goListEnv(environ []string) []string {
	env := make([]string, 0, len(environ)+2)
	for _, kv := range environ {
		key, _, _ := strings.Cut(kv, "=")
		if key == "GOFLAGS" || key == "GOWORK" {
			continue
		}
		env = append(env, kv)
	}
	return append(env, "GOFLAGS=-mod=readonly", "GOWORK=off")
}

// decodePackages decodes the concatenated JSON objects printed by go list -json.
// Every value must be an object with a non-empty, unique ImportPath; an empty
// stream is ErrNoPackages, so that an empty repository never looks compliant.
func decodePackages(r io.Reader) ([]Package, error) {
	dec := json.NewDecoder(r)
	var pkgs []Package
	seen := map[string]bool{}
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("%w: %w", ErrDecode, err)
		}
		if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '{' {
			return nil, fmt.Errorf("%w: value %d is not an object", ErrDecode, len(pkgs)+1)
		}
		var p Package // fresh value: an omitted Imports never inherits the previous package's
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrDecode, err)
		}
		if p.ImportPath == "" {
			return nil, fmt.Errorf("%w: package %d has an empty ImportPath", ErrDecode, len(pkgs)+1)
		}
		if seen[p.ImportPath] {
			return nil, fmt.Errorf("%w: duplicate ImportPath %q", ErrDecode, p.ImportPath)
		}
		seen[p.ImportPath] = true
		pkgs = append(pkgs, p)
	}
	if len(pkgs) == 0 {
		return nil, ErrNoPackages
	}
	return pkgs, nil
}
