package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path"
	"strings"

	"github.com/amezianechayer/rempart/internal/evals"
)

var errUnsafeBaselinePath = errors.New("rempart-evals: baseline path holds a link or a file")

// readBaseline: D18, the baseline of (suite, platform, model) (ADR 0002).
func readBaseline(repo *os.Root, suite string, id Identity) (evals.Baseline, error) {
	p, err := evals.BaselinePath(suite, id.Platform, id.Model)
	if err != nil {
		return evals.Baseline{}, err
	}
	return evals.LoadBaseline(repo.FS(), p)
}

// writeBaseline: D19, zero tolerances, canonical content, temporary file then rename.
func writeBaseline(repo *os.Root, suite string, id Identity, r evals.Report) (string, error) {
	p, err := evals.BaselinePath(suite, id.Platform, id.Model)
	if err != nil {
		return "", err
	}
	data, err := evals.EncodeBaseline(evals.Baseline{Report: r, Tolerances: evals.Tolerances{}})
	if err != nil {
		return "", err
	}
	dir := path.Dir(p)
	parts := strings.Split(dir, "/")
	for i := range parts {
		info, err := repo.Lstat(strings.Join(parts[:i+1], "/"))
		if errors.Is(err, fs.ErrNotExist) {
			break
		}
		if err != nil || !info.IsDir() {
			return "", errUnsafeBaselinePath
		}
	}
	if err := repo.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	var suffix [8]byte
	_, _ = rand.Read(suffix[:])
	tmp := path.Join(dir, ".tmp-"+hex.EncodeToString(suffix[:])+".json")
	f, err := repo.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", err
	}
	_, werr := f.Write(data)
	if cerr := f.Close(); werr != nil || cerr != nil {
		_ = repo.Remove(tmp)
		return "", errors.Join(werr, cerr)
	}
	if err := repo.Rename(tmp, p); err != nil {
		_ = repo.Remove(tmp)
		return "", err
	}
	return p, nil
}
