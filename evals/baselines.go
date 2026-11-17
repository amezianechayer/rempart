// Package evals embeds the registry of the validated routes (ADR 0006, D8):
// a (platform, model) couple is validated for a suite when a human committed
// its baseline under evals/<suite>/baseline/<platform>/<model>.json. The
// composition roots inject it into llm.Config.ValidatedPairs.
package evals

import (
	"embed"
	"errors"
	"io/fs"
	"slices"
	"strings"

	ievals "github.com/amezianechayer/rempart/internal/evals"
	"github.com/amezianechayer/rempart/internal/llm"
	"github.com/amezianechayer/rempart/internal/llm/domain"
)

//go:embed */baseline/*/*.json
var baselines embed.FS

var (
	ErrInvalidSuite = errors.New("evals: invalid suite name")
	ErrInvalidPath  = errors.New("evals: path is not a baseline of a validated route")
)

const suiteBytes = "abcdefghijklmnopqrstuvwxyz0123456789_-"

// validSuite: one path element of [a-z0-9_-], 64 bytes at most, starting
// with a letter or a digit (the embedded pattern has one level of suite).
func validSuite(s string) bool {
	return s != "" && len(s) <= 64 && strings.Trim(s, suiteBytes) == "" && s[0] != '-' && s[0] != '_'
}

// DecodeBaselinePath returns the couple of a path relative to evals/; the
// path is admitted only if evals.BaselinePath gives it back for that couple.
func DecodeBaselinePath(p string) (llm.Pair, error) {
	parts := strings.Split(p, "/")
	if len(parts) != 4 || parts[1] != "baseline" || !validSuite(parts[0]) || !strings.HasSuffix(parts[3], ".json") {
		return llm.Pair{}, ErrInvalidPath
	}
	file := strings.TrimSuffix(parts[3], ".json")
	model := strings.NewReplacer("%3a", ":", "%40", "@", "%2f", "/").Replace(file)
	want, err := ievals.BaselinePath(parts[0], parts[2], model)
	if err != nil || want != "evals/"+p {
		return llm.Pair{}, ErrInvalidPath
	}
	return llm.Pair{Platform: domain.Platform(parts[2]), Model: model}, nil
}

// ValidatedPairs returns the couples validated for suite, sorted, the fake
// route included; a path that does not decode is never a couple.
func ValidatedPairs(suite string) ([]llm.Pair, error) {
	if !validSuite(suite) {
		return nil, ErrInvalidSuite
	}
	files, err := fs.Glob(baselines, suite+"/baseline/*/*.json")
	if err != nil {
		return nil, ErrInvalidSuite
	}
	out := []llm.Pair{}
	for _, f := range files {
		if p, err := DecodeBaselinePath(f); err == nil {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b llm.Pair) int {
		return strings.Compare(string(a.Platform)+"\x00"+a.Model, string(b.Platform)+"\x00"+b.Model)
	})
	return out, nil
}

// RealPairs returns ValidatedPairs without the fake route, the form taken by
// llm.Config.ValidatedPairs.
func RealPairs(suite string) ([]llm.Pair, error) {
	all, err := ValidatedPairs(suite)
	return slices.DeleteFunc(all, func(p llm.Pair) bool { return p.Platform == domain.PlatformFake }), err
}
