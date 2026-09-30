package evals

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
)

const (
	maxDiscoverEntries = 10_000
	maxSuites          = 256
)

// DiscoverSuites returns, sorted, the names of the suites under the root of
// fsys, the evals directory (D17): no link anywhere, at most 10 000 entries
// and 256 suites, names valid and neither all nor changed, no nested suite;
// cases/ and baseline/ of a suite are not searched for suites.
func DiscoverSuites(fsys fs.FS) ([]string, error) {
	lfs, ok := fsys.(fs.ReadLinkFS)
	if !ok {
		return nil, fmt.Errorf("%w: file system", ErrInvalidSuite)
	}
	var suites []string
	entries := 0
	err := fs.WalkDir(lfs, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return errors.New("walk")
		}
		if entries++; entries > maxDiscoverEntries {
			return errors.New("entries")
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return errors.New("link")
		}
		if !d.IsDir() {
			if d.Name() == "suite.yaml" {
				if !d.Type().IsRegular() {
					return errors.New("suite file")
				}
				suites = append(suites, path.Dir(p))
			}
			return nil
		}
		if name := d.Name(); p != "." && (name == "cases" || name == "baseline") {
			if info, err := lfs.Lstat(path.Join(path.Dir(p), "suite.yaml")); err == nil && info.Mode().IsRegular() {
				return fs.SkipDir
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: discovery: %w", ErrInvalidSuite, err)
	}
	slices.Sort(suites)
	if len(suites) > maxSuites {
		return nil, fmt.Errorf("%w: discovery: too many suites", ErrInvalidSuite)
	}
	for i, s := range suites {
		if !validSuiteName(s) || s == "all" || s == "changed" {
			return nil, fmt.Errorf("%w: discovery: suite %d: name", ErrInvalidSuite, i)
		}
		for _, o := range suites {
			if strings.HasPrefix(s, o+"/") {
				return nil, fmt.Errorf("%w: discovery: suite %d: nested", ErrInvalidSuite, i)
			}
		}
	}
	return suites, nil
}
