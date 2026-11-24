package evals

import (
	"io/fs"
	"path"
	"slices"
	"strings"
)

func SelectChanged(suites []Suite, changed []string) []Suite {
	core := []string{"internal/evals/**", "internal/llm/schema/**", "cmd/rempart-evals/**", "go.mod", "go.sum"}
	all := slices.ContainsFunc(changed, func(c string) bool {
		return !fs.ValidPath(c) || strings.ContainsAny(c, "\"\\\t\n") || matchAny(core, c)
	})
	var out []Suite
	for _, s := range suites {
		concerns := func(c string) bool { return strings.HasPrefix(c, "evals/"+s.Name+"/") || matchAny(s.Watch, c) }
		if all || slices.ContainsFunc(changed, concerns) {
			out = append(out, s)
		}
	}
	return out
}

func matchAny(patterns []string, c string) bool {
	return slices.ContainsFunc(patterns, func(p string) bool {
		if !validPattern(p) {
			return true
		}
		prefix, subtree := strings.CutSuffix(p, "/**")
		name, segs, n := c, strings.Split(c, "/"), strings.Count(prefix, "/")+1
		if subtree && len(segs) <= n {
			return false
		}
		if subtree {
			name = strings.Join(segs[:n], "/")
		}
		ok, err := path.Match(prefix, name)
		return p == "**" || err != nil || ok // malformed: selected
	})
}

// patternSet is the closed set of a watch pattern (obligations (v) and (by),
// T67): no blank, control character, upper case, ?, [ ] or backslash.
const patternSet = "abcdefghijklmnopqrstuvwxyz0123456789._/*-"

func validPattern(p string) bool {
	prefix, _ := strings.CutSuffix(p, "/**")
	_, err := path.Match(prefix, "")
	return err == nil && len(p) <= 256 && strings.Trim(p, patternSet) == "" && fs.ValidPath(prefix) && !strings.Contains(prefix, "**")
}
