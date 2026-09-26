package evals

import (
	"errors"
	"strings"
)

var ErrUnsupportedPath = errors.New("evals: unsupported path")

func parsePath(p string) ([]string, error) {
	rest, ok := strings.CutPrefix(p, "$")
	if !ok || len(p) > 256 {
		return nil, ErrUnsupportedPath
	}
	steps := []string{} // "" is [*]
	for rest != "" {
		if len(steps) == 16 {
			return nil, ErrUnsupportedPath
		}
		if tail, isAll := strings.CutPrefix(rest, "[*]"); isAll {
			steps, rest = append(steps, ""), tail
			continue
		}
		field, isField := strings.CutPrefix(rest, ".")
		end := strings.IndexAny(field, ".[")
		if end < 0 {
			end = len(field)
		}
		if !isField || end == 0 || end > 64 || strings.Trim(field[:end], loopSet) != "" {
			return nil, ErrUnsupportedPath
		}
		steps, rest = append(steps, field[:end]), field[end:]
	}
	return steps, nil
}

func selectPath(v any, steps []string) []any {
	cur := []any{v}
	for _, step := range steps {
		var next []any
		for _, x := range cur {
			switch x := x.(type) {
			case []any:
				if step == "" {
					next = append(next, x...)
				}
			case map[string]any:
				if y, ok := x[step]; ok && step != "" {
					next = append(next, y)
				}
			}
		}
		cur = next
	}
	return cur
}
