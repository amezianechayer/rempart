// Package domain holds the pure types of the generic loop engine: normalized
// findings, their fingerprint and their score.
package domain

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
)

// Severity is a normalized severity; any other value weighs as critical.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Finding is one normalized verifier finding. Every field is untrusted.
type Finding struct {
	Code     string   `json:"code"`
	Source   string   `json:"source"`
	Severity Severity `json:"severity"`
	Resource string   `json:"resource"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Message  string   `json:"message"`
}

// Weight returns the score weight of s.
func (s Severity) Weight() int {
	switch s {
	case SeverityCritical:
		return 100
	case SeverityHigh:
		return 20
	case SeverityMedium:
		return 5
	case SeverityLow:
		return 1
	case SeverityInfo:
		return 0
	default:
		return 100 // unknown severity: fail safe
	}
}

// Sort returns a sorted copy of f under a total order (weight descending).
func Sort(f []Finding) []Finding {
	out := slices.Clone(f)
	slices.SortFunc(out, compareFindings)
	return out
}

func compareFindings(a, b Finding) int {
	return cmp.Or(
		cmp.Compare(b.Severity.Weight(), a.Severity.Weight()),
		cmp.Compare(a.Severity, b.Severity),
		cmp.Compare(a.File, b.File),
		cmp.Compare(a.Line, b.Line),
		cmp.Compare(a.Code, b.Code),
		cmp.Compare(a.Resource, b.Resource),
		cmp.Compare(a.Source, b.Source),
		cmp.Compare(a.Message, b.Message),
	)
}

// Top returns the first n findings of Sort(f), none if n <= 0.
func Top(f []Finding, n int) []Finding {
	if n <= 0 {
		return nil
	}
	s := Sort(f)
	return s[:min(n, len(s))]
}

// Score returns the sum of the weights of f, duplicates included.
func Score(f []Finding) int {
	total := 0
	for _, x := range f {
		total += x.Severity.Weight()
	}
	return total
}

// Fingerprint returns the hex SHA-256 of the sorted distinct (code, resource)
// netstrings of the findings weighing at least medium.
func Fingerprint(f []Finding) string {
	type couple struct{ code, resource string }
	var cs []couple
	for _, x := range f {
		if x.Severity.Weight() >= SeverityMedium.Weight() {
			cs = append(cs, couple{x.Code, x.Resource})
		}
	}
	slices.SortFunc(cs, func(a, b couple) int {
		return cmp.Or(cmp.Compare(a.code, b.code), cmp.Compare(a.resource, b.resource))
	})
	cs = slices.Compact(cs)
	var buf []byte
	for _, c := range cs {
		buf = appendNetstring(appendNetstring(buf, c.code), c.resource)
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}

func appendNetstring(buf []byte, s string) []byte {
	buf = strconv.AppendInt(buf, int64(len(s)), 10)
	buf = append(buf, ':')
	buf = append(buf, s...)
	return append(buf, ',')
}
