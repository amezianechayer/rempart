// Package redact masks secrets in text before it reaches a language model
// (skill llm-safety, rule 4; threat T7). Detection is deterministic: fixed
// RE2 regular expressions and fixed exemption rules, compiled once at package
// initialization. Each detected secret is replaced by Placeholder(kind); a
// Match gives its byte offsets in the input, never its value. Secrets are
// found by shape (token prefixes, PEM armor) or by context (a sensitive key
// followed by a value). Free-form secrets without such context are not found:
// see docs/plans/M0-redaction.md, section 5.8.
package redact

import (
	"cmp"
	"slices"
	"strings"
)

// Kind names a family of secrets. Its value appears in Placeholder.
type Kind string

const (
	KindAWSAccessKey    Kind = "aws_access_key"
	KindAWSSecretKey    Kind = "aws_secret_key"
	KindAWSSessionToken Kind = "aws_session_token"
	KindAzureSecret     Kind = "azure_secret"
	KindScalewayKey     Kind = "scaleway_key"
	KindOVHCredential   Kind = Kind("ovh_credential")
	KindPrivateKey      Kind = "private_key"
	KindGitHubToken     Kind = "github_token"
	KindGitLabToken     Kind = "gitlab_token"
	KindSlackToken      Kind = "slack_token"
	KindLLMAPIKey       Kind = Kind("llm_api_key")
	KindURLCredentials  Kind = "url_credentials"
	KindDBConnString    Kind = "db_connection_string"
	KindKubeconfig      Kind = "kubeconfig_credential"
	KindSensitiveVar    Kind = "sensitive_variable"
	KindIPsecPSK        Kind = "ipsec_psk"
)

// allKinds lists every Kind in declaration order.
var allKinds = []Kind{
	KindAWSAccessKey, KindAWSSecretKey, KindAWSSessionToken, KindAzureSecret,
	KindScalewayKey, KindOVHCredential, KindPrivateKey, KindGitHubToken,
	KindGitLabToken, KindSlackToken, KindLLMAPIKey, KindURLCredentials,
	KindDBConnString, KindKubeconfig, KindSensitiveVar, KindIPsecPSK,
}

// Match locates one redacted secret: bytes [Start, End) of the input.
type Match struct {
	Kind       Kind
	Start, End int
}

// Redactor masks secrets. It holds no state: the zero value and a nil
// *Redactor behave exactly like New(). It is safe for concurrent use.
type Redactor struct{}

// New returns a Redactor.
func New() *Redactor { return &Redactor{} }

// Placeholder returns the text that replaces a secret of kind k.
func Placeholder(k Kind) string {
	return "[REDACTED:" + string(k) + "]"
}

// Kinds returns every Kind, in declaration order, in a new slice.
func (r *Redactor) Kinds() []Kind {
	return slices.Clone(allKinds)
}

// ContainsSecret reports whether Redact(s) would redact anything.
func (r *Redactor) ContainsSecret(s string) bool {
	return len(find(s)) > 0
}

// Redact returns s with every detected secret replaced by its Placeholder,
// and the matches, sorted and disjoint, as byte offsets in s. Placeholders
// already present in s are never redacted again: Redact is idempotent.
func (r *Redactor) Redact(s string) (string, []Match) {
	ms := find(s)
	if len(ms) == 0 {
		return s, nil
	}
	var b strings.Builder
	b.Grow(len(s))
	prev := 0
	for _, m := range ms {
		b.WriteString(s[prev:m.Start])
		b.WriteString(Placeholder(m.Kind))
		prev = m.End
	}
	b.WriteString(s[prev:])
	return b.String(), ms
}

// find evaluates every rule on s, where existing placeholders are opaque,
// drops candidates that start inside them, and merges the rest.
func find(s string) []Match {
	protected := placeholderRe.FindAllStringIndex(s, -1)
	view := opaque(s, protected)
	var cs []candidate
	for prio, ru := range rules {
		for _, c := range ru.candidates(view, protected) {
			if c.end <= c.start || inside(protected, c.start) {
				continue
			}
			c.prio = prio
			cs = append(cs, c)
		}
	}
	return merge(cs)
}

// opaque returns s where every byte of the placeholders in protected is NUL,
// a byte that no rule reads through: an existing placeholder, like a secret
// masked by Redact, ends every token, key and value that reaches it, so that
// masking never changes how the rest of the text is read (idempotence).
func opaque(s string, protected [][]int) string {
	if len(protected) == 0 {
		return s
	}
	b := []byte(s)
	for _, p := range protected {
		clear(b[p[0]:p[1]])
	}
	return string(b)
}

// inside reports whether pos lies inside one of the sorted, disjoint spans in
// protected. A candidate that starts in a placeholder is already redacted, or
// is the re-reading of a redacted value: it is never redacted again.
func inside(protected [][]int, pos int) bool {
	return overlaps(protected, pos, pos+1)
}

// overlaps reports whether [lo, hi) overlaps one of the sorted, disjoint spans
// in protected. The search is dichotomic: its cost does not grow linearly
// with the number of placeholders (threat T10).
func overlaps(protected [][]int, lo, hi int) bool {
	// i is the first span that ends after lo.
	i, _ := slices.BinarySearchFunc(protected, lo, func(p []int, lo int) int {
		if p[1] <= lo {
			return -1
		}
		return 1
	})
	return i < len(protected) && protected[i][0] < hi
}

// merge unites strictly overlapping candidates. A group becomes a Match only
// if one of its candidates is not exempt; its Kind is that of the highest
// priority (lowest index) non-exempt candidate.
func merge(cs []candidate) []Match {
	slices.SortFunc(cs, func(a, b candidate) int {
		return cmp.Or(cmp.Compare(a.start, b.start), cmp.Compare(b.end, a.end), cmp.Compare(a.prio, b.prio))
	})
	var out []Match
	for i := 0; i < len(cs); {
		start, end := cs[i].start, cs[i].end
		best, active := len(rules), false
		j := i
		for ; j < len(cs) && cs[j].start < end; j++ {
			end = max(end, cs[j].end)
			if !cs[j].exempt {
				active = true
				best = min(best, cs[j].prio)
			}
		}
		if active {
			out = append(out, Match{Kind: rules[best].kind, Start: start, End: end})
		}
		i = j
	}
	return out
}
