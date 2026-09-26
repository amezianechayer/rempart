package redact

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Test 1 (task sheet): every line of redaction-patterns.md has positive cases
// whose output, kinds and match spans are exact.
func TestRedactPatterns(t *testing.T) {
	names := make([]string, 0, len(positiveCases))
	for _, tc := range positiveCases {
		names = append(names, tc.name)
	}
	requireUniqueNames(t, names)

	r := New()
	for _, tc := range positiveCases {
		t.Run(tc.name, func(t *testing.T) {
			out, ms := r.Redact(tc.in)
			if out != tc.want {
				t.Errorf("%s: Redact output\n got: %q\nwant: %q", tc.name, out, tc.want)
			}
			if got := kindsOf(ms); !slices.Equal(got, tc.kinds) {
				t.Errorf("%s: kinds = %v, want %v", tc.name, got, tc.kinds)
			}
			if !r.ContainsSecret(tc.in) {
				t.Errorf("%s: ContainsSecret(input) = false, want true", tc.name)
			}
			if r.ContainsSecret(out) {
				t.Errorf("%s: ContainsSecret(output) = true, want false", tc.name)
			}
			if err := checkSpans(tc.in, ms); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			for _, m := range ms {
				if span := tc.in[m.Start:m.End]; strings.Contains(out, span) {
					t.Errorf("%s: redacted span %q of match %+v survives in the output", tc.name, span, m)
				}
			}
			if got := rebuild(tc.in, ms); got != out {
				t.Errorf("%s: output is not the input with each match replaced by its placeholder\nrebuilt: %q\n output: %q", tc.name, got, out)
			}
		})
	}
}

// Test 3 (task sheet): ordinary infrastructure text is left untouched.
func TestNoFalsePositive(t *testing.T) {
	names := make([]string, 0, len(negativeCases))
	for _, tc := range negativeCases {
		names = append(names, tc.name)
	}
	requireUniqueNames(t, names)

	r := New()
	for _, tc := range negativeCases {
		t.Run(tc.name, func(t *testing.T) {
			out, ms := r.Redact(tc.in)
			if out != tc.in {
				t.Errorf("%s: Redact changed a text without secret\n got: %q\nwant: %q", tc.name, out, tc.in)
			}
			if ms != nil {
				t.Errorf("%s: Redact matches = %+v, want nil", tc.name, ms)
			}
			if r.ContainsSecret(tc.in) {
				t.Errorf("%s: ContainsSecret = true, want false", tc.name)
			}
		})
	}
}

// Test 6 (task sheet): a Match locates a secret by offsets and never carries
// its value, whatever the rendering.
func TestMatchesCarryNoValue(t *testing.T) {
	t.Run("shape", func(t *testing.T) {
		typ := reflect.TypeFor[Match]()
		if typ.Kind() != reflect.Struct {
			t.Fatalf("Match is a %v, want a struct", typ.Kind())
		}
		want := []struct {
			name string
			typ  reflect.Type
		}{
			{"Kind", reflect.TypeFor[Kind]()},
			{"Start", reflect.TypeFor[int]()},
			{"End", reflect.TypeFor[int]()},
		}
		if typ.NumField() != len(want) {
			t.Fatalf("Match has %d fields, want exactly %d (Kind, Start, End)", typ.NumField(), len(want))
		}
		for i, w := range want {
			f := typ.Field(i)
			if f.Name != w.name || f.Type != w.typ {
				t.Errorf("Match field %d = %s %v, want %s %v", i, f.Name, f.Type, w.name, w.typ)
			}
		}
		if k := reflect.TypeFor[Kind]().Kind(); k != reflect.String {
			t.Errorf("Kind has underlying kind %v, want string", k)
		}
		if n := typ.NumMethod(); n != 0 {
			t.Errorf("Match has %d methods, want 0", n)
		}
		if n := reflect.PointerTo(typ).NumMethod(); n != 0 {
			t.Errorf("*Match has %d methods, want 0", n)
		}
	})

	t.Run("no_secret_in_rendering", func(t *testing.T) {
		r := New()
		for _, tc := range positiveCases {
			_, ms := r.Redact(tc.in)
			if err := checkSpans(tc.in, ms); err != nil {
				t.Errorf("%s: %v", tc.name, err)
				continue
			}
			text := fmt.Sprintf("%v %+v %#v", ms, ms, ms)
			raw, err := json.Marshal(ms)
			if err != nil {
				t.Fatalf("%s: json.Marshal(matches): %v", tc.name, err)
			}
			for _, m := range ms {
				span := tc.in[m.Start:m.End]
				if strings.Contains(text, span) {
					t.Errorf("%s: fmt rendering of the matches contains the redacted span %q", tc.name, span)
				}
				if strings.Contains(string(raw), span) {
					t.Errorf("%s: JSON rendering of the matches contains the redacted span %q", tc.name, span)
				}
			}
		}
	})

	t.Run("kinds_are_known", func(t *testing.T) {
		r := New()
		known := r.Kinds()
		for _, in := range allFixtures() {
			_, ms := r.Redact(in)
			for _, m := range ms {
				if !slices.Contains(known, m.Kind) {
					t.Errorf("Redact(%q) returned kind %q, not listed by Kinds()", in, m.Kind)
				}
			}
		}
	})
}

// Test 7: Kinds lists the 16 kinds of the task sheet, in declaration order,
// in a fresh slice, whatever the receiver.
func TestKinds(t *testing.T) {
	t.Run("exact_order", func(t *testing.T) {
		want := []string{
			"aws_access_key", "aws_secret_key", "aws_session_token", "azure_secret",
			"scaleway_key", "ovh_credential", "private_key", "github_token",
			"gitlab_token", "slack_token", "llm_api_key", "url_credentials",
			"db_connection_string", "kubeconfig_credential", "sensitive_variable", "ipsec_psk",
		}
		got := New().Kinds()
		if len(got) != len(want) {
			t.Fatalf("Kinds() has %d entries, want %d: %v", len(got), len(want), got)
		}
		shape := regexp.MustCompile(`^[a-z][a-z_]*[a-z]$`)
		seen := make(map[Kind]bool, len(got))
		for i, k := range got {
			if string(k) != want[i] {
				t.Errorf("Kinds()[%d] = %q, want %q", i, k, want[i])
			}
			if declaredKinds[i] != k {
				t.Errorf("Kinds()[%d] = %q, but the constant declared at this position is %q", i, k, declaredKinds[i])
			}
			if !shape.MatchString(string(k)) {
				t.Errorf("Kinds()[%d] = %q does not match %s", i, k, shape)
			}
			if seen[k] {
				t.Errorf("Kinds() lists %q twice", k)
			}
			seen[k] = true
		}
	})

	t.Run("fresh_copy", func(t *testing.T) {
		r := New()
		first := r.Kinds()
		if len(first) == 0 {
			t.Fatal("Kinds() is empty")
		}
		first[0] = Kind("mutated_by_caller")
		if again := r.Kinds(); len(again) == 0 || again[0] != KindAWSAccessKey {
			t.Errorf("mutating a returned slice changed the next Kinds() call: %v", again)
		}
		if other := New().Kinds(); len(other) == 0 || other[0] != KindAWSAccessKey {
			t.Errorf("mutating a returned slice changed Kinds() of another Redactor: %v", other)
		}
	})

	t.Run("zero_and_nil", func(t *testing.T) {
		want := New().Kinds()
		if got := (&Redactor{}).Kinds(); !slices.Equal(got, want) {
			t.Errorf("zero Redactor Kinds() = %v, want %v", got, want)
		}
		if got := (*Redactor)(nil).Kinds(); !slices.Equal(got, want) {
			t.Errorf("nil *Redactor Kinds() = %v, want %v", got, want)
		}
	})
}

// Test 8: a placeholder has an exact text and is never taken for a secret.
func TestPlaceholder(t *testing.T) {
	r := New()
	all := make([]string, 0, len(declaredKinds))
	for _, k := range declaredKinds {
		all = append(all, Placeholder(k))
		t.Run(string(k), func(t *testing.T) {
			want := "[REDACTED:" + string(k) + "]"
			p := Placeholder(k)
			if p != want {
				t.Fatalf("Placeholder(%q) = %q, want %q", k, p, want)
			}
			if r.ContainsSecret(p) {
				t.Errorf("ContainsSecret(Placeholder(%q)) = true, want false", k)
			}
			if out, ms := r.Redact(p); out != p || ms != nil {
				t.Errorf("Redact(Placeholder(%q)) = %q, %+v, want the input and nil", k, out, ms)
			}
		})
	}
	joined := strings.Join(all, " ")
	if out, ms := r.Redact(joined); out != joined || ms != nil {
		t.Errorf("Redact(all placeholders) = %q, %+v, want the input and nil", out, ms)
	}
	if r.ContainsSecret(joined) {
		t.Error("ContainsSecret(all placeholders) = true, want false")
	}
}

// Test 9: overlapping candidates become one mask, their union, labelled by the
// most specific kind.
func TestOverlapPriority(t *testing.T) {
	names := make([]string, 0, len(overlapCases))
	for _, tc := range overlapCases {
		names = append(names, tc.name)
	}
	requireUniqueNames(t, names)

	r := New()
	for _, tc := range overlapCases {
		t.Run(tc.name, func(t *testing.T) {
			out, ms := r.Redact(tc.in)
			if out != tc.want {
				t.Errorf("%s: Redact output\n got: %q\nwant: %q", tc.name, out, tc.want)
			}
			if got := kindsOf(ms); !slices.Equal(got, tc.kinds) {
				t.Errorf("%s: kinds = %v, want %v", tc.name, got, tc.kinds)
			}
			if got := rebuild(tc.in, ms); got != out {
				t.Errorf("%s: rebuilt %q, output %q", tc.name, got, out)
			}
			if r.ContainsSecret(out) {
				t.Errorf("%s: ContainsSecret(output) = true, want false", tc.name)
			}
		})
	}
}

// Test 10: matches are byte offsets of the original input, sorted and
// disjoint, and they rebuild the output exactly.
func TestMatchPositions(t *testing.T) {
	r := New()

	t.Run("all_fixtures", func(t *testing.T) {
		type pair struct{ name, in, want string }
		var pairs []pair
		for _, c := range positiveCases {
			pairs = append(pairs, pair{c.name, c.in, c.want})
		}
		for _, c := range overlapCases {
			pairs = append(pairs, pair{c.name, c.in, c.want})
		}
		for _, c := range narrowCases {
			pairs = append(pairs, pair{c.name, c.in, c.want})
		}
		for _, p := range pairs {
			out, ms := r.Redact(p.in)
			if err := checkSpans(p.in, ms); err != nil {
				t.Errorf("%s: %v", p.name, err)
				continue
			}
			if got := rebuild(p.in, ms); got != p.want || got != out {
				t.Errorf("%s: rebuilt %q, output %q, want %q", p.name, got, out, p.want)
			}
		}
	})

	exact := []struct {
		name, in string
		want     []Match
	}{
		{"ascii", "x AKIAIOSFODNN7EXAMPLE y", []Match{{Kind: KindAWSAccessKey, Start: 2, End: 22}}},
		{"multibyte_prefix", "é password: FAKEpw12", []Match{{Kind: KindSensitiveVar, Start: 13, End: 21}}},
		{"two_keys", "a=1 password=FAKEone token=FAKEtwo", []Match{
			{Kind: KindSensitiveVar, Start: 13, End: 20},
			{Kind: KindKubeconfig, Start: 27, End: 34},
		}},
	}
	for _, tc := range exact {
		t.Run(tc.name, func(t *testing.T) {
			_, ms := r.Redact(tc.in)
			if !slices.Equal(ms, tc.want) {
				t.Errorf("%s: matches = %+v, want %+v", tc.name, ms, tc.want)
			}
		})
	}
}

// Test 11: the exemptions of the generic rule are narrow: near misses are
// still redacted.
func TestExemptionsAreNarrow(t *testing.T) {
	names := make([]string, 0, len(narrowCases))
	for _, tc := range narrowCases {
		names = append(names, tc.name)
	}
	requireUniqueNames(t, names)

	r := New()
	for _, tc := range narrowCases {
		t.Run(tc.name, func(t *testing.T) {
			out, ms := r.Redact(tc.in)
			if out != tc.want {
				t.Errorf("%s: Redact output\n got: %q\nwant: %q", tc.name, out, tc.want)
			}
			if len(ms) == 0 {
				t.Errorf("%s: no match, want at least one", tc.name)
			}
			if !r.ContainsSecret(tc.in) {
				t.Errorf("%s: ContainsSecret(input) = false, want true", tc.name)
			}
		})
	}
}

// Test 12: the zero value and a nil *Redactor redact exactly like New().
func TestZeroAndNilRedactor(t *testing.T) {
	ref := New()
	var zero Redactor
	var null *Redactor
	receivers := []struct {
		name string
		r    *Redactor
	}{
		{"zero_value", &zero},
		{"nil_pointer", null},
	}
	for _, rc := range receivers {
		t.Run(rc.name, func(t *testing.T) {
			for _, in := range allFixtures() {
				wantOut, wantMs := ref.Redact(in)
				wantHas := ref.ContainsSecret(in)
				var gotOut string
				var gotMs []Match
				var gotHas bool
				if p := recovered(func() {
					gotOut, gotMs = rc.r.Redact(in)
					gotHas = rc.r.ContainsSecret(in)
				}); p != nil {
					t.Fatalf("%s: panic on %q: %v", rc.name, in, p)
				}
				if gotOut != wantOut || !slices.Equal(gotMs, wantMs) {
					t.Errorf("%s: Redact(%q) = %q, %+v, want %q, %+v", rc.name, in, gotOut, gotMs, wantOut, wantMs)
				}
				if gotHas != wantHas {
					t.Errorf("%s: ContainsSecret(%q) = %v, want %v", rc.name, in, gotHas, wantHas)
				}
			}
		})
	}
}

// recovered runs f and returns the value of a panic, or nil.
func recovered(f func()) (p any) {
	defer func() { p = recover() }()
	f()
	return nil
}

// Test 14: invalid UTF-8 is kept byte for byte; offsets are in bytes.
func TestInvalidUTF8(t *testing.T) {
	cases := []struct {
		in, want string
		ms       []Match
	}{
		{"\xff\xfe AKIAIOSFODNN7EXAMPLE \xff", "\xff\xfe [REDACTED:aws_access_key] \xff", []Match{{Kind: KindAWSAccessKey, Start: 3, End: 23}}},
	}
	r := New()
	for _, tc := range cases {
		out, ms := r.Redact(tc.in)
		if out != tc.want {
			t.Errorf("Redact(%q) = %q, want %q", tc.in, out, tc.want)
		}
		if !slices.Equal(ms, tc.ms) {
			t.Errorf("Redact(%q) matches = %+v, want %+v", tc.in, ms, tc.ms)
		}
	}
}

// Test 15: one Redactor shared by concurrent goroutines (run under -race).
func TestConcurrentUse(t *testing.T) {
	r := New()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 20 {
				for _, tc := range positiveCases {
					out, _ := r.Redact(tc.in)
					if out != tc.want {
						t.Errorf("%s: concurrent Redact = %q, want %q", tc.name, out, tc.want)
						return
					}
					if !r.ContainsSecret(tc.in) {
						t.Errorf("%s: concurrent ContainsSecret = false, want true", tc.name)
						return
					}
				}
			}
		})
	}
	wg.Wait()
}

// Test 16: adversarial inputs of 160 KiB to 1.2 MiB, built to maximise
// restarts, are redacted exactly; run with -timeout 120s, durations are
// logged.
func TestLargeInputAdversarial(t *testing.T) {
	cases := []struct {
		name string
		in   string
		// count is the exact number of matches; kind their only kind.
		count int
		kind  Kind
		// want is the exact output; empty means the input unchanged.
		want       string
		start, end int // bounds of the single match, when count == 1
		// control, when set, is an input of the same size and the same
		// matches as in, without existing placeholders. Redacting in must not
		// cost more than 3 times control plus 1 s: the cost of a candidate
		// does not grow with the number of placeholders (V2 F5).
		control string
	}{
		{
			name:  "many_keyed_values",
			in:    strings.Repeat("password=FAKEvalue0\n", 1<<13),
			count: 1 << 13, kind: KindSensitiveVar,
			want: strings.Repeat("password=[REDACTED:sensitive_variable]\n", 1<<13),
		},
		{
			name:  "pem_headers_without_end",
			in:    strings.Repeat("-----BEGIN FAKE PRIVATE KEY-----", 1<<13),
			count: 1 << 13, kind: KindPrivateKey,
			want: strings.Repeat(Placeholder(KindPrivateKey), 1<<13),
		},
		{
			name: "url_prefixes_without_at",
			in:   strings.Repeat("https://u:", 1<<15),
		},
		{
			name: "long_identifier",
			in:   strings.Repeat("password", 1<<15),
		},
		{
			name:  "long_run_then_llm_key",
			in:    strings.Repeat("a", 1<<18) + " sk-FAKEEXAMPLE0000000000000",
			count: 1, kind: KindLLMAPIKey,
			want:  strings.Repeat("a", 1<<18) + " [REDACTED:llm_api_key]",
			start: 1<<18 + 1, end: -1,
		},
		{
			name: "quoted_keys_without_value",
			in:   strings.Repeat("{\"password\":", 1<<14),
		},
		{
			name: "block_indicators",
			in:   strings.Repeat("password: |\n", 1<<14),
		},
		{
			name:  "nested_keys",
			in:    strings.Repeat("password=(", 1<<15),
			count: 1, kind: KindSensitiveVar,
			want:  "password=[REDACTED:sensitive_variable]",
			start: 9, end: -1,
		},
		// V2 (docs/plans/M0-redaction.md, section 0 bis).
		{
			name:    "placeholders_then_keys",
			in:      strings.Repeat("[REDACTED:ipsec_psk]", 1<<15) + strings.Repeat(" token=x", 1<<16),
			count:   1 << 16,
			kind:    KindKubeconfig,
			want:    strings.Repeat("[REDACTED:ipsec_psk]", 1<<15) + strings.Repeat(" token=[REDACTED:kubeconfig_credential]", 1<<16),
			control: strings.Repeat("[redacted:ipsec_psk]", 1<<15) + strings.Repeat(" token=x", 1<<16),
		},
		{
			name:  "name_value_objects",
			in:    strings.Repeat(`{"name":"db_password","value":"v"}`, 1<<13),
			count: 1 << 13, kind: KindSensitiveVar,
			want: strings.Repeat(`{"name":"db_password","value":"[REDACTED:sensitive_variable]"}`, 1<<13),
		},
		{
			name:  "name_value_yaml_items",
			in:    strings.Repeat("- name: DB_PASSWORD\n  value: v\n", 1<<13),
			count: 1 << 13, kind: KindSensitiveVar,
			want: strings.Repeat("- name: DB_PASSWORD\n  value: [REDACTED:sensitive_variable]\n", 1<<13),
		},
		{
			name:  "nested_name_value_blocks",
			in:    "- name: DB_PASSWORD\n  value: |" + strings.Repeat("\n  - name: DB_PASSWORD\n    value: |", 1<<13),
			count: 1, kind: KindSensitiveVar,
			want:  "- name: DB_PASSWORD\n  value: |\n  [REDACTED:sensitive_variable]",
			start: 33, end: -1,
		},
		{
			name:  "unterminated_quote_long_line",
			in:    `{"password": "` + strings.Repeat(" password: x", 1<<14),
			count: 1, kind: KindSensitiveVar,
			want:  `{"password": "[REDACTED:sensitive_variable]`,
			start: 14, end: -1,
		},
		{
			name: "userinfo_with_at",
			in:   strings.Repeat("https://a@b:", 1<<15),
		},
		{
			name:  "pgp_armor_headers",
			in:    "-----BEGIN PGP PRIVATE KEY BLOCK-----" + strings.Repeat("\nVersion: x", 1<<14),
			count: 1, kind: KindPrivateKey,
			want:  "[REDACTED:private_key]",
			start: 0, end: -1,
		},
		{
			name:  "open_arrays",
			in:    strings.Repeat("api_keys: [", 1<<14),
			count: 1 << 14, kind: KindSensitiveVar,
			want: "api_keys: " + strings.Repeat("[REDACTED:sensitive_variable] ", 1<<14-1) + "[REDACTED:sensitive_variable]",
		},
		{
			name: "authorization_before_placeholders",
			in:   strings.Repeat("Authorization: Basic [REDACTED:ipsec_psk] ", 1<<13),
		},
		{
			name:  "authorization_arrays",
			in:    strings.Repeat("Authorization:[", 1<<14),
			count: 1, kind: KindSensitiveVar,
			want:  "Authorization:[REDACTED:sensitive_variable]",
			start: 14, end: -1,
		},
	}
	r := New()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			begin := time.Now()
			out, ms := r.Redact(tc.in)
			took := time.Since(begin)
			t.Logf("%s: %d bytes redacted in %v", tc.name, len(tc.in), took)

			if tc.control != "" {
				begin := time.Now()
				_, cms := r.Redact(tc.control)
				base := time.Since(begin)
				t.Logf("%s: control of %d bytes redacted in %v", tc.name, len(tc.control), base)
				if len(tc.control) != len(tc.in) || len(cms) != tc.count {
					t.Fatalf("%s: control has %d bytes and %d matches, want %d bytes and %d matches", tc.name, len(tc.control), len(cms), len(tc.in), tc.count)
				}
				if took > 3*base+time.Second {
					t.Errorf("%s: %v with existing placeholders, %v without: the cost of a candidate grows with the number of placeholders", tc.name, took, base)
				}
			}

			if len(ms) != tc.count {
				t.Fatalf("%s: %d matches, want %d", tc.name, len(ms), tc.count)
			}
			for i, m := range ms {
				if m.Kind != tc.kind {
					t.Fatalf("%s: match %d has kind %q, want %q", tc.name, i, m.Kind, tc.kind)
				}
			}
			want := tc.want
			if tc.count == 0 {
				want = tc.in
			}
			if want != "" && out != want {
				t.Errorf("%s: output differs from the expected one (got %d bytes, want %d)", tc.name, len(out), len(want))
			}
			if tc.count == 1 {
				end := tc.end
				if end < 0 {
					end = len(tc.in)
				}
				if ms[0].Start != tc.start || ms[0].End != end {
					t.Errorf("%s: match [%d, %d), want [%d, %d)", tc.name, ms[0].Start, ms[0].End, tc.start, end)
				}
			}
			if err := checkSpans(tc.in, ms); err != nil {
				t.Errorf("%s: %v", tc.name, err)
			}
		})
	}
}
