package redact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// soupWords are hostile fragments: sensitive keys, separators, quotes and
// escapes, block indicators, references, existing placeholders, marked token
// fixtures and PEM armor pieces (docs/plans/M0-redaction.md, section 7.5).
var soupWords = []string{
	"password", "db_password", "token", "max_tokens", "secret_name", "api_key",
	"Authorization", "Bearer ", "PSK ", "https://", "postgres://", "u",
	":", ": ", "=", " = ",
	"\n", "\n  ", `\n`, `\n  `,
	`"`, "'", `\"`, "|", ">", "(", "[", "]", "{", "}",
	"$", "${", "{{", "}}", "&", "?", ";", ",", "@",
	"var.", "true", "1024", "12345678901",
	"[REDACTED:sensitive_variable]", "[REDACTED:github_token]",
	"[REDACTED:private_key]", "[REDACTED:url_credentials]",
	"AKIAIOSFODNN7EXAMPLE",
	"ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000",
	"sk-FAKEEXAMPLE0000000000000",
	"-----BEGIN FAKE PRIVATE KEY-----", "-----END FAKE PRIVATE KEY-----",
	"LS0tLS1CRUdJTi", "Proc-Type: 4,ENCRYPTED",
	"FAKE", "x",
	// V2 (docs/plans/M0-redaction.md, section 0 bis): user names with '@'
	// (F1), arrays (F2), armor headers (F3), name and value pairs (F4),
	// JSON escapes of '&', '<' and '>' (F7), quantity segments (F8), "pass"
	// and "auth" keys (F9).
	"@example.com:", `["`, `"]`, "Basic ",
	"-----BEGIN PGP PRIVATE KEY BLOCK-----", "Version: ",
	"name", "value", "- name: ", "  value: ", `"name":`, `"value":`, "DB_PASSWORD",
	`\u0026`, `\u003c`, `\u003e`, "<",
	"admin_password", "maxTokens", "pass", "auth", "RABBITMQ_DEFAULT_PASS",
}

// soup joins up to 40 hostile fragments or random words, without separator.
func soup() *rapid.Generator[string] {
	parts := rapid.SliceOfN(rapid.OneOf(
		rapid.SampledFrom(soupWords),
		rapid.StringMatching("[A-Za-z0-9]{1,24}"),
	), 0, 40)
	return rapid.Map(parts, func(p []string) string { return strings.Join(p, "") })
}

// example is a text that contains exactly one secret body of a known kind.
type example struct {
	input, body string
	kind        Kind
}

// textGen draws a text and the secret body it contains.
type textGen func(t *rapid.T) (text, body string)

// keyedFormats are the key and value syntaxes of HCL, tfvars, YAML, JSON,
// env files and JSON-escaped JSON; none contains a value. The V2 formats add
// one-line arrays (F2), a quote never closed before the end of the line (F6)
// and a key after '&' written \u0026 by json.Marshal (F7).
var keyedFormats = []string{
	`%s: %s`, `%s: "%s"`, `"%s": "%s"`, `%s = "%s"`, `%s=%s`, `%s: '%s'`, `\"%s\": \"%s\"`,
	`%s: [%s]`, `"%s": ["%s", "x"]`, `%s = ["%s"]`, `"%s": "%s`, `%s: '%s`, `?a=1\u0026%s=%s`,
}

// bodyAlone draws a body matching expr and uses it as the whole text.
func bodyAlone(expr string) textGen {
	return func(t *rapid.T) (string, string) {
		b := rapid.StringMatching(expr).Draw(t, "body")
		return b, b
	}
}

// underKey draws a key among keys, a keyed format and a body matching expr.
func underKey(keys []string, expr string) textGen {
	return underKeyGen(keys, rapid.StringMatching(expr))
}

// underKeyGen draws a key among keys, a keyed format and a body from gen.
func underKeyGen(keys []string, gen *rapid.Generator[string]) textGen {
	return func(t *rapid.T) (string, string) {
		k := rapid.SampledFrom(keys).Draw(t, "key")
		f := rapid.SampledFrom(keyedFormats).Draw(t, "format")
		b := gen.Draw(t, "body")
		return fmt.Sprintf(f, k, b), b
	}
}

// inTemplate draws a body matching expr and formats it into tmpl.
func inTemplate(tmpl, expr string) textGen {
	return func(t *rapid.T) (string, string) {
		b := rapid.StringMatching(expr).Draw(t, "body")
		return fmt.Sprintf(tmpl, b), b
	}
}

// anyOf draws one of the given text generators.
func anyOf(gens ...textGen) textGen {
	return func(t *rapid.T) (string, string) {
		i := rapid.IntRange(0, len(gens)-1).Draw(t, "form")
		return gens[i](t)
	}
}

// pemBlock draws a PEM private key block: armor type (PGP armor ends with
// " BLOCK"), 0 to 3 armor header lines followed by an empty line (V2 F3), 1
// to 5 base64 lines, real or JSON-escaped line breaks, footer present or
// absent. The body is the first base64 line.
func pemBlock(t *rapid.T) (string, string) {
	typ := rapid.SampledFrom([]string{"RSA ", "EC ", "OPENSSH ", "ENCRYPTED ", "DSA ", "", "PGP "}).Draw(t, "type")
	suffix := ""
	if typ == "PGP " {
		suffix = " BLOCK"
	}
	sep := rapid.SampledFrom([]string{"\n", `\n`}).Draw(t, "sep")
	headers := rapid.SliceOfN(rapid.SampledFrom([]string{
		"Version: GnuPG v2", "Comment: https://example.org/key", "Proc-Type: 4,ENCRYPTED",
		"DEK-Info: AES-128-CBC,00FF", "Hash: SHA256",
	}), 0, 3).Draw(t, "headers")
	first := rapid.StringMatching(`[A-Za-z0-9+/]{64}`).Draw(t, "body")
	rest := rapid.SliceOfN(rapid.StringMatching(`[A-Za-z0-9+/]{1,64}={0,2}`), 0, 4).Draw(t, "rest")
	lines := make([]string, 0, len(headers)+len(rest)+2)
	lines = append(lines, headers...)
	if len(headers) > 0 {
		lines = append(lines, "")
	}
	lines = append(append(lines, first), rest...)
	text := fmt.Sprintf("-----BEGIN %sPRIVATE KEY%s-----%s%s", typ, suffix, sep, strings.Join(lines, sep))
	if rapid.Bool().Draw(t, "footer") {
		text = fmt.Sprintf("%s%s-----END %sPRIVATE KEY%s-----", text, sep, typ, suffix)
	}
	return text, first
}

// userinfoURL draws scheme://user:body@host/p with a scheme among schemes.
// The user name may be an e-mail address and the password may contain '@'
// (V2 F1): the password ends at the last '@' of the authority.
func userinfoURL(schemes []string) textGen {
	return func(t *rapid.T) (string, string) {
		s := rapid.SampledFrom(schemes).Draw(t, "scheme")
		u := rapid.StringMatching(`[a-z][a-z0-9]{0,11}(@[a-z][a-z0-9]{0,7}(\.example\.com)?)?`).Draw(t, "user")
		b := rapid.OneOf(
			rapid.StringMatching(`[A-Za-z0-9!$*+.~_-]{8,24}`),
			rapid.StringMatching(`[A-Za-z0-9!$*+.~_-]{4,12}@[A-Za-z0-9!$*+.~_@-]{4,12}`),
		).Draw(t, "body")
		h := rapid.StringMatching(`[a-z][a-z0-9]{0,11}\.example\.com(:[0-9]{2,5})?`).Draw(t, "host")
		return fmt.Sprintf("%s://%s:%s@%s/p", s, u, b, h), b
	}
}

// namedValueFormats are the syntaxes of a "name" field and a "value" field of
// one object: Kubernetes env lists (YAML, in both orders, raw or escaped in a
// JSON string), ECS environment (JSON, one line or pretty-printed, in both
// orders), YAML flow mappings and HCL blocks (V2 F4). The first argument is
// the name, the second the value.
var namedValueFormats = []string{
	"env:\n- name: %[1]s\n  value: %[2]s\n",
	"    env:\n      - value: \"%[2]s\"\n        name: %[1]s",
	"- name: '%[1]s'\n  value: '%[2]s'",
	`{"values":["env:\n- name: %[1]s\n  value: %[2]s\n"]}`,
	`[{"name":"%[1]s","value":"%[2]s"}]`,
	`{"value": "%[2]s", "name": "%[1]s"}`,
	"{\n  \"name\": \"%[1]s\",\n  \"value\": \"%[2]s\"\n}",
	"- {name: %[1]s, value: %[2]s}",
	"set_sensitive {\n  name  = \"%[1]s\"\n  value = \"%[2]s\"\n}",
}

// namedValue draws a sensitive name among names, a syntax of
// namedValueFormats and a value body from gen.
func namedValue(names []string, gen *rapid.Generator[string]) textGen {
	return func(t *rapid.T) (string, string) {
		n := rapid.SampledFrom(names).Draw(t, "name")
		f := rapid.SampledFrom(namedValueFormats).Draw(t, "format")
		b := gen.Draw(t, "body")
		return fmt.Sprintf(f, n, b), b
	}
}

// familyText returns the text generator of kind k (table of section 7.5), or
// nil for an unknown kind.
func familyText(k Kind) textGen {
	switch k {
	case KindAWSAccessKey:
		return bodyAlone(`(AKIA|ASIA)[A-Z0-9]{16}`)
	case KindAWSSecretKey:
		return underKey([]string{"aws_secret_access_key", "AWS_SECRET_ACCESS_KEY", "SecretAccessKey"}, `[A-Za-z0-9/+]{40}`)
	case KindAWSSessionToken:
		return anyOf(
			underKey([]string{"aws_session_token", "AWS_SESSION_TOKEN", "SessionToken"}, `[A-Za-z0-9/+=]{100,300}`),
			bodyAlone(`IQoJb3JpZ2lu[A-Za-z0-9/+=]{60,200}`),
		)
	case KindAzureSecret:
		return anyOf(
			inTemplate("DefaultEndpointsProtocol=https;AccountName=fakeaccount;AccountKey=%s;EndpointSuffix=core.windows.net", `[A-Za-z0-9+/]{86}==`),
			inTemplate("https://fakeaccount.blob.core.windows.net/c/b.txt?sv=2022-11-02&sig=%s", `[A-Za-z0-9%]{43}`),
			inTemplate(`{"sas":"https://fakeaccount.blob.core.windows.net/c/b.txt?sv=2022-11-02\u0026sig=%s"}`, `[A-Za-z0-9%]{43}`),
			bodyAlone(`[A-Za-z0-9]{3}[0-9]Q~[A-Za-z0-9_~.-]{34}`),
			underKey([]string{"client_secret"}, `[A-Za-z0-9_~.-]{34,40}`),
		)
	case KindScalewayKey:
		return anyOf(
			bodyAlone(`SCW[A-Z0-9]{17}`),
			underKey([]string{"SCW_SECRET_KEY"}, `[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}`),
		)
	case KindOVHCredential:
		return underKey([]string{"application_secret", "consumer_key", "OVH_APPLICATION_KEY"}, `[A-Za-z0-9]{16,32}`)
	case KindPrivateKey:
		return pemBlock
	case KindGitHubToken:
		return anyOf(bodyAlone(`gh[pousr]_[A-Za-z0-9]{36}`), bodyAlone(`github_pat_[A-Za-z0-9_]{82}`))
	case KindGitLabToken:
		return bodyAlone(`gl(pat|dt)-[A-Za-z0-9_-]{20,40}`)
	case KindSlackToken:
		return anyOf(
			bodyAlone(`xox[bpas]-[0-9]{10,13}-[A-Za-z0-9-]{10,40}`),
			bodyAlone(`https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}`),
		)
	case KindLLMAPIKey:
		return anyOf(
			bodyAlone(`sk-ant-api03-[A-Za-z0-9_-]{40,95}`),
			bodyAlone(`sk-(proj-)?[A-Za-z0-9_-]{40}`),
			inTemplate(`{"note":"\u003c%s\u003e"}`, `sk-(proj-)?[A-Za-z0-9_-]{40}`),
		)
	case KindURLCredentials:
		return userinfoURL([]string{"https", "ftp", "sftp", "git+https"})
	case KindDBConnString:
		return userinfoURL([]string{"postgres", "postgresql", "mysql", "mongodb+srv", "redis"})
	case KindKubeconfig:
		return underKey([]string{"token", "client-key-data", "id-token"}, `[A-Za-z0-9._-]{20,200}`)
	case KindSensitiveVar:
		keys := []string{
			"password", "db_password", "apiKey", "x-api-key", "auth_token", "SPRING_DATASOURCE_PASSWORD", "passphrase",
			"RABBITMQ_DEFAULT_PASS", "smtpPass", "db.pass", "auth", "admin_password",
		}
		names := []string{"DB_PASSWORD", "API_TOKEN", "RABBITMQ_DEFAULT_PASS", "client-secret", "spring.datasource.password", "Auth"}
		body := rapid.StringMatching(`[A-Za-z][A-Za-z0-9!#%*+./?^_~-]{7,39}`).
			Filter(func(s string) bool { return !hasReferencePrefix(s) })
		return anyOf(underKeyGen(keys, body), namedValue(names, body))
	case KindIPsecPSK:
		const psk = `[A-Za-z0-9!#%*+./?^_~-]{8,40}`
		return anyOf(
			underKey([]string{"tunnel1_preshared_key", "psk", "shared_key", "pre_shared_key"}, psk),
			inTemplate(`192.0.2.10 198.51.100.20 : PSK "%s"`, psk),
		)
	}
	return nil
}

// hasReferencePrefix reports whether s starts like an HCL reference, which
// the generic rule may legitimately exempt.
func hasReferencePrefix(s string) bool {
	for _, p := range []string{"var.", "local.", "data.", "module."} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// family draws pre + "\n" + text + "\n" + post, with random pre and post, and
// keeps only inputs where the body occurs exactly once.
func family(k Kind) *rapid.Generator[example] {
	text := familyText(k)
	if text == nil {
		return nil
	}
	return rapid.Custom(func(t *rapid.T) example {
		txt, body := text(t)
		pre := rapid.String().Draw(t, "pre")
		post := rapid.String().Draw(t, "post")
		return example{input: strings.Join([]string{pre, txt, post}, "\n"), body: body, kind: k}
	}).Filter(func(e example) bool { return strings.Count(e.input, e.body) == 1 })
}

// acceptedKind reports whether a mask of kind got may cover a body of family
// want. Only the families whose random body may contain, by chance, the shape
// of a higher priority kind accept another label (section 7.5, test 5).
func acceptedKind(want, got Kind) bool {
	switch want {
	case KindSensitiveVar:
		return true
	case KindURLCredentials:
		return got != KindSensitiveVar
	case KindDBConnString:
		return got != KindSensitiveVar && got != KindURLCredentials
	}
	return got == want
}

// Test 5 (task sheet): for every family, a random secret in a random context
// never survives redaction and is masked by a match of its kind.
func TestPropertyNoSecretSurvives(t *testing.T) {
	r := New()
	for _, k := range declaredKinds {
		gen := family(k)
		if gen == nil {
			t.Fatalf("no generator for kind %q", k)
		}
		t.Run(string(k), func(t *testing.T) {
			rapid.Check(t, func(t *rapid.T) {
				e := gen.Draw(t, "example")
				out, ms := r.Redact(e.input)
				if strings.Contains(out, e.body) {
					t.Fatalf("%s: body %q survives in %q", k, e.body, out)
				}
				if r.ContainsSecret(out) {
					t.Fatalf("%s: ContainsSecret(output) = true for %q", k, out)
				}
				if again, ms2 := r.Redact(out); again != out || ms2 != nil {
					t.Fatalf("%s: Redact(output) = %q, %+v, want the output and nil", k, again, ms2)
				}
				if err := checkSpans(e.input, ms); err != nil {
					t.Fatalf("%s: %v", k, err)
				}
				at := strings.Index(e.input, e.body)
				for _, m := range ms {
					if m.Start <= at && at+len(e.body) <= m.End && acceptedKind(k, m.Kind) {
						return
					}
				}
				t.Fatalf("%s: no match of an accepted kind masks the body [%d, %d) of %q: %+v", k, at, at+len(e.body), e.input, ms)
			})
		})
	}
}

// idempotenceError checks Redact(Redact(x)) == Redact(x) with zero matches on
// the second pass, and that the output contains no secret.
func idempotenceError(r *Redactor, x string) error {
	out1, _ := r.Redact(x)
	out2, m2 := r.Redact(out1)
	switch {
	case out2 != out1:
		return fmt.Errorf("Redact is not idempotent on %q:\n first: %q\nsecond: %q", x, out1, out2)
	case len(m2) != 0:
		return fmt.Errorf("second Redact of %q found %+v in %q, want no match", x, m2, out1)
	case r.ContainsSecret(out1):
		return fmt.Errorf("ContainsSecret(Redact(%q)) = true on %q", x, out1)
	}
	return nil
}

// Test 4 (task sheet): Redact is idempotent, on fixtures and on hostile soup.
func TestIdempotent(t *testing.T) {
	r := New()
	t.Run("fixtures", func(t *testing.T) {
		for _, x := range allFixtures() {
			if err := idempotenceError(r, x); err != nil {
				t.Error(err)
			}
		}
	})
	t.Run("soup", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			if err := idempotenceError(r, soup().Draw(t, "x")); err != nil {
				t.Fatal(err)
			}
		})
	})
}

// consistencyError checks ContainsSecret(s) == (len(matches of s) > 0) on the
// input and on its redaction.
func consistencyError(r *Redactor, x string) error {
	out, _ := r.Redact(x)
	for _, s := range []string{x, out} {
		_, ms := r.Redact(s)
		if got, want := r.ContainsSecret(s), len(ms) > 0; got != want {
			return fmt.Errorf("ContainsSecret(%q) = %v, but Redact returns %d matches", s, got, len(ms))
		}
	}
	return nil
}

// Test 13: ContainsSecret is exactly "Redact would redact something".
func TestContainsSecretConsistent(t *testing.T) {
	r := New()
	t.Run("fixtures", func(t *testing.T) {
		for _, x := range allFixtures() {
			if err := consistencyError(r, x); err != nil {
				t.Error(err)
			}
		}
	})
	t.Run("soup", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			if err := consistencyError(r, soup().Draw(t, "x")); err != nil {
				t.Fatal(err)
			}
		})
	})
}

// jsonCleanError checks that one level of JSON encoding of a redacted text,
// with and without HTML escaping, contains no secret (contract with T12).
func jsonCleanError(r *Redactor, x string) error {
	out, _ := r.Redact(x)
	raw, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("json.Marshal(%q): %w", out, err)
	}
	if r.ContainsSecret(string(raw)) {
		_, ms := r.Redact(string(raw))
		return fmt.Errorf("JSON of redacted %q contains a secret: %s matches %+v", x, raw, ms)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("json.Encoder.Encode(%q): %w", out, err)
	}
	if r.ContainsSecret(buf.String()) {
		_, ms := r.Redact(buf.String())
		return fmt.Errorf("JSON without HTML escaping of redacted %q contains a secret: %s matches %+v", x, buf.String(), ms)
	}
	return nil
}

// Test 17: a redacted text stays clean once serialized in a JSON body.
func TestRedactedOutputStaysCleanWhenJSONEncoded(t *testing.T) {
	r := New()
	t.Run("fixtures", func(t *testing.T) {
		for _, x := range allFixtures() {
			if err := jsonCleanError(r, x); err != nil {
				t.Error(err)
			}
		}
	})
	t.Run("soup", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			if err := jsonCleanError(r, soup().Draw(t, "x")); err != nil {
				t.Fatal(err)
			}
		})
	})
}
