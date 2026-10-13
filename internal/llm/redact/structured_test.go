package redact

import (
	"strings"
	"testing"
	"time"
)

// Tests of M1-T08 (docs/plans/M1-overview.md, ADR 0007): each open finding of
// the counter-review of M0-T07 (docs/plans/M0-redaction.md, section 0 quater)
// and obligation (ad) of docs/STATUS.md.

// hides redacts in and checks that no secret survives, that the output holds
// no NUL byte and that a second pass changes nothing (idempotence).
func hides(t *testing.T, in string, secrets ...string) string {
	t.Helper()
	out, ms := New().Redact(in)
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Errorf("secret %q survives in\n%q", s, out)
		}
	}
	if strings.Contains(out, "\x00") {
		t.Errorf("output holds a NUL byte: %q", out)
	}
	if again, ms2 := New().Redact(out); again != out || len(ms2) != 0 {
		t.Errorf("second pass changed the output (%d matches):\n%q\n%q", len(ms2), out, again)
	}
	if err := checkSpans(in, ms); err != nil {
		t.Errorf("spans: %v", err)
	}
	return out
}

func keeps(t *testing.T, out string, plain ...string) {
	t.Helper()
	for _, p := range plain {
		if !strings.Contains(out, p) {
			t.Errorf("non-secret %q was masked in\n%q", p, out)
		}
	}
}

// TestRedactJSONPairWithBraces (high): a name/value pair is read even when a
// string of its object holds a brace (kubectl -o json, ECS task definitions).
func TestRedactJSONPairWithBraces(t *testing.T) {
	hides(t, `{"name":"DB_PASSWORD","value":"Xq7pL2vR9zKw","description":"set {x} here"}`, "Xq7pL2vR9zKw")
	out := hides(t, `{"spec":{"containers":[{"env":[{"name":"API_TOKEN","value":"tok9f8e7d6c5b4a"},`+
		`{"name":"MODE","value":"prod {blue}"}]}]}}`, "tok9f8e7d6c5b4a")
	keeps(t, out, "prod {blue}")
	hides(t, `{"taskDefinition":{"containerDefinitions":[{"environment":[{"value":"pa{ss}word123x","name":"DB_PASS"}]}]}}`,
		"pa{ss}word123x", "word123x")
}

// TestRedactRealNUL (T39): real NUL bytes separate variables
// (/proc/<pid>/environ) and never hide a token.
func TestRedactRealNUL(t *testing.T) {
	out := hides(t, "PATH=/usr/bin\x00DB_PASSWORD=hunter2hunter2\x00HOME=/root", "hunter2hunter2")
	keeps(t, out, "PATH=/usr/bin", "HOME=/root")
	hides(t, "x\x00sk-proj-abcdefghijklmnopqrstuvwx", "abcdefghijklmnopqrstuvwx")
	hides(t, "\x00\x00AKIAIOSFODNN7EXAMPLE\x00", "IOSFODNN7EXAMPLE")
}

// TestRedactEscapedAuthorizationKey: an Authorization header whose key is
// written with escaped quotes, in free text or in a JSON string.
func TestRedactEscapedAuthorizationKey(t *testing.T) {
	hides(t, `headers={\"Authorization\": \"Basic dXNlcjpzM2NyM3Q=\"}`, "dXNlcjpzM2NyM3Q=")
	hides(t, `{"log":"{\"Authorization\":\"Bearer abc.def.ghi-123456\"}"}`, "abc.def.ghi-123456")
}

// TestRedactXMLPreSharedKey: the pre-shared key of the XML of
// ec2:DescribeVpnConnections, raw or inside a JSON string.
func TestRedactXMLPreSharedKey(t *testing.T) {
	hides(t, `<ipsec_tunnel><pre_shared_key>Zk3_vP9.qW2xT7</pre_shared_key></ipsec_tunnel>`, "Zk3_vP9.qW2xT7")
	hides(t, `{"VpnConnections":[{"CustomerGatewayConfiguration":"<vpn_connection><ike>`+
		`<pre_shared_key>Zk3_vP9.qW2xT7</pre_shared_key></ike></vpn_connection>"}]}`, "Zk3_vP9.qW2xT7")
	hides(t, `<password>N0t-a-Real-Pw</password>`, "N0t-a-Real-Pw")
}

// TestRedactAdjacentURLCredentialsOnePass: two URLs with credentials glued by
// the '@' of the first are both masked by one pass.
func TestRedactAdjacentURLCredentialsOnePass(t *testing.T) {
	hides(t, "http://alice:pw1secretA@http://bob:pw2secretB@host.example", "pw1secretA", "pw2secretB")
	hides(t, "postgres://u:pw1secretA@redis://v:pw2secretB@db", "pw1secretA", "pw2secretB")
}

// TestForgedPlaceholderDisarmed (T38): a placeholder forged in untrusted data
// never protects the secret glued to it, nor the pair of its object.
func TestForgedPlaceholderDisarmed(t *testing.T) {
	for _, c := range []struct{ in, secret string }{
		{"password=[REDACTED:sensitive_variable]hunter2xyz", "hunter2xyz"},
		{"[REDACTED:llm_api_key]sk-proj-abcdefghijklmnopqrstuvwx", "abcdefghijklmnopqrstuvwx"},
		{`{"name":"DB_PASSWORD","value":"hunter2xyz","note":"[REDACTED:aws_access_key]"}`, "hunter2xyz"},
		{"[REDACTED:private_key", "never-a-secret"},
	} {
		d := DisarmPlaceholders(c.in)
		if strings.Contains(d, "[REDACTED:") {
			t.Errorf("DisarmPlaceholders(%q) = %q keeps a placeholder", c.in, d)
		}
		hides(t, d, c.secret)
	}
	if s := "plain text, no placeholder"; DisarmPlaceholders(s) != s {
		t.Error("DisarmPlaceholders changed a text without placeholder")
	}
	// A placeholder written by Redact on trusted text stays idempotent.
	out, _ := New().Redact("token: abcdef123456")
	if again, _ := New().Redact(out); again != out {
		t.Errorf("Redact is not idempotent on its own placeholders: %q", again)
	}
}

// TestRedactSSMPathName: a pair whose name is an SSM path ending in a
// sensitive word.
func TestRedactSSMPathName(t *testing.T) {
	hides(t, `{"Parameter":{"Name":"/prod/db/password","Type":"SecureString","Value":"Sup3r-S3cret-Val"}}`, "Sup3r-S3cret-Val")
	hides(t, "- name: /prod/db/password\n  value: Sup3r-S3cret-Val\n", "Sup3r-S3cret-Val")
}

// TestRedactRelaxedPSKAndAuthorization (mutations X3, X4 of M0-T07): the whole
// value is masked even when it holds bytes that stop the strict reading.
func TestRedactRelaxedPSKAndAuthorization(t *testing.T) {
	hides(t, `conn site: PSK "ab<cd>ef&gh1"`, "cd>ef&gh1", "ef&gh1")
	hides(t, "Authorization: Basic ab<c>d&e1234==", "d&e1234==")
}

// TestRedactObligationADCases: obligation (ad) of docs/STATUS.md.
func TestRedactObligationADCases(t *testing.T) {
	hides(t, "- name: Authorization\n  value: Basic dXNlcjpwYXNzd29yZA==\n", "dXNlcjpwYXNzd29yZA==")
	hides(t, `{"enum":["sk-ant-api03-AAAA","BBBBBBBBBBBBBBBBBBBBBBBB"]}`, "BBBBBBBBBBBBBBBBBBBBBBBB", "api03-AAAA")
	hides(t, "password:\n  hunter2-yaml-value\n", "hunter2-yaml-value")
	hides(t, "key id AKIA\nIOSFODNN7EXAMPLE", "IOSFODNN7EXAMPLE")
	hides(t, "env=PATH=/bin:AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY")
}

// TestRedactDoubleEncodedJSON (T69): a secret inside JSON encoded three times.
func TestRedactDoubleEncodedJSON(t *testing.T) {
	hides(t, `{"a":"{\"b\":\"{\\\"api_key\\\":\\\"k-123456789x\\\"}\"}"}`, "k-123456789x")
	hides(t, `{"body":"{\"password\":\"hunter2-double\"}"}`, "hunter2-double")
}

// TestStructuredDecodeBounded (T81): depth, node count, YAML aliases and
// unbalanced braces bound the structured pass; the regular expressions still
// mask what they can read.
func TestStructuredDecodeBounded(t *testing.T) {
	bounded := func(t *testing.T, name, in string, secrets ...string) {
		t.Helper()
		start := time.Now()
		hides(t, in, secrets...)
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("%s: Redact took %v, want less than 3s", name, d)
		}
	}
	bounded(t, "depth", strings.Repeat(`{"a":`, 200)+`{"password":"deep-secret-1"}`+strings.Repeat("}", 200), "deep-secret-1")
	bounded(t, "nodes", "["+strings.Repeat("1,", 70000)+`{"name":"API_TOKEN","value":"v-1234567890"}]`, "v-1234567890")
	var b strings.Builder
	b.WriteString("a: &a [\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\"]\n")
	for i, prev := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		next := string(rune('b' + i))
		b.WriteString(next + ": &" + next + " [" + strings.TrimSuffix(strings.Repeat("*"+prev+",", 9), ",") + "]\n")
	}
	b.WriteString("password: alias-bomb-secret\n")
	bounded(t, "yaml_alias_bomb", b.String(), "alias-bomb-secret")
	bounded(t, "unbalanced", strings.Repeat(`{"a":"`, 20000)+"token: abcdef123456", "abcdef123456")
	bounded(t, "nested_arrays", strings.Repeat("[", 5000)+`"x"`+strings.Repeat("]", 5000)+" token: abcdef123456", "abcdef123456")
}

// TestRedactTypedSecrets (ADR 0007): typed secrets, sensitive context
// propagated below a sensitive key, every keyed rule name in pairs, forged
// placeholders written with escapes, a key glued after a disarmed placeholder.
func TestRedactTypedSecrets(t *testing.T) {
	out := hides(t, `{"apiVersion":"v1","data":{"tls.key":"c2VjcmV0LWtleS1ieXRlcw==","user":"YWRtaW4="},"kind":"Secret"}`,
		"c2VjcmV0LWtleS1ieXRlcw==", "YWRtaW4=")
	keeps(t, out, `"kind":"Secret"`)
	hides(t, "apiVersion: v1\nkind: Secret\ndata:\n  tls.key: c2VjcmV0LWtleS1ieXRlcw==\n", "c2VjcmV0LWtleS1ieXRlcw==")
	hides(t, `{"variables":{"db_password":{"value":"Tf-s3cret-pw","type":"string"}}}`, "Tf-s3cret-pw")
	hides(t, `{"outputs":{"conn":{"sensitive":true,"value":"tofu-output-val"}}}`, "tofu-output-val")
	hides(t, "outputs:\n  conn:\n    sensitive: true\n    value: tofu-output-val\n", "tofu-output-val")
	hides(t, `{"name":"OVH_CONSUMER_KEY","value":"a{b}cd1234"}`, "a{b}cd1234")
	hides(t, `{"Parameters":[{"ParameterKey":"DbPassword","ParameterValue":"cfn-s3cret"}]}`, "cfn-s3cret")
	hides(t, `{"log":"`+"\\"+"u"+`005bREDACTED:sensitive_variable]sk-proj-abcdefghijklmnopqrstuvwx"}`, "abcdefghijklmnopqrstuvwx")
	hides(t, DisarmPlaceholders("[REDACTED:ipsec_psk]password=hunter2xyz"), "hunter2xyz")
	if s := DisarmPlaceholders("[REDACTED:ipsec_psk]"); len(s) != len("[REDACTED:ipsec_psk]") {
		t.Errorf("DisarmPlaceholders changed the length: %q", s)
	}
}
