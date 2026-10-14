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

// nested returns a JSON string encoded d times around {"a":"b {x}"}.
func nested(d int) string {
	v := `{"a":"b {x}"}`
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	for range d {
		v = `{"k":"` + esc.Replace(v) + `"}`
	}
	return v
}

// TestRedactReviewFindings: findings of the security review of M1-T08.
func TestRedactReviewFindings(t *testing.T) {
	t.Run("pair_with_escaped_siblings", func(t *testing.T) {
		tag := `{"Key":"t","Value":"{\"a\":\"{\\\"b\\\":1}\"} x"}`
		hides(t, `{"Tags":[`+tag+`,`+tag+`],"name":"DB_PASSWORD","value":"hunter2xyz","description":"set {x} here"}`, "hunter2xyz")
	})
	t.Run("deep_nesting_bounded", func(t *testing.T) {
		in := strings.Repeat(nested(7)+",", (1<<20)/(len(nested(7))+1))
		start := time.Now()
		New().Redact(in)
		if d := time.Since(start); d > 8*time.Second {
			t.Errorf("1 MiB of deeply nested encodings redacted in %v, want less than 8s", d)
		}
	})
	t.Run("yaml_in_prose", func(t *testing.T) {
		hides(t, "Deploy log: step 1: ok\npassword:\n  hunter2-yaml-value\n", "hunter2-yaml-value")
	})
	t.Run("yaml_after_64_documents", func(t *testing.T) {
		hides(t, strings.Repeat("a: 1\n---\n", 70)+"password: hunter2-doc-71\n", "hunter2-doc-71")
	})
	t.Run("yaml_multiline_plain", func(t *testing.T) {
		hides(t, "password: hunter2-first\n  hunter2-second\nuser: x\n", "hunter2-first", "hunter2-second")
	})
	t.Run("yaml_tagged_quoted", func(t *testing.T) {
		hides(t, "password: !!str \"hunter2-tagged\"\n", "hunter2-tagged")
		hides(t, "- name: DB_PASSWORD\n  value: !!str 'hunter2-tagged2'\n", "hunter2-tagged2")
	})
	t.Run("yaml_alias", func(t *testing.T) {
		hides(t, "defaults: &pw hunter2-anchor\npassword: *pw\n", "hunter2-anchor")
	})
	t.Run("cloud_keys", func(t *testing.T) {
		hides(t, `{"Parameter":{"Name":"/prod/app/config","Type":"SecureString","Value":"ssm-secure-v1"}}`, "ssm-secure-v1")
		hides(t, `{"keys":[{"keyName":"key1","value":"azkey-0123456789","permissions":"FULL"}]}`, "azkey-0123456789")
		hides(t, `{"primaryMasterKey":"cosmos-master-k1","accountKey":"az-acct-k2"}`, "cosmos-master-k1", "az-acct-k2")
		hides(t, `{"credentials":"creds-blob-123","jwt":"eyJhbGciOi.x.y"}`, "creds-blob-123", "eyJhbGciOi.x.y")
		hides(t, `{"Name":"/prod/db/password/v2","Value":"ssm-path-v2"}`, "ssm-path-v2")
		hides(t, `{"OptionSettings":[{"OptionName":"DB_PASSWORD","Value":"eb-option-pw"}]}`, "eb-option-pw")
	})
	t.Run("escaped_nul_boundary", func(t *testing.T) {
		hides(t, `{"env":"x`+"\\"+"u"+`0000sk-proj-abcdefghijklmnopqrstuvwx"}`, "abcdefghijklmnopqrstuvwx")
	})
	t.Run("forged_escaped_placeholder", func(t *testing.T) {
		hides(t, `{"msg":"token=`+"\\"+"u"+`005bREDACTED:sensitive_variable]hunter2xyz"}`, "hunter2xyz")
	})
}

// TestRedactSecondReview: probes of the second security review of M1-T08
// (fail closed by default: any doubt masks the whole leaf or text).
func TestRedactSecondReview(t *testing.T) {
	const tok = "sk-proj-abcdefghijklmnopqrstuvwx"
	const tail = "abcdefghijklmnopqrstuvwx"
	sec := "c2VjcmV0LWtleS1ieXRlcw=="
	ls, nel, bom := string(rune(0x2028)), string(rune(0x85)), string(rune(0xFEFF))
	for name, c := range map[string]struct {
		in      string
		secrets []string
	}{
		// JSON escapes the regular expressions do not read.
		"json_f_token":     {`{"m":"x` + "\\" + `f` + tok + `"}`, []string{tail}},
		"json_b_token":     {`{"m":"x` + "\\" + `b` + tok + `"}`, []string{tail}},
		"json_f_key":       {`{"m":"x` + "\\" + `fpassword=hunter2xyz"}`, []string{"hunter2xyz"}},
		"json_b_aws":       {`{"m":"x` + "\\" + `bAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"}`, []string{"wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"}},
		"json_b_in_value":  {`{"m":"password=hunt` + "\\" + `ber2xyz"}`, []string{"er2xyz"}},
		"json_f_postgres":  {`{"m":"x` + "\\" + `fpostgres://u:pw-s3cret@db"}`, []string{"pw-s3cret"}},
		"json_yaml_inside": {`{"log":"password:` + "\\" + `n  hunter2-yaml-value"}`, []string{"hunter2-yaml-value"}},
		"json_key_u":       {`{"` + "\\" + `u0073k-proj-abcdefghijklmnopqrstuvwx":1}`, []string{tail}},
		"json_open_frame":  {`{"name":"DB_PASSWORD","value":"hunter2xyz","note":"set {x}`, []string{"hunter2xyz"}},
		// YAML escapes and folding.
		"yaml_x73":        {"m: \"x \\x73k-proj-abcdefghijklmnopqrstuvwx\"\n", []string{tail}},
		"yaml_x41":        {"m: \"\\x41KIAIOSFODNN7EXAMPLE\"\n", []string{"IOSFODNN7EXAMPLE"}},
		"yaml_U":          {"m: \"\\U00000073k-proj-abcdefghijklmnopqrstuvwx\"\n", []string{tail}},
		"yaml_esc_nl":     {"m: \"sk-proj-abcdefghij\\\n  klmnopqrstuvwx\"\n", []string{"klmnopqrstuvwx"}},
		"yaml_x_key":      {"m: \"pass\\x77ord=hunter2xyz\"\n", []string{"hunter2xyz"}},
		"yaml_e_key":      {"m: \"x\\epassword=hunter2xyz\"\n", []string{"hunter2xyz"}},
		"yaml_N":          {"m: \"x\\N" + tok + "\"\n", []string{tail}},
		"yaml_quote_dup":  {"m: 'password=''hunter2xyz'''\n", []string{"hunter2xyz"}},
		"yaml_dq_folded":  {"m: \"password=\n  hunter2xyz\"\n", []string{"hunter2xyz"}},
		"yaml_key_x":      {"\"\\x73k-proj-abcdefghijklmnopqrstuvwx\": 1\n", []string{tail}},
		"yaml_multi_key":  {"password:\n  hunter2-first\n  hunter2-second\n", []string{"hunter2-first", "hunter2-second"}},
		"yaml_tag_nl":     {"password: !!str\n  \"hunter2-tq\"\n", []string{"hunter2-tq"}},
		"yaml_flow_pair":  {"env: [{name: DB_PASSWORD, value: !!str hunter2-flow}]\n", []string{"hunter2-flow"}},
		"yaml_anchor_tag": {"password: &a !!str 'hunter2-t2'\nother: *a\n", []string{"hunter2-t2"}},
		// Line breaks of the YAML decoder and the BOM (position drift).
		"yaml_cr":         {"kind: Secret\rdata:\r  tls.key: " + sec + "\r", []string{sec}},
		"yaml_cr_shift":   {"kind: Secret\nnote: \"a\rb\"\ndata:\n  tls.key: " + sec + "\n", []string{sec}},
		"yaml_ls_shift":   {"kind: Secret\nnote: \"a" + ls + "b\"\ndata:\n  tls.key: " + sec + "\n", []string{sec}},
		"yaml_nel_shift":  {"kind: Secret\nnote: \"a" + nel + "b\"\ndata:\n  tls.key: " + sec + "\n", []string{sec}},
		"yaml_pair_shift": {"note: \"a" + ls + "b\"\nenv:\n- name: DB_PASSWORD\n  value: !!str hunter2-shift\n", []string{"hunter2-shift"}},
		"yaml_bom":        {bom + "password: \"hunter2 bom\"\n", []string{"hunter2", "bom"}},
	} {
		t.Run(name, func(t *testing.T) { hides(t, c.in, c.secrets...) })
	}
	t.Run("yaml_budget_padding", func(t *testing.T) {
		inner := `"{\"k\":\"` + strings.Repeat(`\\u0041`, 200) + `\"}"`
		items := strings.TrimSuffix(strings.Repeat(inner+",", 150), ",")
		in := "kind: Secret\ndata:\n  tls.key: " + sec + "\nx: [" + items + "]\npad: " + strings.Repeat("a", 258<<10) + "\n"
		hides(t, in, sec)
	})
	t.Run("tiny_leaves_bounded", func(t *testing.T) {
		in := "[" + strings.Repeat(`"\u0041",`, (1<<20)/10) + `"x"]`
		start := time.Now()
		New().Redact(in)
		if d := time.Since(start); d > 8*time.Second {
			t.Errorf("1 MiB of tiny escaped leaves redacted in %v, want less than 8s", d)
		}
	})
}

// TestRedactThirdReview: probes of the third security review of M1-T08. An
// escaped leaf is decoded whatever its escapes (PHP "\/", Go "<"); a
// YAML document without mapping or sequence root never stops the stream; the
// mask of the whole text survives a leading placeholder.
func TestRedactThirdReview(t *testing.T) {
	bs := "\\"
	sec := "c2VjcmV0LWtleS1ieXRlcw=="
	secret := "kind: Secret\ndata:\n  tls.key: " + sec + "\n"
	for name, c := range map[string]struct {
		in      string
		secrets []string
	}{
		"json_slash_pg":     {`{"log":"postgres:` + bs + `/` + bs + `/u:pw-s3cret@db"}`, []string{"pw-s3cret"}},
		"json_slash_https":  {`{"log":"https:` + bs + `/` + bs + `/admin:Adm1nPw0rd@host"}`, []string{"Adm1nPw0rd"}},
		"json_slash_aws":    {`{"log":"aws_secret_access_key=wJalrXUtnFEMI` + bs + `/K7MDENG` + bs + `/bPxRfiCYEXAMPLEKEY"}`, []string{"K7MDENG", "bPxRfiCYEXAMPLEKEY"}},
		"json_tab_eq":       {`{"m":"password` + bs + `t=hunter2xyz"}`, []string{"hunter2xyz"}},
		"json_tab_colon":    {`{"m":"token:` + bs + `thunter2xyz"}`, []string{"hunter2xyz"}},
		"json_quote_val":    {`{"m":"password=` + bs + `"hunter2xyz"}`, []string{"hunter2xyz"}},
		"json_u003c_xml":    {`{"m":"x` + bs + `u003cpassword` + bs + `u003ehunter2xyz` + bs + `u003c/password` + bs + `u003e"}`, []string{"hunter2xyz"}},
		"yaml_dq_slash":     {"m: \"postgres:\\/\\/u:pw-s3cret@db\"\n", []string{"pw-s3cret"}},
		"yaml_dq_tab":       {"m: \"password\\t=hunter2xyz\"\n", []string{"hunter2xyz"}},
		"doc_scalar_first":  {"Applying manifests now\n---\n" + secret, []string{sec}},
		"doc_empty_first":   {"---\n---\n" + secret, []string{sec}},
		"doc_null_first":    {"~\n---\n" + secret, []string{sec}},
		"doc_quoted_first":  {"\"note\"\n---\n" + secret, []string{sec}},
		"doc_prose_typed":   {"Some log: a: b\n" + secret, []string{sec}},
		"helm_empty_doc":    {"---\n# Source: app/templates/empty.yaml\n---\n# Source: app/templates/secret.yaml\napiVersion: v1\nkind: Secret\nmetadata:\n  name: db\ntype: Opaque\ndata:\n  config.json: " + sec + "\n", []string{sec}},
		"pair_after_scalar": {"ok\n---\nenv:\n- name: DB_PASSWORD\n  value: !!str hunter2-shift\n", []string{"hunter2-shift"}},
	} {
		t.Run(name, func(t *testing.T) { hides(t, c.in, c.secrets...) })
	}
	t.Run("placeholder_prefix_bound", func(t *testing.T) {
		leaf := `"{` + bs + `"k` + bs + `":` + bs + `"` + strings.Repeat(bs+bs+"u0041", 200) + bs + `"}"`
		bomb := "[" + strings.TrimSuffix(strings.Repeat(leaf+",", 400), ",") + "]"
		doc := `{"kind":"Secret","data":{"tls.key":"` + sec + `"}} `
		hides(t, "[REDACTED:aws_access_key] "+doc+bomb, sec)
		hides(t, "[REDACTED:aws_access_key] "+doc, sec)
	})
}
