package redact

import (
	"regexp"
	"strings"
)

// rule finds candidates of one Kind. A shape rule matches the secret itself;
// its group "v", when present, narrows the span. A keyed rule matches a
// sensitive key and its separator; the value that follows is read by valueRe.
// The pairs rule reads the value of a "value" field whose sibling "name" field
// holds a sensitive name.
//
// Rules read the text of find, where every existing placeholder is a run of
// NUL bytes: no class of a rule accepts NUL, so that no token, key or value
// starts in, or runs through, a placeholder.
type rule struct {
	kind  Kind
	re    *regexp.Regexp
	keyed bool
	pairs bool
	// blocked: every candidate is exempt. The rule reads the whole value of a
	// shape whose strict rule stops earlier (at a byte that JSON escapes): it
	// is masked only where it overlaps another candidate, and so extends the
	// strict mask to the whole value.
	blocked bool
	// exempt: nil, never exempt. Keyed and pairs rules pass the key and the
	// value; shape rules pass an empty key and the span.
	exempt func(key, value string) bool
}

type candidate struct {
	start, end, prio int
	exempt           bool
}

const (
	// jsonEscape: '&', '<' or '>' as written by json.Marshal (\x5c is '\').
	jsonEscape = `\x5cu00(?:26|3[cCeE])`
	// jsonUnsafe: the characters, besides '"' and '\', that json.Marshal
	// escapes (an invalid UTF-8 byte is read as U+FFFD), for a class. It
	// contains NUL.
	jsonUnsafe = `<>&\x00-\x1f\x{2028}\x{2029}\x{FFFD}`
	// boundary: start of text, a byte that is neither a word byte, nor ']',
	// nor '\', nor NUL (so that masking a neighbour never creates a new
	// match), an escaped newline or tab, or a JSON escape of '&', '<' or '>'.
	// A lone '\' is not a boundary: in a JSON-encoded text, the letter of an
	// escape would otherwise start a new token.
	boundary = `(?:^|[^A-Za-z0-9_\]\\\x00]|\\[nrt]|` + jsonEscape + `)`
	// keyPrefix: start of text, a delimiter, an escaped newline or tab, or a
	// JSON escape of '&', '<' or '>'. ':' and ']' are deliberately absent.
	keyPrefix = "(?:^|[\\s\"'`{}(\\[,;?&|<>$]|\\\\[nrt]|" + jsonEscape + ")"
	// Separators never consume the blanks that follow them: a blank may be the
	// prefix of the next key. A bare ':' (group c) needs a blank after it.
	sepAny  = `[ \t]*(?::=|=>|[:=])`
	sepBare = `[ \t]*(?::=|=>|=|(?P<c>:))`
	// userinfo: the user name may contain '@'; the password runs to the last
	// '@' before the end of the authority.
	userinfo = "[^\\s:/?#\"'`<>\\\\\\[\\]\\x00]*:(?P<v>[^\\s/?#\"'`<>\\\\\\[\\]\\x00]+)@"
	// names: a key that contains a sensitive word, a key with the whole
	// segment "pass" (bounded by '_', '.', '-', a case change or the ends of
	// the key), or the exact key "auth".
	names = `[A-Za-z0-9_.-]*(?:password|passwd|passphrase|pwd|secret|token|api[_.-]?key|apikey|access[_.-]?key|private[_.-]?key)[A-Za-z0-9_.-]*` +
		`|(?:[A-Za-z0-9_.-]*[_.-])?pass(?:[_.-][A-Za-z0-9_.-]*)?` +
		`|(?:[A-Za-z0-9_.-]*[_.-])?(?-i:[Pp]ass[A-Z])[A-Za-z0-9_.-]*` +
		`|[A-Za-z0-9_.-]*(?-i:[a-z0-9]Pass)(?:(?-i:[A-Z_.-])[A-Za-z0-9_.-]*)?` +
		`|auth`
	maxExempt = 256
)

// Shapes. Each literal prefix is followed by a class or a group, never by a
// secret body.
const (
	// rePEM: armor header lines ("Name: text") are accepted in the body.
	rePEM = `-----BEGIN[A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----` +
		`(?:[A-Za-z-]+:[^\r\n\\\x00]*|[A-Za-z0-9+/=\s\\])*` +
		`(?:-----END[A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----)?`
	reAWSKey     = `(?:AKIA|ASIA)[A-Z0-9]{16}`
	reAWSSession = `(?:FwoGZXIvYXdz|IQoJb3JpZ2lu)[A-Za-z0-9/+=]{50,}`
	reAzure      = `(?i:AccountKey|SharedAccessKey)=(?P<v>[A-Za-z0-9+/=]{20,})` +
		`|(?:[?&<>]|` + jsonEscape + `)(?i:sig)=(?P<v>[A-Za-z0-9%/+=]{16,})` +
		`|[A-Za-z0-9_~.]{3}[0-9]Q~[A-Za-z0-9_~.-]{31,34}`
	reScw = `SCW[A-Z0-9]{17}`
	// rePSKLine: strongSwan PSK line. The value stops at a quote, a
	// backslash, a blank or a byte that JSON escapes, so that its match
	// consumes the same text once JSON-encoded; rePSKRelaxed reads the whole
	// value (see rule.blocked).
	rePSKLine = boundary + `(?i:PSK)[ \t]+(?:"(?P<v>[^"\\` + jsonUnsafe + `]+)|'(?P<v>[^'"\\` + jsonUnsafe + `]+)` +
		`|\\"(?P<v>[^"\\` + jsonUnsafe + `]+)|(?P<v>[^\s"'\\` + jsonUnsafe + `]+))`
	rePSKRelaxed = boundary + `(?i:PSK)[ \t]+(?:"(?P<v>[^"\r\n\x00]+)|'(?P<v>[^'\r\n\x00]+)` +
		`|\\"(?P<v>(?:[^\\\r\n\x00]|\\[^"\r\n\x00])+)|(?P<v>[^\s"'\\\x00]+))`
	reGitHub = `gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255}`
	reGitLab = `gl(?:pat|dt|ptt|rt|cbt|oas)-[A-Za-z0-9_-]{20,}`
	reSlack  = `xox[abeoprs]-[A-Za-z0-9-]{10,}|https://hooks\.slack\.com/(?:services|workflows)/[A-Za-z0-9/_-]+`
	reLLM    = `sk-ant-[A-Za-z0-9_-]{20,}|` + boundary + `(?P<v>sk-[A-Za-z0-9_-]{20,})`
	reB64PEM = `LS0tLS1CRUdJTi[A-Za-z0-9+/=]*`
	reDB     = boundary + `(?i:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|sqlserver|mssql|clickhouse|cockroachdb|jdbc:[a-z0-9]+)://` + userinfo
	reURL    = boundary + `[A-Za-z][A-Za-z0-9+.-]*://` + userinfo
	// reAuthz: a one-line array of header values, masked whole from its '['
	// to its ']' or to the end of the line, or a header value, which stops
	// like that of rePSKLine; reAuthzRelaxed reads the whole value.
	authzHead   = boundary + `(?i:(?:proxy-)?authorization)["']?(?:[ \t]|\\t)*[:=](?:[ \t]|\\t)*`
	authzScheme = `(?i:(?:bearer|basic|token|digest|negotiate|ntlm|aws4-hmac-sha256)(?:[ \t]|\\+t)+)?`
	authzArray  = `(?P<v>\[[^\r\n\]\x00]*\]?)`
	reAuthz     = authzHead + `(?:` + authzArray +
		`|["']?` + authzScheme + `(?P<v>[^"'\\` + jsonUnsafe + `]*[^\s"'\\` + jsonUnsafe + `]))`
	reAuthzRelaxed = authzHead + `(?:` + authzArray +
		`|["']?` + authzScheme + `(?P<v>[^\r\n"'\\\x00]*[^\s"'\\\x00]))`
	reAuthScheme = boundary + `(?i:bearer)[ \t]+(?P<v>[A-Za-z0-9._~+/=-]{16,})`
)

// blockLine and blockLineJSON: the content of a line of a YAML block scalar,
// raw or JSON-escaped, after its indentation. It starts neither with a blank
// nor with a line break, raw or escaped: the indentation is never read back
// as content, in the text as in its JSON encoding.
const (
	blockLine     = `[^ \t\r\n\x00][^\r\n\x00]*`
	blockLineJSON = `(?:[^\\" \t\r\n\x00]|\\[^nrt"\r\n\x00])(?:[^\\"\r\n\x00]|\\[^n"\r\n\x00])*`
)

// arrayItem: a byte of a one-line array, other than a bracket, a line break
// (real or escaped) and NUL.
const arrayItem = `(?:[^\[\]\r\n\\\x00]|\\[^nr\r\n\x00])`

// valueRe reads a value at the start of its input, in group v (group u for a
// quote never closed): double quotes (JSON escapes), single quotes, escaped
// double quotes, YAML block scalar (raw or JSON-escaped), shell reference
// with braces, one-line array (one level of nesting), a double quote never
// closed (the value runs to the end of the line, of the text or to a
// placeholder), a single quote never closed (to the end of the line or of the
// text, without '"' or '\', which JSON would escape), or a bare word.
var valueRe = regexp.MustCompile(`^(?:` +
	`"(?P<v>(?:[^"\\\r\n\x00]|\\[^\n\x00])+)"` +
	`|'(?P<v>[^'\\\r\n\x00]+)'` +
	`|\\"(?P<v>[^"\\\r\n\x00]+)\\"` +
	`|[|>][+-]?[0-9]?[ \t]*\r?\n[ \t]+(?P<v>` + blockLine + `(?:\r?\n[ \t]+` + blockLine + `)*)` +
	`|[|>][+-]?[0-9]?[ \t]*\\n[ \t]+(?P<v>` + blockLineJSON + `(?:\\n[ \t]+` + blockLineJSON + `)*)` +
	`|(?P<v>\$\{[A-Za-z_][A-Za-z0-9_.]*\})` +
	`|(?P<v>\[(?:` + arrayItem + `|\[` + arrayItem + `*\])*\])` +
	`|"(?P<u>(?:[^"\\\r\n\x00]|\\[^\r\n\x00])+)\\?(?:[\r\n\x00]|$)` +
	`|'(?P<u>[^'"\\\r\n\x00]+)(?:[\r\n]|$)` +
	"|(?P<v>[^\\s\"'`,;&{}<>\\\\|\\x00][^\\s\"'`,;&{}<>\\\\\\x00]*)" +
	`)`)

// rules, by decreasing priority (section 5.3 of docs/plans/M0-redaction.md).
var rules = []rule{
	shape(KindPrivateKey, rePEM),
	keyed(KindKubeconfig, `client-key-data|token|id-token|refresh-token`, nil),
	keyed(KindAWSSecretKey, `(?:aws_)?secret_?access_?key|aws_secret_key`, nil),
	keyed(KindAWSSessionToken, `(?:aws_)?session_?token|aws_security_token|x-amz-security-token|x-amz-signature`, nil),
	shape(KindAWSSessionToken, reAWSSession),
	keyed(KindAzureSecret, `(?:arm_|azure_)?client_?secret|secret_?text`, nil),
	shape(KindAzureSecret, reAzure),
	keyed(KindScalewayKey, `scw_secret_key|scaleway_secret_key`, nil),
	shape(KindScalewayKey, reScw),
	keyed(KindOVHCredential, `(?:ovh_)?(?:application_?key|application_?secret|consumer_?key)`, nil),
	keyed(KindIPsecPSK, `psk|pre_?shared_?key|tunnel[0-9]_preshared_key|shared_?key|ike_psk`, nil),
	shape(KindIPsecPSK, rePSKLine),
	{kind: KindIPsecPSK, re: regexp.MustCompile(rePSKRelaxed), blocked: true},
	shape(KindAWSAccessKey, reAWSKey),
	shape(KindGitHubToken, reGitHub),
	shape(KindGitLabToken, reGitLab),
	shape(KindSlackToken, reSlack),
	shape(KindLLMAPIKey, reLLM),
	shape(KindPrivateKey, reB64PEM),
	shape(KindDBConnString, reDB),
	shape(KindURLCredentials, reURL),
	{kind: KindSensitiveVar, re: regexp.MustCompile(reAuthz), exempt: exemptScheme},
	{kind: KindSensitiveVar, re: regexp.MustCompile(reAuthzRelaxed), blocked: true},
	shape(KindSensitiveVar, reAuthScheme),
	keyed(KindSensitiveVar, names, exemptGeneric),
	{kind: KindSensitiveVar, pairs: true, exempt: exemptGeneric},
}

func shape(k Kind, expr string) rule {
	return rule{kind: k, re: regexp.MustCompile(expr)}
}

// keyed builds a rule for keys named by keyNames (case-insensitive, whole
// key), quoted, single-quoted, escaped-quoted or bare.
func keyed(k Kind, keyNames string, exempt func(key, value string) bool) rule {
	return rule{kind: k, re: keyRe(keyNames), keyed: true, exempt: exempt}
}

// keyRe matches a key named by keyNames (group k) and its separator.
func keyRe(keyNames string) *regexp.Regexp {
	n := `(?P<k>` + keyNames + `)`
	return regexp.MustCompile(`(?i)` + keyPrefix + `(?:"` + n + `"` + sepAny + `|'` + n + `'` + sepAny +
		`|\\"` + n + `\\"` + sepAny + `|` + n + sepBare + `)`)
}

func (ru rule) candidates(s string, protected [][]int) []candidate {
	if ru.pairs {
		return namedValues(s, protected, ru.exempt)
	}
	var out []candidate
	// keyed: end of the last non-exempt value; values starting in it are
	// redundant. A quote never closed runs to the end of its line and does not
	// skip the keys it contains: JSON escapes it and would read them.
	skip := 0
	colon := ru.re.SubexpIndex("c")
	for _, loc := range ru.re.FindAllStringSubmatchIndex(s, -1) {
		if !ru.keyed {
			st, en := span(ru.re, loc, "v")
			exempt := ru.blocked || (ru.exempt != nil && ru.exempt("", s[st:en]))
			out = append(out, candidate{start: st, end: en, exempt: exempt})
			continue
		}
		vs := afterBlanks(s, loc[1])
		if vs < skip || inside(protected, vs) || (colon > 0 && loc[2*colon] >= 0 && vs == loc[1]) {
			continue
		}
		st, en, open, ok := readValue(s, vs)
		if !ok {
			continue
		}
		ks, ke := span(ru.re, loc, "k")
		exempt := ru.exempt != nil && ru.exempt(s[ks:ke], s[st:en])
		if !exempt && !open {
			skip = en
		}
		out = append(out, candidate{start: st, end: en, exempt: exempt})
	}
	return out
}

// readValue reads the value at vs with valueRe: its bounds, and whether it is
// a quote never closed.
func readValue(s string, vs int) (st, en int, open, ok bool) {
	loc := valueRe.FindStringSubmatchIndex(s[vs:])
	if loc == nil {
		return 0, 0, false, false
	}
	for i, n := range valueRe.SubexpNames() {
		if (n == "v" || n == "u") && loc[2*i] >= 0 {
			return vs + loc[2*i], vs + loc[2*i+1], n == "u", true
		}
	}
	return 0, 0, false, false
}

// afterBlanks returns the position of the first byte at or after i that is
// neither a space nor a tab.
func afterBlanks(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

// span returns the bounds of the first participating group named name, or
// those of the whole match.
func span(re *regexp.Regexp, loc []int, name string) (int, int) {
	for i, n := range re.SubexpNames() {
		if n == name && loc[2*i] >= 0 {
			return loc[2*i], loc[2*i+1]
		}
	}
	return loc[0], loc[1]
}

// Name and value pairs: a "value" field is sensitive when the "name" field
// of the same object, or of the same YAML mapping, is a sensitive name.
var (
	// objectRe: an object without nested braces, on one line or several.
	objectRe = regexp.MustCompile(`\{[^{}]*\}`)
	// objectField: a "name" or "value" key inside an object.
	objectField = keyRe(`name|value`)
	// lineField: a "name" or "value" key at the start of a line (real or
	// JSON-escaped line break), after its indentation and list dash.
	lineField = regexp.MustCompile(`(?:^|\n|\\n)(?P<i>[ \t]*)(?P<d>-[ \t]+)?(?i:(?P<k>name|value))[ \t]*:`)
	// nameValueRe reads a name: an identifier, quoted or followed by a
	// delimiter (a blank, ',', ';', '}', ']', an escaped line break or tab,
	// or the end of the text).
	nameValueRe = regexp.MustCompile(`^(?:"(?P<v>[A-Za-z0-9_.-]+)"|'(?P<v>[A-Za-z0-9_.-]+)'|\\"(?P<v>[A-Za-z0-9_.-]+)\\"` +
		`|(?P<v>[A-Za-z0-9_.-]+)(?:[\s,;}\]]|\\[nrt]|$))`)
	// sensitiveName: a whole name that the generic keyed rule would match.
	sensitiveName = regexp.MustCompile(`(?i)^(?:` + names + `)$`)
)

// namedValues returns the values of "value" fields whose sibling "name" field
// is a sensitive name, in either order: fields of one object (JSON, HCL, YAML
// flow mapping), or fields on two consecutive lines of one YAML mapping (same
// key column, the second line not starting a new list item). Values are read
// by valueRe and exempted like those of the generic keyed rule; a field that
// starts in a non-exempt value already read is redundant. An object or a pair
// of lines that overlaps an existing placeholder is ignored: masking may have
// removed the brace or the line break that kept its fields apart.
func namedValues(s string, protected [][]int, exempt func(key, value string) bool) []candidate {
	var out []candidate
	skip := 0
	add := func(name string, vs int) {
		if vs < skip || inside(protected, vs) {
			return
		}
		st, en, open, ok := readValue(s, vs)
		if !ok {
			return
		}
		ex := exempt != nil && exempt(name, s[st:en])
		if !ex && !open {
			skip = en
		}
		out = append(out, candidate{start: st, end: en, exempt: ex})
	}

	colon := objectField.SubexpIndex("c")
	for _, o := range objectRe.FindAllStringIndex(s, -1) {
		if overlaps(protected, o[0], o[1]) {
			continue
		}
		name := ""
		var values []int
		for _, loc := range objectField.FindAllStringSubmatchIndex(s[o[0]:o[1]], -1) {
			vs := afterBlanks(s, o[0]+loc[1])
			if colon > 0 && loc[2*colon] >= 0 && vs == o[0]+loc[1] {
				continue
			}
			ks, ke := span(objectField, loc, "k")
			if !strings.EqualFold(s[o[0]+ks:o[0]+ke], "name") {
				values = append(values, vs)
			} else if n, ok := readName(s, vs); ok && name == "" {
				name = n
			}
		}
		if name == "" {
			continue
		}
		for _, vs := range values {
			add(name, vs)
		}
	}

	skip = 0
	fields := lineField.FindAllStringSubmatchIndex(s, -1)
	for i := 1; i < len(fields); i++ {
		a, b := fields[i-1], fields[i]
		nameFirst := isNameField(s, a)
		if b[4] >= 0 || nameFirst == isNameField(s, b) || column(a) != column(b) {
			continue
		}
		if gap := s[a[1]:b[0]]; strings.Contains(gap, "\n") || strings.Contains(gap, `\n`) || overlaps(protected, a[0], b[1]) {
			continue
		}
		nf, vf := a, b
		if !nameFirst {
			nf, vf = b, a
		}
		ns, vs := afterBlanks(s, nf[1]), afterBlanks(s, vf[1])
		if ns == nf[1] || vs == vf[1] {
			continue
		}
		if n, ok := readName(s, ns); ok {
			add(n, vs)
		}
	}
	return out
}

// readName returns the name read at vs, and whether it is sensitive.
func readName(s string, vs int) (string, bool) {
	loc := nameValueRe.FindStringSubmatchIndex(s[vs:])
	if loc == nil {
		return "", false
	}
	st, en := span(nameValueRe, loc, "v")
	n := s[vs+st : vs+en]
	return n, sensitiveName.MatchString(n)
}

// isNameField reports whether the lineField match f is a "name" key.
func isNameField(s string, f []int) bool {
	return strings.EqualFold(s[f[6]:f[7]], "name")
}

// column returns the key column of the lineField match f: its indentation
// and its list dash.
func column(f []int) int {
	c := f[3] - f[2]
	if f[4] >= 0 {
		c += f[5] - f[4]
	}
	return c
}

var (
	reKeyword   = regexp.MustCompile(`(?i)^(?:true|false|null|nil|none|yes|no|on|off)$`)
	reSmallInt  = regexp.MustCompile(`^[0-9]{1,9}$`)
	reSegment   = regexp.MustCompile(`[A-Z]?[a-z0-9]+|[A-Z0-9]+`)
	reQuantity  = regexp.MustCompile(`(?i)^(?:len|length|min|minimum|max|maximum|count|age|days|ttl|expir|expiry|expire|expires|expiration|reuse|size|limit|attempts|retries|timeout|rotation|version|port|tokens)$`)
	reReference = regexp.MustCompile(`^(?:(?:var|local|data|module)\.[A-Za-z0-9_.\[\]*-]+|\$\{[^{}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|\$?\{\{[^{}]*\}\})$`)
	reNameKey   = regexp.MustCompile(`(?i:(?:^|[_.-])(?:name|arn|ref|url|uri|endpoint|path|file|policy|version|type))$|(?:Name|Arn|Ref|Url|Uri|Endpoint|Path|File|Policy|Version|Type)$`)
	reScheme    = regexp.MustCompile(`(?i)^(?:bearer|basic|token|digest|negotiate|ntlm|aws4-hmac-sha256)$`)
)

// exemptGeneric reports whether the value of a generic sensitive key is not a
// secret (rules E1 to E4 of docs/plans/M0-redaction.md, section 5.4).
func exemptGeneric(key, value string) bool {
	if len(value) > maxExempt {
		return false
	}
	return reKeyword.MatchString(value) || // E1
		(reSmallInt.MatchString(value) && quantityKey(key)) || // E2
		reReference.MatchString(value) || // E3
		reNameKey.MatchString(key) // E4
}

// quantityKey reports whether a whole segment of key is a quantity word.
// Segments are split at '_', '.', '-' and at case changes.
func quantityKey(key string) bool {
	for _, seg := range reSegment.FindAllString(key, -1) {
		if reQuantity.MatchString(seg) {
			return true
		}
	}
	return false
}

// exemptScheme reports whether an Authorization value is only a scheme name,
// without credentials (the credentials are an existing placeholder).
func exemptScheme(_, value string) bool {
	return reScheme.MatchString(value)
}

// placeholderRe matches the placeholders of the known kinds.
var placeholderRe = regexp.MustCompile(`\[REDACTED:(?:` + kindAlternatives() + `)\]`)

func kindAlternatives() string {
	quoted := make([]string, len(allKinds))
	for i, k := range allKinds {
		quoted[i] = regexp.QuoteMeta(string(k))
	}
	return strings.Join(quoted, "|")
}
