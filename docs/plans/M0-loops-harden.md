# M0-T19b `loops-harden` : bornes, reprise sur cause directe, signal d'approbation canonique

2026-09-27, `architect`, proposé. Cadrage : `docs/plans/M0-demo-prep.md` section 12, `docs/plans/M0-overview.md` 0 bis ; obligations (a), (h), (i), (m) côté `RunLoop`, (j), (n) de `docs/STATUS.md`. Pas d'ADR (contrat interne réversible avant T20). Revue sécurité : oui.

## 0. Amendements

BASE b5821ec.

- V1 (2026-09-27, `test-author`, étape A2) : code de référence (sections 3 à 5) sans défaut, commentaire de `RunLoop` retouché. Tests : `executeWith` enregistre `RunLoop` et l'exécute par son nom (un `converter.RawValue` n'est pas assignable à `json.RawMessage`, `jsontext.Value` en Go 1.27.1) ; remplacements sans effet de 6.3 écrits en échappements JSON (`\"\\u0062ob\"`, `\"plan_hash\":\"\\u0061`) ; littéraux non ASCII en échappements Go ASCII ; gofumpt. Mutations réancrées pour compiler : M7 et M9 de M0-T15 (`err.Error() == \"\"`), N15 (`) != nil || second.Payload() != nil`). Tests renforcés après mutations exploratoires survivantes : chaque octet ASCII, é, U+2028, U+1F600 à la borne et un octet au-dessus, majorant D1 vérifié contre `json.Marshal` ; échec déclaré mais `NonRetryable` non repris ; `ProposeFailure` tronqué (`7}`, `{\"tokens\":7`) refusé ; signal sans préfixe, tronqué, à fins `\\v`, `\\f`, NUL, U+00A0, U+0085, signature à espace ou é refusés. Point 11.3 partiellement infirmé : une `CanceledError` rendue par l'activité arrive en `ActivityError -> ApplicationError -> CanceledError` (même effet, garde `HasDetails`). `LoopResult` maximal mesuré : 203 555 octets. 27, 22 et 25 mutations détectées ; équivalentes : X16b, X17, X28, X34b, X35b.

## 1. Objet et périmètre

Dans : `internal/loops/{spec,runloop,approvals,runloop_test,approvals_test}.go`, `docs/STATUS.md`, `docs/02-THREAT-MODEL.md`. Hors : `fake`, `domain`, T19c, T19d, `workflowcheck.config.yaml`, M1. Aucun appel JSON nouveau dans un workflow ; `approvals.go` perd son `json.Decoder`. Code : déclarations modifiées en entier, `RunLoop` en diff contre BASE ; « HEAD l. x à y » : lignes inchangées de `git show b5821ec:<fichier>`.

## 2. Décisions

| # | Décision |
|---|---|
| D1 | **Bornes (a)** mesurées par `wireLen`, majorant de l'encodage `encoding/json` (HTML échappé) : 6 par octet de contrôle, `<`, `>`, `&` ; 2 par `"`, `\`, octet de rune multi-octets ; 1 sinon. Charge et candidat 64 Kio et UTF-8 valide, 100 findings, 1 Kio de texte par finding, noms de spécification 1 à 64 octets de `[A-Za-z0-9._-]` (la stratégie entre dans la trace). `LoopResult` au pire : 65 536 + 100 x 1 127 + 100 x 256 + 123 = **203 959 < 262 144** (256 Kio, codec M1), vérifié par `TestRunLoopSizeLimits`. |
| D2 | Refus : charge, erreur `InvalidLoopSpec` avant toute activité (elle vient de l'appelant) ; candidat, tokens comptés puis `invalid_response` sans vérification ; findings, `invalid_response` avant `OK`, `Verified` faux. |
| D3 | **(h)** Reprise seulement si `err` est exactement `*temporal.ActivityError`, sa cause directe (`errors.Unwrap`) exactement `*temporal.ApplicationError` (`reflect.TypeOf`), rejouable, avec `ProposeFailure` canonique. `errors.As` ne s'applique qu'à cette cause et ne traverse jamais un délai (errorlint refuse l'assertion, `nolint` interdit). Sans déclaration : 0 token, `activity_failed`. |
| D4 | `ProposeFailure` lu en `converter.RawValue` : unique détail, `json/plain`, octets `{"tokens":N}`, `strconv.Itoa(n) == N` ; sinon `invalid_response`. |
| D5 | **(i)** Tokens invalides : itération tracée (`Tokens` 0) avant l'escalade. `emptyCandidate` retire tous les blancs JSON. |
| D6 | **(m)** `ctx.Err()` juste après le `Get` du vérificateur. Non testable au testsuite (l'annulation y résout le futur en `CanceledError`) : critère 10. |
| D7 | **(j, T57)** Signal admis seulement en `json/plain`, 8 Kio au plus, octets (blancs finaux exceptés) égaux à `json.Marshal(Approval)` : `{"approved":B,"plan_hash":"H","approver":"A","signature":"S"}`, H et S dans `valueBytes` (jamais échappés), S non vide, A canonique. Tout le reste : `malformed`. Remplace D2 de M0-T15. |
| D8 | **(n)** `IgnoredSignal.DeclaredApprover`, JSON `declared_approver`. |
| D9 | Tests adaptés : `ActivityFailureEscalates` (échec repris désormais déclaré, D3) ; `BudgetTokens`, `ProposerFailuresCounted` (1 itération tracée, D5) ; `ign` (D8) ; `execute` délègue à `executeWith`. |

## 3. `internal/loops/spec.go`

Import `strings` ajouté. Après HEAD l. 34 :

```go
// Size bounds (obligation a), upper bounds of the JSON encoding (wireLen): a
// LoopResult then encodes to less than 256 KiB, the M1 codec limit.
const (
	MaxPayloadBytes   = 64 << 10
	MaxCandidateBytes = 64 << 10
	MaxFindings       = 100
	MaxFindingBytes   = 1 << 10
	MaxNameBytes      = 64
)

// nameBytes admits the names of a LoopSpec; JSON never escapes them.
const nameBytes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
```

HEAD l. 67 à 72 de `Validate` remplacées ; fonctions ajoutées après `Validate` :

```go
	case !validName(s.ID) || !validName(s.ProposeActivity) || !validName(s.VerifyActivity):
		return invalidSpec("names")
	case s.ProposeActivity == s.VerifyActivity:
		return invalidSpec("the verifier must not be the proposer")
	case len(s.Strategies) == 0 || len(s.Strategies) > MaxStrategies || slices.ContainsFunc(s.Strategies, invalidName):
		return invalidSpec("strategies")
```
```go
// validName: 1 to MaxNameBytes bytes of nameBytes.
func validName(s string) bool {
	return s != "" && len(s) <= MaxNameBytes && strings.Trim(s, nameBytes) == ""
}

func invalidName(s string) bool { return !validName(s) }
```

## 4. `internal/loops/runloop.go`

Imports : `encoding/json errors reflect slices strconv strings time unicode/utf8`, `converter temporal workflow`, `internal/loops/domain`. Commentaire de `ProposeFailure` : `// ProposeFailure is the only detail of a proposer ApplicationError that spent` / `// tokens. RunLoop admits it only as the exact bytes {"tokens":N} and retries` / `// only such a declared failure (threats T10, T45, obligation h).` Commentaire de `RunLoop` : « or a failed activity » devient « a failed activity or an invalid response », « invalid spec » devient « invalid spec or payload ».

```diff
 		return LoopResult{}, err
 	}
+	if !admittedJSON(payload, MaxPayloadBytes) { // obligation a: bounded payload
+		return LoopResult{}, invalidSpec("payload")
+	}
 	spec = spec.withDefaults()
@@
+		retry := false
 		if perr != nil {
-			prop.Tokens = failedTokens(perr)
+			prop.Tokens, retry = failedCall(perr)
 		}
+		res.Iterations = it
+		res.Trace = append(res.Trace, IterationTrace{Iteration: it, Strategy: req.Strategy, Failed: perr != nil})
+		tr := &res.Trace[len(res.Trace)-1]
 		if prop.Tokens < 0 || prop.Tokens > MaxTokensLimit {
-			return escalate(ReasonInvalidResponse)
+			return escalate(ReasonInvalidResponse) // traced, tokens not counted (obligation i)
 		}
-		res.Iterations, res.Tokens = it, res.Tokens+prop.Tokens
-		res.Trace = append(res.Trace, IterationTrace{Iteration: it, Strategy: req.Strategy, Failed: perr != nil, Tokens: prop.Tokens})
+		tr.Tokens, res.Tokens = prop.Tokens, res.Tokens+prop.Tokens
 		if res.Tokens > spec.Budget.MaxTokens {
@@
-			if !retryable(perr) || failures >= MaxActivityAttempts {
+			if !retry || failures >= MaxActivityAttempts {
@@
 		failures = 0
+		if !admittedJSON(prop.Candidate, MaxCandidateBytes) { // obligation a: bounded candidate
+			return escalate(ReasonInvalidResponse)
+		}
 		if emptyCandidate(prop.Candidate) { // T53: empty desired state
@@
-		if err := workflow.ExecuteActivity(ctx, spec.VerifyActivity, vreq).Get(ctx, &vr); err != nil {
-			if ctx.Err() != nil { // cancellation is no verifier failure (obligation b)
-				return LoopResult{}, ctx.Err()
-			}
+		verr := workflow.ExecuteActivity(ctx, spec.VerifyActivity, vreq).Get(ctx, &vr)
+		if ctx.Err() != nil { // cancellation wins over any verifier result (obligations b, m)
+			return LoopResult{}, ctx.Err()
+		}
+		if verr != nil {
 			return escalate(ReasonActivityFailed) // Temporal retries only
 		}
+		if !findingsInBounds(vr.Findings) { // obligation a: bounded findings
+			return escalate(ReasonInvalidResponse)
+		}
 		fp, score := domain.Fingerprint(vr.Findings), domain.Score(vr.Findings)
-		tr := &res.Trace[len(res.Trace)-1]
 		tr.Verified, tr.Fingerprint, tr.Score, tr.Findings = true, fp, score, len(vr.Findings)
```

HEAD l. 222 à 241 (`failedTokens`, `retryable`, `emptyCandidate`) remplacées par :

```go
const jsonBlanks = " \t\n\r"

// failedCall reads a failed proposer call from the direct cause of the
// ActivityError only (obligation h): no ProposeFailure, 0 tokens and no retry.
func failedCall(err error) (tokens int, retry bool) {
	ae := directApplicationError(err)
	if ae == nil || !ae.HasDetails() {
		return 0, false
	}
	tokens, ok := failureTokens(ae)
	if !ok {
		return -1, false
	}
	return tokens, !ae.NonRetryable() && !slices.Contains(NonRetryableErrorTypes(), ae.Type())
}

// directApplicationError returns the cause of err if err is exactly an
// ActivityError and the cause exactly an ApplicationError (errors.As stops there).
func directApplicationError(err error) *temporal.ApplicationError {
	if reflect.TypeOf(err) != reflect.TypeFor[*temporal.ActivityError]() {
		return nil
	}
	cause := errors.Unwrap(err)
	var ae *temporal.ApplicationError
	if reflect.TypeOf(cause) != reflect.TypeFor[*temporal.ApplicationError]() || !errors.As(cause, &ae) {
		return nil
	}
	return ae
}

// failureTokens admits exactly one json/plain detail whose bytes are
// {"tokens":N}, N in canonical decimal form; RunLoop bounds N.
func failureTokens(ae *temporal.ApplicationError) (int, bool) {
	var first, second converter.RawValue
	if ae.Details(&first, &second) != nil || second.Payload() != nil {
		return 0, false
	}
	p := first.Payload()
	if string(p.GetMetadata()[converter.MetadataEncoding]) != converter.MetadataEncodingJSON {
		return 0, false
	}
	digits, ok1 := strings.CutPrefix(string(p.GetData()), `{"tokens":`)
	digits, ok2 := strings.CutSuffix(digits, "}")
	n, err := strconv.Atoi(digits)
	if !ok1 || !ok2 || err != nil || strconv.Itoa(n) != digits {
		return 0, false
	}
	return n, true
}

// admittedJSON reports raw JSON of valid UTF-8 whose encoding stays within limit.
func admittedJSON(raw json.RawMessage, limit int) bool {
	return utf8.Valid(raw) && wireLen(raw) <= limit
}

// findingsInBounds admits at most MaxFindings findings whose string fields
// encode to at most MaxFindingBytes each (obligation a).
func findingsInBounds(f []domain.Finding) bool {
	return len(f) <= MaxFindings && !slices.ContainsFunc(f, func(x domain.Finding) bool {
		n := wireLen(x.Code) + wireLen(x.Source) + wireLen(x.Severity) + wireLen(x.Resource) + wireLen(x.File) + wireLen(x.Message)
		return n > MaxFindingBytes
	})
}

// wireLen bounds the encoding/json length of s, valid UTF-8, HTML escaped: 6
// for a control byte, <, > and &; 2 for ", \ and multi-byte rune bytes; else 1.
func wireLen[T ~string | ~[]byte](s T) int {
	n := 0
	for i := range len(s) {
		switch b := s[i]; {
		case b < 0x20 || b == '<' || b == '>' || b == '&':
			n += 6
		case b == '"' || b == '\\' || b >= utf8.RuneSelf:
			n += 2
		default:
			n++
		}
	}
	return n
}

// emptyCandidate reports a candidate without content once every JSON blank
// is removed; a string of blanks is empty too (fail safe, obligation i).
func emptyCandidate(c json.RawMessage) bool {
	compact := strings.Map(func(r rune) rune {
		if strings.ContainsRune(jsonBlanks, r) {
			return -1
		}
		return r
	}, string(c))
	return slices.Contains([]string{"", "null", `""`, "{}", "[]"}, compact)
}
```

## 5. `internal/loops/approvals.go`

Imports : `slices strconv strings time`, `converter temporal workflow`. `approvalWire` supprimé. Commentaire d'`Approval` complété : `// A signal counts only in the canonical form of decodeApproval (T57).` Après HEAD l. 34 à 37 :

```go
// valueBytes admits plan hashes and signatures: JSON never escapes them (T57).
const valueBytes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=._:-@"
```

HEAD l. 90 à 94, et l. 208 :

```go
// IgnoredSignal records one ignored signal. DeclaredApprover is what the
// signal claims, never authenticated (T18); empty if malformed.
type IgnoredSignal struct {
	DeclaredApprover string        `json:"declared_approver"`
	Reason           IgnoredReason `json:"reason"`
}
```
```go
		res.Ignored = append(res.Ignored, IgnoredSignal{DeclaredApprover: a.Approver, Reason: reason})
```

HEAD l. 232 à 259 remplacées ; `validValue` après `validIdentity` :

```go
// decodeApproval admits one json/plain payload of at most
// MaxApprovalSignalBytes whose bytes, trailing JSON blanks aside, are exactly
// {"approved":B,"plan_hash":"H","approver":"A","signature":"S"}, the encoding
// of the Approval it yields; any other form is malformed (T57).
func decodeApproval(raw converter.RawValue) (Approval, bool) {
	p := raw.Payload()
	if string(p.GetMetadata()[converter.MetadataEncoding]) != converter.MetadataEncodingJSON {
		return Approval{}, false
	}
	data := p.GetData()
	if len(data) > MaxApprovalSignalBytes {
		return Approval{}, false
	}
	s := strings.TrimRight(string(data), jsonBlanks)
	approved := strings.HasPrefix(s, `{"approved":true,`)
	rest, ok0 := strings.CutPrefix(s, `{"approved":`+strconv.FormatBool(approved)+`,"plan_hash":"`)
	hash, rest, ok1 := strings.Cut(rest, `","approver":"`)
	approver, rest, ok2 := strings.Cut(rest, `","signature":"`)
	signature, ok3 := strings.CutSuffix(rest, `"}`)
	if !ok0 || !ok1 || !ok2 || !ok3 || !validValue(hash) || !validIdentity(approver) ||
		signature == "" || !validValue(signature) {
		return Approval{}, false
	}
	return Approval{Approved: approved, PlanHash: hash, Approver: approver, Signature: signature}, true
}

// validValue: bytes of valueBytes only, the empty string included.
func validValue(s string) bool { return strings.Trim(s, valueBytes) == "" }
```

## 6. Tests (`test-author`, phase tests)

### 6.1 Assistants et diffs

`runloop_test.go` importe en plus `math` et `go.temporal.io/sdk/converter` ; `executeWith` reprend HEAD l. 127 à 146 avec `env.ExecuteWorkflow(RunLoop, spec, in)`.

```go
func execute(t *testing.T, spec LoopSpec, s *script, setup func(*testsuite.TestWorkflowEnvironment)) (LoopResult, error) {
	t.Helper()
	return executeWith(t, spec, payload(), s, setup)
}

// rawValue is a json/plain payload holding exactly data.
func rawValue(t *testing.T, data string) converter.RawValue {
	t.Helper()
	p, err := converter.GetDefaultDataConverter().ToPayload("")
	if err != nil {
		t.Fatal(err)
	}
	p.Data = []byte(data)
	return converter.NewRawValue(p)
}

// obj is {"k":"<fill x n>"}: 12 bytes of weight around the fill.
func obj(fill string, n int) string { return `{"k":"` + strings.Repeat(fill, n) + `"}` }

// rawActivity answers every call to the activity name with data.
func rawActivity(name string, data converter.RawValue) func(*testsuite.TestWorkflowEnvironment) {
	return func(env *testsuite.TestWorkflowEnvironment) {
		env.RegisterActivityWithOptions(func(context.Context, json.RawMessage) (converter.RawValue, error) {
			return data, nil
		}, activity.RegisterOptions{Name: name})
	}
}

func isInvalidSpecErr(err error) bool {
	var ae *temporal.ApplicationError
	return errors.As(err, &ae) && ae.Type() == ErrTypeInvalidLoopSpec && ae.NonRetryable()
}

func traced(failed bool) IterationTrace { return IterationTrace{Iteration: 1, Strategy: "s1", Failed: failed} }
```

```diff
@@ TestRunLoopBudgetTokens, boucle finale
-		want(t, res, StatusEscalated, ReasonInvalidResponse, 0)
-		if _, v := s.calls(); v != 0 || res.Tokens != 0 {
+		want(t, res, StatusEscalated, ReasonInvalidResponse, 1) // traced first (obligation i)
+		if _, v := s.calls(); v != 0 || res.Tokens != 0 || res.Trace[0] != traced(false) {
@@ TestRunLoopActivityFailureEscalates
-	e := step{proposeErr: transient}
+	e := step{proposeErr: temporal.NewApplicationError("transient", "Transient", ProposeFailure{})} // declared (obligation h)
@@ TestRunLoopProposerFailuresCounted, boucle des détails invalides
-		want(t, res, StatusEscalated, ReasonInvalidResponse, 0)
-		if p, _ := s.calls(); p != 1 || res.Tokens != 0 {
+		want(t, res, StatusEscalated, ReasonInvalidResponse, 1)
+		if p, _ := s.calls(); p != 1 || res.Tokens != 0 || res.Trace[0] != traced(true) {
@@ approvals_test.go, func ign
-	return loops.IgnoredSignal{Approver: approver, Reason: r}
+	return loops.IgnoredSignal{DeclaredApprover: approver, Reason: r}
```

### 6.2 `runloop_test.go` : 9 tests en fin de fichier

```go
func TestRunLoopPayloadBounded(t *testing.T) {
	for _, c := range []struct {
		name, data string
		ok         bool
	}{
		{"at the bound", obj("a", MaxPayloadBytes-12), true},
		{"one byte over", obj("a", MaxPayloadBytes-11), false},
		{"raw < weighs 6", obj("<", (MaxPayloadBytes-12)/6+1), false},
		{"rune bytes weigh 2", obj("é", (MaxPayloadBytes-12)/4+1), false},
		{"invalid UTF-8", obj("\xff", 1), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newScript(pass())
			res, err := executeWith(t, testSpec(), rawValue(t, c.data), s, nil)
			p, v := s.calls()
			if c.ok && (err != nil || res.Status != StatusConverged) || !c.ok && (!isInvalidSpecErr(err) || p+v != 0) {
				t.Errorf("error %v, status %q, %d activities", err, res.Status, p+v)
			}
		})
	}
}

func TestRunLoopCandidateBounded(t *testing.T) {
	for _, c := range []struct {
		name, cand string
		ok         bool
	}{
		{"at the bound", obj("a", MaxCandidateBytes-12), true},
		{"one byte over", obj("a", MaxCandidateBytes-11), false},
		{"raw < weighs 6", obj("<", (MaxCandidateBytes-12)/6+1), false},
		{"invalid UTF-8", obj("\xff", 1), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newScript(pass(), pass())
			res := run(t, testSpec(), s, rawActivity(proposeName, rawValue(t, `{"candidate":`+c.cand+`,"tokens":10}`)))
			if c.ok {
				want(t, res, StatusConverged, "", 1)
				return
			}
			want(t, res, StatusEscalated, ReasonInvalidResponse, 1)
			if _, v := s.calls(); v != 0 || res.Tokens != 10 || res.Best != nil {
				t.Errorf("verifies %d, tokens %d, best %d bytes", v, res.Tokens, len(res.Best))
			}
		})
	}
}

func TestRunLoopBlankCandidateRejected(t *testing.T) {
	for _, c := range []string{"[ \n ]", "{\t}", "[\r\n]", `"  "`} {
		s := newScript(pass(), pass())
		res := run(t, testSpec(), s, rawActivity(proposeName, rawValue(t, `{"candidate":`+c+`,"tokens":10}`)))
		want(t, res, StatusEscalated, ReasonInvalidResponse, 1)
		if _, v := s.calls(); v != 0 || res.Tokens != 10 {
			t.Errorf("candidate %q: %d verifies, tokens %d", c, v, res.Tokens)
		}
	}
}

func TestRunLoopFindingsBounded(t *testing.T) {
	many := func(n int) []domain.Finding {
		f := make([]domain.Finding, n)
		for i := range f {
			f[i] = fnd(domain.SeverityLow, "L"+strconv.Itoa(i))
		}
		return f
	}
	refused := func(t *testing.T, st step) {
		t.Helper()
		s := newScript(st, pass())
		res := run(t, testSpec(), s, nil)
		want(t, res, StatusEscalated, ReasonInvalidResponse, 1)
		if _, v := s.calls(); v != 1 || res.Trace[0].Verified || res.Best != nil || res.Remaining != nil {
			t.Errorf("verifies %d, trace %+v, best %s", v, res.Trace[0], res.Best)
		}
	}
	want(t, run(t, testSpec(), newScript(fail(many(MaxFindings)...), pass()), nil), StatusConverged, "", 2)
	refused(t, fail(many(MaxFindings+1)...))
	refused(t, pass(many(MaxFindings+1)...))
	base := domain.Finding{Code: "c", Source: "s", Severity: domain.SeverityLow, Resource: "r", File: "f", Message: "m"} // weight 8
	for i := range 6 {
		at, over := base, base
		for _, c := range []struct {
			f *domain.Finding
			n int
		}{{&at, MaxFindingBytes - 8}, {&over, MaxFindingBytes - 7}} {
			fields := []*string{&c.f.Code, &c.f.Source, (*string)(&c.f.Severity), &c.f.Resource, &c.f.File, &c.f.Message}
			*fields[i] += strings.Repeat("x", c.n)
		}
		if res := run(t, testSpec(), newScript(fail(at), pass()), nil); res.Status != StatusConverged {
			t.Errorf("field %d at the bound: %q %q", i, res.Status, res.Reason)
		}
		refused(t, fail(over))
	}
	lt := base
	lt.Message = strings.Repeat("<", 170) // 170 raw bytes, weight 7 + 1020
	refused(t, fail(lt))
}

func TestRunLoopSizeLimits(t *testing.T) {
	if got := []int{MaxPayloadBytes, MaxCandidateBytes, MaxFindings, MaxFindingBytes, MaxNameBytes}; !slices.Equal(got, []int{64 << 10, 64 << 10, 100, 1 << 10, 64}) {
		t.Fatalf("size limits %v", got)
	}
	for _, c := range []struct { // D1: every bound reached with the bytes JSON expands most
		fill   string
		weight int
	}{{"<", 6}, {"&", 6}, {"\u2028", 6}, {"é", 4}} {
		f := domain.Finding{Message: strings.Repeat(c.fill, MaxFindingBytes/c.weight), Line: math.MinInt}
		tr := IterationTrace{
			Iteration: MaxIterationsLimit, Strategy: strings.Repeat("s", MaxNameBytes), Fingerprint: domain.Fingerprint(nil),
			Score: MaxFindings * 100, Findings: MaxFindings, Tokens: MaxTokensLimit,
		}
		res := LoopResult{
			Status: StatusEscalated, Reason: ReasonStrategiesExhausted,
			Best:      json.RawMessage(`"` + strings.Repeat(c.fill, (MaxCandidateBytes-4)/c.weight) + `"`),
			Remaining: slices.Repeat([]domain.Finding{f}, MaxFindings), Iterations: MaxIterationsLimit,
			Tokens: MaxTokensLimit, Trace: slices.Repeat([]IterationTrace{tr}, MaxIterationsLimit),
		}
		p, err := converter.GetDefaultDataConverter().ToPayload(res)
		if err != nil || len(p.GetData()) >= 256<<10 {
			t.Errorf("fill %q: %d bytes, %v", c.fill, len(p.GetData()), err)
		}
	}
}

func TestRunLoopProposerErrorKinds(t *testing.T) {
	declared := temporal.NewApplicationError("llm call failed", "Transient", ProposeFailure{Tokens: 5})
	check := func(t *testing.T, s *script, res LoopResult) {
		t.Helper()
		want(t, res, StatusEscalated, ReasonActivityFailed, 1)
		if p, _ := s.calls(); p != 1 || res.Tokens != 0 || res.Trace[0] != traced(true) {
			t.Errorf("calls %d, tokens %d, trace %+v", p, res.Tokens, res.Trace)
		}
	}
	for _, c := range []struct {
		name string
		err  error
	}{
		{"undeclared", errors.New("transient")},
		{"declared cause of an undeclared application error", temporal.NewApplicationErrorWithCause("llm", "Transient", declared)},
		{"declared cause of a timeout", temporal.NewTimeoutError(1, declared)}, // 1: START_TO_CLOSE, no import of go.temporal.io/api
		{"cancellation by the activity", temporal.NewCanceledError(ProposeFailure{Tokens: 5})},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newScript(step{proposeErr: c.err}, pass())
			check(t, s, run(t, testSpec(), s, nil))
		})
	}
	t.Run("panic", func(t *testing.T) {
		s := newScript(pass(), pass())
		check(t, s, run(t, testSpec(), s, func(env *testsuite.TestWorkflowEnvironment) {
			env.RegisterActivityWithOptions(func(ctx context.Context, req ProposeRequest) (ProposeResponse, error) {
				r, err := s.propose(ctx, req)
				r.Tokens /= len(req.Findings) // runtime panic: no finding at iteration 1 (criterion 7 bans the builtin)
				return r, err
			}, activity.RegisterOptions{Name: proposeName})
		}))
	})
}

func TestRunLoopProposeFailureCanonical(t *testing.T) {
	failed := func(details ...any) step {
		return step{proposeErr: temporal.NewApplicationError("llm call failed", "Transient", details...)}
	}
	s := newScript(failed(rawValue(t, `{"tokens":7}`)), failed(ProposeFailure{}), pass())
	res := run(t, testSpec(), s, nil)
	want(t, res, StatusConverged, "", 3)
	if res.Tokens != 17 {
		t.Errorf("tokens %d", res.Tokens)
	}
	bad := [][]any{{ProposeFailure{Tokens: 7}, ProposeFailure{Tokens: 7}}, {[]byte(`{"tokens":7}`)}}
	for _, d := range []string{
		`{"tokens":07}`, `{"tokens":+7}`, `{"tokens":-0}`, `{"tokens":7.0}`, `{"tokens":1e1}`, `{"tokens":"7"}`,
		`{"tokens": 7}`, ` {"tokens":7}`, `{"tokens":7} `, `{"Tokens":7}`, `{"tokens":7,"tokens":7}`,
		`{"tokens":7,"cost":1}`, `null`, `{}`,
	} {
		bad = append(bad, []any{rawValue(t, d)})
	}
	for i, d := range bad {
		s := newScript(failed(d...), pass())
		res := run(t, testSpec(), s, nil)
		want(t, res, StatusEscalated, ReasonInvalidResponse, 1)
		if p, _ := s.calls(); p != 1 || res.Tokens != 0 || res.Trace[0] != traced(true) {
			t.Errorf("detail %d: calls %d, tokens %d, trace %+v", i, p, res.Tokens, res.Trace)
		}
	}
}

func TestRunLoopFailureWithoutFindingAtFirstIteration(t *testing.T) {
	res := run(t, testSpec(), newScript(fail(), pass()), nil)
	want(t, res, StatusEscalated, ReasonInvalidResponse, 1)
	if !res.Trace[0].Verified || res.Best != nil || res.Remaining != nil {
		t.Errorf("trace %+v, best %s, remaining %v", res.Trace[0], res.Best, res.Remaining)
	}
}

func TestRunLoopSpecNamesBounded(t *testing.T) {
	long := strings.Repeat("n", MaxNameBytes)
	for i, f := range []func(*LoopSpec){
		func(s *LoopSpec) { s.ID = long + "n" },
		func(s *LoopSpec) { s.ID = "loop\n" },
		func(s *LoopSpec) { s.ProposeActivity = "Propose " },
		func(s *LoopSpec) { s.VerifyActivity = "Vérifier" },
		func(s *LoopSpec) { s.Strategies = []string{"s1", long + "s"} },
		func(s *LoopSpec) { s.Strategies = []string{`s"1`} },
	} {
		s := testSpec()
		f(&s)
		if err := s.Validate(); !isInvalidSpecErr(err) {
			t.Errorf("case %d: %v", i, err)
		}
	}
	s := testSpec()
	s.ID, s.ProposeActivity, s.Strategies = long, "A-Z.a_z0-9", []string{long}
	if err := s.Validate(); err != nil {
		t.Errorf("valid names refused: %v", err)
	}
}
```

### 6.3 `approvals_test.go` : 2 tests en fin de fichier

```go
func TestAwaitApprovalsCanonicalSignalOnly(t *testing.T) {
	valid := signed("bob", true)
	body, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	indented, err := json.MarshalIndent(valid, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	j, sig, h := string(body), valid.Signature, plan()
	var signals []any
	for _, d := range []string{
		strings.Replace(j, `"approver"`, `"Approver"`, 1),
		strings.Replace(j, `"approver":"bob",`, `"approver":"bob","approver":"bob",`, 1),
		strings.Replace(j, `{"approved":true,`, `{"approved":false,"approved":true,`, 1),
		strings.TrimSuffix(j, "}") + `,"signature":"` + sig + `"}`,
		`{"approved":true,"approver":"bob","plan_hash":"` + h + `","signature":"` + sig + `"}`,
		`{"plan_hash":"` + h + `","approved":true,"approver":"bob","signature":"` + sig + `"}`,
		strings.Replace(j, `"bob"`, `"bob"`, 1),
		strings.Replace(j, `"plan_hash":"a`, `"plan_hash":"a`, 1),
		strings.Replace(j, `":`, `": `, 1),
		string(indented), " " + j, "\ufeff" + j,
	} {
		signals = append(signals, rawJSON(t, d))
	}
	n, v := len(signals), newVerifier()
	out := await(t, request(1, false), time.Hour, v, nil, append(signals, rawJSON(t, j+" \t\r\n"))...)
	wantOutcome(t, out, loops.OutcomeApproved, []string{"bob"}, slices.Repeat([]loops.IgnoredSignal{ign("", loops.IgnoredMalformed)}, n)...)
	wantVerified(t, v, "bob")
	t.Run("admitted value bytes, escaped ones malformed", func(t *testing.T) {
		b64 := signed("bob", true)
		b64.Signature = "Zm9v+/8=:x._-@AZ09"
		out := await(t, request(1, false), time.Hour, newVerifier(), nil, b64, onHash("ab<", true), signed("bob", true))
		wantOutcome(t, out, loops.OutcomeApproved, []string{"bob"}, ign("bob", loops.IgnoredInvalidSignature), ign("", loops.IgnoredMalformed))
	})
}

func TestAwaitApprovalsIgnoredSignalDeclared(t *testing.T) {
	b, err := json.Marshal(ign("bob", loops.IgnoredWrongHash))
	if err != nil || string(b) != `{"declared_approver":"bob","reason":"wrong_hash"}` {
		t.Errorf("%s, %v", b, err)
	}
}
```

Rouge sur BASE : compilation (`undefined: MaxPayloadBytes` et quatre autres, `unknown field DeclaredApprover`).

## 7. Critères d'acceptation (racine)

| # | Commande | Attendu |
|---|---|---|
| 1 | `go test ./internal/loops/ -count=1 -run TestRunLoop -v 2>&1 \| grep -c -- '^--- PASS: TestRunLoop'` ; idem `grep -cE -- '--- (FAIL\|SKIP)'` | `28` ; `0` |
| 2 | `go test ./internal/loops/... -count=1 -run TestAwaitApprovals -v 2>&1 \| grep -c -- '^--- PASS: TestAwaitApprovals'` ; critère 2 de `M0-approvals.md` | `18` ; `7` |
| 3 | `go test ./internal/loops/... -count=1 -race; echo rc=$?` ; `make arch-test; echo rc=$?` (workflowcheck) | `rc=0` ; `rc=0` |
| 4 | `go list -f '{{join .Imports " "}}' ./internal/loops \| sed 's#github.com/amezianechayer/rempart/##g'` | `encoding/json errors internal/loops/domain go.temporal.io/sdk/converter go.temporal.io/sdk/temporal go.temporal.io/sdk/workflow reflect slices strconv strings time unicode/utf8` |
| 5 | `grep -nE 'time\.(Now\|Sleep)\|math/rand\|"os"\|"log\|go func\|<-' internal/loops/*.go \| grep -v _test.go \| wc -l` ; `grep -c range internal/loops/approvals.go` ; `grep -n range internal/loops/runloop.go internal/loops/spec.go \| grep -vc 'range len(s)'` | `0` ; `0` ; `0` |
| 6 | `grep -cE 'encoding/json\|json\.' internal/loops/approvals.go` ; `grep -c 'errors.As(' internal/loops/runloop.go` ; `grep -c 'reflect.TypeFor\[' internal/loops/runloop.go` | `0` ; `1` ; `2` |
| 7 | `grep -rnE '//[[:space:]]*(nolint\|#nosec)\|workflowcheck:ignore\|panic\(' --include='*.go' internal/loops \| wc -l` | `0` |
| 8 | `golangci-lint run ./internal/loops/...; echo rc=$?` ; `gofumpt -l internal/loops \| wc -l` ; `go mod tidy -diff; echo rc=$?` | `rc=0` ; `0` ; `rc=0` |
| 9 | `git diff --name-only b5821ec -- ':!docs' \| wc -l` | `5` |
| 10 | (m) `grep -A1 'verr := workflow.ExecuteActivity(ctx, spec.VerifyActivity, vreq).Get(ctx, &vr)' internal/loops/runloop.go \| tail -1 \| grep -c 'if ctx.Err() != nil {'` | `1` |
| 11 | M1 à M27 de M0-T14 sur copie ; M17 réancrée : `prop.Tokens, retry = failedCall(perr)` devient `prop.Tokens, retry = 0, true` (`TestRunLoopValidationErrorNotRetried`) | 27 détectées |
| 12 | M1 à M25 de M0-T15 sauf M17, M18, M21 (retirées avec `json.Decoder`, remplacées par N21 à N23) ; M25 réancrée : `if ctx.Err() != nil { // cancellation wins` devient `if false { //` (`TestRunLoopCanceled`) | 22 détectées |
| 13 | N1 à N25 sur copie | 25 détectées |
| 14 | `make verify-quick; echo rc=$?` | `rc=0` |

## 8. Mutations nouvelles

Script de `docs/plans/M0-tenancy.md` 8.3, fichier en argument, `OLD` présent une fois ; `go test ./internal/loops/... -count=1 2>&1 | grep -cE -- "--- FAIL: ($EXPECTED)"` au moins `1`. Groupes par `EXPECTED` :

- `spec.go`, `TestRunLoopSpecNamesBounded` : N1 `!validName(s.ID) ||` devient `s.ID == "" ||` ; N2 `slices.ContainsFunc(s.Strategies, invalidName)` devient `slices.Contains(s.Strategies, "")` ; N3 `len(s) <= MaxNameBytes && ` supprimé.
- `runloop.go`, `TestRunLoopPayloadBounded` : N4 `if !admittedJSON(payload, MaxPayloadBytes) {` devient `if false {` ; N5 `utf8.Valid(raw) && ` supprimé ; N6 ` || b == '<'` supprimé ; N7 ` || b >= utf8.RuneSelf` supprimé.
- `TestRunLoopCandidateBounded` : N8 `if !admittedJSON(prop.Candidate, MaxCandidateBytes) {` devient `if false {`.
- `TestRunLoopFindingsBounded` : N9 `if !findingsInBounds(vr.Findings) {` devient `if false {` ; N10 `len(f) <= MaxFindings && ` supprimé ; N11 ` + wireLen(x.Resource)` supprimé ; N12 `n > MaxFindingBytes` devient `n >= MaxFindingBytes`.
- `TestRunLoopProposerErrorKinds` : N13 `reflect.TypeOf(cause) != reflect.TypeFor[*temporal.ApplicationError]() || ` supprimé ; N14 ` || !ae.HasDetails()` supprimé.
- `TestRunLoopProposeFailureCanonical` : N15 `, &second) != nil || second.Payload() != nil` devient `) != nil` ; N16 ` || strconv.Itoa(n) != digits` supprimé ; N17 `CutSuffix(digits, "}")` devient `CutSuffix(strings.TrimRight(digits, jsonBlanks), "}")` ; N18 `!= converter.MetadataEncodingJSON {` devient `== "" {`.
- `TestRunLoopBudgetTokens` : N19 `return escalate(ReasonInvalidResponse) // traced` devient `res.Iterations, res.Trace = it-1, res.Trace[:it-1]; return escalate(ReasonInvalidResponse) //`.
- `TestRunLoopBlankCandidateRejected` : N20 `strings.ContainsRune(jsonBlanks, r)` devient `r == ' '`.
- `approvals.go`, `TestAwaitApprovalsCanonicalSignalOnly` : N21 ``signature, ok3 := strings.CutSuffix(rest, `"}`)`` devient ``signature, _, ok3 := strings.Cut(rest, `"`)`` ; N22 `!validValue(hash) || ` supprimé ; N23 `strings.TrimRight(string(data), jsonBlanks)` devient `strings.TrimSpace(string(data))` ; N24 `0123456789+/=._:-@"` devient `0123456789/=._:-@"`.
- `TestAwaitApprovalsIgnoredSignalDeclared` : N25 `json:"declared_approver"` devient `json:"approver"`.

Non mutés, équivalents au testsuite : le contrôle de type de `err` (toute erreur de proposeur y est une `ActivityError`) ; (m), couvert par le critère 10.

## 9. Boucle et menaces

Fiche de `docs/plans/M0-runloop.md` section 8 inchangée sauf `budget` (taille, D1), `escalation` (réponse hors bornes, non canonique ou vide : `invalid_response` tracé), `security_notes` (reprise d'un échec déclaré seulement).

- **T10** : un échec non déclaré (erreur brute, enveloppée, délai, annulation, panique) n'est plus repris ; ses tokens inconnus comptent 0 une fois. Exigence T20 : l'adaptateur LLM rend `ProposeFailure` canonique après tout appel facturé.
- **T45**, **T53** renforcées ; **T57** soldée ; **T18** : `DeclaredApprover` ; **T55** (M1) : `RawValue` à tester derrière le vrai codec.
- **T71 proposée** : réponse ou résultat de boucle surdimensionné ou non encodable : la tâche de workflow échoue et se rejoue sans fin, sans escalade (D). Mitigation D1, D2. Risque : `valueBytes` exclut une signature JSON ou PEM.

## 10. Décisions humaines requises

1. Forme canonique du signal et `valueBytes` (D7), plus stricts que D2 de M0-T15 : à confirmer avant M4.
2. Charge hors bornes en erreur plutôt qu'en `invalid_response` (D2, écart au cadrage).
3. Fin de la reprise d'un échec non déclaré (V2 de M0-T14 reprenait `errors.New`) : contrat de l'adaptateur de T20.
4. (m) sans test comportemental en M0 ; test de rejeu d'historique réel en M1 (T21) à consigner.
5. Déclaration de `workflowcheck.config.yaml` devenue inutile : retrait en T19c.
6. Bornes des noms de spécification (D1), hors cadrage littéral.

## 11. Points non vérifiés (`test-author`, sur copie avant le gel ; sinon amendement V1)

1. `workflowcheck` muet sous `reflect`, `errors.Unwrap`, `strings.Map`, `utf8.Valid` ; sinon déclaration justifiée (accord humain), jamais `//workflowcheck:ignore`.
2. Go 1.27.1 (jsonv2) : `RawMessage` décodé garde blancs internes, `<` brut, octet non UTF-8 (`stream.go` l. 284 lu, couche v2 non lue) ; chaînes décodées en UTF-8 valide (U+FFFD), dont dépend le poids 2 de D1 ; `json.RawMessage` accepté en entrée d'activité de test.
3. `temporal.NewTimeoutError(1, cause)` garde sa cause (`failure_converter.go` l. 119, 258) ; `CanceledError` de l'activité : cause `*CanceledError` ; division par zéro : `PanicError` (l. 230).
4. `Details(&first, &second)` laisse `second` vide pour un détail unique (`composite_data_converter.go` l. 60 à 80).
5. `TestRunLoopSizeLimits` sous 256 Kio ; lints v2 (`wastedassign`, `nilerr`, `errorlint`) ; `-race` sous 60 s.

## 12. Tâches ordonnées

| # | Tâche | Qui | Vérification |
|---|---|---|---|
| 1 | Décisions de la section 10 ; `rempart-state phase tests` | humain, principal | phase `tests` |
| 2 | Section 6 | `test-author` | `go vet ./internal/loops/...` : seulement `undefined: Max...`, `unknown field DeclaredApprover` |
| 3 | Sur copie : sections 3 à 6, critères, section 11 ; écarts en V1 | `test-author` | vert ; 27, 22, 25 détectées |
| 4 | `phase impl` ; cycle 1 : `spec.go` | principal | `go test ./internal/loops/ -run 'SpecNamesBounded\|InvalidSpecRejected'` vert |
| 5 | Cycle 2 : `runloop.go` ; cycle 3 : `approvals.go` | principal | critère 1, puis 2 à 10 |
| 6 | `make verify-quick` ; mutations sur copie du code final | principal | critères 11 à 14 |
| 7 | `security-reviewer`, puis `acceptance-verifier` | subagents | PASS |
| 8 | `docs/STATUS.md`, modèle de menace (T10, T18, T45, T53, T57, T71), `phase free`, commit `fix(loops): bound loop sizes, retry only declared failures, canonical approval signals (M0-T19b)` | principal | `git status --porcelain` vide |
