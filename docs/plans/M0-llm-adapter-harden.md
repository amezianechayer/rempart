# M0-T20b `llm-adapter-harden` : conditions de la revue M0-T12 et obligations (aa) à (ad)

2026-09-28, `architect`, proposé. Cadrage : `M0-overview.md` amendement A4 ; `M0-worker-demo.md` section 1 (terminée avant l'étape B de M0-T20) ; `docs/STATUS.md`. Revue sécurité : oui. Aucun appel réseau réel (`httptest`). SDK anthropic-sdk-go v1.75.0 inchangé.

BASE : `c25c9f9`. Décisions D1 à D8 retenues sur délégation de l'humain (défaut strict, réversibles).

## 1. État constaté (2026-09-28)

| Exigence | Déjà fait | Reste |
|---|---|---|
| T51 | `latest`, `stable`, `default`, `current` refusés | famille libre : `claude-sonnet-4-5` (alias), `claude-preview-5`, Bedrock et Vertex non datés admis ; `preview`, `beta`, `experimental` admis hors Anthropic |
| T50 | délai HTTP par tentative | `MaxRetries` 0 à 3 : attente `Retry-After` bornée par le seul `ctx` appelant |
| T49 | rien | le SDK lit tout corps par `io.ReadAll` (`requestconfig.go` l. 514, 545) |
| T52 | rien | `msg.ID`, `msg.Model`, `request-id` copiés tels quels |
| T47 | `Proxy` nil par défaut, redirections refusées | `Config.Transport` injecté utilisé tel quel |
| `tool_use` | bloc refusé sans outils (`tool_no_tools`) | `stop_reason` `tool_use` sans outils ; outil non déclaré |
| (aa) | clés, chaînes, `k: v` (M0-T19a) | `nom: v` pour `const`, `enum`, `pattern` ; `k: ` sans blancs initiaux |
| (ab) | `\\u`, `\\U`, `\\x` suivis d'hexadécimal ou `{` | chiffre après `\\` ; test Y4 (hexadécimal majuscule) |
| (ac) | liens refusés par `fs.Lstat`, lecture bornée | contrat non documenté |
| (ad) T70 | outils par `param.Override` | schéma de sortie réencodé depuis une `map` (clés triées) ; le SDK compacte et échappe `<`, `>`, `&` (`TestRawMessageNormalized` du SDK) |

## 2. Périmètre

Dans : `internal/llm/domain/policy.go`, `internal/llm/adapters/anthropic/provider.go`, `internal/llm/schema/admit.go`, commentaire de `prompts.LoadFS`, leurs tests, `docs/02-THREAT-MODEL.md`, `docs/STATUS.md`.

Hors : câblage (`anthropic-unwired-m0` maintenue, levée en M1 par décision distincte) ; `ProposeFailure` et reprise ((ae), (af), activité) ; refonte du rédacteur (T37) ; échappement des messages par le SDK (section 9) ; Bedrock, Vertex (M5) ; `type` et `role` de la réponse.

## 3. Décisions (sens le plus strict, réversibles, sans ADR)

| # | Décision |
|---|---|
| D1 | T51 : Anthropic direct, liste fermée `undatedModels` (11 constantes du SDK sans instantané daté), sinon date exigée, famille `opus`, `sonnet` ou `haiku`, jour réel. Bedrock et Vertex : datés seulement jusqu'à vérification à la source. `preview`, `beta`, `experimental` refusés partout, casse ignorée. |
| D2 | T50 : `Config.MaxRetries` supprimé, une tentative, délai global `Timeout`, sinon `ErrTimeout` ; reprise à l'activité (D11 de M0-T20). |
| D3 | T47 : `Transport` nil, ou `*http.Transport` à `Proxy` nil cloné ; sinon `ErrInvalidConfig`. |
| D4 | T52 : `id` ou `model` hors `^[A-Za-z0-9_-]{1,128}$` : réponse refusée (`ErrInvalidMetadata`), plus strict que "valeur vide" ; `APIError.RequestID` invalide : `""`. |
| D5 | T49 : `MaxResponseBytes = 1 << 20` sur tout corps, après décompression ; `Content-Length` supérieur refusé avant lecture ; jamais de troncature. |
| D6 | T70 : octets émis des schémas égaux à `json.Compact` des octets vérifiés, contrôlés avant I/O sur le corps construit, sinon `ErrReencoded` ; un schéma avec `<`, `>`, `&` est refusé. |
| D7 | (ab) `\\` suivi de tout chiffre décimal refusé. |
| D8 | (aa) paires nommées sous `properties` et `$defs`, via `items`, `anyOf`, `oneOf`, `$ref` (couple nom et définition une fois) ; `pattern` brut et sans ancres ; au plus 65 536 textes. |
| D9 | `stop_reason` `tool_use` sans outils, outil non déclaré : `ErrUnexpectedContent`. |

## 4. Code de référence (tabulations dans le code réel)

### 4.1 `internal/llm/domain/policy.go`

```go
// undatedModels: models of anthropic-sdk-go v1.75.0 (message.go) published
// without a dated snapshot, 2026-09-28. Any other model needs its date (T51).
var undatedModels = [...]string{
  "claude-fable-5", "claude-fable-5-1", "claude-mythos-5", "claude-mythos-5-1",
  "claude-opus-4-6", "claude-opus-4-7", "claude-opus-4-8", "claude-opus-5",
  "claude-opus-5-5", "claude-sonnet-4-6", "claude-sonnet-5",
}

const (
  family = `claude-(?:opus|sonnet|haiku)-[0-9]{1,2}(?:-[0-9]{1,2})?`
  dated  = `(?P<date>20[0-9]{6})`
)

var (
  anthropicModel = regexp.MustCompile(`^` + family + `-` + dated + `$`)
  bedrockModel   = regexp.MustCompile(`^(?:(?:eu|us|apac|global)\.)?anthropic\.` + family + `-` + dated + `-v[0-9]+:[0-9]+$`)
  vertexModel    = regexp.MustCompile(`^` + family + `@` + dated + `$`)
)

func modelPinned(r Route) bool {
  lower := strings.ToLower(r.Model)
  for _, tok := range [...]string{"latest", "stable", "default", "current", "preview", "beta", "experimental"} {
    if strings.Contains(lower, tok) {
      return false
    }
  }
  switch r.Platform {
  case PlatformAnthropic:
    return slices.Contains(undatedModels[:], r.Model) || datedMatch(anthropicModel, r.Model)
  case PlatformBedrock:
    return datedMatch(bedrockModel, r.Model)
  case PlatformVertex:
    return datedMatch(vertexModel, r.Model)
  default:
    return genericModel.MatchString(r.Model)
  }
}

// datedMatch: s matches re and its date group is a real calendar day.
func datedMatch(re *regexp.Regexp, s string) bool {
  m := re.FindStringSubmatch(s)
  if m == nil {
    return false
  }
  _, err := time.Parse("20060102", m[re.SubexpIndex("date")])
  return err == nil
}
```

### 4.2 `internal/llm/adapters/anthropic/provider.go`

Sentinelles ajoutées : `ErrTimeout`, `ErrResponseTooLarge`, `ErrInvalidMetadata`, `ErrReencoded` (messages fixes, préfixe `anthropic: `). `Config` perd `MaxRetries`.

```go
const MaxResponseBytes = 1 << 20

// sdkModels: the models of the SDK that CheckPolicy pins (T51, T80).
var sdkModels = []string{
  sdk.ModelClaudeFable5_1, sdk.ModelClaudeOpus5_5, sdk.ModelClaudeMythos5_1, sdk.ModelClaudeSonnet5,
  sdk.ModelClaudeFable5, sdk.ModelClaudeMythos5, sdk.ModelClaudeOpus5, sdk.ModelClaudeOpus4_8,
  sdk.ModelClaudeOpus4_7, sdk.ModelClaudeOpus4_6, sdk.ModelClaudeSonnet4_6,
  sdk.ModelClaudeHaiku4_5_20251001, sdk.ModelClaudeOpus4_5_20251101, sdk.ModelClaudeSonnet4_5_20250929,
}

var metaPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// in New, after the current checks:
  rt, ok := transport(cfg.Transport)
  if !ok {
    return nil, ErrInvalidConfig
  }
  c := sdk.NewClient(
    option.WithoutEnvironmentDefaults(),
    option.WithBaseURL(u.String()),
    option.WithHTTPClient(&http.Client{Transport: capped{rt}, CheckRedirect: refuse, Timeout: cfg.Timeout}),
    option.WithAPIKey(cfg.APIKey.Reveal()),
    option.WithMaxRetries(0),
    option.WithRequestTimeout(cfg.Timeout),
  )

func transport(rt http.RoundTripper) (http.RoundTripper, bool) { // T47
  if rt == nil {
    return noProxy(), true
  }
  t, ok := rt.(*http.Transport)
  if !ok || t == nil || t.Proxy != nil {
    return nil, false
  }
  return t.Clone(), true
}

type capped struct{ rt http.RoundTripper } // T49

func (c capped) RoundTrip(r *http.Request) (*http.Response, error) {
  resp, err := c.rt.RoundTrip(r)
  if err != nil {
    return nil, err
  }
  if resp.ContentLength > MaxResponseBytes {
    _ = resp.Body.Close()
    return nil, ErrResponseTooLarge
  }
  resp.Body = &cappedBody{rc: resp.Body, left: MaxResponseBytes}
  return resp, nil
}

type cappedBody struct {
  rc   io.ReadCloser
  left int64
}

func (b *cappedBody) Read(p []byte) (int, error) {
  if b.left <= 0 {
    var one [1]byte
    n, err := b.rc.Read(one[:])
    if n > 0 {
      return 0, ErrResponseTooLarge
    }
    return 0, err
  }
  if int64(len(p)) > b.left {
    p = p[:b.left]
  }
  n, err := b.rc.Read(p)
  b.left -= int64(n)
  return n, err
}

func (b *cappedBody) Close() error { return b.rc.Close() }
```

`call` : refus avant I/O inchangés ; `params, want, err := buildParams(...)` ; `p.msgs.New(ctx, params, option.WithMiddleware(verifiedBytes(want)))` ; `convertMessage(msg, req.MaxTokens, tools, withTools)`. Le `switch` d'erreur insère, après `ErrRedirectRefused` :

```go
  case errors.Is(err, ErrResponseTooLarge):
    return domain.Response{}, ErrResponseTooLarge
  case errors.Is(err, ErrReencoded):
    return domain.Response{}, ErrReencoded
  case isTimeout(err):
    return domain.Response{}, ErrTimeout
  case errors.As(err, &aerr):
    return domain.Response{}, &APIError{StatusCode: aerr.StatusCode, RequestID: meta(aerr.RequestID)}

func isTimeout(err error) bool {
  var ne net.Error
  return errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout()
}

func meta(s string) string {
  if metaPattern.MatchString(s) {
    return s
  }
  return ""
}
```

T70, `buildParams` rend aussi `want sent` :

```go
type sent struct {
  schema json.RawMessage
  tools  [][]byte
}

  if len(req.Schema) > 0 {
    c, ok := compactObject(req.Schema)
    if !ok {
      return out, sent{}, domain.ErrInvalidRequest
    }
    want.schema = c
    out.OutputConfig = sdk.OutputConfigParam{Format: param.Override[sdk.JSONOutputFormatParam](
      json.RawMessage(`{"type":"json_schema","schema":` + string(c) + `}`))}
  }
  for _, t := range tools {
    c, ok := compactObject(t.InputSchema)
    if !ok || t.Name == "" {
      return out, sent{}, domain.ErrInvalidRequest
    }
    want.tools = append(want.tools, c)
    tp := sdk.ToolUnionParamOfTool(param.Override[sdk.ToolInputSchemaParam](json.RawMessage(bytes.Clone(c))), t.Name)
    // Strict and Description: unchanged
  }

func compactObject(raw json.RawMessage) (json.RawMessage, bool) {
  if _, ok := decodeObject(raw); !ok {
    return nil, false
  }
  var b bytes.Buffer
  if json.Compact(&b, raw) != nil {
    return nil, false
  }
  return b.Bytes(), true
}

type sentBody struct {
  OutputConfig struct {
    Format struct {
      Schema json.RawMessage `json:"schema"`
    } `json:"format"`
  } `json:"output_config"`
  Tools []struct {
    InputSchema json.RawMessage `json:"input_schema"`
  } `json:"tools"`
}

// verifiedBytes refuses, before any I/O, a body whose schemas are not the
// compacted verified bytes (T70).
func verifiedBytes(want sent) option.Middleware {
  return func(r *http.Request, next option.MiddlewareNext) (*http.Response, error) {
    if r.GetBody == nil {
      return nil, ErrReencoded
    }
    rc, err := r.GetBody()
    if err != nil {
      return nil, ErrReencoded
    }
    body, err := io.ReadAll(rc)
    _ = rc.Close()
    var got sentBody
    if err != nil || json.Unmarshal(body, &got) != nil ||
      !bytes.Equal(got.OutputConfig.Format.Schema, want.schema) || len(got.Tools) != len(want.tools) {
      return nil, ErrReencoded
    }
    for i, t := range want.tools {
      if !bytes.Equal(got.Tools[i].InputSchema, t) {
        return nil, ErrReencoded
      }
    }
    return next(r)
  }
}
```

`convertMessage` : après `msg == nil`, `if !metaPattern.MatchString(msg.ID) || !metaPattern.MatchString(msg.Model) {` rend `ErrInvalidMetadata` ; `case sdk.StopReasonToolUse:` séparé, `if !withTools {` rend `ErrUnexpectedContent` ; bloc `case b.Type == "tool_use" && withTools && slices.ContainsFunc(tools, func(t domain.ToolSpec) bool { return t.Name == b.Name }):`. `Capabilities` : `slices.Contains(sdkModels, route.Model)` remplace la constante `models`.

### 4.3 `internal/llm/schema/admit.go`

```go
const maxTexts = 1 << 16

func escapeLike(c, d byte) bool {
  isHex := d >= '0' && d <= '9' || d >= 'a' && d <= 'f' || d >= 'A' && d <= 'F'
  return (c == 'u' || c == 'U' || c == 'x') && (isHex || d == '{') || c >= '0' && c <= '9'
}
```

`Texts` : `add(k, s)` ajoute `k + ": " + s` et, si `t := strings.TrimLeft(s, " \n"); t != s`, `k + ": " + t` ; la marche actuelle appelle `add` pour chaque membre chaîne ; `defs` : `$defs` de la racine. Tout objet ayant `properties` ou `$defs` objet passe chaque couple (nom, sous-schéma) à `named` :

```go
  seen := map[[2]string]bool{}
  var named func(name string, v any)
  named = func(name string, v any) {
    n, ok := v.(map[string]any)
    if !ok {
      return
    }
    if s, ok := n["const"].(string); ok {
      add(name, s)
    }
    if list, ok := n["enum"].([]any); ok {
      for _, e := range list {
        if s, ok := e.(string); ok {
          add(name, s)
        }
      }
    }
    if p, ok := n["pattern"].(string); ok {
      add(name, p)
      add(name, strings.TrimSuffix(strings.TrimPrefix(p, "^"), "$"))
    }
    if ref, ok := n["$ref"].(string); ok {
      if d, ok := strings.CutPrefix(ref, "#/$defs/"); ok && !seen[[2]string{name, d}] {
        seen[[2]string{name, d}] = true
        named(name, defs[d])
      }
    }
    named(name, n["items"])
    for _, k := range []string{"anyOf", "oneOf"} {
      if list, ok := n[k].([]any); ok {
        for _, e := range list {
          named(name, e)
        }
      }
    }
  }
```

Fin : `if len(texts) > maxTexts {` rend `fmt.Errorf("%w: too many texts", ErrInvalidSchema)`.

### 4.4 `internal/llm/prompts/registry.go`

```go
// LoadFS loads the prompt id from fsys, which must hold no link: an embed.FS,
// or the FS of an os.Root (os.Root.FS) that only the process writes. Links and
// non-regular files are refused through fs.Lstat; an FS that does not
// implement fs.ReadLinkFS follows links there and is outside this contract (T43).
```

## 5. Flux de données

`llm.Client` (vérifie, rédige, hache), `Provider.call` (refus avant I/O, `buildParams`, sérialisation du SDK, `verifiedBytes`, `capped`, une tentative dans `Timeout`), `convertMessage`, puis service (modèle comparé, schéma validé). Aucune boucle : gabarit `loop-engineering` sans objet.

## 6. Tests (phase tests, `test-author`)

`internal/llm/domain/policy_test.go` :
- `TestCheckPolicyModelPinned` révisé. Faux désormais : `anthropic_undated`, `bedrock_undated`, `bedrock_eu_undated`, `bedrock_undated_revision`, `vertex_undated`. Vrais : `claude-opus-5`, `claude-sonnet-4-6`, `claude-sonnet-4-20250514`. Faux : `claude-haiku-4-5`, `claude-preview-5`, `claude-beta-5`, `claude-fable-5-20260101`, `claude-sonnet-4-5-20250231`, `claude-opus-5-Preview`, selfhosted `mistral-preview`, `Experimental-x`, fake `fake-beta-v1`.
- `TestUndatedModelsClosed` : 11 entrées triées, uniques, `^claude-[a-z]+-[0-9]{1,2}(-[0-9]{1,2})?$`, sans jeton refusé.

`internal/llm/schema/texts_test.go` (nouveau) :
- `TestTextsNamedValues` : sous `api_key`, `const` donne `api_key: v1` ; `enum` `["a","b"]` deux paires ; `pattern` `^abc$` donne `api_key: ^abc$` et `api_key: abc` ; `$ref` vers `l` à `enum` donne `api_key: x` et `l: x` ; `items`, `anyOf` suivis ; `const` `"\n  v"` donne `api_key: v` ; `"description":"\nw"` donne `description: w` ; `const` numérique : aucune paire ; cycle `{"a":{"anyOf":[{"$ref":"#/$defs/a"},{"$ref":"#/$defs/a"}]}}` sans erreur ; témoins de M0-T19a présents.
- `TestTextsBounded` : `enum` de 40 000 chaînes d'un caractère sous une propriété : `ErrInvalidSchema`.

`internal/llm/schema/strict_test.go`, `TestSchemaRawEscapeDigits` : refusés `a\\101b`, `a\\0`, `a\\9`, `a\\xA1b`, `a\\uABCD`, `pattern` `^\\101$` ; acceptés `a\\d`, `a\\ b`, `a\\-`.

`internal/llm/redact/schema_property_test.go`, `TestSchemaNamedValueProperty` (`rapid`) : `v` = `FAKE` puis 12 à 36 caractères `[A-Za-z0-9]`, retenue si `ContainsSecret(v)` est faux et `ContainsSecret("api_key: "+v)` vrai (compteur, propriété vide refusée) ; sous `api_key` : `const`, `enum`, `pattern` `^v$`, `$ref` vers une définition à `enum`, `const` objet `{"api_key":"\nv"}` ; aucun appel n'atteint le fournisseur ; oracle écrit à part.

`internal/llm/adapters/anthropic/` :
- `helpers_test.go` : `config(url)`, `newProvider(t, url)` sans `MaxRetries` ; `messageID(id, model, stop, ...)`. `provider_test.go` : `529_retried` devient `529` à 1 requête ; colonne `retries` et cas `-1`, `4` retirés.
- `harden_test.go` (nouveau) :
  - `TestResponseBodyBounded` : 200 découpé de `MaxResponseBytes + 1` octets ; `Content-Length` de `MaxResponseBytes + 1`, 10 octets puis attente : refus en moins de 1 s ; 400 de `MaxResponseBytes + 1` ; tous `ErrResponseTooLarge` (pas `ErrAPI`), réponse vide ; témoin complété d'espaces jusqu'à `MaxResponseBytes` accepté.
  - `TestSingleAttemptAndDeadline` : 529 avec `Retry-After-Ms: 3600000` et `Retry-After: 3600` : 1 requête, `APIError` 529, moins de 2 s ; serveur muet 3 s, `Timeout` 300 ms : `ErrTimeout` en moins de 2 s ; `ctx` annulé à 100 ms : `context.Canceled`.
  - `TestTransportProxyRefused` : `http.DefaultTransport`, `&http.Transport{Proxy: http.ProxyURL(piège)}`, `(*http.Transport)(nil)`, `RoundTripper` maison : `ErrInvalidConfig` ; `&http.Transport{}` admis puis `Proxy` réglé vers le piège après `New` : appel réussi, piège à 0 requête.
  - `TestResponseMetadataValidated` : `id` vide, `msg bad`, `msg<x>`, 129 `a`, `msg_é`, `model` `claude.opus` : `ErrInvalidMetadata` ; `id` de 128 `a` accepté ; `request-id` `req bad` ou de 129 caractères : `RequestID == ""`.
  - `TestToolUseOnlyWithTools` : `Structured`, `stop_reason` `tool_use` et texte ; `WithTools`, outil `other` : `ErrUnexpectedContent` ; témoin `greet` accepté.
  - `TestSentSchemaIsVerifiedBytes` : schéma non trié suivi d'un saut de ligne, en `Structured` et en outil : octets reçus égaux à `json.Compact` ; description `a<b` ou `a&b` : `ErrReencoded`, 0 requête, message sans `a<b`.
  - `TestSDKModelsClassified` : les 14 de `sdkModels`, cités par identifiant du SDK : `CheckPolicy` nil, `NativeStructuredOutput` vrai ; `ModelClaudeHaiku4_5`, `ModelClaudeOpus4_5`, `ModelClaudeSonnet4_5`, `ModelClaudeMythosPreview` : `ErrModelNotPinned`, capacités fausses.

## 7. Critères d'acceptation

1. `go test ./internal/llm/adapters/anthropic/ -run 'TestResponseBodyBounded|TestSingleAttemptAndDeadline|TestTransportProxyRefused|TestResponseMetadataValidated|TestToolUseOnlyWithTools|TestSentSchemaIsVerifiedBytes|TestSDKModelsClassified' -v 2>&1 | grep -c '^--- PASS'` : `7`.
2. `go test ./internal/llm/domain/ ./internal/llm/schema/ ./internal/llm/redact/ -run 'TestCheckPolicyModelPinned|TestUndatedModelsClosed|TestTextsNamedValues|TestTextsBounded|TestSchemaRawEscapeDigits|TestSchemaNamedValueProperty' -v 2>&1 | grep -c '^--- PASS'` : `6`.
3. `go test -race -count=1 ./internal/llm/...; echo rc=$?` : `rc=0`.
4. `go doc ./internal/llm/prompts LoadFS | grep -Fc embed.FS` puis `... | grep -Fc os.Root` : au moins `1` chacun.
5. `grep -Ec 'MaxRetries +int' internal/llm/adapters/anthropic/provider.go` : `0` ; `grep -c 'WithMaxRetries(0)' internal/llm/adapters/anthropic/provider.go` : `1`.
6. `grep -c 'github.com/anthropics/anthropic-sdk-go v1.75.0' go.mod` : `1`.
7. `go test ./internal/archtest/ -run 'TestRepositoryConforms|TestAnthropicAdapterUnwired' -v 2>&1 | grep -c '^--- PASS'` : `2` ; `go list -deps ./cmd/... | grep -c llm/adapters/anthropic` : `0`.
8. `grep -c 'https://api.anthropic.com' internal/llm/adapters/anthropic/harden_test.go` : `0`.
9. `git diff --stat <sha-A5> -- '*_test.go' '**/testdata/**'` : vide (`<sha-A5>` consigné en A5).
10. Mutations de la section 8 : toutes détectées (relevé d'`acceptance-verifier`).
11. `make verify-quick; echo rc=$?` et `make verify; echo rc=$?` : `rc=0`.
12. `grep -c 'M0-T20b.*terminée' docs/STATUS.md` : au moins `1`.
13. `grep -cP '[^\x20-\x7E\x{C0}-\x{FF}\x{152}\x{153}\x{178}]' docs/plans/M0-llm-adapter-harden.md` : `0`.

## 8. Mutations (une à la fois, copie privée `mktemp -d`)

| # | Ancre : remplacement | Test |
|---|---|---|
| N1 | `option.WithMaxRetries(0)` : `option.WithMaxRetries(2)` | `TestSingleAttemptAndDeadline` |
| N2 | `Timeout: cfg.Timeout})` : `Timeout: 0})` et `option.WithRequestTimeout(cfg.Timeout),` supprimée | idem |
| N3 | `case isTimeout(err):` : `case false:` | idem |
| N4 | `if resp.ContentLength > MaxResponseBytes {` : `if false {` | `TestResponseBodyBounded` |
| N5 | `resp.Body = &cappedBody{rc: resp.Body, left: MaxResponseBytes}` : `_ = resp.Body` | idem |
| N6 | `if n > 0 {` : `if false {` | idem |
| N7 | `\|\| t.Proxy != nil {` : `{` | `TestTransportProxyRefused` |
| N8 | `return t.Clone(), true` : `return t, true` | idem |
| N9 | `if !metaPattern.MatchString(msg.ID) \|\| !metaPattern.MatchString(msg.Model) {` : `if false {` | `TestResponseMetadataValidated` |
| N10 | `RequestID: meta(aerr.RequestID)` : `RequestID: aerr.RequestID` | idem |
| N11 | `if !withTools {` : `if false {` | `TestToolUseOnlyWithTools` |
| N12 | `&& slices.ContainsFunc(tools, func(t domain.ToolSpec) bool { return t.Name == b.Name })` : supprimé | idem |
| N13 | `!bytes.Equal(got.OutputConfig.Format.Schema, want.schema) \|\|` : supprimé | `TestSentSchemaIsVerifiedBytes` |
| N14 | `if !bytes.Equal(got.Tools[i].InputSchema, t) {` : `if false {` | idem |
| N15 | `slices.Contains(sdkModels, route.Model)` : `true` | `TestSDKModelsClassified` |
| N16 | `"preview", "beta", "experimental"}` : `}` | `TestCheckPolicyModelPinned` |
| N17 | `slices.Contains(undatedModels[:], r.Model) \|\| ` : supprimé | idem |
| N18 | `return err == nil` : `return true` | idem |
| N19 | `claude-(?:opus\|sonnet\|haiku)-` : `claude-[a-z]+-` | idem |
| N20 | `\|\| c >= '0' && c <= '9'` : supprimé | `TestSchemaRawEscapeDigits` |
| N21 | `\|\| d >= 'A' && d <= 'F'` : supprimé (Y4) | idem |
| N22 | `add(name, s)` sous `const` : supprimé | `TestTextsNamedValues`, `TestSchemaNamedValueProperty` |
| N23 | `add(name, strings.TrimSuffix(strings.TrimPrefix(p, "^"), "$"))` : supprimé | `TestTextsNamedValues` |
| N24 | `named(name, defs[d])` : `_ = d` | idem |
| N25 | `if t := strings.TrimLeft(s, " \n"); t != s {` : `if false {` | idem |
| N26 | `if len(texts) > maxTexts {` : `if false {` | `TestTextsBounded` |
| N27 | `&& !seen[[2]string{name, d}]` : supprimé | `TestTextsNamedValues` (cycle) |

Mutation survivante : équivalence démontrée ou test ajouté par amendement, jamais en modifiant un test gelé en phase impl.

## 9. Modèle de menace (`docs/02-THREAT-MODEL.md`)

- T47 : D3 ; résidu : `DialContext` d'un transport injecté peut viser un relais. T49 (D5), T50 (D2), T52 (D4) : soldées. T51 : D1, Bedrock et Vertex datés jusqu'à vérification.
- T70 : soldée pour les schémas (D6) ; résidu : messages et prompt système réécrits par le SDK (`<`, `>`, `&` en échappements Unicode JSON, délimiteurs de `RenderUntrusted` compris), même texte décodé.
- T43 : contrat de `LoadFS` documenté. T44, T69 : D8 ; résidu : secret réparti entre éléments d'`enum`, JSON doublement encodé (T37). T64 inchangée.
- **T80 (nouvelle ; T79 réservée par M0-T20)** : classement des modèles lié à une version du SDK (modèle nouveau non classé, non daté devenu alias). Contrôle : `TestSDKModelsClassified` ; toute montée du SDK revoit `undatedModels`.

## 10. Risques

- `param.Override` sur `JSONOutputFormatParam` non éprouvé : vérifié en A4 avant gel ; sinon amendement (forme réencodée revérifiée par `AdmittedText` et décodage égal, mêmes tests).
- Délais sous `-race` : marge de 2 s pour 300 ms.
- D1 : routes non datées à dater (aucune en M0 hors tests). D6 : aucun schéma actuel ne contient `<`, `>`, `&` (`grep -c '[<>&]' internal/llm/prompts/*/schema.json` : 0).

## 11. Tâches ordonnées

| # | Tâche | Qui | Sortie |
|---|---|---|---|
| A0 | `rempart-state phase tests` | principal | `Phase : free -> tests` |
| A1 | `policy_test.go` | `test-author` | rouge (`undatedModels` indéfini) |
| A2 | `texts_test.go`, `TestSchemaRawEscapeDigits`, `TestSchemaNamedValueProperty` | `test-author` | rouges |
| A3 | `helpers_test.go`, `provider_test.go`, `harden_test.go` | `test-author` | rouge (symboles indéfinis) |
| A4 | Copie privée avec la section 4 : `gofumpt -l`, `golangci-lint`, `go test -race`, N1 à N27 ; écarts en amendement V1 | `test-author` | tableau 8 |
| A5 | Preuve de rouge, commit des tests (SHA consigné), `phase impl` | principal | `Phase : tests -> impl` |
| I1 | `policy.go` (4.1), puis `admit.go` (4.3), puis `LoadFS` (4.4) | principal | critères 2, 4 |
| I2 | `provider.go` (4.2) | principal | critères 1, 3, 5 à 8 |
| F1 | `make verify-quick`, `make verify` | principal | critère 11 |
| F2 | `security-reviewer`, puis `acceptance-verifier` | sous-agents | PASS |
| F3 | Menaces (section 9) ; `docs/STATUS.md` : "M0-T20b `llm-adapter-harden` terminée" ; commit `feat(llm): harden anthropic adapter and schema texts (M0-T20b)` | principal | critères 12, 13 |

## Amendement V1 (A4, `test-author`, base `db109df`)

Copie privée avec la section 4 corrigée : `gofumpt -l` vide, `golangci-lint` 0, `go test -race ./internal/llm/...` vert, `make verify-quick` vert, N1 à N28 détectées. `param.Override` sur `JSONOutputFormatParam` vérifié (octets compactés émis ; `<`, `>`, `&` refusés avant I/O). Délais sous `-race` : 0,30 s et 0,10 s.

- 4.3 : `root, _ := doc.(map[string]any)` puis `defs, _ := root["$defs"].(map[string]any)` (racine non objet sans panique).
- 4.3 : arrêt au plafond : `full := func() bool { return len(texts) > maxTexts }` ; `if !ok || full() {` dans `named` ; `if full() { return }` en tête de `walk`. Sans lui, 60 Ko en `$ref` coûtent 8,3 millions d'allocations (695 Mo, 2 s) avant refus.
- 6, `TestTextsBounded` : l'`enum` de 40 000 chaînes (160 Ko) dépasse `MaxSchemaBytes`, refus pour la taille (N26 survivante). Remplacé : 8 propriétés en `$ref` vers un `enum` de 10 000, puis 1100 vers 7 500 (moins de 64 Kio) : `ErrInvalidSchema`, au plus 2^20 allocations ; témoin 1 vers 10 000 admis.
- 6 : `messageID(id, model, stop, content...)`, usage 12 et 5 ; `//nolint:staticcheck` (SA1019) sur `ModelClaudeMythosPreview`.
- 8, ancres qui ne compilent pas : N6 `if n > 0 {` : `if n < 0 {` ; N14 : `if len(got.Tools[i].InputSchema)+len(t) < 0 {` ; N17 `undatedModels[:], r.Model)` : `undatedModels[:0], r.Model)` ; N18 : `return err == nil || len(m) > 0` ; N22 `add(name, s)` sous `const` : `_ = s` ; N24 : `_, _ = d, defs` ; N25 `; t != s {` : `; false && t != s {`. Ajout N28 `return len(texts) > maxTexts }` : `return false }` (`TestTextsBounded`).
- 10 : `-race` sur `redact` : environ 340 s (249 s pour `TestLargeInputAdversarial`, préexistant). Un échec rapid écrit `internal/llm/redact/testdata/rapid/`, jamais commité.
- Critère de taille de ce plan : 27 000 octets.
