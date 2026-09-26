# M0-T11 `llm-client` : service `llm.Client`, seul point d'entrée des domaines

2026-09-24, `architect`, proposé. Fiche `docs/plans/M0-overview.md` §7, écarts en section 2. Aucun ADR (choix réversibles, cadre de l'ADR 0002). Revue sécurité : oui (T2, T3, T7, T10, T40, T41).

## 0. Amendement V1 (phase tests, 2026-09-24, prime sur le reste du document)

- Code de référence vérifié sur copie par `test-author` avant gel : 19 tests verts sous `-race`, `golangci-lint` 0 issue, archtest vert, aucun contre-exemple ; aucun changement du code.
- Section 9, mutations qui ne compilaient pas telles qu'écrites (variable ou import rendu inutilisé), remplacées par des variantes équivalentes, toutes détectées : M6 `if redact.New().ContainsSecret(p.System) && false {` ; M19 `if err := ts.Validate(tc.Input); err != nil && false {` ; M20 `if !ok && false {`.
- Secrets de test déclarés comme fonctions (`fakeAWSKey()`, etc.) et non en constantes, pour éviter gosec G101 sans directive `nolint`.
- Coût : sous `-race`, les deux cas « exactement 1 Mio » prennent environ 30 s chacun (rédacteur de M0-T07) ; sans `-race` (cas de `verify-quick`), environ 1,6 s.

---

## 1. Objectif et périmètre
Service déterministe au-dessus de `ports.ModelProvider` ; critères 3, 6 et 7 de `prompts/M0.md` (part service). Dans : `internal/llm/{doc.go,client.go,check.go}`, `internal/llm/{helpers,client,route}_test.go`, `docs/STATUS.md`. Hors : adaptateurs (T12) ; câblage `-dev` et configuration de production sans faux (T20) ; budgets par boucle et par tenant (T13, M1) ; cache de prompts ; refonte du rédacteur (M1).

## 2. Décisions
| # | Décision |
|---|---|
| D1 | **Route** (T40) : `Resolve` une fois par appel du service ; `checkedRoute` rend la route acceptée par `CheckPolicy` (avec `provider.Capabilities` de cette route), seule valeur passée au fournisseur, à chaque tentative. Aucune route par défaut ni en configuration. |
| D2 | **Faux** (T41) : `Config.AllowFakeRoute`, valeur zéro `false` ; `PlatformFake` sans l'option : `ErrFakeRouteRefused`. Ni environnement, ni drapeau, ni défaut ; l'option ne lève aucun autre contrôle. |
| D3 | **Rédaction** : texte, `SourceID`, `Content` **masqués, on continue** (copie profonde ; `Trace.Redactions` = somme des `len(matches)`) : refuser rendrait inutilisable toute donnée cloud contenant une clé, et le rédacteur n'est qu'une seconde barrière (M0-T07). Textes **statiques** (système, nom et description d'outil) : secret = **refus** `ErrSecretInPrompt` (masquer changerait l'artefact haché). |
| D4 | **Taille** : octets de `Text`, `SourceID`, `Content` avant rédaction ; plus de 1 Mio : `ErrRequestTooLarge`. Jamais de troncature ; le service ne sérialise rien. |
| D5 | **Prompt** (écart) : `Call` porte `PromptID` et `PromptHash` épinglé, plus un `prompts.Prompt` ; le service charge le prompt (`fs.FS` injecté, `nil` : embarqués), hash égal exigé (`ErrPromptMismatch`). |
| D6 | **Modèle** : `Response.Model != Route.Model` (vide, casse) : `ErrModelMismatch`, sans correction. |
| D7 | **Sortie** : sans appel d'outil, `Output` validé par le schéma du prompt ; sinon chaque `Input` par le schéma de son outil, `Output` écarté ; outil inconnu ou appel d'outil dans `Structured` : `ErrUnknownTool`, sans correction. |
| D8 | **Correction** : seule `schema.ErrOutOfSchema`, au plus `MaxCorrections` fois, par un message `user` citant l'erreur (mot-clé, chemin, jamais la sortie). Autres erreurs : arrêt. |
| D9 | **Erreurs** : messages fixes ; résolveur et fournisseur enveloppés par `opaqueError` (message = sentinelle, `errors.Is` garde la cause). Toute erreur : `Result{}`, outils `nil`. |
| D10 | **Trace** : route vérifiée, tenant, `PromptID`, `PromptHash`, `RequestID` de la réponse, tentatives, rédactions, usage cumulé ; ni contenu ni `RequestHash`. |
| D11 | **Config** (écart) : `MaxCorrections` 0 à 3 pris tel quel ; `MaxTokensPerCall` 1 à 65 536, obligatoire ; `call.MaxTokens` hors `[1, MaxTokensPerCall]` : `ErrTokenBudget`. |
| D12 | **API** (écart) : `NewClient(p, rr, promptFS, cfg)` sans rédacteur injecté (toujours `redact.New()`) ; `domain.ErrNoRoute`, `schema.ErrOutOfSchema` réutilisés. `Client` immuable, sans état, journal ni horloge : sûr en concurrence. |

## 3. Ordre des étapes (W : `WithTools` seulement)
Tout ce qui échoue sans I/O échoue avant `Resolve` (première I/O). S0 à S8 : ni `Resolve` ni appel ; S9 à S12 : `Resolve` une fois, aucun appel ; S13 à S15 : appels.

| Étape | Contrôle | Erreur |
|---|---|---|
| S0 | récepteur nil | `ErrInvalidConfig` |
| S1 | `tenancy.FromContext` | `ErrNoTenant`, `ErrInvalidTenant` |
| S2 | `ctx.Err()` | `Canceled`, `DeadlineExceeded` |
| S3 | W : `HasUntrusted()`, outils nil ou vides compris, avant `Validate` | `ErrUntrustedWithTools` |
| S4 | `Validate()` des messages | `ErrInvalidRequest`, `ErrInvalidPart` |
| S5 | `MaxTokens` | `ErrTokenBudget` |
| S6 | taille avant rédaction | `ErrRequestTooLarge` |
| S7 | W : outils (au moins un, nom unique `^[A-Za-z0-9_-]{1,64}$`, sans secret, schéma strict) | `ErrInvalidTools`, `ErrSecretInPrompt` |
| S8 | prompt, hash, système sans secret | `prompts`, `ErrPromptMismatch`, `ErrSecretInPrompt` |
| S9 | `Resolve` | `opaque(ErrNoRoute, cause)` |
| S10 | `PlatformFake` sans option | `ErrFakeRouteRefused` |
| S11 | `CheckPolicy` | erreurs de `domain` |
| S12 | rédaction, requête (système, schéma, hash du prompt) | aucune |
| S13 | par tentative : `ctx.Err()`, appel avec `route` | `ctx`, `opaque(ErrProviderFailed, cause)` |
| S14 | modèle déclaré | `ErrModelMismatch` |
| S15 | sortie (D7), correction (D8) | `ErrOutOfSchema`, `ErrUnknownTool` |

Obligations de `docs/STATUS.md` : route vérifiée (test 12, M9) ; faux (13, M7, critère 8) ; modèle (9, M13) ; `Validate` avant I/O (16, M2) ; `ctx` (18, M21, M22) ; aucune journalisation (critères 3, 4) ; erreurs sans entrée (19, M10, M17) ; `RequestHash` (critère 6, test 11) ; 1 Mio, rédaction avant sérialisation (4, 16, M4, M11, M12, M27).

## 4. Harnais (non patché)
Entrée : `phase free`, `make verify-quick` vert, arbre propre, `internal/llm/client.go` absent. Un seul tour ; tests en `package llm`, faux importé par les `_test.go` seulement (R5) ; `go vet` : seuls des `undefined:`. Secrets de test sous les formes de M0-T07 : `AKIAIOSFODNN7EXAMPLE`, `AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`, `ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000`.

## 5. Code de référence (normatif ; ancres de la section 9 au caractère près)

`doc.go` (remplace l'actuel) :
```go
// Package llm is the only entry point of the domains to a language model
// (ADR 0002). Client never logs and keeps no state: safe for concurrent use.
package llm
```

`client.go` :
```go
package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"

	"github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/llm/ports"
	"github.com/amezianechayer/rempart/internal/llm/prompts"
	"github.com/amezianechayer/rempart/internal/llm/redact"
	"github.com/amezianechayer/rempart/internal/llm/schema"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

var (
	ErrInvalidConfig    = errors.New("llm: invalid client configuration")
	ErrTokenBudget      = errors.New("llm: token budget exceeded")
	ErrRequestTooLarge  = errors.New("llm: request text exceeds 1 MiB")
	ErrPromptMismatch   = errors.New("llm: prompt hash differs from the pinned hash")
	ErrSecretInPrompt   = errors.New("llm: static prompt or tool text contains a secret")
	ErrInvalidTools     = errors.New("llm: invalid tool specification")
	ErrFakeRouteRefused = errors.New("llm: fake route refused by configuration")
	ErrModelMismatch    = errors.New("llm: response model differs from route")
	ErrProviderFailed   = errors.New("llm: provider call failed")
	ErrUnknownTool      = errors.New("llm: tool call names an unknown tool")
)

const (
	MaxRequestTextBytes = 1 << 20
	MaxCorrectionsLimit = 3
	MaxTokensLimit      = 1 << 16
)

type Config struct {
	MaxCorrections   int  // 0 to 3, taken as is
	MaxTokensPerCall int  // 1 to MaxTokensLimit, no default
	AllowFakeRoute   bool // tests and the -dev root only (T41)
}

// Call names a pinned prompt: PromptHash must equal the loaded prompt hash.
type Call struct {
	PromptID, PromptHash string
	Messages             []domain.Message
	MaxTokens            int
}

// Trace is evidence metadata: no content, never a request hash.
type Trace struct {
	Tenant               tenancy.ID
	Platform             domain.Platform
	Region, Model        string
	PromptID, PromptHash string
	RequestID            string
	Attempts, Redactions int
	Usage                domain.Usage
}

type Result struct {
	Output json.RawMessage
	Trace  Trace
}

type Client struct {
	provider ports.ModelProvider
	resolver ports.RouteResolver
	promptFS fs.FS
	cfg      Config
}

// NewClient: a nil promptFS selects the embedded prompts.
func NewClient(p ports.ModelProvider, rr ports.RouteResolver, promptFS fs.FS, cfg Config) (*Client, error) {
	if p == nil || rr == nil {
		return nil, fmt.Errorf("%w: provider and resolver are required", ErrInvalidConfig)
	}
	if cfg.MaxCorrections < 0 || cfg.MaxCorrections > MaxCorrectionsLimit {
		return nil, fmt.Errorf("%w: corrections out of range", ErrInvalidConfig)
	}
	if cfg.MaxTokensPerCall < 1 || cfg.MaxTokensPerCall > MaxTokensLimit {
		return nil, fmt.Errorf("%w: token budget out of range", ErrInvalidConfig)
	}
	return &Client{provider: p, resolver: rr, promptFS: promptFS, cfg: cfg}, nil
}

// Structured is the only call that may carry untrusted blocks.
func (c *Client) Structured(ctx context.Context, call Call) (Result, error) {
	res, _, err := c.run(ctx, call, nil, false)
	return res, err
}

// WithTools refuses untrusted blocks and checks each tool call against its tool.
func (c *Client) WithTools(ctx context.Context, call Call, tools []domain.ToolSpec) (Result, []domain.ToolCall, error) {
	return c.run(ctx, call, tools, true)
}

func (c *Client) run(ctx context.Context, call Call, tools []domain.ToolSpec, withTools bool) (Result, []domain.ToolCall, error) {
	if c == nil {
		return Result{}, nil, ErrInvalidConfig
	}
	tenant, err := tenancy.FromContext(ctx) // S1
	if err != nil {
		return Result{}, nil, err
	}
	if err := ctx.Err(); err != nil { // S2
		return Result{}, nil, err
	}
	pre := domain.Request{Messages: call.Messages}
	if withTools && pre.HasUntrusted() { // S3
		return Result{}, nil, domain.ErrUntrustedWithTools
	}
	if err := pre.Validate(); err != nil { // S4
		return Result{}, nil, err
	}
	if call.MaxTokens < 1 || call.MaxTokens > c.cfg.MaxTokensPerCall { // S5
		return Result{}, nil, ErrTokenBudget
	}
	if textSize(call.Messages) > MaxRequestTextBytes { // S6
		return Result{}, nil, ErrRequestTooLarge
	}
	var toolSchemas map[string]*schema.Schema
	if withTools { // S7
		if toolSchemas, err = checkTools(tools); err != nil {
			return Result{}, nil, err
		}
	}
	prompt, err := c.loadPrompt(call) // S8
	if err != nil {
		return Result{}, nil, err
	}
	route, err := c.checkedRoute(ctx, tenant) // S9 to S11
	if err != nil {
		return Result{}, nil, err
	}
	msgs, redactions := redactMessages(call.Messages) // S12
	req := domain.Request{
		PromptID: prompt.ID, PromptHash: prompt.Hash, System: prompt.System,
		Messages: msgs, Schema: prompt.Schema.Raw(), MaxTokens: call.MaxTokens,
	}
	tr := Trace{
		Tenant: tenant, Platform: route.Platform, Region: route.Region, Model: route.Model,
		PromptID: prompt.ID, PromptHash: prompt.Hash, Redactions: redactions,
	}
	for attempt := 0; ; attempt++ {
		if cerr := ctx.Err(); cerr != nil { // S13
			return Result{}, nil, cerr
		}
		var resp domain.Response
		if withTools {
			resp, err = c.provider.WithTools(ctx, route, req, tools)
		} else {
			resp, err = c.provider.Structured(ctx, route, req)
		}
		tr.Attempts++
		if err != nil {
			return Result{}, nil, opaque(ErrProviderFailed, err)
		}
		tr.Usage.InputTokens += resp.Usage.InputTokens
		tr.Usage.OutputTokens += resp.Usage.OutputTokens
		if resp.Model != route.Model { // S14
			return Result{}, nil, ErrModelMismatch
		}
		out, calls, verr := checkOutput(prompt.Schema, toolSchemas, resp) // S15
		if verr == nil {
			tr.RequestID = resp.RequestID
			return Result{Output: out, Trace: tr}, calls, nil
		}
		if !errors.Is(verr, schema.ErrOutOfSchema) || attempt >= c.cfg.MaxCorrections {
			return Result{}, nil, verr
		}
		req.Messages = append(req.Messages, correction(verr))
	}
}

// loadPrompt: a secret in a system prompt is refused, never masked (hash).
func (c *Client) loadPrompt(call Call) (prompts.Prompt, error) {
	load := prompts.Load
	if c.promptFS != nil {
		load = func(id string) (prompts.Prompt, error) { return prompts.LoadFS(c.promptFS, id) }
	}
	p, err := load(call.PromptID)
	if err != nil {
		return prompts.Prompt{}, err
	}
	if call.PromptHash != p.Hash {
		return prompts.Prompt{}, ErrPromptMismatch
	}
	if redact.New().ContainsSecret(p.System) {
		return prompts.Prompt{}, ErrSecretInPrompt
	}
	return p, nil
}

// checkedRoute returns exactly the route that CheckPolicy accepted (T40).
func (c *Client) checkedRoute(ctx context.Context, tenant tenancy.ID) (domain.Route, error) {
	pol, err := c.resolver.Resolve(ctx, tenant)
	if err != nil {
		return domain.Route{}, opaque(domain.ErrNoRoute, err)
	}
	if pol.Route.Platform == domain.PlatformFake && !c.cfg.AllowFakeRoute {
		return domain.Route{}, ErrFakeRouteRefused
	}
	if err := domain.CheckPolicy(pol, c.provider.Capabilities(pol.Route)); err != nil {
		return domain.Route{}, err
	}
	return pol.Route, nil
}

// opaqueError prints only kind: a resolver or provider message may quote input.
type opaqueError struct{ kind, cause error }

func (e *opaqueError) Error() string { return e.kind.Error() }

func (e *opaqueError) Unwrap() []error { return []error{e.kind, e.cause} }

func opaque(kind, cause error) error { return &opaqueError{kind: kind, cause: cause} }
```

`check.go` :
```go
package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/llm/redact"
	"github.com/amezianechayer/rempart/internal/llm/schema"
)

var toolName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// textSize counts text bytes before redaction (bound of M0-T07).
func textSize(msgs []domain.Message) int {
	n := 0
	for _, m := range msgs {
		for _, p := range m.Parts {
			n += len(p.Text)
			if p.Untrusted != nil {
				n += len(p.Untrusted.SourceID) + len(p.Untrusted.Content)
			}
		}
	}
	return n
}

func checkTools(tools []domain.ToolSpec) (map[string]*schema.Schema, error) {
	if len(tools) == 0 {
		return nil, fmt.Errorf("%w: no tool", ErrInvalidTools)
	}
	out := make(map[string]*schema.Schema, len(tools))
	for _, t := range tools {
		if !toolName.MatchString(t.Name) {
			return nil, fmt.Errorf("%w: malformed name", ErrInvalidTools)
		}
		if _, dup := out[t.Name]; dup {
			return nil, fmt.Errorf("%w: duplicate name", ErrInvalidTools)
		}
		if redact.New().ContainsSecret(t.Name) || redact.New().ContainsSecret(t.Description) {
			return nil, ErrSecretInPrompt
		}
		s, err := schema.CompileSchema(t.InputSchema)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidTools, err)
		}
		out[t.Name] = s
	}
	return out, nil
}

// redactMessages returns a redacted deep copy and the number of secrets masked.
func redactMessages(msgs []domain.Message) ([]domain.Message, int) {
	r := redact.New()
	n := 0
	red := func(s string) string {
		out, ms := r.Redact(s)
		n += len(ms)
		return out
	}
	out := make([]domain.Message, len(msgs))
	for i, m := range msgs {
		parts := make([]domain.Part, len(m.Parts))
		for j, p := range m.Parts {
			if p.Untrusted != nil {
				parts[j].Untrusted = &domain.UntrustedBlock{SourceID: red(p.Untrusted.SourceID), Content: red(p.Untrusted.Content)}
			} else {
				parts[j].Text = red(p.Text)
			}
		}
		out[i] = domain.Message{Role: m.Role, Parts: parts}
	}
	return out, n
}

// checkOutput: tool calls are checked against their tool and Output is dropped;
// otherwise Output is checked against the prompt schema. Structured has no tool.
func checkOutput(s *schema.Schema, tools map[string]*schema.Schema, resp domain.Response) (json.RawMessage, []domain.ToolCall, error) {
	if len(resp.ToolCalls) == 0 {
		if err := s.Validate(resp.Output); err != nil {
			return nil, nil, err
		}
		return bytes.Clone(resp.Output), nil, nil
	}
	calls := make([]domain.ToolCall, len(resp.ToolCalls))
	for i, tc := range resp.ToolCalls {
		ts, ok := tools[tc.Name]
		if !ok {
			return nil, nil, ErrUnknownTool
		}
		if err := ts.Validate(tc.Input); err != nil {
			return nil, nil, err
		}
		calls[i] = domain.ToolCall{Name: tc.Name, Input: bytes.Clone(tc.Input)}
	}
	return nil, calls, nil
}

// correction quotes the schema error (keyword and path), never the output.
func correction(err error) domain.Message {
	return domain.Message{Role: domain.RoleUser, Parts: []domain.Part{{
		Text: "The previous answer was rejected: " + err.Error() + ". Answer again with JSON that matches the schema exactly.",
	}}}
}
```
Hors contrat : `ctx` nil (S1 rend `ErrNoTenant`), interface nulle typée.

## 6. Tests (`test-author`, `package llm`)
Fixtures (`helpers_test.go`) : `F` = `fstest.MapFS` : `test.greeting.v1` (système `Reply with a JSON greeting.\n`, schéma `{"type":"object","properties":{"greeting":{"type":"string"}},"required":["greeting"],"additionalProperties":false}`), `test.leaky.v1` (même schéma, système `Use key AKIAIOSFODNN7EXAMPLE.\n`). `H` : hash de `test.greeting.v1`. `C0` : `Call{"test.greeting.v1", H, [user: "hello"], 256}`. `K` : `Config{0, 256, true}`. `V` : `{"greeting":"bonjour"}`. Tenants A, B, C de `internal/llm/fake/resolver_test.go`. `PA` : `fake`, `""`, `fake-model-v1`, `eu`, `zero`. Faux : `Models{"fake-model-v1": {}, "fake-model-retain": {RequiresRetention: true}}`. `countingResolver` compte les `Resolve`. `spy` : fournisseur honnête (enregistre tenant du `ctx`, route, requête ; rend `V`, modèle de la route, `spy-req-1`, `Usage{12, 5}` ou une erreur configurée ; inconnu : rétention exigée). `B3` : bedrock `eu-west-3` `eu.anthropic.claude-sonnet-4-20250514-v1:0`, `eu`, `zero`. `T` : `lookup`, schéma `{"type":"object","properties":{"name":{"type":"string"}},"required":["name"],"additionalProperties":false}`.
« Sans I/O » : erreur attendue (`errors.Is`), `Result{}`, outils `nil`, `Invocations()` 0, `Resolve` 0. « Sans appel » : idem, `Resolve` 1 admis.

| # | Test (fichier) | Assertions |
|---|---|---|
| 1 | `TestOutOfSchemaRejected` (client) | `K`, faux neuf par cas : `{"greeting":1}`, `{"greeting":"x","extra":1}`, `{}`, `not json`, vide : `ErrOutOfSchema`, `Result{}`, 1 appel. `V` : `Output` égal à l'octet. |
| 2 | `TestBoundedCorrection` (client) | `MaxCorrections` 1, `[{"greeting":"x","CANARY_OUT":1}, V]` : succès, `Attempts` 2, usage cumulé ; requête 2 = requête 1 plus un message `user` contenant `keyword`, sans `CANARY_OUT`. `MaxCorrections` 2 et 3, toujours invalide : `ErrOutOfSchema` après 3 et 4 appels exactement. |
| 3 | `TestTenantRequired` (client) | `context.Background()`, deux méthodes : sans I/O (`ErrNoTenant`). |
| 4 | `TestRedactionBeforeProvider` (client) | Texte `key AKIAIOSFODNN7EXAMPLE here`, bloc `{AKIAIOSFODNN7EXAMPLE, AWS_SECRET_ACCESS_KEY=...EXAMPLEKEY}` : requête capturée sans secret (`ContainsSecret` sur `Text`, `SourceID`, `Content`, `System`), `redact.Placeholder(redact.KindAWSAccessKey)` présent ; `Redactions` 3 ; entrée inchangée. |
| 5 | `TestUntrustedBlockRejectedWithTools` (client) | `WithTools`, bloc en `user`, en `assistant`, vide, avec partie invalide ; outils `[T]`, nil, vides : sans I/O (`ErrUntrustedWithTools`). `Structured` avec bloc : succès. |
| 6 | `TestTokenBudget` (client) | `MaxTokens` 257, 0, -1 : sans I/O (`ErrTokenBudget`) ; 256 : succès. |
| 7 | `TestNoRouteNoCall` (route) | Tenant C : `ErrNoRoute`, zéro appel, `Resolve` 1 ; résolveur rendant `errors.New("resolver down")` : `ErrNoRoute` et cause, message `domain.ErrNoRoute.Error()` ; politique zéro sans erreur : erreur de `domain`, zéro appel. |
| 8 | `TestRetentionZeroRejectsRetentionModel` (route) | `zero` avec `fake-model-retain`, puis modèle inconnu : sans appel (`ErrRetention`) ; `standard` et `fake-model-retain` : succès. |
| 9 | `TestModelMismatchRejected` (route) | Réponse `fake-model-v2`, `""`, `Fake-model-v1`, `MaxCorrections` 3 : `ErrModelMismatch`, `Result{}`, 1 appel. |
| 10 | `TestCrossTenantRouteIsolation` (route) | `spy`, A `fake-model-a`, B `fake-model-b`, 64 goroutines alternées : route reçue = route du tenant du `ctx` ; `Trace.Tenant`, `Trace.Model` exacts ; 32 appels par route. |
| 11 | `TestTraceCarriesRoute` (route) | `spy`, `AllowFakeRoute` faux, `B3` : trace exacte (dix champs, `H`, `spy-req-1`, `Attempts` 1, `Usage{12, 5}`) ; `RequestID` différent du `RequestHash` capturé ; `reflect` : exactement dix champs. |
| 12 | `TestServicePassesCheckedRoute` (route, T40) | Résolveur : `PA`, puis `fake-model-retain` `eu` `zero`. `MaxCorrections` 1, `[invalide, V]` : `Resolve` 1, deux `Calls()` de route `PA.Route` ; 2e appel du service : `ErrRetention`, zéro appel de plus. `spy`, `B3` : route reçue égale champ à champ. |
| 13 | `TestFakeRouteRefusedByDefault` (route, T41) | `Config{MaxTokensPerCall: 256}`, `PA`, deux méthodes : sans appel (`ErrFakeRouteRefused`) ; même config, `spy`, `B3` : succès ; `AllowFakeRoute` vrai, `PA` : succès. |
| 14 | `TestNewClientValidatesConfig` (client) | Fournisseur nil, résolveur nil, `MaxCorrections` -1 et 4, `MaxTokensPerCall` 0 et 65 537 : `ErrInvalidConfig`, client nil ; bornes acceptées ; `(*Client)(nil)` : `ErrInvalidConfig`. |
| 15 | `TestPromptPinnedAndClean` (client) | Hash vide, 64 zéros, `H` en majuscules : `ErrPromptMismatch` ; `test.unknown.v1` : `ErrUnknownPrompt` ; `Bad.ID` : `ErrInvalidPromptID` ; `test.leaky.v1` : `ErrSecretInPrompt` ; `promptFS` nil : `ErrUnknownPrompt` ; sans I/O. |
| 16 | `TestInvalidCallNoIO` (client) | Sans message, rôle `system`, partie vide, partie double : `ErrInvalidRequest` ou `ErrInvalidPart` ; texte de `1<<20 + 1`, deux parties de `600<<10`, `SourceID` 11 octets et `Content` `1<<20 - 10` : `ErrRequestTooLarge` ; sans I/O. `1<<20` : succès. |
| 17 | `TestWithToolsValidatesToolCalls` (client) | `ToolCalls [{lookup, {"name":"x"}}]` et `Output` `V` : appels égaux, `Output` nil. `MaxCorrections` 1, 2 pas, outil `other` : `ErrUnknownTool`, 1 appel ; `{"name":1}`, `MaxCorrections` 0 : `ErrOutOfSchema` ; appel d'outil dans `Structured` : `ErrUnknownTool`. Outils vides, nom `a b`, doublon, schéma sans `additionalProperties` : `ErrInvalidTools` ; description avec `ghp_FAKE...0000` : `ErrSecretInPrompt` ; sans I/O. |
| 18 | `TestContextRespected` (client) | Annulé, échu : sans I/O ; fournisseur qui délègue au faux puis annule, `MaxCorrections` 1, sortie invalide : `Canceled`, `Invocations()` 1. |
| 19 | `TestErrorsDoNotEchoInput` (client) | `CANARY` dans : texte à rôle invalide, `PromptID` `canary.v1`, erreur du résolveur, erreur du `spy` (`ErrProviderFailed` et cause par `errors.Is`), clé hors schéma, outil appelé inconnu : aucun message ne contient `canary` (casse ignorée) ; moins de 160 octets. |

## 7. Preuves avant gel
7.1 Rouge : `ls internal/llm/*.go | grep -v _test.go` : `internal/llm/doc.go` ; `go vet ./internal/llm 2>&1 | grep -E '\.go:[0-9]+:[0-9]+: ' | grep -vc 'undefined: '` : `0` ; `git add internal/llm/ && git status --porcelain | grep -vcE '^A  internal/llm/(helpers|client|route)_test\.go$'` : `0` ; `rempart-state phase impl` : `Phase : tests -> impl`.

7.2 Copie, obligatoire (`test-author`) : `cp -a . <scratchpad>/t11/r`, section 5 telle quelle ; `gofmt -l internal/llm` vide ; `golangci-lint run ./internal/llm/...` et `go test ./internal/llm/ -count=1 -race` : `rc=0` ; critères 1 à 9 ; M1 à M28. Écart : test corrigé s'il contredit la section 2, sinon amendement V1 en tête ; jamais de correction silencieuse.

## 8. Critères d'acceptation (racine)
| # | Commande | Attendu |
|---|---|---|
| 1 | `go test ./internal/llm/ -count=1 -v 2>&1 \| grep -cE '^--- PASS: (TestOutOfSchemaRejected\|TestBoundedCorrection\|TestTenantRequired\|TestRedactionBeforeProvider\|TestUntrustedBlockRejectedWithTools\|TestTokenBudget\|TestNoRouteNoCall\|TestRetentionZeroRejectsRetentionModel\|TestModelMismatchRejected\|TestCrossTenantRouteIsolation\|TestTraceCarriesRoute\|TestServicePassesCheckedRoute) '` | `12` |
| 1b | idem, `grep -cE '^--- PASS: Test'` ; `grep -cE -- '--- (FAIL\|SKIP)'` | `19` ; `0` |
| 2 | `go test ./internal/llm/... -count=1 -race; echo rc=$?` | `rc=0` |
| 3 | `go list -f '{{join .Imports " "}}' ./internal/llm \| sed 's#github.com/amezianechayer/rempart/##g'` | `bytes context encoding/json errors fmt internal/llm/domain internal/llm/ports internal/llm/prompts internal/llm/redact internal/llm/schema internal/tenancy io/fs regexp` |
| 4 | `grep -nE 'panic\(\|fmt\.Print\|func init\(\|os\.Getenv\|os\.LookupEnv\|"log' internal/llm/*.go \| grep -v _test.go \| wc -l` | `0` |
| 5 | `go test ./internal/archtest/ -count=1 -run TestRepositoryConforms; echo rc=$?` ; `go list -f '{{join .TestImports " "}}' ./internal/llm \| tr ' ' '\n' \| grep -c 'internal/llm/fake$'` | `rc=0` ; `1` |
| 6 | `grep -rl --include='*.go' --exclude='*_test.go' 'RequestHash(' internal cmd \| grep -vcE '^internal/llm/(domain\|fake)/'` | `0` |
| 7 | `grep -rnE '//[[:space:]]*(nolint\|#nosec)' --include='*.go' . \| wc -l` | `0` |
| 8 | `grep -rl --include='*.go' --exclude='*_test.go' 'AllowFakeRoute' internal cmd` | `internal/llm/client.go` |
| 9 | `make verify-quick; echo rc=$?` | `rc=0` |

## 9. Mutations sur copie
Script de `docs/plans/M0-tenancy.md` 8.3. `check.go` pour M4, M12, M18 à M20, M24, M27 ; `client.go` sinon. `OLD` présent une fois dans son fichier ; `go test ./internal/llm/ -count=1 2>&1 | grep -cE -- "--- FAIL: ($EXPECTED)"` au moins `1`, `EXPECTED` : test n de la section 6. « faux » : `if false {`.

| # | `OLD` | `NEW` | n |
|---|---|---|---|
| M1 | `if withTools && pre.HasUntrusted() {` | faux | 5 |
| M2 | `if err := pre.Validate(); err != nil {` | `if err := error(nil); err != nil {` | 16 |
| M3 | `if call.MaxTokens < 1 \|\| call.MaxTokens > c.cfg.MaxTokensPerCall {` | `if call.MaxTokens < 1 {` | 6 |
| M4 | `n += len(p.Text)` | vide | 16 |
| M5 | `if call.PromptHash != p.Hash {` | faux | 15 |
| M6 | `if redact.New().ContainsSecret(p.System) {` | faux | 15 |
| M7 | `if pol.Route.Platform == domain.PlatformFake && !c.cfg.AllowFakeRoute {` | faux | 13 |
| M8 | `c.provider.Capabilities(pol.Route)` | `domain.Capabilities{}` | 8 |
| M9 | `return pol.Route, nil` | `return domain.Route{Platform: pol.Route.Platform, Model: pol.Route.Model}, nil` | 12 |
| M10 | `return domain.Route{}, opaque(domain.ErrNoRoute, err)` | `return domain.Route{}, fmt.Errorf("%w: %w", domain.ErrNoRoute, err)` | 7 |
| M11 | `msgs, redactions := redactMessages(call.Messages)` | `msgs, redactions := call.Messages, 0` | 4 |
| M12 | `SourceID: red(p.Untrusted.SourceID)` | `SourceID: p.Untrusted.SourceID` | 4 |
| M13 | `if resp.Model != route.Model {` | `if resp.Model == "" {` | 9 |
| M14 | `if !errors.Is(verr, schema.ErrOutOfSchema) \|\| attempt >= c.cfg.MaxCorrections {` | `if attempt >= c.cfg.MaxCorrections {` | 17 |
| M15 | idem | `if !errors.Is(verr, schema.ErrOutOfSchema) \|\| attempt > c.cfg.MaxCorrections {` | 2 |
| M16 | `req.Messages = append(req.Messages, correction(verr))` | vide | 2 |
| M17 | `return Result{}, nil, opaque(ErrProviderFailed, err)` | `return Result{}, nil, fmt.Errorf("%w: %w", ErrProviderFailed, err)` | 19 |
| M18 | `if err := s.Validate(resp.Output); err != nil {` | `if err := error(nil); err != nil {` | 1 |
| M19 | `if err := ts.Validate(tc.Input); err != nil {` | idem M18 | 17 |
| M20 | `if !ok {` | faux | 17 |
| M21 | `if cerr := ctx.Err(); cerr != nil {` | `if cerr := error(nil); cerr != nil {` | 18 |
| M22 | `if err := ctx.Err(); err != nil {` | idem M2 | 18 |
| M23 | `tenant, err := tenancy.FromContext(ctx)` | `tenant, err := tenancy.FromContext(ctx); err = nil` | 3 |
| M24 | `if _, dup := out[t.Name]; dup {` | faux | 17 |
| M25 | `if cfg.MaxCorrections < 0 \|\| cfg.MaxCorrections > MaxCorrectionsLimit {` | `if cfg.MaxCorrections < 0 {` | 14 |
| M26 | `return []error{e.kind, e.cause}` | `return []error{e.kind}` | 19 |
| M27 | `n += len(p.Untrusted.SourceID) + len(p.Untrusted.Content)` | `n += len(p.Untrusted.Content)` | 16 |
| M28 | `if c == nil {` | faux | 14 |

## 10. Boucle de correction (gabarit `loop-engineering`, réduit)
Vérificateur déterministe (`schema.Validate`) ; signal : mot-clé et chemin, jamais la sortie ; correction par ajout, requête initiale conservée ; budget `1 + MaxCorrections` appels (4 au plus) et `MaxTokens` par appel ; stagnation sans objet ; trace `Attempts` et usage. Report à T13 : `ErrOutOfSchema`, `ErrModelMismatch`, `ErrFakeRouteRefused` et erreurs de politique non rejouables (`NonRetryableErrorTypes`).

## 11. Revue sécurité, risques, menaces
Revue : T40 (D1, test 12, M9) ; T41 (D2, test 13, M7, critère 8) ; T2 (S3, D7 : tests 5, 17, M1, M19, M20) ; T3 (test 10 sous `-race`, M23) ; T7 (D3, D4, D9 : test 4, M11, M12) ; T10 (S5, D8 : tests 2, 6, M3, M15). Verdict attendu : PASS.

Risques : rédacteur incomplet (réserves M0-T07, garde de `prompts/M1.md`) ; prompt recompilé à chaque appel (cache plus tard) ; réponse de plateforme sans modèle : l'adaptateur le lit ou échoue (T12 et suivantes) ; outils transmis tels quels (mutation concurrente hors contrat).

Menaces : aucune nouvelle. À proposer par `security-reviewer` pour `docs/02-THREAT-MODEL.md` : T40, `TestServicePassesCheckedRoute` ; T41, `TestFakeRouteRefusedByDefault` (part T20 ouverte) ; T7, `TestRedactionBeforeProvider`.

## 12. Tâches ordonnées (un seul tour après validation humaine)
| # | Tâche | Qui | Vérification |
|---|---|---|---|
| A0 | Entrée (section 4), `phase tests` | principal | `Phase : free -> tests` |
| A1 | `helpers_test.go` (fixtures, résolveurs, `spy`, fournisseur qui annule) | `test-author` | `undefined:` seulement |
| A2 | `client_test.go` (1 à 6, 14 à 19), `route_test.go` (7 à 13) | `test-author` | idem |
| A3 | Copie 7.2 | `test-author` | vert, 28 mutations détectées |
| A4 | Rouge, `git add`, `phase impl` (7.1) | principal | `Phase : tests -> impl` |
| I1 | `doc.go`, `client.go`, `check.go`, `make verify-quick` | principal | tests 1 à 19 ; critères 1 à 9 |
| F1 | M1 à M28 sur copie du dépôt final | principal | section 9 |
| F2 | `security-reviewer`, puis `acceptance-verifier` | subagents | PASS |
| F3 | `docs/STATUS.md` (obligations T40, T41 part service, M0-T07, M0-T08 soldées ; reports T13, T20, T12) ; `phase free` ; commit `feat(llm): llm.Client service with checked route, redaction and schema validation (M0-T11)` | principal | `git status` : `doc.go` modifié, 2 sources, 3 `_test.go`, `docs/STATUS.md` ; arbre propre après commit |
