# M0-T10 `llm-fake` : faux fournisseur déterministe et résolveur statique

2026-09-24, `architect`, proposé. Fiche `docs/plans/M0-overview.md` §7, écarts marqués en section 2. Aucun ADR : double de test réversible sous l'ADR 0002.

## 0. Amendement V1 (phase tests, 2026-09-24, prime sur le reste du document)

- Code de référence vérifié sur copie par `test-author` avant gel : 16 tests verts sous `-race`, 18 mutations détectées, aucun défaut de comportement. Seul écart : `resolver.go` n'était pas au format gofumpt ; la structure `StaticResolver` s'écrit sur plusieurs lignes (`type StaticResolver struct {` / `policies map[tenancy.ID]domain.TenantPolicy` / `}`). Aucun changement de sémantique.
- Constat hors périmètre, noté pour une tâche ultérieure : `LoadOptions` ignore sans erreur un script vide (`"id": []`).

---

## 1. Objectif et périmètre
Faux `ports.ModelProvider` sans réseau, déterministe à l'octet, en échec fermé, et `ports.RouteResolver` statique sans défaut : socle des tests de T11 et de la démo. Dans : `internal/llm/fake/{provider,options,resolver}.go`, tests, `testdata/scripted.json`, `docs/STATUS.md`. Hors : tests du critère 7 de `prompts/M0.md` (service, T11 ; ici leurs prérequis), `TestProviderContract` (T12), tout importeur (T20).

## 2. Décisions
| # | Décision |
|---|---|
| D1 | **Enregistrement** : clé (`PromptID`, `domain.RequestHash(req)`), prioritaire, indépendant du rang et du type d'appel. **Script** : séquence par `PromptID`, un curseur chacun, consommée sans enregistrement correspondant. |
| D2 | Sinon `ErrNoRecording` ; script épuisé : `ErrScriptExhausted` ; `Err` scripté : `ErrScripted`. Toute erreur rend `domain.Response{}` : jamais de réponse par défaut. |
| D3 | Ordre : 1. `invocations++` ; 2. `ctx.Err()` ; 3. route `fake` sans région, sinon `domain.ErrInvalidRoute` ; 4. `WithTools` : `HasUntrusted()` donne `domain.ErrUntrustedWithTools`, avant `Validate`, outils nil ou vides compris ; 5. `req.Validate()` ; 6. capture (« I/O » du faux) ; 7. recherche. Refus en 2 à 5 : rien capturé, curseurs intacts. |
| D4 | `Invocations()` compte toute entrée, refus compris : un appel fautif reste visible (« zéro appel » de T11). `Calls()`, `Requests()` : appels capturés, copies profondes. |
| D5 | Sûr en concurrence (un mutex) ; script concurrent : chaque pas servi une fois, ordre libre. Ni horloge, ni aléa, ni map itérée pour répondre ; options et réponses copiées en profondeur. |
| D6 | `Response.Model` et `RequestID` viennent du script, vides compris ; jamais de la route ni du hash. |
| D7 | Écart : `Options.Models map[string]domain.Capabilities` ; route `fake` sans région et modèle connu : sa valeur, sinon `{RequiresRetention: true}`. |
| D8 | Écart : `New(opt) (*Provider, error)` refuse `PromptID` vide, hash hors `^[0-9a-f]{64}$`, doublon, `Err` avec réponse non zéro, script ou clé vide, modèle vide. |
| D9 | `LoadOptions` (démo, evals) : scripts et modèles seulement (un hash figé en fichier casse à chaque changement de prompt ; enregistrements en Go). 1 Mio, `snake_case`, champs inconnus et données finales refusés, `"version": 1`, `requires_retention` obligatoire, `output` brut (non JSON exprimable). |
| D10 | Écart : `NewStaticResolver(map)` vérifie les clés (`tenancy.ParseID`), copie la map. `Resolve` : `ctx.Err()` ; tenant invalide : `ErrNoRoute` et `tenancy.ErrInvalidTenant` ; nil ou absent : `ErrNoRoute` ; sinon la politique telle quelle (`CheckPolicy` par le service). |
| D11 | Messages fixes : ni `PromptID`, hash, contenu, route, tenant ni chemin. |

## 3. Obligations de `docs/STATUS.md`
- T10 : `Validate` avant I/O et `ctx` (tests 10, 11) ; aucune journalisation (critère 3) ; erreurs sans entrée (test 14) ; `Response.Model` du script (test 15) ; `RequestHash` sans autre appelant (critère 6) ; route reçue exposée (T40) ; T41 : R5 (critère 5), ni `init`, ni état global, ni environnement.
- T11 : trace sans contenu, comparaison des modèles, `RequestHash` hors `Trace` et `RequestID`, `TestServicePassesCheckedRoute`, route `fake` refusée sauf option explicite de `Config` (testé). T12 : mêmes gardes dans l'adaptateur. T20 : seul `-dev` câble le faux, configuration de production testée.

## 4. Harnais (non patché)
Entrée : `phase free`, `verify-quick` vert, arbre propre, `internal/llm/fake` absent. Un seul tour de `phase tests` au premier `verify-quick` vert en impl. Tests en `package fake` ; `go vet` : seuls `undefined:` et `no non-test Go files`. `git add internal/llm/fake/` avant `phase impl`. `testdata/` écrit en phase tests, neutre.

## 5. Code de référence (normatif ; ancres de la section 9 au caractère près)

`provider.go` :
```go
// Package fake is the deterministic offline model provider and static route
// resolver of ADR 0002: tests and the -dev composition root only (R5, T41).
package fake

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/llm/ports"
)

var (
	ErrNoRecording     = errors.New("fake: no recording for request")
	ErrScriptExhausted = errors.New("fake: script exhausted")
	ErrScripted        = errors.New("fake: scripted provider error")
	ErrInvalidOptions  = errors.New("fake: invalid options")
)

var _ ports.ModelProvider = (*Provider)(nil)

// Step is one answer. A non-empty Err yields ErrScripted; Response must be zero.
type Step struct {
	Response domain.Response
	Err      string
}

// Recording answers one exact request. RequestHash is a lookup key, never an evidence identity.
type Recording struct {
	PromptID, RequestHash string
	Step
}

type Options struct {
	Recordings []Recording
	Scripts    map[string][]Step              // by PromptID, consumed in order
	Models     map[string]domain.Capabilities // any other route requires retention
}

type Call struct {
	WithTools bool
	Route     domain.Route
	Request   domain.Request
	Tools     []domain.ToolSpec
}

type recKey struct{ promptID, hash string }

type Provider struct {
	mu          sync.Mutex
	recordings  map[recKey]Step
	scripts     map[string][]Step
	cursors     map[string]int
	models      map[string]domain.Capabilities
	invocations int
	calls       []Call
}

func New(opt Options) (*Provider, error) {
	p := &Provider{
		recordings: map[recKey]Step{}, scripts: map[string][]Step{},
		cursors: map[string]int{}, models: map[string]domain.Capabilities{},
	}
	for _, r := range opt.Recordings {
		if r.PromptID == "" || !isHash(r.RequestHash) || !validStep(r.Step) {
			return nil, fmt.Errorf("%w: malformed recording", ErrInvalidOptions)
		}
		k := recKey{r.PromptID, r.RequestHash}
		if _, dup := p.recordings[k]; dup {
			return nil, fmt.Errorf("%w: duplicate recording", ErrInvalidOptions)
		}
		p.recordings[k] = cloneStep(r.Step)
	}
	for id, steps := range opt.Scripts {
		if id == "" || len(steps) == 0 {
			return nil, fmt.Errorf("%w: empty script", ErrInvalidOptions)
		}
		for _, s := range steps {
			if !validStep(s) {
				return nil, fmt.Errorf("%w: malformed step", ErrInvalidOptions)
			}
			p.scripts[id] = append(p.scripts[id], cloneStep(s))
		}
	}
	for m, c := range opt.Models {
		if m == "" {
			return nil, fmt.Errorf("%w: empty model", ErrInvalidOptions)
		}
		p.models[m] = c
	}
	return p, nil
}

func (p *Provider) Structured(ctx context.Context, route domain.Route, req domain.Request) (domain.Response, error) {
	return p.call(ctx, false, route, req, nil)
}

func (p *Provider) WithTools(ctx context.Context, route domain.Route, req domain.Request, tools []domain.ToolSpec) (domain.Response, error) {
	return p.call(ctx, true, route, req, tools)
}

func (p *Provider) call(ctx context.Context, withTools bool, route domain.Route, req domain.Request, tools []domain.ToolSpec) (domain.Response, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.invocations++
	if err := ctx.Err(); err != nil {
		return domain.Response{}, err
	}
	if route.Platform != domain.PlatformFake || route.Region != "" {
		return domain.Response{}, fmt.Errorf("%w: not a fake route", domain.ErrInvalidRoute)
	}
	if withTools && req.HasUntrusted() {
		return domain.Response{}, domain.ErrUntrustedWithTools
	}
	if err := req.Validate(); err != nil {
		return domain.Response{}, err
	}
	p.calls = append(p.calls, Call{withTools, route, cloneRequest(req), cloneTools(tools)})
	step, err := p.lookup(req)
	if err != nil {
		return domain.Response{}, err
	}
	if step.Err != "" {
		return domain.Response{}, ErrScripted
	}
	return cloneResponse(step.Response), nil
}

func (p *Provider) lookup(req domain.Request) (Step, error) {
	if s, ok := p.recordings[recKey{req.PromptID, domain.RequestHash(req)}]; ok {
		return s, nil
	}
	steps, ok := p.scripts[req.PromptID]
	if !ok {
		return Step{}, ErrNoRecording
	}
	i := p.cursors[req.PromptID]
	if i >= len(steps) {
		return Step{}, ErrScriptExhausted
	}
	p.cursors[req.PromptID] = i + 1
	return steps[i], nil
}

func (p *Provider) Capabilities(route domain.Route) domain.Capabilities {
	if route.Platform == domain.PlatformFake && route.Region == "" {
		if c, ok := p.models[route.Model]; ok {
			return c
		}
	}
	return domain.Capabilities{RequiresRetention: true}
}

// Invocations counts every Structured and WithTools call, refused ones included.
func (p *Provider) Invocations() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.invocations
}

func (p *Provider) Calls() []Call {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Call, 0, len(p.calls))
	for _, c := range p.calls {
		out = append(out, Call{c.WithTools, c.Route, cloneRequest(c.Request), cloneTools(c.Tools)})
	}
	return out
}

func (p *Provider) Requests() []domain.Request {
	calls := p.Calls()
	out := make([]domain.Request, len(calls))
	for i, c := range calls {
		out[i] = c.Request
	}
	return out
}

func isHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := range len(s) {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validStep(s Step) bool {
	r := s.Response
	zero := len(r.Output) == 0 && len(r.ToolCalls) == 0 && r.Usage == (domain.Usage{}) && r.Model == "" && r.RequestID == ""
	return s.Err == "" || zero
}

func cloneStep(s Step) Step { return Step{cloneResponse(s.Response), s.Err} }

func cloneResponse(r domain.Response) domain.Response {
	r.Output = bytes.Clone(r.Output)
	if r.ToolCalls != nil {
		tc := make([]domain.ToolCall, len(r.ToolCalls))
		for i, c := range r.ToolCalls {
			tc[i] = domain.ToolCall{Name: c.Name, Input: bytes.Clone(c.Input)}
		}
		r.ToolCalls = tc
	}
	return r
}

func cloneRequest(r domain.Request) domain.Request {
	r.Schema = bytes.Clone(r.Schema)
	if r.Messages != nil {
		msgs := make([]domain.Message, len(r.Messages))
		for i, m := range r.Messages {
			msgs[i].Role = m.Role
			if m.Parts != nil {
				msgs[i].Parts = make([]domain.Part, len(m.Parts))
			}
			for j, pt := range m.Parts {
				msgs[i].Parts[j].Text = pt.Text
				if pt.Untrusted != nil {
					b := *pt.Untrusted
					msgs[i].Parts[j].Untrusted = &b
				}
			}
		}
		r.Messages = msgs
	}
	return r
}

func cloneTools(ts []domain.ToolSpec) []domain.ToolSpec {
	if ts == nil {
		return nil
	}
	out := make([]domain.ToolSpec, len(ts))
	for i, t := range ts {
		out[i] = domain.ToolSpec{Name: t.Name, Description: t.Description, InputSchema: bytes.Clone(t.InputSchema)}
	}
	return out
}
```

`options.go` :
```go
package fake

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/amezianechayer/rempart/internal/llm/domain"
)

const maxOptionsBytes = 1 << 20

type fileStep struct {
	Response struct {
		Output    string `json:"output"`
		Model     string `json:"model"`
		RequestID string `json:"request_id"`
	} `json:"response"`
	Err string `json:"err"`
}

type fileOptions struct {
	Version int                   `json:"version"`
	Scripts map[string][]fileStep `json:"scripts"`
	Models  map[string]struct {
		NativeStructuredOutput bool  `json:"native_structured_output"`
		StrictTools            bool  `json:"strict_tools"`
		RequiresRetention      *bool `json:"requires_retention"`
	} `json:"models"`
}

// LoadOptions reads a version 1 file; New checks the result again.
func LoadOptions(fsys fs.FS, path string) (Options, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return Options{}, fmt.Errorf("%w: cannot open file", ErrInvalidOptions)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxOptionsBytes+1))
	if err != nil || len(raw) > maxOptionsBytes {
		return Options{}, fmt.Errorf("%w: unreadable or too large", ErrInvalidOptions)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var fo fileOptions
	if err := dec.Decode(&fo); err != nil {
		return Options{}, fmt.Errorf("%w: malformed document or unknown field", ErrInvalidOptions)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Options{}, fmt.Errorf("%w: data after the document", ErrInvalidOptions)
	}
	if fo.Version != 1 {
		return Options{}, fmt.Errorf("%w: unsupported version", ErrInvalidOptions)
	}
	opt := Options{Scripts: map[string][]Step{}, Models: map[string]domain.Capabilities{}}
	for id, steps := range fo.Scripts {
		for _, s := range steps {
			st := Step{Response: domain.Response{Model: s.Response.Model, RequestID: s.Response.RequestID}, Err: s.Err}
			if s.Response.Output != "" {
				st.Response.Output = []byte(s.Response.Output)
			}
			opt.Scripts[id] = append(opt.Scripts[id], st)
		}
	}
	for m, c := range fo.Models {
		if c.RequiresRetention == nil {
			return Options{}, fmt.Errorf("%w: requires_retention is mandatory", ErrInvalidOptions)
		}
		opt.Models[m] = domain.Capabilities{NativeStructuredOutput: c.NativeStructuredOutput, StrictTools: c.StrictTools, RequiresRetention: *c.RequiresRetention}
	}
	return opt, nil
}
```

`resolver.go` :
```go
package fake

import (
	"context"
	"fmt"

	"github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/llm/ports"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

var _ ports.RouteResolver = (*StaticResolver)(nil)

// StaticResolver has no default route; the caller runs CheckPolicy on the result.
type StaticResolver struct{ policies map[tenancy.ID]domain.TenantPolicy }

func NewStaticResolver(policies map[tenancy.ID]domain.TenantPolicy) (*StaticResolver, error) {
	cp := make(map[tenancy.ID]domain.TenantPolicy, len(policies))
	for id, pol := range policies {
		if _, err := tenancy.ParseID(string(id)); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidOptions, err)
		}
		cp[id] = pol
	}
	return &StaticResolver{policies: cp}, nil
}

func (r *StaticResolver) Resolve(ctx context.Context, tenant tenancy.ID) (domain.TenantPolicy, error) {
	if err := ctx.Err(); err != nil {
		return domain.TenantPolicy{}, err
	}
	if _, err := tenancy.ParseID(string(tenant)); err != nil {
		return domain.TenantPolicy{}, fmt.Errorf("%w: %w", domain.ErrNoRoute, err)
	}
	if r == nil {
		return domain.TenantPolicy{}, domain.ErrNoRoute
	}
	pol, ok := r.policies[tenant]
	if !ok {
		return domain.TenantPolicy{}, fmt.Errorf("%w: tenant not configured", domain.ErrNoRoute)
	}
	return pol, nil
}
```
`ctx` nil : hors contrat.

`testdata/scripted.json` (exact) :
```json
{
  "version": 1,
  "scripts": {
    "demo.greeting.v1": [
      {"response": {"output": "{\"greeting\":\"bonjour\"}", "model": "fake-model-v1", "request_id": "fake-req-1"}},
      {"err": "provider_unavailable"}
    ]
  },
  "models": {"fake-model-v1": {"native_structured_output": true, "strict_tools": true, "requires_retention": false}}
}
```

## 6. Tests (`test-author`, `package fake`)
`Q` : `PromptID` `demo.greeting.v1`, un message `user`, `Text: "hello"`, `Schema` `{"type":"object"}`, `MaxTokens` 256. `U` : `Q` plus `Untrusted{"r-7f3a", "CANARY"}`. `W` : `Output` `{"greeting":"bonjour"}`, `Model` `fake-model-v1`, `RequestID` `fake-req-1`, `Usage{12, 5}`. Route `fake`, `""`, `fake-model-v1` sauf mention ; hash par `domain.RequestHash`. « Refusé » : erreur attendue (`errors.Is`), `Invocations()` +1, rien capturé, curseur intact.

| # | Test | Assertions |
|---|---|---|
| 1 | `TestFakeDeterministic` | Enregistrement (`Q`, `W`) ; 3 appels sur `p1`, 1 sur `p2` (même `opt`), 1 avec copie profonde de `Q`, 1 par `WithTools` : `reflect.DeepEqual` à `W`, `bytes.Equal` des `Output` ; muter la 1re réponse puis `opt` : suivantes inchangées. |
| 2 | `TestFakeNoRecordingIsError` | Sans options, `Text: "hellO"`, autre `PromptID` : `ErrNoRecording`, réponse zéro, requête capturée. |
| 3 | `TestFakeScriptOrderAndExhaustion` | `[A, Err:"x", B]` : `A`, `ErrScripted`, `B`, deux fois `ErrScriptExhausted` ; curseurs indépendants ; enregistrement exact sans avance du curseur. |
| 4 | `TestFakeWithToolsRefusesUntrusted` | `U`, bloc en message `assistant`, partie texte et bloc, bloc vide ; outils nil, vides, un : refusé (`ErrUntrustedWithTools`) ; `Structured(U)` accepté. |
| 5 | `TestFakeCapturesRequestsCopy` | Muter l'original (`Text`, `Untrusted.Content`, `Schema[0]`, `Role`) et une tranche rendue : `Requests()` inchangé ; `Calls()[0]` : `WithTools`, `Route`, `Tools` exacts et copiés. |
| 6 | `TestLoadOptionsRejectsUnknownFields` | `scripted.json` : `New` réussit, 2 pas, modèle exact. `fstest.MapFS`, `ErrInvalidOptions` : champ inconnu (racine, `response`, modèle, `recordings`), données finales, `version` 0, 2 ou absente, non JSON, `requires_retention` absent, fichier absent, `{"version":1}` et espaces jusqu'à `1<<20 + 1` octets. |
| 7 | `TestStaticResolverUnknownTenant` | Absent, map nil, récepteur nil : `ErrNoRoute`, politique zéro ; `""`, UUID majuscule : `ErrNoRoute` et `tenancy.ErrInvalidTenant` ; A et B : chacun la sienne ; map source mutée : sans effet ; `ctx` annulé : `Canceled`. |
| 8 | `TestNewStaticResolverValidatesKeys` | `tenant-a`, `""`, UUID nul : `ErrInvalidOptions` et `tenancy.ErrInvalidTenant` ; `tenancy.System` accepté. |
| 9 | `TestFakeRefusesForeignRoute` | anthropic, bedrock `eu-west-3`, plateforme vide, `fake` région `local`, deux méthodes : refusé (`ErrInvalidRoute`). |
| 10 | `TestFakeValidatesRequest` | Sans message, rôle `system`, message vide, partie vide : refusé (`ErrInvalidRequest`, `ErrInvalidPart`). |
| 11 | `TestFakeHonorsContext` | Annulé, échu, annulé avec route étrangère : refusé (`Canceled`, `DeadlineExceeded`, `Canceled`). |
| 12 | `TestFakeCapabilities` | Modèle connu : valeur exacte ; inconnu, `Models` nil, même modèle sur anthropic, `fake` avec région : `{RequiresRetention: true}`. |
| 13 | `TestNewValidatesOptions` | Hash de 63 caractères, majuscule ; `PromptID` vide ; doublon ; `Err` avec `Output` ou `Model` ; script vide ; clé vide ; modèle vide : `ErrInvalidOptions`. |
| 14 | `TestFakeErrorsDoNotEchoInput` | `CANARY` dans `PromptID`, texte, bloc, route, `Err`, chemin, champ inconnu, tenant : aucun message ne contient `canary` (casse ignorée) ni le hash ; moins de 128 octets. |
| 15 | `TestFakeResponseModelFromScript` | Script `fake-model-v2` sur route `fake-model-v1` : `v2` ; sans modèle ni `RequestID` : `""`. |
| 16 | `TestFakeConcurrentUse` | 16 goroutines de 50 appels : toutes égales à `W` ; 100 appels concurrents sur un script de 100 pas (`s-000` à `s-099`) : chacun vu une fois, puis `ErrScriptExhausted` ; `Invocations()` exact. |

## 7. Preuves avant gel
7.1 Rouge : `find internal/llm/fake -name '*.go' ! -name '*_test.go' | wc -l` : `0` ; `go vet ./internal/llm/fake 2>&1 | grep -E '\.go:[0-9]+:[0-9]+: ' | grep -vc 'undefined: '` : `0` ; `git add internal/llm/fake/ && git status --porcelain | grep -vcE '^A  internal/llm/fake/([a-z]+_test\.go|testdata/scripted\.json)$'` : `0` ; `rempart-state phase impl` : `Phase : tests -> impl`.

7.2 Copie, obligatoire (`test-author`) : `cp -a . <scratchpad>/t10/r`, section 5 telle quelle ; `gofmt -l` vide ; `golangci-lint run ./internal/llm/fake/...` et `go test ./internal/llm/fake/ -count=1 -race` : `rc=0` ; critères 1 à 6 ; M1 à M18. Écart : test corrigé s'il contredit la section 2, sinon amendement ; jamais de correction silencieuse du code.

## 8. Critères d'acceptation (racine)
| # | Commande | Attendu |
|---|---|---|
| 1 | `go test ./internal/llm/fake/ -count=1 -v 2>&1 \| grep -cE '^--- PASS: (TestFakeDeterministic\|TestFakeNoRecordingIsError\|TestFakeScriptOrderAndExhaustion\|TestFakeWithToolsRefusesUntrusted\|TestFakeCapturesRequestsCopy\|TestLoadOptionsRejectsUnknownFields\|TestStaticResolverUnknownTenant) '` | `7` |
| 1b | idem, `grep -cE '^--- PASS: Test'` ; `grep -cE -- '--- (FAIL\|SKIP)'` | `16` ; `0` |
| 2 | `go test ./internal/llm/fake/ -count=1 -race; echo rc=$?` | `rc=0` |
| 3 | `go list -f '{{join .Imports " "}}' ./internal/llm/fake \| sed 's#github.com/amezianechayer/rempart/##g'` | `bytes context encoding/json errors fmt internal/llm/domain internal/llm/ports internal/tenancy io io/fs sync` |
| 4 | `grep -rnE 'panic\(\|fmt\.Print\|func init\(' --include='*.go' --exclude='*_test.go' internal/llm/fake \| wc -l` | `0` |
| 5 | `go test ./internal/archtest/ -count=1 -run TestRepositoryConforms; echo rc=$?` ; `go list -f '{{.ImportPath}}: {{join .Imports " "}}' ./... \| grep -F 'internal/llm/fake' \| grep -vc '^github.com/amezianechayer/rempart/internal/llm/fake:'` | `rc=0` ; `0` |
| 6 | `grep -rl --include='*.go' --exclude='*_test.go' 'RequestHash(' internal cmd \| grep -vcE '^internal/llm/(domain\|fake)/'` | `0` |
| 7 | `ls internal/llm/fake/testdata` ; `grep -rnE '//[[:space:]]*(nolint\|#nosec)' --include='*.go' . \| wc -l` | `scripted.json` ; `0` |
| 8 | `make verify-quick; echo rc=$?` | `rc=0` |
| 9 | `git status --porcelain` avant commit | 7 fichiers sous `internal/llm/fake/`, `docs/STATUS.md` |

## 9. Mutations sur copie
Script de `docs/plans/M0-tenancy.md` 8.3 ; fichier `provider.go` sauf M16 (`options.go`), M17 et M18 (`resolver.go`) ; `OLD` présent une fois ; `go test ./internal/llm/fake/ -count=1 2>&1 | grep -cE -- "--- FAIL: ($EXPECTED)"` au moins `1`, `EXPECTED` étant le test n de la section 6.

| # | `OLD` | `NEW` | n |
|---|---|---|---|
| M1 | `if withTools && req.HasUntrusted() {` | `if false {` | 4 |
| M2 | idem | `if withTools && req.HasUntrusted() && req.Validate() == nil {` | 4 |
| M3 | `if route.Platform != domain.PlatformFake \|\| route.Region != "" {` | `if route.Region != "" {` | 9 |
| M4 | idem | `if route.Platform != domain.PlatformFake {` | 9 |
| M5 | `if err := req.Validate(); err != nil {` | `if err := error(nil); err != nil {` | 10 |
| M6 | `if err := ctx.Err(); err != nil {` | idem M5 | 11 |
| M7 | `p.invocations++` | vide | 4 ou 9 |
| M8 | `Call{withTools, route, cloneRequest(req), cloneTools(tools)}` | `Call{withTools, route, req, tools}` | 5 |
| M9 | `cloneRequest(c.Request), cloneTools(c.Tools)}` | `c.Request, c.Tools}` | 5 |
| M10 | `return cloneResponse(step.Response), nil` | `return step.Response, nil` | 1 |
| M11 | `p.recordings[k] = cloneStep(r.Step)` | `p.recordings[k] = r.Step` | 1 |
| M12 | `p.cursors[req.PromptID] = i + 1` | `p.cursors[req.PromptID] = i` | 3 |
| M13 | `return Step{}, ErrNoRecording` | `return Step{Response: domain.Response{Output: []byte("{}")}}, nil` | 2 |
| M14 | `return domain.Capabilities{RequiresRetention: true}` | `return domain.Capabilities{}` | 12 |
| M15 | `if _, dup := p.recordings[k]; dup {` | `if false {` | 13 |
| M16 | `dec.DisallowUnknownFields()` | vide | 6 |
| M17 | `return domain.TenantPolicy{}, fmt.Errorf("%w: tenant not configured", domain.ErrNoRoute)` | `return domain.TenantPolicy{}, nil` | 7 |
| M18 | `return &StaticResolver{policies: cp}, nil` | `return &StaticResolver{policies: policies}, nil` | 7 |

## 10. Revue sécurité (légère), risques, menaces
Revue : pas de réponse par défaut, messages sans entrée (2, 14, M13) ; bloc non fiable refusé avant capture (4, M1, M2) ; route étrangère et `Capabilities` inconnue en échec fermé (9, 12, M3, M4, M14) ; compteur et copies (1, 5, M7 à M11) ; résolveur sans défaut (7, 8, M17, M18) ; confinement T41 (critères 3 à 6). Verdict attendu : PASS.

Risques : faux trop permissif masquant un défaut de T11 (gardes fermées, refus comptés, route capturée) ; faux câblé en production (R5, T11, T20) ; enregistrement insensible aux outils (T11 teste les outils par scripts) ; code de référence défectueux (7.2).

Menaces : aucune nouvelle ; proposer d'ajouter aux vérifications T41 le critère 5 et le test 12, T2 le test 4, T3 le test 7, T40 la route capturée. Boucle : sans objet.

## 11. Tâches ordonnées (un seul tour après validation humaine)
| # | Tâche | Qui | Vérification |
|---|---|---|---|
| A0 | Entrée, `phase tests` | principal | `Phase : free -> tests` |
| A1 | `scripted.json`, `provider_test.go` (1 à 5, 9 à 16) | `test-author` | `undefined:` seulement |
| A2 | `options_test.go` (6), `resolver_test.go` (7, 8) | `test-author` | idem |
| A3 | Copie 7.2 | `test-author` | vert, 18 mutations détectées |
| A4 | Rouge, `git add`, `phase impl` (7.1) | principal | `Phase : tests -> impl` |
| I1 | `provider.go` | principal | tests 1 à 5, 9 à 16 |
| I2 | `options.go`, `resolver.go`, `make verify-quick` | principal | tests 6 à 8 ; critères 1 à 8 |
| F1 | M1 à M18 sur copie du dépôt final | principal | section 9 |
| F2 | `security-reviewer`, puis `acceptance-verifier` | subagents | PASS |
| F3 | `docs/STATUS.md` (reports de la section 3) ; `phase free` ; commit `feat(llm): deterministic fake provider and static route resolver (M0-T10)` | principal | arbre propre |
