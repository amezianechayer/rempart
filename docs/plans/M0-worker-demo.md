# M0-T20 `worker-e2e` : obligations (at) à (ax), puis worker et `make demo`

2026-09-27, `architect`, proposé. Cadrage : `M0-overview.md` 0 (A1), 0 bis, fiche M0-T20, 5.3, 5.5 ; `M0-demo-workflow.md` ; `docs/STATUS.md`. Revue sécurité : oui.

## 1. Périmètre

- **A** : (at), (au), (aw), (ax) ; imports de dossiers ignorés (décision 7 de M0-T19d) ; (av), (af) ; règle `anthropic-unwired-m0`.
- **B** (fiche selon A1) : `loops.NewWorkflowID`, (c), `cmd/rempart-worker`, `make demo`, intégration contre `make dev` ; convertisseur par défaut, ni Transit ni `TestHistoryHasNoPlaintext`.
- Hors T20 : conditions de la revue M0-T12 et (aa) à (ad) : **M0-T20b** `llm-adapter-harden`, terminée avant B ; (an) à (as) : **M0-T03b** `pile-dev-harden`, après T20, avant `/close-milestone M0` ; (ag) : M1 ; (ah), (q), `Author` authentifié : M4.

## 2. Décisions (sens le plus strict)

| # | Décision |
|---|---|
| D1 | `LoadConfig(args []string)` : ni environnement, ni secret ; `BaoAddr`, `BaoToken`, `AnthropicKey` retirés jusqu'en M1 (A1, T36). |
| D2 | Drapeaux obligatoires sans défaut ; répétition et positionnel refusés ; erreurs à message fixe. |
| D3 | `-llm=fake` seul, exige `-dev` (T41), revérifié par `run` avant toute I/O ; `-demo-once` obligatoire. |
| D5 | Temporal : IP de bouclage littérale (sans TLS, T18) ; script `fs.ValidPath`, `.json`, sous `os.OpenRoot(".")`. |
| D6 | `-tenant` : `ParseID`, `System` refusé (T34, T75) ; tenant de démo littéral dans la recette. |
| D7 | File de tâches propre au processus `rempart-demo-<uuid>` (T79). |
| D8 | `denyAll` dans `cmd` (issue `timed_out`) ; `internal/loops/fake` réservé aux tests. |
| D9 | `Register` refuse `a.LLM` nil, tenant invalide ou `System` ; nil typé indétectable sans `reflect` : échec fermé testé. |
| D10 | (av) `llm.UsageError{Err, Usage, Bound}` après tout appel ; `Bound` = usage déclaré + `MaxTokens + RequestBytes` par appel sans usage. |
| D11 | (af) seul `ErrOutOfSchema` est repris par `RunLoop` ; 429 et autres : `activity_failed` (attente bornée : adaptateur, T50). |
| D12 | (at) `loops-keyed-literals` : littéral sans clé admis seulement de type explicite tableau, tranche ou table ; type élidé traité comme structure. |
| D13 | (au) noms de décodage et `decodeTargets` sur tout paquet sous `internal/loops` hors `fake`. |
| D14 | (aw) `reflect`, `unsafe`, `C`, `//go:linkname`, source non Go refusés sous `internal/loops`. |
| D15 | (ax) attributs de recherche et mémo interdits ; `GOFLAGS` neutralisé ; T78 figé par test. |
| D16 | (c) `demo.ExecutionTimeout(a)` = `Spec().MaxRunDuration() + a + VerifyApprovalTimeout + CommitTimeout + 30 s` : 228 s pour 5 s. |

## 3. Étape A : code de référence (indentation par espaces ; gofumpt rétablit les tabulations)

### 3.1 `internal/archtest`

`loopsrc.go`, `ReadSources`, après le cas `moduleFile` :
```go
    case !d.IsDir() && strings.HasPrefix(p, "internal/loops/") && slices.Contains(foreignSources, path.Ext(p)): // (aw)
      return fmt.Errorf("archtest: %s: non-Go source under internal/loops (T73)", p)
```
```go
var foreignSources = []string{".s", ".S", ".sx", ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".m", ".f", ".F", ".for", ".f90", ".syso", ".swig", ".swigcxx"}

var searchNames = []string{"GetTypedSearchAttributes", "UpsertTypedSearchAttributes", "UpsertSearchAttributes", "SearchAttributes", "TypedSearchAttributes", "UpsertMemo", "Memo"}

func ignoredElem(e string) bool { return e != "" && (e[0] == '_' || e[0] == '.' || e == "testdata") }

func unkeyed(lit *ast.CompositeLit) bool {
  return slices.ContainsFunc(lit.Elts, func(e ast.Expr) bool { _, kv := e.(*ast.KeyValueExpr); return !kv })
}
```
`decodingNames` gagne `"GetHeartbeatDetails"` ; `decodeTargets` : `case "GetLastCompletionResult":` devient `case "GetLastCompletionResult", "GetHeartbeatDetails":`. `file`, en tête : `inLoops := under(sf.Pkg, c.loops)`, `dec := inLoops && !under(sf.Pkg, fake) // (au)`. Boucle des imports, après `loops-fake-tests-only` :
```go
    if under(p, c.module) && slices.ContainsFunc(strings.Split(p, "/"), ignoredElem) { // T73
      c.add(sf, is, "no-ignored-dir-import", "import "+p)
    }
    if inLoops && slices.Contains([]string{"reflect", "unsafe", "C"}, p) { // (aw)
      c.add(sf, is, "loops-no-reflection", "import "+p)
    }
```
Après cette boucle :
```go
  for _, cg := range sf.File.Comments { // (aw)
    for _, cm := range cg.List {
      if inLoops && strings.HasPrefix(cm.Text, "//go:linkname") {
        c.add(sf, cm, "loops-no-reflection", "go:linkname directive")
      }
    }
  }
```
`walk` : `case wf && !called && slices.Contains(decodingNames, n.Sel.Name):` devient `case dec && !called && ...` ; après le cas `Validator`, `case wf && slices.Contains(searchNames, n.Sel.Name):` et `c.add(sf, n, "loops-no-search-attributes", n.Sel.Name)` ; cas `*ast.CallExpr` : `if wf {` devient `if dec {` ; nouveau cas :
```go
    case *ast.CompositeLit:
      switch n.Type.(type) {
      case *ast.ArrayType, *ast.MapType: // an elided type counts as a struct (D12)
      default:
        if wf && unkeyed(n) { // (at)
          c.add(sf, n, "loops-keyed-literals", "composite literal element without field name")
        }
      }
```
`rules.go`, fin de `DefaultRules` : `{Name: "anthropic-unwired-m0", Kind: Confine, Targets: []string{m("internal/llm/adapters/anthropic/...")}}`, levée seulement après M0-T20b.

### 3.2 `internal/loops/runloop.go` (aw)

Import `reflect` retiré ; même sémantique (types exacts ; `any(...)` pour errorlint) :
```go
func directApplicationError(err error) *temporal.ApplicationError {
  if _, exact := any(err).(*temporal.ActivityError); !exact {
    return nil
  }
  ae, _ := any(errors.Unwrap(err)).(*temporal.ApplicationError)
  return ae
}
```

### 3.3 `internal/llm` (av)

`usage.go` :
```go
// UsageError: every failure after a provider call (av, T10). Bound: declared
// usage, plus MaxTokens and RequestBytes per call failed without usage.
type UsageError struct {
  Err   error
  Usage domain.Usage
  Bound int
}

func (e *UsageError) Error() string { return e.Err.Error() }

func (e *UsageError) Unwrap() error { return e.Err }

// RequestBytes is the size of the text a provider reads for req.
func RequestBytes(req domain.Request) int {
  n := len(req.System) + len(req.Schema)
  for _, m := range req.Messages {
    for _, p := range m.Parts {
      n += len(p.Text)
      if p.Untrusted != nil {
        n += len(domain.RenderUntrusted(*p.Untrusted))
      }
    }
  }
  return n
}
```
`client.go`, `run`, après `tr` :
```go
  bound := 0
  spent := func(err error) (Result, []domain.ToolCall, error) {
    return Result{}, nil, &UsageError{Err: err, Usage: tr.Usage, Bound: bound}
  }
```
Erreur du fournisseur : `bound += call.MaxTokens + RequestBytes(req)` puis `return spent(opaque(ErrProviderFailed, err))` ; après les additions de `tr.Usage` : `bound += resp.Usage.InputTokens + resp.Usage.OutputTokens` ; `ErrModelMismatch` et `verr` rendus par `spent`. Erreurs avant tout appel : inchangées.

### 3.4 `internal/loops/demo`, `Makefile`, skill

`activities.go` : `FailureTokens` et `billed` supprimés ; `var used *llm.UsageError` ; le cas `billed(err)` devient `case errors.As(err, &used): // (ae), (av)`, options `NonRetryable: !errors.Is(err, schema.ErrOutOfSchema), // (af)` et `Details: []any{loops.ProposeFailure{Tokens: used.Bound}},`. `register.go` (importe `internal/tenancy`), en tête de `Register` :
```go
  if r == nil || a == nil || a.LLM == nil || v == nil { // a typed nil v fails closed (D9)
    return ErrInvalidRegistration
  }
  if id, err := tenancy.ParseID(string(a.Tenant)); err != nil || id == tenancy.System { // T34, T75
    return ErrInvalidRegistration
  }
```
`Makefile`, après `export GOWORK := off` : `override GOFLAGS := -mod=readonly` puis `export GOFLAGS`. Skill `loop-engineering/references/temporal-loop-skeleton.md` : aucune valeur du SDK passée à un paquet d'activités ; D12 à D15 (signalé dans STATUS). `docs/loops/L0-demo.md` : D10, D11, D16, `denyAll`.

## 4. Étape B : code de référence (entrée : M0-T20b terminée)

### 4.1 `internal/loops` et `demo`

`workflowid.go` : `ErrInvalidLoopID` ; `MaxLoopIDBytes = 32` (un tenant de 36 octets n'entre pas, T14) ; `loopIDBytes = "abcdefghijklmnopqrstuvwxyz0123456789-"`.
```go
// NewWorkflowID returns "<loopID>-<uuid v4>" from crypto/rand: no tenant, no customer content.
func NewWorkflowID(loopID string) (string, error) {
  if loopID == "" || len(loopID) > MaxLoopIDBytes || strings.Trim(loopID, loopIDBytes) != "" ||
    loopID[0] == '-' || loopID[len(loopID)-1] == '-' {
    return "", ErrInvalidLoopID
  }
  var b [16]byte
  if _, err := rand.Read(b[:]); err != nil {
    return "", err
  }
  b[6] = b[6]&0x0f | 0x40
  b[8] = b[8]&0x3f | 0x80
  h := hex.EncodeToString(b[:])
  return loopID + "-" + h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}
```
`spec.go` (méthode : la règle des points d'entrée ne lit que les paramètres) :
```go
// MaxRunDuration bounds RunLoop (c): wall time, then a verification started
// just before it: MaxActivityAttempts attempts, backoff 1 s then 2 s.
func (s LoopSpec) MaxRunDuration() time.Duration {
  s = s.withDefaults()
  return s.Budget.MaxWallTime + MaxActivityAttempts*s.ActivityTimeout + 3*time.Second
}
```
`demo/workflow.go` : `IDPrefix = "l0-demo"`, `ExecutionMargin = 30 * time.Second`, et `ExecutionTimeout(approvalTimeout time.Duration) time.Duration` qui rend `Spec().MaxRunDuration() + approvalTimeout + loops.VerifyApprovalTimeout + CommitTimeout + ExecutionMargin`.

### 4.2 `cmd/rempart-worker/config.go`

Sentinelles `ErrConfig`, `ErrFakeRequiresDev` (`rempart-worker: -llm=fake requires -dev`), `ErrProviderRefused`, `ErrDemoOnceRequired`. `type Config struct { TemporalAddress, Namespace, LLMProvider, FakeScript string; Dev, DemoOnce bool; Tenant tenancy.ID }`. `type once struct { v string; set bool }` : `String()` rend `""` ; `Set` rend une erreur si `if o.set {`, sinon `o.v, o.set = s, true`.
```go
func LoadConfig(args []string) (Config, error) {
  set := flag.NewFlagSet("rempart-worker", flag.ContinueOnError)
  set.SetOutput(io.Discard) // flag errors quote values
  var addr, ns, provider, script, tenant once
  var cfg Config
  set.Var(&addr, "temporal-address", "")
  set.Var(&ns, "namespace", "")
  set.Var(&provider, "llm", "")
  set.Var(&script, "fake-script", "")
  set.Var(&tenant, "tenant", "")
  set.BoolVar(&cfg.Dev, "dev", false, "")
  set.BoolVar(&cfg.DemoOnce, "demo-once", false, "")
  if err := set.Parse(args); err != nil || set.NArg() != 0 {
    return Config{}, fmt.Errorf("%w: command line refused", ErrConfig)
  }
  switch provider.v {
  case "fake":
  case "anthropic":
    return Config{}, ErrProviderRefused
  default:
    return Config{}, fmt.Errorf("%w: -llm is required", ErrConfig)
  }
  if !cfg.Dev {
    return Config{}, ErrFakeRequiresDev
  }
  if !cfg.DemoOnce {
    return Config{}, ErrDemoOnceRequired
  }
  id, err := tenancy.ParseID(tenant.v)
  if err != nil || id == tenancy.System {
    return Config{}, fmt.Errorf("%w: -tenant is not a customer tenant id", ErrConfig)
  }
  if !loopbackAddr(addr.v) || !validNamespace(ns.v) || !fs.ValidPath(script.v) || path.Ext(script.v) != ".json" {
    return Config{}, fmt.Errorf("%w: -temporal-address, -namespace or -fake-script", ErrConfig)
  }
  cfg.TemporalAddress, cfg.Namespace, cfg.LLMProvider, cfg.FakeScript, cfg.Tenant = addr.v, ns.v, provider.v, script.v, id
  return cfg, nil
}

func loopbackAddr(a string) bool {
  host, port, err := net.SplitHostPort(a)
  ip := net.ParseIP(host)
  p, perr := strconv.Atoi(port)
  return err == nil && ip != nil && ip.IsLoopback() && perr == nil && p > 0 && p < 65536 && strconv.Itoa(p) == port
}
```
`validNamespace` : 1 à 63 octets de `[a-z0-9-]` (`strings.Trim`).

### 4.3 `run.go`, `main.go` (flux de données)

Constantes `fakeModel = "fake-model-v1"`, `demoTarget = "bonjour"`, `demoAuthor = "demo-author"`, `demoApprovalTimeout = 5 * time.Second`, `runGrace = 30 * time.Second`. `type denyAll struct{}`, `VerifyApproval` : `return loops.ApprovalCheck{}, nil`. `demoResult` : `WorkflowID` (`json:"workflow_id"`) et `demo.Output` embarqué. `run(ctx, cfg, stdout) error`, dans l'ordre, chaque erreur rendue aussitôt :
1. `if !cfg.Dev || cfg.LLMProvider != "fake" || !cfg.DemoOnce { // T41, even if LoadConfig is bypassed` : `return ErrFakeRequiresDev`.
2. `fakeClient(cfg)` : `os.OpenRoot(".")`, `llmfake.LoadOptions(root.FS(), cfg.FakeScript)`, `llmfake.New`, `NewStaticResolver` pour `cfg.Tenant` seul (`PlatformFake`, `fakeModel`, `ResidencyEU`, `RetentionZero`), `llm.NewClient(prov, res, nil, llm.Config{MaxTokensPerCall: activities.MaxTokensPerCall, AllowFakeRoute: cfg.Dev})`.
3. `queue, err := loops.NewWorkflowID(demo.TaskQueue) // D7, T79` puis `id` par `NewWorkflowID(demo.IDPrefix)`.
4. `client.Dial` (`HostPort`, `Namespace`, `Logger: tlog.NewStructuredLogger(...)` : `slog` texte sur `os.Stderr`, niveau `Warn`) ; `defer tc.Close()`.
5. `worker.New(tc, queue, worker.Options{})` ; `demo.Register(w, &activities.Activities{LLM: cl, Tenant: cfg.Tenant}, denyAll{})` ; `w.Start()`, `defer w.Stop()`.
6. `in := demo.Input{Target: demoTarget, Author: demoAuthor, ApprovalTimeout: demoApprovalTimeout}` ; `timeout := demo.ExecutionTimeout(in.ApprovalTimeout)` ; contexte borné à `timeout+runGrace`.
7. `tc.ExecuteWorkflow(rctx, client.StartWorkflowOptions{ID: id, TaskQueue: queue, WorkflowExecutionTimeout: timeout}, demo.WorkflowName, in)` ; `wr.Get(rctx, &out)` : `converged`, 5 s, `timed_out`, aucun `Commit`.
8. `json.NewEncoder(stdout).Encode(demoResult{WorkflowID: id, Output: out})`.

Aucun secret lu ; l'historique (en clair, A1) ne contient pas le tenant. `main.go` : `os.Exit(realMain(context.Background(), os.Args[1:], os.Stdout, os.Stderr))` ; `realMain` : erreur de `LoadConfig` sur stderr, `2` ; `signal.NotifyContext` (SIGINT, SIGTERM) ; échec de `run` : `rempart-worker: <err>`, `1` ; sinon `0`.

### 4.4 `Makefile` et script

`.PHONY` gagne `demo` ; recette (tabulations dans le fichier) :
```make
# Démo de bout en bout (M0-T20) : faux LLM derrière -dev, vérificateur qui refuse tout,
# tenant de démo fixe. Sortie standard : un seul document JSON.
demo:
  @$(MAKE) --no-print-directory dev >&2
  @go run ./cmd/rempart-worker -dev -demo-once -llm=fake -tenant=0d3e0000-0000-4000-8000-000000000001 \
    -temporal-address=127.0.0.1:7233 -namespace=rempart \
    -fake-script=internal/loops/demo/testdata/scripts/converge.json
```
`internal/loops/demo/testdata/scripts/converge.json` (phase tests) : version 1 ; `demo.greeting.v1` : `{"greeting":"salut"}` puis `{"greeting":"bonjour"}`, modèle `fake-model-v1`, `request_id` `req-demo-1`, `req-demo-2` ; modèle `fake-model-v1` : `native_structured_output` vrai, `strict_tools` et `requires_retention` faux.

## 5. Tests (`test-author`)

### 5.1 Étape A (règle attendue entre parenthèses)

- `internal/archtest/loops_t20_test.go` :
  - `TestKeyedLiteralsInWorkflowCode` (`loops-keyed-literals`) : `validator_unkeyed` (`workflow.UpdateHandlerOptions{func(ctx workflow.Context, in string) error { return nil }, 0, ""}`), `sdk_struct_unkeyed`, `elided_in_slice`, `elided_in_map`, `alias_type`, `module_struct_unkeyed` ; `conforming` (`[]string{"a"}`, `map[string]int{"a": 1}`, littéraux à clés, `loops.ApprovalResult{}`) : 7.
  - `TestActivityPackagesDecodingTargets` (`loops-raw-decoding-target`), dans `internal/loops/fixture/acts` sans `sdk/workflow` : `receive_param`, `get_value`, `details_param`, `get_heartbeat_details` ; admis `fake_package`, `outside_loops`, `conforming` : 7.
  - `TestLoopsNoReflection` (`loops-no-reflection`) : `reflect_in_loops`, `unsafe_in_demo`, `reflect_in_activities`, `reflect_in_fake`, `cgo_import`, `linkname_directive`, `asm_file` (`ReadSources` sur `MapFS`, erreur citant `internal/loops/x.s`) ; admis `outside_loops` : 8.
  - `TestSearchAttributesRefused` (`loops-no-search-attributes`) : `get_typed`, `upsert_typed`, `upsert_untyped`, `info_search_attributes`, `upsert_memo`, `conforming` : 6.
  - `TestIgnoredDirImportRefused` (`no-ignored-dir-import`) : `underscore_dir`, `dot_dir`, `testdata_dir`, `conforming` : 4.
  - `TestAnthropicAdapterUnwired` (`anthropic-unwired-m0`) : `from_cmd`, `from_internal` en violation, `none` : 3.
- `makefile_test.go` : `TestMakefileGoflagsNeutralized` : lignes exactes `override GOFLAGS := -mod=readonly` et `export GOFLAGS`, une fois chacune.
- `internal/llm/usage_test.go` : `TestUsageErrorBound` : échec au 1er appel, `Bound` 256 + `RequestBytes` (requête vue par le faux) ; hors schéma puis correction, 10/5 par appel : `Usage{20,10}`, `Bound` 30 ; `model_mismatch` : usage déclaré ; `no_route` : pas de `UsageError` ; `Error()` et `errors.Is` inchangés.
- `internal/loops/demo/demo_test.go` : `TestDemoProposeErrors` révisé (`provider_failure` 1 itération, `activity_failed`, 256 + `RequestBytes` ; `model_mismatch` 1, 15 ; `out_of_schema` 3, 45 ; `direct_billed` non rejouable, `ProposeFailure{256 + RequestBytes}` ; `direct_out_of_schema` rejouable, `{15}`) ; `TestDemoRegister` révisé (succès avec client et tenant A ; refus sans enregistrement : 3 nils, `nil_llm`, `invalid_tenant`, `system_tenant`) ; `TestDemoRegisterTypedNilVerifierFailsClosed` (`(*loopsfake.ApprovalVerifier)(nil)`, signal signé de `bob` : `verify_error`, `timed_out`, `Commit` 0) ; `TestDemoInputDecodingFrozen` (entrée `json.RawMessage` : `tenant` en trop accepté, `TARGET` lu comme `target`, doublon : le dernier part au faux ; T78, inversé en M1).

Copie privée avec la section 3 : tout vert, dont `TestLoopSourcesConform` et `TestRepositoryConforms` (aucun faux positif).

### 5.2 Étape B

- `internal/loops/workflowid_test.go` : `TestNewWorkflowIDOpaque` : 1000 ID distincts au motif du critère 8 ; `ErrInvalidLoopID` sans citer l'entrée : vide, `L0-demo`, `l0_demo`, `l0 demo`, `-l0`, `l0-`, 33 octets, tenant A. `spec_test.go` : `TestLoopSpecMaxRunDuration` (démo 153 s ; `ActivityTimeout` nul et 1 min : 963 s). `demo_test.go` : `TestDemoExecutionTimeout` (228 s pour 5 s, 3823 s pour 1 h).
- `cmd/rempart-worker/config_test.go` (8 tests) : `TestLoadConfigRequiresLLMProvider` (sans `-llm`, vide, `openai`, `FAKE`) ; `TestLoadConfigFakeRequiresDev` ; `TestLoadConfigAnthropicRefusedM0` ; `TestLoadConfigDemoTenantValidated` (absent, majuscules, UUID nul, `System`, UUID v1) ; `TestLoadConfigStrictFlags` (positionnel, `-llm` répété, `-anthropic-key=x`, sans `-demo-once`, `10.0.0.1:7233`, `localhost:7233`, port `0` ou `07233`, namespace `Rempart`, script absolu, `../x.json`, `x.yaml`) ; `TestLoadConfigValid` ; `TestConfigNeverPrintsSecrets` (`t.Setenv` de `ANTHROPIC_API_KEY`, `OPENBAO_DEV_ROOT_TOKEN`, `TEMPORAL_ADDRESS`, `TEMPORAL_NAMESPACE` à valeurs `FAKE` : `Config` inchangé ; canari `sk-ant-api03-EXAMPLEEXAMPLE` en valeur de chaque drapeau et en positionnel : absent des erreurs et du stderr de `realMain` ; champs de `Config` exactement ceux de 4.2) ; `TestProductionConfigHasNoFake` (combinaisons de `-dev`, `-demo-once`, `-llm` : seule `-dev -demo-once -llm=fake` passe).
- `run_test.go` : `TestRunRefusesFakeWithoutDev` (`Dev` faux ou `anthropic` : `ErrFakeRequiresDev`, 0 connexion sur un écouteur 127.0.0.1:0 donné en adresse, stdout vide) ; `TestDenyAllVerifier` (signatures de `loopsfake.ExpectedSignature` : `ApprovalCheck{}`, nil). `main_test.go` : `TestRealMainExitCodes` (sans argument, `-demo-once -llm=fake` avec stderr `requires -dev`, `-dev -demo-once -llm=anthropic` : 2, stdout vide).
- `internal/archtest/makefile_test.go` : `TestMakefileDemoTarget` : `demo` dans `.PHONY`, recette en `@`, `dev >&2`, drapeaux de 4.4, aucun `$(` hors `$(MAKE)`.
- Intégration (`//go:build integration`, pile de `make dev`, sans `dev-env.sh run`) : `internal/loops/demo/e2e_integration_test.go` : `TestDemoEndToEnd` (worker en processus, faux `salut` puis `bonjour`, vérificateur local qui refuse tout, file `NewWorkflowID("rempart-demo-it")` : `converged`, 2 itérations, hash attendu, `timed_out`, non commis ; historique sans `demo.Commit` planifié, délai 228 s, sans le tenant A) et `TestDemoApprovedEndToEnd` (`loopsfake.ApprovalVerifier`, délai 30 s, signal signé de `bob` juste après le démarrage : `approved`, un seul `demo.Commit`, commis) ; `cmd/rempart-worker/run_integration_test.go` : `TestRunDemoOnceEndToEnd` (`t.Chdir("../..")`, `TEMPORAL_ADDRESS=10.255.255.1:1` dans l'environnement, configuration de `make demo` : un document, `converged`, `timed_out`, non commis, `workflow_id` opaque ; description : file `^rempart-demo-<uuid>$`, délai 228 s).

## 6. Critères d'acceptation

`BASE` : `ca76c27` (HEAD au lancement) ; `T20A`, `T20B` : commits des tests de A et de B. Décisions de la section 10 retenues sur délégation de l'humain, défaut strict, réversibles.
1. `go test -count=1 -v -run 'TestKeyedLiteralsInWorkflowCode|TestActivityPackagesDecodingTargets|TestLoopsNoReflection|TestSearchAttributesRefused|TestIgnoredDirImportRefused|TestAnthropicAdapterUnwired|TestMakefileGoflagsNeutralized' ./internal/archtest/` : `grep -c '^--- PASS'` `7`, `grep -c '^    --- PASS'` `35`, `grep -c -- '--- FAIL'` `0`.
2. `go test -count=1 ./internal/archtest/` : `ok` ; `grep -c '"reflect"' internal/loops/runloop.go` : `0` ; `grep -rl FailureTokens --include='*.go' internal | wc -l` : `0`.
3. `go test -count=1 -race -v -run TestUsageErrorBound ./internal/llm/` : `--- PASS: TestUsageErrorBound` ; `go test -count=1 -race ./internal/llm/... ./internal/loops/...` : que des `ok`.
4. `go test -count=1 -race -v ./internal/loops/demo/...` : `grep -c '^--- PASS'` `15` en fin de A, `16` en fin de B ; `FAIL` `0`.
5. `go tool workflowcheck ./internal/loops/...; echo rc=$?` : seule sortie `rc=0`.
6. `grep -c 'M0-T20b.*terminée' docs/STATUS.md` : au moins `1` avant le premier commit d'impl de B.
7. `go test -count=1 -v ./cmd/rempart-worker/` : `grep -c '^--- PASS'` `11` ; `go test -count=1 -v -run 'TestNewWorkflowIDOpaque|TestLoopSpecMaxRunDuration' ./internal/loops/` : `2`.
8. `make -s demo 2>/dev/null | jq -e '.loop.status == "converged" and .approval.outcome == "timed_out" and .committed == false and (.workflow_id | test("^l0-demo-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"))'` : `true`, code 0 (critère 4 de M0) ; `make demo 2>/dev/null | jq -s length` : `1`.
9. `make dev >/dev/null && go test -count=1 -tags=integration -v -run 'TestDemoEndToEnd|TestDemoApprovedEndToEnd|TestRunDemoOnceEndToEnd' ./internal/loops/demo/ ./cmd/rempart-worker/` : `grep -c '^--- PASS'` `3`.
10. `d=$(mktemp -d); go build -o "$d/rw" ./cmd/rempart-worker; "$d/rw" -demo-once -llm=fake; echo rc=$?` : stderr `rempart-worker: -llm=fake requires -dev`, `rc=2` ; `"$d/rw" -dev -demo-once -llm=anthropic; echo rc=$?` : `rc=2`.
11. `go list -deps ./cmd/rempart-worker | grep -c -e internal/loops/fake -e llm/adapters/anthropic` : `0`.
12. `git diff --exit-code BASE -- go.mod go.sum; echo rc=$?` : `rc=0`.
13. `git diff --exit-code T20A -- 'internal/**/*_test.go'` (fin de A), `git diff --exit-code T20B -- '*_test.go' internal/loops/demo/testdata` (fin de B) : `rc=0`.
14. Section 7 sur copie privée (`mktemp -d`, SHA consigné, T72) : toutes détectées.
15. `make verify-quick; echo rc=$?` et `make verify; echo rc=$?` : `rc=0`.
16. `wc -c < docs/plans/M0-worker-demo.md` : au plus `33000` (V2) ; `perl -CSD -ne 'print if /[^\n\x20-\x7E\x{C0}-\x{FF}\x{152}\x{153}]/' docs/plans/M0-worker-demo.md | wc -l` : `0`.

## 7. Mutations (une à la fois ; le test cité échoue)

| # | Ancre : remplacement | Test |
|---|---|---|
| A1 | `case dec && !called` : `case wf && !called` | `TestActivityPackagesDecodingTargets` |
| A2 | `case *ast.ArrayType, *ast.MapType: // an elided` : ajout `, *ast.SelectorExpr` avant `:` | `TestKeyedLiteralsInWorkflowCode` |
| A3 | `if wf && unkeyed(n) {` : `if false {` | idem |
| A4 | `[]string{"reflect", "unsafe", "C"}` : `[]string{"unsafe", "C"}` | `TestLoopsNoReflection` |
| A5 | `inLoops && strings.HasPrefix(cm.Text, "//go:linkname")` : `false` | idem |
| A6 | `slices.Contains(foreignSources, path.Ext(p)):` : `false:` | idem |
| A7 | `case wf && slices.Contains(searchNames, n.Sel.Name):` : `case false:` | `TestSearchAttributesRefused` |
| A8 | `slices.ContainsFunc(strings.Split(p, "/"), ignoredElem)` : `false` | `TestIgnoredDirImportRefused` |
| A9 | `any(errors.Unwrap(err))` : `any(err)` | `TestRunLoop` (`./internal/loops/`) |
| A10 | `bound += call.MaxTokens + RequestBytes(req)` : `bound += call.MaxTokens` | `TestUsageErrorBound` |
| A11 | `bound += resp.Usage.InputTokens + resp.Usage.OutputTokens` : `bound += resp.Usage.OutputTokens` | idem |
| A12 | `NonRetryable: !errors.Is(err, schema.ErrOutOfSchema),` : `NonRetryable: false,` | `TestDemoProposeErrors` |
| A13 | `Tokens: used.Bound}` : `Tokens: 0}` | idem |
| A14 | `err != nil \|\| id == tenancy.System { // T34, T75` : `err != nil { // T34, T75` | `TestDemoRegister` |
| A15 | ligne `override GOFLAGS := -mod=readonly` supprimée | `TestMakefileGoflagsNeutralized` |
| B1 | `b[6] = b[6]&0x0f \| 0x40` : `b[6] &= 0x0f` | `TestNewWorkflowIDOpaque` |
| B2 | `MaxActivityAttempts*s.ActivityTimeout` : `s.ActivityTimeout` | `TestLoopSpecMaxRunDuration` |
| B3 | `+ approvalTimeout + loops.VerifyApprovalTimeout` : `+ loops.VerifyApprovalTimeout` | `TestDemoExecutionTimeout` |
| B4 | `case "anthropic":` et son `return` supprimés | `TestLoadConfigAnthropicRefusedM0` |
| B5 | `if !cfg.Dev {` : `if false {` | `TestLoadConfigFakeRequiresDev` |
| B6 | `if err != nil \|\| id == tenancy.System {` : `if err != nil {` | `TestLoadConfigDemoTenantValidated` |
| B7 | `ip != nil && ip.IsLoopback()` : `ip != nil` | `TestLoadConfigStrictFlags` |
| B8 | `if o.set {` : `if false {` | idem |
| B9 | `"%w: command line refused", ErrConfig)` : `"%w: %w", ErrConfig, err)`, `SetOutput` supprimé | `TestConfigNeverPrintsSecrets` |
| B10 | `if !cfg.Dev \|\| cfg.LLMProvider != "fake" \|\| !cfg.DemoOnce {` : `if false {` | `TestRunRefusesFakeWithoutDev` |
| B11 | `return loops.ApprovalCheck{}, nil` : `return loops.ApprovalCheck{SignatureValid: true}, nil` | `TestDenyAllVerifier` |
| B12 | `, WorkflowExecutionTimeout: timeout}` : `}` | `TestRunDemoOnceEndToEnd` |
| B13 | `queue, err := loops.NewWorkflowID(demo.TaskQueue)` : `queue, err := demo.TaskQueue, error(nil)` | idem |

## 8. Modèle de menace (mise à jour par le principal)

- **T10** : délai d'exécution borné ; `Bound` au lieu de 1024 ; plus de rafale sur 429 ; résidu : cadrage du fournisseur. **T14** : identifiants et file opaques. **T18** : bouclage sans TLS, résidu dev inchangé.
- **T34**, **T75** : `System` refusé, tenant par processus validé deux fois. **T36** : ni secret par drapeau, ni environnement. **T41** : faux derrière `-dev` (deux contrôles), `denyAll`, binaire sans `internal/loops/fake` ni adaptateur Anthropic.
- **T73** : (at), (au), (aw), attributs de recherche, imports ignorés ; résidu : décodage par un paquet hors `internal/loops` appelé depuis un workflow. **T74** : `GOFLAGS` neutralisé par le `Makefile` seulement. **T78** : figé.
- **T79 (proposée)** : file partagée entre processus, tâche prise par un autre worker (autre vérificateur, faux ou tenant). M0 : file par processus ; M1 : file par tenant.

## 9. Risques à lever sur copie avant gel

1. `go run` rend 1 quel que soit le code du programme : codes vérifiés sur binaire (critère 10).
2. Journal du SDK hors stdout ; `client.Dial` sans lecture de `TEMPORAL_*`.
3. errorlint sur `any(err).(*T)` ; faux positifs de D12, D13 ; `TestMakefileTargets` à compléter pour `demo`.
4. `json.RawMessage` transmis tel quel par le testsuite ; signal tamponné avant l'attente sur un vrai serveur.
5. Tests de `internal/llm` comparant le type exact d'une erreur ; `override GOFLAGS` écrase un réglage de session ; D10 suppose au moins un octet par token.

## 10. Décisions ouvertes (défaut strict retenu) et ADR

1. Conditions M0-T12 et (aa) à (ad) : **M0-T20b** à part, terminée avant B (lecture littérale de la condition). Variante : avant le premier câblage (M1), `anthropic-unwired-m0` servant de garde.
2. (an) à (as) : **M0-T03b** après T20, avant la clôture ; T20 n'en dépend pas (intégration sans variable lue, hors `dev-env.sh run`, conforme à (ap)).
3. D1, D3, D5 à D7, D9, D11, D12. Aucun ADR : chaque décision se défait par un plan ultérieur, sans donnée persistée.

## 11. Tâches ordonnées

1. Principal : `BASE` ; `rempart-state phase tests`.
2. `test-author` : 5.1, `docs/loops/L0-demo.md` ; copie privée avec la section 3 : vert, A1 à A15, risques 3 à 5 ; dépôt rouge. Commit `T20A`, `phase impl`.
3. Cycles A.1 (`loopsrc.go`, `rules.go`, `runloop.go` : critères 1, 2, 5), A.2 (`usage.go`, `client.go`, `activities.go` : 3, 4), A.3 (`register.go`, `Makefile`, skill ; STATUS : skill à relire). Commit `fix(loops): close archtest gaps, bound failed call tokens (M0-T20)`.
4. Principal : `/task` M0-T20b ; critère 6.
5. `phase tests` ; `test-author` : 5.2, `converge.json` ; copie : section 4, risques 1, 2, 4, B1 à B13 ; dépôt rouge. Commit `T20B`, `phase impl`.
6. Cycles B.1 (`workflowid.go`, `MaxRunDuration`, `ExecutionTimeout`), B.2 (`config.go`, `main.go`), B.3 (`run.go`, `demo`) : critères 7 à 12.
7. `security-reviewer`, puis `acceptance-verifier` (critères 1 à 16, copie privée).
8. Principal : STATUS (soldées : (at) à (ax), (af), (c), T41 et T40 côté worker, décision 7 de M0-T19d ; T79 ; prochaine : M0-T03b), menaces, commit `feat(worker): demo worker and make demo on dev stack (M0-T20)`, `phase free`.

## V1 (test-author, copie 3bb97b5)
- 3.1 `rules.go` : `anthropic-unwired-m0` gagne `AllowedFrom: []string{m("internal/llm/adapters/anthropic/...")}` (l'adaptateur importe ses sous-paquets).
- 3.1 : `internal/loops/domain/findings.go` : `couple{code: x.Code, resource: x.Resource}` (faux positif D12).
- 3.3 `client.go`, S13 : `if cerr := ctx.Err(); cerr != nil { if attempt > 0 { return spent(cerr) }; return Result{}, nil, cerr }` (D10 : annulation après un appel).
- 5.1 : `TestUsageErrorBound` : `canceled_after_call` ; `TestDemoProposeErrors` : `invalid_tenant` devient `direct_invalid_tenant` ; `rules_test.go` : 9 règles, fixtures `anthropic-unwired-m0`, autres fixtures jugées sans elle ; `loops_test.go` : `shadowed_package` à clés.
- 7 : A9 : `any(errors.Unwrap(err))` : `any(errors.Join(err))`, test `-run TestRunLoop` (préfixe) ; A14 : `id == tenancy.System { // T34, T75` : `id == "" { // T34, T75` ; A16 à A19 ajoutées (test-author).
- 6.16 : plafond porté à 31000 octets.

## V2 (test-author, copie 0b0f1f9)
- 7 : B9 : `set.SetOutput(io.Discard) // flag errors quote values` : `_ = io.Discard` (sinon `io` inutilisé : échec de compilation, non du test), avec `"%w: %w", ErrConfig, err)`.
- 6.8, 11 (tâche 5) : sur copie, `make demo` lancerait `make dev` sans `.env.dev` (pile partagée) : critère 8 vérifié par la ligne `go run` de 4.4 ; `make demo` au dépôt en tâche 7.
- 6.16 : plafond porté à 33000 octets.
