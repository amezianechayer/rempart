# M0-T03b `pile-dev-harden` : obligations (an) à (as), puis (bd) à (bh)

Cadrage : amendement A4 de `docs/plans/M0-overview.md`, après M0-T20, avant `/close-milestone M0`. Deux étapes, chacune un cycle tests puis impl : **A** pile de dev ((an) à (as), référence `M0-pile-dev.md`), **B** code Go ((bd) à (bh), référence `M0-worker-demo.md`). (bi) est seulement consignée dans `docs/STATUS.md` pour M1. Menaces : T10, T14, T73, T74, T76, T77.


V0 (principal, 2026-09-29) : D4 réécrit sans exclusion de tests par drapeau ; décisions de la section 11 retenues sur délégation de l'humain (défaut strict, réversibles).

## 1. Objectif et périmètre

Objectif : solder (an) à (as) et (bd) à (bh) par D1 à D10, sans régression de `make verify` ni de `make demo`.

Dans : fichiers des sections 3 et 5 (dont le nouveau `scripts/dev-preflight.sh`), tests des sections 4 et 6, `docs/SETUP.md`, menaces, STATUS, proposition `docs/proposals/0007-garde-exec-pile-dev.md`.

Hors : Transit, clés, jeton du worker (M1) ; `secrets:` compose ((aq) reste un résidu) ; `rules.go` et ses fixtures ; adaptateur Anthropic ; (bi) ; `.claude/`.

## 2. Décisions

- D1 (an) : toute commande compose du `Makefile` et de `scripts/` s'écrit `bash scripts/dev-env.sh run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml <sous-commande>`. `run` exporte les valeurs validées après l'environnement hérité : elles priment. `--env-file` reste (un `.env` racine n'est jamais lu).
- D2 (ao) : `run` retire toute variable `COMPOSE_*` avant `exec` ; `-p rempart-dev` explicite.
- D3 (ao, ar) : `dev-preflight` exécute `bash scripts/dev-preflight.sh` : refus si `DOCKER_HOST` non vide n'est pas `unix:///<chemin>` sans `..`, si l'hôte du contexte courant n'a pas cette forme ou est illisible, si la majeure de `Server.Version` est illisible ou inférieure à 28. Contrôles d'hôte avant `docker info` ; aucune valeur affichée.
- D4 (ap, V0) : `verify` lance `go test -tags=integration $$(go list ./... | grep -v '/internal/archtest$$')` sans secrets, puis `bash scripts/dev-env.sh run go test -count=1 -tags=integration ./internal/archtest` (seul paquet d'intégration qui lit `.env.dev`). Aucune exclusion de tests par drapeau (refusée par le harnais). `devstack_integration_test.go` inchangé.
- D5 (as) : scripts sans écriture pour le groupe et les autres (`perm&0o022 == 0`) ; `postgres-init.sh` lisible et exécutable par les autres (`perm&0o005 == 0o005`) car lu dans le conteneur par l'uid 999.
- D6 (bd) : portée `sa` = code de workflow, paquet sous `cmd/`, ou paquet dont un fichier importe `go.temporal.io/sdk/...` ; dans `sa`, sélecteurs de `searchNames` et clés `Memo`, `SearchAttributes`, `TypedSearchAttributes` de tout `KeyValueExpr` refusés (`loops-no-search-attributes`) ; `loops-keyed-literals` étendue à `cmd/...`.
- D7 (bf) : `//go:linkname` refusé dans tout fichier non test (`loops-no-reflection` sous `internal/loops`, `no-linkname` ailleurs) ; import de `cmd/...` hors `cmd/` refusé (règle source `no-cmd-import`, plus stricte que R4 étendue, sans toucher `DefaultRules`).
- D8 (be) : après un appel réussi, un champ d'usage hors `[0, MaxReportedTokens]` (`1 << 24`) donne `spent(ErrProviderFailed)` avec `bound += call.MaxTokens + RequestBytes(req)`, usage non cumulé, sans correction.
- D9 (bg) : `onceBool` : seconde occurrence refusée, `true` et `false` seulement.
- D10 (bh) : `clientOptions(cfg)` revérifie adresse et espace de noms avant toute I/O de `run`, `Identity` = `loops.NewWorkflowID("rempart-worker")` ; `client.DialContext(ctx, opts)` ; échec : `ErrTemporalUnavailable`, cause non transmise.

Pas d'ADR : décisions locales et réversibles.

## 3. Étape A : code de référence

Recettes du `Makefile` : tabulation, rendue ici par quatre espaces.

`scripts/dev-env.sh` : ligne `run` de l'en-tête et fonction `run` ; le reste (et les ancres des mutations existantes) inchangé.

```bash
#   run CMD [ARG]   valide .env.dev, exporte ses variables (prioritaires sur le shell),
#                   retire les variables COMPOSE_*, exécute CMD (M0-T03b)
run() {
  (($# > 0)) || die "usage : dev-env.sh run CMD [ARG...]"
  check
  local k v
  while IFS='=' read -r k v; do export "$k=$v"; done <"$file"
  local n
  for n in $(compgen -e); do
    if [[ $n == COMPOSE_* ]]; then unset -v "$n"; fi
  done
  exec "$@"
}
```

`scripts/dev-preflight.sh`, mode 755 :

```bash
#!/usr/bin/env bash
# Pile de dev (M0-T03b), sans rien démarrer : compose v2, démon local par socket unix,
# Docker Engine 28 ou plus (publication sur 127.0.0.1 étanche).
set -euo pipefail
die() { echo "dev-preflight : $*" >&2; exit 2; }
local_endpoint() { [[ $1 =~ ^unix:///[A-Za-z0-9._/-]+$ && $1 != *..* ]]; }

docker compose version >/dev/null 2>&1 || die "Docker Engine et le plugin compose v2 sont requis (voir docs/SETUP.md)."
if [[ -n ${DOCKER_HOST:-} ]] && ! local_endpoint "$DOCKER_HOST"; then
  die "DOCKER_HOST ne désigne pas un socket unix local : démon distant refusé (voir docs/SETUP.md)."
fi
host=$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null) || die "contexte Docker illisible (voir docs/SETUP.md)."
local_endpoint "$host" || die "le contexte Docker courant ne désigne pas un socket unix local : démon distant refusé (voir docs/SETUP.md)."
docker info >/dev/null 2>&1 || die "démon Docker injoignable (voir docs/SETUP.md)."
version=$(docker version --format '{{.Server.Version}}' 2>/dev/null) || die "version du démon Docker illisible (voir docs/SETUP.md)."
[[ $version =~ ^([0-9]{1,4})\.[0-9] ]] || die "version du démon Docker illisible (voir docs/SETUP.md)."
((10#${BASH_REMATCH[1]} >= 28)) || die "Docker Engine 28 ou plus requis (voir docs/SETUP.md)."
echo "dev-preflight : Docker Engine 28 ou plus, compose v2 et démon local disponibles."
```

`Makefile` (lignes non citées inchangées) :

```make
verify: verify-quick
    $(MAKE) --no-print-directory dev
    go test -tags=integration $$(go list ./... | grep -v '/internal/archtest$$')
    bash scripts/dev-env.sh run go test -count=1 -tags=integration ./internal/archtest
    go tool govulncheck ./...
# dev, troisième ligne de recette :
    bash scripts/dev-env.sh run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml up -d --wait --wait-timeout 240 --quiet-pull
dev-preflight:
    @bash scripts/dev-preflight.sh
# dev-down, première ligne de recette :
    @if [ -f .env.dev ]; then bash scripts/dev-env.sh run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml down --remove-orphans; \
```

`scripts/dev-bootstrap.sh` ligne 4 : `compose=(bash scripts/dev-env.sh run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml)`. `scripts/dev/postgres-init.sh` ligne 5 : `for v in POSTGRES_PASSWORD TEMPORAL_DB_PASSWORD REMPART_DB_PASSWORD; do`. `docker-compose.yml` ligne 1 : `# Pile de dev (M0-T03). Toujours : bash scripts/dev-env.sh run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml`. `docs/SETUP.md` : forme D1 partout (réinitialisation comprise), Engine 28 minimum, socket unix local, `COMPOSE_*` ignorées.

## 4. Étape A : tests

Tests existants modifiés, par nécessité (ils figent le texte de M0-T03) :
- `internal/archtest/compose_test.go`, `TestMakeDevUsesWait` : `composeFlags` = `" -p rempart-dev --env-file .env.dev -f docker-compose.yml "` ; références `dev`, `dev-down`, `verify`, `dev-preflight` réalignées ; `verifyIntegrationLine` et `integrationViaEnvRe` remplacés par `verifyPlainLine` et `verifySecretLine` (D4). Règles : `dev` avant ces lignes ; toute ligne avec `-tags=integration` vaut l'une d'elles (`integration line ... not allowed`) ; toute ligne avec `scripts/dev-env.sh run` contient la forme D1 ou vaut `verifySecretLine` (`dev-env.sh run gives the secrets to`) ; recette de `dev-preflight` égale à `bash scripts/dev-preflight.sh`. Cas ajoutés : `compose_without_project`, `secrets_to_all_packages`, `plain_without_skip`, `run_other_command`, `preflight_inline`.
- `internal/archtest/devscripts_test.go` : `referenceDevEnv` réaligné ; `devEnvChecks` gagne `run_overrides_environment` ; mutation `run_keeps_compose` (ligne `if [[ $n == COMPOSE_* ]]...` remplacée par `:`, attendu `still exported`) ; `scripts_mode_755` : règle D5, liste étendue à `scripts/dev-preflight.sh`.

Nouveau `internal/archtest/devharden_test.go` (ni Docker ni réseau) :
- `runInEnv(t, dir, extra, name, args...)` : environnement de `runIn` plus `extra`. `checkDevEnvRunOverridesEnvironment` : avec `OPENBAO_DEV_ROOT_TOKEN=root`, `POSTGRES_PASSWORD=weak`, cinq `COMPOSE_*`, `DOCKER_HOST=unix:///x.sock`, `run env` rend les valeurs du fichier (`not overridden by .env.dev`), aucune `COMPOSE_*` (`still exported`), `DOCKER_HOST` conservé.
- `TestDevPreflightScript` : référence et script du dépôt, faux `docker` en tête de `PATH` (journal ; réponses par variables `FAKE_*`). Code 0 : `local_socket` (`unix:///var/run/docker.sock`, `29.3.1`), `rootless`, `engine_28`. Code 2 : `docker_host_tcp` (`info` absent du journal), `docker_host_ssh`, `docker_host_traversal`, `docker_host_not_quoted`, `context_tcp`, `context_ssh`, `context_error`, `engine_27`, `engine_garbage`, `engine_empty`, `compose_missing`, `daemon_down`. Contrôles négatifs : `no_docker_host_check`, `no_context_check`, `engine_min_20`, `lax_endpoint`.
- `TestComposeOnlyThroughDevEnv` : `checkComposeInvocations(name, src)` sur le `Makefile` et tout fichier sous `scripts/` : chaque `composeCallRe` d'une ligne non commentaire, hors `docker compose version`, refuse `docker-compose` et exige la forme D1 depuis `bash scripts/dev-env.sh run `, suivie d'une espace, de `)` ou de la fin (`docker compose outside`). Cas : `makefile_up_bare`, `makefile_down_bare`, `bootstrap_array_bare`, `project_missing`, `project_other`, `runner_lookalike` (`dev-env.sh.bak run`), `legacy_binary`, `conforming`.
- `TestDevBootstrapScript` : une seule ligne contient `docker`, celle de la section 3 ; cas `old_form`, `no_project`, `second_docker_call`.
- `TestPostgresInitValidatesPasswords` : faux `psql` qui crée un témoin ; valeurs valides : code 0, témoin ; `POSTGRES_PASSWORD` absent, `root`, majuscules, 63 chiffres, ou `TEMPORAL_DB_PASSWORD` absent : code 2, ni témoin ni valeur affichée. Contrôle négatif : `referencePostgresInit` inchangée laisse passer `POSTGRES_PASSWORD=root`.

## 5. Étape B : code de référence (gofumpt à l'écriture)

`internal/archtest/loopsrc.go` :

```go
var searchKeys = []string{"Memo", "SearchAttributes", "TypedSearchAttributes"} // (bd)

// srcChecker : sdkPkg map[string]bool, initialisé dans CheckLoopSources.
// index, boucle des imports :
if under(p, "go.temporal.io/sdk") { // (bd)
    c.sdkPkg[sf.Pkg] = true
}
// file, après wf :
cmd := under(sf.Pkg, c.module+"/cmd")
sa := wf || cmd || c.sdkPkg[sf.Pkg] // (bd)
// file, boucle des imports :
if under(p, c.module+"/cmd") && !under(sf.Pkg, c.module+"/cmd") { // (bf)
    c.add(sf, is, "no-cmd-import", sf.Pkg+" imports "+p)
}
// file, commentaires, à la place du if existant :
switch {
case !strings.HasPrefix(cm.Text, "//go:linkname"):
case inLoops: // (aw)
    c.add(sf, cm, "loops-no-reflection", "go:linkname directive")
default: // (bf)
    c.add(sf, cm, "no-linkname", "go:linkname directive")
}
// SelectorExpr : case sa && slices.Contains(searchNames, n.Sel.Name):
// CompositeLit : if (wf || cmd) && unkeyed(n) { // (at), (bd)
// KeyValueExpr, après le contrôle de Validator :
if k, isID := n.Key.(*ast.Ident); sa && isID && slices.Contains(searchKeys, k.Name) { // (bd)
    c.add(sf, n, "loops-no-search-attributes", "key "+k.Name+" in a composite literal")
}
```

`internal/llm/client.go` : `MaxReportedTokens = 1 << 24` dans le bloc `const` ; dans `run`, après `if err != nil { ... }` :

```go
if !validUsage(resp.Usage) { // (be): a negative or oversized count would lower the bound
    bound += call.MaxTokens + RequestBytes(req) // (be)
    return spent(ErrProviderFailed)
}

// validUsage: each declared count is in [0, MaxReportedTokens] (be, T10).
func validUsage(u domain.Usage) bool {
    return u.InputTokens >= 0 && u.OutputTokens >= 0 && u.InputTokens <= MaxReportedTokens && u.OutputTokens <= MaxReportedTokens
}
```

`cmd/rempart-worker/config.go` :

```go
// onceBool is a boolean flag set at most once, to true or false only (bg).
type onceBool struct{ v, set bool }

func (o *onceBool) String() string { return strconv.FormatBool(o != nil && o.v) }

func (o *onceBool) IsBoolFlag() bool { return true }

func (o *onceBool) Set(s string) error {
    if o.set || (s != "true" && s != "false") {
        return errors.New("flag repeated or not a boolean")
    }
    o.v, o.set = s == "true", true
    return nil
}
// LoadConfig : var dev, demoOnce onceBool ; set.Var(&dev, "dev", "") ;
// set.Var(&demoOnce, "demo-once", "") ; après Parse : cfg.Dev, cfg.DemoOnce = dev.v, demoOnce.v
```

`cmd/rempart-worker/run.go` :

```go
var ErrTemporalUnavailable = errors.New("rempart-worker: Temporal unavailable")

const workerIdentityPrefix = "rempart-worker"

// run, après le contrôle ErrFakeRequiresDev, avant fakeClient :
opts, err := clientOptions(cfg)
if err != nil {
    return err
}
// à la place de client.Dial :
tc, err := client.DialContext(ctx, opts)
if err != nil {
    return ErrTemporalUnavailable // (bh): fixed message, the cause may quote the address
}

// clientOptions checks the address again (bh, T14); opaque identity: no host name, no pid.
func clientOptions(cfg Config) (client.Options, error) {
    if !loopbackAddr(cfg.TemporalAddress) || !validNamespace(cfg.Namespace) {
        return client.Options{}, fmt.Errorf("%w: -temporal-address or -namespace", ErrConfig)
    }
    identity, err := loops.NewWorkflowID(workerIdentityPrefix)
    if err != nil {
        return client.Options{}, err
    }
    return client.Options{
        HostPort: cfg.TemporalAddress, Namespace: cfg.Namespace, Identity: identity,
        Logger: tlog.NewStructuredLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))),
    }, nil
}
```

## 6. Étape B : tests (nouveaux fichiers, aucun test existant modifié)

`internal/archtest/loops_t03b_test.go` (aides de `loops_test.go` et `loops_t20_test.go`) :
- `TestSearchAttributeKeysRefused` (`loops-no-search-attributes`) : `child_options_keyed_memo` (`beforeRun("\t_ = workflow.ChildWorkflowOptions{Memo: nil}")`, détail `key Memo`), `child_options_keyed_typed`, `start_options_in_cmd` (`cmd/rempart-worker/opts.go` important le client, `client.StartWorkflowOptions{Memo: nil}`), `schedule_action_in_cmd` (clé `SearchAttributes`), `memo_key_in_cmd_without_sdk` (`cmd/rempart-tool/opts.go` sans import : `type opts struct{ Memo map[string]string }`, `var _ = opts{Memo: nil}`), `selector_in_cmd_without_sdk` (`func f(o opts) { _ = o.Memo }`), `sdk_importer_outside_cmd` (`internal/other/opts.go` important le client). Sous `loops-keyed-literals` : `start_options_unkeyed_in_cmd` (`client.StartWorkflowOptions{"id", "q"}`). Conformes : `internal/other` sans SDK avec `note{Memo: "x"}` ; `client.StartWorkflowOptions{ID: "x"}` dans `cmd/rempart-worker`.
- `TestLinknameRefusedEverywhere` (`no-linkname`) : `linkname_in_cmd` (`import _ "unsafe"`, cible `runtime.nanotime`), `linkname_in_internal` (`internal/llm/clock.go`), `linkname_pull_from_loops` (cible `.../internal/loops.RunLoop`). Conformes : `// go:linkname`, `/*go:linkname a b*/`. `TestLoopsNoReflection/linkname_directive` reste à la seule règle `loops-no-reflection`.
- `TestCmdNotImported` (`no-cmd-import`) : `workflow_imports_cmd` (`fx(loopsImp+"\n)", loopsImp+"\n\t_ \""+modulePath+"/cmd/rempart-worker/wire\"\n)")`), `internal_imports_cmd`. Conformes : `cmd/rempart-worker` important `cmd/rempart-worker/wire` ; `internal/other` important `modulePath+"/cmdx/tool"`.

`internal/llm/usage_harden_test.go`, `TestUsageRejectsInvalidCounts` (aides de `helpers_test.go`, `usage_test.go`), configuration `{MaxCorrections: 1, MaxTokensPerCall: 256, AllowFakeRoute: true}` :
- `negative_usage/<méthode>/{input,output,both}` sur `bothMethods()`, usages `(-1, 5)`, `(5, -1)`, `(-1, -1)` : `ErrProviderFailed`, message `llm: provider call failed`, `Usage` nul, `Bound == 256 + wantRequestBytes(reqs[0])`, un appel.
- `oversized/{input,output}` (`MaxReportedTokens + 1`) : idem ; `at_cap` (`MaxReportedTokens, 0`, sortie valide) : succès, `Trace.Usage` égal.
- `negative_after_correction` : hors schéma `{10, 5}` puis `(-1, 0)` : `Usage {10 5}`, `Bound == 15 + 256 + wantRequestBytes(reqs[1])`, deux appels.

`cmd/rempart-worker/harden_test.go` :
- `TestLoadConfigBoolFlagsOnce` : `ErrConfig`, `Config` nulle pour `-dev -dev`, `-dev=false -dev`, `-dev -dev=false`, `-demo-once` répété, `-dev=1`, `-dev=TRUE`, `-dev=t`, `-demo-once=0` ; `-dev=true -demo-once=true` donne `demoConfig()`.
- `TestClientOptions` : `HostPort`, `Namespace` recopiés ; `Identity` conforme à `^rempart-worker-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`, deux appels distincts ; `10.0.0.1:7233`, `localhost:7233`, `0.0.0.0:7233`, espace `Rempart` : `ErrConfig`, `reflect.ValueOf(opts).IsZero()`.
- `TestRunRefusesNonLoopback` : `t.Chdir(t.TempDir())`, ces adresses : `errors.Is(err, ErrConfig)` (pas une erreur de fichier), sortie vide.
- `TestRunDialFailureOpaque` : `t.Chdir("../..")`, adresse de `countingListener`, contexte de 3 s : `err == ErrTemporalUnavailable`, message exact sans le port, retour en moins de 10 s ; contexte annulé : même erreur en moins de 2 s.
- `TestRunDialsWithContext` : `run.go` lu par `go/parser` : ni `client.Dial`, ni `client.NewLazyClient`, ni `client.NewClient` ; un seul `client.DialContext`, premier argument `ctx`.

## 7. Critères d'acceptation

Étape A (pile `rempart-dev` démarrée) :
1. `go test -count=1 -run 'TestMakeDevUsesWait|TestDevEnvScript|TestPostgresInitScript|TestPostgresInitValidatesPasswords|TestDevPreflightScript|TestDevBootstrapScript|TestComposeOnlyThroughDevEnv|TestMakefileTargets' ./internal/archtest/` : `ok`.
2. `grep -c 'bash scripts/dev-env.sh run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml' Makefile scripts/dev-bootstrap.sh` : `Makefile:2`, `scripts/dev-bootstrap.sh:1`.
3. `grep -hE 'docker[ -]compose' Makefile scripts/*.sh scripts/dev/*.sh | grep -v '^ *#' | grep -vc 'dev-env.sh run docker compose -p rempart-dev '` : `0`.
4. `make dev OPENBAO_DEV_ROOT_TOKEN=root >/dev/null 2>&1; OPENBAO_DEV_ROOT_TOKEN=root POSTGRES_PASSWORD=weak COMPOSE_PROJECT_NAME=evil COMPOSE_FILE=/dev/null make dev >/dev/null 2>&1; echo rc=$?; curl -s --noproxy '*' -o /dev/null -w '%{http_code}\n' -H 'X-Vault-Token: root' http://127.0.0.1:8200/v1/sys/mounts; docker compose ls -a --format json | jq -r '[.[].Name] | sort | join(" ")'` : `rc=0`, `403`, `rempart-dev`.
5. `OPENBAO_DEV_ROOT_TOKEN=root COMPOSE_PROJECT_NAME=evil bash scripts/dev-env.sh run bash -c '[ "$OPENBAO_DEV_ROOT_TOKEN" != root ] && echo overridden; compgen -e | grep -c "^COMPOSE_" || true'` : `overridden`, puis `0`.
6. `DOCKER_HOST=tcp://127.0.0.1:2375 make dev-preflight; echo rc=$?` : message avec `DOCKER_HOST`, `rc=2` ; `DOCKER_CONTEXT=rempart-absent make dev-preflight; echo rc=$?` : `contexte Docker illisible`, `rc=2` ; `make dev-preflight` : `dev-preflight : Docker Engine 28 ou plus, compose v2 et démon local disponibles.`, code 0.
7. `grep -c 'dev-env.sh run go test' Makefile` : `1` ; `grep -cF "grep -v '/internal/archtest" Makefile` : `1` ; `grep -c -- '-skip' Makefile` : `0`.
8. `chmod 700 scripts/dev-env.sh; go test -count=1 -run 'TestDevEnvScript/repository/scripts_mode_755' ./internal/archtest/; chmod 755 scripts/dev-env.sh` : `ok` ; idem avec `chmod 775` : `FAIL` ; mode 755 restauré.
9. `make verify; echo rc=$?` : `rc=0`.

Étape B :
10. `go test -count=1 -run 'TestSearchAttributesRefused|TestSearchAttributeKeysRefused|TestLinknameRefusedEverywhere|TestCmdNotImported|TestLoopsNoReflection|TestLoopSourcesConform|TestKeyedLiteralsInWorkflowCode' ./internal/archtest/` : `ok`.
11. `go test -count=1 -run 'TestUsageErrorBound|TestUsageRejectsInvalidCounts' ./internal/llm/` : `ok`.
12. `go test -race -count=1 ./cmd/rempart-worker/ ./internal/llm/` : `ok`.
13. `go run ./cmd/rempart-worker -dev -dev -demo-once -llm=fake -tenant=0d3e0000-0000-4000-8000-000000000001 -temporal-address=127.0.0.1:7233 -namespace=rempart -fake-script=internal/loops/demo/testdata/scripts/converge.json; echo rc=$?` : `rempart-worker: invalid configuration: command line refused`, `rc=2`.
14. Même ligne sans le second `-dev`, avec `-temporal-address=127.0.0.1:1` et `2>&1 >/dev/null | tail -n 1` : `rempart-worker: rempart-worker: Temporal unavailable`.
15. `make -s demo 2>/dev/null | jq -e '.loop.status == "converged" and .approval.outcome == "timed_out" and .committed == false'` : `true`.
16. `make verify; echo rc=$?` : `rc=0`.
17. Mutations de la section 8, chacune seule sur une copie privée (`mktemp -d`, SHA consigné, T72), compilation vérifiée : toutes détectées.

## 8. Mutations (ancre unique dans le code livré -> remplacement)

A (critère 1) :
- A1 `Makefile` : `bash scripts/dev-env.sh run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml up` -> `docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml up`.
- A2 `Makefile` : `then bash scripts/dev-env.sh run docker compose` -> `then docker compose`.
- A3 `Makefile` : `-p rempart-dev --env-file .env.dev -f docker-compose.yml up` -> `--env-file .env.dev -f docker-compose.yml up`.
- A4 `dev-bootstrap.sh` : `compose=(bash scripts/dev-env.sh run docker compose` -> `compose=(docker compose`.
- A5 `dev-env.sh` : `if [[ $n == COMPOSE_* ]]; then unset -v "$n"; fi` -> `:`.
- A6 `dev-env.sh` : `while IFS='=' read -r k v; do export "$k=$v"; done <"$file"` -> `:`.
- A7 `postgres-init.sh` : `for v in POSTGRES_PASSWORD TEMPORAL_DB_PASSWORD` -> `for v in TEMPORAL_DB_PASSWORD`.
- A8 `dev-preflight.sh` : `if [[ -n ${DOCKER_HOST:-} ]] && ! local_endpoint "$DOCKER_HOST"; then` -> `if false; then`.
- A9 `dev-preflight.sh` : `local_endpoint "$host" || die` -> `true || die`.
- A10 `dev-preflight.sh` : `>= 28))` -> `>= 20))`.
- A11 `dev-preflight.sh` : `^unix:///[A-Za-z0-9._/-]+$` -> `^[a-z]+://.+$`.
- A12 `Makefile` : `-run '^TestDevStack' ./internal/archtest` -> `-run '^TestDevStack' ./...`.
- A13 `Makefile` : ` | grep -v '/internal/archtest$$')` -> `)` (secrets absents au premier passage : `TestDevStack*` échoue).
- A14 `Makefile` : `@bash scripts/dev-preflight.sh` -> `@true`.
- A15 `chmod 775 scripts/dev-env.sh` ; A16 `chmod o-r scripts/dev/postgres-init.sh`.

B (critères 10 à 12) :
- B1 `loopsrc.go` : `sa && isID && slices.Contains(searchKeys, k.Name)` -> `false && isID && slices.Contains(searchKeys, k.Name)`.
- B2 `loopsrc.go` : `sa := wf || cmd || c.sdkPkg[sf.Pkg]` -> `sa := wf || c.sdkPkg[sf.Pkg]`.
- B3 `loopsrc.go` : `cmd || c.sdkPkg[sf.Pkg]` -> `cmd`.
- B4 `loopsrc.go` : `case sa && slices.Contains(searchNames, n.Sel.Name):` -> `case wf && slices.Contains(searchNames, n.Sel.Name):`.
- B5 `loopsrc.go` : `(wf || cmd) && unkeyed(n)` -> `wf && unkeyed(n)`.
- B6 `loopsrc.go` : `c.add(sf, cm, "no-linkname", "go:linkname directive")` -> `_ = cm`.
- B7 `loopsrc.go` : `if under(p, c.module+"/cmd") && !under(sf.Pkg, c.module+"/cmd") {` -> `if false {`.
- B8 `client.go` : `if !validUsage(resp.Usage) {` -> `if false {`.
- B9 `client.go` : `u.OutputTokens >= 0 && ` -> vide.
- B10 `client.go` : ` && u.OutputTokens <= MaxReportedTokens` -> vide.
- B11 `client.go` : `bound += call.MaxTokens + RequestBytes(req) // (be)` -> `// (be)`.
- B12 `config.go` : `set.Var(&dev, "dev", "")` -> `set.BoolVar(&dev.v, "dev", false, "")`.
- B13 `config.go` : `o.set || (s != "true" && s != "false")` -> `s != "true" && s != "false"`.
- B14 `config.go` : `o.set || (s != "true" && s != "false")` -> `o.set`.
- B15 `run.go` : `client.DialContext(ctx, opts)` -> `client.Dial(opts)`.
- B16 `run.go` : `return ErrTemporalUnavailable // (bh)` -> `return err // (bh)`.
- B17 `run.go` : `if !loopbackAddr(cfg.TemporalAddress) || !validNamespace(cfg.Namespace) {` -> `if false {`.
- B18 `run.go` : `Identity: identity,` -> `Identity: fmt.Sprintf("%d@%s", os.Getpid(), identity),`.

## 9. Risques

Aucune boucle ni activité nouvelle : pas de fiche de boucle.
- R1 : sortie de `docker context inspect` sans argument avec `DOCKER_HOST` défini : sonde en phase tests ; repli `docker context inspect "$(docker context show)"` par amendement.
- R2 : `compgen` absent d'un bash sans complétion programmable : échec bruyant, sans fuite ; sonde.
- R3 : socket unix relayant un démon distant (`ssh -L`) : résidu accepté.
- R4 : délais gRPC de `TestRunDialFailureOpaque` : bornes larges ; B15 repose sur le contrôle statique.
- R5 : `make verify` relance `up` : valeurs identiques, aucun conteneur recréé (à constater).

## 10. Modèle de menace

- T77 : (an), (ao) soldées ; résidus : socket relayé, `DOCKER_CONFIG`, `BASH_ENV` hérité.
- T76 : (ap) soldée ; (aq) résidu, proposition 0007 (`guard_bash` : `docker compose exec ... cat`, `docker exec ... cat`, `/proc/*/environ`, `/etc/temporal/config/docker.yaml`, forme `-p rempart-dev` dans 0006).
- T73 : (bd), (bf) ; résidus : `//go:linkname` en `_test.go`, clé non identifiant. T10 : (be). T14 : `Identity` opaque. T74 : mention de `cmd/`.

## 11. Décisions ouvertes (défaut retenu, le plus strict)

1. `COMPOSE_*` retirées par `run` plutôt que refusées (même effet). 2. Socket unix local seulement ; TCP local, TLS, `ssh://`, `npipe://` refusés. 3. Majeure 28 ou plus ; Podman refusé. 4. `MaxReportedTokens = 1 << 24`. 5. `onceBool` : `true`, `false` seulement. 6. `Identity` aléatoire par processus. 7. `no-cmd-import`, `no-linkname` sur tout le module. 8. `loops-keyed-literals` étendue à `cmd/...`. 9. `postgres-init.sh` lisible et exécutable par les autres.

## 12. Tâches ordonnées

1. `test-author`, tests A (`compose_test.go`, `devscripts_test.go`, `devharden_test.go`) ; sondes R1, R2 ; rouges pour la bonne raison, références vertes.
2. Principal, impl A : scripts, `Makefile`, ligne 1 de `docker-compose.yml`, `chmod 755 scripts/dev-preflight.sh`, `docs/SETUP.md` ; critères 1 à 9.
3. `security-reviewer`, `acceptance-verifier` sur A (A1 à A16) ; commit `fix(dev): run compose through dev-env.sh and refuse remote daemons (M0-T03b)`.
4. `test-author`, tests B (`loops_t03b_test.go`, `usage_harden_test.go`, `harden_test.go`) ; rouges.
5. Principal, impl B : `loopsrc.go`, `client.go`, `config.go`, `run.go` ; critères 10 à 16.
6. `security-reviewer`, `acceptance-verifier` sur B (B1 à B18, critère 17).
7. Principal : menaces, proposition 0007, STATUS ((an) à (as) soldées sauf résidu (aq), (bd) à (bh) soldées, (bi) en M1), commit `fix(worker,archtest,llm): harden dial, flags, usage and source rules (M0-T03b)`, `phase free`, `/close-milestone M0`.

## V1

V1 (test-author, étape A, base 3287b6b) : R1 levé sans changement (Docker 29.3.1 : `docker context inspect` sans argument rend `DOCKER_HOST` s'il est défini ; contexte absent : code 1). R2 infirmé : sans `compgen` (`enable -n compgen`), `$(compgen -e)` échoue dans la liste du `for`, `set -e` ne s'applique pas, `run` exécute la commande avec les `COMPOSE_*` ; section 3, `run` : `local n` puis `for n in "${!COMPOSE_@}"; do unset -v "$n"; done` (développement bash, sans complétion) ; A5 : `for n in "${!COMPOSE_@}"; do unset -v "$n"; done` -> `:` ; `run_overrides_environment` rejoue le cas avec `BASH_ENV` qui désactive `compgen`. A12 (ancre absente) : `-count=1 -tags=integration ./internal/archtest` -> `-count=1 -tags=integration ./...`. Critère 3 : insérer `| grep -v 'docker compose version'` avant le dernier `grep` (sinon `1`, ligne de `dev-preflight.sh`). Section 4 : `makefile_test.go` modifié aussi (règle 7 exigeait `go test -tags=integration ./...`, absent de D4 ; `$$(go list ./...` accepté).
