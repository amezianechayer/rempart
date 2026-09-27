# M0-T03 `pile-dev` : `docker-compose.yml` et `make dev`

- Date : 2026-09-27. Auteur : `architect`. Statut : proposé.
- Sources : fiche M0-T03 (`docs/plans/M0-overview.md`) modifiée par l'amendement A1 ; ADR 0003 ; `docs/02-THREAT-MODEL.md` ; `Makefile` ; `internal/archtest` ; `docs/SETUP.md` ; `.gitignore` ; skills `go-platform-conventions`, `secrets-and-identity`.

## 0. Amendement V1 (2026-09-27, agent principal, sonde de l'étape 1)

Code de référence exécuté tel quel sur une copie privée (Docker 29.3.1, démon avec `--registry-mirror=https://mirror.gcr.io`) :
- `up -d --wait` : trois services `healthy` ; `temporal` et `tctl` présents dans `auto-setup` 1.28.1, `SKIP_DB_CREATE` et `SKIP_DEFAULT_NAMESPACE_CREATION` lus par `auto-setup.sh` ; `-dev-no-store-token` et `-dev-listen-address` connus d'OpenBao 2.4.1 (l'entrypoint ajoute déjà `-dev-root-token-id` et `-dev-listen-address`, la valeur de `command` l'emporte).
- Écart corrigé : le premier `dev-bootstrap.sh` échouait (namespace créé mais pas encore visible pour `update`) ; boucle réécrite en section 3.4 (mise à jour réessayée, création tolérée), deux exécutions consécutives : rc=0, rétention `168h0m0s`, namespaces `temporal-system` et `rempart` seulement.
- `SKIP_SETCAP` retiré : l'entrypoint d'OpenBao 2.4.1 ne le lit pas.
- Vérifié : `rempart` vers `temporal` et `temporal` vers `rempart` refusés (`User does not have CONNECT privilege`) ; `rempart` ne crée pas de table dans `public` ; `/v1/sys/health` 200 ; `sys/mounts` 403 sans jeton et avec `root` ; `lookup-self` 200 avec le jeton de `.env.dev` ; montages `cubbyhole identity secret sys` ; aucune des quatre valeurs dans `logs` ; `LogConfig.Type` `none` ; ports publiés : `127.0.0.1` seulement, `postgres` aucun.
- Le message d'échec de `TestDevStackPostgresRolesSeparated` pour une base refusée est `User does not have CONNECT privilege` (détail) sous `permission denied for database` : le test cherche l'un ou l'autre.
- Décisions de la section 11 retenues sur délégation de l'humain (« continue sans t'arrêter, fais ce qu'il faut »), réversibles : (1) D11 : HTTP sur loopback en M0 ; (2) N7 : proposition de garde `guard_bash` rédigée à la clôture (`docs/proposals/0006`) ; (3) critère 6 à cinq tests.

## 1. Objectif et périmètre

`make dev` démarre de façon idempotente PostgreSQL, Temporal et OpenBao (mode dev), sains, sans secret en clair ni port hors de `127.0.0.1`.

Dans le périmètre : fichiers de la section 3 (scripts en mode 755), tests de la section 4, section "Pile de développement" de `docs/SETUP.md`.

Hors périmètre (A1) : Transit, clés de tenants, jeton du worker (M1, T17) ; tables (M1) ; UI Temporal, `admin-tools` ; TLS et authentification de Temporal ; persistance d'OpenBao ; CI (T04).

Aucune API Go de production ni dépendance nouvelle (`go.yaml.in/yaml/v3`, `go.temporal.io/sdk` v1.49.0 déjà dans `go.mod` ; PostgreSQL interrogé par `psql` dans le conteneur). Pas d'ADR : tout est local et réversible.

## 2. Décisions (option la plus stricte)

- D1 : PostgreSQL non publié ; seuls `127.0.0.1:7233` et `127.0.0.1:8200`.
- D2 : trois services exactement (pas d'UI Temporal).
- D3 : secrets par `${VAR:?...}`, par service (moindre privilège) ; `env_file` refusé ; `.env.dev` jamais lu par make ; chargé pour les tests par `dev-env.sh run`, qui valide avant `export` (aucun `source`).
- D4 : journaux d'OpenBao coupés : la bannière dev affiche le jeton root, qu'un `docker compose logs` de l'agent enverrait au fournisseur LLM ; journaux des autres services testés.
- D5 : rôles `temporal` (propriétaire de `temporal`, `temporal_visibility`), `rempart_owner` NOLOGIN (propriétaire de `rempart`), `rempart` LOGIN (CONNECT seul : rôle applicatif non propriétaire, ADR 0003), tous `NO...` ; `REVOKE CONNECT, TEMPORARY ... FROM PUBLIC` sur les cinq bases connectables.
- D6 : namespace `rempart`, rétention 168 h, créé par le bootstrap ; pas de `default`.
- D7 : intégration en échec, jamais `t.Skip`, si une variable manque.
- D8 : compose décodé par liste blanche de clés ; ancres, alias, `<<`, étiquettes, doublons refusés.
- D9 : toute commande compose porte `--env-file .env.dev -f docker-compose.yml` (le `-f` explicite empêche la fusion d'un `override`).
- D10 : `dev-down` garde le volume (jamais `-v`).
- D11 : OpenBao en HTTP sur loopback, exception à trancher (`-dev-tls` : autorité à distribuer, gain nul sur loopback).

## 3. Code de référence

**À revérifier à l'étape 1** : empreintes (`docker buildx imagetools inspect <image:tag>` ou `docker image inspect --format '{{index .RepoDigests 0}}'`) ; variables d'`auto-setup` 1.28.1 ; CLI `temporal` dans l'image (sinon `tctl`) ; `BAO_DEV_ROOT_TOKEN_ID`, `SKIP_SETCAP`, `-dev-no-store-token` d'OpenBao 2.4.1 ; `--auth-local=peer` ; `compose exec -e PGPASSWORD` sans valeur. Empreintes d'index relevées le 2026-09-27 via `mirror.gcr.io` (Docker Hub : 429).

### 3.1 `docker-compose.yml`

```yaml
# Pile de dev (M0-T03). Toujours : docker compose --env-file .env.dev -f docker-compose.yml
name: rempart-dev

services:
  postgres:
    image: postgres:17.6@sha256:00bc86618629af00d2937fdc5a5d63db3ff8450acf52f0636ec813c7f4902929
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?run make dev}
      POSTGRES_INITDB_ARGS: "--auth-local=peer --auth-host=scram-sha-256"
      TEMPORAL_DB_PASSWORD: ${TEMPORAL_DB_PASSWORD:?run make dev}
      REMPART_DB_PASSWORD: ${REMPART_DB_PASSWORD:?run make dev}
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./scripts/dev/postgres-init.sh:/docker-entrypoint-initdb.d/10-rempart.sh:ro
    healthcheck:
      # TCP : pendant l'initialisation, le serveur n'écoute que sur le socket.
      test: ["CMD", "pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "postgres"]
      interval: 2s
      timeout: 3s
      retries: 60
    security_opt: ["no-new-privileges:true"]

  temporal:
    image: temporalio/auto-setup:1.28.1@sha256:607d68caa111338d754771efb876c92dfcdae06d056e4530bb31cd0f37406e6a
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      DB: postgres12
      DB_PORT: "5432"
      POSTGRES_SEEDS: postgres
      POSTGRES_USER: temporal
      POSTGRES_PWD: ${TEMPORAL_DB_PASSWORD:?run make dev}
      DBNAME: temporal
      VISIBILITY_DBNAME: temporal_visibility
      SKIP_DB_CREATE: "true"
      SKIP_DEFAULT_NAMESPACE_CREATION: "true"
    ports:
      - "127.0.0.1:7233:7233"
    healthcheck:
      test: ["CMD-SHELL", "temporal operator cluster health --address \"$$(hostname -i):7233\" | grep -q SERVING"]
      interval: 3s
      timeout: 5s
      retries: 60
      start_period: 30s
    security_opt: ["no-new-privileges:true"]

  openbao:
    image: openbao/openbao:2.4.1@sha256:597f62847dd382382056a1d6704d50465908c2040038c4611832a23269a67112
    command: ["server", "-dev", "-dev-listen-address=0.0.0.0:8200", "-dev-no-store-token"]
    environment:
      BAO_DEV_ROOT_TOKEN_ID: ${OPENBAO_DEV_ROOT_TOKEN:?run make dev}
    ports:
      - "127.0.0.1:8200:8200"
    healthcheck:
      test: ["CMD", "bao", "status", "-address=http://127.0.0.1:8200"]
      interval: 2s
      timeout: 3s
      retries: 30
    logging:
      driver: none
    security_opt: ["no-new-privileges:true"]

volumes:
  pgdata: {}
```

### 3.2 `scripts/dev-env.sh`

```bash
#!/usr/bin/env bash
# Secrets de la pile de dev (M0-T03), depuis la racine du dépôt. N'affiche aucune valeur.
#   ensure          crée .env.dev s'il manque (600), puis le valide
#   run CMD [ARG]   valide .env.dev, exporte ses variables, exécute CMD
set -euo pipefail
umask 077
readonly file=.env.dev
readonly keys=(POSTGRES_PASSWORD TEMPORAL_DB_PASSWORD REMPART_DB_PASSWORD OPENBAO_DEV_ROOT_TOKEN)
die() { echo "dev-env : $*" >&2; exit 2; }
gen() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }

check() {
  [[ -f $file && ! -L $file ]] || die "$file absent ou lien symbolique (lance make dev)."
  local mode; mode=$(stat -c %a "$file" 2>/dev/null || stat -f %Lp "$file")
  [[ $mode == 600 ]] || die "$file doit avoir les droits 600 (actuels : $mode)."
  local -a seen=(); local line n=0
  while IFS= read -r line || [[ -n $line ]]; do
    n=$((n + 1))
    [[ $line =~ ^([A-Z][A-Z0-9_]*)=[0-9a-f]{64}$ ]] || die "$file : ligne $n mal formée."
    seen+=("${BASH_REMATCH[1]}")
  done <"$file"
  [[ "${seen[*]}" == "${keys[*]}" ]] || die "$file : clés attendues ${keys[*]}, dans cet ordre."
}

ensure() {
  git check-ignore -q -- "$file" || die "$file n'est pas ignoré par Git : refus d'écrire."
  if [[ ! -e $file && ! -L $file ]]; then
    local tmp; tmp=$(mktemp .env.dev.XXXXXX)
    trap 'rm -f -- "$tmp"' EXIT
    for k in "${keys[@]}"; do printf '%s=%s\n' "$k" "$(gen)"; done >"$tmp"
    mv -- "$tmp" "$file"
    trap - EXIT
  fi
  check
}

run() {
  (($# > 0)) || die "usage : dev-env.sh run CMD [ARG...]"
  check
  local k v
  while IFS='=' read -r k v; do export "$k=$v"; done <"$file"
  exec "$@"
}

case "${1:-}" in
  ensure) ensure ;;
  run) shift; run "$@" ;;
  *) die "usage : dev-env.sh ensure | run CMD [ARG...]" ;;
esac
```

### 3.3 `scripts/dev/postgres-init.sh`

```bash
#!/usr/bin/env bash
# Bases et rôles distincts (M0-T03, ADR 0003), une fois sur volume vide.
# Aucun mot de passe littéral ni en argument.
set -euo pipefail
for v in TEMPORAL_DB_PASSWORD REMPART_DB_PASSWORD; do
  [[ "${!v:-}" =~ ^[0-9a-f]{64}$ ]] || { echo "postgres-init : $v absent ou mal formé." >&2; exit 2; }
done
psql -v ON_ERROR_STOP=1 --no-psqlrc --username postgres --dbname postgres <<'SQL'
SET log_min_error_statement = panic;
SET log_statement = none;
\getenv temporal_pw TEMPORAL_DB_PASSWORD
\getenv rempart_pw REMPART_DB_PASSWORD
CREATE ROLE temporal LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'temporal_pw';
CREATE ROLE rempart_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE rempart LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'rempart_pw';
CREATE DATABASE temporal OWNER temporal;
CREATE DATABASE temporal_visibility OWNER temporal;
CREATE DATABASE rempart OWNER rempart_owner;
REVOKE CONNECT, TEMPORARY ON DATABASE temporal, temporal_visibility, rempart, postgres, template1 FROM PUBLIC;
GRANT CONNECT ON DATABASE rempart TO rempart;
SQL
```

### 3.4 `scripts/dev-bootstrap.sh`

```bash
#!/usr/bin/env bash
# Préparation idempotente après up --wait (M0-T03). A1 : ni Transit, ni clé, ni jeton du worker.
set -euo pipefail
compose=(docker compose --env-file .env.dev -f docker-compose.yml)
tcli() { "${compose[@]}" exec -T temporal temporal "$@" --address temporal:7233 >/dev/null 2>&1; }
ok=
for _ in $(seq 1 60); do
  # Un namespace créé met quelques secondes à atteindre le cache : on réessaie la mise à jour (V1).
  if tcli operator namespace update --namespace rempart --retention 168h; then ok=1; break; fi
  tcli operator namespace create --namespace rempart --retention 168h || true
  sleep 2
done
[[ -n $ok ]] || { echo "dev-bootstrap : namespace Temporal rempart indisponible." >&2; exit 2; }
"${compose[@]}" exec -T openbao bao status -address=http://127.0.0.1:8200 >/dev/null \
  || { echo "dev-bootstrap : OpenBao scellé ou injoignable." >&2; exit 2; }
echo "dev-bootstrap : pile prête."
```

### 3.5 `Makefile` (tabulation de recette notée par quatre espaces)

```make
# Pile de développement (M0-T03) : dev-preflight, .env.dev, up --wait, bootstrap.
dev: dev-preflight
    @test -f .env.dev || ! docker volume inspect rempart-dev_pgdata >/dev/null 2>&1 || { echo "dev : .env.dev absent mais le volume rempart-dev_pgdata existe (voir docs/SETUP.md)." >&2; exit 2; }
    bash scripts/dev-env.sh ensure
    docker compose --env-file .env.dev -f docker-compose.yml up -d --wait --wait-timeout 240 --quiet-pull
    bash scripts/dev-bootstrap.sh

# Arrêt idempotent ; volume conservé (réinitialisation : docs/SETUP.md).
dev-down: dev-preflight
    @if [ -f .env.dev ]; then docker compose --env-file .env.dev -f docker-compose.yml down --remove-orphans; \
    elif [ -z "$$(docker ps -aq --filter label=com.docker.compose.project=rempart-dev)" ]; then echo "dev-down : aucune pile à arrêter."; \
    else echo "dev-down : conteneurs rempart-dev sans .env.dev (voir docs/SETUP.md)." >&2; exit 2; fi

verify: verify-quick
    $(MAKE) --no-print-directory dev
    bash scripts/dev-env.sh run go test -tags=integration ./...
    go tool govulncheck ./...
```

Aucune variable make nouvelle (T28).

## 4. Tests (phase tests, `test-author`)

Conventions d'`internal/archtest` : contrôles dans les `_test.go` ; sous-tests `negative_controls` (référence verbatim de la section 3 en constante, mutée par `mustReplace`, `setRecipe`, `setRuleLine`) et `repository` ; `expectProblems`, `expectError`, `readRepoFile`, `repoRoot`. Aucun message ne contient une valeur de `.env.dev`.

### 4.1 `internal/archtest/compose_test.go` (unitaires, rouges : fichier absent)

`parseCompose` : `yaml.v3` en `yaml.Node` (refus : second document, ancre, alias, `<<`, étiquette, clé en double), puis `KnownFields(true)` vers des structures limitées aux clés de 3.1 (`privileged`, `cap_add`, `network_mode`, `env_file`, `extends`, `include`... en erreur).

| Test | Contrôles (cas négatifs) |
|---|---|
| `TestComposeServices` | `name: rempart-dev` ; services `openbao postgres temporal` ; aucun autre fichier compose ni `*override*` à la racine (`extra_service`, `override_file`, `alias`, `duplicate_key`, `privileged`) |
| `TestComposeImagesPinnedByDigest` | `<dépôt>:<tag>@sha256:<64 hex>`, pas `latest`, dépôts `postgres`, `openbao/openbao`, `temporalio/auto-setup` (`no_digest`, `unknown_repository`) |
| `TestComposePortsLoopbackOnly` | `127.0.0.1:<p>:<p>` ; exactement `temporal 7233`, `openbao 8200` (`no_host_ip`, `ipv6_any`, `postgres_published`) |
| `TestComposeNoLiteralSecrets` | clé contenant `PASS`, `PWD`, `TOKEN`, `SECRET`, `KEY` : valeur exactement `${NAME:?...}` ; pas de `${` dans `command`, `healthcheck` ; par service : `postgres` trois mots de passe, `temporal` `TEMPORAL_DB_PASSWORD`, `openbao` `OPENBAO_DEV_ROOT_TOKEN` (`literal_password`, `default_value`, `temporal_gets_rempart_password`) |
| `TestComposePostgresOfficialNoAGE` `[ADR-0003]` | image `postgres` ou `docker.io/library/postgres`, majeure `17` ; ni `age`, ni `shared_preload_libraries`, ni `CREATE EXTENSION` (compose et `postgres-init.sh`) |
| `TestComposeHardening` | `no-new-privileges:true` et `healthcheck` partout ; `temporal` attend `postgres` en `service_healthy` ; `openbao` : `logging.driver: none` ; volumes : `pgdata` et le script en `:ro` (`no_nnp`, `openbao_logs_on`, `bind_rw`, `docker_socket`) |
| `TestMakeDevUsesWait` | `dev` : prérequis `dev-preflight`, ordre garde du volume, `dev-env.sh ensure`, `up -d --wait`, `dev-bootstrap.sh` ; tout `docker compose` porte `--env-file .env.dev -f docker-compose.yml` ; `dev-down` sans `-v` ; `verify` : `dev` puis `bash scripts/dev-env.sh run go test -tags=integration ./...` ; ni `include`, `source`, `cat .env`, `compose config`, `compose logs` (`no_wait`, `down_volumes`, `integration_without_env`, `bare_compose`) |

### 4.2 `internal/archtest/devscripts_test.go` (unitaires, sans Docker ni réseau)

- `TestDevEnvScript` : `t.TempDir()`, `git init -q`, `.gitignore` `.env.*`, `exec.CommandContext("bash", script, ...)`. Sous-tests : `creates_file` (600, 4 clés ordonnées, 64 hexadécimaux, distinctes) ; `idempotent` ; `output_has_no_secret` ; `not_ignored` (2, aucun fichier) ; `world_readable` (644 : 2) ; `symlink` ; `malformed_line` (`X=$(touch pwned)` : `run true` code 2, `pwned` absent) ; `missing_key` ; `run_exports` ; `run_without_command` ; `umask_first` (statique).
- `TestPostgresInitScript` (statique) : `\getenv` pour les deux mots de passe, aucun `-v` de mot de passe ; `log_min_error_statement = panic` avant le premier `CREATE ROLE` ; cinq `NO...` par rôle ; `REVOKE CONNECT, TEMPORARY` sur les cinq bases `FROM PUBLIC` ; seul `GRANT` : `CONNECT ON DATABASE rempart TO rempart` ; heredoc `<<'SQL'`.

### 4.3 `internal/archtest/devstack_integration_test.go` (`//go:build integration`)

Variable absente : `t.Fatalf` la nommant (D7). `exec.CommandContext("docker", "compose", "--env-file", ".env.dev", "-f", "docker-compose.yml", ...)` ; sorties expurgées des quatre valeurs avant `t.Log` ; contexte 60 s ; HTTP `Proxy: nil`.

- `TestDevStackTemporalHealthy` : `client.Dial` `127.0.0.1:7233`, `CheckHealth` ; `Describe("rempart")` : rétention `168h` ; `Describe("default")` : `NotFound`.
- `TestDevStackPostgresRolesSeparated` `[ADR-0003]` : `exec -T -e PGPASSWORD postgres psql -h 127.0.0.1 -U <rôle> -d <base> -tAc 'select 1'` : `rempart/rempart` OK ; `rempart` vers `temporal`, `temporal_visibility`, `postgres`, `template1` : `permission denied for database` ; `temporal/rempart` refusé ; `temporal/temporal` OK ; `FAKE-password` : `password authentication failed` (témoin). Catalogue (`-u postgres`) : aucun `rolsuper`, `rolcreatedb`, `rolcreaterole`, `rolreplication`, `rolbypassrls` ; bases connectables : `rempart` pour `rempart`, `temporal temporal_visibility` pour `temporal` ; pas d'extension `age`.
- `TestDevStackOpenBaoReady` (remplace `TestDevStackTransitReady`, A1) : `/v1/sys/health` : 200, `initialized` vrai, `sealed` faux ; `/v1/sys/mounts` sans jeton et avec `root` : 403 ; `lookup-self` avec `OPENBAO_DEV_ROOT_TOKEN` : 200 (corps jamais journalisé) ; aucun montage `transit`.
- `TestDevStackLoopbackOnly` : `port temporal 7233`, `port openbao 8200` sur `127.0.0.1` ; `port postgres 5432` vide ; vers chaque adresse non loopback de l'hôte (au moins une) : TCP 7233, 8200, 5432 refusé en 1 s.
- `TestDevStackLogsHaveNoSecrets` : `logs --no-color postgres temporal` sans aucune des quatre valeurs (échec nommant service et clé) ; `openbao` : `LogConfig.Type` vaut `none`.

## 5. Critères d'acceptation (racine, après impl)

`C` : `docker compose --env-file .env.dev -f docker-compose.yml`.
1. `make dev; echo rc=$?` : `rc=0`, deux fois.
2. `C ps --services --status running | sort | tr '\n' ' '` : `openbao postgres temporal `.
3. `C config --images | grep -Ec '^(docker\.io/library/)?postgres[:@]'` : `1`.
4. `grep -Eic -e 'apache/?age' -e 'create extension.*\bage\b' docker-compose.yml scripts/dev/postgres-init.sh` : `docker-compose.yml:0`, `scripts/dev/postgres-init.sh:0`.
5. `C config --format json | jq -r '.services[].ports[]?.host_ip' | sort -u` : `127.0.0.1` ; `... | jq '[.services[].ports[]?] | length'` : `2`.
6. `bash scripts/dev-env.sh run go test -tags=integration -count=1 -run TestDevStack -v ./internal/archtest/ 2>&1 | grep -c '^--- PASS: TestDevStack'` : `5` ; `grep -c -- '--- FAIL'` : `0`.
7. `git check-ignore .env.dev` : `.env.dev` ; `stat -c %a .env.dev` : `600`.
8. `DOCKER_HOST=unix:///nonexistent make dev; echo rc=$?` : message avec `docs/SETUP.md`, `rc=2`.
9. `make dev-down; echo rc=$?` : `rc=0`, deux fois ; `docker volume inspect rempart-dev_pgdata >/dev/null && echo kept` : `kept`.
10. `go test -count=1 -run 'TestCompose|TestMakeDevUsesWait|TestDevEnvScript|TestPostgresInitScript' -v ./internal/archtest/ 2>&1 | grep -c '^--- PASS'` : `9`.
11. `make dev >"$S/dev.log" 2>&1; bash scripts/dev-env.sh run bash -c 'for k in POSTGRES_PASSWORD TEMPORAL_DB_PASSWORD REMPART_DB_PASSWORD OPENBAO_DEV_ROOT_TOKEN; do grep -qF -- "$(printenv "$k")" "$1" && echo "LEAK $k"; done; echo checked' _ "$S/dev.log"` (`S` : scratchpad) : `checked` seul.
12. `make verify-quick` et `make verify` : `rc=0` ; `git diff --exit-code HEAD -- go.mod go.sum` : `rc=0`.
13. `wc -c < docs/plans/M0-pile-dev.md` : au plus 25000.

## 6. Mutations (une à la fois, copie privée `mktemp -d`, T72)

1 à 19 : `go test -count=1 ./internal/archtest/` échoue. 20 à 23 : sur la pile (ports fixes) après `make dev-down`, `docker volume rm rempart-dev_pgdata`, `make dev`, le critère 6 échoue.

| # | Ancre : mutation | Détectée par |
|---|---|---|
| 1 | `"127.0.0.1:7233:7233"` : `"7233:7233"` | `PortsLoopbackOnly` |
| 2 | `"127.0.0.1:8200:8200"` : `"0.0.0.0:8200:8200"` | idem |
| 3 | `postgres` : `ports: ["127.0.0.1:5432:5432"]` | idem |
| 4 | `openbao/openbao:2.4.1@sha256:...` : empreinte retirée | `ImagesPinnedByDigest` |
| 5 | `POSTGRES_PWD: ${...}` : `FAKE-dev-password` | `NoLiteralSecrets` |
| 6 | `temporal` : `REMPART_DB_PASSWORD: ${REMPART_DB_PASSWORD:?x}` | idem |
| 7 | `${OPENBAO_DEV_ROOT_TOKEN:?run make dev}` : `:-root` | idem |
| 8 | `postgres:17.6@...` : `apache/age:PG17_latest@sha256:<64 hex>` | `PostgresOfficialNoAGE` |
| 9 | `openbao` : `privileged: true` | `ComposeServices` |
| 10 | `logging: driver: none` retiré | `ComposeHardening` |
| 11 | `security_opt` de `temporal` retiré | idem |
| 12 | `service_healthy` : `service_started` | idem |
| 13 | `up -d --wait --wait-timeout 240` : `up -d` | `MakeDevUsesWait` |
| 14 | `dev: dev-preflight` : `dev:` | idem |
| 15 | `down --remove-orphans` : `down -v --remove-orphans` | idem |
| 16 | `bash scripts/dev-env.sh run go test ...` : `go test ...` | idem |
| 17 | `[[ $mode == 600 ]] \|\| die` retiré | `DevEnvScript/world_readable` |
| 18 | `=[0-9a-f]{64}$` : `=.*$` | `DevEnvScript/malformed_line` |
| 19 | `git check-ignore -q -- "$file" \|\| die` retiré | `DevEnvScript/not_ignored` |
| 20 | `REVOKE CONNECT, TEMPORARY ...` retiré | `PostgresInitScript`, `PostgresRolesSeparated` |
| 21 | ajout `GRANT CONNECT ON DATABASE temporal TO rempart;` | idem |
| 22 | rôle `rempart` : `BYPASSRLS` | idem |
| 23 | `--retention 168h` (deux) : `24h` | `TemporalHealthy` |

## 7. Sécurité

- Ports sur `127.0.0.1` seulement (compose et interfaces de l'hôte) ; aucun secret littéral ni défaut (`:?`) ; mot de passe jamais en argument (`\getenv`, `-e PGPASSWORD` sans valeur) ; `log_min_error_statement = panic` à l'initialisation.
- `.env.dev` : `umask 077`, `mktemp` puis `mv`, 600 vérifié à chaque usage, lien refusé, écriture refusée hors `.gitignore`, format validé avant `export` ; lecture interdite à l'agent (`.claude/settings.json`).
- Jeton root OpenBao jamais affiché : aléatoire (`root` refusé, testé), journaux coupés, `-dev-no-store-token` ; règle ajoutée à `docs/SETUP.md` : jamais `docker compose config` sans `jq`, ni `docker inspect` sans `--format` ciblé.
- Rôles distincts, `REVOKE CONNECT ... FROM PUBLIC`, rôle applicatif non propriétaire ; images par empreinte (T6) ; `no-new-privileges`.

## 8. Impact sur le modèle de menace

- **N2 révisée** : section 7 ; jeton du worker et `TestDevStackTransitReady` reportés en M1 (A1, notés en T15, T17) ; preuves : `TestComposePortsLoopbackOnly`, `TestComposeNoLiteralSecrets`, `TestDevStack*`.
- **N7 nouvelle** (I) : secrets de la pile recopiés dans le contexte de l'agent, donc chez le fournisseur LLM, par `logs`, `config` ou `inspect`. Atténuations : D4, lecture de `.env.*` interdite, test des journaux ; résidu : `config`, `inspect` ; garde `guard_bash` à proposer.
- **N8 nouvelle** (T, E) : compose substitué ou fusionné (`override`, `.env` lu d'office, `COMPOSE_FILE`, `COMPOSE_PROJECT_NAME`) qui republie un port. Atténuations : D9, fichiers concurrents refusés ; résidu : variables `COMPOSE_*`.
- T18 : `TestComposePortsLoopbackOnly` livré ; résidu dev : Temporal sans authentification, OpenBao en HTTP, sur loopback.

## 9. Risques

- 429 de Docker Hub : miroir du démon documenté dans `docs/SETUP.md`.
- `auto-setup` différent (variables, CLI) : sonde de l'étape 1 ; repli `tctl` ou namespace de l'image avec attente bornée.
- `auto-setup` qui journalise le mot de passe : `LogsHaveNoSecrets` ; si rouge, journaux coupés pour `temporal`.
- Aucune interface non loopback : `LoopbackOnly` échoue, humain consulté, jamais de saut.
- `.env.dev` perdu, volume gardé : garde de `make dev`, procédure dans `docs/SETUP.md`.

## 10. Tâches ordonnées

1. Principal : `rempart-state phase tests` ; sonde de la section 3, écarts consignés ici et dans `docs/STATUS.md`.
2. `test-author` : 4.1 à 4.3 ; rouge pour la bonne raison ; `go vet -tags=integration ./internal/archtest/` propre.
3. Principal : `git add` des tests, `phase impl`.
4. Cycle : `dev-env.sh` (`TestDevEnvScript`).
5. Cycle : `postgres-init.sh`, `docker-compose.yml` (`TestCompose*`, `TestPostgresInitScript`).
6. Cycle : `dev-bootstrap.sh`, `Makefile` (`TestMakeDevUsesWait`, `TestMakefileTargets`) ; critères 1 à 5, 7 à 9, 11.
7. Cycle : intégration (critère 6) ; `docs/SETUP.md`.
8. Mutations ; `security-reviewer` (N2, N7, N8) ; `acceptance-verifier` (1 à 13).
9. Principal : `docs/STATUS.md`, commit `feat(dev): docker compose dev stack with loopback-only ports and generated secrets (M0-T03)`, `phase free`.

## 11. Décisions humaines requises

1. D11 : HTTP sur loopback, ou `-dev-tls`.
2. N7 : garde `guard_bash` contre `config`, `logs`, `inspect` non filtrés.
3. Critère 6 à cinq tests au lieu de trois (A1 remplace Transit ; `LoopbackOnly`, `LogsHaveNoSecrets` ajoutés).
