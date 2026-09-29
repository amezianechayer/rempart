#!/usr/bin/env bash
# Tests de non-régression des hooks Rempart. Usage : bash .claude/hooks/test_hooks.sh
# Travaille dans un projet temporaire : n'écrit rien dans le vrai dépôt. Code retour 0 si tout passe.
# Les cas qui demandent Go, gofmt ou make sont sautés (et signalés) si l'outil est absent.
set -u
SRC="$(cd "$(dirname "$0")/../.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/.claude/state" "$T/docs"
cp -r "$SRC/.claude/hooks" "$SRC/.claude/bin" "$T/.claude/"
rm -rf "$T/.claude/hooks/__pycache__"
printf '# STATUS\n' > "$T/docs/STATUS.md"
(cd "$T" && git init -q && git -c core.autocrlf=false -c user.name=t -c user.email=t@t commit -q --allow-empty -m init)

native() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }
TN="$(native "$T")"
export CLAUDE_PROJECT_DIR="$TN" PYTHONUTF8=1 PYTHONIOENCODING=utf-8
PY=""
for p in python3 python py; do "$p" -c 'import sys' >/dev/null 2>&1 && { PY=$p; break; }; done
[ -n "$PY" ] || { echo "Python 3 introuvable"; exit 1; }

pass=0; fail=0; skipped=""
check() { if [ "$1" = "$2" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "ÉCHEC : $3 (attendu $1, obtenu $2)"; fi; }
hook() { sh "$T/.claude/hooks/py.sh" "$@" >/dev/null 2>&1; echo $?; }
edit_json() { "$PY" -c 'import json,sys; print(json.dumps({"tool_name":"Write","tool_input":{"file_path":sys.argv[1],"content":sys.argv[2]}}))' "$1" "${2:-x}"; }
bash_json() { "$PY" -c 'import json,sys; print(json.dumps({"tool_input":{"command":sys.argv[1]}}))' "$1"; }
edit() { check "$1" "$(edit_json "$2" "${3:-x}" | hook --fail-closed "$T/.claude/hooks/guard_edit.py")" "edit $2"; }
cmd() { check "$1" "$(bash_json "$2" | hook --fail-closed "$T/.claude/hooks/guard_bash.py")" "bash : $2"; }
phase() { printf '%s\n' "$1" > "$T/.claude/state/phase"; }
state_cmd() { (cd "$T" && "$PY" .claude/bin/rempart-state "$@" >/dev/null 2>&1); echo $?; }
K="AKIA""ABCDEFGHIJKLMNOP"

# --- guard_edit : harnais, baselines, secrets, entrée illisible
phase free
edit 2 "$TN/.claude/settings.json"
edit 2 "$TN/CLAUDE.md"
edit 2 "$TN/claude.md"
edit 2 "$TN/.claude/state/phase"
edit 2 ".claude/hooks/guard_edit.py"
edit 2 "$TN/evals/intent/baseline.json"
edit 2 "$TN/evals/intent/baseline/anthropic/model-x.json"
edit 0 "$TN/evals/intent/cases/baseline-ok.yaml"
edit 2 "$TN/.github/CODEOWNERS"
edit 0 "$TN/internal/x/x.go" "package x"
edit 2 "$TN/internal/x/x.go" "k := \"$K\""
edit 0 "$TN/internal/x/testdata/k.txt" "EXAMPLE $K"
check 2 "$(printf '{"tool_name":"Write","tool_input":{"file_path":"x.go","content":"// \xc3\x81 %s"}}' "$K" | hook --fail-closed "$T/.claude/hooks/guard_edit.py")" "secret précédé d'un caractère non ASCII"
check 2 "$(printf 'pas du json' | hook --fail-closed "$T/.claude/hooks/guard_edit.py")" "entrée illisible (fail-closed)"
if command -v cygpath >/dev/null 2>&1; then
  TW="$(cygpath -w "$T")"
  edit 2 "$TW\\.claude\\settings.json"
  edit 2 "$(printf '%s' "$TW" | tr '[:lower:]' '[:upper:]')\\.CLAUDE\\SETTINGS.JSON"
fi
# --- guard_edit : discipline TDD
phase tests
edit 2 "$TN/internal/x/x.go" "package x"
edit 0 "$TN/internal/x/x_test.go" "package x"
edit 0 "$TN/docs/plans/M0-x.md"
edit 0 "$TN/evals/intent/suite.yaml"
phase impl
edit 2 "$TN/internal/x/x_test.go" "package x"
edit 2 "$TN/evals/intent/cases/a.yaml"
edit 2 "$TN/evals/intent/suite.yaml"
edit 2 "$TN/evals/a/b/suite.yaml"
edit 2 "$TN/internal/x/x.go" "t.Skipf(\"plus tard\")"
edit 0 "$TN/internal/x/x.go" "package x"
phase free

# --- guard_bash
cmd 2 "tofu apply -auto-approve"
cmd 0 "tofu plan -out plan.bin"
cmd 2 "python3 .claude/bin/rempart-state show; tofu apply -auto-approve"
cmd 2 "python3 .claude/bin/rempart-state show && echo free > .claude/state/phase"
cmd 0 "python3 .claude/bin/rempart-state phase impl --allow-green --reason \"caractérisation : l'API existe déjà\""
cmd 0 "python .claude/bin/rempart-state show"
cmd 2 "echo free > .claude/state/phase"
cmd 2 "python -c \"open('.claude/settings.json','w').write('{}')\""
cmd 2 "python -c \"p='.claude\\\\settings.json'; open(p,'w')\""
cmd 0 "grep -n hooks .claude/settings.json 2>/dev/null"
cmd 0 "cat CLAUDE.md"
cmd 0 "ls .claude/hooks"
cmd 2 "go run ./cmd/rempart-evals --suite all --write-baseline"
cmd 2 "go run ./cmd/rempart-evals --suite all -write-baseline"
cmd 2 "make update-baseline"
cmd 2 "cp /tmp/b.json evals/intent/baseline/anthropic/m.json"
cmd 2 "sed -i s/0.9/0.1/ evals/intent/baseline.json"
cmd 2 "echo 'watch: []' > evals/a/b/suite.yaml"
cmd 2 "tee evals/intent/cases/c.yaml < /tmp/c"
cmd 0 "cat evals/intent/suite.yaml"
cmd 2 "cat .env.dev"
cmd 2 "grep POSTGRES .env.dev"
cmd 2 ". ./.env.dev"
cmd 2 "source .env.dev && env"
cmd 0 "git check-ignore .env.dev"
cmd 0 "stat -c %a .env.dev"
cmd 0 "bash scripts/dev-env.sh ensure"
cmd 2 "docker compose --env-file .env.dev -f docker-compose.yml config"
cmd 0 "docker compose --env-file .env.dev -f docker-compose.yml config --images"
cmd 0 "docker compose --env-file .env.dev -f docker-compose.yml config --format json | jq -r '.services[].ports[]?.host_ip'"
cmd 2 "docker inspect rempart-dev-openbao-1"
cmd 0 "docker inspect --format '{{.HostConfig.LogConfig.Type}}' rempart-dev-openbao-1"
cmd 2 "docker compose -f docker-compose.yml exec -T temporal env"
cmd 2 "docker compose -f docker-compose.yml logs openbao"
cmd 0 "docker compose --env-file .env.dev -f docker-compose.yml logs --no-color postgres"
cmd 2 "docker compose -p rempart-dev exec -T temporal cat /etc/temporal/config/docker.yaml"
cmd 2 "docker exec rempart-dev-postgres-1 cat /proc/1/environ"
cmd 2 "cat /proc/self/environ"
cmd 2 "docker cp rempart-dev-temporal-1:/etc/temporal/config/docker.yaml /tmp/x"
cmd 0 "docker compose -p rempart-dev exec -T temporal temporal operator namespace describe --namespace rempart"
cmd 0 "docker compose -p rempart-dev ps"
cmd 0 "make -f Makefile verify-quick"
cmd 0 "make -s -f Makefile verify"
cmd 2 "make -f other.mk verify"
cmd 2 "make -f Makefile.local verify"
cmd 2 "make -if Makefile verify"
cmd 2 "make --file=Makefile verify"
cmd 2 "git push origin +main"
cmd 2 "git push --force-with-lease origin main"
cmd 0 "git push -u origin main"
cmd 0 "git commit -m \"feat: add loop\""
cmd 2 "git commit -n -m x"
cmd 2 "rm -rf .git"
cmd 0 "rm -rf build/"
# T28 et T29 (proposition 0003)
cmd 2 'make dev-down SCENARIO=$(shell touch /tmp/x)'
cmd 2 'make evals EVAL=${shell id}'
cmd 0 "make -s opa-test POLICIES_DIR=policies"
cmd 0 'out=$(make sandbox-plan SCENARIO=demo 2>&1); echo "$out"'
cmd 0 "make sandbox-apply SCENARIO=demo"
cmd 0 "make sandbox-destroy SCENARIO=demo-2"
cmd 2 "printf 'oui\\n' | make sandbox-apply SCENARIO=demo"
cmd 2 "make -s sandbox-apply SCENARIO=demo"
cmd 2 "make SCENARIO=demo sandbox-destroy"
cmd 2 "make sandbox-apply SCENARIO=demo; echo fin"
cmd 2 "./scripts/sandbox.sh apply demo"
cmd 0 "make sandbox-plan SCENARIO=demo"
cmd 2 "gmake -s sandbox-apply SCENARIO=demo"
cmd 2 'gmake dev FOO=$(shell id)'
cmd 2 "make --no-print-directory update-baseline"
cmd 2 "make -i sandbox-apply SCENARIO=demo"
cmd 2 "make -f other.mk verify-quick"
cmd 2 "MAKEFLAGS=i make dev"
cmd 2 "make --eval=x: dev"
cmd 0 "make -s verify-quick"
cmd 0 "make -C . arch-test"
cmd 0 "make evals EVAL=demo-if"
check 2 "$(printf 'pas du json' | hook --fail-closed "$T/.claude/hooks/guard_bash.py")" "bash : entrée illisible (fail-closed)"

# --- py.sh sans Python : bloquant pour les gardes, non bloquant sinon
SHBIN="$(command -v sh)"
check 2 "$(printf '{}' | env PATH=/nonexistent "$SHBIN" "$T/.claude/hooks/py.sh" --fail-closed x.py >/dev/null 2>&1; echo $?)" "py.sh --fail-closed sans Python"
check 1 "$(printf '{}' | env PATH=/nonexistent "$SHBIN" "$T/.claude/hooks/py.sh" x.py >/dev/null 2>&1; echo $?)" "py.sh sans Python"

# --- session_start : UTF-8 et blocages résolus ignorés
printf '# STATUS\n- 2026-01-01 BLOCAGE : ancien, RÉSOLU\n- 2026-01-02 BLOCAGE : actuel\n' > "$T/docs/STATUS.md"
out="$(sh "$T/.claude/hooks/py.sh" "$T/.claude/hooks/session_start.py" 2>&1)"
check 0 "$(printf '%s\n' "$out" | sed -n '/ATTENTION/,$p' | grep -c 'RÉSOLU')" "session_start : blocage résolu non signalé"
check 1 "$(printf '%s\n' "$out" | sed -n '/ATTENTION/,$p' | grep -c 'BLOCAGE : actuel')" "session_start : blocage actif signalé"

# --- rempart-state et stop_verify (Go requis)
if command -v go >/dev/null 2>&1 && command -v gofmt >/dev/null 2>&1; then
  printf 'module example.com/t\n\ngo 1.16\n' > "$T/go.mod"
  (cd "$T" && git -c core.autocrlf=false add go.mod && git -c core.autocrlf=false -c user.name=t -c user.email=t@t commit -qm mod)
  mkdir -p "$T/internal/loops"
  LT="$T/internal/loops/loop_test.go"
  printf 'package loops\n\nimport "testing"\n\nfunc TestNew(t *testing.T) { t.Fatal("pas encore implémenté") }\n' > "$LT"
  phase tests; check 0 "$(state_cmd phase impl)" "impl accepté : test rouge dans un nouveau package"
  phase tests; check 0 "$(printf '{}' | hook "$T/.claude/hooks/stop_verify.py")" "stop en phase tests : la compilation suffit"
  printf 'package loops\n\nimport "testing"\n\nfunc TestNew(t *testing.T) { _ = New() }\n' > "$LT"
  phase tests; check 0 "$(state_cmd phase impl)" "impl accepté : fonction absente"
  phase tests; check 0 "$(edit_json "$LT" | hook "$T/.claude/hooks/post_edit_check.py")" "post_edit en phase tests : symbole absent toléré"
  phase free; check 2 "$(edit_json "$LT" | hook "$T/.claude/hooks/post_edit_check.py")" "post_edit hors phase tests : go vet appliqué"
  printf 'package loops\n\nimport "testing"\n\nfunc TestNew(t *testing.T) {}\n' > "$LT"
  phase tests; check 1 "$(state_cmd phase impl)" "impl refusé : test déjà vert"
  printf 'package loops\n\nfunc TestNew(t *testing.T) {\n' > "$LT"
  phase tests; check 1 "$(state_cmd phase impl)" "impl refusé : erreur de syntaxe"
  check 2 "$(edit_json "$LT" | hook "$T/.claude/hooks/post_edit_check.py")" "post_edit : erreur de syntaxe signalée"
  OUTSIDE="$(mktemp -d)"
  printf 'package x\n\nfunc {\n' > "$OUTSIDE/x_test.go"
  check 0 "$(edit_json "$OUTSIDE/x_test.go" | hook "$T/.claude/hooks/post_edit_check.py")" "post_edit hors du dépôt : ignoré"
  rm -rf "$OUTSIDE"
  rm -f "$LT"
  phase impl; check 0 "$(state_cmd phase tests --reason 'retour : test mal spécifié')" "retour en tests avec raison"
else
  skipped="$skipped rempart-state/stop(phase tests)/post_edit(go absent)"
fi
check 0 "$("$PY" -c "import sys; open(sys.argv[1], encoding='utf-8').read()" "$TN/docs/STATUS.md" >/dev/null 2>&1; echo $?)" "STATUS.md reste en UTF-8"

# --- stop_verify en phase free
phase free
printf 'verify-quick:\n\t@exit 1\n' > "$T/Makefile"
printf 0 > "$T/.claude/state/stop_attempts"
if command -v make >/dev/null 2>&1; then
  check 2 "$(printf '{}' | hook "$T/.claude/hooks/stop_verify.py")" "stop : verify-quick rouge bloque"
  printf 'verify-quick:\n\t@exit 0\n' > "$T/Makefile"
  check 0 "$(printf '{}' | hook "$T/.claude/hooks/stop_verify.py")" "stop : verify-quick vert passe"
  check 0 "$(printf '{}' | hook "$T/.claude/hooks/stop_verify.py")" "stop : arbre inchangé, pas de nouvelle vérification"
  printf 'verify-quick:\n\t@exit 1\n' > "$T/GNUmakefile"
  check 0 "$(printf '{}' | hook "$T/.claude/hooks/stop_verify.py")" "stop : GNUmakefile ignoré, make -f Makefile (T32)"
  rm -f "$T/GNUmakefile"
else
  check 2 "$(printf '{}' | hook "$T/.claude/hooks/stop_verify.py")" "stop : make absent compte comme un échec"
fi

echo "hooks : $pass réussis, $fail échoués${skipped:+ ; sautés :$skipped}"
[ "$fail" -eq 0 ]
