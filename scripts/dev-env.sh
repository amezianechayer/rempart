#!/usr/bin/env bash
# Secrets de la pile de dev (M0-T03), depuis la racine du dépôt. N'affiche aucune valeur.
#   ensure          crée .env.dev s'il manque (600), puis le valide
#   run CMD [ARG]   valide .env.dev (lu une seule fois), exporte ses paires validées
#                   (prioritaires sur le shell), retire les variables COMPOSE_*, lance
#                   scripts/dev-preflight.sh si CMD est docker, exécute CMD (M0-T03b)
set -euo pipefail
umask 077
readonly file=.env.dev
readonly keys=(POSTGRES_PASSWORD TEMPORAL_DB_PASSWORD REMPART_DB_PASSWORD OPENBAO_DEV_ROOT_TOKEN)
pairs=()
die() { echo "dev-env : $*" >&2; exit 2; }
gen() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }

# check valide .env.dev en une seule lecture et garde ses paires dans pairs (V3).
check() {
  [[ -f $file && ! -L $file ]] || die "$file absent ou lien symbolique (lance make dev)."
  local mode; mode=$(stat -c %a "$file" 2>/dev/null || stat -f %Lp "$file")
  [[ $mode == 600 ]] || die "$file doit avoir les droits 600 (actuels : $mode)."
  local -a seen=(); local line n=0
  pairs=()
  while IFS= read -r line || [[ -n $line ]]; do
    n=$((n + 1))
    [[ $line =~ ^([A-Z][A-Z0-9_]*)=[0-9a-f]{64}$ ]] || die "$file : ligne $n mal formée."
    seen+=("${BASH_REMATCH[1]}")
    pairs+=("$line")
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
  local n
  for n in "${!COMPOSE_@}"; do unset -v "$n"; done
  if [[ $1 == docker ]]; then bash scripts/dev-preflight.sh >&2; fi
  builtin export -- "${pairs[@]}"
  exec "$@"
}

case "${1:-}" in
  ensure) ensure ;;
  run) shift; run "$@" ;;
  *) die "usage : dev-env.sh ensure | run CMD [ARG...]" ;;
esac
