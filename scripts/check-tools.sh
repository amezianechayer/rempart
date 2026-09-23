#!/usr/bin/env bash
# Vérifie les outils du poste de développement Rempart (voir docs/SETUP.md).
# Usage : bash scripts/check-tools.sh ; code retour 1 si un outil requis pour M0 manque.
set -u
missing=0

row() { # niveau nom commande_de_version...
  local level=$1 name=$2
  shift 2
  if command -v "$name" >/dev/null 2>&1; then
    printf '  %-14s %s\n' "$name" "$("$@" 2>&1 | head -1)"
  else
    printf '  %-14s ABSENT (%s)\n' "$name" "$level"
    if [ "$level" = "M0" ]; then missing=$((missing + 1)); fi
  fi
}

echo "Requis dès M0 :"
row M0 python3 python3 --version
row M0 git git --version
row M0 make make --version
row M0 jq jq --version
row M0 go go version
row M0 docker docker --version
row M0 golangci-lint golangci-lint --version
row M0 govulncheck govulncheck -version
row M0 gofumpt gofumpt --version
row M0 opa opa version
echo "Requis à partir de M2 ou M3 :"
row M2 conftest conftest --version
row M3 tofu tofu version
row M3 tflint tflint --version
row M3 checkov checkov --version
row M3 trivy trivy --version
row M3 infracost infracost --version
echo "Utiles :"
row option temporal temporal --version
row option gh gh --version
row option node node --version
row option aws aws --version
row option az az version
row option kubectl kubectl version --client
row option helm helm version --short

if command -v go >/dev/null 2>&1; then
  v="$(go version | awk '{print $3}' | sed 's/^go//')"
  major="${v%%.*}"
  rest="${v#*.}"
  minor="${rest%%[!0-9]*}"
  if [ "${major:-0}" -lt 1 ] || { [ "${major:-0}" -eq 1 ] && [ "${minor:-0}" -lt 23 ]; }; then
    echo "Go $v est trop ancien : 1.23 minimum."
    missing=$((missing + 1))
  fi
fi

if [ "$missing" -gt 0 ]; then
  echo "$missing outil(s) requis pour M0 manquant(s) ou trop ancien(s). Voir docs/SETUP.md."
  exit 1
fi
echo "Outils requis pour M0 : OK."
