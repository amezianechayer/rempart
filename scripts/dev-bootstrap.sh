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
