#!/usr/bin/env bash
# Préparation idempotente après up --wait (M0-T03, M1-T01) : namespace Temporal, Transit, clés, politique du worker.
set -euo pipefail
compose=(bash scripts/dev-env.sh run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml)
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
# M1-T01 (D7) : le jeton root entre par l'environnement, jamais en argument ; sorties de bao muettes.
bao() { "${compose[@]}" exec -T -e OPENBAO_DEV_ROOT_TOKEN openbao sh -c 'BAO_TOKEN="$OPENBAO_DEV_ROOT_TOKEN" BAO_ADDR=http://127.0.0.1:8200 exec bao "$@"' bao "$@"; }
mounts=$(bao secrets list -format=json 2>/dev/null) || mounts=
[[ $mounts == *'"transit/"'* ]] || bao secrets enable transit >/dev/null 2>&1 \
  || { echo "dev-bootstrap : moteur Transit non monté." >&2; exit 2; }
for tenant in 0d3e0000-0000-4000-8000-000000000001 00000000-0000-8000-8000-000000000001; do
  key=transit/keys/rempart-tenant-$tenant
  bao read "$key" >/dev/null 2>&1 || bao write -f "$key" type=aes256-gcm96 >/dev/null 2>&1 \
    || { echo "dev-bootstrap : clé Transit rempart-tenant-$tenant non créée." >&2; exit 2; }
  bao write "$key/config" deletion_allowed=false >/dev/null 2>&1 \
    || { echo "dev-bootstrap : configuration de rempart-tenant-$tenant refusée." >&2; exit 2; }
done
bao policy write rempart-worker - <scripts/dev/openbao-worker.hcl >/dev/null 2>&1 \
  || { echo "dev-bootstrap : politique rempart-worker non écrite." >&2; exit 2; }
echo "dev-bootstrap : pile prête."
