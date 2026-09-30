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
