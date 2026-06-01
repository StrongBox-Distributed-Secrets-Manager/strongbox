#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
  cp .env.example .env
  audit_key="$(openssl rand -hex 32)"
  sed -i "s/change-this-64-byte-random-value/${audit_key}/" .env
fi

chmod +x bin/strongbox bin/strongbox-verify lib/shamir.py test/integration/run.sh scripts/*.sh
if [[ "${KEEP_STATE:-0}" != "1" ]]; then
  docker compose down --remove-orphans >/dev/null 2>&1 || true
fi
docker compose up -d --build --force-recreate
docker compose ps

echo
echo "StrongBox is starting behind nginx on port 8080."
public_host="$(grep '^PUBLIC_HOST=' .env | cut -d= -f2-)"
echo "Health: curl http://${public_host:-localhost}:8080/v1/sys/health"
