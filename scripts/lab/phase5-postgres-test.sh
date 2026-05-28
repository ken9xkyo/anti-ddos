#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${ANTI_DDOS_CONTROL_TEST_DSN:-}" ]]; then
  go test ./internal/control -run TestPhase05Integration -count=1
  exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required for phase5 PostgreSQL integration test when ANTI_DDOS_CONTROL_TEST_DSN is unset" >&2
  exit 1
fi

name="anti-ddos-phase5-pg-$$"
password="phase5_test_password"
db="anti_ddos_test"

cleanup() {
  docker rm -f "${name}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run -d --rm \
  --name "${name}" \
  -e POSTGRES_PASSWORD="${password}" \
  -e POSTGRES_DB="${db}" \
  -p 127.0.0.1::5432 \
  postgres:16-alpine >/dev/null

for _ in $(seq 1 60); do
  if docker exec "${name}" pg_isready -U postgres -d "${db}" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! docker exec "${name}" pg_isready -U postgres -d "${db}" >/dev/null 2>&1; then
  echo "postgres container did not become ready" >&2
  exit 1
fi

port="$(docker port "${name}" 5432/tcp | awk -F: '{print $NF}' | head -1)"
if [[ -z "${port}" ]]; then
  echo "could not discover postgres mapped port" >&2
  exit 1
fi

ANTI_DDOS_CONTROL_TEST_DSN="postgres://postgres:${password}@127.0.0.1:${port}/${db}?sslmode=disable" \
  go test ./internal/control -run TestPhase05Integration -count=1
