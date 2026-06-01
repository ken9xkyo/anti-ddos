#!/usr/bin/env bash

run_control_postgres_test() {
  local label="$1"
  local test_regex="$2"
  local container_suffix="$3"
  local password="${4:-control_test_password}"
  local db="${ANTI_DDOS_CONTROL_TEST_DB:-anti_ddos_test}"
  local go_cmd="${GO:-go}"
  local package="${ANTI_DDOS_CONTROL_TEST_PACKAGE:-./internal/control}"
  local timeout="${ANTI_DDOS_CONTROL_TEST_TIMEOUT:-}"
  local -a go_args

  go_args=("${go_cmd}" test "${package}" -run "${test_regex}" -count=1)
  if [[ -n "${timeout}" ]]; then
    go_args+=(-timeout "${timeout}")
  fi

  if [[ -n "${ANTI_DDOS_CONTROL_TEST_DSN:-}" ]]; then
    echo "running ${label} PostgreSQL tests with ANTI_DDOS_CONTROL_TEST_DSN"
    "${go_args[@]}"
    return
  fi

  if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required for ${label} PostgreSQL tests when ANTI_DDOS_CONTROL_TEST_DSN is unset" >&2
    return 1
  fi

  local name="anti-ddos-${container_suffix}-pg-$$"
  trap "docker rm -f '${name}' >/dev/null 2>&1 || true" EXIT

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
    echo "postgres container did not become ready for ${label} tests" >&2
    return 1
  fi

  local port
  port="$(docker port "${name}" 5432/tcp | awk -F: '{print $NF}' | head -1)"
  if [[ -z "${port}" ]]; then
    echo "could not discover postgres mapped port for ${label} tests" >&2
    return 1
  fi

  echo "running ${label} PostgreSQL tests"
  ANTI_DDOS_CONTROL_TEST_DSN="postgres://postgres:${password}@127.0.0.1:${port}/${db}?sslmode=disable" \
    "${go_args[@]}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "source this file from a scripts/lab PostgreSQL test runner" >&2
  exit 2
fi
