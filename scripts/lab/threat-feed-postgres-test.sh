#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/control_postgres.sh
. "${SCRIPT_DIR}/lib/control_postgres.sh"

run_control_postgres_test \
  "threat feed" \
  '^TestFeedSyncIntegration$' \
  "threat-feed" \
  "threat_feed_test_password"
