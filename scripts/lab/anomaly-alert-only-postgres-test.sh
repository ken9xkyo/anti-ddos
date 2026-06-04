#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/control_postgres.sh
. "${SCRIPT_DIR}/lib/control_postgres.sh"

run_control_postgres_test \
  "anomaly alert-only" \
  '^TestAnomalyAlertOnlyIntegration$' \
  "anomaly-alert-only" \
  "anomaly_alert_only_test_password"
