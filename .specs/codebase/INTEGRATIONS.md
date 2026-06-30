# External Integrations

## Database Integration

**Service:** PostgreSQL
* **Purpose:** Stores user profiles, sessions, registered nodes (agents), service interfaces, whitelists, blacklists, rules, audit logs, and incoming security events.
* **Implementation:** Integrated inside `internal/control/store.go` using `github.com/jackc/pgx/v5` and connection pooling with `pgxpool`.
* **Configuration:** Managed via the DSN string environment variable `ANTI_DDOS_DB_DSN` passed to the Control Plane.
* **Authentication:** PostgreSQL username and password (defaults to `anti_ddos` / `change-me-postgres-lab-only` for local Compose setups).

---

## Observability Integrations

**Service:** Prometheus
* **Purpose:** Scraping performance metrics from both the Node Agent and the Control API, as well as maintaining XDP metrics (e.g. packet rates, dropped packets, active whitelist entry counts).
* **Implementation:** Go HTTP handlers using `github.com/prometheus/client_golang` exposed via `/metrics`.
* **Configuration:** The metrics collection server address defaults to `0.0.0.0:9091` on the Node Agent and is embedded in the Control API HTTP listener. Prometheus is configured to query these targets via `deploy/prometheus/compose-prometheus.yml`.

**Service:** Grafana
* **Purpose:** Provides a predefined visual dashboard (`deploy/grafana/anti-ddos-p1-dashboard.json`) containing panels for system load, CPU, memory, and packet rates (passed/dropped/redirected).
* **Configuration:** Provisioned via Grafana's local provisioning folders (`deploy/grafana/provisioning/`).

---

## Alerting Integrations

**Service:** Telegram Bot API
* **Purpose:** Pushes real-time alerts to operations channels when severe security events are detected (e.g. rate limit rule matches, agent drops).
* **Implementation:** The client is implemented in [alert.go](file:///root/anti-ddos/internal/control/alert.go#L38-L100).
* **Configuration:** Calls `https://api.telegram.org` (or configured override `ANTI_DDOS_TELEGRAM_API_URL`) using HTTP POST. Credentials (Telegram Token and Chat ID) are retrieved dynamically from the database config table.
* **Security:** The database stores tokens as plaintext, but the Control API masks them (using `*****`) in UI responses.

---

## Threat Feed Integrations

**Service:** AbuseIPDB & Custom JSON feeds
* **Purpose:** Automatically pulls malicious IP lists to block or restrict traffic dynamically.
* **Implementation:** Handled in [feed.go](file:///root/anti-ddos/internal/control/feed.go).
* **Configuration:** Feeds are defined in the `feed_sources` database table. The server performs external GET requests to download raw CSV/JSON/Plaintext IP blocks.

---

## Webhooks

* **Node Agent to Control API webhook:** The Agent runs a background client loop (`RunControlSync` in [control_client.go](file:///root/anti-ddos/internal/agent/control_client.go)) which heartbeats policy state and posts security events to `/v1/security-events` on the Control API.

---

## Background Jobs

The Control API runs two asynchronous tickers started by `StartBackgroundSchedulers` in [scheduler.go](file:///root/anti-ddos/internal/control/scheduler.go#L13-L19):
1. **Rule Expiry Scheduler (`runRuleExpiryScheduler`):** Ticks every 30 seconds to expire rules (e.g., dynamic drops) whose TTL has passed.
2. **Feed Sync Scheduler (`runFeedScheduler`):** Ticks every 30 seconds to query `feed_sources` for any dynamic blacklist feeds that are due for a synchronization cycle based on their defined interval.
