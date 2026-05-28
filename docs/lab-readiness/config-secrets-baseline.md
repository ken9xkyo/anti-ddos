# Phase 00 Config And Secret Baseline

Date: 2026-05-28

This baseline defines the minimum configuration and secret handling rules for later implementation phases. It intentionally uses references for secrets and does not store raw credentials.

## Required Environment Keys

| Key | Required by | Purpose | Example value | Secret? |
|---|---|---|---|---|
| `ANTI_DDOS_WAN_IFACE` | Agent/XDP attach | WAN ingress interface receiving protected traffic | `<wan-iface>` | No |
| `ANTI_DDOS_LAN_IFACE` | Agent/forwarding | Backend-facing interface, when a single default LAN interface is used | `<lan-iface>` | No |
| `ANTI_DDOS_OUTPUT_IFACE` | Agent/forwarding | Default output interface for lab policies; per-service config may override later | `<output-iface>` | No |
| `ANTI_DDOS_API_URL` | Agent/dashboard | Control Plane API base URL | `http://127.0.0.1:8080` | No |
| `ANTI_DDOS_DB_DSN_SECRET_REF` | Control API | Reference to PostgreSQL DSN | `secret://anti-ddos/db_dsn` | Yes, by reference only |
| `ANTI_DDOS_METRICS_ADDR` | Agent/API | Prometheus scrape bind address | `127.0.0.1:9091` | No |
| `ANTI_DDOS_TELEGRAM_TOKEN_SECRET_REF` | Alert service | Reference to Telegram bot token | `secret://anti-ddos/telegram_bot_token` | Yes, by reference only |
| `ANTI_DDOS_ABUSEIPDB_KEY_SECRET_REF` | Feed sync | Reference to AbuseIPDB API key | `secret://anti-ddos/abuseipdb_key` | Yes, by reference only |
| `ANTI_DDOS_INTERNAL_FEED_URL` | Feed sync | Internal HTTP JSON feed endpoint | `https://feeds.example.invalid/anti-ddos.json` | Usually no; validate deployment-specific auth |

## Non-Secret Runtime Config

These values may appear in plain config, audit diffs, and dashboard views:

- Interface names and ifindexes.
- XDP mode selection: `native`, `generic`, or explicit disabled/diagnostic mode.
- Metrics bind address and scrape interval.
- Policy version, checksum, map capacity limits, sample rate denominator, and attach mode.
- Protected service metadata that is not confidential: service name, owner, criticality, protocol, allowed ports, output interface, enabled state.
- Feed source name, type, enabled state, interval, license note, quota metadata without credentials.

## Secret Handling Rules

- Store only secret references in repo files, environment templates, audit records, and API responses.
- Never commit raw PostgreSQL DSNs, Telegram tokens, AbuseIPDB keys, internal feed credentials, session secrets, password hashes, or bootstrap one-time secrets.
- Log secret resolution status as `present`, `missing`, or `invalid`; do not log secret values.
- Audit before/after diffs must show secret reference changes, not secret material.
- Dashboard and API responses must redact any field classified as secret or token-like.
- Test fixtures must use fake values that cannot be mistaken for live credentials.

## Redaction Baseline

Implement redaction for field names containing:

- `token`
- `secret`
- `password`
- `passwd`
- `dsn`
- `api_key`
- `apikey`
- `authorization`
- `cookie`
- `session`

Implement redaction for values matching token-like patterns:

- HTTP `Authorization` header values.
- URL query parameters named `token`, `key`, `api_key`, `apikey`, `password`, or `secret`.
- Telegram bot token-shaped values.
- DSN values containing a username/password segment.

Recommended replacement string: `[REDACTED]`.

## Example Non-Secret Env Template

```dotenv
ANTI_DDOS_WAN_IFACE=<wan-iface>
ANTI_DDOS_LAN_IFACE=<lan-iface>
ANTI_DDOS_OUTPUT_IFACE=<output-iface>
ANTI_DDOS_API_URL=http://127.0.0.1:8080
ANTI_DDOS_DB_DSN_SECRET_REF=secret://anti-ddos/db_dsn
ANTI_DDOS_METRICS_ADDR=127.0.0.1:9091
ANTI_DDOS_TELEGRAM_TOKEN_SECRET_REF=secret://anti-ddos/telegram_bot_token
ANTI_DDOS_ABUSEIPDB_KEY_SECRET_REF=secret://anti-ddos/abuseipdb_key
ANTI_DDOS_INTERNAL_FEED_URL=https://feeds.example.invalid/anti-ddos.json
```

## Feed Readiness Notes

P1 production readiness requires configured sources for:

- Spamhaus DROP.
- Team Cymru bogon.
- AbuseIPDB.
- Internal HTTP JSON feed.

Each feed source must record enabled state, interval, license note, quota metadata, last success, last error, active entry count, and credential secret ref when credentials are required.

## Config Validation Rules For Later Phases

- Interface names must exist on the host before attach/apply.
- Output interface must be UP before publishing a redirect service policy.
- Protected service policies must not use an unresolved neighbor/MAC target.
- `ANTI_DDOS_METRICS_ADDR` must not conflict with the Control API bind address.
- Secret refs must resolve before the feature requiring them is marked ready.
- Missing Telegram/feed secrets may allow local development, but must block production readiness for features that require them.

