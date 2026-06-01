# Whitelist Search & Filters

## Requirements

- WSF-001: `GET /v1/whitelist` accepts optional `q`, `scope`, `service_id`, `state`, and `expiry` query params while preserving the current no-param array response.
- WSF-002: `q` performs case-insensitive text search across CIDR, label, owner, reason, and scoped service name.
- WSF-003: `scope` supports `all`, `global`, and `service`; invalid values return a bad request.
- WSF-004: `service_id` applies an effective-service filter: global entries plus entries scoped to that service, except when combined with `scope=service`, where only service-scoped entries for that service match.
- WSF-005: `state` supports `all`, `enabled`, and `disabled`; `expiry` supports `all`, `valid`, `expired`, and `none`.
- WSF-006: Dashboard Whitelist CRUD exposes search, scope, service, state, and expiry controls and reloads from the API without changing create/edit/disable behavior.
- WSF-007: The feature does not change policy snapshot generation, whitelist mutation semantics, RBAC, Agent sync, or eBPF map contracts.

## Verification

- Backend parser tests cover defaults and invalid enum values.
- Backend PostgreSQL integration tests cover text, scope, service, state, expiry, and combined filters.
- Frontend API tests cover query encoding and default omission.
- Frontend view tests cover filter-driven reloads and existing Whitelist CRUD workflows.
