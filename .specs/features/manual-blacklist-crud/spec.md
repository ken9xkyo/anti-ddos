# Manual Blacklist CRUD

## Summary

Manual blacklist CRUD promotes existing `manual_blacklist_entries` from create/list-only API support into a full Operator/Admin workflow in Control API and Admin Dashboard. It reuses `PolicySnapshot.BlacklistV4`; no eBPF ABI or XDP program change is required.

## Requirements

- MBLC-001: Viewer can list manual blacklist entries and filter by search text, source, enabled state and expiry state.
- MBLC-002: Operator/Admin can create, edit and soft-disable manual blacklist entries with an audit reason.
- MBLC-003: Manual blacklist action remains `drop`; non-drop actions are rejected.
- MBLC-004: Create, update and disable rebuild the policy snapshot and remove disabled/expired manual entries from the active snapshot.
- MBLC-005: Effective blacklist snapshot de-duplicates exact CIDR keys; enabled manual entries win over feed reputation for the same exact CIDR.
- MBLC-006: Feed reputation rows, including AbuseIPDB rows, are visible in the Blacklist list as read-only entries; feed source configuration remains in the `Reputation` page.

## Interfaces

- `GET /v1/blacklist?q=&source=&state=&expiry=` for the legacy/manual-only array contract
- `GET /v1/blacklist/entries?q=&source=&origin=&state=&expiry=&page=&page_size=` for the paginated combined manual/feed list
- `POST /v1/blacklist`
- `PATCH /v1/blacklist/{id}`
- `DELETE /v1/blacklist/{id}`

`DELETE` is a soft-disable and requires `X-Audit-Reason`.
Combined list feed rows are `editable=false`; manual create/update/delete endpoints only mutate `manual_blacklist_entries`.

## Verification

- PostgreSQL integration covers create/list/filter/update/disable, RBAC denial, audit and snapshot rebuild.
- Feed sync integration covers manual-vs-feed duplicate CIDR precedence and disabled-manual fallback to feed.
- Dashboard unit tests cover Blacklist tab CRUD, paginated filters, viewer read-only behavior, and read-only feed rows.
