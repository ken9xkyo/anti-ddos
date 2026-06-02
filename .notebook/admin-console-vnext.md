# Admin Console vNext
> Full admin console over Control Plane APIs

Entry points:
- Frontend shell: `web/dashboard/src/DashboardShell.tsx`
- Shared MUI wrappers: `web/dashboard/src/adminUi.tsx`
- API client/types: `web/dashboard/src/api.ts`, `web/dashboard/src/types.ts`
- Backend routes: `internal/control/server.go`
- Backend mutations: `internal/control/admin_console.go`
- Snapshot diff: `internal/control/snapshot_diff.go`

Navigation labels are grouped in `web/dashboard/src/navigation.ts`:
- `Operation`: Dashboard (`overview`), Incidents, Detections (`detection`), Events (`investigation`)
- `Configuration`: Services, Rules, Whitelist, Blacklist
- `Threat Intelligence`: Reputation
- `Setting`: Snapshots, Accounts (`access`), Nodes (`fleet`)

Backend semantics:
- Rule/whitelist/blacklist/feed deletes are soft-disable and rebuild policy snapshots.
- Whitelist list supports optional `q`, `scope`, `service_id`, `state`, and `expiry` query params; `service_id` is an effective-service filter that includes global entries unless `scope=service`.
- `/v1/blacklist` remains the manual-only array contract. `/v1/blacklist/entries` is the paginated combined manual/feed list with `q`, `source`, `origin`, `state`, `expiry`, `page`, and `page_size`; feed rows are read-only and feed configuration stays under `Reputation`.
- Effective blacklist snapshots de-duplicate exact CIDRs. Enabled manual entries win over feed reputation for the same exact CIDR.
- User password reset/session revoke are Admin-only.
- Feed `credential_ref` create/update is Admin-only; the store keeps raw values or legacy refs, while API/UI/audit mask non-empty values as `***`.
- Snapshot diff compares semantic collections: services, whitelist_v4, blacklist_v4, rules, runtime/object checksum.

Frontend notes:
- Uses MUI Community, MUI X Data Grid and MUI X Charts.
- Whitelist CRUD toolbar reloads from API filters after a short debounce; default view still requests `/v1/whitelist`.
- Blacklist CRUD uses server-side pagination against `/v1/blacklist/entries`; manual rows keep drawer edit/create and soft-disable, while feed rows render `feed read only`.
- `AdminDrawer` and `ConfirmDialog` are in-tree overlays, not MUI Portal modals, to keep tests stable and avoid aria-hidden issues.
- `JsonTextField` is native textarea because MUI TextareaAutosize hit jsdom selector issues with MUI X runtime ids.

Updated: 2026-06-02
