# Admin Console vNext
> Full admin console over Control Plane APIs

Entry points:
- Frontend shell: `web/dashboard/src/DashboardShell.tsx`
- Shared MUI wrappers: `web/dashboard/src/adminUi.tsx`
- API client/types: `web/dashboard/src/api.ts`, `web/dashboard/src/types.ts`
- Backend routes: `internal/control/server.go`
- Backend mutations: `internal/control/admin_console.go`
- Snapshot diff: `internal/control/snapshot_diff.go`

Tabs added: `rules`, `whitelist`, `snapshots`, `access`.

Backend semantics:
- Rule/whitelist/feed deletes are soft-disable and rebuild policy snapshots.
- Whitelist list supports optional `q`, `scope`, `service_id`, `state`, and `expiry` query params; `service_id` is an effective-service filter that includes global entries unless `scope=service`.
- User password reset/session revoke are Admin-only.
- Feed `credential_ref` create/update is Admin-only.
- Snapshot diff compares semantic collections: services, whitelist_v4, blacklist_v4, rules, runtime/object checksum.

Frontend notes:
- Uses MUI Community, MUI X Data Grid and MUI X Charts.
- Whitelist CRUD toolbar reloads from API filters after a short debounce; default view still requests `/v1/whitelist`.
- `AdminDrawer` and `ConfirmDialog` are in-tree overlays, not MUI Portal modals, to keep tests stable and avoid aria-hidden issues.
- `JsonTextField` is native textarea because MUI TextareaAutosize hit jsdom selector issues with MUI X runtime ids.

Updated: 2026-05-29
