# Admin Dashboard

Admin Dashboard is the React/Vite operations console for the Anti-DDoS Control Plane. It renders account management for admins, owner-scoped operational views for users, read-only user config views for admin support, and global reputation management for normal admin sessions.

## Role Behavior

| Role/session | UI behavior |
|---|---|
| `user` | Can view and mutate own Services, Rules, Whitelist, Manual Blacklist, UDP Ports, Snapshots and Telegram config. |
| `admin` normal session | Can manage Accounts and Reputation feed sources/runs/conflicts. Can open `View config` for an active user. |
| `admin` view-user session | Can read target user dashboard/config data. Mutation controls are hidden and backend mutations return `403`. |

The topbar shows `username · role`. When admin is viewing user config, it also shows `viewing <username>` and `read only`.

## Navigation

| Group | Items |
|---|---|
| Operation | Dashboard, Incidents, Events |
| Configuration | Services, Rules, Whitelist, Blacklist, Reputation, UDP Ports |
| Setting | Snapshots, Accounts, Nodes |

`Accounts` is shown for admins. `Reputation` is shown only for normal admin sessions. Navigation is organized around owner-user operations.

## Main Workflows

- Login calls `POST /v1/auth/login` with `username` and `password`.
- Dashboard polling loads overview, agents, services, rules, recent security events, Telegram config and alerts.
- Feed endpoints are loaded only when `user.role === "admin"` and the session is not read-only and not viewing another user.
- Services/Rules/Whitelist/Manual Blacklist/UDP Ports/Snapshots render mutation controls only when `user.role === "user"` and `read_only` is false.
- Incidents can configure/test Telegram only for a mutable user owner context.
- Accounts lets admins create/update/revoke users, reset passwords, revoke sessions and open read-only user config context.
- Reputation lets normal admins create/update/disable/sync global feed sources and review feed runs/conflicts.
- Blacklist displays manual rows and feed-origin rows; feed-origin rows have `editable=false`.

## Backend API Contracts

| Domain | Method/path | Role/session | Semantics |
|---|---|---|---|
| Auth | `POST /v1/auth/login` | Public | Login |
| Current user | `GET /v1/me`, `POST /v1/me/password` | Authenticated | Load user or change own password |
| Admin view | `POST /v1/admin/view-user` | `admin` | Open read-only config context for active user |
| Users | `GET/POST /v1/users`, `PATCH/DELETE /v1/users/{id}`, password/session subroutes | `admin` | Account lifecycle |
| Config | Services, Rules, Whitelist, Blacklist, UDP Ports, Snapshots, Telegram | `user` owner only for mutation | Mutate own config; read-only admin context can read |
| Reputation | `/v1/feed-sources*`, `/v1/feed-runs`, `/v1/feed-conflicts` | normal `admin` session | Manage global threat feeds |
| Dashboard read | Overview, Agents, Services, Rules, Events, Alerts | Authenticated owner context | Poll dashboard data |

## Verification

- Unit/component tests: `make ui-test`
- Production build: `make ui-build`
- Backend contract tests: `go test ./internal/control -run 'RBAC|DashboardAPIIntegration|ControlCoreIntegration|Server'`
