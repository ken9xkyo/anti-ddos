# Admin Dashboard

Admin Dashboard is the React/Vite operations console for the Anti-DDoS Control Plane. It renders account management for admins, owner-scoped operational views for users, read-only user config views for admin support, and global reputation management for normal admin sessions.

## Role Behavior

| Role/session | UI behavior |
|---|---|
| `user` | Can view effective policy and mutate own Services, user-global/service Rules, Whitelist, Manual Blacklist, UDP Ports, and Snapshots. Cannot access Telegram configuration or Incidents. |
| `admin` normal session | Can manage Accounts, Reputation feed sources/runs/conflicts, and admin-global Rules, Whitelist, Manual Blacklist, and UDP Ports. Can view, configure, and test Telegram alerts, manage Incidents (including triggering ISP Escalations), and open `View config` for an active user. |
| `admin` view-user session | Can read target user dashboard/config data. Mutation controls are hidden and backend mutations return `403`. |

The topbar shows `username · role`. When admin is viewing user config, it also shows `viewing <username>` and `read only`.

## Navigation

| Group | Items |
|---|---|
| Operation | Dashboard, Incidents, Events |
| Configuration | Services, Rules, Whitelist, Blacklist, Reputation, UDP Ports |
| Setting | Snapshots, Accounts, Nodes |

`Accounts` and `Incidents` are shown for admins. `Reputation` is shown only for normal admin sessions. Navigation is organized around owner-user operations.

## Main Workflows

- Login calls `POST /v1/auth/login` with `username` and `password`.
- Dashboard polling loads overview, agents, services, rules, and recent security events. Telegram config and alerts are only requested and loaded if the user role is `admin`.
- Feed endpoints are loaded only when `user.role === "admin"` and the session is not read-only and not viewing another user.
- Services/Snapshots render mutation controls only for mutable user sessions.
- Rules/Whitelist/Manual Blacklist/UDP Ports render mutation controls for mutable user policy scopes and normal admin admin-global policy scopes; row actions still honor `editable=false`.
- Incidents tab allows admins to view platform alerts, configure/test Telegram integrations, and evaluate/trigger manual ISP Escalations.
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
| User config | Services, Snapshots | `user` owner only for mutation | Mutate own user-owned config; read-only admin context can read |
| Telegram config | `/v1/telegram/config`, `/v1/telegram/test` | normal `admin` session | Configure and test Telegram alert delivery |
| Alerts / Incidents | `/v1/alerts`, `/v1/alerts/*` | `admin` | List alerts, get delivery status, or trigger manual ISP Escalation |
| Policy config | Rules, Whitelist, Blacklist, UDP Ports | `user` for `user_global`/`service`, normal `admin` for `admin_global` | Mutate scoped policy; effective reads include read-only rows where applicable |
| Reputation | `/v1/feed-sources*`, `/v1/feed-runs`, `/v1/feed-conflicts` | normal `admin` session | Manage global threat feeds |
| Dashboard read | Overview, Agents, Services, Rules, Events | Authenticated owner context | Poll general dashboard data |

## Verification

- Unit/component tests: `make ui-test`
- Production build: `make ui-build`
- Backend contract and alerting tests: `make alerting-postgres-test` and `go test ./internal/control -run 'RBAC|DashboardAPIIntegration|ControlCoreIntegration|Server'`
