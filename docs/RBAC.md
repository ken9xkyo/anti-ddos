# RBAC Admin/User

Control Plane exposes two user roles: `admin` and `user`. Operational data isolation is enforced by owner context.

## Role Model

| Role | Main permissions |
|---|---|
| `user` | Read effective policy and mutate their own user-global/service policy plus Services, Snapshots, Agents/Events/Alerts and Telegram Channel. |
| `admin` | Manage account lifecycle, global threat feeds, admin-global policy, and open a read-only dashboard context for a user through Accounts. |

## Auth And Session

- `POST /v1/auth/login` accepts `username` and `password`.
- Returned `User.role` is `admin` or `user`.
- Returned sessions include token, expiry and user object.
- `POST /v1/admin/view-user` accepts `{ "user_id": "..." }` for admins and returns the same session token with `viewing_user` and `read_only=true`.
- The current user/session response includes the user object and optional read-only view context.

## Data Ownership

Operational data is scoped by `owner_user_id`:

- User request: `owner_user_id = actor.ID`.
- Admin view-user request: `owner_user_id = target user`.
- Services, forwarding policies, snapshots, Telegram and alerts call user config mutation guards; admin view-user sessions receive `403`.
- Admin account/global-feed operations use unscoped transactions where needed.

Policy configuration uses `scope_type`:

- `admin_global`: created by an admin, applies to every user, visible read-only in user effective policy views.
- `user_global`: created by a user, applies to every service owned by that user.
- `service`: created by a user, applies to one service owned by that user.

Policy rows store the creator in `owner_user_id`. Admin-global rows use the admin creator as owner, but any normal admin can manage admin-global rows. User-created rows use the user creator as owner. Client-supplied owner values are ignored on create/update.

Effective policy list APIs return:

- Normal admin: admin-global rows.
- User: admin-global rows with `editable=false` plus own user-global/service rows.
- Admin view-user: the viewed user's effective union, read-only.

The current schema uses owner-scoped indexes and composite keys for operational data. Global threat feed rows use `owner_user_id = NULL`, while feed conflicts point to the user owner affected by a whitelist overlap.

## Agent Ownership

Agent registration must identify the config owner with one of:

- `X-Owner-User-ID`
- `X-Owner-Username`

After registration, heartbeat, snapshot fetch, apply status and event ingest resolve owner from `agent_id`.

## Dashboard

- Accounts is visible to `admin`.
- Reputation is visible only to normal admin sessions.
- Normal admins see mutation controls for admin-global Rules, Whitelist, Manual Blacklist and UDP Ports in the existing policy tabs.
- Users see mutation controls for their own user-global/service policy and user-owned operational config.
- Admin view-user context shows the target user's config without mutation controls.
- User dashboards do not call feed management endpoints, but Blacklist can display feed-origin rows as read-only entries.

## Verification

Primary gates for RBAC and owner isolation:

```bash
go test ./internal/control -run 'RBAC|Migration|DashboardAPIIntegration|ControlCoreIntegration|Server'
make go-test
make ui-test
make ui-build
make control-postgres-test
```
