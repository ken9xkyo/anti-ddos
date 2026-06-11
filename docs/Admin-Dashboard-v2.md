# Admin Dashboard

Trang thai: cap nhat theo RBAC `admin`/`user` khong con tenant ngay 2026-06-11.

Admin Dashboard la ops console cho Control Plane Anti-DDoS. Dashboard khong con tenant switcher, Tenants navigation, `operator`, `viewer` hay `platform_admin`. Threat Feed/Reputation ton tai lai duoi dang admin-only global.

## Role behavior

| Role | UI behavior |
|---|---|
| `user` | Thay dashboard va duoc mutation config cua chinh minh: Services, Rules, Whitelist, Manual Blacklist, UDP Ports, Snapshots va Telegram. |
| `admin` | Thay Accounts de quan ly users va Reputation de quan ly global threat feeds. Co nut `View config` de mo dashboard read-only cua mot user. Khong co mutation controls cho config cua user. |

Topbar hien `username · role`. Khi admin dang xem config user, chip hien them `viewing <username>` va `read only`.

## Navigation

| Group | Items |
|---|---|
| Operation | Dashboard, Incidents, Events |
| Configuration | Services, Rules, Whitelist, Blacklist, Reputation, UDP Ports |
| Setting | Snapshots, Accounts, Nodes |

`Accounts` chi hien voi `admin`. `Reputation` chi hien voi admin normal session; user va admin view-user context khong thay tab nay. `Tenants` khong con trong navigation.

## Main workflows

- `POST /v1/auth/login` dang nhap bang `username`/`password`, response khong co tenant fields.
- Dashboard polling goi overview, agents, services, rules, events, Telegram config va alerts. Chi admin normal session moi goi `/v1/feed-*`; user va admin view-user context khong goi feed endpoints. Dashboard khong goi `/v1/tenants*`.
- Services/Rules/Whitelist/Manual Blacklist/UDP Ports/Snapshots chi render mutation controls khi `user.role === "user"` va `read_only` khong bat.
- Telegram config/test chi cho `user` trong owner context cua chinh minh.
- Accounts cho `admin` create/update/revoke/reset password/revoke sessions va `View config`.
- `View config` goi `POST /v1/admin/view-user` voi `{ "user_id": "..." }`, sau do dashboard reload trong context read-only cua target user.
- Reputation cho `admin` create/update/disable/sync global feed source, xem run history va whitelist conflicts.
- Blacklist cua user hien ca manual rows va feed-origin rows; feed-origin rows read-only va khong co action edit/disable.

## Backend API contracts

| Domain | Method/path | Role | Semantics |
|---|---|---|---|
| Auth | `POST /v1/auth/login` | Public | Dang nhap user |
| Admin view | `POST /v1/admin/view-user` | `admin` | Mo read-only config context cua target user |
| Users | `GET /v1/users` | `admin` | List accounts |
| Users | `POST /v1/users` | `admin` | Create account |
| Users | `PATCH /v1/users/{id}` | `admin` | Update role/status/password-change flag |
| Users | `DELETE /v1/users/{id}` | `admin` | Revoke account |
| Users | `POST /v1/users/{id}/password-reset` | `admin` | Reset password va revoke sessions |
| Users | `POST /v1/users/{id}/sessions/revoke` | `admin` | Revoke sessions |
| Config | Services/Rules/Whitelist/Blacklist/UDP Ports/Snapshots/Telegram | `user` owner only | Mutation own config; admin read-only context bi `403` |
| Reputation | `/v1/feed-sources*`, `/v1/feed-runs`, `/v1/feed-conflicts` | `admin` normal session only | Quan ly global threat feeds; user va admin view-user bi `403` |
| Dashboard read | Overview/Agents/Services/Rules/Events/Alerts | Authenticated | Read owner-scoped data |

## Verification

- Unit/component tests: `make ui-test`
- Production build: `make ui-build`
- Backend contract tests: `go test ./internal/control -run 'RBAC|DashboardAPIIntegration|ControlCoreIntegration|Server'`
