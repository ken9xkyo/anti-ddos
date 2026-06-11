# Admin Dashboard

Trang thai: cap nhat theo RBAC `admin`/`user` khong con tenant ngay 2026-06-11.

Admin Dashboard la ops console cho Control Plane Anti-DDoS. Dashboard khong con tenant switcher, Tenants navigation, Threat Feed/Reputation navigation, `operator`, `viewer` hay `platform_admin`.

## Role behavior

| Role | UI behavior |
|---|---|
| `user` | Thay dashboard va duoc mutation config cua chinh minh: Services, Rules, Whitelist, Manual Blacklist, UDP Ports, Snapshots, Telegram, Baselines/Anomalies. |
| `admin` | Thay Accounts de quan ly users. Co nut `View config` de mo dashboard read-only cua mot user. Khong co mutation controls cho config cua user. |

Topbar hien `username · role`. Khi admin dang xem config user, chip hien them `viewing <username>` va `read only`.

## Navigation

| Group | Items |
|---|---|
| Operation | Dashboard, Incidents, Detections, Events |
| Configuration | Services, Rules, Whitelist, Blacklist, UDP Ports |
| Setting | Snapshots, Accounts, Nodes |

`Accounts` chi hien voi `admin`. `Tenants` va `Reputation` khong con trong navigation.

## Main workflows

- `POST /v1/auth/login` dang nhap bang `username`/`password`, response khong co tenant fields.
- Dashboard polling goi overview, agents, services, rules, events, baselines, anomalies, Telegram config va alerts. Khong goi `/v1/tenants*` hoac `/v1/feed-*`.
- Services/Rules/Whitelist/Manual Blacklist/UDP Ports/Snapshots chi render mutation controls khi `user.role === "user"` va `read_only` khong bat.
- Telegram config/test chi cho `user` trong owner context cua chinh minh.
- Accounts cho `admin` create/update/revoke/reset password/revoke sessions va `View config`.
- `View config` goi `POST /v1/admin/view-user` voi `{ "user_id": "..." }`, sau do dashboard reload trong context read-only cua target user.

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
| Dashboard read | Overview/Agents/Services/Rules/Events/Baselines/Anomalies/Alerts | Authenticated | Read owner-scoped data |

## Verification

- Unit/component tests: `make ui-test`
- Production build: `make ui-build`
- Backend contract tests: `go test ./internal/control -run 'RBAC|DashboardAPIIntegration|ControlCoreIntegration|Server'`
