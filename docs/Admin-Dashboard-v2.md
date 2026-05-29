# Admin Console vNext

## 1. Muc tieu

Admin Console vNext mo rong Dashboard v2 thanh console van hanh day du cho Anti-DDoS Scrubbing Gateway. Man hinh dau tien van la ops console day dac, khong landing page, nhung them cac luong quan tri policy/access/snapshot can thiet de Operator va Admin lam viec truc tiep tren Control Plane.

Pham vi vNext:

- Lam moi UI bang React/Vite hien tai, khong nang major Vite.
- Dung MUI Community, MUI X Data Grid va MUI X Charts; khong dung Pro/Premium/commercial features.
- Them User Management, Rule CRUD, Whitelist CRUD, Feed CRUD, Snapshot semantic diff/rollback UI.
- Mutations co reason/audit, soft-disable thay vi physical delete cho rule/whitelist/feed.
- Khong them eBPF ABI hay data-plane contract moi.

Khong phai muc tieu cua increment nay:

- SSO/MFA/OIDC.
- User group/tenant model.
- Physical delete policy object.
- Rule engine moi hoac thay doi packet path.
- Grafana replacement; console nay bo sung workflow Control Plane.

## 2. Personas va RBAC

| Persona | Muc tieu chinh | Quyen console |
|---|---|---|
| Viewer | Theo doi tinh trang, xem services, alerts, events, feeds, snapshots | Chi doc; khong hien mutation entrypoints |
| Operator | Truc van hanh, thao tac policy/feed/snapshot rollback | Rule/whitelist/feed/service/snapshot operational actions, khong quan ly users, khong doi feed credentials |
| Admin | Quan tri access va secret references | Bao gom Operator, them user management, password reset, session revoke, Telegram config va feed credential_ref |

Nguyen tac RBAC:

- Moi mutation phai co reason.
- Viewer khong thay nut tao/sua/disable/test/sync/rollback.
- Operator/Admin duoc thao tac policy/feed van hanh.
- Chi Admin duoc tao/sua user, reset password, revoke sessions, update Telegram config va thay doi feed `credential_ref`.
- Audit khong bao gio luu raw password, plaintext token hay credential value.

## 3. Navigation

| View | Muc dich | Noi dung chinh |
|---|---|---|
| Overview | Tinh trang he thong trong 1 man hinh | Traffic charts, decision rates, Prometheus, agents, policy version, top sources/ports, anomaly/alert moi |
| Incidents | Alerting va ISP runbook | Alerts, Telegram status/test/config, delivery log, ISP escalation payload |
| Services | Protected backend service registry | Search/filter, create/edit/disable, interface metadata, apply failure |
| Rules | Rule CRUD | Data Grid, create/edit/soft-disable, thresholds, TTL, confidence, evidence |
| Whitelist | Allow-list CRUD | Data Grid, create/edit/soft-disable, global/service scope, expiry, priority |
| Detection | Observe posture | Anomalies, baselines, active rules read-only/observe |
| Reputation | Threat feed management | Feed CRUD/sync/soft-disable, run history, whitelist conflicts |
| Snapshots | Policy version control | Snapshot list, semantic diff, rollback confirm |
| Access | Local user management | Users, role/status, force password change, reset password, revoke sessions |
| Fleet | Agent va XDP fleet | Agent health, XDP mode, policy version, interfaces, map utilization, apply status |
| Investigation | Event investigation | Recent sampled events, investigate endpoint UI |

## 4. UI stack va UX

- MUI theme rieng cho ops-console: dense spacing, radius <= 8px, neutral surface, blue/teal/amber/red accent.
- MUI X Data Grid Community cho cac CRUD grids, moi grid co fixed parent height, pagination, loading/empty/error states.
- MUI X Charts cho Overview traffic shape va decision rates, chi chart khi du lieu hien co du dung.
- Khong dung nested decorative cards; page section la panels/vung full-width co noi dung ro.
- Tables/grid mobile-safe bang fixed height, horizontal overflow va width constraints.
- Drawer/form va confirm dialog la overlay noi bo trong React tree de tranh portal/aria-hidden test instability.

## 5. Feature set

### 5.1 Overview

- Hien pps, bps, cps va chart traffic shape.
- Hien decision rates chart theo action/drop/redirect/not_allowed_service neu co.
- Hien Prometheus healthy/unconfigured/error ro rang.
- Hien agent online/stale, snapshot version hien tai va latest apply status.
- Hien top source /24, top ports, decision samples, anomaly moi nhat va alert moi nhat.

### 5.2 Incidents

- Hien Telegram channel status: enabled/disabled, token present/missing, chat id.
- Admin duoc cap nhat Telegram config bang secret reference.
- Operator/Admin duoc gui test alert va evaluate ISP escalation.
- Alerts table hien severity, type, affected service, vector, status, delivery moi nhat va recommended action.
- ISP runbook la manual escalation; khong tu dong BGP/RTBH/FlowSpec.

### 5.3 Services

- Search/filter theo name, backend CIDR, output interface, owner, criticality, ports, protocol va enabled state.
- Operator/Admin co create/edit/disable flow.
- Form service mac dinh disabled de tranh apply nham.
- Output interface dropdown lay tu Agent reported interfaces; khi chon interface thi autofill ifindex/source MAC neu co.
- Khi enable service can resolved ifindex/source MAC tu interface metadata. Next-hop MAC do Agent tu resolve/cau hinh, dashboard khong cho nhap tay.
- Apply failure hien agent, policy version, stage va reason.

### 5.4 Rules

- Lazy-load `/v1/rules` khi vao tab Rules.
- Data Grid hien name, scope, action, mode, dimension, thresholds, TTL, confidence, expiry va enabled state.
- Operator/Admin tao rule moi qua drawer; edit rule hien before state hien tai; disable la soft-disable bang `DELETE /v1/rules/{id}`.
- Moi create/update/disable rebuild policy snapshot va audit before/after o backend.
- Evidence va match expression nhap bang JSON object field; invalid JSON bi chan tai UI/client.

### 5.5 Whitelist

- Lazy-load `/v1/whitelist` khi vao tab Whitelist.
- Data Grid hien CIDR, scope, service, label, owner, priority, expiry va enabled state.
- Operator/Admin create/edit/soft-disable bang existing whitelist model.
- Scope global hoac service; service scope bat buoc chon service.
- Disable giu audit/history va loai entry khoi active snapshot tiep theo.

### 5.6 Detection

- Anomalies hien service, score, confidence, signals, recommendation, TTL, source va status.
- Baselines hien service, interface, protocol/port, window, expected pps/bps/cps, confidence va approved state.
- Rules trong Detection la observe/read-only posture; CRUD nam o tab Rules rieng de tach workflow.

### 5.7 Reputation

- Feed sources hien enabled/status, active entries, conflicts, parse errors, next run va license note.
- Operator/Admin create/edit/sync/soft-disable feed source.
- Chi Admin duoc gui `credential_ref` khi create/update feed.
- Run history hien fetched/valid/parse errors/snapshot.
- Whitelist conflicts hien reputation CIDR, whitelist CIDR, source va detected time.

### 5.8 Snapshots

- Lazy-load `/v1/snapshots?include_snapshot=false`; khong keo raw snapshot vao polling overview.
- List snapshot hien version, checksum, object checksum, rollback_from, created_by, created_at.
- Semantic diff goi `/v1/snapshots/diff?from=&to=` va nhom theo services, whitelist_v4, blacklist_v4, rules, runtime/object checksum.
- Rollback tiep tuc dung endpoint hien co `/v1/snapshots/rollback`, co confirm va reason; rollback tao snapshot moi.

### 5.9 Access

- Admin xem local users tu `/v1/users`.
- Admin tao user voi role ban dau.
- Admin PATCH role/status/force_password_change de revoke/reactivate hoac dieu chinh access.
- Admin reset password bang `/v1/users/{id}/password-reset`; UI gui temporary password nhung audit/log khong luu raw value.
- Admin revoke sessions bang `/v1/users/{id}/sessions/revoke`.
- User co the doi password cua minh qua `/v1/me/password` de clear `force_password_change`.

### 5.10 Fleet va Investigation

- Fleet hien hostname, online/stale, XDP mode, active policy, DEVMAP support, latest apply, interfaces va map utilization neu co.
- Investigation hien recent sampled events va form goi `/v1/security-events/investigate?target=...`.

## 6. API contracts

Khong them migration DB bat buoc neu dung cac cot hien co: `enabled`, `status`, `force_password_change`, `password_hash`, `user_sessions.revoked_at`.

Endpoints vNext:

- Users: giu `GET/POST /v1/users`; them `PATCH /v1/users/{id}`, `POST /v1/users/{id}/password-reset`, `POST /v1/users/{id}/sessions/revoke`, `POST /v1/me/password`.
- Rules: giu `GET/POST /v1/rules`; them `PATCH /v1/rules/{id}`, `DELETE /v1/rules/{id}` soft-disable.
- Whitelist: giu `GET/POST /v1/whitelist`; them `PATCH /v1/whitelist/{id}`, `DELETE /v1/whitelist/{id}` soft-disable.
- Feeds: giu `GET/POST/PATCH/sync /v1/feed-sources`; them `DELETE /v1/feed-sources/{id}` soft-disable.
- Snapshots: them `GET /v1/snapshots/{version}` va `GET /v1/snapshots/diff?from=&to=`.

TypeScript view-models can bo sung:

- `User`, `UserUpdateInput`, `PasswordResetInput`, `OwnPasswordInput`.
- `RuleInput`, `WhitelistEntry`, `WhitelistInput`, `FeedSourceInput`.
- `SnapshotMetadata`, `SnapshotDiff`, `AuditEvent`.

## 7. Data states

| State | Yeu cau UI |
|---|---|
| Loading | Shell van render, grid/panel hien loading state khong giat layout |
| Empty | Message ngan theo tung table/view |
| Error | Inline result/banner co error body tu API, giu context hien tai |
| Stale | Freshness chip chuyen warn neu qua nguong refresh |
| Unconfigured | Prometheus/Telegram hien unconfigured/missing thay vi crash |
| Failed apply | Hien agent, policy version, stage va reason |
| Read-only | Viewer thay data nhung khong thay mutation controls |

## 8. Backlog sau vNext

- Blacklist manual CRUD neu can ngoai feed/rule flow.
- Audit browser/timeline day du.
- User self-service recovery, SSO/MFA/OIDC.
- Snapshot raw object browser va side-by-side JSON diff nang cao.
- Grafana deep links theo service/rule/agent.
- Saved filters, URL state va export CSV cho grids.
