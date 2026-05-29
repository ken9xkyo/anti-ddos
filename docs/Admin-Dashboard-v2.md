# Admin Dashboard v2 / Admin Console vNext

Trang thai: da cap nhat theo implementation Admin Console vNext trong working tree ngay 2026-05-29.

Tai lieu nay mo ta dashboard/admin console sau khi Dashboard v2 duoc mo rong thanh console van hanh day du cho Anti-DDoS Scrubbing Gateway. Day la spec san pham + contract trien khai, khong phai landing-page brief.

## 1. Muc tieu

Admin Console vNext la giao dien ops console day dac, chuyen nghiep, dung cho Viewer, Operator va Admin lam viec truc tiep voi Control Plane.

Muc tieu chinh:

- Giu man hinh dau tien la console van hanh, khong co landing page.
- Cho phep quan sat he thong, dieu tra event, quan tri policy, feed, snapshot va local access trong mot shell thong nhat.
- Dung React/Vite hien tai, khong nang major Vite.
- Dung MUI Community, MUI X Data Grid va MUI X Charts; khong dung Pro/Premium/commercial features.
- Tat ca mutation quan trong phai co reason va audit.
- Delete rule/whitelist/feed la soft-disable de giu audit/history va giam rui ro rollback/FK.
- Khong them eBPF ABI, data-plane contract hoac packet-path semantics moi.

Ngoai pham vi increment nay:

- SSO/MFA/OIDC va tenant/group model.
- Physical delete policy object.
- Rule engine moi hoac thay doi XDP/eBPF data path.
- Grafana replacement.
- Raw snapshot browser day du va audit timeline day du.

## 2. Requirement traceability

| ID | Requirement | Trang thai | Verification |
|---|---|---|---|
| AD2-REQ-001 | Dashboard la ops console, khong landing page | Done | Shell render truc tiep sau login |
| AD2-REQ-002 | MUI Community + MUI X Data Grid + MUI X Charts tren React/Vite hien tai | Done | `package.json`, build gate |
| AD2-REQ-003 | Viewer read-only, Operator/Admin operational mutations, Admin access/secret mutations | Done | Vitest RBAC coverage |
| AD2-REQ-004 | User Management console | Done | Access tab + Go endpoints |
| AD2-REQ-005 | Rule CRUD voi soft-disable | Done | Rules tab + Go endpoints |
| AD2-REQ-006 | Whitelist CRUD voi soft-disable | Done | Whitelist tab + Go endpoints |
| AD2-REQ-007 | Feed CRUD/sync/soft-disable, Admin-only credential_ref | Done | Reputation tab + Go endpoints |
| AD2-REQ-008 | Snapshot semantic diff va rollback confirm | Done | Snapshots tab + Go endpoints |
| AD2-REQ-009 | Next-hop MAC khong nhap tay tren dashboard; Agent tu resolve/cau hinh | Done | Services form/test + doc policy |
| AD2-REQ-010 | Audit khong luu raw password/credential value | Done | Go integration coverage |

## 3. Personas va RBAC

| Persona | Muc tieu | Quyen UI/API |
|---|---|---|
| Viewer | Theo doi tinh trang, xem services, alerts, events, feeds, snapshots | Chi doc; khong hien nut create/edit/disable/sync/test/rollback |
| Operator | Truc van hanh va thay doi policy runtime | Service, rule, whitelist, feed operational actions, snapshot rollback, alert test/runbook; khong quan ly users, khong doi credentials |
| Admin | Quan tri access va secret references | Bao gom Operator; them user management, password reset, session revoke, Telegram config, feed `credential_ref` |

Nguyen tac:

- Moi mutation phai co `reason` trong body hoac `X-Audit-Reason`.
- UI khong render mutation control cho Viewer.
- Backend van enforce RBAC; UI chi la lop bao ve dau tien.
- Admin khong duoc vo tinh revoke/ha cap admin active cuoi cung.
- Password va credential value khong duoc ghi raw vao audit/log/response.

## 4. Navigation

| View | Nhom | Muc dich | Data loading |
|---|---|---|---|
| Overview | Operations | Tong quan traffic, decisions, health, current signal | Polling dashboard endpoints |
| Incidents | Operations | Alerting, Telegram, ISP manual runbook | Polling dashboard endpoints + mutation theo action |
| Services | Policy | Protected service registry | Polling dashboard endpoints |
| Rules | Policy | Rule CRUD | Lazy-load `/v1/rules` khi vao tab |
| Whitelist | Policy | Allow-list CRUD | Lazy-load `/v1/whitelist` khi vao tab |
| Detection | Policy | Observe anomalies/baselines/active rules | Polling dashboard endpoints, read-only posture |
| Reputation | Intelligence | Feed CRUD/sync + run/conflict visibility | Polling feed summary + lazy/action refresh |
| Snapshots | Control | Snapshot list, semantic diff, rollback | Lazy-load `/v1/snapshots?include_snapshot=false` |
| Access | Control | Local user management | Lazy-load `/v1/users` khi vao tab |
| Fleet | Infrastructure | Agents, XDP mode, interfaces, map utilization | Polling dashboard endpoints |
| Investigation | Infrastructure | Sampled event search | Recent events + `/v1/security-events/investigate` |

Top bar:

- Hien username/role.
- Freshness chip dua tren `lastRefresh`.
- Refresh action.
- Logout action.

## 5. UI stack va design constraints

Frontend stack:

- React `18.3.1`.
- Vite `5.4.11`; khong nang major Vite trong increment nay.
- MUI Material `^9.0.1`.
- MUI X Data Grid `^9.3.0`.
- MUI X Charts `^9.3.0`.
- `react-is` pin/override `18.3.1` de phu hop React version cua project.

UX constraints:

- Ops-console dense layout, khong hero/landing page.
- Radius <= 8px.
- Palette tiet che: neutral surface, blue/teal/amber/red accent theo trang thai.
- Khong dung nested decorative cards.
- Data Grid phai co parent height on dinh de tranh layout shift.
- Table/grid mobile-safe bang width constraints va horizontal overflow noi bo.
- Drawer/form va confirm dialog nam trong React tree, tranh portal instability trong jsdom tests.
- Empty/loading/error state phai ro, khong lam mat context hien tai.

## 6. Feature spec

### 6.1 Overview

Muc tieu: mot man hinh cho tinh trang Control Plane va data plane signal.

Hien thi:

- Metric cards: pps, bps, cps, agent healthy, drop rate, redirect rate, service miss, anomaly score.
- MUI X Charts: traffic shape va decision rates.
- Prometheus state: healthy, unconfigured, error.
- Snapshot version hien tai va latest apply status theo agent.
- Top source /24, top ports, decision samples.
- Alert moi nhat va anomaly moi nhat.

### 6.2 Incidents

Hien thi:

- Alerts table voi severity, type, affected service, vector, status, delivery moi nhat va recommended action.
- Telegram status: enabled/disabled, token present/missing, chat id.
- ISP escalation payload/runbook cho manual operation.

Actions:

- Operator/Admin duoc gui test alert.
- Operator/Admin duoc evaluate ISP escalation.
- Admin duoc update Telegram config bang secret reference.
- Khong tu dong BGP/RTBH/FlowSpec trong dashboard.

### 6.3 Services

Hien thi:

- Search/filter theo name, backend CIDR, protocol, ports, output interface, owner, criticality, enabled state.
- Apply failure table hien agent, policy version, stage, reason.

Actions:

- Operator/Admin create/edit/disable service.
- Form create mac dinh disabled de tranh apply nham.
- Output interface selector lay tu Agent reported interfaces.
- Khi chon interface, UI autofill `resolved_ifindex` va `resolved_src_mac` neu metadata co san.
- Khi enable service, UI yeu cau ifindex/source MAC hop le tu metadata.
- Next-hop MAC khong co input thu cong. Agent tu resolve/cau hinh next-hop MAC trong snapshot/apply path.

### 6.4 Rules

Hien thi:

- MUI X Data Grid cho name, service/scope, action, mode, dimension, thresholds, TTL, confidence, expiry, enabled.
- Empty/loading/error state rieng cho tab.

Actions:

- Operator/Admin create rule.
- Operator/Admin edit rule.
- Operator/Admin soft-disable bang `DELETE /v1/rules/{id}`.
- Evidence va match expression la JSON object field; invalid JSON bi chan tai UI.
- Backend rebuild policy snapshot va audit before/after cho create/update/disable.

### 6.5 Whitelist

Hien thi:

- MUI X Data Grid cho CIDR, scope, service, label, owner, priority, expiry, enabled.

Actions:

- Operator/Admin create whitelist entry.
- Operator/Admin edit whitelist entry.
- Operator/Admin soft-disable bang `DELETE /v1/whitelist/{id}`.
- Scope `global` khong can service; scope `service` can service_id.
- Disabled entry khong vao active snapshot tiep theo nhung van giu history.

### 6.6 Detection

Muc tieu: observe posture, khong pha tron voi CRUD workflow.

Hien thi:

- Anomalies: service, score, confidence, signals, recommendation, proposed TTL, source, status.
- Baselines: service, interface, protocol/port, window, expected pps/bps/cps, confidence, approval.
- Active rules: read-only posture. CRUD nam o tab Rules.

### 6.7 Reputation

Hien thi:

- Feed sources: enabled/status, active entries, conflicts, parse errors, next run, license note.
- Feed run history: fetched, valid, parse errors, snapshot version.
- Whitelist conflicts: reputation CIDR, whitelist CIDR, source, detected time.

Actions:

- Operator/Admin create/edit/sync/soft-disable feed source.
- Chi Admin duoc create/update `credential_ref`.
- Soft-disable bang `DELETE /v1/feed-sources/{id}`.
- Sync bang `POST /v1/feed-sources/{id}/sync`.

### 6.8 Snapshots

Hien thi:

- Snapshot list tu `/v1/snapshots?include_snapshot=false`.
- Columns: version, checksum, object_checksum, rollback_from, created_by, created_at.
- Semantic diff grouped by services, whitelist_v4, blacklist_v4, rules, runtime/object checksum.

Actions:

- Operator/Admin rollback snapshot bang confirm dialog va reason.
- Rollback goi `/v1/snapshots/rollback` va tao snapshot moi tu selected version.
- Raw snapshot khong bi keo vao polling overview mac dinh.

### 6.9 Access

Hien thi:

- Local users tu `/v1/users`.
- Columns: username, role, status, force_password_change, last_login_at, created_at.

Actions:

- Admin create user voi role ban dau.
- Admin PATCH role/status/force_password_change.
- Admin reset password bang `/v1/users/{id}/password-reset`.
- Admin revoke sessions bang `/v1/users/{id}/sessions/revoke`.
- Backend co `/v1/me/password` de user doi password va clear `force_password_change`; dedicated self-service UI la backlog nho neu can expose trong topbar/profile.

### 6.10 Fleet

Hien thi:

- Hostname, online/stale, XDP mode, DEVMAP support, active policy version.
- Latest apply status.
- Interfaces: name, role, ifindex, MAC, link speed.
- Map utilization neu agent report.

### 6.11 Investigation

Hien thi:

- Recent sampled events tu dashboard polling.
- Form target goi `/v1/security-events/investigate?target=...&limit=50`.
- Result table giu cung format voi recent events.

## 7. Backend API contracts

Khong can migration moi neu dung cac cot hien co: `enabled`, `status`, `force_password_change`, `password_hash`, `user_sessions.revoked_at`.

| Domain | Method/path | Role | Semantics |
|---|---|---|---|
| Auth | `POST /v1/auth/login` | Public | Dang nhap local user |
| Me | `GET /v1/me` | Authenticated | Lay current user |
| Me | `POST /v1/me/password` | Authenticated | Doi password, clear force change, revoke sessions khac |
| Users | `GET /v1/users` | Admin | List local users |
| Users | `POST /v1/users` | Admin | Create user |
| Users | `PATCH /v1/users/{id}` | Admin | Update role/status/force_password_change |
| Users | `DELETE /v1/users/{id}` | Admin | Legacy revoke user route |
| Users | `POST /v1/users/{id}/password-reset` | Admin | Reset password, revoke sessions |
| Users | `POST /v1/users/{id}/sessions/revoke` | Admin | Revoke active sessions |
| Rules | `GET /v1/rules` | Authenticated | List rules |
| Rules | `POST /v1/rules` | Operator/Admin | Create rule, rebuild snapshot |
| Rules | `PATCH /v1/rules/{id}` | Operator/Admin | Update rule, rebuild snapshot |
| Rules | `DELETE /v1/rules/{id}` | Operator/Admin | Soft-disable rule, rebuild snapshot |
| Whitelist | `GET /v1/whitelist` | Authenticated | List whitelist entries |
| Whitelist | `POST /v1/whitelist` | Operator/Admin | Create entry, rebuild snapshot |
| Whitelist | `PATCH /v1/whitelist/{id}` | Operator/Admin | Update entry, rebuild snapshot |
| Whitelist | `DELETE /v1/whitelist/{id}` | Operator/Admin | Soft-disable entry, rebuild snapshot |
| Feeds | `GET /v1/feed-sources` | Authenticated | List feed sources |
| Feeds | `POST /v1/feed-sources` | Operator/Admin | Create feed; `credential_ref` Admin-only |
| Feeds | `PATCH /v1/feed-sources/{id}` | Operator/Admin | Update feed; `credential_ref` Admin-only |
| Feeds | `DELETE /v1/feed-sources/{id}` | Operator/Admin | Soft-disable feed, rebuild snapshot when active state changes |
| Feeds | `POST /v1/feed-sources/{id}/sync` | Operator/Admin | Manual sync |
| Snapshots | `GET /v1/snapshots?include_snapshot=false` | Authenticated | List metadata without raw snapshot |
| Snapshots | `GET /v1/snapshots/{version}` | Authenticated | Get metadata/raw snapshot, controlled by `include_snapshot` |
| Snapshots | `GET /v1/snapshots/diff?from=&to=` | Authenticated | Semantic diff |
| Snapshots | `POST /v1/snapshots/rollback` | Operator/Admin | Create rollback snapshot |
| Dashboard | `/v1/dashboard/*` | Authenticated | Overview, agents, services, rules polling data |

TypeScript models:

- `User`, `UserUpdateInput`, `PasswordResetInput`, `OwnPasswordInput`.
- `Rule`, `RuleInput`.
- `WhitelistEntry`, `WhitelistInput`.
- `FeedSource`, `FeedSourceInput`.
- `SnapshotMetadata`, `SnapshotDiff`, `SnapshotCollectionDiff`, `AuditEvent`.

## 8. Audit va mutation policy

Bat buoc:

- Reason required cho create/update/delete/rollback/reset/revoke.
- Audit before/after cho policy va access mutations.
- Audit entity type phai ro: `user`, `rule`, `whitelist`, `feed_source`, `snapshot`.
- Raw password, temporary password, bot token, credential value khong vao audit.
- Feed `credential_ref` chi la reference, khong phai secret plaintext.

Snapshot rebuild:

- Rule create/update/disable rebuild snapshot.
- Whitelist create/update/disable rebuild snapshot.
- Feed enabled/disabled state change rebuild snapshot khi anh huong active blacklist.
- Service create/update/disable rebuild snapshot theo existing flow.

## 9. Data states

| State | UI behavior |
|---|---|
| Loading | Shell van render, grid/panel giu kich thuoc on dinh |
| Empty | Message ngan theo dung domain, khong hien bang trong vo nghia |
| Error | Inline result/banner hien API error, giu context hien tai |
| Stale | Freshness chip warn khi qua nguong refresh |
| Unconfigured | Prometheus/Telegram hien unconfigured/missing thay vi crash |
| Failed apply | Hien agent, policy version, stage va reason |
| Read-only | Viewer thay data nhung khong thay mutation controls |
| Invalid JSON | JSON field chan submit va hien loi tai UI/client |

## 10. Verification gates

Gates bat buoc cho thay doi Admin Console:

- `npm --prefix web/dashboard test -- --run`
- `npm --prefix web/dashboard run build`
- `go test ./...`
- `go test -race ./...`
- `go vet ./...`
- `golangci-lint run` neu installed
- Playwright/manual smoke desktop va mobile cho navigation, DataGrid sizing, nonblank charts, no obvious overlap, rollback confirm.

Coverage can giu:

- Viewer read-only.
- Operator/Admin visible actions.
- Rule CRUD va soft-disable.
- Whitelist CRUD va soft-disable.
- Feed CRUD/sync/soft-disable, Admin-only credential_ref.
- User create/update/password reset/session revoke.
- Snapshot diff va rollback confirmation.
- Empty/null list normalization.
- API error states.
- Audit khong leak raw password/credential.

## 11. Implementation map

Frontend:

- Shell/theme: `web/dashboard/src/App.tsx`, `web/dashboard/src/DashboardShell.tsx`, `web/dashboard/src/muiTheme.ts`, `web/dashboard/src/styles.css`.
- Shared admin UI: `web/dashboard/src/adminUi.tsx`.
- Client/types/navigation: `web/dashboard/src/api.ts`, `web/dashboard/src/types.ts`, `web/dashboard/src/navigation.ts`.
- Views: `AccessView`, `RulesAdminView`, `WhitelistAdminView`, `ReputationView`, `SnapshotsView`, `OverviewView`.
- Tests: `web/dashboard/src/App.test.tsx`, `web/dashboard/src/api.test.ts`.

Backend:

- Routes/handlers: `internal/control/server.go`.
- Admin console mutations: `internal/control/admin_console.go`.
- Snapshot diff/get: `internal/control/snapshot_diff.go`.
- Feed snapshot side effects: `internal/control/feed.go`.
- Types: `internal/control/types.go`.
- Integration coverage: `internal/control/admin_dashboard_integration_test.go`.

## 12. Backlog sau vNext

- Dedicated self-service change-password/profile UI trong topbar.
- Audit browser/timeline day du.
- Raw snapshot object browser va side-by-side JSON diff nang cao.
- Blacklist manual CRUD neu can ngoai feed/rule flow.
- SSO/MFA/OIDC va user recovery flow.
- Grafana deep links theo service/rule/agent.
- Saved filters, URL state, export CSV cho grids.
- Role permission editor neu can vuot qua local `viewer/operator/admin`.
