# Admin Dashboard

## Mục Tiêu

Admin Dashboard là management UI cho vận hành anti-DDoS. UI dùng React 18, TypeScript, Vite, Material UI, lucide-react và gọi Control API qua `ApiClient`. Dashboard không truy cập DB trực tiếp.

## Runtime And Build

| Item | Giá trị |
|---|---|
| Source root | `web/dashboard` |
| Entrypoint | `web/dashboard/src/main.tsx`, `web/dashboard/src/App.tsx` |
| Build | `npm --prefix web/dashboard run build` hoặc `make ui-build` |
| Test | `npm --prefix web/dashboard test -- --run` hoặc `make ui-test` |
| Runtime image | Nginx image build từ `deploy/docker/admin-dashboard.Dockerfile` |
| Default compose port | Host `8088` tới container `8080` |

## Shell Behavior

- Khi chưa có user, hiển thị login form.
- Login gọi `POST /v1/auth/login`; token lưu localStorage key `anti_ddos_token`.
- Sau login, UI gọi `GET /v1/me`, sau đó poll dashboard data mỗi 3 giây.
- `DashboardShell` hiển thị tenant switcher khi user có nhiều tenant.
- Tenant switch gọi `POST /v1/tenants/switch`, update token/session mới.
- Refresh button gọi lại aggregated dashboard loader.
- Logout chỉ clear token local và state UI; API logout có client method riêng nhưng shell hiện clear local token trực tiếp.

## Navigation

| Group | Views | API chính |
|---|---|---|
| Operation | Dashboard, Incidents, Detections, Events | `/v1/dashboard/*`, `/v1/alerts`, `/v1/baselines`, `/v1/anomalies`, `/v1/security-events` |
| Configuration | Services, Rules, Whitelist, Blacklist, UDP Ports | `/v1/services`, `/v1/rules`, `/v1/whitelist`, `/v1/blacklist`, `/v1/udp-source-port-blocks` |
| Threat Intelligence | Reputation | `/v1/feed-sources`, `/v1/feed-runs`, `/v1/feed-conflicts` |
| Setting | Snapshots, Tenants, Accounts, Nodes | `/v1/snapshots`, `/v1/tenants`, `/v1/users`, `/v1/dashboard/agents` |

`Tenants` có `platformOnly: true` và chỉ hiển thị với `platform_role === "platform_admin"`.

## RBAC In UI

| User state | UI behavior |
|---|---|
| `viewer` | Read-only; mutation buttons/forms bị ẩn hoặc disabled trong các admin views |
| `operator` | `canMutate=true`; có thể thao tác policy, services, lists, snapshots, Telegram test/config theo backend permission |
| `admin` | `canMutate=true`; thêm quyền feed credential mutation và account management rộng hơn |
| `platform_admin` | Thấy Tenants view và tenant switcher cross-tenant |

`canMutate` trong shell được tính bằng `user.role === "admin" || user.role === "operator"`.

## Page-Level Notes

| View file | Mục đích | Mutation chính |
|---|---|---|
| `OverviewView.tsx` | Tổng quan traffic, agent, snapshot, decisions | Không |
| `IncidentsView.tsx` | Alerts, Telegram config/test, ISP escalation | Operator/Admin |
| `DetectionView.tsx` | Baselines/anomalies alert-only | Chủ yếu observe/evaluate |
| `InvestigationView.tsx` | Security event investigation | Không |
| `ServicesView.tsx` | Protected service CRUD, forwarding status | Operator/Admin |
| `RulesAdminView.tsx` | Rule create/edit/disable | Operator/Admin |
| `WhitelistAdminView.tsx` | Whitelist create/edit/disable | Operator/Admin |
| `BlacklistAdminView.tsx` | Manual blacklist and feed/manual combined list | Operator/Admin |
| `UDPPortsAdminView.tsx` | UDP source-port block create/edit/disable | Operator/Admin |
| `ReputationView.tsx` | Feed sources/runs/conflicts | Admin for credential changes, operator for non-secret metadata |
| `SnapshotsView.tsx` | Snapshot list/diff/build/rollback | Operator/Admin |
| `TenantsView.tsx` | Tenant create/update | Platform admin |
| `AccessView.tsx` | User/account lifecycle | Admin; operator limited to viewers |
| `FleetView.tsx` | Agent/nodes status | Read-oriented |

## API Client Contract

`web/dashboard/src/api.ts` centralizes:

- Auth token storage and Authorization header.
- Aggregated `dashboard()` loader with parallel requests.
- CRUD helpers for services, rules, lists, feeds, snapshots, users, tenants.
- Query string encoding for whitelist/blacklist/UDP filters.
- Error normalization from Control API responses.

## Rebuild Notes

- Preserve type definitions in `web/dashboard/src/types.ts` aligned to `internal/control/types.go`.
- Preserve grouped navigation IDs because tests and shell route rendering depend on them.
- Keep viewer read-only behavior covered by UI tests.
- Keep refresh polling interval behavior if cloning operational feel.

## Source Alignment

- App shell: `web/dashboard/src/App.tsx`, `web/dashboard/src/DashboardShell.tsx`
- Navigation: `web/dashboard/src/navigation.ts`
- API client/types: `web/dashboard/src/api.ts`, `web/dashboard/src/types.ts`
- Admin shared UI: `web/dashboard/src/adminUi.tsx`
- Tests: `web/dashboard/src/App.test.tsx`, `web/dashboard/src/api.test.ts`
- Existing guide docs: `docs/guide/*.md`, `docs/Admin-Dashboard-v2.md`
