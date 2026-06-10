# Admin Dashboard

## Mục Tiêu

Admin Dashboard là management UI cho vận hành anti-DDoS theo mô hình multitenant SaaS. UI dùng React 18, TypeScript, Vite, Material UI, lucide-react và gọi Control API qua `ApiClient`. Dashboard không truy cập DB trực tiếp.

Dashboard phải phục vụ hai bề mặt tách biệt:

- Tenant workspace cho Customer Account đang active.
- Platform console cho tenant lifecycle, platform audit và support access.

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
- Shell luôn hiển thị active Customer Account khi user đang ở tenant workspace.
- Tenant switcher liệt kê memberships active và support grants active nếu user là platform support.
- Tenant switch gọi `POST /v1/tenants/switch`, update token/session mới.
- Platform users có platform console riêng, không trộn với tenant workspace.
- Refresh button gọi lại aggregated dashboard loader.
- Logout clear token local/state UI và nên gọi API logout khi implementation hỗ trợ.

## Navigation

| Group | Views | API chính | Target audience |
|---|---|---|---|
| Operation | Dashboard, Incidents, Detections, Events | `/v1/dashboard/*`, `/v1/alerts`, `/v1/baselines`, `/v1/anomalies`, `/v1/security-events` | Tenant roles |
| Configuration | Services, Rules, Whitelist, Blacklist, UDP Ports | `/v1/services`, `/v1/rules`, `/v1/whitelist`, `/v1/blacklist`, `/v1/udp-source-port-blocks` | Security/network tenant roles |
| Threat Intelligence | Reputation | `/v1/feed-sources`, `/v1/feed-runs`, `/v1/feed-conflicts` | Security tenant roles |
| Setting | Snapshots, Accounts, Nodes, Tenant Settings | `/v1/snapshots`, `/v1/users`, `/v1/dashboard/agents`, tenant settings API | `tenant_owner`, `tenant_admin`, `security_operator`, `network_operator` |
| Platform | Tenants, Support Access, Platform Audit | `/v1/tenants`, `/v1/audit` platform scope, support grant API | Platform roles |

Tenant workspace never shows another tenant's data. Platform console must visually distinguish platform scope from active tenant scope.

## RBAC In UI

| Role | UI behavior |
|---|---|
| `platform_owner` | Platform console, platform role management, tenant revoke/offboarding approval, break-glass policy |
| `platform_admin` | Platform console, tenant provision/update/suspend, support grant management |
| `platform_support` | Only assigned support tenant sessions; UI shows support banner, TTL and reason |
| `platform_auditor` | Read-only platform audit and support access history |
| `tenant_owner` | Full tenant workspace including membership/settings/offboarding request |
| `tenant_admin` | Tenant workspace admin actions except owner-only critical actions |
| `security_operator` | Mutation controls for rules, whitelist, blacklist, UDP blocks, feeds, snapshots and incidents |
| `network_operator` | Mutation controls for services, forwarding, agents/nodes and network metadata |
| `viewer` | Read-only operational dashboard/API; no mutation buttons/forms |
| `auditor` | Read-only audit/change/alert history; operational mutation hidden/disabled |

UI action visibility is an ergonomics layer only. Backend authorization remains source of enforcement and must return 403 for forbidden action attempts.

## Page-Level Notes

| View file | Mục đích | Target mutation/read behavior |
|---|---|---|
| `OverviewView.tsx` | Tổng quan traffic, agent, snapshot, decisions | Read for all active tenant roles |
| `IncidentsView.tsx` | Alerts, Telegram config/test, ISP escalation | Security mutation by `security_operator`, `tenant_admin`, `tenant_owner`; read by `viewer`/`auditor` |
| `DetectionView.tsx` | Baselines/anomalies alert-only | Security evaluate/approve/recalibrate; read for all tenant roles |
| `InvestigationView.tsx` | Security event investigation | Read for all tenant roles; audit export by `auditor`, `tenant_admin`, `tenant_owner` |
| `ServicesView.tsx` | Protected service CRUD, forwarding status | Network mutation by `network_operator`, `tenant_admin`, `tenant_owner` |
| `RulesAdminView.tsx` | Rule create/edit/disable | Security mutation |
| `WhitelistAdminView.tsx` | Whitelist create/edit/disable | Security mutation |
| `BlacklistAdminView.tsx` | Manual blacklist and feed/manual combined list | Security mutation |
| `UDPPortsAdminView.tsx` | UDP source-port block create/edit/disable | Security mutation |
| `ReputationView.tsx` | Feed sources/runs/conflicts | Security mutation; secret ref change by `tenant_admin`/`tenant_owner` |
| `SnapshotsView.tsx` | Snapshot list/diff/build/rollback | Build/rollback by `security_operator`, `tenant_admin`, `tenant_owner`; read for all tenant roles |
| `TenantsView.tsx` | Customer Account lifecycle | `platform_owner`, `platform_admin`; read-only for `platform_auditor` |
| `AccessView.tsx` | Tenant member lifecycle | `tenant_owner`, `tenant_admin`; support grant UI in platform console |
| `FleetView.tsx` | Agent/nodes status | Network controls by `network_operator`; read for all tenant roles |

## SaaS UX Requirements

- Tenant switcher must show customer name/slug and current effective role.
- Support sessions must show platform support actor, reason/ticket and expiry.
- Empty states must be tenant-scoped: empty service list means the active Customer Account has no services, not that platform has no services.
- Error states must distinguish forbidden, suspended tenant, revoked membership and missing active tenant.
- Mutation forms must require reason where backend audit requires it.
- Audit views must make tenant scope visible and prevent accidental platform/tenant audit mixing.
- Platform tenant console must include lifecycle state, created/suspended/offboarding/revoked timestamps and actor history.
- `viewer`/`auditor` read-only states must hide primary mutation controls and also disable contextual row actions.

## API Client Contract

`web/dashboard/src/api.ts` centralizes:

- Auth token storage and Authorization header.
- Active tenant/session refresh.
- Aggregated `dashboard()` loader with parallel requests.
- CRUD helpers for services, rules, lists, feeds, snapshots, users, tenants.
- Query string encoding for whitelist/blacklist/UDP filters.
- Error normalization from Control API responses.

## Rebuild Notes

- Preserve type definitions in `web/dashboard/src/types.ts` aligned to target API DTOs.
- Preserve grouped navigation IDs where tests and shell route rendering depend on them, but map action visibility to target roles.
- Cover read-only behavior for `viewer` and `auditor`.
- Cover permission split for `security_operator` and `network_operator`.
- Cover platform tenant console and support session banner.
- Keep refresh polling interval behavior if cloning operational feel.

## Source Alignment

- App shell: `web/dashboard/src/App.tsx`, `web/dashboard/src/DashboardShell.tsx`
- Navigation: `web/dashboard/src/navigation.ts`
- API client/types: `web/dashboard/src/api.ts`, `web/dashboard/src/types.ts`
- Admin shared UI: `web/dashboard/src/adminUi.tsx`
- Tests: `web/dashboard/src/App.test.tsx`, `web/dashboard/src/api.test.ts`
- Existing guide docs: `docs/guide/*.md`, `docs/Admin-Dashboard-v2.md`
