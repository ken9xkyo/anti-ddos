# Security, RBAC And Secrets

Sơ đồ RBAC target: [diagrams/rbac-tenant-flow.mmd](diagrams/rbac-tenant-flow.mmd)

Sơ đồ vòng đời tenant: [diagrams/tenant-lifecycle-flow.mmd](diagrams/tenant-lifecycle-flow.mmd)

## Target Security Model

Hệ thống được đặc tả như một multitenant SaaS application. `Tenant` là một Customer Account: mọi protected service, policy, agent, snapshot, security event, alert, audit entry và observability view thuộc về đúng một tenant, trừ các đối tượng platform dùng để vận hành SaaS.

Các lớp bảo vệ bắt buộc:

1. API authentication bằng bearer token/session cho user và shared token riêng cho Agent.
2. Session của user luôn có `active_tenant` khi thao tác tenant-scoped resource.
3. Authorization dùng role canonical của target SaaS, tách platform role khỏi tenant membership role.
4. PostgreSQL RLS hoặc cơ chế tương đương chặn query tenant-scoped nếu thiếu tenant context.
5. Mọi mutation và mọi platform support/break-glass access đều có actor, tenant, reason, thời hạn và audit event.
6. Secret redaction áp dụng cho log, audit, API response và UI.
7. XDP/NIC operational guardrails giữ nguyên, không bị bypass bởi role nghiệp vụ.

Billing, subscription plan, entitlement, feature gating và quota thương mại nằm ngoài scope của RBAC spec này.

## Canonical Role Taxonomy

### Platform Roles

Platform role chỉ áp dụng cho vận hành SaaS platform. Platform role không tự động trở thành tenant role và không được bypass audit khi truy cập dữ liệu khách hàng.

| Role | Scope | Quyền target |
|---|---|---|
| `platform_owner` | Toàn platform | Quản trị cao nhất, quản lý `platform_admin`, `platform_support`, `platform_auditor`, phê duyệt break-glass policy và tenant lifecycle critical actions |
| `platform_admin` | Toàn platform | Provision/update/suspend tenant, quản lý cấu hình platform, hỗ trợ bootstrap và vận hành control plane |
| `platform_support` | Time-bound tenant access | Hỗ trợ khách hàng theo ticket/reason, chỉ vào tenant cụ thể trong thời hạn đã cấp, mọi action audited |
| `platform_auditor` | Read-only platform audit | Xem platform audit, tenant lifecycle history và support access history; không mutation |

### Tenant Roles

Tenant role đến từ `TenantMembership` của user trong `active_tenant`.

| Role | Scope | Quyền target |
|---|---|---|
| `tenant_owner` | Một Customer Account | Quản trị cao nhất của tenant, quản lý `tenant_admin`, settings, membership, offboarding request và mọi resource tenant |
| `tenant_admin` | Một Customer Account | Quản lý members, services, policies, integrations, snapshots, alerts và audit trong tenant, trừ chuyển ownership/offboarding critical action nếu policy yêu cầu owner |
| `security_operator` | Một Customer Account | Quản lý rules, whitelist, blacklist, UDP source-port block, threat feeds, snapshots policy và incident response |
| `network_operator` | Một Customer Account | Quản lý protected services, forwarding metadata, agents/nodes và network-facing operational state |
| `viewer` | Một Customer Account | Read-only operational dashboard, services, events, alerts và snapshots |
| `auditor` | Một Customer Account | Read-only audit, change history, alert history và compliance exports trong tenant |

## Tenant Lifecycle

| State | Ý nghĩa | Actor được chuyển state | Audit bắt buộc |
|---|---|---|---|
| `provisioned` | Customer Account đã được tạo, chưa active vận hành | `platform_owner`, `platform_admin` | Tenant ID, customer name, actor, reason |
| `active` | Tenant được phép login, register agent, quản lý service/policy và nhận snapshot | `platform_owner`, `platform_admin` | State transition, reason |
| `suspended` | Login/mutation/agent registration mới bị chặn; read-only/audit access theo policy hỗ trợ vẫn có thể mở | `platform_owner`, `platform_admin` | Reason, effective time, customer notification ref |
| `offboarding` | Tenant đang được export/cleanup; mutation mới bị chặn trừ runbook offboarding | `platform_owner`, `platform_admin`, có request từ `tenant_owner` | Export checklist, retention decision |
| `revoked` | Tenant bị thu hồi hoàn toàn; chỉ platform audit/retention access còn lại | `platform_owner` | Final reason, retention marker |

Tenant-scoped resources không được query hoặc mutate ngoài tenant context, kể cả khi tenant bị suspended/offboarding. Platform access hợp lệ phải đi qua platform transaction có reason và audit.

## Membership Lifecycle

| State | Ý nghĩa | Transition chính |
|---|---|---|
| `invited` | User đã được mời vào tenant nhưng chưa kích hoạt membership | Created by `tenant_owner` hoặc `tenant_admin` |
| `active` | User có thể chọn tenant làm `active_tenant` và nhận effective role | Invite accepted hoặc membership restored |
| `suspended` | User tạm thời không được dùng tenant role trong tenant đó | Suspended by `tenant_owner` hoặc `tenant_admin` |
| `revoked` | Membership bị thu hồi, session tenant đó phải invalidated | Revoked by `tenant_owner` hoặc `tenant_admin`; owner removal cần owner/platform policy |

Session response phải trả `active_tenant`, danh sách memberships hợp lệ và `effective_role`. Khi membership bị suspended/revoked, các session đang dùng tenant đó phải bị revoke hoặc không còn authorize được request kế tiếp.

## Permission Matrix

| Resource / Action | Platform roles | Tenant roles | Audit/reason |
|---|---|---|---|
| Create/update/suspend tenant | `platform_owner`, `platform_admin` | Không | Bắt buộc |
| Revoke tenant | `platform_owner` | Không | Bắt buộc, reason và retention marker |
| View tenant platform inventory | `platform_owner`, `platform_admin`, `platform_auditor` | Không | Read audit event khuyến nghị với export |
| Time-bound support access | `platform_owner`, `platform_admin` grant; `platform_support` use | Không | Bắt buộc ticket/reason, TTL, tenant ID |
| Tenant settings | Không, trừ audited support session | `tenant_owner`, `tenant_admin` | Bắt buộc khi mutation |
| Members/invitations | Không, trừ audited support session | `tenant_owner`, `tenant_admin` | Bắt buộc |
| Ownership transfer/offboarding request | Không, trừ platform approval | `tenant_owner` | Bắt buộc |
| Protected services | Không, trừ audited support session | `tenant_owner`, `tenant_admin`, `network_operator` | Bắt buộc |
| Forwarding policies/interface metadata | Không, trừ audited support session | `tenant_owner`, `tenant_admin`, `network_operator` | Bắt buộc |
| Agent registration/agent state | Agent API tenant-bound; platform read for ops | `tenant_owner`, `tenant_admin`, `network_operator` | Register/apply ack audited hoặc evented |
| Rules/whitelist/blacklist/UDP blocks | Không, trừ audited support session | `tenant_owner`, `tenant_admin`, `security_operator` | Bắt buộc |
| Threat feeds and credential refs | Không, trừ audited support session | `tenant_owner`, `tenant_admin`, `security_operator` for non-secret sync/config; secret ref changes require `tenant_owner` or `tenant_admin` | Bắt buộc và redacted |
| Snapshot build/rollback | Không, trừ audited support session | `tenant_owner`, `tenant_admin`, `security_operator`; `network_operator` may view impact | Bắt buộc |
| Alerts/incidents | Không, trừ audited support session | `tenant_owner`, `tenant_admin`, `security_operator`, `viewer` read, `auditor` read audit/history | Mutation bắt buộc reason |
| Audit events | `platform_auditor`, `platform_owner`, `platform_admin` for platform audit | `tenant_owner`, `tenant_admin`, `auditor` for tenant audit | Export/read tracked |
| Dashboard read views | Không, trừ audited support session | All active tenant roles | Không bắt buộc cho normal read |

`viewer` và `auditor` luôn read-only. `security_operator` không được quản lý forwarding/interface lifecycle nếu không có thêm `network_operator`, `tenant_admin` hoặc `tenant_owner`. `network_operator` không được thay đổi security enforcement rules nếu không có thêm `security_operator`, `tenant_admin` hoặc `tenant_owner`.

## Tenant Context And RLS

Target API semantics:

- Auth trả `active_tenant`, `memberships[]`, `platform_roles[]` nếu có và `effective_role` cho active tenant.
- User request đến tenant-scoped endpoint phải có active tenant trong session hoặc tenant context tương đương đã được authorize.
- Tenant switch chỉ được phép tới tenant mà user có membership active hoặc support grant đang active.
- Agent registration luôn tenant-bound bằng tenant identifier và agent shared token; các call Agent sau resolve tenant từ `agent_id`.
- Tenant-scoped query không bao giờ chạy ngoài tenant context.

RLS policy target dùng hai mode:

- Tenant transaction: set tenant context, chỉ thấy row có `tenant_id` tương ứng.
- Platform transaction: chỉ dùng cho platform inventory/lifecycle/support workflows, phải có reason/audit và không được dùng như đường tắt cho tenant operations thông thường.

## Platform Support And Break-Glass

Support/break-glass là cơ chế ngoại lệ, không phải role tenant ẩn.

Yêu cầu bắt buộc:

- Grant gắn với tenant cụ thể, actor cụ thể, reason/ticket cụ thể và TTL cụ thể.
- UI/API hiển thị rõ đang ở support session.
- Mọi read nhạy cảm, export và mutation trong support session ghi audit với `platform_support` actor và tenant target.
- Hết TTL thì access tự hết hiệu lực; không gia hạn ngầm.
- Break-glass production cần approval policy của `platform_owner` hoặc `platform_admin` theo mức độ nghiêm trọng.

## Secret Handling

| Secret | Contract |
|---|---|
| `ANTI_DDOS_DB_DSN` | Env only, không ghi vào docs/log |
| `ANTI_DDOS_AGENT_SHARED_TOKEN` | Env in control-api, placeholder trong `.env.example` |
| `ANTI_DDOS_AGENT_TOKEN` | Host Agent env, redacted khi log lỗi |
| Feed credentials | Dùng credential ref như `env://VAR_NAME` hoặc `secret://anti-ddos/name`; không log plaintext |
| Telegram token | API/UI mask output; audit/log không chứa raw token |
| Bootstrap password | CLI bootstrap đọc từ stdin trong vận hành thật; env chỉ dùng lab non-interactive |

## XDP/NIC Safety

- Compose stack không attach XDP; chỉ chạy management/control services.
- Host Agent mới attach XDP, thông qua Makefile hoặc binary trực tiếp.
- Không attach trên NIC thật nếu chưa xác nhận WAN/output roles, service inventory, rollback và change window.
- Detach/remove phải đi qua guardrail runbook; không replace XDP program lạ trên output NIC.

## Source Alignment

- Target RBAC docs: `documents/11-security-rbac-and-secrets.md`, `documents/06-control-plane-api.md`, `documents/09-admin-dashboard.md`
- Current role/type implementation anchors: `internal/control/types.go`, `internal/control/tenant.go`
- Tenant transactions/RLS context: `internal/control/tenant.go`
- Tenant store and switch: `internal/control/tenant_store.go`
- User/admin console: `internal/control/admin_console.go`, `internal/control/store.go`
- RBAC tests: `internal/control/rbac_test.go`
- Redaction: `internal/agent/redaction.go`, `internal/control/store.go`
- Safety commands: `Makefile`, `README.md`
