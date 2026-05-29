# Phase 05 - Control Plane Core

## Mục tiêu

Xây dựng Control Plane API làm nguồn cấu hình chính cho users, agents, protected services, forwarding policies, rules, whitelist, blacklist placeholders, policy snapshots, audit và rollback. Phase này biến local/mock snapshot thành luồng API -> PostgreSQL -> snapshot -> Agent sync.

## Phạm vi

- Control API Go với PostgreSQL.
- Local RBAC: Admin, Operator, Viewer.
- CRUD cho backend service, forwarding policy, rules, whitelist, manual blacklist/feed config placeholder, agents.
- Immutable policy snapshots có version/checksum/rollback_from.
- Audit log cho mọi mutation và reason bắt buộc với policy-affecting changes.
- Authentication/session local; không SSO, không multi-tenant.

## Công việc

| ID | Công việc | Mục đích | Kết quả bàn giao | Phụ thuộc |
|---|---|---|---|---|
| P05-T01 | Tạo Control API service skeleton | Nền tảng API và DB access | Go API, config, kết nối DB, migration runner | Phase 03 |
| P05-T02 | Triển khai PostgreSQL migrations core | Lưu durable state | Tables users, sessions, agents, services, forwarding policies, rules, whitelist, snapshots, audit | P05-T01 |
| P05-T03 | Triển khai local auth và RBAC | Bảo vệ mutation và dashboard | Login/session, password hash, role middleware Admin/Operator/Viewer | P05-T02 |
| P05-T04 | Triển khai audit middleware/service | Mọi thay đổi có before/after/reason | `audit_events` writes cho mutation endpoints, secret redaction | P05-T03 |
| P05-T05 | Triển khai backend service CRUD | Quản lý source cho service allowlist | API validate CIDR/proto/ports/output interface/owner/criticality | P05-T04 |
| P05-T06 | Triển khai forwarding policy validation | Chặn policy mở port/route sai | Conflict checks overlap CIDR, duplicate port, invalid protocol, unresolved output target | P05-T05 |
| P05-T07 | Triển khai whitelist CRUD | Hỗ trợ allow override có audit | API validate IP/CIDR, scope global/service, owner, reason, expiry, priority | P05-T04 |
| P05-T08 | Triển khai blacklist/rule CRUD | Quản lý manual mitigation | API rule action/mode/TTL/evidence/confidence validation | P05-T04 |
| P05-T09 | Triển khai effective snapshot builder | Tạo policy apply cho Agent | Canonical snapshot từ DB gồm services, rules, whitelist/blacklist, xdp_config, checksum | P05-T06, P05-T07, P05-T08 |
| P05-T10 | Triển khai Agent register/heartbeat/fetch/ack | Kết nối Agent với Control Plane | Endpoints register, heartbeat, fetch snapshot, apply ack/failure | P05-T09 |
| P05-T11 | Triển khai rollback API | Khôi phục policy version nhanh | Rollback tạo snapshot mới với `rollback_from`, audit reason | P05-T09 |
| P05-T12 | Triển khai bootstrap Admin CLI/secret | Tạo tài khoản Admin đầu tiên an toàn | One-time bootstrap, force password change, audit event | P05-T03 |
| P05-T13 | Triển khai Viewer read-only behavior | Đảm bảo RBAC đúng | Tests Viewer không mutate, Admin/Operator mutate theo quyền | P05-T03 |

## Tiến độ thực hiện

Ngày cập nhật: 2026-05-28

Evidence chính: `make phase5-verify` PASS; report ở `reports/phase-05-control-plane-core.md`. Phase này triển khai Control Plane lõi với PostgreSQL, local RBAC, audit, policy snapshot builder và Agent sync API. Verification dùng PostgreSQL Docker container vì `psql/postgres` local vẫn chưa được cài trên lab host.

| ID | Status | Evidence |
|---|---|---|
| P05-T01 | Done | `cmd/control-api` có `migrate`, `serve`, config env và kết nối PostgreSQL qua `pgx/v5`. |
| P05-T02 | Done | Migration runner idempotent tạo core tables cho users, sessions, agents, services, forwarding policies, rules, whitelist, blacklist placeholders, feed placeholders, snapshots, apply status và audit. |
| P05-T03 | Done | Local login/session dùng bearer/cookie token hash, bcrypt password hash và role Admin/Operator/Viewer. |
| P05-T04 | Done | Mutations ghi `audit_events` với before/after/reason và redaction cho password/token/API key/session/authorization-like fields. |
| P05-T05 | Done | Backend service API validate IPv4 CIDR, protocol, allowed ports, output interface, owner, criticality, mode và resolved forwarding metadata. |
| P05-T06 | Done | Forwarding policy API validate protocol/port/action/output target; snapshot builder reject active non-host CIDR/unresolved metadata fail-closed trước Agent apply. |
| P05-T07 | Done | Whitelist API validate IPv4 CIDR, global/service scope, owner, reason, expiry và priority; entries enter Agent snapshot as allow CIDR policy. |
| P05-T08 | Done | Rule và manual blacklist APIs validate action/mode/TTL/evidence/confidence/source và publish effective rule/blacklist entries. |
| P05-T09 | Done | Snapshot builder reuses `agent.PolicySnapshot`, signs canonical checksum, verifies capacity/shape and skips redundant unchanged effective snapshots. |
| P05-T10 | Done | Agent endpoints support register, heartbeat desired version, snapshot fetch and apply ack/failure; Agent optional sync activates with `ANTI_DDOS_CONTROL_URL`. |
| P05-T11 | Done | Rollback API creates a new snapshot from target content with fresh version and `rollback_from` set to latest active version. |
| P05-T12 | Done | `cmd/control-admin bootstrap --username admin --password-stdin` creates the first Admin once, forces password change and audits bootstrap. |
| P05-T13 | Done | Integration test confirms Viewer cannot mutate while Admin can create policy-affecting resources. |

## Tiêu chí chấp nhận

- Admin có thể quản lý users, services, policies, rules, feeds config, rollback và mọi mutation ghi audit.
- Operator có thể quản lý rule, whitelist, forwarding policy và rollback theo quyền.
- Viewer chỉ đọc dashboard/data, không mutate policy.
- Snapshot builder tạo version mới khi effective policy thay đổi và checksum canonical ổn định.
- Agent heartbeat nhận desired version, fetch snapshot và gửi apply ack/failure.
- Rollback tạo snapshot mới bằng content target version và set `rollback_from`.

## Kiểm chứng

- Migration test trên PostgreSQL sạch.
- API integration tests cho RBAC: Admin, Operator, Viewer.
- Audit tests xác nhận before/after/reason được ghi cho service, whitelist, rule, rollback.
- Snapshot test xác nhận DB state -> JSON canonical -> checksum -> Agent verify.
- Rollback test xác nhận version mới được tạo và Agent fetch/apply được.
- Secret redaction test cho password, Telegram token và feed API key placeholders.

## Truy vết PRD

- PRD-004: rule TTL và rollback target.
- PRD-005: feed config và blacklist state source.
- PRD-006: whitelist management.
- PRD-007: backend service allowlist, forwarding policy và protected service registry.
- PRD-009: local RBAC, audit log, rollback.
- PRD-010: agent sync, apply status, stale policy foundation.

## Ghi chú và rủi ro

- API response không bao giờ trả plaintext secrets.
- Audit diff phải redact token/API key/password.
- Snapshot builder phải deterministic ordering để checksum ổn định.
- DB schema nên chuẩn bị partition cho events/audit; retention job có thể đến Phase 10.
