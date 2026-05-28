# Phase 05 - Control Plane Core

## Muc tieu

Xay dung Control Plane API lam source of truth cho users, agents, protected services, forwarding policies, rules, whitelist, blacklist placeholders, policy snapshots, audit va rollback. Phase nay bien local/mock snapshot thanh luong API -> PostgreSQL -> snapshot -> Agent sync.

## Pham vi

- Control API Go voi PostgreSQL.
- Local RBAC: Admin, Operator, Viewer.
- CRUD cho backend service, forwarding policy, rules, whitelist, manual blacklist/feed config placeholder, agents.
- Immutable policy snapshots co version/checksum/rollback_from.
- Audit log cho moi mutation va reason bat buoc voi policy-affecting changes.
- Authentication/session local; khong SSO, khong multi-tenant.

## Cong viec

| ID | Cong viec | Muc dich | Ket qua ban giao | Phu thuoc |
|---|---|---|---|---|
| P05-T01 | Tao Control API service skeleton | Nen tang API va DB access | Go API, config, DB connection, migration runner | Phase 03 |
| P05-T02 | Implement PostgreSQL migrations core | Luu durable state | Tables users, sessions, agents, services, forwarding policies, rules, whitelist, snapshots, audit | P05-T01 |
| P05-T03 | Implement local auth va RBAC | Bao ve mutation va dashboard | Login/session, password hash, role middleware Admin/Operator/Viewer | P05-T02 |
| P05-T04 | Implement audit middleware/service | Moi thay doi co before/after/reason | `audit_events` writes cho mutation endpoints, secret redaction | P05-T03 |
| P05-T05 | Implement backend service CRUD | Quan ly source cho service allowlist | API validate CIDR/proto/ports/output interface/owner/criticality | P05-T04 |
| P05-T06 | Implement forwarding policy validation | Chan policy mo port/route sai | Conflict checks overlap CIDR, duplicate port, invalid protocol, unresolved output target | P05-T05 |
| P05-T07 | Implement whitelist CRUD | Ho tro allow override co audit | API validate IP/CIDR, scope global/service, owner, reason, expiry, priority | P05-T04 |
| P05-T08 | Implement blacklist/rule CRUD | Quan ly manual mitigation | API rule action/mode/TTL/evidence/confidence validation | P05-T04 |
| P05-T09 | Implement effective snapshot builder | Tao policy apply cho Agent | Canonical snapshot tu DB gom services, rules, whitelist/blacklist, xdp_config, checksum | P05-T06, P05-T07, P05-T08 |
| P05-T10 | Implement Agent register/heartbeat/fetch/ack | Ket noi Agent voi Control Plane | Endpoints register, heartbeat, fetch snapshot, apply ack/failure | P05-T09 |
| P05-T11 | Implement rollback API | Khoi phuc policy version nhanh | Rollback tao snapshot moi voi `rollback_from`, audit reason | P05-T09 |
| P05-T12 | Implement bootstrap Admin CLI/secret | Tao tai khoan Admin dau tien an toan | One-time bootstrap, force password change, audit event | P05-T03 |
| P05-T13 | Implement Viewer read-only behavior | Dam bao RBAC dung | Tests Viewer khong mutate, Admin/Operator mutate theo quyen | P05-T03 |

## Tieu chi chap nhan

- Admin co the quan ly users, services, policies, rules, feeds config, rollback va moi mutation ghi audit.
- Operator co the quan ly rule, whitelist, forwarding policy va rollback theo quyen.
- Viewer chi doc dashboard/data, khong mutate policy.
- Snapshot builder tao version moi khi effective policy thay doi va checksum canonical on dinh.
- Agent heartbeat nhan desired version, fetch snapshot va gui apply ack/failure.
- Rollback tao snapshot moi bang content target version va set `rollback_from`.

## Kiem chung

- Migration test tren PostgreSQL sach.
- API integration tests cho RBAC: Admin, Operator, Viewer.
- Audit tests xac nhan before/after/reason duoc ghi cho service, whitelist, rule, rollback.
- Snapshot test xac nhan DB state -> JSON canonical -> checksum -> Agent verify.
- Rollback test xac nhan version moi duoc tao va Agent fetch/apply duoc.
- Secret redaction test cho password, Telegram token va feed API key placeholders.

## Truy vet PRD

- PRD-004: rule TTL va rollback target.
- PRD-005: feed config va blacklist state source.
- PRD-006: whitelist management.
- PRD-007: backend service allowlist, forwarding policy va protected service registry.
- PRD-009: local RBAC, audit log, rollback.
- PRD-010: agent sync, apply status, stale policy foundation.

## Ghi chu va rui ro

- API response khong bao gio tra plaintext secrets.
- Audit diff phai redact token/API key/password.
- Snapshot builder phai deterministic ordering de checksum on dinh.
- DB schema nen chuan bi partition cho events/audit; retention job co the den Phase 10.

