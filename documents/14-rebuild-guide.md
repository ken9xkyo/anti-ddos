# Rebuild Guide

## Mục Tiêu

Tài liệu này mô tả thứ tự dựng lại một hệ thống tương tự theo target multitenant SaaS spec. Mục tiêu không phải copy từng dòng code, mà là giữ nguyên các contract bắt buộc: eBPF ABI, policy snapshot, Control API, DB schema, Agent apply semantics, SaaS RBAC, dashboard workflows và test gates.

`Tenant` phải được implement như Customer Account. Billing, subscription plans, entitlement và quota thương mại không nằm trong rebuild scope này.

## Phase 0 - Khóa Scope Và Inventory

Trước khi viết code:

1. Xác nhận chỉ hỗ trợ IPv4 L3/L4 trong v1.
2. Xác nhận không làm TLS termination, HTTP proxy, WAF hoặc DPI.
3. Thu thập production/lab service inventory từ Network/SRE.
4. Gán rõ WAN interface và output/backend interface.
5. Chốt rollback plan trước khi attach XDP vào NIC thật.
6. Chốt SaaS RBAC taxonomy và tenant/customer lifecycle.

Output bắt buộc:

- Service inventory template.
- Interface role matrix.
- Lab-only deployment plan.
- Secret handling policy.
- Tenant lifecycle policy.
- Membership lifecycle policy.
- Platform support/break-glass policy.

## Phase 1 - Data Plane Contract

Implement trước:

1. `include/anti_ddos/bpf_contract.h` tương đương.
2. `bpf/xdp_data_plane.bpf.c` với maps A/B slot.
3. Packet parse IPv4/TCP/UDP/ICMP.
4. Service allowlist fail closed.
5. Whitelist precedence, blacklist, UDP source-port block.
6. Rule actions/modes và token bucket.
7. MAC rewrite và `tx_devmap` redirect.
8. Counters và ringbuf event records.

Verification:

- BPF build với clang target bpf.
- Verifier pass.
- Packet fixture tests cho pass/drop/redirect/reason.

## Phase 2 - Agent

Implement:

1. Config env contract.
2. Load BPF object, validate expected program/maps.
3. Pin maps/program/link in bpffs.
4. Last-valid snapshot load/create.
5. Policy snapshot schema/verify/sign.
6. A/B map apply transaction.
7. Netlink forwarding resolver.
8. Metrics and health endpoints.
9. Control sync loop and event forwarder.
10. Tenant-bound registration and tenant-bound events/apply ack.

Verification:

- Unit tests for config, checksum, snapshot validation, apply failure modes.
- Agent register rejects missing/invalid tenant.
- VETH lifecycle lab.
- DEVMAP forwarding lab with `xdp_pass` if needed.

## Phase 3 - Control Plane And Database

Implement:

1. PostgreSQL migration runner and migrations v1-v8-equivalent.
2. Target concepts: `Tenant`, `TenantMembership`, `PlatformUser`, `Session`, `AuditEvent`, support grant.
3. Tenant lifecycle: `provisioned`, `active`, `suspended`, `offboarding`, `revoked`.
4. Membership lifecycle: `invited`, `active`, `suspended`, `revoked`.
5. Store methods for identity, tenants, services, policy, feeds, snapshots, alerts, events.
6. Tenant transaction helpers and RLS/isolation guard.
7. REST routes listed in [06-control-plane-api.md](06-control-plane-api.md).
8. Resource-specific authorization for security and network duties.
9. Snapshot builder/diff/rollback.
10. Background schedulers.
11. Audit with redaction and platform support/break-glass tracking.
12. Metrics.

Verification:

- Migration uniqueness/increasing test.
- PostgreSQL integration tests by domain.
- SaaS RBAC/RLS tests.
- Snapshot build/apply/status tests.
- Cross-tenant deny tests.

## Phase 4 - Dashboard

Implement:

1. Login shell, token storage and refresh loop.
2. Tenant switcher showing active Customer Account and effective role.
3. Platform console for tenant lifecycle, platform audit and support access.
4. API client aligned to Control API.
5. Views: Overview, Incidents, Detection, Events, Services, Rules, Whitelist, Blacklist, UDP Ports, Reputation, Snapshots, Tenants, Accounts, Nodes.
6. Target role visibility: `tenant_owner`, `tenant_admin`, `security_operator`, `network_operator`, `viewer`, `auditor`.
7. Platform role visibility: `platform_owner`, `platform_admin`, `platform_support`, `platform_auditor`.
8. Forms require reason for mutations where audit requires it.
9. Support session banner with reason and expiry.

Verification:

- API client tests for method/path/body/header.
- Shell tests for tenant switcher and active tenant display.
- Role visibility tests for read-only roles and operator split.
- Platform console/support access tests.
- View workflow tests for CRUD/disable/rollback/feed/Telegram.
- Vite build.

## Phase 5 - Deploy And Operations

Implement:

1. Makefile build/test/compose/agent targets.
2. Docker Compose lab stack.
3. Control API and dashboard Dockerfiles.
4. Prometheus scrape config and recording rules.
5. Grafana dashboard provisioning.
6. Runbooks for bootstrap, tenant onboarding/offboarding, deploy, rollback, XDP safety and support/break-glass.

Verification:

- `make compose-config`.
- `make deploy`.
- Bootstrap `platform_owner`/`platform_admin`.
- Create lab tenant and `tenant_owner`/`tenant_admin`.
- `make dev-health`.
- Full `make test-all`.

## Contracts Không Được Phá

| Contract | Lý do |
|---|---|
| eBPF map names and struct layout | Agent loader/apply phụ thuộc |
| Snapshot checksum canonicalization | Agent reject snapshot sai |
| `object_checksum` | Bảo đảm Control snapshot target đúng BPF object |
| A/B active slot flip | Rollout policy an toàn |
| `/v1/agents/*` protocol | Agent-Control sync |
| Tenant `active_tenant_id` and RLS GUC | Data isolation |
| Tenant role taxonomy canonical | Dashboard/API/tests và handoff cùng dùng một contract |
| Platform support TTL/reason/audit | Cross-tenant access không bị lạm dụng |
| Dashboard API paths | UI workflow và tests phụ thuộc |
| Make target names | Runbooks và CI/lab scripts phụ thuộc |

## Source Alignment

- Detailed traceability: [16-source-traceability.md](16-source-traceability.md)
- Test plan: [13-testing-and-verification.md](13-testing-and-verification.md)
- Operations: [12-deployment-and-operations.md](12-deployment-and-operations.md)
