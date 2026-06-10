# Rebuild Guide

## Mục Tiêu

Tài liệu này mô tả thứ tự dựng lại một hệ thống tương tự, gần sát hành vi hiện tại. Mục tiêu không phải copy từng dòng code, mà là giữ nguyên các contract bắt buộc: eBPF ABI, policy snapshot, Control API, DB schema, Agent apply semantics, RBAC, dashboard workflows và test gates.

## Phase 0 - Khóa Scope Và Inventory

Trước khi viết code:

1. Xác nhận chỉ hỗ trợ IPv4 L3/L4 trong v1.
2. Xác nhận không làm TLS termination, HTTP proxy, WAF hoặc DPI.
3. Thu thập production/lab service inventory từ Network/SRE.
4. Gán rõ WAN interface và output/backend interface.
5. Chốt rollback plan trước khi attach XDP vào NIC thật.

Output bắt buộc:

- Service inventory template.
- Interface role matrix.
- Lab-only deployment plan.
- Secret handling policy.

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

Verification:

- Unit tests for config, checksum, snapshot validation, apply failure modes.
- VETH lifecycle lab.
- DEVMAP forwarding lab with `xdp_pass` if needed.

## Phase 3 - Control Plane And Database

Implement:

1. PostgreSQL migration runner and migrations v1-v8 equivalent.
2. Store methods for identity, tenants, services, policy, feeds, snapshots, alerts, events.
3. Tenant transaction helpers and RLS.
4. REST routes listed in [06-control-plane-api.md](06-control-plane-api.md).
5. Snapshot builder/diff/rollback.
6. Background schedulers.
7. Audit with redaction.
8. Metrics.

Verification:

- Migration uniqueness/increasing test.
- PostgreSQL integration tests by domain.
- RBAC/RLS tests.
- Snapshot build/apply/status tests.

## Phase 4 - Dashboard

Implement:

1. Login shell, token storage and refresh loop.
2. Navigation groups and platform-only Tenants entry.
3. API client aligned to Control API.
4. Views: Overview, Incidents, Detection, Events, Services, Rules, Whitelist, Blacklist, UDP Ports, Reputation, Snapshots, Tenants, Accounts, Nodes.
5. Viewer read-only, operator/admin mutation states.
6. Forms require reason for mutations.

Verification:

- API client tests for method/path/body/header.
- Shell tests for RBAC visibility and viewer read-only.
- View workflow tests for CRUD/disable/rollback/feed/Telegram.
- Vite build.

## Phase 5 - Deploy And Operations

Implement:

1. Makefile build/test/compose/agent targets.
2. Docker Compose lab stack.
3. Control API and dashboard Dockerfiles.
4. Prometheus scrape config and recording rules.
5. Grafana dashboard provisioning.
6. Runbooks for bootstrap, deploy, rollback, XDP safety.

Verification:

- `make compose-config`.
- `make deploy`.
- `make admin-bootstrap`.
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
| Dashboard API paths | UI workflow và tests phụ thuộc |
| Make target names | Runbooks và CI/lab scripts phụ thuộc |

## Source Alignment

- Detailed traceability: [16-source-traceability.md](16-source-traceability.md)
- Test plan: [13-testing-and-verification.md](13-testing-and-verification.md)
- Operations: [12-deployment-and-operations.md](12-deployment-and-operations.md)
