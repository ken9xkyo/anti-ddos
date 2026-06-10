# Bộ Tài Liệu Bàn Giao Anti-DDoS Scrubbing Gateway

Trạng thái: tài liệu được tạo từ source code hiện tại vào ngày 2026-06-10.

Bộ tài liệu này dùng để bàn giao hệ thống Anti-DDoS Scrubbing Gateway eBPF/XDP cho một team khác có thể tái triển khai một hệ thống tương tự, gần sát hành vi hiện tại. Nguồn sự thật ưu tiên là source code trong repo; tài liệu cũ trong `docs/`, README, `.specs/project/STATE.md` và `.notebook/` chỉ được dùng để đối chiếu và diễn giải.

## Cách Đọc

| Nhu cầu | Tài liệu nên đọc |
|---|---|
| Nắm hệ thống trong 30 phút | [00-executive-summary.md](00-executive-summary.md), [03-system-context-and-architecture.md](03-system-context-and-architecture.md) |
| Hiểu bài toán, scope, yêu cầu | [01-product-brief-and-scope.md](01-product-brief-and-scope.md), [02-requirements-and-success-criteria.md](02-requirements-and-success-criteria.md) |
| Clone lại backend/control plane | [06-control-plane-api.md](06-control-plane-api.md), [07-database-schema-and-migrations.md](07-database-schema-and-migrations.md), [08-policy-snapshot-and-enforcement.md](08-policy-snapshot-and-enforcement.md) |
| Clone lại data plane/agent | [04-data-plane-ebpf-xdp.md](04-data-plane-ebpf-xdp.md), [05-node-agent.md](05-node-agent.md), [08-policy-snapshot-and-enforcement.md](08-policy-snapshot-and-enforcement.md) |
| Clone lại dashboard | [09-admin-dashboard.md](09-admin-dashboard.md), [06-control-plane-api.md](06-control-plane-api.md) |
| Deploy, vận hành, test | [12-deployment-and-operations.md](12-deployment-and-operations.md), [13-testing-and-verification.md](13-testing-and-verification.md), [15-runbooks-and-troubleshooting.md](15-runbooks-and-troubleshooting.md) |
| Dựng lại từ đầu | [14-rebuild-guide.md](14-rebuild-guide.md), [16-source-traceability.md](16-source-traceability.md) |

## Danh Mục

1. [Executive Summary](00-executive-summary.md)
2. [Product Brief And Scope](01-product-brief-and-scope.md)
3. [Requirements And Success Criteria](02-requirements-and-success-criteria.md)
4. [System Context And Architecture](03-system-context-and-architecture.md)
5. [Data Plane eBPF/XDP](04-data-plane-ebpf-xdp.md)
6. [Node Agent](05-node-agent.md)
7. [Control Plane API](06-control-plane-api.md)
8. [Database Schema And Migrations](07-database-schema-and-migrations.md)
9. [Policy Snapshot And Enforcement](08-policy-snapshot-and-enforcement.md)
10. [Admin Dashboard](09-admin-dashboard.md)
11. [Observability, Alerting And Audit](10-observability-alerting-and-audit.md)
12. [Security, RBAC And Secrets](11-security-rbac-and-secrets.md)
13. [Deployment And Operations](12-deployment-and-operations.md)
14. [Testing And Verification](13-testing-and-verification.md)
15. [Rebuild Guide](14-rebuild-guide.md)
16. [Runbooks And Troubleshooting](15-runbooks-and-troubleshooting.md)
17. [Source Traceability](16-source-traceability.md)

## Sơ Đồ

Các sơ đồ Mermaid nằm trong [diagrams/](diagrams/):

| File | Mục đích |
|---|---|
| [system-context.mmd](diagrams/system-context.mmd) | System context, actor ngoài hệ thống và dependency |
| [container-architecture.mmd](diagrams/container-architecture.mmd) | Runtime container/component architecture |
| [packet-decision-flow.mmd](diagrams/packet-decision-flow.mmd) | Hot path quyết định packet trong XDP |
| [policy-snapshot-lifecycle.mmd](diagrams/policy-snapshot-lifecycle.mmd) | Vòng đời policy snapshot và A/B map apply |
| [agent-control-sequence.mmd](diagrams/agent-control-sequence.mmd) | Giao tiếp Agent-Control API |
| [database-erd.mmd](diagrams/database-erd.mmd) | ERD lõi |
| [rbac-tenant-flow.mmd](diagrams/rbac-tenant-flow.mmd) | Multi-tenant RBAC và RLS |
| [observability-flow.mmd](diagrams/observability-flow.mmd) | Metrics, events, alerts |
| [deployment-topology.mmd](diagrams/deployment-topology.mmd) | Lab deployment topology |

## Quy Ước Source Reference

- Đường dẫn source được ghi tương đối từ repo root.
- Khi có xung đột giữa tài liệu và source, source code hiện tại thắng.
- Không đưa secret thật, token thật, DSN thật hoặc thông tin vận hành nhạy cảm vào tài liệu.
- Các giới hạn an toàn XDP/NIC là bắt buộc: không attach XDP vào NIC thật nếu chưa có phê duyệt vận hành, inventory dịch vụ, vai trò interface và rollback plan.

## Source Alignment

- README hiện hữu: `README.md`
- Tài liệu nền: `docs/High-Level-Design.md`, `docs/Low-Level-Design.md`, `docs/System-Architecture-Design.md`, `docs/Control-Api.md`
- Trạng thái/decision: `.specs/project/STATE.md`, `.notebook/INDEX.md`
- Source chính: `bpf/`, `cmd/`, `internal/`, `web/dashboard/`, `deploy/`, `Makefile`, `docker-compose.yml`
