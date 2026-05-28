# Phase 06 - Observability và Dashboard

## Mục tiêu

Xây dựng khả năng quan sát và dashboard vận hành cho P1: Prometheus scrape Agent/Control API, event ingestion cho sampled packet/rule events, dashboard realtime cho traffic/drop/redirect/rules/services/agents và Grafana dashboard tối thiểu.

## Phạm vi

- Prometheus scrape Agent và Control API.
- Metric labels bounded, không dùng raw source IP/CIDR trong high-cardinality labels.
- Event ingestion từ Agent vào Control API/PostgreSQL cho sampled packet/rule/redirect events.
- React dashboard tập trung vận hành, không landing page marketing.
- Grafana dashboards cho bps/pps/cps, drop/redirect, map utilization, neighbor health, alerts.

## Công việc

| ID | Công việc | Mục đích | Kết quả bàn giao | Phụ thuộc |
|---|---|---|---|---|
| P06-T01 | Chốt metric catalog `anti_ddos_*` | Thống nhất labels và naming | Metric definitions cho agent, XDP, traffic, maps, feed, alerts, redirect | Phase 02 |
| P06-T02 | Thêm Control API metrics | Quan sát API, snapshot, DB, alerts | `/metrics` cho API request, snapshot versions, apply status, DB health | Phase 05 |
| P06-T03 | Triển khai event ingestion endpoint | Lưu sampled packet/rule events | API receive events, validate, write `security_events` | Phase 05 |
| P06-T04 | Triển khai event query APIs | Dashboard tra cứu IP/subnet/service | APIs filter by time, service, src IP, action, reason, rule | P06-T03 |
| P06-T05 | Xây dựng overview dashboard view | Operator thấy tình trạng ngay | Realtime bps/pps/cps, drops, redirects, attack status, top ports | P06-T04 |
| P06-T06 | Xây dựng rules/mitigation view | Vận hành active rule và TTL | Rule table, action, mode, counters, TTL, evidence, rollback entrypoint | P06-T04 |
| P06-T07 | Xây dựng whitelist/blacklist views | Quản lý reputation và conflicts | Search CIDR, state, source, expiry, audit link, conflict display | P06-T04 |
| P06-T08 | Xây dựng service/forwarding view | Theo dõi backend allowlist và DEVMAP path | Service counters, not_allowed_service, redirect errors, neighbor status, output interface | P06-T04 |
| P06-T09 | Xây dựng Agent health/map view | Phát hiện stale và map gần đầy | XDP mode, policy version, map utilization, attach errors, devmap support | P06-T01 |
| P06-T10 | Tạo Grafana dashboards | Có dashboard Prometheus sẵn dùng | JSON dashboard bps/pps/drops/redirect/maps/neighbor/alerts | P06-T01 |
| P06-T11 | Thêm dashboard RBAC behavior | Viewer read-only trên UI | UI ẩn/chặn mutation cho Viewer, hiển thị audit/result cho mutations | Phase 05 |
| P06-T12 | Thêm dashboard freshness indicators | Biết dữ liệu có stale hay không | Last update timestamp, stale markers, apply pending/failed/applied state | P06-T05 |

## Tiêu chí chấp nhận

- Prometheus scrape được Agent và Control API metrics.
- Dashboard overview refresh dữ liệu chính trong mục tiêu <= 3 giây khi backend/API cho phép.
- Operator xem được XDP mode, policy version, map utilization, route/neighbor health và active rules.
- IP/subnet investigation hiện event history, counters, reputation/whitelist/blacklist state.
- Viewer không thấy hoặc không thực hiện được mutation actions.
- Grafana có dashboard tối thiểu cho traffic, decisions, redirect/neighbor health, map utilization và alerts.

## Kiểm chứng

- Prometheus target health xanh cho Agent và API.
- Metric label audit xác nhận không có `src_ip`, CIDR raw, alert text, username trong high-cardinality labels.
- UI integration tests cho Admin/Operator/Viewer.
- Nạp fixture sampled events và search trên dashboard.
- Sinh metrics not-allowed-service, redirect error và attach error, xác nhận hiện trên dashboard/Grafana.

## Truy vết PRD

- PRD-001: hiện baseline/anomaly inputs và low-confidence status cho Phase 07.
- PRD-002: realtime monitoring, Prometheus/Grafana.
- PRD-006: whitelist UI và conflict display.
- PRD-007: backend service allowlist, forwarding counters, neighbor health.
- PRD-008: alert visibility và delivery status nền tảng cho Phase 09.
- PRD-009: Viewer read-only và audit visibility.
- PRD-010: stale policy và apply status visibility.

## Ghi chú và rủi ro

- UI ưu tiên thông tin vận hành đầy đủ, không tạo landing/marketing page.
- Dùng PostgreSQL events cho top source và investigation để tránh Prometheus cardinality cao.
- Dashboard data freshness phụ thuộc scrape interval, API polling/websocket và aggregation path.
- Mutations trên UI phải yêu cầu reason khi policy/audit cần.
