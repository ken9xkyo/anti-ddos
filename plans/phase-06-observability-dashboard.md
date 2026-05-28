# Phase 06 - Observability va Dashboard

## Muc tieu

Xay dung observability va dashboard van hanh cho P1: Prometheus scrape Agent/Control API, event ingestion cho sampled packet/rule events, dashboard realtime cho traffic/drop/redirect/rules/services/agents va Grafana dashboard toi thieu.

## Pham vi

- Prometheus scrape Agent va Control API.
- Metric labels bounded, khong dung raw source IP/CIDR trong high-cardinality labels.
- Event ingestion tu Agent vao Control API/PostgreSQL cho sampled packet/rule/redirect events.
- React dashboard tap trung van hanh, khong landing page marketing.
- Grafana dashboards cho bps/pps/cps, drop/redirect, map utilization, neighbor health, alerts.

## Cong viec

| ID | Cong viec | Muc dich | Ket qua ban giao | Phu thuoc |
|---|---|---|---|---|
| P06-T01 | Chot metric catalog `anti_ddos_*` | Thong nhat labels va naming | Metric definitions cho agent, XDP, traffic, maps, feed, alerts, redirect | Phase 02 |
| P06-T02 | Add Control API metrics | Quan sat API, snapshot, DB, alerts | `/metrics` cho API request, snapshot versions, apply status, DB health | Phase 05 |
| P06-T03 | Implement event ingestion endpoint | Luu sampled packet/rule events | API receive events, validate, write `security_events` | Phase 05 |
| P06-T04 | Implement event query APIs | Dashboard tra cuu IP/subnet/service | APIs filter by time, service, src IP, action, reason, rule | P06-T03 |
| P06-T05 | Build overview dashboard view | Operator thay tinh trang ngay | Realtime bps/pps/cps, drops, redirects, attack status, top ports | P06-T04 |
| P06-T06 | Build rules/mitigation view | Van hanh active rule va TTL | Rule table, action, mode, counters, TTL, evidence, rollback entrypoint | P06-T04 |
| P06-T07 | Build whitelist/blacklist views | Quan ly reputation va conflicts | Search CIDR, state, source, expiry, audit link, conflict display | P06-T04 |
| P06-T08 | Build service/forwarding view | Theo doi backend allowlist va DEVMAP path | Service counters, not_allowed_service, redirect errors, neighbor status, output interface | P06-T04 |
| P06-T09 | Build Agent health/map view | Phat hien stale va map gan day | XDP mode, policy version, map utilization, attach errors, devmap support | P06-T01 |
| P06-T10 | Create Grafana dashboards | Co dashboard Prometheus san dung | JSON dashboard bps/pps/drops/redirect/maps/neighbor/alerts | P06-T01 |
| P06-T11 | Add dashboard RBAC behavior | Viewer read-only tren UI | UI hides/blocks mutation for Viewer, shows audit/result for mutations | Phase 05 |
| P06-T12 | Add dashboard freshness indicators | Biet du lieu co stale hay khong | Last update timestamp, stale markers, apply pending/failed/applied state | P06-T05 |

## Tieu chi chap nhan

- Prometheus scrape duoc Agent va Control API metrics.
- Dashboard overview refresh du lieu chinh trong muc tieu <= 3 giay khi backend/API cho phep.
- Operator xem duoc XDP mode, policy version, map utilization, route/neighbor health va active rules.
- IP/subnet investigation hien event history, counters, reputation/whitelist/blacklist state.
- Viewer khong thay hoac khong thuc hien duoc mutation actions.
- Grafana co dashboard toi thieu cho traffic, decisions, redirect/neighbor health, map utilization va alerts.

## Kiem chung

- Prometheus target health xanh cho Agent va API.
- Metric label audit xac nhan khong co `src_ip`, CIDR raw, alert text, username trong high-cardinality labels.
- UI integration tests cho Admin/Operator/Viewer.
- Insert sampled events fixture va search tren dashboard.
- Generate not-allowed-service, redirect error va attach error metrics, xac nhan hien tren dashboard/Grafana.

## Truy vet PRD

- PRD-001: hien baseline/anomaly inputs va low-confidence status cho Phase 07.
- PRD-002: realtime monitoring, Prometheus/Grafana.
- PRD-006: whitelist UI va conflict display.
- PRD-007: backend service allowlist, forwarding counters, neighbor health.
- PRD-008: alert visibility va delivery status nen tang cho Phase 09.
- PRD-009: Viewer read-only va audit visibility.
- PRD-010: stale policy va apply status visibility.

## Ghi chu va rui ro

- UI uu tien thong tin van hanh day du, khong tao landing/marketing page.
- Dung PostgreSQL events cho top source va investigation de tranh Prometheus cardinality cao.
- Dashboard data freshness phu thuoc scrape interval, API polling/websocket va aggregation path.
- Mutations tren UI phai yeu cau reason khi policy/audit can.

