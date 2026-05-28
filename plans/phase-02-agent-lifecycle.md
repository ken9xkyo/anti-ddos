# Phase 02 - Agent Lifecycle

## Muc tieu

Xay dung Node Agent de quan ly lifecycle data plane: load/attach native XDP, fallback co canh bao, pin maps, rollback program, doc counters/events, expose `/metrics` va giu last-valid snapshot khi Control Plane khong san sang.

## Pham vi

- Agent la process chay tren scrubbing node Ubuntu 24.04.
- Quan ly eBPF object C/libbpf thong qua libbpf binding hoac wrapper phu hop.
- Attach vao WAN interface, uu tien native XDP; generic fallback chi khi policy cho phep.
- Pin maps/program metadata de ho tro restart, debug va rollback.
- Doc per-CPU counters, ringbuf events, map utilization va expose Prometheus metrics toi thieu.
- Chua can Control Plane API day du; co local/mock snapshot de test restart va fail-safe.

## Cong viec

| ID | Cong viec | Muc dich | Ket qua ban giao | Phu thuoc |
|---|---|---|---|---|
| P02-T01 | Tao Agent service skeleton | Co runtime quan ly XDP rieng biet | Binary agent, config loader, structured logging, signal handling | Phase 01 |
| P02-T02 | Load eBPF object va discover maps | Ket noi userspace voi data plane | Loader load object, lay program/map handles, validate object version | P02-T01 |
| P02-T03 | Attach native XDP vao WAN interface | Dat filtering o ingress som nhat | Attach flow native mode voi status metric | P02-T02 |
| P02-T04 | Implement fallback generic theo config | Van co che do chay khi native fail | Fallback logic, performance warning, attach error counter | P02-T03 |
| P02-T05 | Pin maps va program metadata | Ho tro restart/debug/rollback | Pin path convention, program version/checksum metadata | P02-T02 |
| P02-T06 | Rollback program khi load/attach fail | Khong lam mat data plane dang chay | Previous-program retention va rollback procedure | P02-T05 |
| P02-T07 | Doc per-CPU counters dinh ky | Bien XDP counters thanh metrics | Counter aggregator packets/bytes theo labels bounded | P02-T02 |
| P02-T08 | Consume ringbuf events | Day sampled security events len pipeline sau | Ringbuf consumer co backpressure va reconnect handling | P02-T02 |
| P02-T09 | Expose `/metrics` | Prometheus scrape duoc Agent | Metrics endpoint cho health, mode, counters, map utilization | P02-T07 |
| P02-T10 | Luu va load last-valid snapshot local | Dam bao restart khong can Control Plane ngay | Snapshot file/db local, checksum verification | P02-T01 |
| P02-T11 | Implement healthcheck va safe detach policy | Van hanh an toan khi stop/restart | Health endpoint, uptime metric, optional detach theo config | P02-T09 |
| P02-T12 | Redact sensitive config/log values | Tranh lo secret tu agent logs | Log redaction cho token, key, DSN sensitive | P02-T01 |

## Tieu chi chap nhan

- Agent attach XDP native thanh cong tren interface cau hinh, hoac fallback generic co metric/canh bao khi policy cho phep.
- Load/attach failure khong detach program dang chay neu rollback khong thanh cong.
- `/metrics` expose agent up, XDP mode, attach errors, packet counters, redirect counters va map utilization.
- Agent restart co the load last-valid snapshot local truoc khi sync snapshot moi.
- Ringbuf consumer khong block packet path va co counter cho event dropped/consume errors.

## Kiem chung

- Chay Agent trong lab voi VETH hoac NIC test, xac nhan XDP program attach bang `ip link` va `bpftool prog`.
- Kill/restart Agent, xac nhan program/map state khong bi mat ngoai detach policy da cau hinh.
- Ep native attach fail tren interface khong ho tro de xac nhan fallback/canh bao.
- Scrape `/metrics` va kiem tra metric names/labels bounded.
- Tao ringbuf event tu packet fixture va xac nhan Agent consume khong crash.

## Truy vet PRD

- PRD-002: Agent metrics endpoint va map utilization.
- PRD-003: native XDP attach, fallback, load failure handling.
- PRD-007: expose redirect/neighbor metrics groundwork.
- PRD-010: last-valid snapshot, control-plane fail-safe, agent restart behavior.

## Ghi chu va rui ro

- Neu Go binding khong ho tro libbpf feature can dung, boc C/libbpf nho va giu API userspace on dinh.
- Safe detach can theo policy: production thuong khong tu detach khi stop neu dieu do lam backend mat protection.
- Prometheus labels khong duoc chua raw source IP/CIDR de tranh cardinality cao.
- Log phai redact secret/config sensitive ngay tu phase nay.

