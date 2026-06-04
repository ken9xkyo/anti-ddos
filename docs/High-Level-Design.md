# High-Level Design - Anti-DDoS Scrubbing Gateway eBPF/XDP

Trạng thái: tài liệu HLD được lập từ source code, README, `.specs/project/STATE.md` và [docs/System-Architecture-Design.md](System-Architecture-Design.md) ngày 2026-06-04.

Tài liệu này mô tả thiết kế mức cao của Anti-DDoS Scrubbing Gateway: một gateway lọc DDoS L3/L4 dùng XDP/eBPF trên host, Control API/PostgreSQL cho policy source of truth, Node Agent để load/apply policy vào eBPF maps, và Admin Dashboard/Prometheus/Grafana cho vận hành. HLD tập trung vào mục tiêu, ranh giới hệ thống, các plane chính, luồng runtime, yêu cầu phi chức năng, rủi ro và tiêu chí chấp nhận. Chi tiết map, schema, endpoint và sequence đã có trong tài liệu kiến trúc hệ thống và các tài liệu API liên quan.

## 1. Executive Summary

Anti-DDoS Scrubbing Gateway là scrubbing gateway L3/L4 đặt trước các protected backend service. Packet vào WAN NIC được xử lý sớm trong XDP/eBPF; chỉ lưu lượng hợp lệ theo service allowlist và policy runtime mới được rewrite MAC và redirect qua DEVMAP tới interface/backend phía sau.

Hệ thống được thiết kế theo nguyên tắc:

- Fail-closed: IPv4 traffic không khớp service đã khai báo bị drop với `REASON_NOT_ALLOWED_SERVICE`.
- Control Plane không ghi trực tiếp vào eBPF maps; mọi thay đổi policy đi qua PostgreSQL, snapshot versioned và Agent apply.
- Data Plane tối giản và bounded: parse L3/L4, lookup eBPF maps, count decision, sample event và redirect/drop.
- Operator có thể quan sát, thay đổi policy, rollback snapshot và điều tra sự kiện với audit trail.
- Detection baselines chỉ dùng để giám sát/cảnh báo; anomaly evaluation không tự tạo hoặc auto-enforce `rate_limit` rule.
- Lab-first: Docker Compose chỉ khởi động management/control stack; Node Agent trên host mới có quyền attach XDP và chỉ được chạy trên interface đã phê duyệt.

Hệ thống không kết thúc TLS, không proxy HTTP, không xử lý L7/DPI và không thay thế WAF.

## 2. Business Context

### 2.1 Vấn đề cần giải quyết

Khi protected service bị tấn công L3/L4, backend thường không nên là nơi đầu tiên xử lý lưu lượng bất thường. Cần một scrubbing gateway có thể loại bỏ traffic không thuộc service hợp lệ, chặn nguồn xấu, giới hạn tốc độ và chỉ forward traffic sạch tới backend. Đồng thời đội vận hành cần thay đổi policy nhanh, có rollback, có bằng chứng audit và có metrics để đánh giá tác động.

Detection baseline giải quyết nhu cầu nhận biết traffic lệch khỏi baseline và phát cảnh báo sớm mà không làm thay đổi policy runtime ngoài ý muốn. Operator xem anomaly score, source evidence và recommended action, sau đó quyết định có tạo rule `rate_limit`, blacklist hoặc hành động runbook khác bằng workflow policy thủ công.

### 2.2 Personas

| Persona | Nhu cầu chính | Quyền hạn mức cao |
|---|---|---|
| Viewer | Theo dõi health, events, services, snapshots, alerts và dashboards | Read-only sau khi xác thực |
| Operator | Vận hành chính sách, xử lý sự cố, rollback snapshot, test alert | Mutation operational có reason và audit |
| Admin | Quản trị người dùng, secret/config đặc quyền, session và password | Bao gồm Operator và các thao tác admin |

### 2.3 Mục tiêu thành công

- Traffic không thuộc protected service đã khai báo không được forward.
- Whitelist, blacklist, UDP source-port block, rule runtime và forwarding policy được phân phối bằng signed policy snapshot.
- Apply snapshot thất bại không làm đổi active runtime slot và được báo cáo qua `policy_apply_status`.
- Mọi mutation quan trọng có reason và audit event.
- Metrics/events được hiển thị qua Dashboard, Prometheus và Grafana để hỗ trợ điều tra và vận hành.
- Baseline/anomaly evaluation tạo visibility và alert-only signal; không có baseline nào tự enforce rate-limit trên Data Plane.

## 3. Scope And Non-Scope

### 3.1 In scope của MVP

- Một node Ubuntu 24.04, IPv4, native XDP là đường chạy chính.
- Data Plane XDP/eBPF xử lý service allowlist, whitelist, blacklist, UDP source-port block, rule action, rate-limit, event sampling và DEVMAP redirect.
- Node Agent chạy trên host để load/attach XDP, đồng bộ snapshot, resolve forwarding metadata, cập nhật eBPF maps và expose metrics.
- Control API Go và PostgreSQL làm source of truth cho users, sessions, policy objects, snapshots, events, alerts, audit và agent state.
- Admin Dashboard React/Vite, Prometheus và Grafana cho vận hành.
- Baselines/anomalies phục vụ detection posture: lưu baseline profile, ghi anomaly evaluation, tạo alert và guidance thủ công cho Operator.
- Docker Compose cho management/control lab stack.

### 3.2 Out of scope hiện tại

- TLS termination, HTTP reverse proxy, L7 inspection, DPI và WAF behavior.
- IPv6 data plane.
- Multi-node HA production, tenant/group model và centralized global policy distribution.
- BGP, RTBH, FlowSpec automation hoặc ISP escalation automation production.
- Attach XDP lên NIC production khi chưa có phê duyệt interface role, backend inventory và rollback plan.

## 4. High-Level Architecture

Hệ thống được chia thành năm plane để tách trách nhiệm và giảm blast radius.

| Plane | Thành phần | Trách nhiệm |
|---|---|---|
| Data Plane | `xdp_entry`, eBPF maps | Parse packet, enforce policy, count/drop/sample/redirect |
| Forwarding Plane | L2 MAC rewrite, `tx_devmap` | Forward traffic hợp lệ tới backend/output interface |
| Node Plane | Node Agent | Load/attach XDP, verify/apply snapshot, resolve route/neigh, expose host metrics |
| Control Plane | Control API, PostgreSQL | Auth/RBAC, policy CRUD, snapshot build/rollback, audit, agent state, events, alerts |
| Management Plane | Admin Dashboard, Prometheus, Grafana | Vận hành, điều tra, dashboard, alert visibility và reporting |

Sơ đồ tham chiếu:

- System context: [Mermaid](diagrams/system-architecture/system-context-c4.mmd), [SVG](diagrams/system-architecture/system-context-c4.svg)
- Runtime containers: [Mermaid](diagrams/system-architecture/runtime-containers-c4.mmd), [SVG](diagrams/system-architecture/runtime-containers-c4.svg)
- Lab deployment: [Mermaid](diagrams/system-architecture/lab-deployment-flow.mmd), [SVG](diagrams/system-architecture/lab-deployment-flow.svg)

## 5. Core Runtime Flows

### 5.1 Packet decision flow

Data Plane được thiết kế để ra quyết định sớm, có giới hạn state và không gọi Control Plane trên packet path.

Luồng xử lý mức cao:

1. Packet vào `xdp_entry` trên WAN NIC.
2. `runtime_config` được đọc để lấy active A/B policy slot, policy version, malformed action và event sampling denominator.
3. Non-IPv4 traffic được pass; IPv4 malformed hoặc fragment bị drop theo malformed/fragment policy.
4. Packet IPv4 hợp lệ được match theo destination IPv4, protocol và destination port trong `service_allowlist_a/b`.
5. Nếu không có service match, packet bị drop fail-closed với `REASON_NOT_ALLOWED_SERVICE`.
6. Whitelist được kiểm tra trước blacklist và UDP source-port block; source whitelisted được bỏ qua các threat block tương ứng.
7. Blacklist và UDP source-port block có thể drop packet với `REASON_BLACKLIST` hoặc `REASON_UDP_AMP_SOURCE_PORT`.
8. Service forwarding metadata phải resolved; nếu neighbor/output metadata chưa resolved thì drop với `REASON_NEIGHBOR_UNRESOLVED`.
9. Rule runtime có thể drop, observe, sample hoặc rate-limit theo threshold và dimension.
10. Traffic được chấp nhận sẽ rewrite Ethernet source/destination MAC và `bpf_redirect_map()` qua `tx_devmap`.

Sơ đồ chi tiết: [xdp-packet-decision-flow.mmd](diagrams/system-architecture/xdp-packet-decision-flow.mmd), [xdp-packet-decision-flow.svg](diagrams/system-architecture/xdp-packet-decision-flow.svg).

### 5.2 Policy snapshot lifecycle

Policy runtime không được push trực tiếp từ UI vào eBPF maps. Control API tạo snapshot bất biến, Agent verify và apply theo A/B slot.

Luồng mức cao:

1. Operator/Admin gửi mutation qua Dashboard hoặc API kèm `reason` hoặc `X-Audit-Reason`.
2. Control API kiểm tra RBAC, validate input, ghi PostgreSQL và audit event.
3. Control API rebuild effective policy snapshot từ database, tính canonical checksum và gắn `object_checksum`.
4. Nếu nội dung policy không đổi, Control API không tạo snapshot version mới.
5. Agent heartbeat định kỳ tới Control API để lấy desired policy version.
6. Khi có version mới, Agent fetch snapshot, verify schema/checksum/object checksum/capacity và cho phép service unresolved ở bước đầu.
7. Agent resolve forwarding metadata trên host nếu service còn unresolved.
8. Agent populate inactive A/B maps, cập nhật `tx_devmap`, sau đó flip `runtime_config.active_slot`.
9. Nếu bất kỳ bước nào fail trước runtime flip, active slot không đổi; Agent báo cáo error stage như `resolve_forwarding`, `populate_tx_devmap` hoặc `runtime_flip`.
10. Control API ghi kết quả vào `policy_apply_status` và có thể tạo alert nếu apply failed.

Sơ đồ chi tiết: [policy-snapshot-sequence.mmd](diagrams/system-architecture/policy-snapshot-sequence.mmd), [policy-snapshot-sequence.svg](diagrams/system-architecture/policy-snapshot-sequence.svg).

### 5.3 Observability and event flow

Observability tách counters nhanh trong XDP khỏi event chi tiết có sampling để tránh đưa dữ liệu raw packet vào hot path qua nhiều kênh.

Luồng mức cao:

1. XDP cập nhật `drop_counters` theo reason/action/service/rule/proto.
2. Khi sampling bật, XDP ghi `event_record` vào ringbuf `events`.
3. Agent đọc counters định kỳ, expose `/metrics` và cập nhật map/forwarding/snapshot metrics.
4. Agent consume ringbuf, normalize event batch và POST về Control API.
5. Control API lưu `security_events` vào PostgreSQL, gom source prefix phục vụ điều tra.
6. Dashboard đọc overview, events, baselines, anomalies, alerts, snapshots và fleet state qua Control API.
7. Prometheus scrape Control API và Agent metrics; Grafana hiển thị dashboard từ datasource Prometheus.

Anomaly evaluation dùng Prometheus metrics và baseline profile để ghi `anomaly_evaluations`. Khi score đủ ngưỡng, Control API tạo alert `anomaly` với `recommended_action` như `rate_limit`, nhưng không tạo rule, không rebuild snapshot và không làm thay đổi eBPF maps. Enforcement chỉ xảy ra khi Operator/Admin tạo hoặc sửa policy object như `rules`, blacklist hoặc UDP source-port block.

Sơ đồ chi tiết: [observability-events-sequence.mmd](diagrams/system-architecture/observability-events-sequence.mmd), [observability-events-sequence.svg](diagrams/system-architecture/observability-events-sequence.svg).

## 6. Data And Control Boundaries

### 6.1 Source of truth

PostgreSQL là source of truth cho:

- Users, sessions, RBAC state.
- Backend services, forwarding policies, whitelist, blacklist, UDP source-port blocks, rules và feed/reputation state.
- Baseline profiles và anomaly evaluations dùng cho detection/alert-only workflow.
- Immutable policy snapshots và rollback history.
- Agent registration, heartbeat, interfaces và policy apply status.
- Security events, alerts và audit events.

eBPF maps là runtime projection của latest applied snapshot trên từng host, không phải source of truth.

### 6.2 Control API boundary

Control API chịu trách nhiệm auth/RBAC, CRUD, validation, snapshot build, audit, alert và agent-facing API. Control API không attach XDP và không ghi trực tiếp vào pinned eBPF maps. Điều này giúp giữ boundary rõ ràng: Control Plane quyết định desired state, Node Agent quyết định khả năng apply trên host.

Chi tiết API: [docs/Control-Api.md](Control-Api.md).

### 6.3 Node Agent boundary

Node Agent là thành phần host-privileged. Agent:

- Load BPF object và verify map/program contract.
- Attach/detach XDP theo cấu hình và safety gate.
- Resolve output interface, ifindex, source MAC và next-hop MAC bằng host networking.
- Apply snapshot vào inactive maps, update `tx_devmap` và flip `runtime_config`.
- Lưu last-valid snapshot và expose Agent metrics.

Agent có thể chạy không đồng bộ Control API nếu dùng bootstrap/local snapshot, nhưng trong runtime control-plane flow thì Agent đồng bộ qua heartbeat/fetch/apply.

### 6.4 Management boundary

Admin Dashboard là UI vận hành trên Control API. UI có thể ẩn/disable mutation controls theo role, nhưng enforcement chính vẫn nằm ở backend. Prometheus/Grafana là observability surfaces, không phải source of truth policy.

Chi tiết UI: [docs/Admin-Dashboard-v2.md](Admin-Dashboard-v2.md).

## 7. Security, RBAC And Safety

### 7.1 Auth and RBAC

- User auth dùng bearer session token hoặc cookie `anti_ddos_session`.
- Agent auth dùng bearer shared token khi cấu hình.
- Viewer có quyền read, Operator có quyền mutation operational, Admin có quyền user/secret/session privileged operations.
- Backend là enforcement chính cho RBAC.

### 7.2 Audit and reason

- Mutation quan trọng yêu cầu reason từ body `reason` hoặc header `X-Audit-Reason`.
- Audit event lưu actor, action, entity, before/after và reason.
- Delete trong nhiều policy domain là soft-disable để giữ history/rollback.

### 7.3 Secret handling

- Raw password, raw credential và token không được trả về response hoặc audit.
- Secret/feed credential được biểu diễn bằng reference; tài liệu vận hành không nên ghi plaintext secret.
- Log/error phải tránh lộ raw DSN, token và credential.

### 7.4 XDP/NIC safety

- Docker Compose chỉ khởi động management/control stack; nó không attach XDP và không tác động trực tiếp production traffic.
- Node Agent chạy trên host và có thể attach XDP, vì vậy chỉ được chạy khi `AGENT_WAN_IFACE` và output interfaces đã được phê duyệt.
- Real NIC attach cần rollback plan riêng, xác nhận WAN/LAN/output role và backend inventory.
- Một số driver native XDP như `ixgbe` có thể cần output NIC chạy pass-through XDP program để DEVMAP redirect có TX queues.

Chi tiết deploy lab: [docs/deployment/docker-compose.md](deployment/docker-compose.md).

## 8. Non-Functional Requirements

| Requirement | HLD expectation |
|---|---|
| Performance | Packet path không gọi Control API/DB; lookup trong eBPF maps và redirect/drop trong XDP |
| Safety | Unknown service fail-closed; unresolved forwarding metadata không được redirect |
| Consistency | Policy runtime được version bằng signed snapshot và A/B map slot flip |
| Rollback | Rollback tạo snapshot version mới từ version cũ; Agent chỉ apply snapshot hợp lệ |
| Observability | Counters/events/metrics phân tách giữa XDP, Agent, Control API, Dashboard và Prometheus/Grafana |
| Capacity | Snapshot verify map capacity và estimated memory trước khi apply |
| Auditability | Operator/Admin mutation có reason và audit event |
| Detection safety | Baseline/anomaly workflow là alert-only; mitigation runtime phải đi qua policy mutation có audit |
| Operability | Lab-first deploy, health/metrics endpoints, last-valid snapshot và apply status rõ ràng |
| Security | RBAC backend, secret redaction, agent token support và không đưa raw secret vào docs/logs |

## 9. Risks And Constraints

| Risk / Constraint | Impact | Mitigation |
|---|---|---|
| Backend service inventory chưa đầy đủ | Có thể fail-closed traffic hợp lệ nếu service chưa khai báo | Network/SRE cung cấp service name, IP/CIDR, protocol, ports, owner, output interface và return path trước rollout |
| WAN/LAN/output interface roles chưa được phê duyệt | Attach XDP sai interface có thể gây gián đoạn traffic | Yêu cầu phê duyệt interface role và rollback plan trước khi chạy Agent trên NIC thật |
| Native XDP/driver constraints | DEVMAP redirect có thể lỗi trên một số driver/output interface | Dùng VETH lab trước; với driver cần TX queues, attach `xdp_pass` trên output NIC theo hướng dẫn |
| Benchmark chưa có | Chưa thể cam kết throughput 10/40 Gbps production | Lập benchmark matrix sau khi interface/backend inventory đã chốt |
| IPv4-only MVP | IPv6 traffic không được bảo vệ theo policy hiện tại | Ghi rõ non-scope, lập design riêng cho IPv6 nếu cần |
| Single-node MVP | Không có HA production trong thiết kế hiện tại | Định nghĩa HA/multi-node là future design, không ngầm hiểu sẵn sàng production HA |
| Policy/operator error | Mutation sai có thể drop traffic hợp lệ | RBAC, reason, audit, diff snapshot, rollback và staged lab verification |
| Auto-mitigation false positive | Nếu baseline tự enforce, spike hợp lệ có thể bị rate-limit ngoài ý muốn | Baseline/anomaly chỉ tạo alert và manual mitigation guidance; rule enforcement phải do Operator/Admin tạo có audit |

## 10. Acceptance Criteria

Tài liệu HLD được xem là đạt khi:

- Mô tả đúng Anti-DDoS Gateway là L3/L4 scrubbing gateway dùng XDP/eBPF, không phải WAF/L7 proxy.
- Giữ rõ ranh giới giữa Data Plane, Node Agent, Control API/PostgreSQL và Management Plane.
- Ghi rõ unknown service traffic fail-closed với `REASON_NOT_ALLOWED_SERVICE`.
- Ghi rõ snapshot apply failure không flip active runtime slot và được báo cáo qua apply status.
- Ghi rõ baselines/anomalies không auto-enforce `rate_limit`; chúng chỉ tạo alert/guidance và giữ enforcement trong workflow policy thủ công.
- Ghi rõ Compose không attach XDP; Node Agent trên host mới có khả năng attach XDP và cần interface đã phê duyệt.
- Link sang tài liệu chi tiết thay vì lặp lại toàn bộ endpoint/schema/eBPF ABI.
- Không đưa vào tài liệu bất kỳ secret, raw DSN, token hoặc credential plaintext.

## 11. Reference Documents

- [README.md](../README.md)
- [docs/System-Architecture-Design.md](System-Architecture-Design.md)
- [docs/Control-Api.md](Control-Api.md)
- [docs/Admin-Dashboard-v2.md](Admin-Dashboard-v2.md)
- [docs/deployment/docker-compose.md](deployment/docker-compose.md)
- [Core data model ERD](diagrams/system-architecture/core-data-model-erd.mmd)
- [Runtime containers C4](diagrams/system-architecture/runtime-containers-c4.mmd)
- [Packet decision flow](diagrams/system-architecture/xdp-packet-decision-flow.mmd)
- [Policy snapshot sequence](diagrams/system-architecture/policy-snapshot-sequence.mmd)
- [Observability events sequence](diagrams/system-architecture/observability-events-sequence.mmd)

## 12. Source Alignment Notes

Những điểm HLD đã đối chiếu trực tiếp với source:

- eBPF contract và map capacity: `include/anti_ddos/bpf_contract.h`, `internal/agent/contracts_bpf.go`.
- Packet decision path: `bpf/xdp_data_plane.bpf.c`.
- Snapshot verify/apply và A/B map flip: `internal/agent/policy_snapshot.go`, `internal/agent/policy_apply.go`.
- Snapshot build/rollback/fetch: `internal/control/snapshot.go`.
- Agent-facing API và management endpoints: `internal/control/server.go`.
- Dashboard API usage: `web/dashboard/src/api.ts`, `web/dashboard/src/DashboardShell.tsx`.
