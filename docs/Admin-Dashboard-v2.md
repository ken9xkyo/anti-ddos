# Admin Dashboard v2

## 1. Muc tieu

Admin Dashboard v2 la giao dien van hanh chinh cho Anti-DDoS Scrubbing Gateway. V2 tap trung vao mot ops console day dac, chuyen nghiep va thuc dung cho SRE/SOC theo doi, dieu tra va thao tac nhanh tren Control Plane hien co.

Pham vi v2:

- Lam lai UX/UI tren React/Vite dashboard hien co.
- Su dung API Control Plane hien co, khong them migration, endpoint Go, eBPF contract hay DB schema.
- Uu tien kha nang scan nhanh: trang thai attack, agent, policy apply, services, alerts, feeds va sampled events.
- Giu RBAC hien tai: Viewer chi doc; Operator thao tac van hanh da co; Admin cau hinh Telegram.

Ngoai pham vi v2:

- Khong lam full user management console.
- Khong them rule CRUD, whitelist CRUD, feed CRUD neu API/UI hien tai chua ho tro.
- Khong them snapshot diff/rollback UI nang cao.
- Khong thay Grafana; dashboard nay bo sung luong van hanh Control Plane.
- Khong them chart/UI framework moi.

## 2. Personas va quyen

| Persona | Muc tieu chinh | Quyen dashboard |
|---|---|---|
| Viewer | Theo doi tinh trang, xem services, alerts, events, feeds | Chi doc; khong hien mutation entrypoints |
| Operator | Truc van hanh, tao/sua/disable service, test alert, chay ISP runbook | Duoc thao tac cac action van hanh hien co |
| Admin | Quan tri kenh canh bao va cac thao tac rui ro cao | Bao gom Operator va cau hinh Telegram |

Nguyen tac RBAC:

- Moi mutation phai co reason/audit theo contract hien co.
- Viewer khong thay nut tao/sua/xoa/test/cau hinh.
- Cac nut khong co handler thuc thi khong duoc hien thi.

## 3. Navigation v2

Dashboard dung sidebar/tabs theo nhom van hanh:

| View | Muc dich | Noi dung chinh |
|---|---|---|
| Overview | Tinh trang he thong trong 1 man hinh | Traffic, drops/redirects, Prometheus, agents, policy version, top sources/ports, anomaly/alert moi |
| Incidents | Alerting va ISP runbook | Alerts, Telegram status/test, delivery log, payload ISP escalation thu cong |
| Services | Protected backend service registry | Search/filter, create/edit/disable, output interface metadata, apply failure |
| Detection | Mitigation va anomaly posture | Anomalies, baselines, active rules, TTL/confidence/evidence |
| Reputation | Threat feed posture | Feed status, run history, whitelist conflicts |
| Fleet | Agent va XDP fleet | Agent health, XDP mode, policy version, interfaces, map utilization, apply status |
| Investigation | Event investigation | Recent sampled events, query source/IP/subnet qua endpoint investigate |

## 4. Feature set

### 4.1 Overview

- Hien thi pps, bps, cps tu Prometheus proxy khi Prometheus duoc cau hinh.
- Hien thi drop/redirect/not_allowed_service decision rates neu co.
- Hien thi Prometheus healthy/unconfigured/error ro rang.
- Hien thi agent online/stale va policy snapshot version hien tai.
- Hien thi latest apply status theo fleet, bao gom failed/pending/applied.
- Hien top source /24, top ports va decision samples tu security event summary.
- Hien anomaly moi nhat va alert moi nhat de operator co huong dieu tra.

### 4.2 Incidents

- Hien Telegram channel status: enabled/disabled, token present/missing, chat id.
- Admin duoc cap nhat Telegram config bang secret reference, khong nhap plaintext token.
- Operator/Admin duoc gui test alert va evaluate ISP escalation bang API hien co.
- Alerts table hien severity, type, affected service, vector, status, delivery moi nhat va recommended action.
- ISP runbook chi ro manual escalation, khong tu dong BGP/RTBH/FlowSpec.
- Payload escalation can copy/inspect duoc va uu tien peak bps/pps, vector, target, top sources neu co.

### 4.3 Services

- Search/filter theo name, backend CIDR, output interface, owner, criticality, ports, protocol va enabled state.
- Operator/Admin co create/edit/delete-disable flow hien co.
- Form service mac dinh disabled de tranh apply nham.
- Output interface dropdown lay tu Agent reported interfaces; khi chon interface thi autofill ifindex/source MAC neu co.
- Service enabled bat buoc co resolved ifindex va source MAC tu Agent-reported interface; next-hop MAC do resolver/Agent tu resolve va dashboard khong cho nhap tay.
- Apply failure cua agent/policy phai hien ro stage va reason.
- Viewer chi xem danh sach va trang thai.

### 4.4 Detection

- Anomalies hien service, score, confidence, signals, recommendation, TTL, source va status.
- Baselines hien service, interface, protocol/port, window, pps/bps/cps expected, confidence va low-confidence state.
- Rules hien action, mode, dimension, thresholds, TTL remaining, confidence, state va counters neu co.
- V2 khong them rule CRUD; cac action nay nam trong backlog.

### 4.5 Reputation

- Feed sources hien enabled/status, active entries, conflicts, parse errors, next run va license note.
- Run history hien fetched/valid/parse errors/snapshot.
- Whitelist conflicts hien reputation CIDR, whitelist CIDR, source va detected time.
- V2 khong them feed CRUD/sync UI neu khong co handler day du.

### 4.6 Fleet

- Agent table hien hostname, stale/online, XDP mode, active policy, DEVMAP support va latest apply.
- Interface metadata hien name, role, ifindex, MAC, link speed.
- Map utilization JSON hien dang compact/inspectable neu Agent report.
- Stale agent va apply failure phai noi bat nhung khong che khuong bo cuc.

### 4.7 Investigation

- Recent sampled events hien time, source, target, protocol, action, reason, rule/service, sample rate.
- Investigation form goi `/v1/security-events/investigate?target=...`.
- Ket qua query dung table rieng, khong lam mat recent events.
- Empty state phai ro rang khi khong co samples hoac khong co ket qua.

## 5. Data states

| State | Yeu cau UI |
|---|---|
| Loading | Shell van render, noi dung hien loading state khong giat layout |
| Empty | Hien message ngan theo tung table/view, khong hien table trong |
| Error | Banner co error body tu API, giu du lieu cu neu co |
| Stale | Freshness chip chuyen warn neu qua nguong refresh |
| Unconfigured | Prometheus/Telegram hien unconfigured/missing thay vi crash |
| Failed apply | Hien agent, policy version, stage va reason |
| Read-only | Viewer thay data nhung khong thay mutation controls |

## 6. UX va visual

- Layout uu tien scan va thao tac lap lai, khong dung hero/marketing.
- Mau sac restrained: nen trung tinh, accent teal cho healthy/control, amber cho warn, red cho danger, blue cho informational data.
- Border radius toi da 8px.
- Tables co horizontal scroll tren mobile va min-width on dinh.
- Text trong chip/button/table khong overlap; dung wrap/ellipsis khi can.
- Icon dung `lucide-react` cho action/status quen thuoc.
- Khong dung card long nhau; panels la cac vung doc lap.

## 7. Backlog sau v2

- Rule CRUD, whitelist CRUD va blacklist manual management.
- Feed source CRUD/sync nang cao.
- Snapshot version diff, rollback UI va audit timeline.
- User/RBAC management UI.
- Incident lifecycle workflow day du.
- Grafana deep links theo service/rule/agent.
- Saved filters va URL state cho dashboard views.
