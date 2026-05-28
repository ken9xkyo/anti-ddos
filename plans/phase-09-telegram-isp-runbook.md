# Phase 09 - Telegram Alerting va ISP Runbook

## Muc tieu

Hoan thien alerting bat buoc cho MVP: alert schema, Telegram delivery, dedupe/rate-limit/retry, test alert workflow va manual ISP escalation runbook khi link/upstream vuot kha nang scrubbing node.

## Pham vi

- Alert Service trong Control Plane hoac service rieng, dung alert event contract da thiet ke.
- Telegram bot token/chat_id luu an toan, redact trong log/audit/API responses.
- Dedupe theo `dedupe_key`, severity, rule/service/vector/time window.
- Retry co exponential backoff va ghi tung delivery attempt.
- ISP escalation la manual runbook, khong tu dong BGP/RTBH/FlowSpec.

## Cong viec

| ID | Cong viec | Muc dich | Ket qua ban giao | Phu thuoc |
|---|---|---|---|---|
| P09-T01 | Implement alert schema va policies | Luu alert lifecycle va routing | Tables/API alerts, alert_policies, alert_deliveries | Phase 05 |
| P09-T02 | Implement Telegram config API | Cho admin/operator cau hinh kenh | Bot token secret ref, chat_id, parse mode, test endpoint | P09-T01 |
| P09-T03 | Implement alert creation API/service | Detection/feed/route tao alert thong nhat | `createAlert` voi severity, type, dedupe_key, evidence, action | P09-T01 |
| P09-T04 | Implement dedupe/rate-limit | Giam alert storm | Recent sent lookup theo dedupe_key va policy window | P09-T03 |
| P09-T05 | Implement Telegram `sendMessage` client | Gui canh bao bat buoc | Client render template, call API, handle response | P09-T02 |
| P09-T06 | Implement retry backoff va delivery log | Khong mat visibility khi API loi | Attempt records, sent/failed/deduped statuses | P09-T05 |
| P09-T07 | Implement test alert workflow | Xac minh config truoc su co | API/UI test alert va hien ket qua delivery | P09-T06 |
| P09-T08 | Wire alert producers | Cac subsystem tao alert dung contract | Auto-enforce, feed failure, redirect/neighbor failure, stale Agent alert producers | P09-T03 |
| P09-T09 | Implement route/link saturation evaluator | Phat hien can ISP escalation | Rule tu link utilization, packet loss, peak pps/bps, route failure | Phase 06 |
| P09-T10 | Build ISP escalation payload | Operator co thong tin gui ISP | Payload peak bps/pps, target, vector, start time, top sources summary | P09-T09 |
| P09-T11 | Add runbook dashboard view | Huong dan thao tac khi escalation | UI view cho escalation alert, copyable incident data, action checklist | P09-T10 |

## Tieu chi chap nhan

- Test alert gui Telegram thanh cong va hien delivery result tren dashboard.
- Alert trung `dedupe_key` trong rate-limit window bi mark deduped, khong spam Telegram.
- Telegram API loi duoc retry co backoff va ghi delivery failure neu het attempts.
- Auto-enforce, feed failure, redirect failure, neighbor unresolved, stale Agent va ISP escalation co the tao alert dung contract.
- ISP escalation alert gom peak bps/pps, affected service/target, vector, start time va top source summary neu co.
- Runbook hien ro day la escalation thu cong toi ISP, khong tu dong BGP/RTBH/FlowSpec.

## Kiem chung

- Unit tests cho dedupe key, rate-limit window va retry backoff.
- Integration test voi Telegram mock server: success, 429, 5xx, timeout, malformed response.
- UI test cho test alert va delivery log.
- Generate redirect/neighbor failure fixture, xac nhan alert type va evidence day du.
- Generate route/link saturation fixture, xac nhan alert type `isp_escalation_needed` va payload du truong.
- Secret redaction test cho token trong logs/audit/API response.

## Truy vet PRD

- PRD-002: dashboard hien active alerts va affected service.
- PRD-003: redirect target error tao alert/counter.
- PRD-008: Telegram alerting, dedupe, rate-limit, retry, test config.
- PRD-010: stale Agent/control-plane alert.
- PRD-011: manual ISP escalation runbook va evidence payload.

## Ghi chu va rui ro

- Telegram la kenh bat buoc cho MVP nhung van co the unavailable; delivery failure phai visible.
- Alert template can ngan gon, uu tien severity, affected service, vector, action va link investigation.
- Top source summary dua tren sampled events nen khong dam bao exact accounting trong attack rat lon.
- ISP escalation khong bao ve khi upstream/link da saturate neu khong co hanh dong tu ISP.

