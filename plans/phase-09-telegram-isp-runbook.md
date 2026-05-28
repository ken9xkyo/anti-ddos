# Phase 09 - Telegram Alerting và ISP Runbook

## Mục tiêu

Hoàn thiện alerting bắt buộc cho MVP: alert schema, Telegram delivery, dedupe/rate-limit/retry, test alert workflow và manual ISP escalation runbook khi link/upstream vượt khả năng scrubbing node.

## Phạm vi

- Alert Service trong Control Plane hoặc service riêng, dùng alert event contract đã thiết kế.
- Telegram bot token/chat_id lưu an toàn, redact trong log/audit/API responses.
- Dedupe theo `dedupe_key`, severity, rule/service/vector/time window.
- Retry có exponential backoff và ghi từng delivery attempt.
- ISP escalation là manual runbook, không tự động BGP/RTBH/FlowSpec.

## Công việc

| ID | Công việc | Mục đích | Kết quả bàn giao | Phụ thuộc |
|---|---|---|---|---|
| P09-T01 | Triển khai alert schema và policies | Lưu alert lifecycle và routing | Tables/API alerts, alert_policies, alert_deliveries | Phase 05 |
| P09-T02 | Triển khai Telegram config API | Cho admin/operator cấu hình kênh | Bot token secret ref, chat_id, parse mode, test endpoint | P09-T01 |
| P09-T03 | Triển khai alert creation API/service | Detection/feed/route tạo alert thống nhất | `createAlert` với severity, type, dedupe_key, evidence, action | P09-T01 |
| P09-T04 | Triển khai dedupe/rate-limit | Giảm alert storm | Recent sent lookup theo dedupe_key và policy window | P09-T03 |
| P09-T05 | Triển khai Telegram `sendMessage` client | Gửi cảnh báo bắt buộc | Client render template, call API, handle response | P09-T02 |
| P09-T06 | Triển khai retry backoff và delivery log | Không mất visibility khi API lỗi | Attempt records, sent/failed/deduped statuses | P09-T05 |
| P09-T07 | Triển khai test alert workflow | Xác minh config trước sự cố | API/UI test alert và hiện kết quả delivery | P09-T06 |
| P09-T08 | Kết nối alert producers | Các subsystem tạo alert đúng contract | Auto-enforce, feed failure, redirect/neighbor failure, stale Agent alert producers | P09-T03 |
| P09-T09 | Triển khai route/link saturation evaluator | Phát hiện cần ISP escalation | Rule từ link utilization, packet loss, peak pps/bps, route failure | Phase 06 |
| P09-T10 | Tạo ISP escalation payload | Operator có thông tin gửi ISP | Payload peak bps/pps, target, vector, start time, top sources summary | P09-T09 |
| P09-T11 | Thêm runbook dashboard view | Hướng dẫn thao tác khi escalation | UI view cho escalation alert, copyable incident data, action checklist | P09-T10 |

## Tiêu chí chấp nhận

- Alert thử gửi Telegram thành công và hiện delivery result trên dashboard.
- Alert trùng `dedupe_key` trong rate-limit window bị mark deduped, không spam Telegram.
- Telegram API lỗi được retry có backoff và ghi delivery failure nếu hết attempts.
- Auto-enforce, feed failure, redirect failure, neighbor unresolved, stale Agent và ISP escalation có thể tạo alert đúng contract.
- ISP escalation alert gồm peak bps/pps, affected service/target, vector, start time và top source summary nếu có.
- Runbook hiện rõ đây là escalation thủ công tới ISP, không tự động BGP/RTBH/FlowSpec.

## Kiểm chứng

- Unit tests cho dedupe key, rate-limit window và retry backoff.
- Integration test với Telegram mock server: success, 429, 5xx, timeout, malformed response.
- UI test cho test alert và delivery log.
- Sinh redirect/neighbor failure fixture, xác nhận alert type và evidence đầy đủ.
- Sinh route/link saturation fixture, xác nhận alert type `isp_escalation_needed` và payload đủ trường.
- Secret redaction test cho token trong logs/audit/API response.

## Truy vết PRD

- PRD-002: dashboard hiện active alerts và affected service.
- PRD-003: redirect target error tạo alert/counter.
- PRD-008: Telegram alerting, dedupe, rate-limit, retry, test config.
- PRD-010: stale Agent/control-plane alert.
- PRD-011: manual ISP escalation runbook và evidence payload.

## Ghi chú và rủi ro

- Telegram là kênh bắt buộc cho MVP nhưng vẫn có thể unavailable; delivery failure phải visible.
- Alert template cần ngắn gọn, ưu tiên severity, affected service, vector, action và link investigation.
- Top source summary dựa trên sampled events nên không đảm bảo exact accounting trong attack rất lớn.
- ISP escalation không bảo vệ khi upstream/link đã saturate nếu không có hành động từ ISP.
