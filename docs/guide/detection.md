# Trang Detection

## Mục đích

`Detection` là trang quan sát posture phát hiện bất thường. Trang này hiển thị anomaly evaluation, baseline profile và active rules ở chế độ read-only để người vận hành hiểu hệ thống đang cảnh báo hoặc gợi ý điều tra điều gì.

## Ai dùng

Tất cả role đều dùng được trang này. Trang không có nút mutation; CRUD rule nằm ở `Rules`.

## Thành phần UI

- `Anomalies / Alerts`: bảng evaluation gồm service, score, confidence, signals, recommended action, source, status và evaluated time.
- `Baselines`: bảng baseline gồm service, interface, protocol/port, window, expected PPS/BPS/CPS, history, confidence và status.
- `Active Rules`: bảng rule đang được dashboard biết tới, gồm name, action, mode, dimension, thresholds, TTL, confidence, counters và state.

## Dữ liệu và API liên quan

- Anomaly lấy từ API anomalies trong dashboard polling.
- Baseline lấy từ API baselines.
- Active rules dùng dữ liệu rules trong dashboard polling, không phải luồng CRUD riêng của tab `Rules`.

## Thao tác chính

1. Xem `Anomalies / Alerts` để xác định service nào đang có score cao, confidence cao hoặc cần operator xử lý.
2. Kiểm tra `Signals` để biết nguyên nhân như spike PPS/BPS/CPS hoặc drop ratio.
3. Xem `Recommended action` trước khi tự tạo rule ở `Rules`.
4. Đối chiếu `Baselines` để biết baseline có đủ history và đã approved hay chưa.
5. Xem `Active Rules` để biết rule đang tồn tại ở posture hiện tại.

## Trạng thái rỗng và lỗi

- Nếu chưa có anomaly, bảng hiển thị `No anomaly evaluations available`.
- Nếu chưa có baseline, bảng hiển thị `No baseline profiles configured`.
- Nếu chưa có rule, bảng hiển thị `No mitigation rules configured`.

## Lưu ý vận hành

- `observe_only` nghĩa là hệ thống đang quan sát, chưa enforce.
- `alert_only` nghĩa là hệ thống đã ghi anomaly và alert, nhưng không tạo rule hoặc enforce traffic.
- Whitelist conflict nếu có chỉ là evidence để triage, không còn là trạng thái chặn auto-enforcement.
- Baseline có history thấp hoặc chưa approved nên được xem là tín hiệu tham khảo, không phải bằng chứng độc lập để block traffic.
