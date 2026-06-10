# Trang Incidents

## Mục đích

`Incidents` tập trung vào cảnh báo vận hành, trạng thái kênh Telegram và runbook escalation thủ công tới ISP. Trang này giúp người trực kiểm tra alert gần nhất và chuẩn bị payload cần thiết khi sự cố vượt khả năng xử lý nội bộ.

## Ai dùng

- `viewer`: xem alert, Telegram state và runbook ở chế độ đọc.
- `operator`: cấu hình Telegram của tenant, gửi test alert và chạy đánh giá ISP runbook.
- `admin`: có toàn bộ quyền operator.

## Thành phần UI

- `Telegram Channel`: trạng thái enabled/disabled, token present/missing, chat id và parse mode.
- Form cấu hình Telegram cho operator/admin: `Bot token`, `Chat ID`, `Parse mode`, `Reason`, `Enabled`.
- Nút `Test alert`: gửi cảnh báo thử qua kênh Telegram.
- Nút `ISP runbook`: gọi đánh giá escalation thủ công.
- `Alerts`: bảng alert gần đây gồm time, severity, type, service, vector, status, delivery và recommended action.
- `ISP Escalation Runbook`: hiển thị mode, automation policy, target, vector và JSON evidence/payload.

## Dữ liệu và API liên quan

- Dashboard đọc alert và Telegram config qua các endpoint alert/Telegram.
- Mutation dùng các API cấu hình Telegram, test Telegram và evaluate ISP escalation.
- Telegram token là dữ liệu nhạy cảm: dashboard chỉ hiển thị `*****` khi token đã tồn tại.

## Thao tác chính

1. Kiểm tra `Telegram Channel` để biết kênh alert đã enabled và có token hay chưa.
2. Với role operator/admin, cập nhật token/chat/parse mode và nhập `Reason` rõ ràng trước khi `Save config`.
3. Với operator/admin, dùng `Test alert` sau khi cấu hình để kiểm tra đường gửi.
4. Khi có nguy cơ link saturation, chọn `ISP runbook` để tạo hoặc cập nhật alert escalation.
5. Dùng bảng `Alerts` để kiểm tra severity, vector, delivery attempt và recommended action.

## Trạng thái rỗng và lỗi

- Nếu không có alert trong cửa sổ hiện tại, bảng hiển thị `No alerts in the current window`.
- Nếu user không phải operator/admin, form cấu hình Telegram không xuất hiện và có thông báo cần operator role.
- Kết quả action hiển thị inline; lỗi request hoặc failed delivery sẽ được đánh dấu theo tone lỗi.

## Lưu ý vận hành

- `ISP Escalation Runbook` là thủ công. Dashboard không tự động chạy BGP, RTBH hoặc FlowSpec.
- Không nhập token Telegram vào nơi khác ngoài form dành cho operator/admin.
- `Test alert` nên được dùng sau thay đổi cấu hình, nhưng không nên xem test thành công là bằng chứng mọi alert nghiệp vụ đều đã được xử lý đúng.
