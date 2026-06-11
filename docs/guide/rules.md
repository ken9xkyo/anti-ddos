# Trang Rules

## Mục đích

`Rules` quản lý mitigation rule. Trang này dùng cho CRUD rule, đặt threshold, scope theo service hoặc global, nhập JSON match/evidence và soft-disable rule khỏi snapshot active tiếp theo.

## Ai dùng

- `user`: tạo, sửa và disable rule của chính mình.
- `admin`: chỉ xem read-only khi đang ở `View config` context.

## Thành phần UI

- `Rule CRUD`: header hiển thị số mitigation rules và nút `Add rule` khi user có quyền mutate.
- Bảng rule dùng Data Grid với các cột: `Name`, `Scope`, `Action`, `Mode`, `Dimension`, `Thresholds`, `TTL`, `Confidence`, `Expires`, `State`, `Actions`.
- Drawer `Add Rule` hoặc `Edit ...` gồm:
  - `Name`, `Service scope`, `Action`, `Mode`, `Dimension`, `Priority`.
  - Threshold: `PPS`, `BPS`, `CPS`.
  - Burst/sample: `Burst packets`, `Burst bytes`, `Sample denom`.
  - Thời gian/tin cậy: `TTL seconds`, `Confidence`, `Expires at`.
  - `Owner`, checkbox `Enabled`.
  - `Match expression` và `Evidence` dạng JSON object.
  - `Reason`.
- Confirm dialog `Disable ...` yêu cầu `Reason`.

## Dữ liệu và API liên quan

- Trang lazy-load rule qua API rules khi mở tab.
- Create/update rule gửi dữ liệu từ drawer.
- Disable rule dùng API delete/disable với reason; backend rebuild policy snapshot và giữ audit before/after.

## Thao tác chính

1. Chọn `Add rule` để tạo rule mới hoặc `Edit` trên một dòng để sửa.
2. Chọn `Service scope`: để trống là `Global`, chọn service để giới hạn rule theo service.
3. Chọn `Action` theo mục tiêu vận hành: `observe`, `drop`, `rate_limit` hoặc `sample`.
4. Chọn `Mode`: `observe` để theo dõi, `enforce` để thực thi.
5. Điền threshold, burst, TTL, confidence và expiry nếu rule cần tự hết hạn hoặc cần metadata điều tra.
6. Nhập `Match expression` và `Evidence` bằng JSON object hợp lệ nếu cần.
7. Nhập `Reason` rồi `Save rule`.
8. Khi muốn gỡ rule khỏi snapshot active tiếp theo, chọn `Disable` và nhập reason.

## Trạng thái rỗng và lỗi

- Nếu chưa có rule, bảng hiển thị `No mitigation rules configured`.
- Nếu JSON không hợp lệ hoặc không phải object, UI báo lỗi `JSON value must be an object`.
- Các trường số phải là số không âm; UI báo lỗi nếu nhập số âm hoặc không phải số.

## Lưu ý vận hành

- `Rules` là nơi xem và thay đổi rule; mọi thay đổi cần reason để audit.
- Disable là soft-disable: rule vẫn nhìn thấy trong lịch sử/danh sách nhưng bị loại khỏi snapshot active tiếp theo.
- `Mode` và `Action` nên được chọn thận trọng. `drop` hoặc `rate_limit` ở `enforce` có thể tác động traffic thật.
