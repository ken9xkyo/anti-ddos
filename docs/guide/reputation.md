# Trang Reputation

## Mục đích

`Reputation` quản lý nguồn threat feed và quan sát kết quả ingest reputation. Trang này giúp vận hành feed source, xem lịch sử sync, parse error và xung đột giữa reputation CIDR với whitelist.

## Ai dùng

- `viewer`: xem feed source, run history và conflict.
- `operator`: tạo, sửa, sync và disable feed source.
- `admin`: có toàn bộ quyền operator và được cấu hình `Credential ref`.

## Thành phần UI

- `Threat Feed Management`: header hiển thị số feed sources và nút `Add feed`.
- Data Grid feed sources gồm: `Name`, `Type`, `Status`, `Active`, `Conflicts`, `Parse errors`, `Next run`, `License`, `Actions`.
- Drawer `Add Feed Source` hoặc `Edit ...` gồm:
  - `Name`, `Type`, `Interval seconds`, `URL`.
  - `Credential ref` chỉ enable với admin.
  - `Status`, `License note`.
  - Checkbox `Enabled` và `Required`.
  - `Quota metadata` dạng JSON object.
  - `Reason`.
- Action trên từng feed: `Edit`, `Sync`, `Disable`.
- `Feed Run History`: bảng run gần đây gồm source, status, fetched, valid, parse errors, snapshot, started, finished.
- `Whitelist Conflicts`: bảng conflict gồm source, reputation CIDR, whitelist CIDR, status và detected time.

## Dữ liệu và API liên quan

- Feed sources được đọc từ API feed sources và được refresh sau mutation.
- Feed run history và conflict được lấy từ dashboard polling.
- Sync feed gọi API sync feed source với reason.
- Disable feed là soft-disable qua API feed source delete/disable.

## Thao tác chính

1. Xem `Status`, `Active`, `Parse errors` và `Next run` để xác định feed có đang chạy bình thường không.
2. Chọn `Add feed` để thêm source mới. Mặc định feed mới disabled và status dạng placeholder.
3. Chọn type phù hợp như `internal_json`, `spamhaus_drop`, `team_cymru` hoặc `abuseipdb`.
4. Với admin, nhập `Credential ref` nếu feed cần secret reference hoặc raw API key. Sau khi lưu, hệ thống chỉ hiển thị `***`. Operator không được sửa trường này.
5. Nhập `Quota metadata` bằng JSON object nếu cần lưu metadata quota.
6. Chọn `Sync` để chạy sync thủ công và nhập reason.
7. Chọn `Disable` để soft-disable source và nhập reason.

## Trạng thái rỗng và lỗi

- Nếu chưa có feed source, grid hiển thị `No threat feed sources configured`.
- Nếu chưa có run history, bảng hiển thị `No feed runs recorded`.
- Nếu không phát hiện xung đột whitelist, bảng hiển thị `No whitelist conflicts detected`.
- JSON metadata sai định dạng sẽ bị chặn với lỗi JSON object.

## Lưu ý vận hành

- `Credential ref` là trường write-only cho admin: có thể nhập raw API key hoặc `env://`/`secret://anti-ddos/` reference, nhưng API/UI/audit chỉ trả về `***`.
- Parse errors cao có thể làm active entries thấp hoặc snapshot reputation không đầy đủ.
- Whitelist conflict cần xử lý cẩn thận: whitelist có thể cố ý override reputation, nhưng cũng có thể là cấu hình allow-list quá rộng.
- Disable feed giữ lại bản ghi để audit và giảm rủi ro mất lịch sử.
