# Trang Snapshots

## Mục đích

`Snapshots` quản lý các version policy snapshot bất biến, hỗ trợ so sánh semantic diff và rollback bằng cách tạo snapshot mới từ version đã chọn.

## Ai dùng

- `viewer`: xem snapshot versions và semantic diff.
- `operator`: rollback snapshot.
- `admin`: có toàn bộ quyền operator.

## Thành phần UI

- `Snapshot Versions`: Data Grid các snapshot version với cột `Version`, `Checksum`, `Object`, `Rollback from`, `Created by`, `Created`, `Actions`.
- `Semantic Diff`: chọn `From`, `To` và nút `Load diff`.
- Diff summary gồm:
  - `From`, `To`, trạng thái `Object checksum`.
  - Các nhóm `Services`, `Whitelist`, `Blacklist`, `Rules`.
  - Mỗi nhóm hiển thị số `Added`, `Removed`, `Changed`, `Unchanged`.
  - `Runtime` nếu diff có runtime change.
- Confirm dialog `Rollback to v...` yêu cầu `Reason` và nút `Create rollback`.

## Dữ liệu và API liên quan

- Trang lazy-load snapshot metadata qua `/v1/snapshots?include_snapshot=false`.
- Semantic diff gọi API snapshot diff theo `from` và `to`.
- Rollback gọi API rollback snapshot với target version và reason.
- Raw snapshot không được kéo vào polling overview mặc định.

## Thao tác chính

1. Mở `Snapshots` để xem version mới nhất và lịch sử tạo snapshot.
2. Chọn hai version trong `From` và `To`.
3. Chọn `Load diff` để xem thay đổi theo nhóm semantic.
4. Kiểm tra checksum, số changed/added/removed và JSON preview nếu có.
5. Nếu cần rollback, chọn `Rollback` trên version đích.
6. Nhập `Reason` rõ ràng và chọn `Create rollback`.

## Trạng thái rỗng và lỗi

- Nếu chưa có snapshot, grid hiển thị `No snapshots created`.
- Nếu chưa load diff, panel hiển thị `No diff loaded`.
- Lỗi diff hoặc rollback được hiển thị inline bằng message kết quả.

## Lưu ý vận hành

- Rollback không xóa hay ghi đè snapshot cũ. Hệ thống tạo snapshot mới từ version được chọn.
- Luôn kiểm tra semantic diff trước khi rollback nếu có đủ snapshot để so sánh.
- Sau rollback, cần theo dõi `Overview` hoặc `Fleet` để xác nhận agent apply policy version mới thành công.
