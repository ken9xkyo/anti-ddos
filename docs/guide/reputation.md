# Trang Reputation

## Mục đích

`Reputation` là trang admin-only để quản lý global threat feeds. Feed/reputation không thuộc config riêng của user và không dùng tenant.

## Ai dùng

- `admin` normal session: tạo, sửa, disable, sync feed source; xem run history và whitelist conflicts.
- `user`: không thấy navigation `Reputation` và không gọi feed endpoints.
- `admin` trong `View config` context: không thấy navigation `Reputation`.

## Thành phần UI

- `Threat Feed Management`: danh sách global feed sources, trạng thái, số active entries, conflict count, parse errors và next run.
- Drawer `Add Feed Source` hoặc `Edit ...`: name, type, URL, credential ref, interval, status, license note, quota metadata, enabled, required và reason.
- Confirm dialog cho `Sync` và `Disable`.
- `Feed Run History`: lịch sử sync gần nhất.
- `Whitelist Conflicts`: conflicts giữa global reputation và whitelist của từng user.

## Dữ liệu và API liên quan

- Trang chỉ load khi `user.role === "admin"` và không có `read_only`/`viewing_user`.
- API sử dụng: `/v1/feed-sources`, `/v1/feed-sources/{id}`, `/v1/feed-sources/{id}/sync`, `/v1/feed-runs`, `/v1/feed-conflicts`.
- Credential trong response và audit luôn mask bằng `***`.
- Active global reputation được đưa vào policy snapshot của mọi active user.

## Lưu ý vận hành

- User thấy feed-origin rows tại tab `Blacklist` ở chế độ read-only để biết rule nào đang tác động.
- User không thể patch/delete feed-origin rows qua blacklist API.
- Disable feed source rebuild snapshot của mọi active user để gỡ reputation source khỏi policy.
