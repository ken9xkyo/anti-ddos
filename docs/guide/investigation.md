# Trang Investigation

## Mục đích

`Investigation` hỗ trợ tra cứu sampled security events theo source, prefix hoặc service target. Trang này giúp người vận hành drill-down từ signal tổng quan sang các event cụ thể.

## Ai dùng

Tất cả role đều dùng được trang này. Trang hiện tại là read-only, chỉ gọi truy vấn điều tra.

## Thành phần UI

- `Investigate Source / Prefix / Service`: form nhập `Target` và nút `Investigate`.
- `Target`: chấp nhận giá trị như IP nguồn, prefix `/24` hoặc target service tùy API hỗ trợ.
- `Investigation results for ...`: bảng kết quả trả về cho target vừa truy vấn.
- `Recent Sampled Events`: bảng event gần đây từ dashboard polling.
- Bảng event gồm: `Time`, `Source`, `Target`, `Proto`, `Action`, `Reason`, `Service`, `Rule`, `Sample`.

## Dữ liệu và API liên quan

- Recent events lấy từ `/v1/security-events?limit=50` trong dashboard polling.
- Điều tra target gọi `/v1/security-events/investigate?target=...&limit=50`.
- Action và reason hiển thị dạng số theo constants packet/action của hệ thống.

## Thao tác chính

1. Nhập IP, prefix hoặc target cần điều tra vào `Target`.
2. Chọn `Investigate`.
3. Đọc bảng kết quả để xác định source, destination, protocol, action, reason, service và rule liên quan.
4. Nếu không có target cụ thể, dùng `Recent Sampled Events` để xem mẫu gần nhất.
5. Đối chiếu action/reason với `Overview`, `Rules` và `Whitelist` khi cần kết luận nguyên nhân.

## Trạng thái rỗng và lỗi

- Nếu target không có event khớp, bảng kết quả hiển thị `No sampled events matched the investigation target`.
- Nếu chưa có sampled event gần đây, bảng recent hiển thị `No sampled security events recorded`.
- Nút `Investigate` bị disabled khi target trống hoặc request đang chạy.
- Lỗi truy vấn hiển thị inline cạnh form.

## Lưu ý vận hành

- Sampled events là mẫu, không phải toàn bộ packet stream. Không dùng một mình nó để tính tổng traffic.
- `Sample` cho biết sample rate; cần cân nhắc khi suy luận tần suất thực tế.
- Event investigation phù hợp để xác nhận nguyên nhân gần nhất, còn phân tích dài hạn nên đối chiếu thêm metric và log ngoài dashboard.
