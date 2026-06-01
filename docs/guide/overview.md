# Trang Overview

## Mục đích

`Overview` là màn hình tổng quan cho trực vận hành. Trang này giúp nhìn nhanh traffic, quyết định xử lý packet, sức khỏe agent, trạng thái Control Plane và tín hiệu sự cố mới nhất.

## Ai dùng

Tất cả role đều dùng được trang này. Đây là trang read-only, không có thao tác mutation.

## Thành phần UI

- Metric cards:
  - `Packets/s`: tốc độ packet theo terminal actions.
  - `Bits/s`: ước lượng ingress throughput.
  - `Connections/s`: xấp xỉ TCP SYN per second.
  - `Agents healthy`: số agent heartbeat còn fresh trên tổng agent.
  - `Drop rate`: packet/s đang bị drop.
  - `Redirect rate`: packet/s được redirect hợp lệ.
  - `Not allowed`: service miss hoặc traffic không khớp service được bảo vệ.
  - `Anomaly score`: điểm anomaly mới nhất và trạng thái signal.
- `Traffic Shape`: biểu đồ PPS, Kbps và CPS.
- `Decision Rates`: biểu đồ packet/s theo action.
- `Control Plane Status`: trạng thái Prometheus, snapshot version hiện tại và thời điểm generated.
- `Current Operational Signal`: alert và anomaly mới nhất.
- Top lists: `Top source /24`, `Top ports`, `Decision samples`.
- `Latest Apply Status`: bảng trạng thái apply policy theo agent.

## Dữ liệu và API liên quan

Trang lấy dữ liệu từ luồng dashboard polling, chủ yếu từ overview, alerts, anomalies, agents và security event summary. Trang chỉ mô tả trạng thái đang thấy; contract chi tiết nằm trong [Control API](../Control-Api.md).

## Thao tác chính

- Đọc metric cards trước để xác định hệ thống đang bình thường, bị tăng traffic hay có drop/not-allowed bất thường.
- So sánh `Drop rate`, `Redirect rate` và `Not allowed` để phân biệt traffic bị chặn, traffic sạch được chuyển tiếp, và traffic không khớp service.
- Xem `Current Operational Signal` để biết alert/anomaly nào cần ưu tiên.
- Xem `Latest Apply Status` nếu nghi ngờ policy snapshot chưa được agent apply thành công.

## Trạng thái rỗng và lỗi

- Nếu chưa có apply status, bảng hiển thị `No apply status has been reported yet`.
- Nếu không có alert, phần signal hiển thị `No active alert samples`.
- Nếu Prometheus chưa cấu hình, trạng thái hiển thị `prometheus unconfigured`; dashboard vẫn có thể hoạt động với dữ liệu từ Control API.

## Lưu ý vận hành

- `Agents healthy` giảm hoặc `Latest Apply Status` có `failed` là tín hiệu cần đối chiếu thêm ở `Fleet` và `Services`.
- `Anomaly score` cao không tự động có nghĩa dashboard đã enforce. Cần kiểm tra `Detection` để xem status, source, confidence và recommended action.
- `Overview` không thay thế biểu đồ chi tiết dài hạn trong Grafana; trang này tối ưu cho quyết định nhanh trong dashboard.
