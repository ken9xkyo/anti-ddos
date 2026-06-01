# Trang Fleet

## Mục đích

`Fleet` hiển thị trạng thái agent, XDP mode, policy version, DEVMAP support, interface metadata và map utilization. Trang này dùng để kiểm tra lớp hạ tầng agent trước khi kết luận lỗi nằm ở policy hay data plane.

## Ai dùng

Tất cả role đều dùng được trang này. Trang hiện tại là read-only.

## Thành phần UI

- `Agents / XDP`: bảng agent gồm host, status, XDP mode, active policy version, DEVMAP support, last seen và latest apply.
- `Reported Interfaces`: bảng interface agent report gồm agent, name, role, ifindex, MAC và link speed.
- `Map Utilization`: panel JSON theo từng agent, hiển thị utilization nếu agent report.

## Dữ liệu và API liên quan

- Dữ liệu đến từ dashboard agents endpoint trong vòng polling.
- `latest_apply` trên agent được dùng để hiển thị policy version mới nhất và lỗi apply nếu có.
- Interface metadata cũng là nguồn để `Services` gợi ý output interface và autofill forwarding metadata.

## Thao tác chính

1. Kiểm tra `Agents / XDP` để biết agent còn online hay stale.
2. Xem `XDP` và `DEVMAP` để xác định khả năng data plane cần thiết.
3. So sánh active policy version của agent với snapshot/control plane version ở `Overview`.
4. Nếu `Apply` có failed, đọc stage và reason ngay trong bảng.
5. Mở `Reported Interfaces` để xác nhận interface name, role, ifindex và MAC trước khi enable service.
6. Xem `Map Utilization` khi nghi ngờ map đầy hoặc agent không còn capacity.

## Trạng thái rỗng và lỗi

- Nếu chưa có agent, bảng hiển thị `No agents registered`.
- Nếu agent chưa report interface metadata, bảng hiển thị `No interface metadata reported`.
- Nếu không có utilization, panel hiển thị JSON rỗng hoặc thông báo không có agent map utilization.

## Lưu ý vận hành

- Agent stale có thể làm dashboard vẫn còn dữ liệu cũ nhưng không thể tin là host đang apply policy mới.
- Interface metadata ở đây ảnh hưởng trực tiếp tới flow tạo service ở `Services`.
- Khi apply failed, ưu tiên xem `Fleet`, `Overview` và `Services` cùng lúc để phân biệt lỗi snapshot, lỗi interface metadata hoặc lỗi agent runtime.
