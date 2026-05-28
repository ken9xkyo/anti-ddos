# Phase 00 - Nền tảng lab và readiness

## Mục tiêu

Tạo nền tảng để các phase sau có thể thực thi an toàn: chốt topology mạng, thông số NIC/kernel, backend/service cần bảo vệ, toolchain eBPF/libbpf/Go, PostgreSQL, Prometheus và benchmark matrix. Phase này không triển khai packet filtering, nhưng tạo đủ điều kiện để biên dịch, load, redirect và kiểm chứng.

## Phạm vi

- Thu thập thông tin WAN/LAN interface, route, backend CIDR, allowed ports, output interface, link speed, RSS/queue, NIC driver và kernel Ubuntu 24.04.
- Chuẩn bị lab/dev host có `clang/llvm`, `libbpf`, `bpftool`, BTF/vmlinux.h, Go toolchain, PostgreSQL, Prometheus và dashboard toolchain.
- Chốt quy ước source tree cho data plane, agent, control API, dashboard, deploy/config.
- Tạo benchmark input cho drop path, service miss, blacklist hit, UDP flood, SYN flood, ICMP flood, neighbor unresolved và DEVMAP redirect path.
- Chưa tạo code runtime; phase này chỉ tạo điều kiện và đầu vào kiểm chứng.

## Công việc

| ID | Công việc | Mục đích | Kết quả bàn giao | Phụ thuộc |
|---|---|---|---|---|
| P00-T01 | Lập danh sách protected backend services | Biết chính xác traffic nào được redirect | Bảng backend IP/CIDR, protocol, port, owner, criticality, output interface | Không |
| P00-T02 | Ghi nhận topology WAN/LAN và return path | Đảm bảo gateway không làm sai đường đi gói tin | Sơ đồ WAN/LAN, upstream, backend subnet, asymmetric return path nếu có | P00-T01 |
| P00-T03 | Kiểm tra route, ARP/neighbor và MAC target | Chuẩn bị cho L2 rewrite và DEVMAP redirect | Bảng route, next-hop/backend MAC, neighbor state, output ifindex dự kiến | P00-T02 |
| P00-T04 | Kiểm tra NIC, driver, RSS, queue và link speed | Xác định điều kiện benchmark 10 Gbps và report 40 Gbps | Inventory NIC, driver, queue count, offload, MTU, link speed | P00-T02 |
| P00-T05 | Kiểm tra kernel/BTF trên Ubuntu 24.04 | Đảm bảo CO-RE/libbpf có đủ dữ liệu cần thiết | Kết quả `uname`, `/sys/kernel/btf/vmlinux`, kernel config liên quan | Không |
| P00-T06 | Chuẩn bị eBPF build toolchain | Có thể build và verifier-test XDP object | Package/tool versions cho `clang`, `llvm`, `bpftool`, `libbpf`, `vmlinux.h` | P00-T05 |
| P00-T07 | Chuẩn bị userspace/runtime toolchain | Sẵn sàng cho Agent, API và dashboard | Go version, PostgreSQL, Prometheus, Node/React toolchain nếu dùng | Không |
| P00-T08 | Định nghĩa environment config tối thiểu | Tránh hard-code interface, ports và secrets | Mẫu config cho WAN/LAN, API URL, DB DSN, metrics port, secret refs | P00-T01 |
| P00-T09 | Lập traffic benchmark matrix | Kiểm thử đủ drop path và DEVMAP redirect path | Matrix traffic hợp lệ, malformed, blacklist, service miss, flood, redirect failure | P00-T04 |
| P00-T10 | Xác định secret handling baseline | Tránh lộ Telegram token và feed API key từ đầu | Quy ước secret ref/encrypted column/redaction cho log/audit/API | P00-T07 |
| P00-T11 | Chốt Definition of Done cho MVP | Làm rõ điều kiện kết thúc phase và release | Checklist build, verifier, integration, benchmark, UAT, runbook | P00-T09 |

## Tiêu chí chấp nhận

- Có inventory đầy đủ cho backend service, WAN/LAN route, neighbor/MAC, NIC, driver, RSS/queue, kernel và BTF.
- Có toolchain build eBPF và Go userspace trên Ubuntu 24.04.
- Có benchmark matrix gồm drop-only, service allowlist miss, rate limit, blacklist và full DEVMAP redirect path.
- Có config convention cho interface, route/neighbor, policy sync, database, metrics và secrets.
- Các rủi ro hiệu năng ban đầu được ghi rõ: native XDP support, generic fallback, queue/RSS, link saturation.

## Kiểm chứng

- Chạy check toolchain: `clang --version`, `bpftool version`, `go version`, `psql --version`, `prometheus --version` nếu có sẵn.
- Kiểm tra BTF: `/sys/kernel/btf/vmlinux` tồn tại trên host mục tiêu.
- Kiểm tra NIC/driver/RSS bằng `ethtool -i`, `ethtool -l`, `ip link`, `nproc`.
- Kiểm tra route/neighbor bằng `ip route`, `ip neigh`, MAC backend/next-hop và ifindex output.
- Review bảng backend service với Network/SRE để xác nhận allowed ports và return path.

## Truy vết PRD

- PRD-002: chuẩn bị metrics/dashboard inputs.
- PRD-003: chuẩn bị kernel capability cho XDP/eBPF.
- PRD-007: chốt route topology, output interface, neighbor/MAC và service allowlist input.
- PRD-010: chuẩn bị last-valid snapshot và fail-safe requirement.
- PRD-011: thu thập link/topology input cho ISP escalation.

## Ghi chú và rủi ro

- Mục tiêu 10 Gbps chỉ được xác nhận sau benchmark trên NIC/kernel/queue thực tế.
- Nếu NIC không hỗ trợ native XDP, MVP có thể kiểm thử chức năng bằng generic fallback nhưng phải cảnh báo hiệu năng.
- Nếu neighbor/MAC không resolve ổn định, Phase 04 sẽ fail-closed và cần root-cause topology trước khi UAT.
- Secrets phải được thiết kế từ đầu để tránh audit/log làm lộ token.
