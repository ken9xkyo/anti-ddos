# Phase 00 - Nen tang lab va readiness

## Muc tieu

Tao nen tang de cac phase sau co the thuc thi an toan: chot topology mang, thong so NIC/kernel, backend/service can bao ve, toolchain eBPF/libbpf/Go, PostgreSQL, Prometheus va benchmark matrix. Phase nay khong implement packet filtering, nhung tao du dieu kien de build, load, redirect va verify.

## Pham vi

- Thu thap thong tin WAN/LAN interface, route, backend CIDR, allowed ports, output interface, link speed, RSS/queue, NIC driver va kernel Ubuntu 24.04.
- Chuan bi lab/dev host co `clang/llvm`, `libbpf`, `bpftool`, BTF/vmlinux.h, Go toolchain, PostgreSQL, Prometheus va dashboard toolchain.
- Chot convention source tree cho data plane, agent, control API, dashboard, deploy/config.
- Tao benchmark input cho drop path, service miss, blacklist hit, UDP flood, SYN flood, ICMP flood, neighbor unresolved va DEVMAP redirect path.
- Chua tao code runtime; phase nay chi tao dieu kien va dau vao kiem chung.

## Cong viec

| ID | Cong viec | Muc dich | Ket qua ban giao | Phu thuoc |
|---|---|---|---|---|
| P00-T01 | Lap danh sach protected backend services | Biet chinh xac traffic nao duoc redirect | Bang backend IP/CIDR, protocol, port, owner, criticality, output interface | Khong |
| P00-T02 | Ghi nhan topology WAN/LAN va return path | Dam bao gateway khong lam sai duong di goi tin | So do WAN/LAN, upstream, backend subnet, asymmetric return path neu co | P00-T01 |
| P00-T03 | Kiem tra route, ARP/neighbor va MAC target | Chuan bi cho L2 rewrite va DEVMAP redirect | Bang route, next-hop/backend MAC, neighbor state, output ifindex du kien | P00-T02 |
| P00-T04 | Kiem tra NIC, driver, RSS, queue va link speed | Xac dinh dieu kien benchmark 10 Gbps va report 40 Gbps | Inventory NIC, driver, queue count, offload, MTU, link speed | P00-T02 |
| P00-T05 | Kiem tra kernel/BTF tren Ubuntu 24.04 | Dam bao CO-RE/libbpf co du du lieu can thiet | Ket qua `uname`, `/sys/kernel/btf/vmlinux`, kernel config lien quan | Khong |
| P00-T06 | Chuan bi eBPF build toolchain | Co the build va verifier-test XDP object | Package/tool versions cho `clang`, `llvm`, `bpftool`, `libbpf`, `vmlinux.h` | P00-T05 |
| P00-T07 | Chuan bi userspace/runtime toolchain | San sang cho Agent, API va dashboard | Go version, PostgreSQL, Prometheus, Node/React toolchain neu dung | Khong |
| P00-T08 | Dinh nghia environment config toi thieu | Tranh hard-code interface, ports va secrets | Mau config cho WAN/LAN, API URL, DB DSN, metrics port, secret refs | P00-T01 |
| P00-T09 | Lap traffic benchmark matrix | Test du drop path va DEVMAP redirect path | Matrix traffic hop le, malformed, blacklist, service miss, flood, redirect failure | P00-T04 |
| P00-T10 | Xac dinh secret handling baseline | Tranh lo Telegram token va feed API key tu dau | Quy uoc secret ref/encrypted column/redaction cho log/audit/API | P00-T07 |
| P00-T11 | Chot Definition of Done cho MVP | Lam ro dieu kien ket thuc phase va release | Checklist build, verifier, integration, benchmark, UAT, runbook | P00-T09 |

## Tieu chi chap nhan

- Co inventory day du cho backend service, WAN/LAN route, neighbor/MAC, NIC, driver, RSS/queue, kernel va BTF.
- Co toolchain build eBPF va Go userspace tren Ubuntu 24.04.
- Co benchmark matrix gom drop-only, service allowlist miss, rate limit, blacklist va full DEVMAP redirect path.
- Co config convention cho interface, route/neighbor, policy sync, database, metrics va secrets.
- Cac rui ro hieu nang ban dau duoc ghi ro: native XDP support, generic fallback, queue/RSS, link saturation.

## Kiem chung

- Chay check toolchain: `clang --version`, `bpftool version`, `go version`, `psql --version`, `prometheus --version` neu co san.
- Kiem tra BTF: `/sys/kernel/btf/vmlinux` ton tai tren host muc tieu.
- Kiem tra NIC/driver/RSS bang `ethtool -i`, `ethtool -l`, `ip link`, `nproc`.
- Kiem tra route/neighbor bang `ip route`, `ip neigh`, MAC backend/next-hop va ifindex output.
- Review bang backend service voi Network/SRE de xac nhan allowed ports va return path.

## Truy vet PRD

- PRD-002: chuan bi metrics/dashboard inputs.
- PRD-003: chuan bi kernel capability cho XDP/eBPF.
- PRD-007: chot route topology, output interface, neighbor/MAC va service allowlist input.
- PRD-010: chuan bi last-valid snapshot va fail-safe requirement.
- PRD-011: thu thap link/topology input cho ISP escalation.

## Ghi chu va rui ro

- Muc tieu 10 Gbps chi duoc xac nhan sau benchmark tren NIC/kernel/queue thuc te.
- Neu NIC khong ho tro native XDP, MVP co the functional-test bang generic fallback nhung phai canh bao hieu nang.
- Neu neighbor/MAC khong resolve on dinh, Phase 04 se fail-closed va can root-cause topology truoc khi UAT.
- Secrets phai duoc thiet ke tu dau de tranh audit/log lam lo token.

