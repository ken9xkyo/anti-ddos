# Project State

Last updated: 2026-05-28

## Decisions

- Current host `cyberrange02` is the Phase 0 lab target.
- Backend services are not inferred from route or neighbor entries. The official service list must come from Network/SRE.
- Phase 0 creates project memory and lab readiness documentation only. It does not attach XDP, create runtime source directories, or implement Agent/API/dashboard code.
- Runtime source tree conventions are documented in Phase 0, but actual runtime directories start in Phase 01 or later.
- Secrets are represented as references only; raw DB DSNs, Telegram tokens, and feed API keys must not appear in config, logs, audit entries, or docs.

## Current Host Facts

- OS: Ubuntu 24.04.3 LTS (`noble`).
- Kernel: `6.8.0-106-generic` on `x86_64`.
- BTF: `/sys/kernel/btf/vmlinux` exists.
- CPU: `96` logical processors.
- eBPF toolchain present: `clang 18.1.3`, `llvm-strip`, `bpftool v7.4.0`, `libbpf v1.4`.
- Go present: `go1.22.2 linux/amd64`.
- Node toolchain present: Node `v18.19.1`, npm `9.2.0`.
- Runtime gaps: `psql` and `prometheus` commands are missing.
- 10G NIC candidates: `enp94s0f0` and `enp134s0f1`, both `ixgbe`, link `10000Mb/s`, combined queues `63`.
- Default route priority currently favors `enp134s0f1` with metric `100`; `enp94s0f0` is secondary with metric `200`.

## Open Blockers

- Protected backend service inventory is missing: service name, backend IP/CIDR, protocol, allowed ports, owner, criticality, output interface, and return path.
- WAN/LAN roles are not formally assigned for `enp94s0f0` and `enp134s0f1`.
- PostgreSQL and Prometheus binaries are not installed on the lab target.
- `vmlinux.h` has not been generated into the future source tree.
- Native XDP attach capability has not been tested; no XDP program should be attached without explicit execution approval.
- 10 Gbps and 40 Gbps benchmark results are not available yet.

## Next Actions

- Network/SRE confirms protected backend service inventory and final WAN/LAN/output interface roles.
- Install PostgreSQL client/server components and Prometheus according to the deployment decision for the lab.
- Generate `vmlinux.h` from `/sys/kernel/btf/vmlinux` when Phase 01 creates the data-plane source tree.
- Run Phase 01 build/verifier work only after Phase 0 readiness gaps are acknowledged.

