# Project State

Last updated: 2026-05-28

Current work: Phase 01 - XDP Data Plane Skeleton completed; Phase 02 - Agent Lifecycle is next.

## Decisions

- Current host `cyberrange02` is the Phase 0 lab target.
- Backend services are not inferred from route or neighbor entries. The official service list must come from Network/SRE.
- Phase 0 creates project memory and lab readiness documentation only. It does not attach XDP, create runtime source directories, or implement Agent/API/dashboard code.
- Runtime source tree conventions are documented in Phase 0, but actual runtime directories start in Phase 01 or later.
- Secrets are represented as references only; raw DB DSNs, Telegram tokens, and feed API keys must not appear in config, logs, audit entries, or docs.
- Phase 01 valid IPv4 traffic without a service policy fails closed with `XDP_DROP` and `REASON_NOT_ALLOWED_SERVICE`.
- Phase 01 verification is build/load/verifier/`BPF_PROG_TEST_RUN` only; no XDP program was attached to a real or veth interface.

## Phase Progress

| Phase | Status | Evidence |
|---|---|---|
| 00 - Foundation Lab Readiness | Ready for Phase 01 with gaps carried | Lab readiness docs exist; backend inventory, interface roles, PostgreSQL, Prometheus, native attach and benchmarks remain open. |
| 01 - XDP Data Plane Skeleton | Done | `make phase1-verify` PASS on 2026-05-28; report `reports/phase-01-xdp-data-plane-skeleton.md`; verifier log `build/bpf/verifier.log`. |
| 02 - Agent Lifecycle | Planned | Next phase after Phase 01. |

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
- Native XDP attach capability has not been tested; no XDP program should be attached without explicit execution approval.
- 10 Gbps and 40 Gbps benchmark results are not available yet.

## Next Actions

- Start Phase 02 Agent Lifecycle using the Phase 01 object and map contracts.
- Network/SRE confirms protected backend service inventory and final WAN/LAN/output interface roles before any redirect policy work.
- Install PostgreSQL client/server components and Prometheus according to the deployment decision for the lab.
- Keep native XDP attach disabled until explicit execution approval and interface roles are confirmed.
- Run benchmark matrix only after Agent attach flow and service redirect path exist.
