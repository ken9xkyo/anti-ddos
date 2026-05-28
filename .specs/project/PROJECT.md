# Project: Anti-DDoS Scrubbing Gateway eBPF/XDP

## Vision

Build a single-node MVP scrubbing gateway on Ubuntu 24.04 that filters volumetric L3/L4 DDoS traffic at WAN ingress with XDP/eBPF and redirects only clean, allowlisted service traffic to protected backends with L2 MAC rewrite plus XDP DEVMAP.

## Source Documents

- `docs/PRD-Anti-DDoS.md` v1.2
- `docs/System-Architecture-Design.md` v1.0
- `docs/HLD.md` v1.0
- `docs/LLD.md` v1.0
- `plans/README.md`
- `plans/phase-00-foundation-lab-readiness.md`

## MVP Boundaries

- Single active scrubbing server.
- Ubuntu 24.04 target.
- Native XDP preferred; generic XDP or TC fallback only with explicit performance warning.
- IPv4 enforcement is mandatory for MVP; IPv6 schema may be reserved but enforcement can remain disabled.
- No NAT/DNAT, TLS termination, L7/DPI, WAF replacement, BGP/RTBH/FlowSpec automation, or HA in MVP.
- Backend response path may be asymmetric.

## Core Outcomes

- Drop, rate-limit, and count volumetric L3/L4 attack traffic before it reaches the kernel network stack.
- Redirect only traffic that matches protected backend service allowlists.
- Keep last valid policy snapshot when the Agent or Control Plane fails.
- Expose packet, rule, forwarding, map, feed, and alert metrics through Prometheus and dashboard views.
- Provide auditable RBAC, policy versioning, rollback, Telegram alerting, and manual ISP escalation inputs.

## Phase 0 Baseline

Phase 0 treats `cyberrange02` as the current lab target and records host readiness, network inventory, NIC/kernel/toolchain facts, config and secret conventions, source tree conventions, and benchmark inputs. It does not create runtime source code, attach XDP programs, or infer protected backend services from host routing data.

