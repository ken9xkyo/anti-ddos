# Anti-DDoS Scrubbing Gateway

**Vision:** A high-performance inline network scrubbing system designed to mitigate L3/L4 volumetric and protocol DDoS attacks using a kernel-level eBPF/XDP data plane and a Go control plane.
**For:** Network operations, SREs, and tenant resource owners requiring high-throughput protection of server backends.
**Solves:** Heavy traffic processing delays by bypassing the standard kernel network stack to drop malicious packets or redirect clean packets with minimal latency.

## Goals

- [ ] High-throughput L3/L4 volumetric attack mitigation (UDP floods, ICMP, TCP SYN, etc.) using eBPF/XDP at driver level.
- [ ] Safe, atomic policy deployment using double-buffered A/B eBPF kernel maps.
- [ ] L2 MAC redirection via device maps (`tx_devmap`) with automated neighbor address resolution.
- [ ] Strict role-based isolation of client-tenant configurations from global admin capabilities.
- [ ] Automated threat intelligence feed integration and conflict resolution with whitelists.
- [ ] Instant Telegram alerting for security incidents, rate violations, and feed failures.

## Tech Stack

**Core:**

- Framework: None (Go standard library `net/http` for API server)
- Language: Go 1.22.2 (Backend), TypeScript 5.7.2 (Frontend), C (eBPF Data Plane), Python 3 (E2E/Lab Tests)
- Database: PostgreSQL 16+

**Key dependencies:**
- `github.com/cilium/ebpf` (v0.17.3)
- `github.com/jackc/pgx/v5` (v5.7.2)
- `github.com/prometheus/client_golang` (v1.22.0)
- `github.com/vishvananda/netlink` (v1.3.1)
- React 18.3.1 & Material-UI v9.0.1 (Frontend)

## Scope

**v1 includes:**
- Packet filtering hot path: Service allowlist, global/service whitelist/blacklist, UDP source port blocks.
- Redirect flow via `tx_devmap` with destination MAC and source MAC rewrite.
- Control plane API supporting RBAC login, session audit, and policy CRUD.
- Automated policy snapshot generation with SHA-256 validation.
- Node agent polling, heartbeat reporting, inactive map loading, and slot switching.
- Observability: drop counters exported via Prometheus, event sampling to Control API.
- Admin support features: view-user read-only dashboard impersonation.
- Security feed integration (Cymru/AbuseIPDB) with custom schedule synchronization.

**Explicitly out of scope:**
- L7 protocol termination (WAF, HTTP inspection, SSL/TLS decryption).
- Deep packet inspection.
- Reverse proxying.
- Automated BGP/RTBH/FlowSpec routing adjustments (escalations remain manual).

## Constraints

- Operating System: Ubuntu 24.04.3 LTS (kernel version >= 6.8.0).
- Lab targets: target host `cyberrange02`, 10G candidate interfaces `enp94s0f0` and `enp134s0f1`.
- eBPF limits: IPv4-only, no dynamic loops in XDP hot path, fail-closed design.
- Configuration: Secret tokens (Telegram, feed credentials) must not appear in plaintext logs or database rows.
