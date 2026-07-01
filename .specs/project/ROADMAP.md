# Roadmap

**Current Milestone:** Phase 9 - Telegram ISP Runbook
**Status:** In Progress

---

## Completed Milestones

### Phase 0: Lab Readiness & Project Memory
- **Goal:** Setup project memory and confirm lab requirements.
- **Status:** COMPLETE
- **Key Deliverables:** Host environment audit, toolchain verification, and lab target selection.

### Phase 1: eBPF/XDP Basic Data Plane
- **Goal:** Compile C XDP program and verify behavior.
- **Status:** COMPLETE
- **Key Deliverables:** Driver-level packet parse structure and initial `XDP_PASS` verification.

### Phase 2: Go Node Agent
- **Goal:** Implement daemon to load compiled BPF files into maps.
- **Status:** COMPLETE
- **Key Deliverables:** Loader code using `cilium/ebpf` and netns testing framework.

### Phase 3: Prometheus Metrics
- **Goal:** Collect and expose kernel-level decision metrics.
- **Status:** COMPLETE
- **Key Deliverables:** Prometheus client endpoint scraping drop/observe counters.

### Phase 4: Forwarding Plane (Redirection)
- **Goal:** Redirect clean traffic out of target interfaces.
- **Status:** COMPLETE
- **Key Deliverables:** `tx_devmap` L2 rewrite and netlink-based neighbor ARP resolution.

### Phase 5: Go Control Plane (API Server)
- **Goal:** Centralized configuration, signed snapshot builds, and RBAC.
- **Status:** COMPLETE
- **Key Deliverables:** Go REST API, user login sessions, and database migrations.

### Phase 6: Management Plane (Dashboard)
- **Goal:** Build operational React console.
- **Status:** COMPLETE
- **Key Deliverables:** Config editor UI, admin view-user impersonation, and live fleet monitoring views.

### Phase 7: Rate Limiting & Rules Engine
- **Goal:** Custom threshold-based packet filtering and profile baselines.
- **Status:** COMPLETE
- **Key Deliverables:** Token bucket algorithm (CPS/PPS/BPS) in BPF C and baselines scheduler.

### Phase 8: Threat Intelligence Feed Sync
- **Goal:** Global feed ingest and blacklist union logic.
- **Status:** COMPLETE
- **Key Deliverables:** Cymru HTTP feed parsing, database entries, and conflict resolver.

### Additional Features Completed
- **Manual Blacklist CRUD** - COMPLETE
- **UDP Reflection Source-Port Blocking** - COMPLETE
- **Whitelist Search & Filter** - COMPLETE
- **Allocated CIDR Management** - COMPLETE

---

## Active & Upcoming Milestones

## [Phase 9: Telegram ISP Runbook]

**Goal:** Deliver immediate platform alerts to Telegram and set up manual ISP runbook escalations.
**Target:** Verify end-to-end alert dispatching and dashboard runbook escalation panel.

### Features

**Telegram Alerting** - IN PROGRESS
- [ ] Admin-only configuration, testing, and viewing endpoints.
- [ ] Multi-attempt delivery queue with deduping.
- [ ] Feed failure notification alerts.

---

## Future Considerations

- [ ] IPv6 support for scrubbing filters and services.
- [ ] Automated BGP/RTBH/FlowSpec route injection.
- [ ] Automated baseline deviation enforcement (automatic rules).
