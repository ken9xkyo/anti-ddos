# Anti-DDoS Metric Catalog

Phase 06 standardizes `anti_ddos_*` metrics for Prometheus scrape targets.

## Label Policy

- Allowed high-use labels: `method`, `route`, `status`, `mode`, `action`, `reason`, `proto`, `protocol`, `service_id`, `rule_id`, `map`, `output_interface`, `xdp_mode`.
- Do not use raw source IPs, raw CIDRs, usernames, alert text, API tokens, passwords, or free-form error text as metric labels.
- Source investigation uses PostgreSQL `security_events`, not Prometheus labels.

## Agent Metrics

| Metric | Type | Labels | Purpose |
|---|---|---|---|
| `anti_ddos_agent_up` | gauge | none | Agent process readiness. |
| `anti_ddos_xdp_mode` | gauge | `mode` | Active XDP mode. |
| `anti_ddos_xdp_attach_errors_total` | counter | `mode` | Attach failure count by attempted mode. |
| `anti_ddos_xdp_packets_total` | gauge | `reason`, `action`, `proto`, `service_id`, `rule_id` | Cumulative eBPF packet counters. |
| `anti_ddos_xdp_bytes_total` | gauge | `reason`, `action`, `proto`, `service_id`, `rule_id` | Cumulative eBPF byte counters. |
| `anti_ddos_ebpf_map_entries` | gauge | `map` | Current eBPF map entries. |
| `anti_ddos_ebpf_map_capacity` | gauge | `map` | eBPF map capacity. |
| `anti_ddos_ebpf_map_utilization_ratio` | gauge | `map` | eBPF map utilization ratio. |
| `anti_ddos_ringbuf_events_consumed_total` | counter | none | Ringbuf events decoded by Agent. |
| `anti_ddos_ringbuf_consume_errors_total` | counter | none | Ringbuf decode/read errors. |
| `anti_ddos_agent_last_valid_snapshot_version` | gauge | none | Last valid policy version loaded by Agent. |
| `anti_ddos_redirected_packets_total` | gauge | `service_id`, `protocol`, `output_interface` | Successful DEVMAP redirect packets. |
| `anti_ddos_redirect_errors_total` | gauge | `service_id`, `output_interface`, `reason` | Redirect fail-closed drops. |
| `anti_ddos_not_allowed_service_total` | gauge | `protocol` | Drops because no service allowlist matched. |
| `anti_ddos_neighbor_unresolved_total` | gauge | `service_id`, `output_interface` | Drops due to unresolved neighbor metadata. |
| `anti_ddos_neighbor_resolution_status` | gauge | `service_id`, `output_interface` | Active service neighbor status. |
| `anti_ddos_agent_control_events_forwarded_total` | counter | none | Sampled events posted to Control API. |
| `anti_ddos_agent_control_events_dropped_total` | counter | `reason` | Best-effort sampled event drops. |
| `anti_ddos_agent_control_event_forward_errors_total` | counter | none | Control event forwarding POST errors. |

## Control API Metrics

| Metric | Type | Labels | Purpose |
|---|---|---|---|
| `anti_ddos_control_http_requests_total` | counter | `method`, `route`, `status` | Control API request count with bounded route names. |
| `anti_ddos_control_http_request_duration_seconds` | histogram | `method`, `route` | Control API latency. |
| `anti_ddos_control_db_up` | gauge | none | PostgreSQL reachability. |
| `anti_ddos_control_policy_snapshot_version` | gauge | none | Latest policy snapshot version. |
| `anti_ddos_control_policy_apply_status` | gauge | `status` | Latest apply status counts. |
| `anti_ddos_control_agents` | gauge | `status`, `xdp_mode` | Registered agents by state. |
| `anti_ddos_control_agent_stale` | gauge | `status`, `xdp_mode` | Stale agent state. |
| `anti_ddos_control_security_events_ingested_total` | counter | `action`, `reason`, `protocol` | Accepted sampled security events. |
| `anti_ddos_control_security_events_rejected_total` | counter | `reason` | Rejected sampled event batches. |
| `anti_ddos_control_prometheus_queries_total` | counter | `result` | Dashboard Prometheus proxy queries. |
