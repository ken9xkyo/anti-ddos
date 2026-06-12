# Quick Task 003 Summary

Changed `agent-start` so Control API sync is only enabled when `AGENT_CONTROL_URL` or `ANTI_DDOS_CONTROL_URL` is explicitly configured.

Verification passed:
- `bash -n <(make -n AGENT_WAN_IFACE=enp94s0f0 AGENT_OUTPUT_IFACES=enp134s0f1 agent-start)`
- `make -n AGENT_WAN_IFACE=enp94s0f0 AGENT_OUTPUT_IFACES=enp134s0f1 agent-start | rg -n "ANTI_DDOS_CONTROL_URL|127\\.0\\.0\\.1:8080|OWNER_USER_ID|OWNER_USERNAME|required when AGENT_CONTROL_URL"`
- `go test ./internal/agent`
- `make agent-build`
- Explicit Control sync without owner config fails before output XDP attach.

Operational note:
- The documented local command can run without owner env because `ANTI_DDOS_CONTROL_URL` is empty by default.
