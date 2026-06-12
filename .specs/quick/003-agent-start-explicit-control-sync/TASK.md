# Quick Task 003: Agent Start Explicit Control Sync

**Date:** 2026-06-12
**Status:** Done

## Description

Fix `agent-start` so a local Agent run does not implicitly enable Control sync and fail owner validation.

## Files Changed

- `Makefile` - remove the implicit localhost Control URL fallback, validate owner config before output XDP attach when Control sync is explicit, and pass owner env through to the Agent.
- `.notebook/ixgbe-devmap-target-xdp-pass.md` - update the failed-start lifecycle note for the new Control sync behavior.

## Verification

- [x] `bash -n <(make -n AGENT_WAN_IFACE=enp94s0f0 AGENT_OUTPUT_IFACES=enp134s0f1 agent-start)`
- [x] `make -n AGENT_WAN_IFACE=enp94s0f0 AGENT_OUTPUT_IFACES=enp134s0f1 agent-start | rg -n "ANTI_DDOS_CONTROL_URL|127\\.0\\.0\\.1:8080|OWNER_USER_ID|OWNER_USERNAME|required when AGENT_CONTROL_URL"`
- [x] `go test ./internal/agent`
- [x] `make agent-build`
- [x] `make AGENT_PROCESS=agtst AGENT_WAN_IFACE=lo AGENT_OUTPUT_IFACES=enp134s0f1 AGENT_CONTROL_URL=http://127.0.0.1:8080 agent-start` fails at owner validation before output attach.

## Commit

`fix(agent): keep control sync explicit in agent-start`
