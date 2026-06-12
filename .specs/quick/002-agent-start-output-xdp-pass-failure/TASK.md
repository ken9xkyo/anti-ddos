# Quick Task 002: Agent Start Output XDP Pass Failure

**Date:** 2026-06-12
**Status:** Done

## Description

Fix `make AGENT_WAN_IFACE=enp94s0f0 AGENT_OUTPUT_IFACES=enp134s0f1 agent-start` detaching output `xdp_pass` after the Agent fails to stay running.

## Files Changed

- `Makefile` - leave output `xdp_pass` attached on `agent-start` failure and document the explicit `agent-remove` cleanup path.
- `.notebook/ixgbe-devmap-target-xdp-pass.md` - record the failed-start lifecycle gotcha for ixgbe DEVMAP output NICs.

## Verification

- [x] `make -n AGENT_WAN_IFACE=enp94s0f0 AGENT_OUTPUT_IFACES=enp134s0f1 agent-start` shows no failed-start detach command.
- [x] `bash -n <(make -n AGENT_WAN_IFACE=enp94s0f0 AGENT_OUTPUT_IFACES=enp134s0f1 agent-start)`
- [x] `make agent-build`

## Commit

`fix(agent): preserve output xdp_pass on failed start`
