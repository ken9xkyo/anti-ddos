# ixgbe DEVMAP Target XDP Pass
> ixgbe output interfaces need XDP TX queues before native DEVMAP redirect works

Symptom: `service_allowlist` and `tx_devmap` are correct, `anti_ddos_redirected_packets_total` can increase, but clients still time out. Kernel tracepoint shows `xdp_redirect_err` with `err=-95` from ingress ifindex to output ifindex.

Observed live on 2026-06-02:
- Ingress `enp94s0f0` ran `xdp_entry`.
- Service `24` redirected `118.107.78.137:2283/tcp` through `tx_devmap` key `24` to output ifindex `7` (`enp134s0f1`).
- `bpftrace` showed `redirect_err prog=2508 if=4 to=7 err=-95 map=2355 idx=24`.
- `dmesg` showed `enp134s0f1` had `XDP Queue count = 0` after its XDP program was detached.

Fix used: attach the minimal pass-through program to the output NIC:

```bash
ip link set dev enp134s0f1 xdpdrv obj build/bpf/xdp_pass.bpf.o sec xdp
```

After fix:
- `bpftool net` showed `enp94s0f0` with `xdp_entry` and `enp134s0f1` with `xdp_pass`.
- `dmesg` showed `enp134s0f1` with `XDP Queue count = 64`.
- `bpftrace` showed `devmap_xmit from=4 to=7 sent=1 drops=0 err=0`.
- External TCP checks to `118.107.78.137:2283` succeeded.

Pointers:
- Data plane redirect branch: `bpf/xdp_data_plane.bpf.c:xdp_entry()`
- Pass-through program: `bpf/xdp_pass.bpf.c:xdp_pass()`
- Lab precedent: `scripts/lab/devmap-forwarding-veth-test.sh`

Operational caveat: this runtime attach is not managed by the Agent today. If `enp134s0f1` is detached, reset, or the host reboots, reattach `xdp_pass` before expecting native DEVMAP forwarding to work.

Agent lifecycle gotcha:
- `make agent-start` may attach `xdp_pass` to configured output interfaces before the Agent process proves it stayed running.
- If the Agent then exits early, `agent-start` must leave output `xdp_pass` attached. Detaching it recreates the ixgbe `XDP Queue count = 0` failure mode above.
- Use `make AGENT_WAN_IFACE=<wan> AGENT_OUTPUT_IFACES=<output> agent-remove` when an operator intentionally wants to detach output `xdp_pass`.
- A live failed-start example on 2026-06-12 exited before attach verification because `ANTI_DDOS_OWNER_USER_ID or ANTI_DDOS_OWNER_USERNAME is required when ANTI_DDOS_CONTROL_URL is set`.

Updated: 2026-06-12
