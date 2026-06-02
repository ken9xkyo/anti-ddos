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

Updated: 2026-06-02
