#!/usr/bin/env bash
# Per-NIC and system tuning for 100 Gbps XDP anti-DDoS.
# Idempotent; safe to run repeatedly.
#
# Usage: sudo ./tuning.sh <ingress-iface> <egress-iface>
set -euo pipefail

INGRESS="${1:?ingress iface required}"
EGRESS="${2:?egress iface required}"
NQUEUES="${NQUEUES:-32}"

log() { printf '[tuning] %s\n' "$*"; }

# --- sysctl (BPF + network) -------------------------------------------------
sysctl -w net.core.bpf_jit_enable=1
sysctl -w net.core.bpf_jit_harden=0
sysctl -w net.core.netdev_budget=600
sysctl -w net.core.netdev_budget_usecs=8000
sysctl -w net.core.rmem_max=268435456
sysctl -w net.core.wmem_max=268435456

# --- per-interface ---------------------------------------------------------
tune_nic() {
    local ifn="$1"
    log "tuning $ifn"

    ip link set dev "$ifn" up
    ip link set dev "$ifn" mtu "${MTU:-1500}"

    # Offloads off on the XDP path.
    ethtool -K "$ifn" gro off lro off tso off gso off ufo off || true

    # Combined queues (RSS spread across cores).
    ethtool -L "$ifn" combined "$NQUEUES" || true

    # RSS symmetric hashing so both directions land on the same core.
    # 's d f n' = src IP + dst IP + src port + dst port for TCP and UDP.
    for proto in tcp4 udp4 tcp6 udp6; do
        ethtool -N "$ifn" rx-flow-hash "$proto" sdfn || true
    done

    # Spread RSS evenly.
    ethtool -X "$ifn" equal "$NQUEUES" || true

    # Large rings.
    ethtool -G "$ifn" rx 4096 tx 4096 || true

    # Flow director / ATR (E810): spreads single-flow floods.
    ethtool --set-priv-flags "$ifn" channel-pkt-inspect-optimize on 2>/dev/null || true
    ethtool -K "$ifn" ntuple on || true
}

tune_nic "$INGRESS"
tune_nic "$EGRESS"

# --- mount bpffs (for pinning) --------------------------------------------
if ! mountpoint -q /sys/fs/bpf; then
    mount -t bpf bpf /sys/fs/bpf
fi
mkdir -p /sys/fs/bpf/antiddos

log "done. Remember to apply boot cmdline options:"
log "    isolcpus=1-31 nohz_full=1-31 rcu_nocbs=1-31"
log "    default_hugepagesz=1G hugepagesz=1G hugepages=16"
