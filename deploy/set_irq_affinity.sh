#!/usr/bin/env bash
# Pin NIC rx/tx IRQs to cores 1:1 with queues. Disables irqbalance interference.
# Usage: sudo ./set_irq_affinity.sh <iface>
set -euo pipefail

IFACE="${1:?iface required}"
NCPU="$(nproc)"

if systemctl is-active --quiet irqbalance; then
    systemctl stop irqbalance || true
fi

i=0
for irq in $(awk -v ifn="$IFACE" '$0 ~ ifn {gsub(":",""); print $1}' /proc/interrupts); do
    cpu=$((i % NCPU))
    mask=$(printf '%x' $((1 << cpu)))
    echo "$mask" > /proc/irq/"$irq"/smp_affinity 2>/dev/null || true
    printf 'irq=%s iface=%s cpu=%d mask=%s\n' "$irq" "$IFACE" "$cpu" "$mask"
    i=$((i + 1))
done
