# antiddos — XDP Anti-DDoS mitigator (100 Gbps)

High-performance, inline (bump-in-the-wire) XDP-based anti-DDoS for a 32-core /
64 GB server on Intel E810/XL710 NICs. Mitigates L3/L4 volumetric floods and
reflection/protocol attacks at line rate.

## Layout

```
bpf/            eBPF datapath (C, compiled by clang + bpf2go)
cmd/antiddosd/  Userspace daemon entrypoint
pkg/loader/     Loader + bpf2go generated bindings
pkg/maps/       Typed map wrappers (blocklist, whitelist, rate, conntrack)
pkg/config/     YAML config + fsnotify hot-reload
pkg/api/        REST admin API (chi)
pkg/metrics/    Prometheus exporter
pkg/events/     Ringbuf event consumer
deploy/         systemd unit, tuning & IRQ scripts, example config
test/           prog_test_run unit tests, load-test scenarios
```

## Build

```
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r)
make bpf    # compile eBPF + generate Go bindings
make build  # build bin/antiddosd
```

## Run (inline bump-in-the-wire)

Assuming `eth0` = ingress (from Internet), `eth1` = egress (to backend):

```
sudo ./deploy/tuning.sh eth0 eth1
sudo ./deploy/set_irq_affinity.sh eth0
sudo ./deploy/set_irq_affinity.sh eth1
sudo ./bin/antiddosd --config /etc/antiddosd/config.yaml
```

Pinned BPF objects live under `/sys/fs/bpf/antiddos/`, so the daemon can be
restarted without detaching the XDP program.

## Admin API (default 127.0.0.1:8080)

```
POST   /v1/block     {cidr, ttl_seconds}
DELETE /v1/block     {cidr}
POST   /v1/whitelist {cidr}
GET    /v1/stats
GET    /v1/topn
POST   /v1/config    (atomic swap)
GET    /metrics      (Prometheus)
```

## Performance targets

- Native XDP on `ice` driver (E810), 32 queues pinned 1:1 to cores 0..31.
- ~5 Mpps/core worst case, 150 Mpps total (64B), 100 Gbps clean throughput.
- Sub-100 µs added latency on the pass/redirect path.

See the full design doc under `.qoder/plans/` (git-ignored).
