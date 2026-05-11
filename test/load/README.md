# Load-test scenarios (TRex)

Target: saturate the device-under-test (DUT) at 100 Gbps with worst-case 64-byte
packets and a mix of attack/legit profiles.

## Environment

* Traffic generator host with Intel E810 (100G) or 2× 40G bonded.
* DUT running `antiddosd` inline between generator and sink.
* Optics/DAC back-to-back — no intermediate switch that re-hashes flows.

## Scenarios

| # | Name | PPS target | Mix |
| - | ---- | ---------- | --- |
| 1 | `bench_pass.py`   | 150 Mpps | legit TCP SYN + established, uniform src/dst |
| 2 | `syn_flood.py`    | 100 Mpps | spoofed TCP SYN flood, randomized src /24 |
| 3 | `udp_reflect.py`  | 80  Mpps | UDP src=53/123/11211, small packets |
| 4 | `icmp_flood.py`   | 50  Mpps | ICMP echo flood, single src |
| 5 | `mixed.py`        | 100 Mpps | 70% legit + 30% mixed attack |

## Run (example)

```
# on the generator
./t-rex-64 -i \
  -f cap2/antiddos/syn_flood.yaml \
  -c 16 -m 10 -d 300 -l 1000 --iom 0 \
  --prom
```

## Metrics to collect

* DUT: `antiddos_rx_total`, `antiddos_drop_*`, `antiddos_redirect`, per-core
  softirq CPU, `ethtool -S eth0 | grep -E 'rx_drop|fw_packets|xdp'`.
* Generator: TX pps, RX loopback pps, latency histogram (hw timestamping).

## Pass criteria

* Scenario 1: 0% drop at 150 Mpps.
* Scenarios 2-4: drop rate > 99.5% of attack, pass rate ~100% for legit.
* No per-core pps imbalance above 30% (indicates RSS issue).
