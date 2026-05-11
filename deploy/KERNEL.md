# Kernel baseline for antiddosd (single-target build)

This build is **not** CO-RE. The eBPF object is compiled for a specific kernel
version and must match the production kernel.

## Supported kernel

* Ubuntu 22.04 LTS: `linux-image-5.15.0-x86_64` and later `5.15.x` HWE
* RHEL 9 / Rocky 9: `kernel-5.14.0-x86_64` with BPF and XDP backports
* Minimum: **5.15** (for `bpf_jiffies64`, XDP `bpf_redirect_map`, LRU percpu
  hash, ringbuf).

## Required kernel config

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_BPF_JIT_DEFAULT_ON=y
CONFIG_XDP_SOCKETS=y
CONFIG_NET_CLS_BPF=y
CONFIG_NET_ACT_BPF=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_FTRACE_SYSCALLS=y
# for syncookie helper (M5):
CONFIG_SYN_COOKIES=y
```

## Build-time pinning

`make bpf` runs `bpf2go`, which invokes `clang -target bpf` against the headers
installed at `/usr/src/linux-headers-$(uname -r)`. If you change the production
kernel, rebuild the BPF object and ship both `antiddosd` and the new `.o`.

## Driver

* Intel `ice` >= 1.9 (E810) with native XDP
* Intel `i40e` >= 2.20 (XL710) with native XDP

Do **not** run in `skb` (generic) mode at 100 Gbps — it will drop packets in
softirq and burn CPU. The loader will log a warning if native attach fails.
