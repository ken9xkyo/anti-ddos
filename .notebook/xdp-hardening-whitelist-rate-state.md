# XDP Hardening, Whitelist Split, Rate State v2

Date: 2026-06-12

## Notes

- `whitelist_v4_a/b` are now global-only LPM maps. Service-scoped whitelist entries go into `whitelist_service_v4_a/b` with key `{prefixlen, service_id, addr}` and prefix length `32 + cidr_bits`.
- `rate_state` remains defined for rollout compatibility. Active token buckets use `rate_state_v2`, a `BPF_MAP_TYPE_HASH | BPF_F_NO_PREALLOC` value with top-level `bpf_spin_lock`.
- The XDP IPv4 parser enforces L4 bounds against IPv4 `tot_len`, but verifier rejected `ip + tot_len` pointer math after endian swap. Keep `tot_len` checks scalar-based and pass `ip_payload_len` into L4 parsing.
- Test coverage lives in `tests/xdp/xdp_fixture_test.c` and covers double VLAN IPv4, malformed `tot_len`, bad UDP length, bad TCP doff, fragments, blacklist, global/service whitelist overlap, UDP source-port block, and rate-limit enforce/observe.
