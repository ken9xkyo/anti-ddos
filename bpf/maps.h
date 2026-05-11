/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ANTIDDOS_MAPS_H
#define __ANTIDDOS_MAPS_H

#include "common.h"

/* ---- stats (per-cpu) ----------------------------------------------------- */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, STAT_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} stats SEC(".maps");

/* ---- config (array of 1) ------------------------------------------------- */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct config);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} config_map SEC(".maps");

/* ---- LPM tries: blocklist + whitelist ----------------------------------- */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v4_key);
    __type(value, __u64);           /* expiry jiffies (0 = permanent) */
    __uint(max_entries, BLOCKLIST_V4_MAX);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocklist_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v6_key);
    __type(value, __u64);
    __uint(max_entries, BLOCKLIST_V6_MAX);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocklist_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v4_key);
    __type(value, __u64);
    __uint(max_entries, WHITELIST_V4_MAX);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} whitelist_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v6_key);
    __type(value, __u64);
    __uint(max_entries, WHITELIST_V6_MAX);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} whitelist_v6 SEC(".maps");

/* ---- token-bucket rate limiter ------------------------------------------ */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key, struct rate_key);
    __type(value, struct rate_val);
    __uint(max_entries, RATE_BUCKETS_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rate_buckets SEC(".maps");

/* ---- conntrack-lite ------------------------------------------------------ */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct ct_key);
    __type(value, struct ct_val);
    __uint(max_entries, CONNTRACK_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} conntrack SEC(".maps");

/* ---- top talkers --------------------------------------------------------- */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct rate_key);    /* reuse: src + proto */
    __type(value, struct topn_val);
    __uint(max_entries, TOPN_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} topn_src SEC(".maps");

/* ---- devmap egress ------------------------------------------------------- */
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 4);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} egress_devmap SEC(".maps");

/* ---- events ringbuf ------------------------------------------------------ */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, EVENTS_RB_BYTES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} events SEC(".maps");

/* ---- shared helpers ------------------------------------------------------ */
static __always_inline void stats_inc(__u32 idx, __u64 val)
{
    __u64 *c = bpf_map_lookup_elem(&stats, &idx);
    if (c)
        *c += val;
}

static __always_inline __u64 now_jiffies(void)
{
    return bpf_jiffies64();
}

static __always_inline struct config *get_config(void)
{
    __u32 k = 0;
    return bpf_map_lookup_elem(&config_map, &k);
}

#endif /* __ANTIDDOS_MAPS_H */
