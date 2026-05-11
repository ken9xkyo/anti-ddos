/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ANTIDDOS_POLICY_H
#define __ANTIDDOS_POLICY_H

#include "common.h"
#include "maps.h"

/* token bucket: tokens are in 1/1000 pps units; refill 1000 per jiffy/HZ. */
#ifndef CONFIG_HZ
#define CONFIG_HZ 1000
#endif

/* Build a rate_key for a given source. proto is IPPROTO_* or 0 for global. */
static __always_inline void rate_key_init(struct rate_key *k,
                                          const __u32 saddr[4],
                                          __u16 proto, __u8 v6)
{
    __builtin_memset(k, 0, sizeof(*k));
    if (v6) {
        k->saddr_hi   = saddr[0];
        k->saddr      = saddr[1];
        k->saddr_mid1 = saddr[2];
        k->saddr_mid2 = saddr[3];
    } else {
        k->saddr = saddr[1];
    }
    k->proto = proto;
}

/*
 * Returns 1 if the packet is allowed (token consumed), 0 if rate-limited.
 * pps: sustained rate, burst: capacity.
 */
static __always_inline int rate_allow(const __u32 saddr[4],
                                      __u16 proto, __u8 v6,
                                      __u32 pps, __u32 burst)
{
    if (pps == 0)
        return 1;

    struct rate_key k;
    rate_key_init(&k, saddr, proto, v6);

    __u64 now = now_jiffies();
    struct rate_val *v = bpf_map_lookup_elem(&rate_buckets, &k);
    if (!v) {
        struct rate_val nv = {
            .tokens = (__u64)burst * 1000,
            .last_jiffies = now,
        };
        /* consume one token */
        if (nv.tokens >= 1000)
            nv.tokens -= 1000;
        bpf_map_update_elem(&rate_buckets, &k, &nv, BPF_ANY);
        return 1;
    }

    __u64 elapsed = now - v->last_jiffies;
    /* refill: pps * 1000 / HZ per jiffy */
    __u64 refill = elapsed * pps * 1000 / CONFIG_HZ;
    __u64 cap = (__u64)burst * 1000;
    __u64 tok = v->tokens + refill;
    if (tok > cap) tok = cap;
    v->last_jiffies = now;

    if (tok >= 1000) {
        v->tokens = tok - 1000;
        return 1;
    }
    v->tokens = tok;
    return 0;
}

/* Reflection-attack source-port blacklist (UDP).
 * Dropped unconditionally unless whitelisted upstream.
 */
static __always_inline int is_reflect_sport(__u16 sport)
{
    switch (sport) {
    case 19:    /* chargen */
    case 17:    /* qotd */
    case 53:    /* DNS */
    case 69:    /* TFTP */
    case 111:   /* portmap */
    case 123:   /* NTP */
    case 137:   /* NetBIOS */
    case 161:   /* SNMP */
    case 389:   /* LDAP */
    case 1434:  /* MS-SQL */
    case 1900:  /* SSDP */
    case 3702:  /* WS-Discovery */
    case 5353:  /* mDNS */
    case 5683:  /* CoAP */
    case 10001: /* ubiquiti */
    case 11211: /* memcached */
    case 27015: /* SRCDS */
        return 1;
    }
    return 0;
}

/* Accept control-plane frames we don't want to swallow in the fast path. */
static __always_inline int is_control_tcp_port(__u16 dport)
{
    return dport == 179; /* BGP */
}

/* Update top-talker bookkeeping (sampled). */
static __always_inline void topn_bump(const __u32 saddr[4], __u16 proto,
                                      __u8 v6, __u32 bytes)
{
    struct rate_key k;
    rate_key_init(&k, saddr, proto, v6);
    struct topn_val *v = bpf_map_lookup_elem(&topn_src, &k);
    if (v) {
        v->pkts += 1;
        v->bytes += bytes;
        v->last_jiffies = now_jiffies();
    } else {
        struct topn_val nv = { .pkts = 1, .bytes = bytes, .last_jiffies = now_jiffies() };
        bpf_map_update_elem(&topn_src, &k, &nv, BPF_ANY);
    }
}

/* Emit a sampled event to the ringbuf. */
static __always_inline void emit_event(const struct pkt_ctx *p,
                                       __u8 action, __u8 reason)
{
    struct config *cfg = get_config();
    __u32 every = cfg ? cfg->sample_every : 1024;
    if (every == 0) every = 1024;
    /* jiffies-based coarse sampling keeps it cheap */
    if ((now_jiffies() % every) != 0)
        return;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;
    e->ts_jiffies = now_jiffies();
    e->saddr_hi   = p->saddr[0];
    e->saddr      = p->saddr[1];
    e->saddr_mid1 = p->saddr[2];
    e->saddr_mid2 = p->saddr[3];
    e->sport = p->sport;
    e->dport = p->dport;
    e->proto = p->l3_proto;
    e->action = action;
    e->reason = reason;
    e->v6 = p->v6;
    e->bytes = p->ip_tot_len;
    bpf_ringbuf_submit(e, 0);
}

#endif /* __ANTIDDOS_POLICY_H */
