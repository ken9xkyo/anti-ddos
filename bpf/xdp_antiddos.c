/* SPDX-License-Identifier: GPL-2.0
 *
 * xdp_antiddos - high-performance inline anti-DDoS XDP program.
 *
 * Pipeline (inlined, no tail calls for lower overhead on happy path):
 *   parse -> static policy -> proto guards -> rate-limit ->
 *   conntrack-lite -> action (REDIRECT / DROP / PASS)
 */

#include "common.h"
#include "maps.h"
#include "parser.h"
#include "policy.h"

char LICENSE[] SEC("license") = "GPL";

/* ---- LPM lookups --------------------------------------------------------- */
static __always_inline int lpm_match_v4(void *map, __u32 addr_be)
{
    struct lpm_v4_key k = { .prefixlen = 32, .addr = addr_be };
    return bpf_map_lookup_elem(map, &k) != NULL;
}

static __always_inline int lpm_match_v6(void *map, const __u32 addr[4])
{
    struct lpm_v6_key k = { .prefixlen = 128 };
    __builtin_memcpy(k.addr, addr, 16);
    return bpf_map_lookup_elem(map, &k) != NULL;
}

/* ---- conntrack lookup/update -------------------------------------------- */
static __always_inline void ct_key_init(struct ct_key *k, const struct pkt_ctx *p)
{
    __builtin_memset(k, 0, sizeof(*k));
    if (p->v6) {
        k->saddr_hi = p->saddr[0]; k->saddr = p->saddr[1];
        k->saddr_mid1 = p->saddr[2]; k->saddr_mid2 = p->saddr[3];
        k->daddr_hi = p->daddr[0]; k->daddr = p->daddr[1];
        k->daddr_mid1 = p->daddr[2]; k->daddr_mid2 = p->daddr[3];
    } else {
        k->saddr = p->saddr[1];
        k->daddr = p->daddr[1];
    }
    k->sport = p->sport;
    k->dport = p->dport;
    k->proto = p->l3_proto;
}

/*
 * TCP state machine (abbreviated).
 * Returns: 1 to allow, 0 to drop (out of state).
 */
static __always_inline int ct_tcp(struct pkt_ctx *p)
{
    struct ct_key k;
    ct_key_init(&k, p);

    __u8 flags = p->tcp_flags;
    const __u8 SYN = 0x02, ACK = 0x10, RST = 0x04, FIN = 0x01;

    struct ct_val *v = bpf_map_lookup_elem(&conntrack, &k);
    if (!v) {
        /* only SYN (no ACK) may create a new flow */
        if ((flags & (SYN | ACK)) != SYN) {
            stats_inc(STAT_DROP_OOS_TCP, 1);
            return 0;
        }
        struct ct_val nv = {
            .last_jiffies = now_jiffies(),
            .pkts = 1,
            .state = CT_STATE_SYN_SENT,
        };
        bpf_map_update_elem(&conntrack, &k, &nv, BPF_ANY);
        stats_inc(STAT_CT_NEW, 1);
        return 1;
    }

    v->last_jiffies = now_jiffies();
    v->pkts += 1;
    if (v->state == CT_STATE_SYN_SENT && (flags & ACK))
        v->state = CT_STATE_ESTABLISHED;
    if (flags & (RST | FIN))
        v->state = CT_STATE_CLOSING;
    if (v->state == CT_STATE_ESTABLISHED)
        stats_inc(STAT_CT_ESTABLISHED, 1);
    return 1;
}

/* ---- SYN cookie --------------------------------------------------------- */
static __always_inline int syncookie_check(struct xdp_md *ctx, struct pkt_ctx *p)
{
#ifdef HAVE_SYNCOOKIE
    /*
     * Requires kernel with XDP_FLAGS_SKB_MODE or recent ice driver supporting
     * bpf_tcp_raw_{gen,check}_syncookie_ipv{4,6}. Implementation is a stub
     * here; wire it up in M5.
     */
    (void)ctx; (void)p;
#endif
    (void)ctx; (void)p;
    return 1;
}

/* ---- main XDP prog ------------------------------------------------------- */
SEC("xdp")
int xdp_antiddos(struct xdp_md *ctx)
{
    struct pkt_ctx p = {};
    __u64 pkt_bytes = (__u64)((long)ctx->data_end - (long)ctx->data);

    stats_inc(STAT_RX_TOTAL, 1);
    stats_inc(STAT_BYTES_RX, pkt_bytes);

    int pr = parse_packet(ctx, &p);
    if (pr == PARSE_DROP) {
        stats_inc(STAT_DROP_MALFORMED, 1);
        stats_inc(STAT_BYTES_DROPPED, pkt_bytes);
        return XDP_DROP;
    }
    if (pr == PARSE_PASS) {
        stats_inc(STAT_PASS, 1);
        return XDP_PASS;
    }

    struct config *cfg = get_config();
    __u32 feats = cfg ? cfg->feature_flags : 0;

    /* ---- Stage 1: static policy ------------------------------------- */
    if (!p.v6) {
        if (is_martian_v4(p.saddr[1])) {
            stats_inc(STAT_DROP_MARTIAN, 1);
            stats_inc(STAT_BYTES_DROPPED, pkt_bytes);
            emit_event(&p, 2, STAT_DROP_MARTIAN);
            return XDP_DROP;
        }
        if (lpm_match_v4(&whitelist_v4, p.saddr[1])) {
            stats_inc(STAT_WHITELIST_HIT, 1);
            goto action_redirect;
        }
        if (lpm_match_v4(&blocklist_v4, p.saddr[1])) {
            stats_inc(STAT_DROP_BLOCKLIST, 1);
            stats_inc(STAT_BYTES_DROPPED, pkt_bytes);
            emit_event(&p, 2, STAT_DROP_BLOCKLIST);
            return XDP_DROP;
        }
    } else {
        if (lpm_match_v6(&whitelist_v6, p.saddr)) {
            stats_inc(STAT_WHITELIST_HIT, 1);
            goto action_redirect;
        }
        if (lpm_match_v6(&blocklist_v6, p.saddr)) {
            stats_inc(STAT_DROP_BLOCKLIST, 1);
            stats_inc(STAT_BYTES_DROPPED, pkt_bytes);
            emit_event(&p, 2, STAT_DROP_BLOCKLIST);
            return XDP_DROP;
        }
    }

    /* ---- Stage 2: fragments ----------------------------------------- */
    if (p.is_frag && (feats & FEAT_DROP_FRAGMENTS)) {
        stats_inc(STAT_DROP_FRAG, 1);
        stats_inc(STAT_BYTES_DROPPED, pkt_bytes);
        emit_event(&p, 2, STAT_DROP_FRAG);
        return XDP_DROP;
    }

    /* ---- Stage 3: protocol-specific guards -------------------------- */
    if (p.l3_proto == IPPROTO_UDP) {
        if ((feats & FEAT_DROP_REFLECT) && is_reflect_sport(p.sport)) {
            stats_inc(STAT_DROP_REFLECT, 1);
            stats_inc(STAT_BYTES_DROPPED, pkt_bytes);
            emit_event(&p, 2, STAT_DROP_REFLECT);
            return XDP_DROP;
        }
        if ((feats & FEAT_RATE_LIMIT) && cfg &&
            !rate_allow(p.saddr, IPPROTO_UDP, p.v6,
                        cfg->udp_rate_pps, cfg->bucket_burst)) {
            stats_inc(STAT_DROP_RATE, 1);
            stats_inc(STAT_BYTES_DROPPED, pkt_bytes);
            emit_event(&p, 2, STAT_DROP_RATE);
            return XDP_DROP;
        }
    } else if (p.l3_proto == IPPROTO_ICMP || p.l3_proto == IPPROTO_ICMPV6) {
        if ((feats & FEAT_RATE_LIMIT) && cfg &&
            !rate_allow(p.saddr, p.l3_proto, p.v6,
                        cfg->icmp_rate_pps, cfg->bucket_burst)) {
            stats_inc(STAT_DROP_ICMP_FLOOD, 1);
            stats_inc(STAT_BYTES_DROPPED, pkt_bytes);
            emit_event(&p, 2, STAT_DROP_ICMP_FLOOD);
            return XDP_DROP;
        }
    } else if (p.l3_proto == IPPROTO_TCP) {
        /* let control plane (e.g. BGP) through */
        if (is_control_tcp_port(p.dport)) {
            stats_inc(STAT_PASS, 1);
            return XDP_PASS;
        }
        const __u8 SYN = 0x02, ACK = 0x10;
        if ((p.tcp_flags & (SYN | ACK)) == SYN) {
            /* SYN: rate-limit, then (optional) cookie */
            if ((feats & FEAT_RATE_LIMIT) && cfg &&
                !rate_allow(p.saddr, IPPROTO_TCP, p.v6,
                            cfg->syn_rate_pps, cfg->bucket_burst)) {
                stats_inc(STAT_DROP_SYN_FLOOD, 1);
                stats_inc(STAT_BYTES_DROPPED, pkt_bytes);
                emit_event(&p, 2, STAT_DROP_SYN_FLOOD);
                return XDP_DROP;
            }
            if ((feats & FEAT_SYNCOOKIE) && !syncookie_check(ctx, &p)) {
                stats_inc(STAT_DROP_SYN_FLOOD, 1);
                stats_inc(STAT_BYTES_DROPPED, pkt_bytes);
                return XDP_DROP;
            }
            stats_inc(STAT_SYNCOOKIE_PASS, 1);
        } else {
            /* non-SYN: optional conntrack-lite */
            if ((feats & FEAT_CONNTRACK) && !ct_tcp(&p)) {
                stats_inc(STAT_BYTES_DROPPED, pkt_bytes);
                emit_event(&p, 2, STAT_DROP_OOS_TCP);
                return XDP_DROP;
            }
        }
    }

    /* ---- Stage 4: generic per-source rate ceiling ------------------- */
    if ((feats & FEAT_RATE_LIMIT) && cfg && cfg->global_rate_pps &&
        !rate_allow(p.saddr, 0, p.v6, cfg->global_rate_pps, cfg->bucket_burst)) {
        stats_inc(STAT_DROP_RATE, 1);
        stats_inc(STAT_BYTES_DROPPED, pkt_bytes);
        emit_event(&p, 2, STAT_DROP_RATE);
        return XDP_DROP;
    }

    /* ---- Stage 5: top-N bookkeeping (sampled) ----------------------- */
    if ((pkt_bytes & 0xff) == 0)
        topn_bump(p.saddr, p.l3_proto, p.v6, pkt_bytes);

action_redirect:
    if (feats & FEAT_REDIRECT) {
        stats_inc(STAT_REDIRECT, 1);
        return bpf_redirect_map(&egress_devmap, 0, 0);
    }
    stats_inc(STAT_PASS, 1);
    return XDP_PASS;
}

/*
 * Fallback XDP program used when the daemon is not running or the main one
 * needs to be replaced atomically. Passes everything.
 */
SEC("xdp")
int xdp_passthru(struct xdp_md *ctx)
{
    (void)ctx;
    return XDP_PASS;
}
