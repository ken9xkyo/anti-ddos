/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ANTIDDOS_COMMON_H
#define __ANTIDDOS_COMMON_H

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ---- configuration limits ------------------------------------------------ */
#define BLOCKLIST_V4_MAX   1048576   /* 1M */
#define BLOCKLIST_V6_MAX   262144    /* 256k */
#define WHITELIST_V4_MAX   65536
#define WHITELIST_V6_MAX   16384
#define RATE_BUCKETS_MAX   2097152   /* 2M */
#define CONNTRACK_MAX      4194304   /* 4M */
#define TOPN_MAX           65536
#define EVENTS_RB_BYTES    (16 * 1024 * 1024)

/* ---- stats counters ------------------------------------------------------ */
enum stat_idx {
    STAT_RX_TOTAL = 0,
    STAT_PASS,
    STAT_REDIRECT,
    STAT_DROP_MALFORMED,
    STAT_DROP_MARTIAN,
    STAT_DROP_BLOCKLIST,
    STAT_DROP_FRAG,
    STAT_DROP_REFLECT,
    STAT_DROP_ICMP_FLOOD,
    STAT_DROP_SYN_FLOOD,
    STAT_DROP_RATE,
    STAT_DROP_OOS_TCP,
    STAT_DROP_UNKNOWN,
    STAT_WHITELIST_HIT,
    STAT_SYNCOOKIE_ISSUED,
    STAT_SYNCOOKIE_PASS,
    STAT_CT_NEW,
    STAT_CT_ESTABLISHED,
    STAT_BYTES_RX,
    STAT_BYTES_DROPPED,
    STAT_MAX
};

/* ---- config feature flags ------------------------------------------------ */
struct config {
    __u32 feature_flags;            /* bit mask, see FEAT_* below */
    __u32 sample_every;             /* emit 1/N events to ringbuf */
    __u32 syn_rate_pps;             /* SYN per src per sec */
    __u32 udp_rate_pps;             /* UDP per src per sec */
    __u32 icmp_rate_pps;            /* ICMP per src per sec */
    __u32 global_rate_pps;          /* generic per-src pps ceiling */
    __u32 bucket_burst;             /* token bucket burst capacity */
    __u32 egress_ifindex;           /* fallback if devmap[0] empty */
} __attribute__((aligned(8)));

#define FEAT_DROP_FRAGMENTS   (1 << 0)
#define FEAT_DROP_REFLECT     (1 << 1)
#define FEAT_SYNCOOKIE        (1 << 2)
#define FEAT_CONNTRACK        (1 << 3)
#define FEAT_RATE_LIMIT       (1 << 4)
#define FEAT_REDIRECT         (1 << 5)

/* ---- rate bucket --------------------------------------------------------- */
struct rate_key {
    __u32 saddr_hi;  /* upper 32 bits for v6 (0 for v4) */
    __u32 saddr;
    __u32 saddr_mid1;
    __u32 saddr_mid2;
    __u16 proto;
    __u16 _pad;
} __attribute__((packed));

struct rate_val {
    __u64 tokens;        /* fixed-point: pps * 1000 */
    __u64 last_jiffies;
} __attribute__((aligned(8)));

/* ---- conntrack-lite ------------------------------------------------------ */
struct ct_key {
    __u32 saddr_hi;
    __u32 saddr;
    __u32 saddr_mid1;
    __u32 saddr_mid2;
    __u32 daddr_hi;
    __u32 daddr;
    __u32 daddr_mid1;
    __u32 daddr_mid2;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  _pad[3];
} __attribute__((packed));

#define CT_STATE_NEW         1
#define CT_STATE_SYN_SENT    2
#define CT_STATE_ESTABLISHED 3
#define CT_STATE_CLOSING     4

struct ct_val {
    __u64 last_jiffies;
    __u64 pkts;
    __u8  state;
    __u8  _pad[7];
} __attribute__((aligned(8)));

/* ---- LPM keys ------------------------------------------------------------ */
struct lpm_v4_key {
    __u32 prefixlen;
    __u32 addr;       /* network byte order */
} __attribute__((packed));

struct lpm_v6_key {
    __u32 prefixlen;
    __u8  addr[16];
} __attribute__((packed));

/* ---- top-N --------------------------------------------------------------- */
struct topn_val {
    __u64 pkts;
    __u64 bytes;
    __u64 last_jiffies;
} __attribute__((aligned(8)));

/* ---- event record (ringbuf) --------------------------------------------- */
struct event {
    __u64 ts_jiffies;
    __u32 saddr_hi;
    __u32 saddr;
    __u32 saddr_mid1;
    __u32 saddr_mid2;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  action;      /* 0=pass 1=redirect 2=drop */
    __u8  reason;      /* stat_idx */
    __u8  v6;
    __u32 bytes;
} __attribute__((aligned(8)));

/* ---- parsed packet ctx --------------------------------------------------- */
struct pkt_ctx {
    void *data;
    void *data_end;
    __u32 l3_off;
    __u32 l4_off;
    __u32 payload_off;
    __u16 eth_proto;     /* host byte order */
    __u8  l3_proto;      /* IPPROTO_TCP etc. */
    __u8  v6;
    __u8  is_frag;
    __u8  _pad;
    __u32 saddr[4];      /* network byte order; v4 in [1] */
    __u32 daddr[4];
    __u16 sport;
    __u16 dport;
    __u16 ip_tot_len;
    __u16 _pad2;
    __u8  tcp_flags;
};

#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))

static __always_inline void stats_inc(__u32 idx, __u64 val);
static __always_inline __u64 now_jiffies(void);

#endif /* __ANTIDDOS_COMMON_H */
