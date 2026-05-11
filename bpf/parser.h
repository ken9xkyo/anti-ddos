/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ANTIDDOS_PARSER_H
#define __ANTIDDOS_PARSER_H

#include "common.h"

#define PARSE_OK       0
#define PARSE_DROP     1   /* malformed */
#define PARSE_PASS     2   /* non-IP frames, pass to kernel */

static __always_inline int parse_packet(struct xdp_md *ctx, struct pkt_ctx *p)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    p->data = data;
    p->data_end = data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return PARSE_DROP;

    __u16 h_proto = bpf_ntohs(eth->h_proto);
    __u32 off = sizeof(*eth);

    /* strip up to two VLAN tags */
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (h_proto != ETH_P_8021Q && h_proto != ETH_P_8021AD)
            break;
        struct vlan_hdr {
            __be16 h_vlan_TCI;
            __be16 h_vlan_encapsulated_proto;
        } *vh;
        vh = data + off;
        if ((void *)(vh + 1) > data_end)
            return PARSE_DROP;
        h_proto = bpf_ntohs(vh->h_vlan_encapsulated_proto);
        off += sizeof(*vh);
    }

    p->eth_proto = h_proto;
    p->l3_off = off;

    if (h_proto == ETH_P_IP) {
        struct iphdr *iph = data + off;
        if ((void *)(iph + 1) > data_end)
            return PARSE_DROP;
        if (iph->version != 4 || iph->ihl < 5)
            return PARSE_DROP;
        __u32 ihl = iph->ihl * 4;
        if (data + off + ihl > data_end)
            return PARSE_DROP;

        p->v6 = 0;
        p->l3_proto = iph->protocol;
        p->saddr[0] = 0; p->saddr[1] = iph->saddr; p->saddr[2] = 0; p->saddr[3] = 0;
        p->daddr[0] = 0; p->daddr[1] = iph->daddr; p->daddr[2] = 0; p->daddr[3] = 0;
        p->ip_tot_len = bpf_ntohs(iph->tot_len);
        __u16 frag_off = bpf_ntohs(iph->frag_off);
        p->is_frag = (frag_off & (0x1FFF | 0x2000)) != 0; /* MF or non-zero offset */
        p->l4_off = off + ihl;
    } else if (h_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = data + off;
        if ((void *)(ip6 + 1) > data_end)
            return PARSE_DROP;
        p->v6 = 1;
        p->l3_proto = ip6->nexthdr;
        __builtin_memcpy(p->saddr, &ip6->saddr, 16);
        __builtin_memcpy(p->daddr, &ip6->daddr, 16);
        p->ip_tot_len = bpf_ntohs(ip6->payload_len) + sizeof(*ip6);
        p->is_frag = (ip6->nexthdr == IPPROTO_FRAGMENT);
        p->l4_off = off + sizeof(*ip6);
        /* NB: no extension-header walking; fragments handled by is_frag */
    } else {
        /* ARP, LLDP, etc. — let the kernel handle them */
        return PARSE_PASS;
    }

    p->sport = 0;
    p->dport = 0;
    p->tcp_flags = 0;

    if (p->is_frag)
        return PARSE_OK;

    if (p->l3_proto == IPPROTO_TCP) {
        struct tcphdr *th = data + p->l4_off;
        if ((void *)(th + 1) > data_end)
            return PARSE_DROP;
        p->sport = bpf_ntohs(th->source);
        p->dport = bpf_ntohs(th->dest);
        p->tcp_flags = ((__u8 *)th)[13];
        p->payload_off = p->l4_off + (th->doff * 4);
    } else if (p->l3_proto == IPPROTO_UDP) {
        struct udphdr *uh = data + p->l4_off;
        if ((void *)(uh + 1) > data_end)
            return PARSE_DROP;
        p->sport = bpf_ntohs(uh->source);
        p->dport = bpf_ntohs(uh->dest);
        p->payload_off = p->l4_off + sizeof(*uh);
    } else if (p->l3_proto == IPPROTO_ICMP || p->l3_proto == IPPROTO_ICMPV6) {
        /* minimal sanity */
        if (data + p->l4_off + 4 > data_end)
            return PARSE_DROP;
        p->payload_off = p->l4_off + 4;
    } else {
        p->payload_off = p->l4_off;
    }

    return PARSE_OK;
}

/* martian / bogon for IPv4 only (fast); IPv6 martians handled by blocklist. */
static __always_inline int is_martian_v4(__u32 saddr_be)
{
    __u32 a = bpf_ntohl(saddr_be);
    __u8 b0 = (a >> 24) & 0xff;

    if (b0 == 0)   return 1;              /* 0.0.0.0/8 */
    if (b0 == 127) return 1;              /* 127/8 */
    if (b0 >= 224) return 1;              /* 224/4 + 240/4 */
    if (b0 == 169 && ((a >> 16) & 0xff) == 254) return 1; /* link-local */
    /* broadcast */
    if (a == 0xffffffff) return 1;
    return 0;
}

#endif /* __ANTIDDOS_PARSER_H */
