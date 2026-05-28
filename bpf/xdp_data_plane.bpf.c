#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "anti_ddos/bpf_contract.h"

#define ETH_P_IP 0x0800
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPV4_MF 0x2000
#define IPV4_OFFSET 0x1fff
#define TCP_FLAGS_OFFSET 13

enum parse_result {
	PARSE_OK = 0,
	PARSE_MALFORMED = 1,
	PARSE_NON_IPV4 = 2,
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, ANTI_DDOS_MAX_WHITELIST_V4);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_v4_key);
	__type(value, struct cidr_policy_value);
} whitelist_v4_a SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, ANTI_DDOS_MAX_WHITELIST_V4);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_v4_key);
	__type(value, struct cidr_policy_value);
} whitelist_v4_b SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, ANTI_DDOS_MAX_BLACKLIST_V4);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_v4_key);
	__type(value, struct cidr_policy_value);
} blacklist_v4_a SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, ANTI_DDOS_MAX_BLACKLIST_V4);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_v4_key);
	__type(value, struct cidr_policy_value);
} blacklist_v4_b SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, ANTI_DDOS_MAX_SERVICE_ALLOWLIST);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct service_key);
	__type(value, struct service_value);
} service_allowlist_a SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, ANTI_DDOS_MAX_SERVICE_ALLOWLIST);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct service_key);
	__type(value, struct service_value);
} service_allowlist_b SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(max_entries, ANTI_DDOS_MAX_TX_DEVMAP);
	__type(key, __u32);
	__type(value, __u32);
} tx_devmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, ANTI_DDOS_MAX_RATE_STATE);
	__type(key, struct rate_key);
	__type(value, struct rate_value);
} rate_state SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, ANTI_DDOS_MAX_RULES);
	__type(key, __u32);
	__type(value, struct rule_value);
} rule_config_a SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, ANTI_DDOS_MAX_RULES);
	__type(key, __u32);
	__type(value, struct rule_value);
} rule_config_b SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, ANTI_DDOS_MAX_DROP_COUNTERS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct counter_key);
	__type(value, struct counter_value);
} drop_counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, ANTI_DDOS_EVENTS_BYTES);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct runtime_config_value);
} runtime_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, ANTI_DDOS_MAX_PROG_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
} prog_array SEC(".maps");

static __always_inline __u16 packet_len(void *data, void *data_end)
{
	__u64 len = data_end - data;

	if (len > 0xffff)
		return 0xffff;

	return (__u16)len;
}

static __always_inline void count_packet(const struct packet_meta *meta)
{
	struct counter_key key = {
		.reason = meta->reason,
		.rule_id = meta->rule_id,
		.service_id = meta->service_id,
		.proto = meta->proto,
		.action = meta->action,
	};
	struct counter_value init = {
		.packets = 1,
		.bytes = meta->pkt_len,
	};
	struct counter_value *value;

	value = bpf_map_lookup_elem(&drop_counters, &key);
	if (value) {
		value->packets += 1;
		value->bytes += meta->pkt_len;
		return;
	}

	bpf_map_update_elem(&drop_counters, &key, &init, BPF_ANY);
}

static __always_inline void count_ringbuf_drop(const struct packet_meta *meta)
{
	struct packet_meta event_meta = *meta;

	event_meta.reason = REASON_MAP_ERROR;
	event_meta.action = ACTION_SAMPLE;
	count_packet(&event_meta);
}

static __always_inline void maybe_sample(const struct packet_meta *meta,
					 const struct runtime_config_value *cfg)
{
	struct event_record *rec;
	__u32 denom = cfg->sample_denom;

	if (denom == 0)
		return;

	if (denom > ANTI_DDOS_MAX_EVENT_SAMPLE_DENOM)
		denom = ANTI_DDOS_MAX_EVENT_SAMPLE_DENOM;

	if (denom > 1 && (bpf_get_prandom_u32() % denom) != 0)
		return;

	rec = bpf_ringbuf_reserve(&events, sizeof(*rec), 0);
	if (!rec) {
		count_ringbuf_drop(meta);
		return;
	}

	rec->ts_mono_ns = bpf_ktime_get_ns();
	rec->policy_version = cfg->policy_version;
	rec->src_v4 = meta->src_v4;
	rec->dst_v4 = meta->dst_v4;
	rec->src_port = meta->src_port;
	rec->dst_port = meta->dst_port;
	rec->proto = meta->proto;
	rec->tcp_flags = meta->tcp_flags;
	rec->action = meta->action;
	rec->reason = meta->reason;
	rec->service_id = meta->service_id;
	rec->rule_id = meta->rule_id;
	rec->pkt_len = meta->pkt_len;

	bpf_ringbuf_submit(rec, 0);
}

static __always_inline int parse_l4(void *l4, void *data_end,
				    struct packet_meta *meta)
{
	if (meta->proto == L4_TCP) {
		struct tcphdr *tcp = l4;
		__u8 *tcp_flags = l4 + TCP_FLAGS_OFFSET;

		if ((void *)(tcp + 1) > data_end)
			return PARSE_MALFORMED;

		meta->src_port = bpf_ntohs(tcp->source);
		meta->dst_port = bpf_ntohs(tcp->dest);
		meta->tcp_flags = *tcp_flags;
		return PARSE_OK;
	}

	if (meta->proto == L4_UDP) {
		struct udphdr *udp = l4;

		if ((void *)(udp + 1) > data_end)
			return PARSE_MALFORMED;

		meta->src_port = bpf_ntohs(udp->source);
		meta->dst_port = bpf_ntohs(udp->dest);
		return PARSE_OK;
	}

	if (meta->proto == L4_ICMP) {
		struct icmphdr *icmp = l4;

		if ((void *)(icmp + 1) > data_end)
			return PARSE_MALFORMED;

		return PARSE_OK;
	}

	return PARSE_OK;
}

static __always_inline int parse_packet(struct xdp_md *ctx,
					struct packet_meta *meta)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	void *l4;
	__u8 version_ihl;
	__u8 version;
	__u8 ihl;
	__u32 ip_header_len;
	__u16 total_len;
	__u16 frag_off;

	meta->pkt_len = packet_len(data, data_end);

	if ((void *)(eth + 1) > data_end)
		return PARSE_MALFORMED;

	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return PARSE_NON_IPV4;

	ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return PARSE_MALFORMED;

	version_ihl = *(__u8 *)ip;
	version = version_ihl >> 4;
	ihl = version_ihl & 0x0f;
	if (version != 4 || ihl < 5)
		return PARSE_MALFORMED;

	ip_header_len = (__u32)ihl * 4;
	if ((void *)ip + ip_header_len > data_end)
		return PARSE_MALFORMED;

	total_len = bpf_ntohs(ip->tot_len);
	if (total_len < ip_header_len)
		return PARSE_MALFORMED;

	meta->src_v4 = ip->saddr;
	meta->dst_v4 = ip->daddr;

	if (ip->protocol == IPPROTO_TCP)
		meta->proto = L4_TCP;
	else if (ip->protocol == IPPROTO_UDP)
		meta->proto = L4_UDP;
	else if (ip->protocol == IPPROTO_ICMP)
		meta->proto = L4_ICMP;
	else
		meta->proto = L4_UNKNOWN;

	frag_off = bpf_ntohs(ip->frag_off);
	if ((frag_off & (IPV4_MF | IPV4_OFFSET)) != 0) {
		meta->is_fragment = 1;
		return PARSE_OK;
	}

	l4 = (void *)ip + ip_header_len;
	return parse_l4(l4, data_end, meta);
}

SEC("xdp")
int xdp_entry(struct xdp_md *ctx)
{
	struct packet_meta meta = {};
	struct runtime_config_value *cfg;
	__u32 cfg_key = 0;
	int parse_result;

	cfg = bpf_map_lookup_elem(&runtime_config, &cfg_key);
	if (!cfg || cfg->policy_version == 0) {
		void *data = (void *)(long)ctx->data;
		void *data_end = (void *)(long)ctx->data_end;

		meta.pkt_len = packet_len(data, data_end);
		meta.action = ACTION_DROP;
		meta.reason = REASON_MAP_ERROR;
		count_packet(&meta);
		return XDP_DROP;
	}

	parse_result = parse_packet(ctx, &meta);
	if (parse_result == PARSE_NON_IPV4) {
		meta.action = ACTION_PASS;
		meta.reason = REASON_NONE;
		count_packet(&meta);
		maybe_sample(&meta, cfg);
		return XDP_PASS;
	}

	if (parse_result == PARSE_MALFORMED) {
		meta.is_malformed = 1;
		meta.action = ACTION_DROP;
		meta.reason = REASON_MALFORMED;
		count_packet(&meta);
		maybe_sample(&meta, cfg);
		return XDP_DROP;
	}

	if (meta.is_fragment) {
		meta.action = ACTION_DROP;
		meta.reason = REASON_FRAGMENT;
		count_packet(&meta);
		maybe_sample(&meta, cfg);
		return XDP_DROP;
	}

	meta.action = ACTION_DROP;
	meta.reason = REASON_NOT_ALLOWED_SERVICE;
	count_packet(&meta);
	maybe_sample(&meta, cfg);
	return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
