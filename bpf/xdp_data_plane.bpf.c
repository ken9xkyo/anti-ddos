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
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_ACK 0x10
#define ETH_ALEN 6
#define NSEC_PER_SEC 1000000000ULL
#define IPV4_PREFIX24_MASK 0x00ffffffU

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
		.tcp_syn = meta->proto == L4_TCP &&
			(meta->tcp_flags & TCP_FLAG_SYN) != 0 &&
			(meta->tcp_flags & TCP_FLAG_ACK) == 0,
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

static __always_inline void maybe_sample_with_denom(const struct packet_meta *meta,
						    const struct runtime_config_value *cfg,
						    __u32 denom)
{
	struct event_record *rec;

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

static __always_inline void maybe_sample(const struct packet_meta *meta,
					 const struct runtime_config_value *cfg)
{
	maybe_sample_with_denom(meta, cfg, cfg->sample_denom);
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

static __always_inline struct cidr_policy_value *
lookup_active_whitelist(__u32 active_slot, __u32 src_v4)
{
	struct lpm_v4_key key = {
		.prefixlen = 32,
		.addr = src_v4,
	};

	if (active_slot == 0)
		return bpf_map_lookup_elem(&whitelist_v4_a, &key);

	return bpf_map_lookup_elem(&whitelist_v4_b, &key);
}

static __always_inline struct cidr_policy_value *
lookup_active_blacklist(__u32 active_slot, __u32 src_v4)
{
	struct lpm_v4_key key = {
		.prefixlen = 32,
		.addr = src_v4,
	};

	if (active_slot == 0)
		return bpf_map_lookup_elem(&blacklist_v4_a, &key);

	return bpf_map_lookup_elem(&blacklist_v4_b, &key);
}

static __always_inline struct service_value *
lookup_active_service(__u32 active_slot, const struct packet_meta *meta)
{
	struct service_key key = {
		.dst_v4 = meta->dst_v4,
		.dst_port = meta->dst_port,
		.proto = meta->proto,
	};

	if (active_slot == 0)
		return bpf_map_lookup_elem(&service_allowlist_a, &key);

	return bpf_map_lookup_elem(&service_allowlist_b, &key);
}

static __always_inline struct rule_value *
lookup_active_rule(__u32 active_slot, __u32 rule_id)
{
	if (rule_id == 0 || rule_id >= ANTI_DDOS_MAX_RULES)
		return NULL;

	if (active_slot == 0)
		return bpf_map_lookup_elem(&rule_config_a, &rule_id);

	return bpf_map_lookup_elem(&rule_config_b, &rule_id);
}

static __always_inline __u8 is_tcp_syn_without_ack(const struct packet_meta *meta)
{
	return meta->proto == L4_TCP &&
		(meta->tcp_flags & TCP_FLAG_SYN) != 0 &&
		(meta->tcp_flags & TCP_FLAG_ACK) == 0;
}

static __always_inline __u64 min_u64(__u64 left, __u64 right)
{
	if (left < right)
		return left;
	return right;
}

static __always_inline __u64 nonzero_u64(__u64 preferred, __u64 fallback)
{
	if (preferred != 0)
		return preferred;
	if (fallback != 0)
		return fallback;
	return 1;
}

static __always_inline void build_rate_key(struct rate_key *key,
					   const struct rule_value *rule,
					   const struct packet_meta *meta)
{
	key->rule_id = rule->rule_id;
	key->proto = meta->proto;
	key->dimension = rule->dimension;

	if (rule->dimension == RATE_DIM_SOURCE) {
		key->src_v4 = meta->src_v4;
		return;
	}
	if (rule->dimension == RATE_DIM_SUBNET) {
		key->src_v4 = meta->src_v4 & IPV4_PREFIX24_MASK;
		return;
	}
	if (rule->dimension == RATE_DIM_SERVICE) {
		key->service_id = meta->service_id;
		return;
	}

	key->src_v4 = meta->src_v4;
	key->service_id = meta->service_id;
	key->dimension = RATE_DIM_SOURCE_SERVICE;
}

static __always_inline int apply_token_bucket(const struct rule_value *rule,
					      const struct packet_meta *meta)
{
	struct rate_key key = {};
	struct rate_value init = {};
	struct rate_value *state;
	__u64 now = bpf_ktime_get_ns();
	__u64 elapsed;
	__u64 packet_burst = nonzero_u64(rule->burst_packets, rule->threshold_pps);
	__u64 byte_burst = rule->burst_bytes;
	__u64 syn_burst = nonzero_u64(rule->burst_packets, rule->threshold_cps);
	__u8 tcp_syn = is_tcp_syn_without_ack(meta);
	__u8 over_limit = 0;

	if (byte_burst == 0 && rule->threshold_bps != 0)
		byte_burst = (__u64)rule->threshold_bps / 8;
	byte_burst = nonzero_u64(byte_burst, meta->pkt_len);

	build_rate_key(&key, rule, meta);
	state = bpf_map_lookup_elem(&rate_state, &key);
	if (!state) {
		init.last_refill_ns = now;
		init.tokens_packets = packet_burst;
		init.tokens_bytes = byte_burst;
		init.tokens_syn = syn_burst;
		if (bpf_map_update_elem(&rate_state, &key, &init, BPF_NOEXIST) != 0)
			return 1;
		state = bpf_map_lookup_elem(&rate_state, &key);
		if (!state)
			return 1;
	}

	elapsed = now - state->last_refill_ns;
	if (elapsed > NSEC_PER_SEC)
		elapsed = NSEC_PER_SEC;

	if (elapsed > 0) {
		if (rule->threshold_pps != 0) {
			__u64 refill_packets = (elapsed * (__u64)rule->threshold_pps) / NSEC_PER_SEC;
			state->tokens_packets = min_u64(packet_burst, state->tokens_packets + refill_packets);
		}
		if (rule->threshold_bps != 0) {
			__u64 refill_bytes = (elapsed * (__u64)rule->threshold_bps) / (8ULL * NSEC_PER_SEC);
			state->tokens_bytes = min_u64(byte_burst, state->tokens_bytes + refill_bytes);
		}
		if (rule->threshold_cps != 0) {
			__u64 refill_syn = (elapsed * (__u64)rule->threshold_cps) / NSEC_PER_SEC;
			state->tokens_syn = min_u64(syn_burst, state->tokens_syn + refill_syn);
		}
		state->last_refill_ns = now;
	}

	state->packets_seen += 1;
	state->bytes_seen += meta->pkt_len;
	if (tcp_syn)
		state->syn_seen += 1;

	if (rule->threshold_pps != 0 && state->tokens_packets < 1)
		over_limit = 1;
	if (rule->threshold_bps != 0 && state->tokens_bytes < meta->pkt_len)
		over_limit = 1;
	if (rule->threshold_cps != 0 && tcp_syn && state->tokens_syn < 1)
		over_limit = 1;

	if (over_limit)
		return 1;

	if (rule->threshold_pps != 0)
		state->tokens_packets -= 1;
	if (rule->threshold_bps != 0)
		state->tokens_bytes -= meta->pkt_len;
	if (rule->threshold_cps != 0 && tcp_syn)
		state->tokens_syn -= 1;

	return 0;
}

static __always_inline int apply_rule(const struct rule_value *rule,
				      struct packet_meta *meta,
				      const struct runtime_config_value *cfg)
{
	__u32 sample_denom;
	int over_limit = 0;

	if (!rule || rule->rule_id == 0)
		return 0;

	meta->rule_id = rule->rule_id;

	if (rule->action == ACTION_DROP) {
		if (rule->mode == 1) {
			meta->action = ACTION_DROP;
			meta->reason = REASON_RULE_DROP;
			count_packet(meta);
			maybe_sample(meta, cfg);
			return 1;
		}
		meta->action = ACTION_OBSERVE;
		meta->reason = REASON_RULE_DROP;
		count_packet(meta);
		maybe_sample(meta, cfg);
		return 0;
	}

	if (rule->action == ACTION_SAMPLE) {
		sample_denom = rule->sample_denom;
		if (sample_denom == 0)
			sample_denom = 1;
		meta->action = ACTION_SAMPLE;
		meta->reason = REASON_NONE;
		count_packet(meta);
		maybe_sample_with_denom(meta, cfg, sample_denom);
		return 0;
	}

	if (rule->action == ACTION_RATE_LIMIT) {
		over_limit = apply_token_bucket(rule, meta);
		if (over_limit && rule->mode == 1) {
			meta->action = ACTION_DROP;
			meta->reason = REASON_RATE_LIMIT;
			count_packet(meta);
			maybe_sample(meta, cfg);
			return 1;
		}
		if (rule->mode == 0) {
			meta->action = ACTION_OBSERVE;
			meta->reason = over_limit ? REASON_RATE_LIMIT : REASON_NONE;
			count_packet(meta);
			maybe_sample(meta, cfg);
		}
		return 0;
	}

	if (rule->action == ACTION_OBSERVE) {
		meta->action = ACTION_OBSERVE;
		meta->reason = REASON_NONE;
		count_packet(meta);
		maybe_sample(meta, cfg);
	}

	return 0;
}

static __always_inline int rewrite_eth_addrs(struct xdp_md *ctx,
					     const __u8 dst_mac[ETH_ALEN],
					     const __u8 src_mac[ETH_ALEN])
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return -1;

	eth->h_dest[0] = dst_mac[0];
	eth->h_dest[1] = dst_mac[1];
	eth->h_dest[2] = dst_mac[2];
	eth->h_dest[3] = dst_mac[3];
	eth->h_dest[4] = dst_mac[4];
	eth->h_dest[5] = dst_mac[5];
	eth->h_source[0] = src_mac[0];
	eth->h_source[1] = src_mac[1];
	eth->h_source[2] = src_mac[2];
	eth->h_source[3] = src_mac[3];
	eth->h_source[4] = src_mac[4];
	eth->h_source[5] = src_mac[5];

	return 0;
}

SEC("xdp")
int xdp_entry(struct xdp_md *ctx)
{
	struct packet_meta meta = {};
	struct runtime_config_value *cfg;
	struct cidr_policy_value *whitelist;
	struct cidr_policy_value *blacklist;
	struct service_value *service;
	struct rule_value *rule;
	__u8 whitelist_applies = 0;
	__u32 cfg_key = 0;
	int parse_result;
	int redirect_ret;

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
	if (cfg->active_slot > 1) {
		void *data = (void *)(long)ctx->data;
		void *data_end = (void *)(long)ctx->data_end;

		meta.pkt_len = packet_len(data, data_end);
		meta.action = ACTION_DROP;
		meta.reason = REASON_MAP_ERROR;
		count_packet(&meta);
		maybe_sample(&meta, cfg);
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

	service = lookup_active_service(cfg->active_slot, &meta);
	if (!service) {
		meta.action = ACTION_DROP;
		meta.reason = REASON_NOT_ALLOWED_SERVICE;
		count_packet(&meta);
		maybe_sample(&meta, cfg);
		return XDP_DROP;
	}
	meta.service_id = service->service_id;
	meta.rule_id = service->default_rule_id;

	whitelist = lookup_active_whitelist(cfg->active_slot, meta.src_v4);
	if (whitelist && (whitelist->scope == POLICY_SCOPE_GLOBAL ||
			  (whitelist->scope == POLICY_SCOPE_SERVICE &&
			   whitelist->service_id == service->service_id)))
		whitelist_applies = 1;

	blacklist = lookup_active_blacklist(cfg->active_slot, meta.src_v4);
	if (!whitelist_applies && blacklist && blacklist->action == ACTION_DROP) {
		meta.rule_id = blacklist->rule_id;
		meta.action = ACTION_DROP;
		meta.reason = REASON_BLACKLIST;
		count_packet(&meta);
		maybe_sample(&meta, cfg);
		return XDP_DROP;
	}

	if (service->neighbor_status != NEIGHBOR_RESOLVED) {
		meta.action = ACTION_DROP;
		meta.reason = REASON_NEIGHBOR_UNRESOLVED;
		count_packet(&meta);
		maybe_sample(&meta, cfg);
		return XDP_DROP;
	}

	if (!whitelist_applies) {
		rule = lookup_active_rule(cfg->active_slot, service->default_rule_id);
		if (apply_rule(rule, &meta, cfg) != 0)
			return XDP_DROP;
	}

	if (service->action != ACTION_REDIRECT ||
	    rewrite_eth_addrs(ctx, service->dst_mac, service->src_mac) != 0) {
		meta.action = ACTION_DROP;
		meta.reason = REASON_REDIRECT_ERROR;
		count_packet(&meta);
		maybe_sample(&meta, cfg);
		return XDP_DROP;
	}

	redirect_ret = bpf_redirect_map(&tx_devmap, service->devmap_key, XDP_DROP);
	if (redirect_ret != XDP_REDIRECT) {
		meta.action = ACTION_DROP;
		meta.reason = REASON_REDIRECT_ERROR;
		count_packet(&meta);
		maybe_sample(&meta, cfg);
		return redirect_ret;
	}

	meta.action = ACTION_REDIRECT;
	meta.reason = REASON_NONE;
	count_packet(&meta);
	maybe_sample(&meta, cfg);
	return redirect_ret;
}

char LICENSE[] SEC("license") = "GPL";
