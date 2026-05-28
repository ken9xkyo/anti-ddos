#ifndef ANTI_DDOS_BPF_CONTRACT_H
#define ANTI_DDOS_BPF_CONTRACT_H

#define ANTI_DDOS_MAX_RULES 4096
#define ANTI_DDOS_MAX_SERVICES 4096
#define ANTI_DDOS_MAX_EVENT_SAMPLE_DENOM 1000000

#define ANTI_DDOS_MAX_WHITELIST_V4 65536
#define ANTI_DDOS_MAX_BLACKLIST_V4 1000000
#define ANTI_DDOS_MAX_SERVICE_ALLOWLIST 16384
#define ANTI_DDOS_MAX_TX_DEVMAP 128
#define ANTI_DDOS_MAX_RATE_STATE 2000000
#define ANTI_DDOS_MAX_DROP_COUNTERS 262144
#define ANTI_DDOS_EVENTS_BYTES (64 * 1024 * 1024)
#define ANTI_DDOS_MAX_PROG_ARRAY 16

enum anti_ddos_l4_proto {
	L4_UNKNOWN = 0,
	L4_ICMP = 1,
	L4_TCP = 6,
	L4_UDP = 17,
};

enum anti_ddos_packet_action {
	ACTION_PASS = 0,
	ACTION_DROP = 1,
	ACTION_RATE_LIMIT = 2,
	ACTION_OBSERVE = 3,
	ACTION_SAMPLE = 4,
	ACTION_NOT_FORWARD = 5,
	ACTION_REDIRECT = 6,
};

enum anti_ddos_drop_reason {
	REASON_NONE = 0,
	REASON_MALFORMED = 1,
	REASON_BOGON = 2,
	REASON_BLACKLIST = 3,
	REASON_NOT_ALLOWED_SERVICE = 4,
	REASON_RATE_LIMIT = 5,
	REASON_RULE_DROP = 6,
	REASON_MAP_ERROR = 7,
	REASON_REDIRECT_ERROR = 8,
	REASON_NEIGHBOR_UNRESOLVED = 9,
	REASON_FRAGMENT = 10,
};

enum anti_ddos_policy_scope {
	POLICY_SCOPE_GLOBAL = 0,
	POLICY_SCOPE_SERVICE = 1,
};

enum anti_ddos_neighbor_status {
	NEIGHBOR_UNRESOLVED = 0,
	NEIGHBOR_RESOLVED = 1,
};

enum anti_ddos_rate_dimension {
	RATE_DIM_SOURCE = 0,
	RATE_DIM_SUBNET = 1,
	RATE_DIM_SERVICE = 2,
	RATE_DIM_SOURCE_SERVICE = 3,
};

struct packet_meta {
	__u32 src_v4;
	__u32 dst_v4;
	__u16 src_port;
	__u16 dst_port;
	__u8 proto;
	__u8 tcp_flags;
	__u16 pkt_len;
	__u32 service_id;
	__u32 rule_id;
	__u8 is_fragment;
	__u8 is_malformed;
	__u8 action;
	__u8 reason;
};

struct runtime_config_value {
	__u32 active_slot;
	__u32 policy_version;
	__u32 malformed_policy;
	__u32 sample_denom;
	__u64 updated_at_unix_ns;
};

struct lpm_v4_key {
	__u32 prefixlen;
	__u32 addr;
};

struct cidr_policy_value {
	__u32 entry_id;
	__u32 priority;
	__u32 action;
	__u32 source_type;
	__u32 scope;
	__u32 service_id;
	__u32 score;
	__u32 rule_id;
	__u64 expires_at_unix_ns;
};

struct service_key {
	__u32 dst_v4;
	__u16 dst_port;
	__u8 proto;
	__u8 pad;
};

struct service_value {
	__u32 service_id;
	__u32 forwarding_policy_id;
	__u32 action;
	__u32 priority;
	__u32 default_rule_id;
	__u32 output_ifindex;
	__u32 devmap_key;
	__u32 neighbor_status;
	__u8 dst_mac[6];
	__u8 src_mac[6];
	__u16 pad;
};

struct rule_value {
	__u32 rule_id;
	__u32 priority;
	__u32 action;
	__u32 mode;
	__u32 service_id;
	__u32 dimension;
	__u32 threshold_pps;
	__u32 threshold_bps;
	__u32 threshold_cps;
	__u32 burst_packets;
	__u32 burst_bytes;
	__u32 sample_denom;
	__u32 pad;
	__u32 tail_pad;
	__u64 expires_at_unix_ns;
};

struct rate_key {
	__u32 src_v4;
	__u32 service_id;
	__u32 rule_id;
	__u8 proto;
	__u8 dimension;
	__u16 pad;
};

struct rate_value {
	__u64 last_refill_ns;
	__u64 tokens_packets;
	__u64 tokens_bytes;
	__u64 tokens_syn;
	__u64 packet_remainder_ns;
	__u64 byte_remainder_ns;
	__u64 syn_remainder_ns;
	__u64 syn_seen;
	__u64 packets_seen;
	__u64 bytes_seen;
};

struct counter_key {
	__u32 reason;
	__u32 rule_id;
	__u32 service_id;
	__u8 proto;
	__u8 action;
	__u8 tcp_syn;
	__u8 pad;
};

struct counter_value {
	__u64 packets;
	__u64 bytes;
};

struct event_record {
	__u64 ts_mono_ns;
	__u32 policy_version;
	__u32 src_v4;
	__u32 dst_v4;
	__u16 src_port;
	__u16 dst_port;
	__u8 proto;
	__u8 tcp_flags;
	__u8 action;
	__u8 reason;
	__u32 service_id;
	__u32 rule_id;
	__u32 pkt_len;
};

#endif
