#include <arpa/inet.h>
#include <errno.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

#include "anti_ddos/bpf_contract.h"

#ifndef XDP_PASS
#define XDP_PASS 2
#endif

#ifndef XDP_DROP
#define XDP_DROP 1
#endif

#ifndef IP_MF
#define IP_MF 0x2000
#endif

#ifndef TH_SYN
#define TH_SYN 0x02
#endif

#define MAX_PACKET_SIZE 128

struct vlan_hdr_simple {
	uint16_t tci;
	uint16_t encapsulated_proto;
};

static int map_fd(struct bpf_object *obj, const char *name)
{
	int fd = bpf_object__find_map_fd_by_name(obj, name);

	if (fd < 0)
		fprintf(stderr, "missing map %s\n", name);
	return fd;
}

static int update_map(int fd, const void *key, const void *value, const char *name)
{
	if (fd < 0 || bpf_map_update_elem(fd, key, value, BPF_ANY) != 0) {
		fprintf(stderr, "update %s: %s\n", name, strerror(errno));
		return -1;
	}
	return 0;
}

static size_t eth_header_len(int vlan_tags)
{
	return sizeof(struct ethhdr) + (size_t)vlan_tags * sizeof(struct vlan_hdr_simple);
}

static void build_eth(uint8_t *packet, int vlan_tags)
{
	struct ethhdr *eth = (struct ethhdr *)packet;
	struct vlan_hdr_simple *vlan;

	memset(packet, 0, MAX_PACKET_SIZE);
	memset(eth->h_dest, 0x02, ETH_ALEN);
	memset(eth->h_source, 0x01, ETH_ALEN);
	if (vlan_tags == 0) {
		eth->h_proto = htons(ETH_P_IP);
		return;
	}

	eth->h_proto = htons(vlan_tags == 2 ? ETH_P_8021AD : ETH_P_8021Q);
	vlan = (struct vlan_hdr_simple *)(packet + sizeof(*eth));
	vlan[0].tci = htons(10);
	vlan[0].encapsulated_proto = htons(vlan_tags == 2 ? ETH_P_8021Q : ETH_P_IP);
	if (vlan_tags == 2) {
		vlan[1].tci = htons(20);
		vlan[1].encapsulated_proto = htons(ETH_P_IP);
	}
}

static size_t build_udp_packet(uint8_t *packet, int vlan_tags, uint32_t src_v4,
			       uint32_t dst_v4, uint16_t src_port, uint16_t dst_port,
			       uint16_t tot_len_override, uint16_t udp_len_override,
			       uint16_t frag_off)
{
	size_t eth_len = eth_header_len(vlan_tags);
	struct iphdr *ip;
	struct udphdr *udp;
	uint16_t tot_len = sizeof(*ip) + sizeof(*udp);

	build_eth(packet, vlan_tags);
	ip = (struct iphdr *)(packet + eth_len);
	udp = (struct udphdr *)((uint8_t *)ip + sizeof(*ip));

	ip->version = 4;
	ip->ihl = 5;
	ip->ttl = 64;
	ip->protocol = IPPROTO_UDP;
	ip->saddr = src_v4;
	ip->daddr = dst_v4;
	ip->frag_off = htons(frag_off);
	ip->tot_len = htons(tot_len_override != 0 ? tot_len_override : tot_len);

	udp->source = htons(src_port);
	udp->dest = htons(dst_port);
	udp->len = htons(udp_len_override != 0 ? udp_len_override : sizeof(*udp));

	return eth_len + sizeof(*ip) + sizeof(*udp);
}

static size_t build_tcp_packet(uint8_t *packet, int vlan_tags, uint32_t src_v4,
			       uint32_t dst_v4, uint16_t src_port, uint16_t dst_port,
			       uint8_t doff, uint8_t flags)
{
	size_t eth_len = eth_header_len(vlan_tags);
	struct iphdr *ip;
	struct tcphdr *tcp;

	build_eth(packet, vlan_tags);
	ip = (struct iphdr *)(packet + eth_len);
	tcp = (struct tcphdr *)((uint8_t *)ip + sizeof(*ip));

	ip->version = 4;
	ip->ihl = 5;
	ip->ttl = 64;
	ip->protocol = IPPROTO_TCP;
	ip->saddr = src_v4;
	ip->daddr = dst_v4;
	ip->tot_len = htons(sizeof(*ip) + sizeof(*tcp));

	tcp->source = htons(src_port);
	tcp->dest = htons(dst_port);
	*((uint8_t *)tcp + 12) = doff << 4;
	*((uint8_t *)tcp + 13) = flags;

	return eth_len + sizeof(*ip) + sizeof(*tcp);
}

static size_t build_arp_packet(uint8_t *packet)
{
	struct ethhdr *eth = (struct ethhdr *)packet;

	memset(packet, 0, MAX_PACKET_SIZE);
	memset(eth->h_dest, 0x02, ETH_ALEN);
	memset(eth->h_source, 0x01, ETH_ALEN);
	eth->h_proto = htons(ETH_P_ARP);
	return sizeof(*eth);
}

static int run_raw_packet(int prog_fd, const uint8_t *packet, size_t packet_len,
			  uint32_t want_retval, const char *name)
{
	uint8_t out[MAX_PACKET_SIZE];
	struct bpf_test_run_opts opts = {
		.sz = sizeof(opts),
		.data_in = (void *)packet,
		.data_size_in = (uint32_t)packet_len,
		.data_out = out,
		.data_size_out = sizeof(out),
		.repeat = 1,
	};
	int err = bpf_prog_test_run_opts(prog_fd, &opts);

	if (err != 0) {
		fprintf(stderr, "%s: bpf_prog_test_run_opts: %s\n", name, strerror(errno));
		return -1;
	}
	if (opts.retval != want_retval) {
		fprintf(stderr, "%s: XDP retval %u, want %u\n", name, opts.retval, want_retval);
		return -1;
	}
	return 0;
}

static uint64_t counter_packets(int counter_fd, struct counter_key key)
{
	int cpus = libbpf_num_possible_cpus();
	struct counter_value *values;
	uint64_t packets = 0;
	int i;

	if (cpus <= 0) {
		fprintf(stderr, "libbpf_num_possible_cpus failed\n");
		return 0;
	}
	values = calloc((size_t)cpus, sizeof(*values));
	if (!values) {
		fprintf(stderr, "calloc counters failed\n");
		return 0;
	}
	if (bpf_map_lookup_elem(counter_fd, &key, values) != 0) {
		free(values);
		if (errno == ENOENT)
			return 0;
		fprintf(stderr, "lookup drop_counters: %s\n", strerror(errno));
		return 0;
	}
	for (i = 0; i < cpus; i++)
		packets += values[i].packets;
	free(values);
	return packets;
}

static int expect_counter(int counter_fd, struct counter_key key, uint64_t want,
			  const char *name)
{
	uint64_t got = counter_packets(counter_fd, key);

	if (got != want) {
		fprintf(stderr, "%s packets = %llu, want %llu\n",
			name, (unsigned long long)got, (unsigned long long)want);
		return -1;
	}
	return 0;
}

static int seed_service(struct bpf_object *obj, const char *dst_v4, uint16_t dst_port,
			uint8_t proto, uint32_t service_id, uint32_t default_rule_id,
			uint32_t neighbor_status, uint32_t devmap_key)
{
	struct service_key key = {
		.dst_v4 = inet_addr(dst_v4),
		.dst_port = dst_port,
		.proto = proto,
	};
	struct service_value value = {
		.service_id = service_id,
		.forwarding_policy_id = service_id + 100,
		.action = ACTION_REDIRECT,
		.priority = 10,
		.default_rule_id = default_rule_id,
		.output_ifindex = 1,
		.devmap_key = devmap_key,
		.neighbor_status = neighbor_status,
		.dst_mac = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
		.src_mac = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
	};

	if (neighbor_status != NEIGHBOR_RESOLVED)
		value.output_ifindex = 0;

	return update_map(map_fd(obj, "service_allowlist_a"), &key, &value,
			  "service_allowlist_a");
}

static int seed_policy_maps(struct bpf_object *obj)
{
	uint32_t cfg_key = 0;
	struct runtime_config_value cfg = {
		.active_slot = 0,
		.policy_version = 1,
		.malformed_policy = ACTION_DROP,
		.sample_denom = 0,
		.updated_at_unix_ns = 1,
	};
	uint32_t udp_port_key = 123;
	struct udp_src_port_block_value udp_port_value = {
		.entry_id = 30,
		.port = 123,
	};
	struct lpm_v4_key whitelist_global_key = {
		.prefixlen = 24,
		.addr = inet_addr("198.51.100.0"),
	};
	struct cidr_policy_value whitelist_global_value = {
		.entry_id = 40,
		.priority = 10,
		.action = ACTION_PASS,
		.source_type = 1,
		.scope = POLICY_SCOPE_GLOBAL,
	};
	struct service_lpm_v4_key whitelist_service_key = {
		.prefixlen = 64,
		.service_id = 10,
		.addr = inet_addr("192.0.2.30"),
	};
	struct cidr_policy_value whitelist_service_value = {
		.entry_id = 41,
		.priority = 10,
		.action = ACTION_PASS,
		.source_type = 1,
		.scope = POLICY_SCOPE_SERVICE,
		.service_id = 10,
	};
	struct service_lpm_v4_key whitelist_other_service_key = {
		.prefixlen = 64,
		.service_id = 11,
		.addr = inet_addr("198.51.100.55"),
	};
	struct cidr_policy_value whitelist_other_service_value = {
		.entry_id = 42,
		.priority = 10,
		.action = ACTION_PASS,
		.source_type = 1,
		.scope = POLICY_SCOPE_SERVICE,
		.service_id = 11,
	};
	struct lpm_v4_key blacklist_key = {
		.prefixlen = 32,
		.addr = inet_addr("203.0.113.200"),
	};
	struct cidr_policy_value blacklist_value = {
		.entry_id = 50,
		.priority = 10,
		.action = ACTION_DROP,
		.source_type = 1,
		.scope = POLICY_SCOPE_GLOBAL,
		.rule_id = 77,
	};
	uint32_t enforce_rule_key = 1;
	struct rule_value enforce_rule = {
		.rule_id = 1,
		.priority = 10,
		.action = ACTION_RATE_LIMIT,
		.mode = 1,
		.dimension = RATE_DIM_SOURCE_SERVICE,
		.threshold_pps = 1,
		.burst_packets = 1,
	};
	uint32_t observe_rule_key = 2;
	struct rule_value observe_rule = {
		.rule_id = 2,
		.priority = 10,
		.action = ACTION_RATE_LIMIT,
		.mode = 0,
		.dimension = RATE_DIM_SOURCE_SERVICE,
		.threshold_pps = 1,
		.burst_packets = 1,
	};

	return update_map(map_fd(obj, "runtime_config"), &cfg_key, &cfg, "runtime_config") ||
	       seed_service(obj, "203.0.113.10", 443, L4_UDP, 10, 0, NEIGHBOR_UNRESOLVED, 3) ||
	       seed_service(obj, "203.0.113.20", 443, L4_TCP, 20, 1, NEIGHBOR_RESOLVED, 4) ||
	       seed_service(obj, "203.0.113.30", 443, L4_TCP, 30, 2, NEIGHBOR_RESOLVED, 5) ||
	       update_map(map_fd(obj, "udp_src_port_blocks_a"), &udp_port_key, &udp_port_value, "udp_src_port_blocks_a") ||
	       update_map(map_fd(obj, "whitelist_v4_a"), &whitelist_global_key, &whitelist_global_value, "whitelist_v4_a") ||
	       update_map(map_fd(obj, "whitelist_service_v4_a"), &whitelist_service_key, &whitelist_service_value, "whitelist_service_v4_a") ||
	       update_map(map_fd(obj, "whitelist_service_v4_a"), &whitelist_other_service_key, &whitelist_other_service_value, "whitelist_service_v4_a") ||
	       update_map(map_fd(obj, "blacklist_v4_a"), &blacklist_key, &blacklist_value, "blacklist_v4_a") ||
	       update_map(map_fd(obj, "rule_config_a"), &enforce_rule_key, &enforce_rule, "rule_config_a") ||
	       update_map(map_fd(obj, "rule_config_a"), &observe_rule_key, &observe_rule, "rule_config_a");
}

static int run_fixtures(int prog_fd)
{
	uint8_t packet[MAX_PACKET_SIZE];
	size_t len;

	len = build_arp_packet(packet);
	if (run_raw_packet(prog_fd, packet, len, XDP_PASS, "non-ip pass") != 0)
		return -1;

	len = build_udp_packet(packet, 2, inet_addr("203.0.113.60"), inet_addr("203.0.113.10"),
			       1900, 443, 0, 0, 0);
	if (run_raw_packet(prog_fd, packet, len, XDP_DROP, "double-vlan ipv4 udp") != 0)
		return -1;

	len = build_udp_packet(packet, 0, inet_addr("203.0.113.61"), inet_addr("203.0.113.10"),
			       1900, 443, sizeof(struct iphdr), 0, 0);
	if (run_raw_packet(prog_fd, packet, len, XDP_DROP, "malformed tot_len") != 0)
		return -1;

	len = build_udp_packet(packet, 0, inet_addr("203.0.113.62"), inet_addr("203.0.113.10"),
			       1900, 443, 0, sizeof(struct udphdr) - 1, 0);
	if (run_raw_packet(prog_fd, packet, len, XDP_DROP, "malformed udp len") != 0)
		return -1;

	len = build_tcp_packet(packet, 0, inet_addr("203.0.113.63"), inet_addr("203.0.113.20"),
			       40000, 443, 4, TH_SYN);
	if (run_raw_packet(prog_fd, packet, len, XDP_DROP, "malformed tcp doff") != 0)
		return -1;

	len = build_udp_packet(packet, 0, inet_addr("203.0.113.64"), inet_addr("203.0.113.10"),
			       1900, 443, 0, 0, IP_MF);
	if (run_raw_packet(prog_fd, packet, len, XDP_DROP, "fragment") != 0)
		return -1;

	len = build_udp_packet(packet, 0, inet_addr("203.0.113.200"), inet_addr("203.0.113.10"),
			       1900, 443, 0, 0, 0);
	if (run_raw_packet(prog_fd, packet, len, XDP_DROP, "blacklist") != 0)
		return -1;

	len = build_udp_packet(packet, 0, inet_addr("203.0.113.50"), inet_addr("203.0.113.10"),
			       123, 443, 0, 0, 0);
	if (run_raw_packet(prog_fd, packet, len, XDP_DROP, "udp source port block") != 0)
		return -1;

	len = build_udp_packet(packet, 0, inet_addr("203.0.113.70"), inet_addr("203.0.113.10"),
			       1900, 443, 0, 0, 0);
	if (run_raw_packet(prog_fd, packet, len, XDP_DROP, "neighbor unresolved") != 0)
		return -1;

	len = build_udp_packet(packet, 0, inet_addr("198.51.100.20"), inet_addr("203.0.113.10"),
			       123, 443, 0, 0, 0);
	if (run_raw_packet(prog_fd, packet, len, XDP_DROP, "global whitelist bypasses udp block") != 0)
		return -1;

	len = build_udp_packet(packet, 0, inet_addr("192.0.2.30"), inet_addr("203.0.113.10"),
			       123, 443, 0, 0, 0);
	if (run_raw_packet(prog_fd, packet, len, XDP_DROP, "service whitelist bypasses udp block") != 0)
		return -1;

	len = build_udp_packet(packet, 0, inet_addr("198.51.100.55"), inet_addr("203.0.113.10"),
			       123, 443, 0, 0, 0);
	if (run_raw_packet(prog_fd, packet, len, XDP_DROP, "service whitelist does not mask global") != 0)
		return -1;

	len = build_tcp_packet(packet, 0, inet_addr("203.0.113.80"), inet_addr("203.0.113.20"),
			       40000, 443, 5, TH_SYN);
	if (run_raw_packet(prog_fd, packet, len, XDP_DROP, "rate enforce first packet") != 0 ||
	    run_raw_packet(prog_fd, packet, len, XDP_DROP, "rate enforce second packet") != 0)
		return -1;

	len = build_tcp_packet(packet, 0, inet_addr("203.0.113.90"), inet_addr("203.0.113.30"),
			       40000, 443, 5, TH_SYN);
	if (run_raw_packet(prog_fd, packet, len, XDP_DROP, "rate observe first packet") != 0 ||
	    run_raw_packet(prog_fd, packet, len, XDP_DROP, "rate observe second packet") != 0)
		return -1;

	return 0;
}

static int verify_counters(int counter_fd)
{
	struct counter_key malformed_udp_key = {
		.reason = REASON_MALFORMED,
		.proto = L4_UDP,
		.action = ACTION_DROP,
	};
	struct counter_key malformed_tcp_key = {
		.reason = REASON_MALFORMED,
		.proto = L4_TCP,
		.action = ACTION_DROP,
	};
	struct counter_key fragment_key = {
		.reason = REASON_FRAGMENT,
		.proto = L4_UDP,
		.action = ACTION_DROP,
	};
	struct counter_key blacklist_key = {
		.reason = REASON_BLACKLIST,
		.rule_id = 77,
		.service_id = 10,
		.proto = L4_UDP,
		.action = ACTION_DROP,
	};
	struct counter_key udp_block_key = {
		.reason = REASON_UDP_AMP_SOURCE_PORT,
		.service_id = 10,
		.proto = L4_UDP,
		.action = ACTION_DROP,
	};
	struct counter_key neighbor_key = {
		.reason = REASON_NEIGHBOR_UNRESOLVED,
		.service_id = 10,
		.proto = L4_UDP,
		.action = ACTION_DROP,
	};
	struct counter_key enforce_rate_key = {
		.reason = REASON_RATE_LIMIT,
		.rule_id = 1,
		.service_id = 20,
		.proto = L4_TCP,
		.action = ACTION_DROP,
		.tcp_syn = 1,
	};
	struct counter_key observe_rate_key = {
		.reason = REASON_RATE_LIMIT,
		.rule_id = 2,
		.service_id = 30,
		.proto = L4_TCP,
		.action = ACTION_OBSERVE,
		.tcp_syn = 1,
	};
	struct counter_key enforce_redirect_key = {
		.reason = REASON_REDIRECT_ERROR,
		.rule_id = 1,
		.service_id = 20,
		.proto = L4_TCP,
		.action = ACTION_DROP,
		.tcp_syn = 1,
	};
	struct counter_key observe_redirect_key = {
		.reason = REASON_REDIRECT_ERROR,
		.rule_id = 2,
		.service_id = 30,
		.proto = L4_TCP,
		.action = ACTION_DROP,
		.tcp_syn = 1,
	};

	return expect_counter(counter_fd, malformed_udp_key, 2, "malformed udp") ||
	       expect_counter(counter_fd, malformed_tcp_key, 1, "malformed tcp") ||
	       expect_counter(counter_fd, fragment_key, 1, "fragment") ||
	       expect_counter(counter_fd, blacklist_key, 1, "blacklist") ||
	       expect_counter(counter_fd, udp_block_key, 1, "udp source-port block") ||
	       expect_counter(counter_fd, neighbor_key, 5, "neighbor unresolved") ||
	       expect_counter(counter_fd, enforce_rate_key, 1, "enforce rate-limit") ||
	       expect_counter(counter_fd, observe_rate_key, 1, "observe rate-limit") ||
	       expect_counter(counter_fd, enforce_redirect_key, 1, "enforce redirect fallback") ||
	       expect_counter(counter_fd, observe_redirect_key, 2, "observe redirect fallback");
}

int main(int argc, char **argv)
{
	const char *object_path;
	struct rlimit rlim = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};
	struct bpf_object *obj;
	struct bpf_program *prog;
	int prog_fd;
	int counter_fd;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <xdp_data_plane.bpf.o>\n", argv[0]);
		return 2;
	}
	object_path = argv[1];
	if (setrlimit(RLIMIT_MEMLOCK, &rlim) != 0)
		fprintf(stderr, "warning: setrlimit memlock failed: %s\n", strerror(errno));

	obj = bpf_object__open_file(object_path, NULL);
	if (!obj) {
		fprintf(stderr, "open BPF object %s failed\n", object_path);
		return 1;
	}
	if (bpf_object__load(obj) != 0) {
		fprintf(stderr, "load BPF object %s failed: %s\n", object_path, strerror(errno));
		bpf_object__close(obj);
		return 1;
	}
	prog = bpf_object__find_program_by_name(obj, "xdp_entry");
	if (!prog) {
		fprintf(stderr, "missing xdp_entry program\n");
		bpf_object__close(obj);
		return 1;
	}
	prog_fd = bpf_program__fd(prog);
	counter_fd = map_fd(obj, "drop_counters");
	if (counter_fd < 0 || seed_policy_maps(obj) != 0) {
		bpf_object__close(obj);
		return 1;
	}

	if (run_fixtures(prog_fd) != 0 || verify_counters(counter_fd) != 0) {
		bpf_object__close(obj);
		return 1;
	}

	bpf_object__close(obj);
	return 0;
}
