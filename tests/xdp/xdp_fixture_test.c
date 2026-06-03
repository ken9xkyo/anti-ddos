#include <arpa/inet.h>
#include <errno.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

#include "anti_ddos/bpf_contract.h"

#ifndef XDP_DROP
#define XDP_DROP 1
#endif

static int map_fd(struct bpf_object *obj, const char *name)
{
	int fd = bpf_object__find_map_fd_by_name(obj, name);

	if (fd < 0)
		fprintf(stderr, "missing map %s\n", name);
	return fd;
}

static int update_map(int fd, const void *key, const void *value, const char *name)
{
	if (bpf_map_update_elem(fd, key, value, BPF_ANY) != 0) {
		fprintf(stderr, "update %s: %s\n", name, strerror(errno));
		return -1;
	}
	return 0;
}

static uint16_t packet_len(void)
{
	return sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
}

static void build_udp_packet(uint8_t *packet, uint32_t src_v4, uint32_t dst_v4,
			     uint16_t src_port, uint16_t dst_port)
{
	struct ethhdr *eth = (struct ethhdr *)packet;
	struct iphdr *ip = (struct iphdr *)(packet + sizeof(*eth));
	struct udphdr *udp = (struct udphdr *)((uint8_t *)ip + sizeof(*ip));

	memset(packet, 0, packet_len());
	memset(eth->h_dest, 0x02, ETH_ALEN);
	memset(eth->h_source, 0x01, ETH_ALEN);
	eth->h_proto = htons(ETH_P_IP);

	ip->version = 4;
	ip->ihl = 5;
	ip->ttl = 64;
	ip->protocol = IPPROTO_UDP;
	ip->saddr = src_v4;
	ip->daddr = dst_v4;
	ip->tot_len = htons(sizeof(*ip) + sizeof(*udp));

	udp->source = htons(src_port);
	udp->dest = htons(dst_port);
	udp->len = htons(sizeof(*udp));
}

static int run_packet(int prog_fd, uint32_t src_v4, uint16_t src_port)
{
	uint8_t packet[sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr)];
	uint8_t out[sizeof(packet)];
	struct bpf_test_run_opts opts = {
		.sz = sizeof(opts),
		.data_in = packet,
		.data_size_in = sizeof(packet),
		.data_out = out,
		.data_size_out = sizeof(out),
		.repeat = 1,
	};
	int err;

	build_udp_packet(packet, src_v4, inet_addr("203.0.113.10"), src_port, 443);
	err = bpf_prog_test_run_opts(prog_fd, &opts);
	if (err != 0) {
		fprintf(stderr, "bpf_prog_test_run_opts: %s\n", strerror(errno));
		return -1;
	}
	if (opts.retval != XDP_DROP) {
		fprintf(stderr, "unexpected XDP retval %u, want XDP_DROP\n", opts.retval);
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
	struct service_key service_key = {
		.dst_v4 = inet_addr("203.0.113.10"),
		.dst_port = 443,
		.proto = L4_UDP,
	};
	struct service_value service_value = {
		.service_id = 10,
		.forwarding_policy_id = 20,
		.action = ACTION_REDIRECT,
		.priority = 10,
		.output_ifindex = 0,
		.devmap_key = 3,
		.neighbor_status = NEIGHBOR_UNRESOLVED,
	};
	uint32_t udp_port_key = 123;
	struct udp_src_port_block_value udp_port_value = {
		.entry_id = 30,
		.port = 123,
	};
	struct lpm_v4_key whitelist_key = {
		.prefixlen = 32,
		.addr = inet_addr("198.51.100.10"),
	};
	struct cidr_policy_value whitelist_value = {
		.entry_id = 40,
		.priority = 10,
		.action = ACTION_PASS,
		.source_type = 1,
		.scope = POLICY_SCOPE_GLOBAL,
	};

	return update_map(map_fd(obj, "runtime_config"), &cfg_key, &cfg, "runtime_config") ||
	       update_map(map_fd(obj, "service_allowlist_a"), &service_key, &service_value, "service_allowlist_a") ||
	       update_map(map_fd(obj, "udp_src_port_blocks_a"), &udp_port_key, &udp_port_value, "udp_src_port_blocks_a") ||
	       update_map(map_fd(obj, "whitelist_v4_a"), &whitelist_key, &whitelist_value, "whitelist_v4_a");
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
	uint64_t udp_block_packets;
	uint64_t neighbor_packets;

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

	if (run_packet(prog_fd, inet_addr("198.51.100.20"), 123) != 0 ||
	    run_packet(prog_fd, inet_addr("198.51.100.20"), 1900) != 0 ||
	    run_packet(prog_fd, inet_addr("198.51.100.10"), 123) != 0) {
		bpf_object__close(obj);
		return 1;
	}

	udp_block_packets = counter_packets(counter_fd, udp_block_key);
	neighbor_packets = counter_packets(counter_fd, neighbor_key);
	if (udp_block_packets != 1) {
		fprintf(stderr, "UDP source-port block packets = %llu, want 1\n",
			(unsigned long long)udp_block_packets);
		bpf_object__close(obj);
		return 1;
	}
	if (neighbor_packets != 2) {
		fprintf(stderr, "neighbor-unresolved packets = %llu, want 2\n",
			(unsigned long long)neighbor_packets);
		bpf_object__close(obj);
		return 1;
	}

	bpf_object__close(obj);
	return 0;
}
