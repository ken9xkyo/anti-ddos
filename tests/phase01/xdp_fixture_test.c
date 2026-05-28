#include <arpa/inet.h>
#include <errno.h>
#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "anti_ddos/bpf_contract.h"

#define TEST_LOG_PATH "build/bpf/verifier.log"
#define VERIFIER_LOG_SIZE (1024 * 1024)
#define MAX_PACKET_SIZE 256

extern unsigned int if_nametoindex(const char *ifname);

struct test_env {
	struct bpf_object *obj;
	int prog_fd;
	int runtime_config_fd;
	int whitelist_v4_a_fd;
	int blacklist_v4_a_fd;
	int service_allowlist_a_fd;
	int rule_config_a_fd;
	int tx_devmap_fd;
	int drop_counters_fd;
	int nr_cpus;
	size_t counter_stride;
};

struct packet_fixture {
	uint8_t data[MAX_PACKET_SIZE];
	uint32_t len;
};

struct expected_map {
	const char *name;
	enum bpf_map_type type;
	uint32_t max_entries;
};

static const struct expected_map expected_maps[] = {
	{"whitelist_v4_a", BPF_MAP_TYPE_LPM_TRIE, ANTI_DDOS_MAX_WHITELIST_V4},
	{"whitelist_v4_b", BPF_MAP_TYPE_LPM_TRIE, ANTI_DDOS_MAX_WHITELIST_V4},
	{"blacklist_v4_a", BPF_MAP_TYPE_LPM_TRIE, ANTI_DDOS_MAX_BLACKLIST_V4},
	{"blacklist_v4_b", BPF_MAP_TYPE_LPM_TRIE, ANTI_DDOS_MAX_BLACKLIST_V4},
	{"service_allowlist_a", BPF_MAP_TYPE_HASH, ANTI_DDOS_MAX_SERVICE_ALLOWLIST},
	{"service_allowlist_b", BPF_MAP_TYPE_HASH, ANTI_DDOS_MAX_SERVICE_ALLOWLIST},
	{"tx_devmap", BPF_MAP_TYPE_DEVMAP, ANTI_DDOS_MAX_TX_DEVMAP},
	{"rate_state", BPF_MAP_TYPE_LRU_HASH, ANTI_DDOS_MAX_RATE_STATE},
	{"rule_config_a", BPF_MAP_TYPE_ARRAY, ANTI_DDOS_MAX_RULES},
	{"rule_config_b", BPF_MAP_TYPE_ARRAY, ANTI_DDOS_MAX_RULES},
	{"drop_counters", BPF_MAP_TYPE_PERCPU_HASH, ANTI_DDOS_MAX_DROP_COUNTERS},
	{"events", BPF_MAP_TYPE_RINGBUF, ANTI_DDOS_EVENTS_BYTES},
	{"runtime_config", BPF_MAP_TYPE_ARRAY, 1},
	{"prog_array", BPF_MAP_TYPE_PROG_ARRAY, ANTI_DDOS_MAX_PROG_ARRAY},
};

static size_t roundup8(size_t value)
{
	return (value + 7U) & ~7U;
}

static void write_verifier_log(const char *log_buf)
{
	FILE *fp = fopen(TEST_LOG_PATH, "w");

	if (!fp)
		return;

	if (log_buf && log_buf[0] != '\0')
		fputs(log_buf, fp);
	else
		fputs("verifier log was empty on successful load\n", fp);

	fclose(fp);
}

static int map_fd_by_name(struct bpf_object *obj, const char *name)
{
	struct bpf_map *map = bpf_object__find_map_by_name(obj, name);

	if (!map) {
		fprintf(stderr, "missing BPF map: %s\n", name);
		return -1;
	}

	return bpf_map__fd(map);
}

static int validate_map_contracts(struct bpf_object *obj)
{
	size_t map_count = sizeof(expected_maps) / sizeof(expected_maps[0]);

	for (size_t i = 0; i < map_count; i++) {
		const struct expected_map *expected = &expected_maps[i];
		struct bpf_map *map = bpf_object__find_map_by_name(obj, expected->name);

		if (!map) {
			fprintf(stderr, "missing expected map: %s\n", expected->name);
			return -1;
		}

		if (bpf_map__type(map) != expected->type) {
			fprintf(stderr, "%s: expected map type %u, got %u\n",
				expected->name, expected->type, bpf_map__type(map));
			return -1;
		}

		if (bpf_map__max_entries(map) != expected->max_entries) {
			fprintf(stderr, "%s: expected max_entries %u, got %u\n",
				expected->name, expected->max_entries,
				bpf_map__max_entries(map));
			return -1;
		}
	}

	printf("PASS map contracts\n");
	return 0;
}

static int open_env(const char *obj_path, struct test_env *env)
{
	static char verifier_log[VERIFIER_LOG_SIZE];
	struct bpf_object_open_opts opts = {
		.sz = sizeof(opts),
		.kernel_log_buf = verifier_log,
		.kernel_log_size = sizeof(verifier_log),
		.kernel_log_level = 1,
	};
	struct bpf_program *prog;
	int err;

	memset(env, 0, sizeof(*env));
	env->prog_fd = -1;
	env->runtime_config_fd = -1;
	env->whitelist_v4_a_fd = -1;
	env->blacklist_v4_a_fd = -1;
	env->service_allowlist_a_fd = -1;
	env->rule_config_a_fd = -1;
	env->tx_devmap_fd = -1;
	env->drop_counters_fd = -1;
	env->nr_cpus = libbpf_num_possible_cpus();
	env->counter_stride = roundup8(sizeof(struct counter_value));

	if (env->nr_cpus <= 0) {
		fprintf(stderr, "libbpf_num_possible_cpus failed\n");
		return -1;
	}

	env->obj = bpf_object__open_file(obj_path, &opts);
	err = libbpf_get_error(env->obj);
	if (err) {
		env->obj = NULL;
		fprintf(stderr, "failed to open BPF object: %s\n", strerror(-err));
		return -1;
	}

	err = bpf_object__load(env->obj);
	write_verifier_log(verifier_log);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %s\n", strerror(-err));
		return -1;
	}

	if (validate_map_contracts(env->obj) != 0)
		return -1;

	prog = bpf_object__find_program_by_name(env->obj, "xdp_entry");
	if (!prog) {
		fprintf(stderr, "missing xdp_entry program\n");
		return -1;
	}
	env->prog_fd = bpf_program__fd(prog);
	env->runtime_config_fd = map_fd_by_name(env->obj, "runtime_config");
	env->whitelist_v4_a_fd = map_fd_by_name(env->obj, "whitelist_v4_a");
	env->blacklist_v4_a_fd = map_fd_by_name(env->obj, "blacklist_v4_a");
	env->service_allowlist_a_fd = map_fd_by_name(env->obj, "service_allowlist_a");
	env->rule_config_a_fd = map_fd_by_name(env->obj, "rule_config_a");
	env->tx_devmap_fd = map_fd_by_name(env->obj, "tx_devmap");
	env->drop_counters_fd = map_fd_by_name(env->obj, "drop_counters");

	if (env->prog_fd < 0 || env->runtime_config_fd < 0 ||
	    env->whitelist_v4_a_fd < 0 || env->blacklist_v4_a_fd < 0 ||
	    env->service_allowlist_a_fd < 0 || env->rule_config_a_fd < 0 ||
	    env->tx_devmap_fd < 0 ||
	    env->drop_counters_fd < 0)
		return -1;

	return 0;
}

static void close_env(struct test_env *env)
{
	if (env->obj)
		bpf_object__close(env->obj);
}

static int seed_runtime_config(struct test_env *env)
{
	uint32_t key = 0;
	struct runtime_config_value cfg = {
		.active_slot = 0,
		.policy_version = 1,
		.malformed_policy = ACTION_DROP,
		.sample_denom = 0,
		.updated_at_unix_ns = 1,
	};

	if (bpf_map_update_elem(env->runtime_config_fd, &key, &cfg, BPF_ANY) != 0) {
		fprintf(stderr, "failed to seed runtime_config: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int upsert_cidr_policy(int map_fd, const char *ip, uint32_t entry_id,
			      uint32_t action, uint32_t scope, uint32_t rule_id)
{
	struct lpm_v4_key key = {
		.prefixlen = 32,
		.addr = inet_addr(ip),
	};
	struct cidr_policy_value value = {
		.entry_id = entry_id,
		.priority = 100,
		.action = action,
		.scope = scope,
		.rule_id = rule_id,
	};

	if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
		fprintf(stderr, "failed to update cidr policy %s: %s\n", ip,
			strerror(errno));
		return -1;
	}

	return 0;
}

static int upsert_service_with_rule(int map_fd, const char *dst_ip, uint8_t proto,
				    uint16_t dst_port, uint32_t service_id,
				    uint32_t action, uint32_t devmap_key,
				    uint32_t neighbor_status,
				    uint32_t default_rule_id)
{
	const uint8_t dst_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
	const uint8_t src_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
	struct service_key key = {
		.dst_v4 = inet_addr(dst_ip),
		.dst_port = dst_port,
		.proto = proto,
	};
	struct service_value value = {
		.service_id = service_id,
		.forwarding_policy_id = service_id + 100,
		.action = action,
		.priority = 100,
		.default_rule_id = default_rule_id,
		.output_ifindex = 1,
		.devmap_key = devmap_key,
		.neighbor_status = neighbor_status,
	};

	memcpy(value.dst_mac, dst_mac, sizeof(value.dst_mac));
	memcpy(value.src_mac, src_mac, sizeof(value.src_mac));

	if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
		fprintf(stderr, "failed to update service %u: %s\n", service_id,
			strerror(errno));
		return -1;
	}

	return 0;
}

static int upsert_service(int map_fd, const char *dst_ip, uint8_t proto,
			  uint16_t dst_port, uint32_t service_id,
			  uint32_t action, uint32_t devmap_key,
			  uint32_t neighbor_status)
{
	return upsert_service_with_rule(map_fd, dst_ip, proto, dst_port, service_id,
					action, devmap_key, neighbor_status, 0);
}

static int upsert_rule(int map_fd, uint32_t rule_id, uint32_t action, uint32_t mode,
		       uint32_t service_id, uint32_t dimension, uint32_t threshold_pps,
		       uint32_t threshold_bps, uint32_t threshold_cps,
		       uint32_t burst_packets, uint32_t burst_bytes)
{
	struct rule_value value = {
		.rule_id = rule_id,
		.priority = 10,
		.action = action,
		.mode = mode,
		.service_id = service_id,
		.dimension = dimension,
		.threshold_pps = threshold_pps,
		.threshold_bps = threshold_bps,
		.threshold_cps = threshold_cps,
		.burst_packets = burst_packets,
		.burst_bytes = burst_bytes,
	};

	if (bpf_map_update_elem(map_fd, &rule_id, &value, BPF_ANY) != 0) {
		fprintf(stderr, "failed to update rule %u: %s\n", rule_id,
			strerror(errno));
		return -1;
	}

	return 0;
}

static int upsert_devmap_target(int map_fd, uint32_t devmap_key)
{
	uint32_t output_ifindex = if_nametoindex("lo");

	if (output_ifindex == 0) {
		fprintf(stderr, "failed to resolve loopback ifindex: %s\n",
			strerror(errno));
		return -1;
	}

	if (bpf_map_update_elem(map_fd, &devmap_key, &output_ifindex, BPF_ANY) != 0) {
		fprintf(stderr, "failed to update tx_devmap key %u: %s\n",
			devmap_key, strerror(errno));
		return -1;
	}

	return 0;
}

static uint64_t read_counter(struct test_env *env, const struct counter_key *key)
{
	uint64_t packets = 0;
	uint8_t *values = calloc((size_t)env->nr_cpus, env->counter_stride);

	if (!values) {
		fprintf(stderr, "calloc failed while reading counters\n");
		exit(1);
	}

	if (bpf_map_lookup_elem(env->drop_counters_fd, key, values) != 0) {
		free(values);
		return 0;
	}

	for (int i = 0; i < env->nr_cpus; i++) {
		struct counter_value *value;

		value = (struct counter_value *)(values + ((size_t)i * env->counter_stride));
		packets += value->packets;
	}

	free(values);
	return packets;
}

static uint64_t read_counter_by_reason_action(struct test_env *env, uint32_t reason,
					      uint8_t action)
{
	struct counter_key prev_key = {};
	struct counter_key next_key = {};
	const struct counter_key *lookup_key = NULL;
	uint64_t packets = 0;

	while (bpf_map_get_next_key(env->drop_counters_fd, lookup_key, &next_key) == 0) {
		if (next_key.reason == reason && next_key.action == action)
			packets += read_counter(env, &next_key);

		prev_key = next_key;
		lookup_key = &prev_key;
	}

	return packets;
}

static void dump_counters(struct test_env *env)
{
	struct counter_key prev_key = {};
	struct counter_key next_key = {};
	const struct counter_key *lookup_key = NULL;

	fprintf(stderr, "current counters:\n");
	while (bpf_map_get_next_key(env->drop_counters_fd, lookup_key, &next_key) == 0) {
		uint64_t packets = read_counter(env, &next_key);

		fprintf(stderr,
			"  reason=%u action=%u proto=%u rule=%u service=%u packets=%llu\n",
			next_key.reason, next_key.action, next_key.proto, next_key.rule_id,
			next_key.service_id, (unsigned long long)packets);
		prev_key = next_key;
		lookup_key = &prev_key;
	}
}

static int run_packet_capture(struct test_env *env, const struct packet_fixture *fixture,
			      uint32_t *retval, struct packet_fixture *out_fixture)
{
	uint8_t out[MAX_PACKET_SIZE] = {};
	struct bpf_test_run_opts opts = {
		.sz = sizeof(opts),
		.data_in = fixture->data,
		.data_out = out,
		.data_size_in = fixture->len,
		.data_size_out = sizeof(out),
		.repeat = 1,
	};

	if (bpf_prog_test_run_opts(env->prog_fd, &opts) != 0) {
		fprintf(stderr, "BPF_PROG_TEST_RUN failed: %s\n", strerror(errno));
		return -1;
	}

	*retval = opts.retval;
	if (out_fixture) {
		memset(out_fixture, 0, sizeof(*out_fixture));
		out_fixture->len = opts.data_size_out;
		if (out_fixture->len > sizeof(out_fixture->data))
			out_fixture->len = sizeof(out_fixture->data);
		memcpy(out_fixture->data, out, out_fixture->len);
	}
	return 0;
}

static int run_packet(struct test_env *env, const struct packet_fixture *fixture,
		      uint32_t *retval)
{
	return run_packet_capture(env, fixture, retval, NULL);
}

static void init_eth(struct packet_fixture *fixture, uint16_t eth_proto)
{
	struct ethhdr *eth = (struct ethhdr *)fixture->data;

	memset(fixture, 0, sizeof(*fixture));
	memset(eth->h_dest, 0x11, sizeof(eth->h_dest));
	memset(eth->h_source, 0x22, sizeof(eth->h_source));
	eth->h_proto = htons(eth_proto);
	fixture->len = sizeof(*eth);
}

static struct iphdr *append_ipv4(struct packet_fixture *fixture, uint8_t proto,
				 uint16_t l4_len)
{
	struct iphdr *ip;

	ip = (struct iphdr *)(fixture->data + fixture->len);
	fixture->len += sizeof(*ip) + l4_len;

	ip->version = 4;
	ip->ihl = 5;
	ip->ttl = 64;
	ip->protocol = proto;
	ip->tot_len = htons((uint16_t)(sizeof(*ip) + l4_len));
	ip->saddr = inet_addr("198.51.100.10");
	ip->daddr = inet_addr("203.0.113.10");

	return ip;
}

static struct packet_fixture make_tcp_syn_port(uint16_t dst_port)
{
	struct packet_fixture fixture = {};
	struct tcphdr *tcp;

	init_eth(&fixture, ETH_P_IP);
	append_ipv4(&fixture, IPPROTO_TCP, sizeof(*tcp));
	tcp = (struct tcphdr *)(fixture.data + sizeof(struct ethhdr) + sizeof(struct iphdr));
	tcp->source = htons(12345);
	tcp->dest = htons(dst_port);
	tcp->doff = 5;
	tcp->syn = 1;

	return fixture;
}

static struct packet_fixture make_tcp_syn(void)
{
	return make_tcp_syn_port(80);
}

static struct packet_fixture make_udp_port(uint16_t dst_port)
{
	struct packet_fixture fixture = {};
	struct udphdr *udp;

	init_eth(&fixture, ETH_P_IP);
	append_ipv4(&fixture, IPPROTO_UDP, sizeof(*udp));
	udp = (struct udphdr *)(fixture.data + sizeof(struct ethhdr) + sizeof(struct iphdr));
	udp->source = htons(12345);
	udp->dest = htons(dst_port);
	udp->len = htons(sizeof(*udp));

	return fixture;
}

static struct packet_fixture make_udp(void)
{
	return make_udp_port(53);
}

static struct packet_fixture make_icmp(void)
{
	struct packet_fixture fixture = {};
	struct icmphdr *icmp;

	init_eth(&fixture, ETH_P_IP);
	append_ipv4(&fixture, IPPROTO_ICMP, sizeof(*icmp));
	icmp = (struct icmphdr *)(fixture.data + sizeof(struct ethhdr) + sizeof(struct iphdr));
	icmp->type = ICMP_ECHO;

	return fixture;
}

static struct packet_fixture make_unknown_ipv4(void)
{
	struct packet_fixture fixture = {};

	init_eth(&fixture, ETH_P_IP);
	append_ipv4(&fixture, 143, 0);

	return fixture;
}

static struct packet_fixture make_ipv4_fragment(void)
{
	struct packet_fixture fixture = {};
	uint8_t *frag_off;

	init_eth(&fixture, ETH_P_IP);
	append_ipv4(&fixture, IPPROTO_TCP, 0);
	frag_off = fixture.data + sizeof(struct ethhdr) + 6;
	frag_off[0] = 0x20;
	frag_off[1] = 0x00;

	return fixture;
}

static struct packet_fixture make_bad_ihl(void)
{
	struct packet_fixture fixture = {};
	struct iphdr *ip;

	init_eth(&fixture, ETH_P_IP);
	ip = append_ipv4(&fixture, IPPROTO_TCP, 0);
	ip->ihl = 4;

	return fixture;
}

static struct packet_fixture make_truncated_eth(void)
{
	struct packet_fixture fixture = {};

	init_eth(&fixture, ETH_P_IP);

	return fixture;
}

static struct packet_fixture make_non_ipv4(void)
{
	struct packet_fixture fixture = {};

	init_eth(&fixture, ETH_P_ARP);

	return fixture;
}

static int expect_decision(struct test_env *env, const char *name,
			   const struct packet_fixture *fixture, uint32_t expected_ret,
			   const struct counter_key *counter_key)
{
	uint64_t before = 0;
	uint64_t after = 0;
	uint32_t retval = 0;

	if (counter_key)
		before = read_counter(env, counter_key);

	if (run_packet(env, fixture, &retval) != 0)
		return -1;

	if (retval != expected_ret) {
		fprintf(stderr, "%s: expected retval %u, got %u\n", name, expected_ret,
			retval);
		return -1;
	}

	if (counter_key) {
		after = read_counter(env, counter_key);
		if (after != before + 1) {
			fprintf(stderr,
				"%s: expected counter delta 1, got before=%llu after=%llu\n",
				name, (unsigned long long)before,
				(unsigned long long)after);
			dump_counters(env);
			return -1;
		}
	}

	printf("PASS %s\n", name);
	return 0;
}

static int expect_decision_reason_action(struct test_env *env, const char *name,
					 const struct packet_fixture *fixture,
					 uint32_t expected_ret, uint32_t reason,
					 uint8_t action)
{
	uint64_t before;
	uint64_t after;
	uint32_t retval = 0;

	before = read_counter_by_reason_action(env, reason, action);

	if (run_packet(env, fixture, &retval) != 0)
		return -1;

	if (retval != expected_ret) {
		fprintf(stderr, "%s: expected retval %u, got %u\n", name, expected_ret,
			retval);
		return -1;
	}

	after = read_counter_by_reason_action(env, reason, action);
	if (after != before + 1) {
		fprintf(stderr,
			"%s: expected reason/action counter delta 1, got before=%llu after=%llu\n",
			name, (unsigned long long)before, (unsigned long long)after);
		dump_counters(env);
		return -1;
	}

	printf("PASS %s\n", name);
	return 0;
}

static int expect_rewrite(struct test_env *env, const char *name,
			  const struct packet_fixture *fixture,
			  uint32_t expected_ret,
			  const struct counter_key *counter_key)
{
	static const uint8_t expected_dst[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
	static const uint8_t expected_src[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
	struct packet_fixture out = {};
	struct ethhdr *eth = (struct ethhdr *)out.data;
	uint64_t before = 0;
	uint64_t after = 0;
	uint32_t retval = 0;

	if (counter_key)
		before = read_counter(env, counter_key);

	if (run_packet_capture(env, fixture, &retval, &out) != 0)
		return -1;

	if (retval != expected_ret) {
		fprintf(stderr, "%s: expected retval %u, got %u\n", name,
			expected_ret, retval);
		return -1;
	}
	if (out.len < sizeof(*eth)) {
		fprintf(stderr, "%s: output packet too short: %u\n", name, out.len);
		return -1;
	}
	if (memcmp(eth->h_dest, expected_dst, sizeof(expected_dst)) != 0 ||
	    memcmp(eth->h_source, expected_src, sizeof(expected_src)) != 0) {
		fprintf(stderr, "%s: ethernet MAC rewrite mismatch\n", name);
		return -1;
	}

	if (counter_key) {
		after = read_counter(env, counter_key);
		if (after != before + 1) {
			fprintf(stderr,
				"%s: expected counter delta 1, got before=%llu after=%llu\n",
				name, (unsigned long long)before,
				(unsigned long long)after);
			dump_counters(env);
			return -1;
		}
	}

	printf("PASS %s\n", name);
	return 0;
}

static struct counter_key key_for(uint32_t reason, uint8_t action, uint8_t proto)
{
	struct counter_key key = {
		.reason = reason,
		.rule_id = 0,
		.service_id = 0,
		.proto = proto,
		.action = action,
		.tcp_syn = proto == L4_TCP ? 1 : 0,
		.pad = 0,
	};

	return key;
}

static int expect_counter_delta(struct test_env *env, const char *name,
				const struct counter_key *counter_key,
				uint64_t before, uint64_t delta)
{
	uint64_t after = read_counter(env, counter_key);

	if (after != before + delta) {
		fprintf(stderr,
			"%s: expected counter delta %llu, got before=%llu after=%llu\n",
			name, (unsigned long long)delta, (unsigned long long)before,
			(unsigned long long)after);
		dump_counters(env);
		return -1;
	}

	printf("PASS %s\n", name);
	return 0;
}

int main(int argc, char **argv)
{
	struct test_env env;
	struct packet_fixture pkt;
	struct counter_key key;
	int ret = 1;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <xdp_data_plane.bpf.o>\n", argv[0]);
		return 1;
	}

	if (open_env(argv[1], &env) != 0)
		return 1;

	pkt = make_tcp_syn();
	key = key_for(REASON_MAP_ERROR, ACTION_DROP, L4_UNKNOWN);
	if (expect_decision(&env, "missing runtime config", &pkt, XDP_DROP, &key) != 0)
		goto out;

	if (seed_runtime_config(&env) != 0)
		goto out;

	pkt = make_tcp_syn();
	key = key_for(REASON_NOT_ALLOWED_SERVICE, ACTION_DROP, L4_TCP);
	if (expect_decision(&env, "service allowlist miss", &pkt, XDP_DROP, &key) != 0)
		goto out;

	if (upsert_service(env.service_allowlist_a_fd, "203.0.113.10", L4_TCP, 80,
			   10, ACTION_REDIRECT, 3, NEIGHBOR_RESOLVED) != 0)
		goto out;

	pkt = make_tcp_syn();
	key = key_for(REASON_REDIRECT_ERROR, ACTION_DROP, L4_TCP);
	key.service_id = 10;
	if (expect_rewrite(&env, "missing devmap target fails closed", &pkt,
			   XDP_DROP, &key) != 0)
		goto out;

	if (upsert_devmap_target(env.tx_devmap_fd, 3) != 0)
		goto out;

	pkt = make_tcp_syn();
	key = key_for(REASON_NONE, ACTION_REDIRECT, L4_TCP);
	key.service_id = 10;
	if (expect_rewrite(&env, "allowed tcp service redirects with mac rewrite",
			   &pkt, XDP_REDIRECT, &key) != 0)
		goto out;

	if (upsert_rule(env.rule_config_a_fd, 100, ACTION_RATE_LIMIT, 1, 14,
			RATE_DIM_SOURCE_SERVICE, 1, 0, 0, 1, 0) != 0)
		goto out;
	if (upsert_service_with_rule(env.service_allowlist_a_fd, "203.0.113.10",
				     L4_TCP, 9090, 14, ACTION_REDIRECT, 3,
				     NEIGHBOR_RESOLVED, 100) != 0)
		goto out;
	pkt = make_tcp_syn_port(9090);
	key = key_for(REASON_NONE, ACTION_REDIRECT, L4_TCP);
	key.service_id = 14;
	key.rule_id = 100;
	if (expect_rewrite(&env, "rate limit under pps redirects", &pkt,
			   XDP_REDIRECT, &key) != 0)
		goto out;
	pkt = make_tcp_syn_port(9090);
	key = key_for(REASON_RATE_LIMIT, ACTION_DROP, L4_TCP);
	key.service_id = 14;
	key.rule_id = 100;
	if (expect_decision(&env, "rate limit over pps drops", &pkt,
			    XDP_DROP, &key) != 0)
		goto out;
	sleep(1);
	pkt = make_tcp_syn_port(9090);
	key = key_for(REASON_NONE, ACTION_REDIRECT, L4_TCP);
	key.service_id = 14;
	key.rule_id = 100;
	if (expect_rewrite(&env, "rate limit refills after elapsed time", &pkt,
			   XDP_REDIRECT, &key) != 0)
		goto out;

	if (upsert_rule(env.rule_config_a_fd, 106, ACTION_RATE_LIMIT, 1, 20,
			RATE_DIM_SOURCE_SERVICE, 2, 0, 0, 1, 0) != 0)
		goto out;
	if (upsert_service_with_rule(env.service_allowlist_a_fd, "203.0.113.10",
				     L4_TCP, 9096, 20, ACTION_REDIRECT, 3,
				     NEIGHBOR_RESOLVED, 106) != 0)
		goto out;
	pkt = make_tcp_syn_port(9096);
	key = key_for(REASON_NONE, ACTION_REDIRECT, L4_TCP);
	key.service_id = 20;
	key.rule_id = 106;
	if (expect_rewrite(&env, "fractional refill first packet redirects", &pkt,
			   XDP_REDIRECT, &key) != 0)
		goto out;
	pkt = make_tcp_syn_port(9096);
	key = key_for(REASON_RATE_LIMIT, ACTION_DROP, L4_TCP);
	key.service_id = 20;
	key.rule_id = 106;
	if (expect_decision(&env, "fractional refill immediate packet drops", &pkt,
			    XDP_DROP, &key) != 0)
		goto out;
	usleep(250000);
	pkt = make_tcp_syn_port(9096);
	if (expect_decision(&env, "fractional refill first half interval drops", &pkt,
			    XDP_DROP, &key) != 0)
		goto out;
	usleep(250000);
	pkt = make_tcp_syn_port(9096);
	key = key_for(REASON_NONE, ACTION_REDIRECT, L4_TCP);
	key.service_id = 20;
	key.rule_id = 106;
	if (expect_rewrite(&env, "fractional refill accumulated interval redirects",
			   &pkt, XDP_REDIRECT, &key) != 0)
		goto out;

	if (upsert_rule(env.rule_config_a_fd, 101, ACTION_RATE_LIMIT, 0, 15,
			RATE_DIM_SOURCE_SERVICE, 1, 0, 0, 1, 0) != 0)
		goto out;
	if (upsert_service_with_rule(env.service_allowlist_a_fd, "203.0.113.10",
				     L4_TCP, 9091, 15, ACTION_REDIRECT, 3,
				     NEIGHBOR_RESOLVED, 101) != 0)
		goto out;
	pkt = make_tcp_syn_port(9091);
	key = key_for(REASON_NONE, ACTION_REDIRECT, L4_TCP);
	key.service_id = 15;
	key.rule_id = 101;
	if (expect_rewrite(&env, "observe rate limit under threshold redirects", &pkt,
			   XDP_REDIRECT, &key) != 0)
		goto out;
	pkt = make_tcp_syn_port(9091);
	key = key_for(REASON_RATE_LIMIT, ACTION_OBSERVE, L4_TCP);
	key.service_id = 15;
	key.rule_id = 101;
	{
		uint64_t before = read_counter(&env, &key);
		struct counter_key redirect_key = key_for(REASON_NONE, ACTION_REDIRECT, L4_TCP);

		redirect_key.service_id = 15;
		redirect_key.rule_id = 101;
		if (expect_rewrite(&env, "observe rate limit over threshold still redirects",
				   &pkt, XDP_REDIRECT, &redirect_key) != 0)
			goto out;
		if (expect_counter_delta(&env, "observe over-limit counter increments",
					 &key, before, 1) != 0)
			goto out;
	}

	if (upsert_rule(env.rule_config_a_fd, 102, ACTION_DROP, 1, 16,
			RATE_DIM_SOURCE_SERVICE, 0, 0, 0, 0, 0) != 0)
		goto out;
	if (upsert_service_with_rule(env.service_allowlist_a_fd, "203.0.113.10",
				     L4_TCP, 9092, 16, ACTION_REDIRECT, 3,
				     NEIGHBOR_RESOLVED, 102) != 0)
		goto out;
	pkt = make_tcp_syn_port(9092);
	key = key_for(REASON_RULE_DROP, ACTION_DROP, L4_TCP);
	key.service_id = 16;
	key.rule_id = 102;
	if (expect_decision(&env, "drop rule drops matching service packet", &pkt,
			    XDP_DROP, &key) != 0)
		goto out;

	if (upsert_rule(env.rule_config_a_fd, 104, ACTION_RATE_LIMIT, 1, 18,
			RATE_DIM_SOURCE_SERVICE, 0, 8, 0, 0, 60) != 0)
		goto out;
	if (upsert_service_with_rule(env.service_allowlist_a_fd, "203.0.113.10",
				     L4_TCP, 9094, 18, ACTION_REDIRECT, 3,
				     NEIGHBOR_RESOLVED, 104) != 0)
		goto out;
	pkt = make_tcp_syn_port(9094);
	key = key_for(REASON_NONE, ACTION_REDIRECT, L4_TCP);
	key.service_id = 18;
	key.rule_id = 104;
	if (expect_rewrite(&env, "rate limit under bps redirects", &pkt,
			   XDP_REDIRECT, &key) != 0)
		goto out;
	pkt = make_tcp_syn_port(9094);
	key = key_for(REASON_RATE_LIMIT, ACTION_DROP, L4_TCP);
	key.service_id = 18;
	key.rule_id = 104;
	if (expect_decision(&env, "rate limit over bps drops", &pkt,
			    XDP_DROP, &key) != 0)
		goto out;

	if (upsert_rule(env.rule_config_a_fd, 105, ACTION_RATE_LIMIT, 1, 19,
			RATE_DIM_SOURCE_SERVICE, 0, 0, 1, 1, 0) != 0)
		goto out;
	if (upsert_service_with_rule(env.service_allowlist_a_fd, "203.0.113.10",
				     L4_TCP, 9095, 19, ACTION_REDIRECT, 3,
				     NEIGHBOR_RESOLVED, 105) != 0)
		goto out;
	pkt = make_tcp_syn_port(9095);
	key = key_for(REASON_NONE, ACTION_REDIRECT, L4_TCP);
	key.service_id = 19;
	key.rule_id = 105;
	if (expect_rewrite(&env, "syn cps under threshold redirects", &pkt,
			   XDP_REDIRECT, &key) != 0)
		goto out;
	pkt = make_tcp_syn_port(9095);
	key = key_for(REASON_RATE_LIMIT, ACTION_DROP, L4_TCP);
	key.service_id = 19;
	key.rule_id = 105;
	if (expect_decision(&env, "syn cps over threshold drops", &pkt,
			    XDP_DROP, &key) != 0)
		goto out;

	if (upsert_service(env.service_allowlist_a_fd, "203.0.113.10", L4_UDP, 53,
			   11, ACTION_REDIRECT, 3, NEIGHBOR_RESOLVED) != 0)
		goto out;

	pkt = make_udp();
	key = key_for(REASON_NONE, ACTION_REDIRECT, L4_UDP);
	key.service_id = 11;
	if (expect_rewrite(&env, "allowed udp service redirects", &pkt,
			   XDP_REDIRECT, &key) != 0)
		goto out;

	if (upsert_service(env.service_allowlist_a_fd, "203.0.113.10", L4_ICMP, 0,
			   12, ACTION_REDIRECT, 3, NEIGHBOR_RESOLVED) != 0)
		goto out;

	pkt = make_icmp();
	key = key_for(REASON_NONE, ACTION_REDIRECT, L4_ICMP);
	key.service_id = 12;
	if (expect_rewrite(&env, "allowed icmp service redirects", &pkt,
			   XDP_REDIRECT, &key) != 0)
		goto out;

	if (upsert_service(env.service_allowlist_a_fd, "203.0.113.10", L4_TCP, 8080,
			   13, ACTION_REDIRECT, 3, NEIGHBOR_UNRESOLVED) != 0)
		goto out;

	pkt = make_tcp_syn_port(8080);
	key = key_for(REASON_NEIGHBOR_UNRESOLVED, ACTION_DROP, L4_TCP);
	key.service_id = 13;
	if (expect_decision(&env, "unresolved neighbor fails closed", &pkt,
			    XDP_DROP, &key) != 0)
		goto out;

	if (upsert_cidr_policy(env.blacklist_v4_a_fd, "198.51.100.10", 1,
			       ACTION_DROP, POLICY_SCOPE_GLOBAL, 77) != 0)
		goto out;

	pkt = make_tcp_syn();
	key = key_for(REASON_BLACKLIST, ACTION_DROP, L4_TCP);
	key.rule_id = 77;
	key.service_id = 10;
	if (expect_decision(&env, "blacklist source drops after service match",
			    &pkt, XDP_DROP, &key) != 0)
		goto out;

	if (upsert_cidr_policy(env.whitelist_v4_a_fd, "198.51.100.10", 2,
			       ACTION_PASS, POLICY_SCOPE_GLOBAL, 0) != 0)
		goto out;

	pkt = make_tcp_syn();
	key = key_for(REASON_NONE, ACTION_REDIRECT, L4_TCP);
	key.service_id = 10;
	if (expect_rewrite(&env, "whitelist overrides blacklist after service match",
			   &pkt, XDP_REDIRECT, &key) != 0)
		goto out;

	if (upsert_rule(env.rule_config_a_fd, 103, ACTION_RATE_LIMIT, 1, 17,
			RATE_DIM_SOURCE_SERVICE, 1, 0, 0, 1, 0) != 0)
		goto out;
	if (upsert_service_with_rule(env.service_allowlist_a_fd, "203.0.113.10",
				     L4_TCP, 9093, 17, ACTION_REDIRECT, 3,
				     NEIGHBOR_RESOLVED, 103) != 0)
		goto out;
	pkt = make_tcp_syn_port(9093);
	key = key_for(REASON_NONE, ACTION_REDIRECT, L4_TCP);
	key.service_id = 17;
	key.rule_id = 103;
	if (expect_rewrite(&env, "whitelist bypasses rate limit first packet", &pkt,
			   XDP_REDIRECT, &key) != 0)
		goto out;
	pkt = make_tcp_syn_port(9093);
	key = key_for(REASON_NONE, ACTION_REDIRECT, L4_TCP);
	key.service_id = 17;
	key.rule_id = 103;
	if (expect_rewrite(&env, "whitelist bypasses rate limit over threshold", &pkt,
			   XDP_REDIRECT, &key) != 0)
		goto out;

	pkt = make_tcp_syn_port(81);
	key = key_for(REASON_NOT_ALLOWED_SERVICE, ACTION_DROP, L4_TCP);
	if (expect_decision(&env, "whitelist cannot bypass service allowlist",
			    &pkt, XDP_DROP, &key) != 0)
		goto out;

	pkt = make_truncated_eth();
	if (expect_decision_reason_action(&env, "truncated ethernet payload", &pkt,
					  XDP_DROP, REASON_MALFORMED, ACTION_DROP) != 0)
		goto out;

	pkt = make_bad_ihl();
	if (expect_decision_reason_action(&env, "malformed ipv4 ihl", &pkt, XDP_DROP,
					  REASON_MALFORMED, ACTION_DROP) != 0)
		goto out;

	pkt = make_ipv4_fragment();
	if (expect_decision_reason_action(&env, "ipv4 fragment", &pkt, XDP_DROP,
					  REASON_FRAGMENT, ACTION_DROP) != 0)
		goto out;

	pkt = make_tcp_syn_port(81);
	key = key_for(REASON_NOT_ALLOWED_SERVICE, ACTION_DROP, L4_TCP);
	if (expect_decision(&env, "valid tcp syn to non-allowlisted port", &pkt,
			    XDP_DROP, &key) != 0)
		goto out;

	pkt = make_udp_port(5353);
	key = key_for(REASON_NOT_ALLOWED_SERVICE, ACTION_DROP, L4_UDP);
	if (expect_decision(&env, "valid udp to non-allowlisted port", &pkt,
			    XDP_DROP, &key) != 0)
		goto out;

	pkt = make_unknown_ipv4();
	key = key_for(REASON_NOT_ALLOWED_SERVICE, ACTION_DROP, L4_UNKNOWN);
	if (expect_decision(&env, "unknown ipv4 protocol", &pkt, XDP_DROP, &key) != 0)
		goto out;

	pkt = make_non_ipv4();
	key = key_for(REASON_NONE, ACTION_PASS, L4_UNKNOWN);
	if (expect_decision(&env, "non-ipv4 pass", &pkt, XDP_PASS, &key) != 0)
		goto out;

	ret = 0;

out:
	close_env(&env);
	return ret;
}
