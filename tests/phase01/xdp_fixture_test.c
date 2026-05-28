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

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "anti_ddos/bpf_contract.h"

#define TEST_LOG_PATH "build/bpf/verifier.log"
#define VERIFIER_LOG_SIZE (1024 * 1024)
#define MAX_PACKET_SIZE 256

struct test_env {
	struct bpf_object *obj;
	int prog_fd;
	int runtime_config_fd;
	int whitelist_v4_a_fd;
	int blacklist_v4_a_fd;
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
	env->drop_counters_fd = map_fd_by_name(env->obj, "drop_counters");

	if (env->prog_fd < 0 || env->runtime_config_fd < 0 ||
	    env->whitelist_v4_a_fd < 0 || env->blacklist_v4_a_fd < 0 ||
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

static int run_packet(struct test_env *env, const struct packet_fixture *fixture,
		      uint32_t *retval)
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
	return 0;
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

static struct packet_fixture make_tcp_syn(void)
{
	struct packet_fixture fixture = {};
	struct tcphdr *tcp;

	init_eth(&fixture, ETH_P_IP);
	append_ipv4(&fixture, IPPROTO_TCP, sizeof(*tcp));
	tcp = (struct tcphdr *)(fixture.data + sizeof(struct ethhdr) + sizeof(struct iphdr));
	tcp->source = htons(12345);
	tcp->dest = htons(80);
	tcp->doff = 5;
	tcp->syn = 1;

	return fixture;
}

static struct packet_fixture make_udp(void)
{
	struct packet_fixture fixture = {};
	struct udphdr *udp;

	init_eth(&fixture, ETH_P_IP);
	append_ipv4(&fixture, IPPROTO_UDP, sizeof(*udp));
	udp = (struct udphdr *)(fixture.data + sizeof(struct ethhdr) + sizeof(struct iphdr));
	udp->source = htons(12345);
	udp->dest = htons(53);
	udp->len = htons(sizeof(*udp));

	return fixture;
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

static struct counter_key key_for(uint32_t reason, uint8_t action, uint8_t proto)
{
	struct counter_key key = {
		.reason = reason,
		.rule_id = 0,
		.service_id = 0,
		.proto = proto,
		.action = action,
		.pad = 0,
	};

	return key;
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

	if (upsert_cidr_policy(env.blacklist_v4_a_fd, "198.51.100.10", 1,
			       ACTION_DROP, POLICY_SCOPE_GLOBAL, 77) != 0)
		goto out;

	pkt = make_tcp_syn();
	key = key_for(REASON_BLACKLIST, ACTION_DROP, L4_TCP);
	key.rule_id = 77;
	if (expect_decision(&env, "blacklist source drop", &pkt, XDP_DROP, &key) != 0)
		goto out;

	if (upsert_cidr_policy(env.whitelist_v4_a_fd, "198.51.100.10", 2,
			       ACTION_PASS, POLICY_SCOPE_GLOBAL, 0) != 0)
		goto out;

	pkt = make_tcp_syn();
	key = key_for(REASON_NOT_ALLOWED_SERVICE, ACTION_DROP, L4_TCP);
	if (expect_decision(&env, "whitelist overrides blacklist before service allowlist",
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

	pkt = make_tcp_syn();
	key = key_for(REASON_NOT_ALLOWED_SERVICE, ACTION_DROP, L4_TCP);
	if (expect_decision(&env, "valid tcp syn", &pkt, XDP_DROP, &key) != 0)
		goto out;

	pkt = make_udp();
	key = key_for(REASON_NOT_ALLOWED_SERVICE, ACTION_DROP, L4_UDP);
	if (expect_decision(&env, "valid udp", &pkt, XDP_DROP, &key) != 0)
		goto out;

	pkt = make_icmp();
	key = key_for(REASON_NOT_ALLOWED_SERVICE, ACTION_DROP, L4_ICMP);
	if (expect_decision(&env, "valid icmp", &pkt, XDP_DROP, &key) != 0)
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
