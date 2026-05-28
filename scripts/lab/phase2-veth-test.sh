#!/usr/bin/env bash
set -euo pipefail

AGENT_BIN="${AGENT_BIN:-build/agent/anti-ddos-agent}"
BPF_OBJ="${BPF_OBJ:-build/bpf/xdp_data_plane.bpf.o}"
WORK_DIR="${WORK_DIR:-build/phase2-veth}"
RUN_ID="p2$$"
NS="ns${RUN_ID}"
HOST_IF="h${RUN_ID}"
PEER_IF="p${RUN_ID}"
PIN_DIR="/sys/fs/bpf/anti-ddos-${RUN_ID}"
SNAPSHOT_PATH="${WORK_DIR}/last-valid-snapshot.json"
LOG_PATH="${WORK_DIR}/agent.log"
METRICS_PATH="${WORK_DIR}/metrics.txt"

choose_port() {
	for port in $(seq 19091 19140); do
		if ! ss -ltn | awk -v suffix=":${port}" '$4 ~ suffix "$" {found = 1} END {exit found ? 0 : 1}'; then
			printf '%s\n' "${port}"
			return 0
		fi
	done
	return 1
}

cleanup() {
	if [[ -n "${AGENT_PID:-}" ]] && kill -0 "${AGENT_PID}" 2>/dev/null; then
		kill -TERM "${AGENT_PID}" 2>/dev/null || true
		wait "${AGENT_PID}" 2>/dev/null || true
	fi
	ip link del "${HOST_IF}" 2>/dev/null || true
	ip netns del "${NS}" 2>/dev/null || true
	rm -rf "${PIN_DIR}" "${WORK_DIR}"
}
trap cleanup EXIT

require_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing required command: $1" >&2
		exit 1
	fi
}

start_agent() {
	local safe_detach="$1"
	: > "${LOG_PATH}"
	ANTI_DDOS_WAN_IFACE="${HOST_IF}" \
	ANTI_DDOS_XDP_OBJECT="${BPF_OBJ}" \
	ANTI_DDOS_XDP_MODE="native" \
	ANTI_DDOS_XDP_ALLOW_GENERIC_FALLBACK="true" \
	ANTI_DDOS_METRICS_ADDR="127.0.0.1:${PORT}" \
	ANTI_DDOS_BPF_PIN_DIR="${PIN_DIR}" \
	ANTI_DDOS_SNAPSHOT_PATH="${SNAPSHOT_PATH}" \
	ANTI_DDOS_SAFE_DETACH_ON_EXIT="${safe_detach}" \
		"${AGENT_BIN}" 2>>"${LOG_PATH}" &
	AGENT_PID=$!

	for _ in $(seq 1 80); do
		if curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then
			return 0
		fi
		if ! kill -0 "${AGENT_PID}" 2>/dev/null; then
			echo "agent exited before healthcheck passed" >&2
			cat "${LOG_PATH}" >&2 || true
			exit 1
		fi
		sleep 0.1
	done

	echo "agent healthcheck timed out" >&2
	cat "${LOG_PATH}" >&2 || true
	exit 1
}

stop_agent() {
	if [[ -n "${AGENT_PID:-}" ]] && kill -0 "${AGENT_PID}" 2>/dev/null; then
		kill -TERM "${AGENT_PID}"
		wait "${AGENT_PID}"
	fi
	unset AGENT_PID
}

require_cmd ip
require_cmd ss
require_cmd curl

if [[ "$(id -u)" != "0" ]]; then
	echo "phase2-veth-test must run as root for netns and XDP attach" >&2
	exit 1
fi
if [[ ! -x "${AGENT_BIN}" ]]; then
	echo "missing agent binary: ${AGENT_BIN}" >&2
	exit 1
fi
if [[ ! -f "${BPF_OBJ}" ]]; then
	echo "missing BPF object: ${BPF_OBJ}" >&2
	exit 1
fi
if ! awk '$2 == "/sys/fs/bpf" && $3 == "bpf" {found = 1} END {exit found ? 0 : 1}' /proc/mounts; then
	echo "/sys/fs/bpf is not mounted as bpffs" >&2
	exit 1
fi

mkdir -p "${WORK_DIR}" "${PIN_DIR}"
PORT="$(choose_port)"

ip netns add "${NS}"
ip link add "${HOST_IF}" type veth peer name "${PEER_IF}"
ip link set "${PEER_IF}" netns "${NS}"
ip addr add 192.0.2.1/24 dev "${HOST_IF}"
ip link set "${HOST_IF}" up
ip -n "${NS}" addr add 192.0.2.2/24 dev "${PEER_IF}"
ip -n "${NS}" link set "${PEER_IF}" up

start_agent false
ip -d link show dev "${HOST_IF}" | grep -q "xdp"
ip netns exec "${NS}" ping -c 3 -W 1 192.0.2.1 >/dev/null 2>&1 || true

for _ in $(seq 1 80); do
	curl -fsS "http://127.0.0.1:${PORT}/metrics" > "${METRICS_PATH}"
	if grep -q 'anti_ddos_xdp_packets_total' "${METRICS_PATH}"; then
		break
	fi
	sleep 0.1
done
grep -q 'anti_ddos_agent_up 1' "${METRICS_PATH}"
grep -q 'anti_ddos_xdp_mode{mode=' "${METRICS_PATH}"
grep -q 'anti_ddos_ebpf_map_capacity{map="drop_counters"}' "${METRICS_PATH}"

stop_agent
test -e "${PIN_DIR}/links/xdp_${HOST_IF}"
test -s "${SNAPSHOT_PATH}"

start_agent true
curl -fsS "http://127.0.0.1:${PORT}/metrics" > "${METRICS_PATH}"
grep -q 'anti_ddos_agent_up 1' "${METRICS_PATH}"
stop_agent

echo "PASS phase2 veth lifecycle"
