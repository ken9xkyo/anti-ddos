#!/usr/bin/env bash
set -euo pipefail

AGENT_BIN="${AGENT_BIN:-build/agent/anti-ddos-agent}"
POLICYGEN_BIN="${POLICYGEN_BIN:-build/phase4-policygen}"
BPF_OBJ="${BPF_OBJ:-build/bpf/xdp_data_plane.bpf.o}"
PASS_BPF_OBJ="${PASS_BPF_OBJ:-build/bpf/xdp_pass.bpf.o}"
WORK_DIR="${WORK_DIR:-build/phase4-devmap-veth}"
RUN_ID="p4$$"
CLIENT_NS="c${RUN_ID}"
BACKEND_NS="b${RUN_ID}"
WAN_HOST_IF="wh${RUN_ID}"
WAN_CLIENT_IF="wc${RUN_ID}"
BACKEND_HOST_IF="bh${RUN_ID}"
BACKEND_PEER_IF="bp${RUN_ID}"
PIN_DIR="/sys/fs/bpf/anti-ddos-${RUN_ID}"
SNAPSHOT_PATH="${WORK_DIR}/last-valid-snapshot.json"
BOOTSTRAP_POLICY="${WORK_DIR}/phase4-policy.json"
LOG_PATH="${WORK_DIR}/agent.log"
METRICS_PATH="${WORK_DIR}/metrics.txt"
CAPTURE_PATH="${WORK_DIR}/backend-capture.txt"
ALLOWED_PORT="5300"
DENIED_PORT="5301"
BACKEND_IP="203.0.113.10"
CLIENT_GW="198.51.100.1"
CLIENT_IP="198.51.100.10"

choose_port() {
	for port in $(seq 19141 19190); do
		if ! ss -ltn | awk -v suffix=":${port}" '$4 ~ suffix "$" {found = 1} END {exit found ? 0 : 1}'; then
			printf '%s\n' "${port}"
			return 0
		fi
	done
	return 1
}

cleanup() {
	local status=$?
	if [[ -n "${AGENT_PID:-}" ]] && kill -0 "${AGENT_PID}" 2>/dev/null; then
		if [[ "${status}" != "0" && -n "${PORT:-}" ]]; then
			curl -fsS "http://127.0.0.1:${PORT}/metrics" > "${METRICS_PATH}" 2>/dev/null || true
		fi
		kill -TERM "${AGENT_PID}" 2>/dev/null || true
		wait "${AGENT_PID}" 2>/dev/null || true
	fi
	if [[ "${KEEP_NETNS:-0}" != "1" ]]; then
		ip link del "${WAN_HOST_IF}" 2>/dev/null || true
		ip link del "${BACKEND_HOST_IF}" 2>/dev/null || true
		ip netns del "${CLIENT_NS}" 2>/dev/null || true
		ip netns del "${BACKEND_NS}" 2>/dev/null || true
	fi
	rm -rf "${PIN_DIR}"
	if [[ "${KEEP_WORK_DIR:-0}" == "1" || "${status}" != "0" ]]; then
		echo "preserved phase4 work dir: ${WORK_DIR}" >&2
	else
		rm -rf "${WORK_DIR}"
	fi
}
trap cleanup EXIT

require_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing required command: $1" >&2
		exit 1
	fi
}

link_mac() {
	local ns="$1"
	local dev="$2"
	if [[ -n "${ns}" ]]; then
		ip -n "${ns}" -o link show dev "${dev}" | awk '{for (i = 1; i <= NF; i++) if ($i == "link/ether") {print $(i + 1); exit}}'
	else
		ip -o link show dev "${dev}" | awk '{for (i = 1; i <= NF; i++) if ($i == "link/ether") {print $(i + 1); exit}}'
	fi
}

start_agent() {
	: > "${LOG_PATH}"
	ANTI_DDOS_WAN_IFACE="${WAN_HOST_IF}" \
	ANTI_DDOS_XDP_OBJECT="${BPF_OBJ}" \
	ANTI_DDOS_XDP_MODE="native" \
	ANTI_DDOS_XDP_ALLOW_GENERIC_FALLBACK="true" \
	ANTI_DDOS_METRICS_ADDR="127.0.0.1:${PORT}" \
	ANTI_DDOS_BPF_PIN_DIR="${PIN_DIR}" \
	ANTI_DDOS_SNAPSHOT_PATH="${SNAPSHOT_PATH}" \
	ANTI_DDOS_BOOTSTRAP_POLICY_PATH="${BOOTSTRAP_POLICY}" \
	ANTI_DDOS_SAFE_DETACH_ON_EXIT="true" \
		"${AGENT_BIN}" 2>>"${LOG_PATH}" &
	AGENT_PID=$!

	for _ in $(seq 1 100); do
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

capture_backend_packet() {
	local dst_port="$1"
	local output_path="$2"
	local timeout_s="$3"
	local ready_path="${output_path}.ready"
	ip netns exec "${BACKEND_NS}" python3 - "${BACKEND_PEER_IF}" "${dst_port}" "${output_path}" "${ready_path}" "${timeout_s}" <<'PY'
import socket
import struct
import sys
import time

iface = sys.argv[1]
want_port = int(sys.argv[2])
output = sys.argv[3]
ready = sys.argv[4]
deadline = time.time() + float(sys.argv[5])

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
sock.bind((iface, 0))
sock.settimeout(0.2)
with open(ready, "w", encoding="utf-8") as fp:
    fp.write("ready\n")

def mac(raw):
    return ":".join(f"{b:02x}" for b in raw)

while time.time() < deadline:
    try:
        data, _ = sock.recvfrom(65535)
    except socket.timeout:
        continue
    if len(data) < 42:
        continue
    if struct.unpack("!H", data[12:14])[0] != 0x0800:
        continue
    ihl = (data[14] & 0x0f) * 4
    proto = data[23]
    dst = socket.inet_ntoa(data[30:34])
    if proto != 17 or dst != "203.0.113.10":
        continue
    l4 = 14 + ihl
    if len(data) < l4 + 8:
        continue
    dst_port = struct.unpack("!H", data[l4 + 2:l4 + 4])[0]
    if dst_port != want_port:
        continue
    with open(output, "w", encoding="utf-8") as fp:
        fp.write(f"{mac(data[0:6])} {mac(data[6:12])} {proto} {dst_port} {len(data)}\n")
    sys.exit(0)

sys.exit(3)
PY
}

wait_capture_ready() {
	local ready_path="$1"
	for _ in $(seq 1 50); do
		if [[ -f "${ready_path}" ]]; then
			return 0
		fi
		sleep 0.1
	done
	echo "backend capture did not become ready" >&2
	return 1
}

send_udp() {
	local dst_port="$1"
	ip netns exec "${CLIENT_NS}" python3 - "${BACKEND_IP}" "${dst_port}" <<'PY'
import socket
import sys

dst = sys.argv[1]
port = int(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(1)
sock.sendto(b"phase4", (dst, port))
sock.close()
PY
}

require_cmd ip
require_cmd ss
require_cmd curl
require_cmd python3

if [[ "$(id -u)" != "0" ]]; then
	echo "phase4-devmap-veth-test must run as root for netns and XDP attach" >&2
	exit 1
fi
if [[ ! -x "${AGENT_BIN}" ]]; then
	echo "missing agent binary: ${AGENT_BIN}" >&2
	exit 1
fi
if [[ ! -x "${POLICYGEN_BIN}" ]]; then
	echo "missing policy generator: ${POLICYGEN_BIN}" >&2
	exit 1
fi
if [[ ! -f "${BPF_OBJ}" ]]; then
	echo "missing BPF object: ${BPF_OBJ}" >&2
	exit 1
fi
if [[ ! -f "${PASS_BPF_OBJ}" ]]; then
	echo "missing pass-through BPF object: ${PASS_BPF_OBJ}" >&2
	exit 1
fi
if ! awk '$2 == "/sys/fs/bpf" && $3 == "bpf" {found = 1} END {exit found ? 0 : 1}' /proc/mounts; then
	echo "/sys/fs/bpf is not mounted as bpffs" >&2
	exit 1
fi

mkdir -p "${WORK_DIR}" "${PIN_DIR}"
PORT="$(choose_port)"

ip netns add "${CLIENT_NS}"
ip netns add "${BACKEND_NS}"

ip link add "${WAN_HOST_IF}" type veth peer name "${WAN_CLIENT_IF}"
ip link set "${WAN_CLIENT_IF}" netns "${CLIENT_NS}"
ip addr add "${CLIENT_GW}/24" dev "${WAN_HOST_IF}"
ip link set "${WAN_HOST_IF}" up
ip -n "${CLIENT_NS}" addr add "${CLIENT_IP}/24" dev "${WAN_CLIENT_IF}"
ip -n "${CLIENT_NS}" link set "${WAN_CLIENT_IF}" up
ip -n "${CLIENT_NS}" route add default via "${CLIENT_GW}" dev "${WAN_CLIENT_IF}"

ip link add "${BACKEND_HOST_IF}" type veth peer name "${BACKEND_PEER_IF}"
ip link set "${BACKEND_PEER_IF}" netns "${BACKEND_NS}"
ip link set "${BACKEND_HOST_IF}" up
ip -n "${BACKEND_NS}" addr add "${BACKEND_IP}/32" dev "${BACKEND_PEER_IF}"
ip -n "${BACKEND_NS}" link set "${BACKEND_PEER_IF}" up
ip netns exec "${BACKEND_NS}" ip link set dev "${BACKEND_PEER_IF}" xdp obj "${PASS_BPF_OBJ}" sec xdp

BACKEND_IFINDEX="$(cat "/sys/class/net/${BACKEND_HOST_IF}/ifindex")"
BACKEND_SRC_MAC="$(link_mac "" "${BACKEND_HOST_IF}")"
BACKEND_DST_MAC="$(link_mac "${BACKEND_NS}" "${BACKEND_PEER_IF}")"

"${POLICYGEN_BIN}" \
	-out "${BOOTSTRAP_POLICY}" \
	-xdp-object "${BPF_OBJ}" \
	-version 4 \
	-service-id 40 \
	-forwarding-policy-id 400 \
	-dst-v4 "${BACKEND_IP}" \
	-dst-port "${ALLOWED_PORT}" \
	-proto 17 \
	-output-ifindex "${BACKEND_IFINDEX}" \
	-devmap-key 4 \
	-dst-mac "${BACKEND_DST_MAC}" \
	-src-mac "${BACKEND_SRC_MAC}"

start_agent
ip -d link show dev "${WAN_HOST_IF}" | grep -q "xdp"

rm -f "${CAPTURE_PATH}" "${CAPTURE_PATH}.ready"
capture_backend_packet "${ALLOWED_PORT}" "${CAPTURE_PATH}" 5 &
CAPTURE_PID=$!
wait_capture_ready "${CAPTURE_PATH}.ready"
send_udp "${ALLOWED_PORT}"
wait "${CAPTURE_PID}"

read -r GOT_DST_MAC GOT_SRC_MAC GOT_PROTO GOT_PORT _ < "${CAPTURE_PATH}"
test "${GOT_DST_MAC}" = "${BACKEND_DST_MAC}"
test "${GOT_SRC_MAC}" = "${BACKEND_SRC_MAC}"
test "${GOT_PROTO}" = "17"
test "${GOT_PORT}" = "${ALLOWED_PORT}"

rm -f "${CAPTURE_PATH}" "${CAPTURE_PATH}.ready"
capture_backend_packet "${DENIED_PORT}" "${CAPTURE_PATH}" 1 &
CAPTURE_PID=$!
wait_capture_ready "${CAPTURE_PATH}.ready"
send_udp "${DENIED_PORT}"
if wait "${CAPTURE_PID}"; then
	echo "backend received non-allowlisted UDP/${DENIED_PORT}" >&2
	exit 1
fi

for _ in $(seq 1 100); do
	curl -fsS "http://127.0.0.1:${PORT}/metrics" > "${METRICS_PATH}"
	if grep -q 'anti_ddos_redirected_packets_total{.*service_id="40".*} 1' "${METRICS_PATH}" &&
	   grep -q 'anti_ddos_not_allowed_service_total{protocol="17"} 1' "${METRICS_PATH}" &&
	   grep -q 'anti_ddos_neighbor_resolution_status{.*service_id="40".*} 1' "${METRICS_PATH}"; then
		break
	fi
	sleep 0.1
done

grep -q 'anti_ddos_redirected_packets_total{.*service_id="40".*} 1' "${METRICS_PATH}"
grep -q 'anti_ddos_not_allowed_service_total{protocol="17"} 1' "${METRICS_PATH}"
grep -q 'anti_ddos_neighbor_resolution_status{.*service_id="40".*} 1' "${METRICS_PATH}"

echo "PASS phase4 devmap veth forwarding"
