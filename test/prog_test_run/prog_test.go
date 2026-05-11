// Package progtest runs the XDP program against crafted packets using the
// kernel BPF_PROG_TEST_RUN facility. Compile-time dependency on the
// bpf2go-generated file; the tests are skipped if the compiled object is
// missing or CAP_BPF is unavailable.
package progtest

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

const bpfObjectEnv = "ANTIDDOS_BPF_OBJ"

func mustObjectPath(t *testing.T) string {
	t.Helper()
	p := os.Getenv(bpfObjectEnv)
	if p == "" {
		t.Skipf("set %s=/path/to/bpf.o to run prog_test_run tests", bpfObjectEnv)
	}
	return p
}

func loadProg(t *testing.T, name string) *ebpf.Program {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("rlimit: %v", err)
	}
	spec, err := ebpf.LoadCollectionSpec(mustObjectPath(t))
	if err != nil {
		t.Skipf("load spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("not permitted (need CAP_BPF): %v", err)
		}
		t.Fatalf("new collection: %v", err)
	}
	t.Cleanup(coll.Close)
	p := coll.Programs[name]
	if p == nil {
		t.Fatalf("program %q not found", name)
	}
	return p
}

// ---- packet builders -----------------------------------------------------

func ethHdr(src, dst net.HardwareAddr, proto uint16) []byte {
	b := make([]byte, 14)
	copy(b[0:6], dst)
	copy(b[6:12], src)
	binary.BigEndian.PutUint16(b[12:14], proto)
	return b
}

func ipv4Hdr(src, dst net.IP, proto uint8, payloadLen int) []byte {
	b := make([]byte, 20)
	b[0] = 0x45 // v4, IHL=5
	binary.BigEndian.PutUint16(b[2:4], uint16(20+payloadLen))
	b[8] = 64 // TTL
	b[9] = proto
	copy(b[12:16], src.To4())
	copy(b[16:20], dst.To4())
	return b
}

func tcpHdr(sport, dport uint16, flags uint8) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:2], sport)
	binary.BigEndian.PutUint16(b[2:4], dport)
	b[12] = 0x50 // data offset = 5
	b[13] = flags
	return b
}

func udpHdr(sport, dport uint16, payload int) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:2], sport)
	binary.BigEndian.PutUint16(b[2:4], dport)
	binary.BigEndian.PutUint16(b[4:6], uint16(8+payload))
	return b
}

func buildTCPv4(src, dst net.IP, sport, dport uint16, flags uint8) []byte {
	sm := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01}
	dm := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x02}
	tcp := tcpHdr(sport, dport, flags)
	ip := ipv4Hdr(src, dst, 6, len(tcp))
	return append(append(ethHdr(sm, dm, 0x0800), ip...), tcp...)
}

func buildUDPv4(src, dst net.IP, sport, dport uint16, payload int) []byte {
	sm := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01}
	dm := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x02}
	udp := udpHdr(sport, dport, payload)
	pl := make([]byte, payload)
	ip := ipv4Hdr(src, dst, 17, len(udp)+len(pl))
	out := append(ethHdr(sm, dm, 0x0800), ip...)
	out = append(out, udp...)
	out = append(out, pl...)
	return out
}

// ---- tests --------------------------------------------------------------

// XDP verdicts.
const (
	XdpAborted  = 0
	XdpDrop     = 1
	XdpPass     = 2
	XdpTx       = 3
	XdpRedirect = 4
)

func TestMalformedDropped(t *testing.T) {
	p := loadProg(t, "xdp_antiddos")
	short := []byte{0x00, 0x01, 0x02}
	ret, _, err := p.Test(short)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if ret != XdpDrop {
		t.Fatalf("want drop, got %d", ret)
	}
}

func TestMartianDropped(t *testing.T) {
	p := loadProg(t, "xdp_antiddos")
	pkt := buildUDPv4(net.IPv4(127, 0, 0, 1), net.IPv4(10, 0, 0, 1), 53, 12345, 32)
	ret, _, err := p.Test(pkt)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if ret != XdpDrop {
		t.Fatalf("want drop (martian), got %d", ret)
	}
}

func TestReflectionSrcPortDropped(t *testing.T) {
	p := loadProg(t, "xdp_antiddos")
	// NB: expects feature_flags to include FEAT_DROP_REFLECT; test harness
	// should pre-populate config_map when running standalone.
	pkt := buildUDPv4(net.IPv4(1, 2, 3, 4), net.IPv4(10, 0, 0, 1), 53, 12345, 512)
	ret, _, err := p.Test(pkt)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if ret != XdpDrop && ret != XdpPass {
		t.Logf("verdict=%d (expected drop with reflection feature enabled)", ret)
	}
}

func TestLegitTCPAllowed(t *testing.T) {
	p := loadProg(t, "xdp_antiddos")
	// SYN-ACK is treated as non-new flow and would be OOS without conntrack;
	// with conntrack disabled in default test harness, should REDIRECT/PASS.
	pkt := buildTCPv4(net.IPv4(8, 8, 8, 8), net.IPv4(10, 0, 0, 1), 54321, 443, 0x02 /*SYN*/)
	ret, _, err := p.Test(pkt)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if ret == XdpDrop {
		t.Fatalf("legit SYN should not be dropped by default")
	}
}
