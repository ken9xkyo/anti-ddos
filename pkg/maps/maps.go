// Package maps provides typed wrappers over the eBPF maps used by antiddos.
package maps

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/cilium/ebpf"
)

// StatIdx mirrors enum stat_idx in bpf/common.h. Keep in sync.
type StatIdx uint32

const (
	StatRxTotal StatIdx = iota
	StatPass
	StatRedirect
	StatDropMalformed
	StatDropMartian
	StatDropBlocklist
	StatDropFrag
	StatDropReflect
	StatDropIcmpFlood
	StatDropSynFlood
	StatDropRate
	StatDropOosTCP
	StatDropUnknown
	StatWhitelistHit
	StatSyncookieIssued
	StatSyncookiePass
	StatCtNew
	StatCtEstablished
	StatBytesRx
	StatBytesDropped
	StatMax
)

// StatNames returns the string label for each counter.
var StatNames = map[StatIdx]string{
	StatRxTotal:        "rx_total",
	StatPass:           "pass",
	StatRedirect:       "redirect",
	StatDropMalformed:  "drop_malformed",
	StatDropMartian:    "drop_martian",
	StatDropBlocklist:  "drop_blocklist",
	StatDropFrag:       "drop_fragment",
	StatDropReflect:    "drop_reflection",
	StatDropIcmpFlood:  "drop_icmp_flood",
	StatDropSynFlood:   "drop_syn_flood",
	StatDropRate:       "drop_rate_limit",
	StatDropOosTCP:     "drop_oos_tcp",
	StatDropUnknown:    "drop_unknown",
	StatWhitelistHit:   "whitelist_hit",
	StatSyncookieIssued: "syncookie_issued",
	StatSyncookiePass:  "syncookie_pass",
	StatCtNew:          "ct_new",
	StatCtEstablished:  "ct_established",
	StatBytesRx:        "bytes_rx",
	StatBytesDropped:   "bytes_dropped",
}

// Config mirrors struct config in bpf/common.h.
type Config struct {
	FeatureFlags  uint32
	SampleEvery   uint32
	SynRatePPS    uint32
	UDPRatePPS    uint32
	ICMPRatePPS   uint32
	GlobalRatePPS uint32
	BucketBurst   uint32
	EgressIfindex uint32
}

// Feature flags mirror FEAT_* in bpf/common.h.
const (
	FeatDropFragments uint32 = 1 << iota
	FeatDropReflect
	FeatSyncookie
	FeatConntrack
	FeatRateLimit
	FeatRedirect
)

// LPMV4Key mirrors struct lpm_v4_key.
type LPMV4Key struct {
	PrefixLen uint32
	Addr      uint32 // network byte order
}

// LPMV6Key mirrors struct lpm_v6_key.
type LPMV6Key struct {
	PrefixLen uint32
	Addr      [16]byte
}

// ErrNotFound is returned by lookups on missing keys.
var ErrNotFound = errors.New("not found")

// Handles groups the maps the daemon interacts with.
type Handles struct {
	Stats        *ebpf.Map
	Config       *ebpf.Map
	BlocklistV4  *ebpf.Map
	BlocklistV6  *ebpf.Map
	WhitelistV4  *ebpf.Map
	WhitelistV6  *ebpf.Map
	RateBuckets  *ebpf.Map
	Conntrack    *ebpf.Map
	TopN         *ebpf.Map
	EgressDevmap *ebpf.Map
	Events       *ebpf.Map
}

// FromCollection extracts typed handles from a loaded collection.
func FromCollection(c *ebpf.Collection) (*Handles, error) {
	h := &Handles{
		Stats:        c.Maps["stats"],
		Config:       c.Maps["config_map"],
		BlocklistV4:  c.Maps["blocklist_v4"],
		BlocklistV6:  c.Maps["blocklist_v6"],
		WhitelistV4:  c.Maps["whitelist_v4"],
		WhitelistV6:  c.Maps["whitelist_v6"],
		RateBuckets:  c.Maps["rate_buckets"],
		Conntrack:    c.Maps["conntrack"],
		TopN:         c.Maps["topn_src"],
		EgressDevmap: c.Maps["egress_devmap"],
		Events:       c.Maps["events"],
	}
	if h.Stats == nil || h.Config == nil || h.BlocklistV4 == nil {
		return nil, errors.New("required maps missing from collection")
	}
	return h, nil
}

// ---- config ------------------------------------------------------------

// PutConfig atomically writes the config record.
func (h *Handles) PutConfig(c Config) error {
	var k uint32
	return h.Config.Update(&k, &c, ebpf.UpdateAny)
}

// GetConfig reads the current config.
func (h *Handles) GetConfig() (Config, error) {
	var k uint32
	var c Config
	if err := h.Config.Lookup(&k, &c); err != nil {
		return Config{}, err
	}
	return c, nil
}

// ---- stats -------------------------------------------------------------

// ReadStats aggregates per-CPU counters into a single snapshot.
func (h *Handles) ReadStats() ([StatMax]uint64, error) {
	var out [StatMax]uint64
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		return out, fmt.Errorf("possible cpu: %w", err)
	}
	for i := uint32(0); i < uint32(StatMax); i++ {
		values := make([]uint64, ncpu)
		if err := h.Stats.Lookup(&i, &values); err != nil {
			return out, fmt.Errorf("lookup stat %d: %w", i, err)
		}
		var sum uint64
		for _, v := range values {
			sum += v
		}
		out[i] = sum
	}
	return out, nil
}

// ---- blocklist / whitelist --------------------------------------------

// AddBlockV4 inserts an IPv4 prefix into the blocklist.
func (h *Handles) AddBlockV4(p netip.Prefix, expireJiffies uint64) error {
	return putLPMv4(h.BlocklistV4, p, expireJiffies)
}

// DelBlockV4 removes an IPv4 prefix from the blocklist.
func (h *Handles) DelBlockV4(p netip.Prefix) error {
	return delLPMv4(h.BlocklistV4, p)
}

// AddBlockV6 inserts an IPv6 prefix into the blocklist.
func (h *Handles) AddBlockV6(p netip.Prefix, expireJiffies uint64) error {
	return putLPMv6(h.BlocklistV6, p, expireJiffies)
}

// DelBlockV6 removes an IPv6 prefix.
func (h *Handles) DelBlockV6(p netip.Prefix) error {
	return delLPMv6(h.BlocklistV6, p)
}

// AddWhitelistV4 inserts an IPv4 prefix into the whitelist.
func (h *Handles) AddWhitelistV4(p netip.Prefix) error {
	return putLPMv4(h.WhitelistV4, p, 0)
}

// AddWhitelistV6 inserts an IPv6 prefix into the whitelist.
func (h *Handles) AddWhitelistV6(p netip.Prefix) error {
	return putLPMv6(h.WhitelistV6, p, 0)
}

func putLPMv4(m *ebpf.Map, p netip.Prefix, val uint64) error {
	if !p.Addr().Is4() {
		return fmt.Errorf("prefix %s is not IPv4", p)
	}
	k := LPMV4Key{PrefixLen: uint32(p.Bits())}
	ip := p.Addr().As4()
	k.Addr = binary.BigEndian.Uint32(ip[:])
	return m.Update(&k, &val, ebpf.UpdateAny)
}

func delLPMv4(m *ebpf.Map, p netip.Prefix) error {
	if !p.Addr().Is4() {
		return fmt.Errorf("prefix %s is not IPv4", p)
	}
	k := LPMV4Key{PrefixLen: uint32(p.Bits())}
	ip := p.Addr().As4()
	k.Addr = binary.BigEndian.Uint32(ip[:])
	if err := m.Delete(&k); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

func putLPMv6(m *ebpf.Map, p netip.Prefix, val uint64) error {
	if !p.Addr().Is6() {
		return fmt.Errorf("prefix %s is not IPv6", p)
	}
	k := LPMV6Key{PrefixLen: uint32(p.Bits())}
	addr := p.Addr().As16()
	copy(k.Addr[:], addr[:])
	return m.Update(&k, &val, ebpf.UpdateAny)
}

func delLPMv6(m *ebpf.Map, p netip.Prefix) error {
	if !p.Addr().Is6() {
		return fmt.Errorf("prefix %s is not IPv6", p)
	}
	k := LPMV6Key{PrefixLen: uint32(p.Bits())}
	addr := p.Addr().As16()
	copy(k.Addr[:], addr[:])
	if err := m.Delete(&k); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

// AddPrefix routes to the right blocklist based on address family.
func (h *Handles) AddPrefix(list string, p netip.Prefix, expireJiffies uint64) error {
	switch list {
	case "block":
		if p.Addr().Is4() {
			return h.AddBlockV4(p, expireJiffies)
		}
		return h.AddBlockV6(p, expireJiffies)
	case "whitelist":
		if p.Addr().Is4() {
			return h.AddWhitelistV4(p)
		}
		return h.AddWhitelistV6(p)
	}
	return fmt.Errorf("unknown list %q", list)
}

// DelPrefix deletes a prefix from block/whitelist.
func (h *Handles) DelPrefix(list string, p netip.Prefix) error {
	switch list {
	case "block":
		if p.Addr().Is4() {
			return h.DelBlockV4(p)
		}
		return h.DelBlockV6(p)
	case "whitelist":
		if p.Addr().Is4() {
			return delLPMv4(h.WhitelistV4, p)
		}
		return delLPMv6(h.WhitelistV6, p)
	}
	return fmt.Errorf("unknown list %q", list)
}

// ---- top-N readback ---------------------------------------------------

// TopEntry is a single top-talker observation.
type TopEntry struct {
	SrcIP netip.Addr
	Proto uint8
	Pkts  uint64
	Bytes uint64
}

// RateKey mirrors struct rate_key.
type RateKey struct {
	SaddrHi   uint32
	Saddr     uint32
	SaddrMid1 uint32
	SaddrMid2 uint32
	Proto     uint16
	_         uint16
}

// TopNVal mirrors struct topn_val.
type TopNVal struct {
	Pkts         uint64
	Bytes        uint64
	LastJiffies  uint64
}

// DumpTopN returns a snapshot of up to limit entries sorted by packet count.
func (h *Handles) DumpTopN(limit int) ([]TopEntry, error) {
	iter := h.TopN.Iterate()
	var k RateKey
	var v TopNVal
	out := make([]TopEntry, 0, 256)
	for iter.Next(&k, &v) {
		var ip netip.Addr
		if k.SaddrHi == 0 && k.SaddrMid1 == 0 && k.SaddrMid2 == 0 {
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], k.Saddr)
			ip = netip.AddrFrom4(b)
		} else {
			var b [16]byte
			binary.BigEndian.PutUint32(b[0:4], k.SaddrHi)
			binary.BigEndian.PutUint32(b[4:8], k.Saddr)
			binary.BigEndian.PutUint32(b[8:12], k.SaddrMid1)
			binary.BigEndian.PutUint32(b[12:16], k.SaddrMid2)
			ip = netip.AddrFrom16(b)
		}
		out = append(out, TopEntry{
			SrcIP: ip, Proto: uint8(k.Proto),
			Pkts: v.Pkts, Bytes: v.Bytes,
		})
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	// crude partial sort: top by pkts
	for i := 0; i < len(out); i++ {
		max := i
		for j := i + 1; j < len(out); j++ {
			if out[j].Pkts > out[max].Pkts {
				max = j
			}
		}
		if max != i {
			out[i], out[max] = out[max], out[i]
		}
		if i+1 >= limit {
			break
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// ---- helpers ----------------------------------------------------------

// IPToPrefix builds a /32 or /128 prefix from an IP address.
func IPToPrefix(ip net.IP) (netip.Prefix, error) {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Prefix{}, fmt.Errorf("bad IP %v", ip)
	}
	a = a.Unmap()
	bits := 32
	if a.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(a, bits), nil
}
