package config

import (
	"fmt"
	"net/netip"
	"strings"
)

// parsePrefix accepts "1.2.3.4", "1.2.3.0/24", or IPv6 equivalents.
func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("bad address %q: %w", s, err)
	}
	bits := 32
	if a.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(a, bits), nil
}
