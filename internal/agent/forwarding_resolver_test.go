package agent

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type fakeNetlinkClient struct {
	link     netlink.Link
	linkErr  error
	routes   []netlink.Route
	routeErr error
	neighs   []netlink.Neigh
	neighErr error
}

func (f fakeNetlinkClient) LinkByName(string) (netlink.Link, error) {
	if f.linkErr != nil {
		return nil, f.linkErr
	}
	return f.link, nil
}

func (f fakeNetlinkClient) RouteGet(net.IP) ([]netlink.Route, error) {
	if f.routeErr != nil {
		return nil, f.routeErr
	}
	return f.routes, nil
}

func (f fakeNetlinkClient) NeighList(int, int) ([]netlink.Neigh, error) {
	if f.neighErr != nil {
		return nil, f.neighErr
	}
	return f.neighs, nil
}

func TestNetlinkForwardingResolverResolvesService(t *testing.T) {
	resolver := newNetlinkForwardingResolver(fakeResolvedClient(unix.NUD_STALE))

	resolved, err := resolver.ResolveService(testResolveRequest())
	if err != nil {
		t.Fatalf("ResolveService() error = %v", err)
	}
	service := resolved.Service
	if service.OutputIfindex != 7 || service.NeighborStatus != neighborResolved {
		t.Fatalf("unexpected service metadata: %#v", service)
	}
	if service.DstMAC != "02:00:00:00:00:02" || service.SrcMAC != "02:00:00:00:00:01" {
		t.Fatalf("unexpected MAC metadata: %#v", service)
	}
	if resolved.NeighborTarget != "203.0.113.10" || resolved.NeighborState != "stale" {
		t.Fatalf("unexpected neighbor metadata: %#v", resolved)
	}
}

func TestNetlinkForwardingResolverRejectsInvalidTargets(t *testing.T) {
	tests := []struct {
		name   string
		client fakeNetlinkClient
		want   string
	}{
		{
			name: "link down",
			client: fakeNetlinkClient{
				link: testLink(0, testMAC(1)),
			},
			want: "is down",
		},
		{
			name: "route mismatch",
			client: fakeNetlinkClient{
				link:   testLink(net.FlagUp, testMAC(1)),
				routes: []netlink.Route{{LinkIndex: 8}},
			},
			want: "no route",
		},
		{
			name:   "neighbor failed",
			client: fakeResolvedClient(unix.NUD_FAILED),
			want:   "failed",
		},
		{
			name: "neighbor missing mac",
			client: fakeNetlinkClient{
				link:   testLink(net.FlagUp, testMAC(1)),
				routes: []netlink.Route{{LinkIndex: 7}},
				neighs: []netlink.Neigh{{
					LinkIndex: 7,
					IP:        net.IPv4(203, 0, 113, 10),
					State:     unix.NUD_REACHABLE,
				}},
			},
			want: "expected 6-byte MAC",
		},
		{
			name: "link lookup error",
			client: fakeNetlinkClient{
				linkErr: errors.New("missing"),
			},
			want: "lookup output interface",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolver := newNetlinkForwardingResolver(tc.client)
			if _, err := resolver.ResolveService(testResolveRequest()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ResolveService() error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestNetlinkForwardingResolverValidatesServiceShape(t *testing.T) {
	req := testResolveRequest()
	req.Proto = 99
	resolver := newNetlinkForwardingResolver(fakeResolvedClient(unix.NUD_REACHABLE))

	if _, err := resolver.ResolveService(req); err == nil || !strings.Contains(err.Error(), "unsupported service proto") {
		t.Fatalf("ResolveService() error = %v", err)
	}
}

func fakeResolvedClient(state int) fakeNetlinkClient {
	return fakeNetlinkClient{
		link:   testLink(net.FlagUp, testMAC(1)),
		routes: []netlink.Route{{LinkIndex: 7}},
		neighs: []netlink.Neigh{{
			LinkIndex:    7,
			IP:           net.IPv4(203, 0, 113, 10),
			HardwareAddr: testMAC(2),
			State:        state,
			Type:         unix.RTN_UNICAST,
			Family:       unix.AF_INET,
			Flags:        0,
			Vlan:         0,
			VNI:          0,
			MasterIndex:  0,
		}},
	}
}

func testResolveRequest() ServiceResolveRequest {
	return ServiceResolveRequest{
		ServiceID:          10,
		ForwardingPolicyID: 20,
		DstV4:              "203.0.113.10",
		DstPort:            443,
		Proto:              l4TCP,
		Priority:           10,
		OutputInterface:    "backend0",
		DevmapKey:          3,
	}
}

func testLink(flags net.Flags, mac net.HardwareAddr) netlink.Link {
	attrs := netlink.NewLinkAttrs()
	attrs.Name = "backend0"
	attrs.Index = 7
	attrs.Flags = flags
	attrs.HardwareAddr = mac
	return &netlink.Dummy{LinkAttrs: attrs}
}

func testMAC(last byte) net.HardwareAddr {
	return net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, last}
}
