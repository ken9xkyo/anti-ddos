package agent

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type fakeNetlinkClient struct {
	link              netlink.Link
	linkErr           error
	routes            []netlink.Route
	routeErr          error
	neighs            []netlink.Neigh
	neighLists        [][]netlink.Neigh
	neighErr          error
	neighSetErr       error
	neighSetCalls     int
	neighSetRequests  []netlink.Neigh
	afterNeighSetFunc func()
}

func (f *fakeNetlinkClient) LinkByName(string) (netlink.Link, error) {
	if f.linkErr != nil {
		return nil, f.linkErr
	}
	return f.link, nil
}

func (f *fakeNetlinkClient) RouteGet(net.IP) ([]netlink.Route, error) {
	if f.routeErr != nil {
		return nil, f.routeErr
	}
	return f.routes, nil
}

func (f *fakeNetlinkClient) NeighList(int, int) ([]netlink.Neigh, error) {
	if f.neighErr != nil {
		return nil, f.neighErr
	}
	if len(f.neighLists) > 0 {
		neighs := f.neighLists[0]
		if len(f.neighLists) > 1 {
			f.neighLists = f.neighLists[1:]
		}
		return neighs, nil
	}
	return f.neighs, nil
}

func (f *fakeNetlinkClient) NeighSet(neighbor *netlink.Neigh) error {
	f.neighSetCalls++
	if neighbor != nil {
		f.neighSetRequests = append(f.neighSetRequests, *neighbor)
	}
	if f.afterNeighSetFunc != nil {
		f.afterNeighSetFunc()
	}
	if f.neighSetErr != nil {
		return f.neighSetErr
	}
	return nil
}

func TestNetlinkForwardingResolverResolvesService(t *testing.T) {
	client := fakeResolvedClient(unix.NUD_STALE)
	resolver := newNetlinkForwardingResolver(client)

	resolved, err := resolver.ResolveService(context.Background(), testResolveRequest())
	if err != nil {
		t.Fatalf("ResolveService() error = %v", err)
	}
	if client.neighSetCalls != 0 {
		t.Fatalf("NeighSet calls = %d, want 0 for already resolved neighbor", client.neighSetCalls)
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

func TestNetlinkForwardingResolverProbesMissingNeighbor(t *testing.T) {
	client := &fakeNetlinkClient{
		link:   testLink(net.FlagUp, testMAC(1)),
		routes: []netlink.Route{{LinkIndex: 7}},
		neighLists: [][]netlink.Neigh{
			{},
			{testNeighbor(unix.NUD_REACHABLE)},
		},
	}
	resolver := newNetlinkForwardingResolver(client, WithNeighborProbeTiming(0, 0))

	resolved, err := resolver.ResolveService(context.Background(), testResolveRequest())
	if err != nil {
		t.Fatalf("ResolveService() error = %v", err)
	}
	if resolved.Service.DstMAC != "02:00:00:00:00:02" {
		t.Fatalf("unexpected resolved service: %#v", resolved.Service)
	}
	if client.neighSetCalls != 1 {
		t.Fatalf("NeighSet calls = %d, want 1", client.neighSetCalls)
	}
	probe := client.neighSetRequests[0]
	if probe.LinkIndex != 7 || probe.Family != netlink.FAMILY_V4 || probe.State != unix.NUD_NONE || probe.Type != unix.RTN_UNICAST || probe.Flags != netlink.NTF_USE {
		t.Fatalf("unexpected neighbor probe request: %#v", probe)
	}
	if !probe.IP.Equal(net.IPv4(203, 0, 113, 10)) {
		t.Fatalf("neighbor probe IP = %s, want 203.0.113.10", probe.IP)
	}
}

func TestNetlinkForwardingResolverRefreshesUnresolvedNeighbor(t *testing.T) {
	tests := []struct {
		name  string
		state int
	}{
		{name: "failed", state: unix.NUD_FAILED},
		{name: "incomplete", state: unix.NUD_INCOMPLETE},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeNetlinkClient{
				link:   testLink(net.FlagUp, testMAC(1)),
				routes: []netlink.Route{{LinkIndex: 7}},
				neighLists: [][]netlink.Neigh{
					{testNeighbor(tc.state)},
					{testNeighbor(unix.NUD_REACHABLE)},
				},
			}
			resolver := newNetlinkForwardingResolver(client, WithNeighborProbeTiming(0, 0))

			resolved, err := resolver.ResolveService(context.Background(), testResolveRequest())
			if err != nil {
				t.Fatalf("ResolveService() error = %v", err)
			}
			if resolved.NeighborState != "reachable" {
				t.Fatalf("neighbor state = %q, want reachable", resolved.NeighborState)
			}
			if client.neighSetCalls != 1 {
				t.Fatalf("NeighSet calls = %d, want 1", client.neighSetCalls)
			}
		})
	}
}

func TestNetlinkForwardingResolverRejectsProbeFailure(t *testing.T) {
	client := &fakeNetlinkClient{
		link:        testLink(net.FlagUp, testMAC(1)),
		routes:      []netlink.Route{{LinkIndex: 7}},
		neighLists:  [][]netlink.Neigh{{}},
		neighSetErr: errors.New("operation not permitted"),
	}
	resolver := newNetlinkForwardingResolver(client, WithNeighborProbeTiming(0, 0))

	if _, err := resolver.ResolveService(context.Background(), testResolveRequest()); err == nil || !strings.Contains(err.Error(), "neighbor probe") || !strings.Contains(err.Error(), "operation not permitted") {
		t.Fatalf("ResolveService() error = %v, want neighbor probe failure", err)
	}
	if client.neighSetCalls != 1 {
		t.Fatalf("NeighSet calls = %d, want 1", client.neighSetCalls)
	}
}

func TestNetlinkForwardingResolverTimesOutWhenProbeDoesNotResolve(t *testing.T) {
	client := &fakeNetlinkClient{
		link:   testLink(net.FlagUp, testMAC(1)),
		routes: []netlink.Route{{LinkIndex: 7}},
		neighLists: [][]netlink.Neigh{
			{},
			{},
		},
	}
	resolver := newNetlinkForwardingResolver(client, WithNeighborProbeTiming(0, 0))

	if _, err := resolver.ResolveService(context.Background(), testResolveRequest()); err == nil || !strings.Contains(err.Error(), "unresolved after probe timeout") {
		t.Fatalf("ResolveService() error = %v, want probe timeout", err)
	}
	if client.neighSetCalls != 1 {
		t.Fatalf("NeighSet calls = %d, want 1", client.neighSetCalls)
	}
}

func TestNetlinkForwardingResolverStopsPollingWhenContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &fakeNetlinkClient{
		link:   testLink(net.FlagUp, testMAC(1)),
		routes: []netlink.Route{{LinkIndex: 7}},
		neighLists: [][]netlink.Neigh{
			{},
			{},
		},
		afterNeighSetFunc: cancel,
	}
	resolver := newNetlinkForwardingResolver(client)

	if _, err := resolver.ResolveService(ctx, testResolveRequest()); !errors.Is(err, context.Canceled) {
		t.Fatalf("ResolveService() error = %v, want context.Canceled", err)
	}
	if client.neighSetCalls != 1 {
		t.Fatalf("NeighSet calls = %d, want 1", client.neighSetCalls)
	}
}

func TestNetlinkForwardingResolverRejectsInvalidTargets(t *testing.T) {
	tests := []struct {
		name   string
		client *fakeNetlinkClient
		want   string
	}{
		{
			name: "link down",
			client: &fakeNetlinkClient{
				link: testLink(0, testMAC(1)),
			},
			want: "is down",
		},
		{
			name: "route mismatch",
			client: &fakeNetlinkClient{
				link:   testLink(net.FlagUp, testMAC(1)),
				routes: []netlink.Route{{LinkIndex: 8}},
			},
			want: "no route",
		},
		{
			name:   "neighbor failed",
			client: fakeResolvedClient(unix.NUD_FAILED),
			want:   "last state failed",
		},
		{
			name: "neighbor missing mac",
			client: &fakeNetlinkClient{
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
			client: &fakeNetlinkClient{
				linkErr: errors.New("missing"),
			},
			want: "lookup output interface",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolver := newNetlinkForwardingResolver(tc.client, WithNeighborProbeTiming(0, 0))
			if _, err := resolver.ResolveService(context.Background(), testResolveRequest()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ResolveService() error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestNetlinkForwardingResolverValidatesServiceShape(t *testing.T) {
	req := testResolveRequest()
	req.Proto = 99
	resolver := newNetlinkForwardingResolver(fakeResolvedClient(unix.NUD_REACHABLE))

	if _, err := resolver.ResolveService(context.Background(), req); err == nil || !strings.Contains(err.Error(), "unsupported service proto") {
		t.Fatalf("ResolveService() error = %v", err)
	}
}

func fakeResolvedClient(state int) *fakeNetlinkClient {
	return &fakeNetlinkClient{
		link:   testLink(net.FlagUp, testMAC(1)),
		routes: []netlink.Route{{LinkIndex: 7}},
		neighs: []netlink.Neigh{testNeighbor(state)},
	}
}

func testNeighbor(state int) netlink.Neigh {
	return netlink.Neigh{
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
