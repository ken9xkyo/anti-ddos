package agent

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type ServiceResolveRequest struct {
	ServiceID          uint32
	ForwardingPolicyID uint32
	DstV4              string
	DstPort            uint16
	Proto              uint8
	Priority           uint32
	DefaultRuleID      uint32
	OutputInterface    string
	DevmapKey          uint32
}

type ResolvedService struct {
	Service         PolicyService
	OutputInterface string
	NeighborTarget  string
	NeighborState   string
}

type ForwardingResolver interface {
	ResolveService(ServiceResolveRequest) (ResolvedService, error)
}

type netlinkClient interface {
	LinkByName(string) (netlink.Link, error)
	RouteGet(net.IP) ([]netlink.Route, error)
	NeighList(int, int) ([]netlink.Neigh, error)
}

type systemNetlinkClient struct{}

func (systemNetlinkClient) LinkByName(name string) (netlink.Link, error) {
	return netlink.LinkByName(name)
}

func (systemNetlinkClient) RouteGet(ip net.IP) ([]netlink.Route, error) {
	return netlink.RouteGet(ip)
}

func (systemNetlinkClient) NeighList(linkIndex, family int) ([]netlink.Neigh, error) {
	return netlink.NeighList(linkIndex, family)
}

type NetlinkForwardingResolver struct {
	client netlinkClient
}

func NewNetlinkForwardingResolver() *NetlinkForwardingResolver {
	return &NetlinkForwardingResolver{client: systemNetlinkClient{}}
}

func newNetlinkForwardingResolver(client netlinkClient) *NetlinkForwardingResolver {
	return &NetlinkForwardingResolver{client: client}
}

func (r *NetlinkForwardingResolver) ResolveService(req ServiceResolveRequest) (ResolvedService, error) {
	if r == nil || r.client == nil {
		return ResolvedService{}, errors.New("nil forwarding resolver")
	}
	dstIP, err := parseResolveV4(req.DstV4)
	if err != nil {
		return ResolvedService{}, err
	}
	if strings.TrimSpace(req.OutputInterface) == "" {
		return ResolvedService{}, errors.New("output interface is required")
	}
	if err := validateResolveRequest(req); err != nil {
		return ResolvedService{}, err
	}

	link, err := r.client.LinkByName(req.OutputInterface)
	if err != nil {
		return ResolvedService{}, fmt.Errorf("lookup output interface %s: %w", req.OutputInterface, err)
	}
	attrs := link.Attrs()
	if attrs == nil || attrs.Index == 0 {
		return ResolvedService{}, fmt.Errorf("output interface %s has no ifindex", req.OutputInterface)
	}
	if attrs.Flags&net.FlagUp == 0 {
		return ResolvedService{}, fmt.Errorf("output interface %s is down", req.OutputInterface)
	}
	srcMAC, err := validateHardwareAddr(attrs.HardwareAddr)
	if err != nil {
		return ResolvedService{}, fmt.Errorf("output interface %s source MAC: %w", req.OutputInterface, err)
	}

	routes, err := r.client.RouteGet(dstIP)
	if err != nil {
		return ResolvedService{}, fmt.Errorf("route lookup for %s: %w", req.DstV4, err)
	}
	route, ok := selectOutputRoute(routes, attrs.Index)
	if !ok {
		return ResolvedService{}, fmt.Errorf("no route to %s through output interface %s ifindex %d", req.DstV4, req.OutputInterface, attrs.Index)
	}
	neighborIP := route.Gw
	if neighborIP == nil || neighborIP.To4() == nil {
		neighborIP = dstIP
	}

	neighs, err := r.client.NeighList(attrs.Index, netlink.FAMILY_V4)
	if err != nil {
		return ResolvedService{}, fmt.Errorf("neighbor lookup on %s: %w", req.OutputInterface, err)
	}
	neighbor, ok := selectNeighbor(neighs, neighborIP)
	if !ok {
		return ResolvedService{}, fmt.Errorf("neighbor %s on %s is unresolved", neighborIP.String(), req.OutputInterface)
	}
	dstMAC, err := validateHardwareAddr(neighbor.HardwareAddr)
	if err != nil {
		return ResolvedService{}, fmt.Errorf("neighbor %s MAC: %w", neighborIP.String(), err)
	}
	if !isResolvedNeighborState(neighbor.State) {
		return ResolvedService{}, fmt.Errorf("neighbor %s on %s is %s", neighborIP.String(), req.OutputInterface, neighborStateName(neighbor.State))
	}

	return ResolvedService{
		Service: PolicyService{
			ServiceID:          req.ServiceID,
			ForwardingPolicyID: req.ForwardingPolicyID,
			DstV4:              req.DstV4,
			DstPort:            req.DstPort,
			Proto:              req.Proto,
			Action:             actionRedirect,
			Priority:           req.Priority,
			DefaultRuleID:      req.DefaultRuleID,
			OutputIfindex:      uint32(attrs.Index),
			DevmapKey:          req.DevmapKey,
			NeighborStatus:     neighborResolved,
			DstMAC:             dstMAC.String(),
			SrcMAC:             srcMAC.String(),
		},
		OutputInterface: req.OutputInterface,
		NeighborTarget:  neighborIP.String(),
		NeighborState:   neighborStateName(neighbor.State),
	}, nil
}

func validateResolveRequest(req ServiceResolveRequest) error {
	if req.ServiceID == 0 {
		return errors.New("service_id must be non-zero")
	}
	switch req.Proto {
	case l4TCP, l4UDP:
		if req.DstPort == 0 {
			return errors.New("tcp/udp service dst_port must be non-zero")
		}
	case l4ICMP:
		if req.DstPort != 0 {
			return errors.New("icmp service dst_port must be 0")
		}
	default:
		return fmt.Errorf("unsupported service proto %d", req.Proto)
	}
	return nil
}

func parseResolveV4(value string) (net.IP, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return nil, err
	}
	if !addr.Is4() {
		return nil, fmt.Errorf("IPv6 address %q is not supported for forwarding resolution", value)
	}
	v4 := addr.As4()
	return net.IPv4(v4[0], v4[1], v4[2], v4[3]), nil
}

func selectOutputRoute(routes []netlink.Route, outputIfindex int) (netlink.Route, bool) {
	for _, route := range routes {
		if route.LinkIndex == outputIfindex {
			return route, true
		}
	}
	return netlink.Route{}, false
}

func selectNeighbor(neighs []netlink.Neigh, target net.IP) (netlink.Neigh, bool) {
	for _, neighbor := range neighs {
		if neighbor.IP != nil && neighbor.IP.Equal(target) {
			return neighbor, true
		}
	}
	return netlink.Neigh{}, false
}

func validateHardwareAddr(mac net.HardwareAddr) (net.HardwareAddr, error) {
	if len(mac) != 6 {
		return nil, fmt.Errorf("expected 6-byte MAC, got %d bytes", len(mac))
	}
	var zero [6]byte
	if copyAndCompareMAC(mac, zero) {
		return nil, errors.New("zero MAC is not allowed")
	}
	out := make(net.HardwareAddr, 6)
	copy(out, mac)
	return out, nil
}

func copyAndCompareMAC(mac net.HardwareAddr, value [6]byte) bool {
	for i := 0; i < 6; i++ {
		if mac[i] != value[i] {
			return false
		}
	}
	return true
}

func isResolvedNeighborState(state int) bool {
	switch state {
	case unix.NUD_REACHABLE, unix.NUD_STALE, unix.NUD_DELAY, unix.NUD_PROBE, unix.NUD_PERMANENT:
		return true
	default:
		return false
	}
}

func neighborStateName(state int) string {
	switch state {
	case unix.NUD_INCOMPLETE:
		return "incomplete"
	case unix.NUD_REACHABLE:
		return "reachable"
	case unix.NUD_STALE:
		return "stale"
	case unix.NUD_DELAY:
		return "delay"
	case unix.NUD_PROBE:
		return "probe"
	case unix.NUD_FAILED:
		return "failed"
	case unix.NUD_NOARP:
		return "noarp"
	case unix.NUD_PERMANENT:
		return "permanent"
	default:
		return fmt.Sprintf("unknown:%d", state)
	}
}
