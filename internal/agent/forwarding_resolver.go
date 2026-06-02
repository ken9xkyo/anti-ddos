package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	defaultNeighborProbeTimeout  = 2 * time.Second
	defaultNeighborProbeInterval = 100 * time.Millisecond
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
	ResolveService(context.Context, ServiceResolveRequest) (ResolvedService, error)
}

type netlinkClient interface {
	LinkByName(string) (netlink.Link, error)
	RouteGet(net.IP) ([]netlink.Route, error)
	NeighList(int, int) ([]netlink.Neigh, error)
	NeighSet(*netlink.Neigh) error
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

func (systemNetlinkClient) NeighSet(neighbor *netlink.Neigh) error {
	return netlink.NeighSet(neighbor)
}

type NetlinkForwardingResolver struct {
	client                netlinkClient
	neighborProbeTimeout  time.Duration
	neighborProbeInterval time.Duration
}

// NetlinkForwardingResolverOption customizes netlink forwarding resolution.
type NetlinkForwardingResolverOption func(*NetlinkForwardingResolver)

// WithNeighborProbeTiming configures the active neighbor probe wait window.
func WithNeighborProbeTiming(timeout, interval time.Duration) NetlinkForwardingResolverOption {
	return func(r *NetlinkForwardingResolver) {
		if timeout < 0 {
			timeout = 0
		}
		if interval < 0 {
			interval = 0
		}
		r.neighborProbeTimeout = timeout
		r.neighborProbeInterval = interval
	}
}

// NewNetlinkForwardingResolver creates a resolver backed by host netlink.
func NewNetlinkForwardingResolver(options ...NetlinkForwardingResolverOption) *NetlinkForwardingResolver {
	return newNetlinkForwardingResolver(systemNetlinkClient{}, options...)
}

func newNetlinkForwardingResolver(client netlinkClient, options ...NetlinkForwardingResolverOption) *NetlinkForwardingResolver {
	resolver := &NetlinkForwardingResolver{
		client:                client,
		neighborProbeTimeout:  defaultNeighborProbeTimeout,
		neighborProbeInterval: defaultNeighborProbeInterval,
	}
	for _, option := range options {
		if option != nil {
			option(resolver)
		}
	}
	return resolver
}

func (r *NetlinkForwardingResolver) ResolveService(ctx context.Context, req ServiceResolveRequest) (ResolvedService, error) {
	if r == nil || r.client == nil {
		return ResolvedService{}, errors.New("nil forwarding resolver")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return ResolvedService{}, fmt.Errorf("resolve forwarding cancelled: %w", err)
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

	neighbor, dstMAC, err := r.resolveNeighbor(ctx, attrs.Index, req.OutputInterface, neighborIP)
	if err != nil {
		return ResolvedService{}, err
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
			OutputInterface:    req.OutputInterface,
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

func (r *NetlinkForwardingResolver) resolveNeighbor(ctx context.Context, ifindex int, ifname string, target net.IP) (netlink.Neigh, net.HardwareAddr, error) {
	neighbor, dstMAC, resolved, _, err := r.lookupResolvedNeighbor(ifindex, ifname, target)
	if err != nil {
		return netlink.Neigh{}, nil, err
	}
	if resolved {
		return neighbor, dstMAC, nil
	}
	if err := ctx.Err(); err != nil {
		return netlink.Neigh{}, nil, fmt.Errorf("neighbor probe for %s on %s cancelled: %w", target.String(), ifname, err)
	}
	if err := r.probeNeighbor(ifindex, ifname, target); err != nil {
		return netlink.Neigh{}, nil, err
	}
	return r.waitForResolvedNeighbor(ctx, ifindex, ifname, target)
}

func (r *NetlinkForwardingResolver) lookupResolvedNeighbor(ifindex int, ifname string, target net.IP) (netlink.Neigh, net.HardwareAddr, bool, string, error) {
	neighs, err := r.client.NeighList(ifindex, netlink.FAMILY_V4)
	if err != nil {
		return netlink.Neigh{}, nil, false, "", fmt.Errorf("neighbor lookup on %s: %w", ifname, err)
	}
	neighbor, ok := selectNeighbor(neighs, target)
	if !ok {
		return netlink.Neigh{}, nil, false, "missing", nil
	}
	state := neighborStateName(neighbor.State)
	if !isResolvedNeighborState(neighbor.State) {
		return neighbor, nil, false, state, nil
	}
	dstMAC, err := validateHardwareAddr(neighbor.HardwareAddr)
	if err != nil {
		return netlink.Neigh{}, nil, false, state, fmt.Errorf("neighbor %s MAC: %w", target.String(), err)
	}
	return neighbor, dstMAC, true, state, nil
}

func (r *NetlinkForwardingResolver) probeNeighbor(ifindex int, ifname string, target net.IP) error {
	neighbor := &netlink.Neigh{
		LinkIndex: ifindex,
		Family:    netlink.FAMILY_V4,
		State:     unix.NUD_NONE,
		Type:      unix.RTN_UNICAST,
		Flags:     netlink.NTF_USE,
		IP:        cloneIP(target),
	}
	if err := r.client.NeighSet(neighbor); err != nil {
		return fmt.Errorf("neighbor probe for %s on %s: %w", target.String(), ifname, err)
	}
	return nil
}

func (r *NetlinkForwardingResolver) waitForResolvedNeighbor(ctx context.Context, ifindex int, ifname string, target net.IP) (netlink.Neigh, net.HardwareAddr, error) {
	if r.neighborProbeTimeout <= 0 || r.neighborProbeInterval <= 0 {
		return r.checkResolvedNeighborAfterProbe(ctx, ifindex, ifname, target)
	}

	waitCtx, cancel := context.WithTimeout(ctx, r.neighborProbeTimeout)
	defer cancel()
	for {
		if err := waitCtx.Err(); err != nil {
			return netlink.Neigh{}, nil, r.neighborWaitError(ctx, ifname, target, "")
		}
		neighbor, dstMAC, resolved, lastState, err := r.lookupResolvedNeighbor(ifindex, ifname, target)
		if err != nil {
			return netlink.Neigh{}, nil, err
		}
		if resolved {
			return neighbor, dstMAC, nil
		}
		timer := time.NewTimer(r.neighborProbeInterval)
		select {
		case <-waitCtx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return netlink.Neigh{}, nil, r.neighborWaitError(ctx, ifname, target, lastState)
		case <-timer.C:
		}
	}
}

func (r *NetlinkForwardingResolver) checkResolvedNeighborAfterProbe(ctx context.Context, ifindex int, ifname string, target net.IP) (netlink.Neigh, net.HardwareAddr, error) {
	if err := ctx.Err(); err != nil {
		return netlink.Neigh{}, nil, r.neighborWaitError(ctx, ifname, target, "")
	}
	neighbor, dstMAC, resolved, lastState, err := r.lookupResolvedNeighbor(ifindex, ifname, target)
	if err != nil {
		return netlink.Neigh{}, nil, err
	}
	if resolved {
		return neighbor, dstMAC, nil
	}
	return netlink.Neigh{}, nil, r.neighborWaitError(context.Background(), ifname, target, lastState)
}

func (r *NetlinkForwardingResolver) neighborWaitError(ctx context.Context, ifname string, target net.IP, lastState string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("neighbor probe for %s on %s cancelled: %w", target.String(), ifname, err)
	}
	message := fmt.Sprintf("neighbor %s on %s is unresolved after probe timeout %s", target.String(), ifname, r.neighborProbeTimeout)
	if lastState != "" && lastState != "missing" {
		message += fmt.Sprintf(" (last state %s)", lastState)
	}
	return errors.New(message)
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

func cloneIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
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
