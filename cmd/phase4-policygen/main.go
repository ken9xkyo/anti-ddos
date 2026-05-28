package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/ken9xkyo/anti-ddos/internal/agent"
)

const (
	actionDrop     = 1
	actionRedirect = 6
	neighborOK     = 1
)

func main() {
	var (
		outPath            = flag.String("out", "", "path to write signed policy snapshot")
		xdpObject          = flag.String("xdp-object", "build/bpf/xdp_data_plane.bpf.o", "XDP object used for object checksum")
		version            = flag.Uint("version", 4, "policy snapshot version")
		serviceID          = flag.Uint("service-id", 40, "service id")
		forwardingPolicyID = flag.Uint("forwarding-policy-id", 400, "forwarding policy id")
		dstV4              = flag.String("dst-v4", "", "protected destination IPv4")
		dstPort            = flag.Uint("dst-port", 5300, "allowed destination port")
		proto              = flag.Uint("proto", 17, "L4 protocol number")
		outputIfindex      = flag.Uint("output-ifindex", 0, "resolved output interface ifindex")
		devmapKey          = flag.Uint("devmap-key", 4, "DEVMAP key")
		dstMAC             = flag.String("dst-mac", "", "resolved next-hop/backend destination MAC")
		srcMAC             = flag.String("src-mac", "", "source MAC for output interface")
		sampleDenom        = flag.Uint("sample-denom", 0, "event sample denominator")
	)
	flag.Parse()

	if *outPath == "" || *dstV4 == "" || *outputIfindex == 0 || *dstMAC == "" || *srcMAC == "" {
		fmt.Fprintln(os.Stderr, "out, dst-v4, output-ifindex, dst-mac and src-mac are required")
		os.Exit(2)
	}

	objectChecksum, err := agent.FileSHA256(*xdpObject)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hash xdp object: %v\n", err)
		os.Exit(1)
	}

	snapshot := agent.PolicySnapshot{
		SchemaVersion:  1,
		Version:        uint32(*version),
		ObjectChecksum: objectChecksum,
		FeatureFlags:   []string{"policy_snapshot_v1", "ipv4", "ab_policy_maps", "tx_devmap"},
		Runtime: agent.PolicyRuntimeConfig{
			MalformedPolicy: actionDrop,
			SampleDenom:     uint32(*sampleDenom),
		},
		Services: []agent.PolicyService{{
			ServiceID:          uint32(*serviceID),
			ForwardingPolicyID: uint32(*forwardingPolicyID),
			DstV4:              *dstV4,
			DstPort:            uint16(*dstPort),
			Proto:              uint8(*proto),
			Action:             actionRedirect,
			Priority:           10,
			OutputIfindex:      uint32(*outputIfindex),
			DevmapKey:          uint32(*devmapKey),
			NeighborStatus:     neighborOK,
			DstMAC:             *dstMAC,
			SrcMAC:             *srcMAC,
		}},
	}
	snapshot, err = agent.SignPolicySnapshot(snapshot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign policy snapshot: %v\n", err)
		os.Exit(1)
	}

	raw, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode policy snapshot: %v\n", err)
		os.Exit(1)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(*outPath, raw, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "write policy snapshot: %v\n", err)
		os.Exit(1)
	}
}
