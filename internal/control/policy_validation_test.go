package control

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPolicyInputValidation(t *testing.T) {
	validService := ServiceInput{
		Name:                     "api",
		BackendCIDR:              "203.0.113.10/32",
		Protocol:                 "tcp",
		AllowedPorts:             []uint16{443},
		OutputInterface:          "backend0",
		Owner:                    "sre",
		ProtectionMode:           "enforce",
		ResolvedNextHopMAC:       "02:00:00:00:00:02",
		ResolvedSourceMAC:        "02:00:00:00:00:01",
		NeighborResolutionStatus: "resolved",
	}
	validForwarding := ForwardingPolicyInput{
		ServiceID:       "service-1",
		MatchProtocol:   "udp",
		MatchDstPort:    53,
		BackendTarget:   "203.0.113.53/32",
		OutputInterface: "backend0",
		Action:          "redirect",
		Owner:           "sre",
	}

	tests := []struct {
		name     string
		validate func() error
		wantErr  string
	}{
		{
			name:     "service valid",
			validate: func() error { return validateServiceInput(validService) },
		},
		{
			name: "service tcp requires ports",
			validate: func() error {
				input := validService
				input.AllowedPorts = nil
				return validateServiceInput(input)
			},
			wantErr: "require at least one allowed port",
		},
		{
			name:     "forwarding valid",
			validate: func() error { return validateForwardingPolicyInput(validForwarding) },
		},
		{
			name: "forwarding action must redirect",
			validate: func() error {
				input := validForwarding
				input.Action = "drop"
				return validateForwardingPolicyInput(input)
			},
			wantErr: "action must be redirect",
		},
		{
			name: "service scoped whitelist requires service id",
			validate: func() error {
				return validateWhitelistInput(WhitelistInput{CIDR: "198.51.100.0/24", Scope: "service", Owner: "sre"})
			},
			wantErr: "requires service_id",
		},
		{
			name: "rule rejects invalid json",
			validate: func() error {
				return validateRuleInput(RuleInput{
					Name:      "bad-json",
					Action:    "drop",
					Mode:      "enforce",
					Dimension: "source_service",
					MatchExpr: json.RawMessage(`{"broken"`),
					Owner:     "soc",
				})
			},
			wantErr: "match_expr must be valid JSON",
		},
		{
			name: "blacklist action must drop",
			validate: func() error {
				return validateBlacklistInput(BlacklistInput{CIDR: "198.51.100.10/32", Source: "manual", Action: "observe"})
			},
			wantErr: "manual blacklist action must be drop",
		},
		{
			name: "feed source rejects invalid quota metadata",
			validate: func() error {
				return validateFeedSourceInput(FeedSourceInput{Name: "internal", Type: "internal_json", QuotaMetadata: json.RawMessage(`{"broken"`)})
			},
			wantErr: "quota_metadata must be valid JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validate() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}
