package docker

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/awesfdawe/dockwall/internal/config"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

type mockNetworkInspector struct {
	networks map[string]network.Inspect
	err      error
}

func (m *mockNetworkInspector) NetworkInspect(_ context.Context, networkID string, _ client.NetworkInspectOptions) (client.NetworkInspectResult, error) {
	if m.err != nil {
		return client.NetworkInspectResult{}, m.err
	}
	n, ok := m.networks[networkID]
	if !ok {
		return client.NetworkInspectResult{}, errors.New("network not found")
	}
	return client.NetworkInspectResult{Network: n}, nil
}

func TestBridgeName(t *testing.T) {
	cases := []struct {
		name     string
		inspect  network.Inspect
		expected string
	}{
		{
			name: "custom bridge name",
			inspect: network.Inspect{
				Network: network.Network{
					Options: map[string]string{
						"com.docker.network.bridge.name": "my-custom-br",
					},
				},
			},
			expected: "my-custom-br",
		},
		{
			name: "default docker bridge",
			inspect: network.Inspect{
				Network: network.Network{
					Name: "bridge",
					ID:   "some-id",
				},
			},
			expected: "docker0",
		},
		{
			name: "standard user defined bridge",
			inspect: network.Inspect{
				Network: network.Network{
					ID: "abcdef1234567890abcdef",
				},
			},
			expected: "br-abcdef123456",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := BridgeName(tc.inspect)
			if got != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, got)
			}
		})
	}
}

func TestResolvePolicies(t *testing.T) {
	proxyIP := netip.MustParsePrefix("172.20.0.2/16")
	xrayIP := netip.MustParsePrefix("172.21.0.2/16")

	mock := &mockNetworkInspector{
		networks: map[string]network.Inspect{
			"proxy": {
				Network: network.Network{
					ID:   "1111222233334444",
					Name: "proxy",
				},
				Containers: map[string]network.EndpointResource{
					"c1": {
						Name:        "/reverse-proxy",
						IPv4Address: proxyIP,
					},
					"c2": {
						Name:        "/service-1",
						IPv4Address: netip.MustParsePrefix("172.20.0.3/16"),
					},
				},
			},
			"bypass": {
				Network: network.Network{
					ID:   "5555666677778888",
					Name: "bypass",
				},
				Containers: map[string]network.EndpointResource{
					"c3": {
						Name:        "xray-core",
						IPv4Address: xrayIP,
					},
					"c4": {
						Name:        "client-1",
						IPv4Address: netip.MustParsePrefix("172.21.0.3/16"),
					},
				},
			},
		},
	}

	d := NewDiscoverer(mock)
	policies := []config.Policy{
		{
			Network: "proxy",
			Rules: []config.Rule{
				{From: "reverse-proxy", To: "*"},
			},
		},
		{
			Network: "bypass",
			Rules: []config.Rule{
				{From: "*", To: "xray-core"},
			},
		},
	}

	resolved, err := d.ResolvePolicies(context.Background(), policies)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(resolved) != 2 {
		t.Fatalf("expected 2 resolved policies, got %d", len(resolved))
	}

	if resolved[0].BridgeName != "br-111122223333" {
		t.Errorf("expected bridge br-111122223333, got %s", resolved[0].BridgeName)
	}
	if len(resolved[0].Rules) != 1 {
		t.Fatalf("expected 1 rule in policy 0, got %d", len(resolved[0].Rules))
	}
	if resolved[0].Rules[0].FromIP != "172.20.0.2" || resolved[0].Rules[0].ToIP != "" {
		t.Errorf("unexpected rule in policy 0: %+v", resolved[0].Rules[0])
	}

	if resolved[1].BridgeName != "br-555566667777" {
		t.Errorf("expected bridge br-555566667777, got %s", resolved[1].BridgeName)
	}
	if len(resolved[1].Rules) != 1 {
		t.Fatalf("expected 1 rule in policy 1, got %d", len(resolved[1].Rules))
	}
	if resolved[1].Rules[0].FromIP != "" || resolved[1].Rules[0].ToIP != "172.21.0.2" {
		t.Errorf("unexpected rule in policy 1: %+v", resolved[1].Rules[0])
	}
}

func TestResolvePolicies_NetworkNotFound(t *testing.T) {
	mock := &mockNetworkInspector{
		networks: map[string]network.Inspect{},
	}
	d := NewDiscoverer(mock)
	policies := []config.Policy{
		{
			Network: "nonexistent",
			Rules:   []config.Rule{{From: "a", To: "*"}},
		},
	}
	resolved, err := d.ResolvePolicies(context.Background(), policies)
	if err != nil {
		t.Fatalf("expected nil error for missing network, got: %v", err)
	}
	if len(resolved) != 0 {
		t.Errorf("expected 0 resolved policies, got %d", len(resolved))
	}
}

func TestResolvePolicies_FatalError(t *testing.T) {
	mock := &mockNetworkInspector{
		err: errors.New("daemon connection failed"),
	}
	d := NewDiscoverer(mock)
	policies := []config.Policy{
		{
			Network: "proxy",
			Rules:   []config.Rule{{From: "a", To: "*"}},
		},
	}
	_, err := d.ResolvePolicies(context.Background(), policies)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
