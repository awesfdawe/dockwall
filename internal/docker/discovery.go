package docker

import (
	"context"
	"fmt"
	"strings"

	"github.com/awesfdawe/dockwall/internal/config"
	"github.com/awesfdawe/dockwall/internal/firewall"
	"github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

type NetworkInspector interface {
	NetworkInspect(ctx context.Context, networkID string, options client.NetworkInspectOptions) (client.NetworkInspectResult, error)
}

type Discoverer struct {
	client NetworkInspector
}

func NewDiscoverer(inspector NetworkInspector) *Discoverer {
	return &Discoverer{client: inspector}
}

func BridgeName(inspect network.Inspect) string {
	if custom, ok := inspect.Options["com.docker.network.bridge.name"]; ok && custom != "" {
		return custom
	}
	if inspect.Name == "bridge" || inspect.ID == "bridge" {
		return "docker0"
	}
	id := inspect.ID
	if len(id) > 12 {
		id = id[:12]
	}
	return "br-" + id
}

func (d *Discoverer) ResolvePolicies(ctx context.Context, policies []config.Policy) ([]firewall.NetworkPolicy, error) {
	var resolved []firewall.NetworkPolicy

	for _, p := range policies {
		res, err := d.client.NetworkInspect(ctx, p.Network, client.NetworkInspectOptions{})
		if err != nil {
			if errdefs.IsNotFound(err) || strings.Contains(strings.ToLower(err.Error()), "not found") {
				continue
			}
			return nil, fmt.Errorf("inspecting network %s: %w", p.Network, err)
		}

		br := BridgeName(res.Network)
		np := firewall.NetworkPolicy{
			BridgeName: br,
		}

		for _, r := range p.Rules {
			var fromIP, toIP string

			if r.From != "*" {
				fromIP = findContainerIP(res.Network, r.From)
				if fromIP == "" {
					continue
				}
			}

			if r.To != "*" {
				toIP = findContainerIP(res.Network, r.To)
				if toIP == "" {
					continue
				}
			}

			np.Rules = append(np.Rules, firewall.RuleTarget{
				FromIP: fromIP,
				ToIP:   toIP,
			})
		}

		resolved = append(resolved, np)
	}

	return resolved, nil
}

func findContainerIP(inspect network.Inspect, targetName string) string {
	target := strings.TrimPrefix(targetName, "/")
	for _, ep := range inspect.Containers {
		name := strings.TrimPrefix(ep.Name, "/")
		if strings.EqualFold(name, target) {
			if ep.IPv4Address.IsValid() && !ep.IPv4Address.Addr().IsUnspecified() {
				return ep.IPv4Address.Addr().String()
			}
		}
	}
	return ""
}
