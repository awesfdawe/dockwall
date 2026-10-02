package controller

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/awesfdawe/dockwall/internal/config"
	"github.com/awesfdawe/dockwall/internal/docker"
	"github.com/awesfdawe/dockwall/internal/firewall"
	"github.com/moby/moby/client"
)

type DockerClient interface {
	docker.NetworkInspector
	Events(ctx context.Context, options client.EventsListOptions) client.EventsResult
}

type FirewallSyncer interface {
	Sync(policies []firewall.NetworkPolicy) error
	Cleanup() error
}

type Controller struct {
	cfg            *config.Config
	dockerCli      DockerClient
	discoverer     *docker.Discoverer
	firewall       FirewallSyncer
	reconcileFn    func(ctx context.Context) error
	reconnectDelay time.Duration
}

func New(cfg *config.Config, dockerCli DockerClient, fw FirewallSyncer) *Controller {
	c := &Controller{
		cfg:            cfg,
		dockerCli:      dockerCli,
		discoverer:     docker.NewDiscoverer(dockerCli),
		firewall:       fw,
		reconnectDelay: 2 * time.Second,
	}
	c.reconcileFn = c.reconcile
	return c
}

func (c *Controller) Run(ctx context.Context) error {
	defer func() {
		if err := c.firewall.Cleanup(); err != nil {
			log.Printf("cleanup error: %v", err)
		}
	}()

	if err := c.reconcileFn(ctx); err != nil {
		log.Printf("initial sync error: %v", err)
	}

	ticker := time.NewTicker(c.cfg.PollInterval)
	defer ticker.Stop()

	eventsCh := make(chan struct{}, 100)
	reconnectCh := make(chan struct{}, 1)

	go c.watchEvents(ctx, eventsCh, reconnectCh)

	var debounceTimer *time.Timer
	var debounceCh <-chan time.Time

	for {
		select {
		case <-ctx.Done():
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return ctx.Err()

		case <-eventsCh:
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			debounceTimer = time.NewTimer(c.cfg.Debounce)
			debounceCh = debounceTimer.C

		case <-debounceCh:
			debounceCh = nil
			if err := c.reconcileFn(ctx); err != nil {
				log.Printf("reconcile error: %v", err)
			}

		case <-ticker.C:
			if err := c.reconcileFn(ctx); err != nil {
				log.Printf("periodic sync error: %v", err)
			}

		case <-reconnectCh:
			log.Printf("reconnected to docker, syncing rules")
			if err := c.reconcileFn(ctx); err != nil {
				log.Printf("reconnect sync error: %v", err)
			}
		}
	}
}

func (c *Controller) watchEvents(ctx context.Context, eventsCh chan<- struct{}, reconnectCh chan<- struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		res := c.dockerCli.Events(ctx, client.EventsListOptions{
			Filters: client.Filters{}.Add("type", "container", "network"),
		})

	eventLoop:
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-res.Messages:
				if !ok {
					break eventLoop
				}
				select {
				case eventsCh <- struct{}{}:
				default:
				}
			case <-res.Err:
				break eventLoop
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(c.reconnectDelay):
		}

		select {
		case reconnectCh <- struct{}{}:
		default:
		}
	}
}

func (c *Controller) reconcile(ctx context.Context) error {
	resolved, err := c.discoverer.ResolvePolicies(ctx, c.cfg.Policies)
	if err != nil {
		return fmt.Errorf("resolving policies: %w", err)
	}
	if err := c.firewall.Sync(resolved); err != nil {
		return fmt.Errorf("syncing firewall: %w", err)
	}
	return nil
}
