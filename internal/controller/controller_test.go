package controller

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awesfdawe/dockwall/internal/config"
	"github.com/awesfdawe/dockwall/internal/firewall"
	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
)

type mockDockerClient struct {
	msgCh chan events.Message
	errCh chan error
}

func newMockDockerClient() *mockDockerClient {
	return &mockDockerClient{
		msgCh: make(chan events.Message, 10),
		errCh: make(chan error, 10),
	}
}

func (m *mockDockerClient) NetworkInspect(_ context.Context, _ string, _ client.NetworkInspectOptions) (client.NetworkInspectResult, error) {
	return client.NetworkInspectResult{}, nil
}

func (m *mockDockerClient) Events(_ context.Context, _ client.EventsListOptions) client.EventsResult {
	return client.EventsResult{
		Messages: m.msgCh,
		Err:      m.errCh,
	}
}

type mockFirewall struct {
	syncCount    int32
	cleanupCount int32
}

func (m *mockFirewall) Sync(_ []firewall.NetworkPolicy) error {
	atomic.AddInt32(&m.syncCount, 1)
	return nil
}

func (m *mockFirewall) Cleanup() error {
	atomic.AddInt32(&m.cleanupCount, 1)
	return nil
}

func TestController_Debounce(t *testing.T) {
	cfg := &config.Config{
		Debounce:     50 * time.Millisecond,
		PollInterval: 10 * time.Second,
		Policies: []config.Policy{
			{Network: "test-net", Rules: []config.Rule{{From: "a", To: "*"}}},
		},
	}

	dockerCli := newMockDockerClient()
	fw := &mockFirewall{}
	ctrl := New(cfg, dockerCli, fw)

	var reconcileCalls int32
	ctrl.reconcileFn = func(_ context.Context) error {
		atomic.AddInt32(&reconcileCalls, 1)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan struct{})
	go func() {
		_ = ctrl.Run(ctx)
		close(runDone)
	}()

	time.Sleep(20 * time.Millisecond)
	if atomic.LoadInt32(&reconcileCalls) != 1 {
		t.Fatalf("expected initial reconcile, got %d", atomic.LoadInt32(&reconcileCalls))
	}

	for i := 0; i < 5; i++ {
		dockerCli.msgCh <- events.Message{Type: "container", Action: "start"}
		time.Sleep(10 * time.Millisecond)
	}

	if atomic.LoadInt32(&reconcileCalls) != 1 {
		t.Fatalf("expected no reconcile during debouncing, got %d", atomic.LoadInt32(&reconcileCalls))
	}

	time.Sleep(80 * time.Millisecond)

	if atomic.LoadInt32(&reconcileCalls) != 2 {
		t.Fatalf("expected 2 reconcile calls after debounce, got %d", atomic.LoadInt32(&reconcileCalls))
	}

	cancel()
	<-runDone

	if atomic.LoadInt32(&fw.cleanupCount) != 1 {
		t.Fatalf("expected cleanup on exit, got %d", atomic.LoadInt32(&fw.cleanupCount))
	}
}

func TestController_Polling(t *testing.T) {
	cfg := &config.Config{
		Debounce:     50 * time.Millisecond,
		PollInterval: 60 * time.Millisecond,
		Policies: []config.Policy{
			{Network: "test-net", Rules: []config.Rule{{From: "a", To: "*"}}},
		},
	}

	dockerCli := newMockDockerClient()
	fw := &mockFirewall{}
	ctrl := New(cfg, dockerCli, fw)

	var reconcileCalls int32
	ctrl.reconcileFn = func(_ context.Context) error {
		atomic.AddInt32(&reconcileCalls, 1)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan struct{})
	go func() {
		_ = ctrl.Run(ctx)
		close(runDone)
	}()

	time.Sleep(150 * time.Millisecond)

	cancel()
	<-runDone

	calls := atomic.LoadInt32(&reconcileCalls)
	if calls < 2 {
		t.Fatalf("expected at least 2 reconcile calls from polling, got %d", calls)
	}
}

func TestController_Reconnect(t *testing.T) {
	cfg := &config.Config{
		Debounce:     50 * time.Millisecond,
		PollInterval: 10 * time.Second,
		Policies: []config.Policy{
			{Network: "test-net", Rules: []config.Rule{{From: "a", To: "*"}}},
		},
	}

	dockerCli := newMockDockerClient()
	fw := &mockFirewall{}
	ctrl := New(cfg, dockerCli, fw)
	ctrl.reconnectDelay = 20 * time.Millisecond

	var reconcileCalls int32
	ctrl.reconcileFn = func(_ context.Context) error {
		atomic.AddInt32(&reconcileCalls, 1)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan struct{})
	go func() {
		_ = ctrl.Run(ctx)
		close(runDone)
	}()

	time.Sleep(20 * time.Millisecond)
	if atomic.LoadInt32(&reconcileCalls) != 1 {
		t.Fatalf("expected initial reconcile, got %d", atomic.LoadInt32(&reconcileCalls))
	}

	dockerCli.errCh <- errors.New("connection reset by peer")

	time.Sleep(60 * time.Millisecond)

	if atomic.LoadInt32(&reconcileCalls) < 2 {
		t.Fatalf("expected reconcile call after reconnect, got %d", atomic.LoadInt32(&reconcileCalls))
	}

	cancel()
	<-runDone
}
