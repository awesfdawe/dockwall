package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/awesfdawe/dockwall/internal/config"
	"github.com/awesfdawe/dockwall/internal/controller"
	"github.com/awesfdawe/dockwall/internal/firewall"
	"github.com/awesfdawe/dockwall/internal/syscheck"
	"github.com/moby/moby/client"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	if err := syscheck.CheckBrNetfilter(); err != nil {
		log.Fatalf("kernel check failed: %v", err)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	dockerCli, err := client.New(client.FromEnv)
	if err != nil {
		log.Fatalf("failed to connect to docker: %v", err)
	}
	defer func() {
		_ = dockerCli.Close()
	}()

	fw, err := firewall.New()
	if err != nil {
		log.Fatalf("failed to initialize firewall: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ctrl := controller.New(cfg, dockerCli, fw)

	log.Printf("dockwall started with %d policies", len(cfg.Policies))
	if err := ctrl.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("dockwall error: %v", err)
	}
	log.Println("dockwall stopped")
}
