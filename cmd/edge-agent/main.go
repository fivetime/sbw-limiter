// Command edge-agent runs on each edge: it subscribes to the controller's
// desired state, materializes it into BIRD (anchors) and VPP (policer/classify/
// ABF/uRPF) via the control socket and govpp, and reconciles every 60s.
// See DESIGN.md §7.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/fivetime/sbw-contract/buildinfo"
	"github.com/fivetime/sbw-contract/logx"
	"github.com/fivetime/sbw-limiter/internal/agent"
)

func main() {
	cfgPath := flag.String("config", "", "path to JSON config file (optional; env overrides apply)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(buildinfo.String())
		return
	}

	cfg, cfgErr := agent.LoadConfig(*cfgPath)

	log, err := logx.New(cfg.Log, os.Stderr)
	if err != nil {
		log = logx.Default()
		log.Warn("invalid log config; falling back to defaults", "err", err)
	}
	if cfgErr != nil {
		log.Error("configuration error", "err", cfgErr)
		os.Exit(1)
	}

	log.Info("edge-agent starting",
		"version", buildinfo.Version,
		"component", "edge-agent",
		"edge_id", cfg.EdgeID,
		"bird_socket", cfg.BIRDSocketPath,
		"vpp_api_socket", cfg.VPPAPISocket,
		"reconcile_interval", cfg.ReconcileInterval.String(),
	)

	// Run as a long-lived daemon under systemd (T-504): block until SIGTERM
	// (systemctl stop) or SIGINT, then shut down cleanly so the unit reports a
	// clean stop rather than a failure.
	//
	// TODO(T-6xx): wire the controller desired-state subscription, the govpp
	// materializers + reconcile loop (agent.Reconciler.Run), the route audit
	// (agent.RouteAudit), and the anchor reloader into this run loop. Until then
	// the daemon idles; the unit lifecycle (start/restart/stop) is already real.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("edge-agent running; awaiting desired-state wiring (T-6xx). Send SIGTERM/SIGINT to stop.")
	<-ctx.Done()
	log.Info("edge-agent received shutdown signal; stopping")
}
