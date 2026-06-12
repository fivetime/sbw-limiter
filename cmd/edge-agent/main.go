// Command edge-agent runs on each edge: it subscribes to the controller's
// desired state, materializes it into BIRD (anchors) and VPP (policer/classify/
// ABF/uRPF) via the control socket and govpp, and reconciles every 60s.
// See DESIGN.md §7.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fivetime/sbw-contract/buildinfo"
	"github.com/fivetime/sbw-contract/logx"
	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/agent"
	"github.com/fivetime/sbw-limiter/internal/grpcclient"
	"github.com/fivetime/sbw-limiter/internal/metrics"
	"github.com/fivetime/sbw-limiter/internal/vpp"
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
		"controller", cfg.ControllerEndpoint,
		"capacity_bps", cfg.CapacityBps,
		"reconcile_interval", cfg.ReconcileInterval.String(),
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// VPP data-plane connection — the agent reconciles desired state into it.
	conn, err := vpp.Dial(ctx, cfg.VPPAPISocket)
	if err != nil {
		log.Error("vpp connect failed", "socket", cfg.VPPAPISocket, "err", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Control-plane plumbing:
	//   grpcclient ──desired──▶ DesiredStore ──provider──▶ Reconciler ─▶ VPP
	//        ▲                                    │
	//        └────── Reporter ◀── HealthChecker ◀─┘ (observer)
	store := agent.NewDesiredStore()
	recon := agent.New(conn, log)
	health := agent.NewHealthChecker(model.EdgeID(cfg.EdgeID), conn)
	recon.AddObserver(health.Observe) // reconcile result drives soft-death health (B-05)

	// Observability (T-1003): the metrics observer runs AFTER health.Observe, so
	// health.Last() reflects this pass. Record reconcile activity + health gauges.
	met := metrics.New(model.EdgeID(cfg.EdgeID))
	recon.AddObserver(func(_ model.EdgeDesiredState, _ agent.Result, reconcileErr error) {
		met.RecordReconcile(reconcileErr)
		if rep, ok := health.Last(); ok {
			met.RecordHealth(rep)
		}
		st := store.Status()
		met.RecordDesiredStatus(st.Frozen, st.Generation)
	})

	reporter := agent.NewReporter(model.EdgeID(cfg.EdgeID), health,
		agent.WithCapacity(func() model.CapacityReport {
			return model.CapacityReport{NICCapacityBps: cfg.CapacityBps}
		}),
		agent.WithReporterLogger(log),
	)

	client, err := grpcclient.Dial(cfg.ControllerEndpoint, model.EdgeID(cfg.EdgeID),
		grpcclient.WithDesired(func(st model.EdgeDesiredState) {
			if store.Accept(st) {
				recon.Wake() // apply a fresh push now, not on the next timer tick (T-705)
			}
		}),
		grpcclient.WithLogger(log),
	)
	if err != nil {
		log.Error("controller dial failed", "endpoint", cfg.ControllerEndpoint, "err", err)
		os.Exit(1)
	}
	defer func() { _ = client.Close() }()

	// Announce this edge + its NIC capacity (controller turns it into tokens). A
	// transient failure here is non-fatal: client.Run re-subscribes, and the next
	// reconcile/report cadence proceeds; registration is idempotent server-side.
	if err := client.Register(ctx, cfg.CapacityBps); err != nil {
		log.Warn("initial register failed; will proceed and rely on resubscribe", "err", err)
	}

	// Prometheus /metrics (T-1003).
	if cfg.MetricsListenAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", met.Handler())
		msrv := &http.Server{Addr: cfg.MetricsListenAddr, Handler: mux}
		go func() {
			if err := msrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error("metrics server stopped", "err", err)
			}
		}()
		defer func() { _ = msrv.Close() }()
		log.Info("metrics serving", "addr", cfg.MetricsListenAddr, "path", "/metrics")
	}

	// Start the three loops. Each blocks until ctx is cancelled.
	go client.Run(ctx)                                            // downlink: subscribe + dispatch desired state
	go recon.Run(ctx, cfg.ReconcileInterval.Std(), store.Desired) // converge VPP to desired every interval
	go reporter.Run(ctx, cfg.ReportInterval.Std(), client)        // uplink: health/capacity report (B-03)

	// TODO(C-05 触发源 / B-04 audit): wire the BIRD route audit (agent.RouteAudit)
	// + anchor reloader and controller-down/up fail-static signalling once the
	// accounting checker is composed here.

	log.Info("edge-agent running; subscribed to controller. Send SIGTERM/SIGINT to stop.")
	<-ctx.Done()
	log.Info("edge-agent received shutdown signal; stopping")
	// Give in-flight loops a moment to observe ctx cancellation before exit.
	time.Sleep(100 * time.Millisecond)
}
