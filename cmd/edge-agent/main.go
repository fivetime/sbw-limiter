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
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fivetime/sbw-contract/buildinfo"
	"github.com/fivetime/sbw-contract/logx"
	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/agent"
	"github.com/fivetime/sbw-limiter/internal/anchors"
	"github.com/fivetime/sbw-limiter/internal/bird"
	"github.com/fivetime/sbw-limiter/internal/grpcclient"
	"github.com/fivetime/sbw-limiter/internal/metrics"
	"github.com/fivetime/sbw-limiter/internal/vpp"
)

const (
	// vppReconnectAttempts is effectively unbounded: keep retrying the VPP binary
	// API across an arbitrarily long outage (crash + supervisor reglue + container
	// restart) instead of govpp's 3-attempt default, which gives up in ~1.5s and
	// leaves the agent permanently disconnected. At vppReconnectInterval each, this
	// is centuries of retries — i.e. "until VPP comes back or the agent stops".
	vppReconnectAttempts = 1 << 30
	vppReconnectInterval = time.Second
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
	// Reconnect effectively forever (not govpp's 3-attempt default): a VPP crash
	// can be down for many seconds (supervisor + container restart) and the agent
	// must keep retrying, then reinstall its rules on reconnect (Reconnects() →
	// Reconciler.Reset, §5/§7). The logger is passed so reconnect/restart events
	// are visible instead of discarded.
	conn, err := vpp.Dial(ctx, cfg.VPPAPISocket,
		vpp.WithReconnect(vppReconnectAttempts, vppReconnectInterval),
		vpp.WithLogger(log),
	)
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
	recon.SetPolicerInterfaces(cfg.PolicerInterfaces)
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

	// BIRD materialization (B-03 apply): only when the include paths are
	// configured — anchors (/32 carriers to MX204) + egress FlowSpec (to R),
	// applied with check+configure+rollback discipline.
	//
	// Use a self-reconnecting BIRD client: a BIRD restart (e.g. after a VPP crash
	// recreates the lcp interfaces and the node supervisor restarts BIRD) kills
	// the control socket, and a one-shot client would wedge on ErrClosed forever.
	// The wrapper redials transparently on the next apply pass and re-pushes the
	// includes. It dials lazily, so the agent can also start before BIRD is up.
	var birdApply *agent.BirdApplier
	if cfg.BirdAnchorsInclude != "" && cfg.BirdFlowspecInclude != "" {
		bc := bird.NewReconnecting(cfg.BIRDSocketPath, log)
		defer func() { _ = bc.Close() }()
		birdApply = agent.NewBirdApplier(
			anchors.NewApplier(cfg.BirdAnchorsInclude, bc, anchors.WithLogger(log)),
			anchors.NewApplier(cfg.BirdFlowspecInclude, bc, anchors.WithLogger(log)),
			log,
		)
		if err := birdApply.EnsureFiles(); err != nil {
			log.Error("bird include init failed", "err", err)
			os.Exit(1)
		}
	}

	// Canary (soft-death §4.7/6.13): advertise CanaryPrefix tagged with CanaryLC
	// via BIRD while the data plane is healthy; withdraw it on HealthDataPlaneDown
	// so the controller's RIB tap sees CanaryDown and (with the agent's own
	// healthDead report) trips soft-death failover — catching a dead data plane
	// that BGP/heartbeat alone cannot see. The canary IS a blackhole /32+large-
	// community route = exactly a model.Anchor, so it reuses the anchors apply
	// machinery (atomic write + check + reconfigure + rollback + skip-if-unchanged).
	if cfg.CanaryInclude != "" && cfg.CanaryPrefix != "" && cfg.CanaryLC != "" {
		cpfx, err := netip.ParsePrefix(cfg.CanaryPrefix)
		if err != nil {
			log.Error("invalid canary prefix", "prefix", cfg.CanaryPrefix, "err", err)
			os.Exit(1)
		}
		clc, err := parseLC(cfg.CanaryLC)
		if err != nil {
			log.Error("invalid canary LC", "lc", cfg.CanaryLC, "err", err)
			os.Exit(1)
		}
		advContent := renderCanary(cpfx, clc, true)  // protocol with the route
		wdContent := renderCanary(cpfx, clc, false)  // protocol, no route = withdrawn
		cbc := bird.NewReconnecting(cfg.BIRDSocketPath, log)
		defer func() { _ = cbc.Close() }()
		// anchors.Applier is a generic "managed BIRD include" (atomic write + check
		// + configure + rollback + skip-if-unchanged); we feed it raw canary bytes
		// via ApplyBytes (its Apply([]Anchor) would emit an "anchors4" protocol that
		// collides with the real anchors include — the canary uses its own
		// "canary4"/"canary6" protocol).
		canaryApplier := anchors.NewApplier(cfg.CanaryInclude, cbc, anchors.WithLogger(log))
		if err := canaryApplier.EnsureFileBytes(wdContent); err != nil {
			log.Error("canary include init failed", "err", err)
			os.Exit(1)
		}
		// Advertise once up front (assume healthy until a reconcile proves the
		// data plane dead); the observer below self-corrects on the first pass.
		if _, err := canaryApplier.ApplyBytes(advContent); err != nil {
			log.Warn("canary initial advertise failed", "err", err)
		}
		// Health-driven toggle. Added AFTER health.Observe, so health.Last()
		// reflects this pass. ApplyBytes skips reconfigure when content is
		// unchanged, so BIRD is only touched on an actual healthy<->dead flip.
		lastAdvertised := true
		recon.AddObserver(func(_ model.EdgeDesiredState, _ agent.Result, _ error) {
			advertised := true
			if rep, ok := health.Last(); ok && rep.State == model.HealthDataPlaneDown {
				advertised = false
			}
			content := advContent
			if !advertised {
				content = wdContent
			}
			if _, err := canaryApplier.ApplyBytes(content); err != nil {
				log.Warn("canary apply failed", "advertised", advertised, "err", err)
				return
			}
			if advertised != lastAdvertised {
				log.Info("canary advertisement toggled", "advertised", advertised)
				lastAdvertised = advertised
			}
		})
		log.Info("canary enabled (soft-death)", "prefix", cpfx, "lc", cfg.CanaryLC, "include", cfg.CanaryInclude)
	}

	client, err := grpcclient.Dial(cfg.ControllerEndpoint, model.EdgeID(cfg.EdgeID),
		grpcclient.WithDesired(func(st model.EdgeDesiredState) {
			if store.Accept(st) {
				recon.Wake() // apply a fresh push now, not on the next timer tick (T-705)
				if birdApply != nil {
					birdApply.Wake()
				}
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

	// Start the loops. Each blocks until ctx is cancelled.
	go client.Run(ctx)                                            // downlink: subscribe + dispatch desired state
	go recon.Run(ctx, cfg.ReconcileInterval.Std(), store.Desired) // converge VPP to desired every interval
	go reporter.Run(ctx, cfg.ReportInterval.Std(), client)        // uplink: health/capacity report (B-03)
	if birdApply != nil {
		go birdApply.Run(ctx, cfg.ReconcileInterval.Std(), store.Desired) // anchors+FlowSpec → BIRD
	}

	// Chaos hook (6.13): SIGUSR1 toggles forced data-plane-down, injecting a
	// soft-death (the agent withdraws the canary + reports healthDead) WHILE VPP
	// keeps forwarding — so the canary withdrawal reaches the controller's tap and
	// the soft-death conjunction (canaryDown ∧ healthDead) trips an auto-failover.
	// A real VPP outage cannot demo this here because the canary BGP rides through
	// VPP and the hard PeerDown path fires first.
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGUSR1)
		forced := false
		for {
			select {
			case <-ctx.Done():
				return
			case <-ch:
				forced = !forced
				health.SetForcedDataPlaneDown(forced)
				recon.Wake() // re-run health+canary now, not on the next timer tick
				log.Warn("CHAOS: forced data-plane-down toggled (6.13 soft-death inject)", "forced", forced)
			}
		}
	}()

	// TODO(C-05 触发源 / B-04 audit): wire the BIRD route audit (agent.RouteAudit)
	// + anchor reloader and controller-down/up fail-static signalling once the
	// accounting checker is composed here.

	log.Info("edge-agent running; subscribed to controller. Send SIGTERM/SIGINT to stop.")
	<-ctx.Done()
	log.Info("edge-agent received shutdown signal; stopping")
	// Give in-flight loops a moment to observe ctx cancellation before exit.
	time.Sleep(100 * time.Millisecond)
}

// renderCanary builds the canary BIRD include: a static "canary4"/"canary6"
// protocol that, when advertise is true, originates a single blackhole route for
// pfx tagged with the canary large-community (the marker the controller's RIB
// tap recognises). When advertise is false the protocol exists but holds no
// route — i.e. the canary is withdrawn (CanaryDown at the tap). A dedicated
// protocol name avoids colliding with the agent's anchors4/anchors6 protocols.
func renderCanary(pfx netip.Prefix, lc model.LargeCommunity, advertise bool) []byte {
	proto, channel, table := "canary4", "ipv4", "master4"
	if pfx.Addr().Is6() {
		proto, channel, table = "canary6", "ipv6", "master6"
	}
	var b strings.Builder
	b.WriteString("# Managed by bwpool edge-agent — canary (soft-death §4.7). DO NOT EDIT.\n")
	fmt.Fprintf(&b, "protocol static %s {\n", proto)
	fmt.Fprintf(&b, "  %s { table %s; };\n", channel, table)
	if advertise {
		fmt.Fprintf(&b, "  route %s blackhole {\n", pfx)
		fmt.Fprintf(&b, "    bgp_large_community.add((%d, %d, %d));\n", lc.GlobalAdmin, lc.LocalData1, lc.LocalData2)
		b.WriteString("  };\n")
	}
	b.WriteString("}\n")
	return []byte(b.String())
}

// parseLC parses a "global:local1:local2" large-community string (decimal).
func parseLC(s string) (model.LargeCommunity, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 3 {
		return model.LargeCommunity{}, fmt.Errorf("want global:local1:local2, got %q", s)
	}
	var v [3]uint32
	for i, p := range parts {
		n, err := strconv.ParseUint(strings.TrimSpace(p), 10, 32)
		if err != nil {
			return model.LargeCommunity{}, fmt.Errorf("part %d (%q): %w", i, p, err)
		}
		v[i] = uint32(n)
	}
	return model.LargeCommunity{GlobalAdmin: v[0], LocalData1: v[1], LocalData2: v[2]}, nil
}
