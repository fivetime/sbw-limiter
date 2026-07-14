// Command edge-agent runs on each edge: it subscribes to the controller's
// desired state, materializes it into BIRD (anchors) and VPP (policer + classify)
// via the control socket and govpp, and reconciles every 60s. See DESIGN.md §7.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fivetime/sbw-contract/buildinfo"
	"github.com/fivetime/sbw-contract/logx"
	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/agent"
	"github.com/fivetime/sbw-limiter/internal/anchors"
	"github.com/fivetime/sbw-limiter/internal/bird"
	"github.com/fivetime/sbw-limiter/internal/birdfeed"
	"github.com/fivetime/sbw-limiter/internal/grpcclient"
	"github.com/fivetime/sbw-limiter/internal/kafkasink"
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

	// Event-driven report delays (DESIGN-liveness §4.2.4 ★实测更新). A VPP health
	// transition wakes the reporter so vpp-gone / recovery reaches the server
	// without waiting out the 15s report sampling — the dominant term of
	// permanent-VPP-death failover (8–23s → ~9s deterministic).
	//
	//   - DOWN: report fast, but jitter 0–2s so a CORRELATED mass VPP death (bad
	//     image rollout) doesn't synchronize every edge's failover into one burst
	//     — today's 15s sampling phase-spreads them naturally; keep some spread.
	//   - UP: delay ~2.5s (+ the same jitter) — the post-reconnect report's fault
	//     sensor dumps interfaces, and right after a VPP restart the main thread
	//     is busy with the full data-plane reinstall; give it room to breathe.
	//     Recovery still reaches the server in ~3–5s instead of ≤15s.
	//
	// Both stay well inside the server's vpp-gone restartGrace (5s) + report
	// tolerance, so the flap-safety judgement (single container restart ~1s never
	// fails over) is unchanged.
	reportDownJitterMax = 2 * time.Second
	reportUpDelay       = 2500 * time.Millisecond
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
		vpp.WithHealthCheck(cfg.VPPHealthTimeout.Std()),
		vpp.WithReplyTimeout(cfg.VPPReplyTimeout.Std()),
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

	// Layered data-plane liveness (DESIGN-liveness §4.1): a phase tracker over the VPP
	// socket (real death) + apply progress, so the report tells a busy VPP (Reconciling)
	// from a dead one (Degraded/Dead) instead of racing the ControlPing. It deliberately
	// does NOT read the L4 engine loop counter — an adaptive VPP sleeps when idle so the
	// loops freeze, which a probe misreads as a wedge (verify-proven); "worker really
	// forwarding" can't be told passively (§4.1.6).
	phaseTracker := agent.NewPhaseTracker(conn, log)
	health := agent.NewHealthChecker(model.EdgeID(cfg.EdgeID), conn,
		agent.WithPhase(phaseTracker), agent.WithDeltasDropped(recon.DeltasDropped))
	recon.AddObserver(health.Observe) // reconcile result drives soft-death health (B-05)

	// Observability (T-1003): the metrics observer runs AFTER health.Observe, so
	// health.Last() reflects this pass. Record reconcile activity + health gauges.
	// Bird-materialization health source (assigned after the materializer is set
	// up below; read only from goroutines started after that assignment).
	var birdFeedStatus func() (fails, lastOKUnixMs int64)

	met := metrics.New(model.EdgeID(cfg.EdgeID))
	recon.AddObserver(func(_ model.EdgeDesiredState, _ agent.Result, reconcileErr error) {
		met.RecordReconcile(reconcileErr)
		if rep, ok := health.Last(); ok {
			met.RecordHealth(rep)
		}
		st := store.Status()
		met.RecordDesiredStatus(st.Frozen, st.Generation)
		// NOTE: the bird-feed gauge is NOT updated here — the reconcile cadence
		// (60s) is far too coarse to see a sub-minute feed transient. It is
		// refreshed on the 3s phase ticker instead (runPhaseTicker below), which
		// matches the feed's own retry cadence.
	})

	// Materialization-busy signal (§6.67 wall-①): while the edge is Reconciling, the
	// VPP-layer sensors below treat their own starvation (frozen heartbeat, stale
	// probe gauge) as busy-not-dead instead of declaring faults. A truly wedged VPP
	// errors the reconcile → phase Degraded → the gates open (phase model closes it).
	sensorBusy := func() bool { return phaseTracker.Phase() == model.PhaseReconciling }

	// ③ forwarding-broken (§4.2.7/§4.2.8) — see setupForwardingProbe.
	probeBroken, probeCleanup := setupForwardingProbe(ctx, cfg, conn, log, sensorBusy)
	if probeCleanup != nil {
		defer probeCleanup()
	}

	// Stats-segment VPP liveness (§6.44) — see setupVppLiveness. OnTransition + Run
	// are wired below, after the reporter exists.
	vppLive, vppLiveDead, liveCleanup := setupVppLiveness(cfg, log, sensorBusy)
	if liveCleanup != nil {
		defer liveCleanup()
	}

	reporter := agent.NewReporter(model.EdgeID(cfg.EdgeID), health,
		agent.WithCapacity(func() model.CapacityReport {
			// SessionBudget (DESIGN §9.1 admission): the max members this edge can
			// materialize before its classify heap os_panics — the SAME auto-sized
			// capacity the reconciler builds its tables from, so the controller's
			// session-dimension placement never over-commits the data plane.
			return model.CapacityReport{
				NICCapacityBps: cfg.CapacityBps,
				SessionBudget:  agent.ClassifySessionBudget(),
			}
		}),
		// Installed pool-set hash: the controller compares it against its expected
		// set to detect drift and trigger a full DESIRED_STATE resync (the
		// report-driven backstop to the controller-driven delta hot path).
		agent.WithPoolHash(recon.InstalledPoolHash),
		// §4.2.3 live fault typing: co-located with VPP, the agent types vpp-gone
		// (api.sock EOF) / link-down (policer-interface carrier down) / forwarding-broken
		// (③ probe verdict) at report time so the server routes a DETERMINATE fault to its
		// fast failover (§4.2.4) instead of the blanket soft-death debounce.
		agent.WithFault(agent.NewFaultSensor(conn, cfg.PolicerInterfaces, probeBroken, vppLiveDead, log)),
		// Bird-feed health (anchors/flowspec traction convergence): sustained apply
		// failure was log-only — surface it so the server can emit the
		// bird-feed-degraded BSS event (policy-integrity, not a death signal).
		// Indirect through a closure: birdFeedStatus is assigned BELOW (after the
		// materializer is chosen), so passing it directly here would capture nil.
		agent.WithDesiredCounts(func() (int, int, bool) {
			st, ok := store.Desired()
			return len(st.Policers), len(st.ClassifySessions), ok
		}),
		agent.WithActualCounts(recon.ActualCounts),
		agent.WithBirdFeedStatus(func() (int64, int64) {
			if birdFeedStatus == nil {
				return 0, 0
			}
			return birdFeedStatus()
		}),
		agent.WithReporterLogger(log),
	)

	// BIRD materialization (B-03 apply) — see setupBirdMaterializers.
	feed, birdApply, birdCleanup, err := setupBirdMaterializers(cfg, log)
	if err != nil {
		log.Error("bird include init failed", "err", err)
		os.Exit(1)
	}
	if birdCleanup != nil {
		defer birdCleanup()
	}
	// Wake whichever bird materializer is active (a fresh push / pool change applies now).
	birdWake := func() {
		if feed != nil {
			feed.Wake()
		}
		if birdApply != nil {
			birdApply.Wake()
		}
	}
	// Bird-materialization health source for the report/metrics (whichever
	// materializer is active); stays nil when neither is configured.
	if feed != nil {
		birdFeedStatus = feed.Status
	} else if birdApply != nil {
		birdFeedStatus = birdApply.Status
	}
	// §6.63 phase-aware liveness (the bird-vpp blind spot): while the bird feed is
	// failing/reconnecting (bird down or re-dumping after a restart), report
	// PhaseReconciling so the server's hard-death grace rides out the restart instead
	// of failing over a live edge. birdFeedStatus is assigned just above; the closure
	// is only called later (phase ticker / reconcile Observe), so it is set by then.
	phaseTracker.SetBirdBusy(func() bool {
		if birdFeedStatus == nil {
			return false
		}
		fails, _ := birdFeedStatus()
		return fails > 0
	})
	// Canary (soft-death §4.7/6.13) — see setupCanary.
	canaryCleanup, err := setupCanary(cfg, recon, health, log)
	if err != nil {
		log.Error("canary setup failed", "err", err)
		os.Exit(1)
	}
	if canaryCleanup != nil {
		defer canaryCleanup()
	}

	// Controller connection via the homing director (L-06): the agent boots from
	// the bootstrap endpoint set, Registers on any one, and is told its primary +
	// fallback coverers; it homes onto the primary (reports + subscribes there) and
	// re-homes on a REHOME push, falling back to another coverer if the primary is
	// unreachable. With sharding off the controller returns no coverers and the
	// agent simply stays on its single endpoint. The director is the ReportSink.
	onDesired := func(st model.EdgeDesiredState) {
		if store.Accept(st) {
			recon.Wake() // apply a fresh push now, not on the next timer tick (T-705)
			birdWake()
		} else {
			// Rejected: older generation, or a content-stale snapshot (rendered from
			// a follower-read DB snapshot predating an already-applied delta — the
			// stale-render guard; see DesiredStore.Accept). Level-triggered resyncs
			// deliver a fresh-enough one within seconds; log for gen-level tracing.
			log.Info("desired state rejected (older generation or content-stale snapshot)",
				"generation", st.Generation, "content_watermark_ms", st.GeneratedAtUnixMs,
				"policers", len(st.Policers))
		}
	}
	// Delta hot path (the agent is hands, not brain): apply just the touched pools in
	// O(delta) instead of re-reconciling the whole edge. onDelta runs ON the reconcile
	// goroutine (SubmitDelta enqueues; SetDeltaApplier wires this), so it is mutually
	// exclusive with the full Reconcile and may safely touch the VPP channel + polIdx.
	//
	// applyOneDelta merges one delta into the held state in lockstep with VPP. It
	// reports whether last-applied ADVANCED so the sequencer knows the chain moved.
	applyOneDelta := func(delta model.EdgeDesiredDelta) bool {
		prev, ok := store.Merge(delta) // mutate the held state in lockstep with VPP
		if !ok {
			log.Warn("desired-delta with no base state; dropping (cold start, awaiting full state)",
				"delta_generation", delta.Generation)
			return false
		}
		if _, err := recon.ApplyDelta(delta, prev); err != nil {
			// VPP only partially applied → do NOT wake BIRD: it must not advertise anchors/
			// FlowSpec for a delta VPP could not fully install (traffic would steer to an
			// uninstalled policer = unpoliced). The held-state/VPP divergence is healed by
			// the periodic full reconcile, which retries everything in the held state.
			//
			// But DO advance the desired chain (§6.40 layer 4): the Merge above already
			// adopted this delta into the held state, so the chain position moved — and a
			// delta that can NEVER apply (VPP rejects its parameters on every retry) must
			// not strand all later deltas in the reorder buffer, or even this pool's own
			// REMOVAL can never land and the ghost keeps the edge Degraded forever.
			recon.AdoptDeltaBaseline(delta.Generation)
			log.Error("desired-delta apply failed; chain advanced, not waking BIRD, full reconcile will retry", "err", err)
			return true
		}
		birdWake() // a removed/added pool may change anchors/flowspec
		return true
	}
	// REORDERING (§6.28): a delta builds on BaseGeneration, and the controller mints
	// each edge's chain under one lock (so it is strictly linear), but it ENQUEUES
	// deltas from concurrent goroutines — under a burst a successor can arrive before
	// its predecessor. Dropping the successor (the old behaviour) forced a full resync
	// and, under sustained concurrent churn, degraded the delta hot path to periodic
	// resync. The sequencer buffers an ahead-of-chain delta and drains it the instant
	// its predecessor lands; a genuinely lost predecessor still heals via the
	// controller's hash-mismatch resync (which strands + evicts the buffered entry).
	deltaSeq := agent.NewDeltaSequencer(recon.LastAppliedGeneration, applyOneDelta, log)
	recon.SetDeltaApplier(deltaSeq.Submit)
	// REFACTOR step 4: connect DIRECTLY to the server (no coverer relay, no homing
	// director). One server endpoint; the gRPC ClientConn reconnects transparently and
	// RunDirect re-registers + re-subscribes on each drop. cfg.Bootstrap() returns
	// ControllerEndpoints (env BWPOOL_CONTROLLER_ENDPOINTS, re-pointed at sbw-server) if
	// set, else [ControllerEndpoint]; take the first (a single server Service DNS name —
	// gRPC handles replicas behind it).
	boot := cfg.Bootstrap()
	if len(boot) == 0 {
		log.Error("no controller/server endpoint configured (set CONTROLLER_ENDPOINT[S])")
		os.Exit(1)
	}
	serverEndpoint := boot[0]
	client, err := grpcclient.Dial(serverEndpoint, model.EdgeID(cfg.EdgeID),
		grpcclient.WithDesired(onDesired),
		grpcclient.WithDelta(recon.SubmitDelta), // hot path: queue deltas to the reconcile goroutine
		// Fail-static (T-505): flip the held desired state to FROZEN the moment the
		// controller connection is lost (reported via DesiredStore.Status). The
		// reconcile loop keeps converging to the last-good state regardless.
		grpcclient.WithConnState(store.ControllerUp, store.ControllerDown),
		grpcclient.WithLogger(log),
	)
	if err != nil {
		log.Error("dial server failed", "endpoint", serverEndpoint, "err", err)
		os.Exit(1)
	}
	defer func() { _ = client.Close() }()

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
	go client.RunDirect(ctx, cfg.CapacityBps)                     // downlink: register + subscribe + dispatch, direct to server (REFACTOR step 4)
	go recon.Run(ctx, cfg.ReconcileInterval.Std(), store.Desired) // converge VPP to desired every interval
	go reporter.Run(ctx, cfg.ReportInterval.Std(), client)        // uplink: health/capacity report direct to server (B-03); client is the ReportSink
	// Stats-segment liveness transitions (§6.44) wake the reporter too, with the
	// same de-correlation jitter as the govpp health path. Wedge/death is already
	// debounced inside VppLiveness (wedgeGrace / disconnect), so no extra delay on
	// the down edge beyond the jitter; recovery reuses the up-delay reasoning.
	if vppLive != nil {
		vppLive.OnTransition(func(dead bool) {
			delay := time.Duration(rand.Int64N(int64(reportDownJitterMax)))
			if !dead {
				delay += reportUpDelay
			}
			log.Info("vpp stats liveness transition; scheduling event-driven report",
				"dead", dead, "delay", delay.Round(time.Millisecond))
			time.AfterFunc(delay, reporter.Wake)
		})
		go vppLive.Run(ctx)
	}
	go runHealthTransitionReports(ctx, conn, reporter, log)   // event-driven report: VPP health transition → wake the reporter (§4.2.4 ★实测更新)
	go runPhaseTicker(ctx, phaseTracker, met, birdFeedStatus) // L4 engine + socket probe (§4.1) + 3s bird-feed gauge refresh
	if feed != nil {
		go feed.Run(ctx, cfg.ReconcileInterval.Std(), store.Desired) // anchors+FlowSpec → bird api proto (incremental)
	} else if birdApply != nil {
		go birdApply.Run(ctx, cfg.ReconcileInterval.Std(), store.Desired) // anchors+FlowSpec → BIRD (legacy configure)
	}

	startMetering(ctx, cfg, recon, log) // metering export (T-1001): VPP policer counters → Kafka
	go runChaosHook(ctx, health, recon, log)

	log.Info("edge-agent running; subscribed to controller. Send SIGTERM/SIGINT to stop.")
	<-ctx.Done()
	log.Info("edge-agent received shutdown signal; stopping")
	// Give in-flight loops a moment to observe ctx cancellation before exit.
	time.Sleep(100 * time.Millisecond)
}

// runHealthTransitionReports turns govpp binary-API health transitions into
// event-driven reports (§4.2.4 ★实测更新): a transition wakes the reporter so
// vpp-gone / recovery reaches the server without waiting out the 15s sampling.
// Down gets the de-correlation jitter; up additionally waits reportUpDelay so
// the post-restart reinstall can breathe (see the const doc).
func runHealthTransitionReports(ctx context.Context, conn *vpp.Conn, reporter *agent.Reporter, log *slog.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-conn.HealthTransitions():
		}
		// Snapshot health NOW; the delay below may straddle another
		// transition, which stays pending in the coalescing channel and is
		// re-evaluated (with a fresh snapshot) on the next iteration — so a
		// down→up race at worst sends one extra already-true report.
		healthy := conn.Healthy()
		delay := time.Duration(rand.Int64N(int64(reportDownJitterMax))) // de-correlate mass events
		if healthy {
			delay += reportUpDelay // let the post-restart reinstall breathe (see const doc)
		}
		log.Info("vpp health transition; scheduling event-driven report",
			"healthy", healthy, "delay", delay.Round(time.Millisecond))
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
			reporter.Wake()
		}
	}
}

// runPhaseTicker drives the L4 engine + socket probe faster than the reconcile
// pass, so a worker wedge / socket loss surfaces in seconds (§4.1). It also
// refreshes the bird-feed gauge at this 3s cadence (birdFeedStatus, nil if no
// materializer) — the reconcile observer's 60s cadence is far too coarse to see
// a sub-minute feed transient, which the lab regression exposed as a blind gauge.
func runPhaseTicker(ctx context.Context, pt *agent.PhaseTracker, met *metrics.Metrics, birdFeedStatus func() (fails, lastOKUnixMs int64)) {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			met.RecordPhase(pt.Tick())
			if birdFeedStatus != nil {
				met.RecordBirdFeed(birdFeedStatus())
			}
		}
	}
}

// startMetering wires the metering export (T-1001): read VPP policer counters
// every interval and push raw cumulative samples to Kafka (→ ClickHouse → BSS).
// Telemetry decoupled from the control plane; a setup failure disables metering
// but never the agent. No-op unless enabled with brokers configured.
func startMetering(ctx context.Context, cfg agent.Config, recon *agent.Reconciler, log *slog.Logger) {
	if !cfg.MeteringEnable || len(cfg.KafkaBrokers) == 0 {
		return
	}
	statsReader, err := vpp.NewStatsReader(cfg.VPPStatsSocket)
	if err != nil {
		log.Error("metering disabled: VPP stats connect failed", "err", err, "socket", cfg.VPPStatsSocket)
		return
	}
	sink, err := kafkasink.New(kafkasink.Config{
		Brokers: cfg.KafkaBrokers, Topic: cfg.KafkaTopic,
		Username: cfg.KafkaSASLUser, Password: cfg.KafkaSASLPass, Mechanism: cfg.KafkaSASLMech,
		TLSCAFile: cfg.KafkaTLSCAFile, TLSInsecureSkipVerify: cfg.KafkaTLSInsecure,
		Plaintext: cfg.KafkaPlaintext,
	})
	if err != nil {
		log.Error("metering disabled: kafka sink init failed", "err", err)
		_ = statsReader.Close()
		return
	}
	meter := agent.NewMetering(model.EdgeID(cfg.EdgeID), statsReader, recon.PolicerIndexes, sink,
		agent.WithMeteringLogger(log))
	go meter.Run(ctx, cfg.MeteringInterval.Std())
	log.Info("metering export started", "brokers", cfg.KafkaBrokers, "topic", cfg.KafkaTopic,
		"interval", cfg.MeteringInterval.Std())
}

// runChaosHook is the 6.13 chaos hook: SIGUSR1 toggles forced data-plane-down,
// injecting a soft-death (the agent withdraws the canary + reports healthDead)
// WHILE VPP keeps forwarding — so the canary withdrawal reaches the controller's
// tap and the soft-death conjunction (canaryDown ∧ healthDead) trips an
// auto-failover. A real VPP outage cannot demo this here because the canary BGP
// rides through VPP and the hard PeerDown path fires first.
func runChaosHook(ctx context.Context, health *agent.HealthChecker, recon *agent.Reconciler, log *slog.Logger) {
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
}

// setupBirdMaterializers wires the BIRD materialization (B-03 apply): anchors
// (/32 carriers to MX204) + egress FlowSpec (to R), applied with
// check+configure+rollback discipline. Two mutually-exclusive paths:
//   - feed (BirdFeedMode=="api", DESIGN-bird-api.md): stream anchors + egress
//     flowspec incrementally to bird-vpp's `api` proto over the socket, no
//     full-file `birdc configure`. Lazy connect; (re)connect triggers a
//     HELLO+EOR resync, the proto's grace window covers brief reconnects without
//     flapping the routes. Anchors + egress flowspec are fed straight from
//     desired, UNCONDITIONALLY — there is no advertisement gate (anti-blackhole
//     turned out to be a non-problem; DESIGN-liveness §2/§10).
//   - birdApply (legacy include-file configure), only when both include paths are
//     configured. Uses a self-reconnecting BIRD client: a BIRD restart (e.g.
//     after a VPP crash recreates the lcp interfaces and the node supervisor
//     restarts BIRD) kills the control socket, and a one-shot client would wedge
//     on ErrClosed forever; the wrapper redials transparently on the next apply
//     pass. It dials lazily, so the agent can also start before BIRD is up.
//
// cleanup, when non-nil, closes the legacy path's BIRD client — main defers it.
func setupBirdMaterializers(cfg agent.Config, log *slog.Logger) (*birdfeed.Feed, *agent.BirdApplier, func(), error) {
	if cfg.BirdFeedMode == "api" {
		feed := birdfeed.NewFeed(cfg.BirdAPISocket, log,
			birdfeed.WithPacing(cfg.BirdFeedMaxOpsPerPass, cfg.BirdFeedPace.Std()))
		log.Info("bird control plane via api socket (incremental feed)", "socket", cfg.BirdAPISocket,
			"feed_max_ops_per_pass", cfg.BirdFeedMaxOpsPerPass, "feed_pace", cfg.BirdFeedPace.Std())
		return feed, nil, nil, nil
	}
	if cfg.BirdAnchorsInclude != "" && cfg.BirdFlowspecInclude != "" {
		bc := bird.NewReconnecting(cfg.BIRDSocketPath, log)
		birdApply := agent.NewBirdApplier(
			anchors.NewApplier(cfg.BirdAnchorsInclude, bc, anchors.WithLogger(log)),
			anchors.NewApplier(cfg.BirdFlowspecInclude, bc, anchors.WithLogger(log)),
			log,
		)
		if err := birdApply.EnsureFiles(); err != nil {
			_ = bc.Close()
			return nil, nil, nil, err
		}
		return nil, birdApply, func() { _ = bc.Close() }, nil
	}
	return nil, nil, nil, nil
}

// setupCanary wires the canary (soft-death §4.7/6.13): advertise CanaryPrefix
// tagged with CanaryLC via BIRD while the data plane is healthy; withdraw it on
// HealthDataPlaneDown so the controller's RIB tap sees CanaryDown and (with the
// agent's own healthDead report) trips soft-death failover — catching a dead
// data plane that BGP/heartbeat alone cannot see. The canary IS a blackhole
// /32+large-community route = exactly a model.Anchor, so it reuses the anchors
// apply machinery (atomic write + check + reconfigure + rollback +
// skip-if-unchanged). No-op (nil, nil) unless all three canary settings are set.
// cleanup, when non-nil, closes the canary's BIRD client — main defers it.
func setupCanary(cfg agent.Config, recon *agent.Reconciler, health *agent.HealthChecker, log *slog.Logger) (func(), error) {
	if cfg.CanaryInclude == "" || cfg.CanaryPrefix == "" || cfg.CanaryLC == "" {
		return nil, nil
	}
	cpfx, err := netip.ParsePrefix(cfg.CanaryPrefix)
	if err != nil {
		return nil, fmt.Errorf("invalid canary prefix %q: %w", cfg.CanaryPrefix, err)
	}
	clc, err := parseLC(cfg.CanaryLC)
	if err != nil {
		return nil, fmt.Errorf("invalid canary LC %q: %w", cfg.CanaryLC, err)
	}
	advContent := renderCanary(cpfx, clc, true) // protocol with the route
	wdContent := renderCanary(cpfx, clc, false) // protocol, no route = withdrawn
	cbc := bird.NewReconnecting(cfg.BIRDSocketPath, log)
	// anchors.Applier is a generic "managed BIRD include" (atomic write + check
	// + configure + rollback + skip-if-unchanged); we feed it raw canary bytes
	// via ApplyBytes (its Apply([]Anchor) would emit an "anchors4" protocol that
	// collides with the real anchors include — the canary uses its own
	// "canary4"/"canary6" protocol).
	canaryApplier := anchors.NewApplier(cfg.CanaryInclude, cbc, anchors.WithLogger(log))
	if err := canaryApplier.EnsureFileBytes(wdContent); err != nil {
		_ = cbc.Close()
		return nil, fmt.Errorf("canary include init: %w", err)
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
		// Withdraw on SoftDead (now phase-aware, §4.1): the data-plane link down,
		// OR a Degraded phase (wedged worker / erroring applies) the ControlPing is
		// blind to. This is the BGP half of the canary∧healthDead conjunction; the
		// gRPC half (SoftDead in the report) tracks the same predicate.
		if rep, ok := health.Last(); ok && rep.SoftDead() {
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
	return func() { _ = cbc.Close() }, nil
}

// setupVppLiveness wires the stats-segment VPP liveness (§6.44): it reads the
// probe plugin's /probe/heartbeat over its own stats connection. A stalled
// heartbeat = main-thread wedge; a disconnected stats socket = process death
// (govpp fsnotify, immediate). This judges VPP off the main thread, covering
// govpp's binary-API health-check blind spots (30s reply-timeout stall + wedge).
// Best-effort: if the dedicated stats connection can't be established, liveness
// is skipped (nil, nil, nil) and FaultSensor falls back to conn.Healthy() alone
// (pre-§6.44 behavior). Detection only — never touches the govpp binary-API
// connection. wedgeGrace 3s = 3× the probe 1s scan cadence: tolerates the
// cooperative vlib_process being skipped by a genuinely busy (not wedged) main
// thread, while catching a real stall promptly. A ~1s container self-heal shows
// up as a stats disconnect (process death path), not a stall, and is absorbed by
// the server's restartGrace like any vpp-gone. cleanup closes the (current)
// stats reader — main defers it at the call site.
func setupVppLiveness(cfg agent.Config, log *slog.Logger, busy func() bool) (vppLive *agent.VppLiveness, dead func() bool, cleanup func()) {
	liveStats, lerr := vpp.NewStatsReader(cfg.VPPStatsSocket)
	if lerr != nil {
		log.Error("vpp liveness disabled: dedicated stats connect failed (falling back to conn.Healthy)",
			"err", lerr, "socket", cfg.VPPStatsSocket)
		return nil, nil, nil
	}
	// Swappable reader: a rapid VPP restart can leave govpp's fsnotify-based
	// reconnect stuck on a stale segment (frozen heartbeat → falsely wedged); the
	// stale-reconnect hook rebuilds it while dead. Guard reads/swaps with a mutex.
	var liveMu sync.Mutex
	cleanup = func() { liveMu.Lock(); _ = liveStats.Close(); liveMu.Unlock() }
	vppLive = agent.NewVppLiveness(
		func() (uint64, error) {
			liveMu.Lock()
			r := liveStats
			liveMu.Unlock()
			return r.ReadGauge("/probe/heartbeat")
		},
		vpp.IsStatsDisconnected, time.Second, 3*time.Second, log)
	vppLive.BindBusy(busy) // §6.67 wall-①: a stalled heartbeat while Reconciling is busy, not wedged
	vppLive.OnStaleReconnect(func() {
		nr, rerr := vpp.NewStatsReader(cfg.VPPStatsSocket)
		if rerr != nil {
			log.Warn("vpp liveness: stale-segment stats reconnect failed", "err", rerr)
			return
		}
		liveMu.Lock()
		_ = liveStats.Close()
		liveStats = nr
		liveMu.Unlock()
		log.Info("vpp liveness: rebuilt stats reader (recovering from a possibly stale segment)")
	}, 8*time.Second)
	return vppLive, vppLive.Dead, cleanup
}

// setupForwardingProbe wires ③ forwarding-broken (§4.2.7/§4.2.8): a device-level
// active forwarding check — ForwardingProbeFails consecutive black-holed rounds →
// forwarding-broken (device up, links up, but a silent black-hole). Two sources,
// selected by config:
//   - plugin gauge (§4.2.8, preferred): the `probe` VPP plugin resolves the target
//     in the FIB on its own process node and publishes reachability to the stats
//     segment; the agent reads it over shared memory, never touching VPP's single
//     main thread — a busy VPP can't self-time-out the probe (the cli_inband ping's
//     fatal flaw under load).
//   - cli_inband ping (§4.2.7, legacy fallback): pings the target through the data
//     plane. Immune to the policer (a low-rate echo is below any pool rate).
//
// Disabled (nil, nil) if no target set. cleanup, when non-nil, closes the probe's
// dedicated stats reader — main defers it at the call site.
func setupForwardingProbe(ctx context.Context, cfg agent.Config, conn *vpp.Conn, log *slog.Logger, busy func() bool) (broken func() bool, cleanup func()) {
	if cfg.ForwardingProbeTarget == "" {
		return nil, nil
	}
	var fp *agent.ForwardingProbe
	if cfg.ForwardingProbePlugin {
		// Its own read-only stats connection (shared memory, decoupled from the
		// metering reader's lifetime). A connect failure disables ③ but not the agent.
		if probeStats, serr := vpp.NewStatsReader(cfg.VPPStatsSocket); serr != nil {
			log.Error("forwarding probe (plugin) disabled: VPP stats connect failed",
				"err", serr, "socket", cfg.VPPStatsSocket)
		} else {
			cleanup = func() { _ = probeStats.Close() }
			gauge := "/probe/fib/" + cfg.ForwardingProbeStatName + "/reachable"
			// The `probe fib add` CLI needs a prefix; a bare next-hop address
			// (the natural way to express the target) gets its host length.
			probePrefix := cfg.ForwardingProbeTarget
			if !strings.Contains(probePrefix, "/") {
				if a, perr := netip.ParseAddr(probePrefix); perr == nil {
					if a.Is4() {
						probePrefix += "/32"
					} else {
						probePrefix += "/128"
					}
				}
			}
			// Register the target once — a main-thread setup call (not the detection
			// loop). Idempotent-ish: an "already exists" on agent restart is benign,
			// and a fresh VPP (post-restart) is self-healed by the lazy re-register
			// in the round below.
			register := func() error {
				_, cerr := conn.CliInband(fmt.Sprintf("probe fib add %s table %d name %s",
					probePrefix, cfg.ForwardingProbeTable, cfg.ForwardingProbeStatName),
					cfg.ForwardingProbeTimeout.Std())
				return cerr
			}
			if rerr := register(); rerr != nil {
				log.Warn("probe target register at startup returned error (continuing; gauge read is source of truth)", "err", rerr)
			}
			fp = agent.NewForwardingProbe(func() (int, error) {
				v, gerr := probeStats.ReadGauge(gauge)
				if gerr != nil {
					// Gauge absent = target unregistered (fresh VPP after a restart).
					// Re-register best-effort and report "could not run" (verdict
					// unchanged), so a VPP restart never false-positives a black-hole.
					_ = register()
					return 0, gerr
				}
				return int(v), nil
			}, cfg.ForwardingProbeInterval.Std(), cfg.ForwardingProbeFails, log)
			log.Info("forwarding probe enabled (plugin gauge, §4.2.8)", "target", cfg.ForwardingProbeTarget,
				"gauge", gauge, "interval", cfg.ForwardingProbeInterval.Std(), "fails", cfg.ForwardingProbeFails)
		}
	} else {
		fp = agent.NewForwardingProbe(
			func() (int, error) {
				_, recv, err := conn.Ping(cfg.ForwardingProbeTarget, 3, 0.1, cfg.ForwardingProbeTimeout.Std())
				return recv, err
			},
			cfg.ForwardingProbeInterval.Std(), cfg.ForwardingProbeFails, log)
		log.Info("forwarding probe enabled (cli_inband ping, §4.2.7 legacy)", "target", cfg.ForwardingProbeTarget,
			"interval", cfg.ForwardingProbeInterval.Std(), "fails", cfg.ForwardingProbeFails)
	}
	if fp != nil {
		// VPP restart (generation bump) disarms the probe until first
		// reachability: the post-restart FIB-rebuild window (bird/vppfib
		// re-feed, tens of seconds) must not read as a black-hole (§6.44).
		fp.BindDataplaneGeneration(conn.Generation)
		fp.BindBusy(busy) // §6.67 wall-①: zero-reach while Reconciling is inconclusive
		go fp.Run(ctx)
		broken = fp.Broken
	}
	return broken, cleanup
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
