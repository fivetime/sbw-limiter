package agent

import (
	"context"
	"log/slog"
	"time"

	"github.com/fivetime/sbw-contract/model"
)

// This file is the L-side of the controller⇄agent boundary frozen by S-04
// (limiter §4.3). The agent depends only on these interfaces; the transport
// (unified gRPC, controller-side T-704/705) implements them.
//
//	DOWNLINK (controller→agent): the transport pushes desired state into the
//	  *DesiredStore (Accept / ControllerUp / ControllerDown, T-505); the
//	  Reconciler reads it via DesiredStore.Desired (fail-static §6.4).
//	UPLINK   (agent→controller): the Reporter assembles an EdgeReport from the
//	  soft-death HealthChecker (B-05) + capacity/metering sources and sends it
//	  via a ReportSink.

// ReportSink is the uplink transport: it delivers one EdgeReport to the
// controller. Implemented by the distribution layer; the agent knows only this.
type ReportSink interface {
	SendReport(ctx context.Context, r model.EdgeReport) error
}

// HealthSource provides the latest soft-death health report. *HealthChecker
// (B-05) satisfies it.
type HealthSource interface {
	Last() (model.HealthReport, bool)
}

// CapacityFunc reports the edge's current headroom (NIC line rate, Σ sold home
// bandwidth, observed throughput) for the controller's bin-packing constraint
// (§3.1). nil → a zero CapacityReport.
type CapacityFunc func() model.CapacityReport

// FaultSource types the edge's data-plane fault kind LIVE (DESIGN-liveness §4.2.3),
// consulted at report-build time so a determinate fault (vpp-gone / link-down) reaches
// the controller within one report interval, not one (slower) reconcile interval.
// *FaultSensor satisfies it. nil → the report carries FaultNone (the reconcile-derived
// classification stands unchanged).
type FaultSource interface {
	Fault() (model.FaultKind, string)
}

// PoolHashFunc reports the hash of the pool-set the agent currently has
// materialized in its data plane (model.PoolSetHash over the installed pool ids).
// *Reconciler.InstalledPoolHash satisfies it. The controller compares this against
// its own expected-set hash to detect drift and trigger a full DESIRED_STATE resync
// (the report-driven backstop). nil → the report carries 0 (no attestation).
type PoolHashFunc func() uint64

// wakeMinInterval is the storm guard for event-driven (Wake) reports: a wake
// landing within it of the previous send is dropped — the periodic ticker
// backstops it, so dropping costs at most one interval of latency, never
// correctness. Transitions are already rate-bounded upstream (govpp health-check
// detection + kubelet restart backoff), so this is insurance, not load-bearing.
const wakeMinInterval = time.Second

// Reporter assembles the agent's EdgeReport uplink (B-03) from the soft-death
// health (B-05) plus capacity/metering sources, and sends it periodically.
type Reporter struct {
	edgeID        model.EdgeID
	health        HealthSource
	capacity      CapacityFunc
	poolHash      PoolHashFunc
	birdFeed      func() (fails, lastOKUnixMs int64)
	desiredCounts func() (policers, sessions int, ok bool)
	actualCounts  func() (policers, sessions int, ok bool)
	fault         FaultSource
	now           func() int64
	log           *slog.Logger

	// wake requests one out-of-cycle report (event-driven, e.g. a VPP health
	// transition — §4.2.4 ★实测更新: removes the 15s report-sampling term from
	// permanent-VPP-death failover). Buffered to one; Wake never blocks.
	wake chan struct{}
}

// ReporterOption configures a Reporter.
type ReporterOption func(*Reporter)

// WithCapacity wires the headroom source.
func WithCapacity(fn CapacityFunc) ReporterOption { return func(r *Reporter) { r.capacity = fn } }

// WithPoolHash wires the installed pool-set hash source (reconciler.InstalledPoolHash):
// the report carries it so the controller can detect drift and resync.
func WithPoolHash(fn PoolHashFunc) ReporterOption { return func(r *Reporter) { r.poolHash = fn } }

// WithFault wires the live fault-kind sensor (§4.2.3): Build overlays its verdict onto
// the report so a determinate fault is typed + surfaced within one report interval.
func WithFault(fn FaultSource) ReporterOption { return func(r *Reporter) { r.fault = fn } }

// WithDesiredCounts wires a CURRENT-held-desired counts source (len of the
// store's policers/classify sessions — pure memory). Build overlays them onto
// HealthReport.PolicersDesired/SessionsDesired, which otherwise carry the LAST
// full-reconcile Result (up to a reconcile interval stale): after a DELTA the
// agent echoes the new AppliedVersion at once but the stale desired counts made
// the server's B-02 audit see a phantom expected≠desired "delivery-loss" during
// routine pool churn (§6.52 #5). Same definition as the server's ExpectedCounts,
// so applied==desired ⇒ gap≡0.
func WithDesiredCounts(fn func() (policers, sessions int, ok bool)) ReporterOption {
	return func(r *Reporter) { r.desiredCounts = fn }
}

// WithActualCounts wires the incrementally-maintained ACTUAL programmed counts
// (Reconciler.ActualCounts: anchored to VPP truth each full reconcile, adjusted
// per successful delta mutate). Build overlays them onto
// HealthReport.PolicersActual/SessionsActual, which otherwise carry the LAST
// full-reconcile count (up to a reconcile interval stale) — the desired-side
// §6.52 #5 fix alone just relabeled the phantom to "program-drift" (fresh
// desired vs stale actual); this is the symmetric other half. ok=false (before
// the first anchor) leaves the Result counts untouched.
func WithActualCounts(fn func() (policers, sessions int, ok bool)) ReporterOption {
	return func(r *Reporter) { r.actualCounts = fn }
}

// WithBirdFeedStatus wires the bird-materialization health source (birdfeed.Feed.Status
// or BirdApplier.Status): Build overlays HealthReport.BirdFeedFails/BirdFeedLastOKUnixMs
// so a persistently failing traction feed (anchors + egress flowspec) is VISIBLE to the
// server (bird-feed-degraded BSS event) instead of log-only. Reads two atomics — never
// touches bird/VPP, so it cannot stall the report hot path.
func WithBirdFeedStatus(fn func() (fails, lastOKUnixMs int64)) ReporterOption {
	return func(r *Reporter) { r.birdFeed = fn }
}

// WithReporterClock overrides the timestamp source (tests).
func WithReporterClock(now func() int64) ReporterOption { return func(r *Reporter) { r.now = now } }

// WithReporterLogger sets the logger (default: discard).
func WithReporterLogger(l *slog.Logger) ReporterOption { return func(r *Reporter) { r.log = l } }

// NewReporter builds a reporter for edgeID drawing health from the given source
// (a *HealthChecker).
func NewReporter(edgeID model.EdgeID, health HealthSource, opts ...ReporterOption) *Reporter {
	r := &Reporter{
		edgeID: edgeID, health: health,
		now:  func() int64 { return time.Now().UnixMilli() },
		log:  slog.New(slog.DiscardHandler),
		wake: make(chan struct{}, 1),
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Build assembles the current EdgeReport. It returns ok=false until at least one
// health observation exists (nothing meaningful to report before the first
// reconcile). The report's Generation echoes the health's GenerationApplied so
// the controller knows which desired intent the facts correspond to.
func (r *Reporter) Build() (model.EdgeReport, bool) {
	h, ok := r.health.Last()
	if !ok {
		return model.EdgeReport{}, false
	}
	rep := model.EdgeReport{
		SchemaVersion:    model.SchemaVersion,
		EdgeID:           r.edgeID,
		Generation:       h.GenerationApplied,
		ReportedAtUnixMs: r.now(),
		Health:           h,
	}
	// §4.2.3 live fault typing: overlay the sensor's verdict onto the (possibly stale)
	// reconcile-derived health. A DETERMINATE fault (vpp-gone / link-down) also forces
	// State=DataPlaneDown so SoftDead() is true — the server's typed-fault dataDead()
	// trusts the report on that healthDead signal alone and routes it to its fast
	// debounce (§4.2.4). FaultNone leaves the reconcile classification untouched.
	if r.fault != nil {
		if fk, reason := r.fault.Fault(); fk != model.FaultNone {
			rep.Health.FaultKind = fk
			rep.Health.State = model.HealthDataPlaneDown
			if reason != "" {
				rep.Health.Reason = reason
			}
		}
	}
	if r.capacity != nil {
		rep.Capacity = r.capacity()
	}
	if r.poolHash != nil {
		rep.InstalledPoolHash = r.poolHash()
	}
	// Bird-feed health (two atomics, never touches bird/VPP): a sustained non-zero
	// fails means anchors/flowspec convergence is silently stale — the server turns
	// it into the bird-feed-degraded/-recovered BSS events (policy-integrity signal).
	if r.birdFeed != nil {
		rep.Health.BirdFeedFails, rep.Health.BirdFeedLastOKUnixMs = r.birdFeed()
	}
	// Desired counts from the CURRENT held state (fresh across deltas; §6.52 #5).
	if r.desiredCounts != nil {
		if pol, sess, ok := r.desiredCounts(); ok {
			rep.Health.PolicersDesired, rep.Health.SessionsDesired = pol, sess
		}
	}
	if r.actualCounts != nil {
		if pol, sess, ok := r.actualCounts(); ok {
			rep.Health.PolicersActual, rep.Health.SessionsActual = pol, sess
		}
	}
	return rep, true
}

// Wake requests one immediate out-of-cycle report. Non-blocking; concurrent
// wakes coalesce (the report reflects state at build time, so a coalesced wake
// loses nothing). Wakes within wakeMinInterval of the last send are dropped in
// Run (storm guard); the periodic ticker backstops any dropped wake.
func (r *Reporter) Wake() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// Run sends a report every interval until ctx is cancelled, plus immediately on
// Wake (event-driven, rate-guarded). A send failure is logged, not fatal — the
// next tick retries with fresh state (the controller's soft-death detection
// tolerates a missed report via去抖, §4.7).
func (r *Reporter) Run(ctx context.Context, interval time.Duration, sink ReportSink) {
	t := time.NewTicker(interval)
	defer t.Stop()
	var lastSend time.Time
	send := func() {
		rep, ok := r.Build()
		if !ok {
			return
		}
		if err := sink.SendReport(ctx, rep); err != nil {
			r.log.Warn("edge report send failed", "err", err, "generation", rep.Generation)
		}
		lastSend = time.Now()
	}
	for {
		select {
		case <-ctx.Done():
			r.log.Info("reporter stopped")
			return
		case <-t.C:
			send()
		case <-r.wake:
			if since := time.Since(lastSend); since < wakeMinInterval {
				// Storm guard — but DEFER, don't drop: a permanent-death wake
				// arriving just after a periodic send would otherwise fall back
				// to the full report-interval latency (the exact term this path
				// exists to remove). The deferred re-Wake passes through this
				// guard again, so a flapping source still can't exceed one send
				// per wakeMinInterval.
				time.AfterFunc(wakeMinInterval-since, r.Wake)
				continue
			}
			send()
		}
	}
}
