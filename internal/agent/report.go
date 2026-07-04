package agent

import (
	"context"
	"log/slog"
	"net/netip"
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

// MeteringFunc reports per-pool policer accounting (T-1001). nil → no metering.
type MeteringFunc func() []model.PoolMetering

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

// ObservedMembersFunc yields the member host prefixes the agent PHYSICALLY observes
// on its member interface (VPP ARP/ND neighbor table) — the L's physical authority
// (DESIGN-liveness §11). nil → the report carries no set (backward compatible).
type ObservedMembersFunc func() []netip.Prefix

// Reporter assembles the agent's EdgeReport uplink (B-03) from the soft-death
// health (B-05) plus capacity/metering sources, and sends it periodically.
type Reporter struct {
	edgeID   model.EdgeID
	health   HealthSource
	capacity CapacityFunc
	metering MeteringFunc
	poolHash PoolHashFunc
	fault    FaultSource
	observed ObservedMembersFunc
	now      func() int64
	log      *slog.Logger
}

// ReporterOption configures a Reporter.
type ReporterOption func(*Reporter)

// WithCapacity wires the headroom source.
func WithCapacity(fn CapacityFunc) ReporterOption { return func(r *Reporter) { r.capacity = fn } }

// WithMetering wires the per-pool metering source (T-1001).
func WithMetering(fn MeteringFunc) ReporterOption { return func(r *Reporter) { r.metering = fn } }

// WithPoolHash wires the installed pool-set hash source (reconciler.InstalledPoolHash):
// the report carries it so the controller can detect drift and resync.
func WithPoolHash(fn PoolHashFunc) ReporterOption { return func(r *Reporter) { r.poolHash = fn } }

// WithFault wires the live fault-kind sensor (§4.2.3): Build overlays its verdict onto
// the report so a determinate fault is typed + surfaced within one report interval.
func WithFault(fn FaultSource) ReporterOption { return func(r *Reporter) { r.fault = fn } }

// WithObservedMembers wires the physical member-presence source (VPP ARP/ND neighbor
// table): Build carries its set as EdgeReport.ObservedMembers, the L's physical
// authority the server consumes for member-up/down + locality (REFACTOR §2/§3).
func WithObservedMembers(fn ObservedMembersFunc) ReporterOption {
	return func(r *Reporter) { r.observed = fn }
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
		now: func() int64 { return time.Now().UnixMilli() },
		log: slog.New(slog.DiscardHandler),
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
	if r.metering != nil {
		rep.Metering = r.metering()
	}
	if r.poolHash != nil {
		rep.InstalledPoolHash = r.poolHash()
	}
	if r.observed != nil {
		rep.ObservedMembers = r.observed()
	}
	return rep, true
}

// Run sends a report every interval until ctx is cancelled. A send failure is
// logged, not fatal — the next tick retries with fresh state (the controller's
// soft-death detection tolerates a missed report via去抖, §4.7).
func (r *Reporter) Run(ctx context.Context, interval time.Duration, sink ReportSink) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			r.log.Info("reporter stopped")
			return
		case <-t.C:
			rep, ok := r.Build()
			if !ok {
				continue
			}
			if err := sink.SendReport(ctx, rep); err != nil {
				r.log.Warn("edge report send failed", "err", err, "generation", rep.Generation)
			}
		}
	}
}
