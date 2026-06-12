package agent

import (
	"context"
	"log/slog"
	"time"

	"github.com/fivetime/sbw-contract/model"
)

// This file is the L-side of the controller⇄agent boundary frozen by S-04
// (limiter §4.3). The agent depends only on these interfaces; the transport
// (Redpanda regular / gRPC urgent, controller-side T-704/705) implements them.
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

// Reporter assembles the agent's EdgeReport uplink (B-03) from the soft-death
// health (B-05) plus capacity/metering sources, and sends it periodically.
type Reporter struct {
	edgeID   model.EdgeID
	health   HealthSource
	capacity CapacityFunc
	metering MeteringFunc
	now      func() int64
	log      *slog.Logger
}

// ReporterOption configures a Reporter.
type ReporterOption func(*Reporter)

// WithCapacity wires the headroom source.
func WithCapacity(fn CapacityFunc) ReporterOption { return func(r *Reporter) { r.capacity = fn } }

// WithMetering wires the per-pool metering source (T-1001).
func WithMetering(fn MeteringFunc) ReporterOption { return func(r *Reporter) { r.metering = fn } }

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
	if r.capacity != nil {
		rep.Capacity = r.capacity()
	}
	if r.metering != nil {
		rep.Metering = r.metering()
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
