// Package metrics is the edge-agent's Prometheus surface (T-1003, B half): it
// exposes the reconcile loop's health and activity — soft-death state (B-05),
// VPP link liveness, three-way drift (T-502), desired-state generation and
// fail-static freeze (§6.4), and reconcile repair volume. The agent records into
// a *Metrics from its reconcile observer; the cmd serves Handler on an HTTP port.
//
// edge_id is a const label so a fleet's series are distinguishable. Methods are
// nil-safe (nil *Metrics no-ops) so wiring is unconditional.
package metrics

import (
	"net/http"

	"github.com/fivetime/sbw-contract/model"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds the agent's collectors over a private registry.
type Metrics struct {
	reg *prometheus.Registry

	reconcilePasses prometheus.Counter
	reconcileErrors prometheus.Counter
	repairs         prometheus.Counter

	healthState     prometheus.Gauge // 0 healthy, 1 degraded, 2 data-plane-down
	vppConnected    prometheus.Gauge // 1 up, 0 down
	birdFeedFails   prometheus.Gauge
	birdFeedLastOK  prometheus.Gauge
	policersDesired prometheus.Gauge
	sessionsDesired prometheus.Gauge
	generation      prometheus.Gauge // last applied desired-state generation
	frozen          prometheus.Gauge // 1 when fail-static frozen (controller unreachable)
	dataPlanePhase  prometheus.Gauge // §4.1: 0 Ready,1 Reconciling,2 Pending,3 Degraded,4 Dead,-1 unknown
}

// New builds a Metrics for one edge over a fresh registry. edge is added as a
// const label so a scraped fleet is distinguishable.
func New(edge model.EdgeID) *Metrics {
	reg := prometheus.NewRegistry()
	f := factory{reg: reg, labels: prometheus.Labels{"edge_id": string(edge)}}
	m := &Metrics{reg: reg}

	m.reconcilePasses = f.counter("sbw_agent_reconcile_passes_total", "Reconcile passes the agent has run.")
	m.reconcileErrors = f.counter("sbw_agent_reconcile_errors_total", "Reconcile passes that returned an error.")
	m.repairs = f.counter("sbw_agent_reconcile_repairs_total", "VPP add/update/delete/move ops applied across reconciles.")

	m.healthState = f.gauge("sbw_agent_health_state", "Soft-death state: 0 healthy, 1 degraded, 2 data-plane-down (B-05).")
	m.vppConnected = f.gauge("sbw_agent_vpp_connected", "VPP control-link liveness: 1 up, 0 down.")
	m.birdFeedFails = f.gauge("sbw_agent_bird_feed_consecutive_failures", "Consecutive failed bird-materialization passes (anchors+flowspec feed); 0 = healthy. Sustained non-zero = traction convergence silently stale.")
	m.birdFeedLastOK = f.gauge("sbw_agent_bird_feed_last_success_timestamp_seconds", "Unix time of the last fully-applied bird-feed pass; 0 = never.")
	m.policersDesired = f.gauge("sbw_agent_policers_desired", "Policers in the current desired state.")
	m.sessionsDesired = f.gauge("sbw_agent_classify_sessions_desired", "Classify sessions in the current desired state.")
	m.generation = f.gauge("sbw_agent_desired_generation", "Last applied desired-state generation.")
	m.frozen = f.gauge("sbw_agent_controller_frozen", "1 when fail-static frozen (controller unreachable, holding last state).")
	m.dataPlanePhase = f.gauge("sbw_agent_dataplane_phase", "Data-plane liveness phase (DESIGN-liveness §4.1): 0 Ready, 1 Reconciling, 2 Pending, 3 Degraded, 4 Dead, -1 unknown.")
	return m
}

// Handler is the /metrics exposition handler.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// RecordReconcile records one reconcile pass (and an error if reconcileErr!=nil).
func (m *Metrics) RecordReconcile(reconcileErr error) {
	if m == nil {
		return
	}
	m.reconcilePasses.Inc()
	if reconcileErr != nil {
		m.reconcileErrors.Inc()
	}
}

// RecordHealth folds the latest HealthReport (after a reconcile) into the gauges
// and the repair counter.
func (m *Metrics) RecordHealth(r model.HealthReport) {
	if m == nil {
		return
	}
	m.repairs.Add(float64(r.RepairActions))
	m.healthState.Set(float64(r.State))
	m.policersDesired.Set(float64(r.PolicersDesired))
	m.sessionsDesired.Set(float64(r.SessionsDesired))
	m.generation.Set(float64(r.GenerationApplied))
	m.vppConnected.Set(boolGauge(r.VPPConnected))
}

// RecordPhase folds the current data-plane liveness phase into the gauge. Driven by
// the phase probe ticker (more frequent than a reconcile pass).
// RecordBirdFeed folds the bird-materialization health (birdfeed.Feed.Status /
// BirdApplier.Status) into gauges: consecutive failed passes + last-success time.
func (m *Metrics) RecordBirdFeed(fails, lastOKUnixMs int64) {
	if m == nil {
		return
	}
	m.birdFeedFails.Set(float64(fails))
	m.birdFeedLastOK.Set(float64(lastOKUnixMs) / 1000.0)
}

func (m *Metrics) RecordPhase(p model.DataPlanePhase) {
	if m == nil {
		return
	}
	m.dataPlanePhase.Set(phaseCode(p))
}

// phaseCode maps a phase to a numeric gauge value (higher = worse): Ready 0,
// Reconciling 1, Pending 2, Degraded 3, Dead 4, unknown/empty -1.
func phaseCode(p model.DataPlanePhase) float64 {
	switch p {
	case model.PhaseReady:
		return 0
	case model.PhaseReconciling:
		return 1
	case model.PhasePending:
		return 2
	case model.PhaseDegraded:
		return 3
	case model.PhaseDead:
		return 4
	default:
		return -1
	}
}

// RecordDesiredStatus folds the DesiredStore's fail-static snapshot into gauges.
func (m *Metrics) RecordDesiredStatus(frozen bool, generation uint64) {
	if m == nil {
		return
	}
	m.frozen.Set(boolGauge(frozen))
	if generation > 0 {
		m.generation.Set(float64(generation))
	}
}

func boolGauge(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// factory registers collectors at construction with shared const labels.
type factory struct {
	reg    *prometheus.Registry
	labels prometheus.Labels
}

func (f factory) counter(name, help string) prometheus.Counter {
	c := prometheus.NewCounter(prometheus.CounterOpts{Name: name, Help: help, ConstLabels: f.labels})
	f.reg.MustRegister(c)
	return c
}
func (f factory) gauge(name, help string) prometheus.Gauge {
	g := prometheus.NewGauge(prometheus.GaugeOpts{Name: name, Help: help, ConstLabels: f.labels})
	f.reg.MustRegister(g)
	return g
}
