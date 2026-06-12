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
	fibDrift        prometheus.Gauge
	policersDesired prometheus.Gauge
	sessionsDesired prometheus.Gauge
	generation      prometheus.Gauge // last applied desired-state generation
	frozen          prometheus.Gauge // 1 when fail-static frozen (controller unreachable)
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
	m.fibDrift = f.gauge("sbw_agent_fib_drift", "Three-way route-count drift (T-502); 0 = consistent.")
	m.policersDesired = f.gauge("sbw_agent_policers_desired", "Policers in the current desired state.")
	m.sessionsDesired = f.gauge("sbw_agent_classify_sessions_desired", "Classify sessions in the current desired state.")
	m.generation = f.gauge("sbw_agent_desired_generation", "Last applied desired-state generation.")
	m.frozen = f.gauge("sbw_agent_controller_frozen", "1 when fail-static frozen (controller unreachable, holding last state).")
	return m
}

// Registry exposes the underlying registry (tests).
func (m *Metrics) Registry() *prometheus.Registry { return m.reg }

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
	m.fibDrift.Set(float64(r.FIBDrift))
	m.policersDesired.Set(float64(r.PolicersDesired))
	m.sessionsDesired.Set(float64(r.SessionsDesired))
	m.generation.Set(float64(r.GenerationApplied))
	m.vppConnected.Set(boolGauge(r.VPPConnected))
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
