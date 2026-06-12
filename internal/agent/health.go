package agent

import (
	"sync"
	"time"

	"github.com/fivetime/sbw-contract/model"
)

// Liveness is the data-plane control-link liveness signal; *vpp.Conn satisfies
// it. False means the agent cannot reach VPP at all — a hard soft-death signal
// (BGP/BFD cannot see it).
type Liveness interface {
	Healthy() bool
}

// Classify turns one reconcile pass into a soft-death health report (B-05,
// limiter §5.6). It is a pure function of the data-plane ground truth the
// reconcile observed:
//
//   - VPP link down, or the reconcile itself failed → DataPlaneDown: local
//     repair is impossible, the controller must promote the backup (§4.3/§4.7).
//   - VPP up but the pass had to repair drift (rules lost/destroyed) or the FIB
//     drifted → Degraded: a soft-death symptom that self-healed this cycle.
//   - VPP up, nothing to repair, FIB agrees → Healthy.
//
// The reconcile is the dataplane-penetrating probe (it dumps actual VPP state to
// compute drift), so its result IS the ground truth — no second scan needed.
func Classify(edgeID model.EdgeID, desired model.EdgeDesiredState, vppHealthy bool, res Result, reconcileErr error, fibDrift int, nowMs int64) model.HealthReport {
	rep := model.HealthReport{
		EdgeID:            edgeID,
		GenerationApplied: desired.Generation,
		ObservedAtUnixMs:  nowMs,
		VPPConnected:      vppHealthy,
		PolicersDesired:   len(desired.Policers),
		SessionsDesired:   len(desired.ClassifySessions),
		RepairActions:     res.Total(),
		FIBDrift:          fibDrift,
	}

	switch {
	case !vppHealthy:
		rep.State = model.HealthDataPlaneDown
		rep.Reason = "vpp control link down"
	case reconcileErr != nil:
		rep.State = model.HealthDataPlaneDown
		rep.Reason = "reconcile failed: " + reconcileErr.Error()
	case rep.RepairActions > 0:
		rep.State = model.HealthDegraded
		rep.Reason = "data-plane drift repaired locally (soft-death symptom)"
	case fibDrift != 0:
		rep.State = model.HealthDegraded
		rep.Reason = "FIB route-count drift (linux-cp soft death)"
	default:
		rep.State = model.HealthHealthy
	}
	return rep
}

// HealthChecker maintains the latest soft-death health report off the reconcile
// loop (B-05). Register Observe via Reconciler.AddObserver; the controller-facing
// uplink (B-03) reads Last() to report data-plane ground truth.
type HealthChecker struct {
	edgeID model.EdgeID
	live   Liveness

	// fibDrift returns the current accounting three-way route-count drift; nil
	// (no accounting wired) is treated as 0. The route audit (T-502) owns FIB
	// drift; this just folds it into the unified report.
	fibDrift func() int

	// now is injectable for tests; defaults to time.Now().UnixMilli.
	now func() int64

	mu   sync.Mutex
	last model.HealthReport
	seen bool
}

// HealthOption configures a HealthChecker.
type HealthOption func(*HealthChecker)

// WithFIBDrift wires a live FIB-drift source (e.g. the route audit) into the
// report.
func WithFIBDrift(fn func() int) HealthOption {
	return func(h *HealthChecker) { h.fibDrift = fn }
}

// WithClock overrides the timestamp source (tests).
func WithClock(now func() int64) HealthOption {
	return func(h *HealthChecker) { h.now = now }
}

// NewHealthChecker builds a checker for edgeID observing the data-plane link
// live (a *vpp.Conn).
func NewHealthChecker(edgeID model.EdgeID, live Liveness, opts ...HealthOption) *HealthChecker {
	h := &HealthChecker{edgeID: edgeID, live: live, now: func() int64 { return time.Now().UnixMilli() }}
	for _, o := range opts {
		o(h)
	}
	return h
}

// Observe classifies one reconcile pass into the latest report. Wire it via
// Reconciler.AddObserver(hc.Observe).
func (h *HealthChecker) Observe(desired model.EdgeDesiredState, res Result, reconcileErr error) {
	drift := 0
	if h.fibDrift != nil {
		drift = h.fibDrift()
	}
	rep := Classify(h.edgeID, desired, h.live.Healthy(), res, reconcileErr, drift, h.now())
	h.mu.Lock()
	h.last = rep
	h.seen = true
	h.mu.Unlock()
}

// Last returns the most recent report and whether any pass has been observed.
func (h *HealthChecker) Last() (model.HealthReport, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.last, h.seen
}
