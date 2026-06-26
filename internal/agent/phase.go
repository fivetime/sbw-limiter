package agent

import (
	"log/slog"
	"sync"

	"github.com/fivetime/sbw-contract/model"
)

// engineProbe is the L4 data-plane-engine liveness probe: Stalled returns the
// worker indices whose vlib loop counter is frozen (wedged). *vpp.EngineLiveness
// satisfies it; nil disables wedge detection (e.g. no stats segment).
type engineProbe interface {
	Stalled() ([]int, error)
}

// PhaseInputs are the layered-liveness facts ComputePhase reduces to a phase
// (DESIGN-liveness §4.1). They come from the layers that matter — the socket and
// the L4 engine — never from the L2 ControlPing.
type PhaseInputs struct {
	SocketUp      bool  // VPP socket connected + binding-compatible (vpp.Conn.Healthy)
	EverConnected bool  // have we ever been SocketUp (startup-Pending vs lost-Dead)
	Pending       int   // desired-actual deltas still to apply (>0 = busy applying)
	ApplyErr      error // last reconcile pass error (a real failure, not slowness)
	WedgedWorkers int   // L4: count of frozen worker loops (0 = engine advancing)
}

// ComputePhase reduces the layered facts to one phase. Pure + total — the whole
// point is to NOT depend on a fixed timeout. The order encodes precedence: a gone
// socket dominates (real death); a wedged engine or an erroring apply is Degraded;
// outstanding work is Reconciling (busy == alive, NOT dead); otherwise Ready.
func ComputePhase(in PhaseInputs) model.DataPlanePhase {
	switch {
	case !in.SocketUp && in.EverConnected:
		return model.PhaseDead // socket lost after being up — real death
	case !in.SocketUp:
		return model.PhasePending // startup / first connect not yet healthy
	case in.WedgedWorkers > 0:
		return model.PhaseDegraded // L4 worker wedge — ControlPing-blind partial outage
	case in.ApplyErr != nil:
		return model.PhaseDegraded // applies erroring (real failure, not slowness)
	case in.Pending > 0:
		return model.PhaseReconciling // busy applying — a slow main thread is normal here
	default:
		return model.PhaseReady // synced, engine advancing
	}
}

// PhaseTracker maintains the agent's current data-plane phase across two cadences:
// the reconcile loop feeds apply progress via SetApplyState (per pass, ~60s), and a
// fast probe ticker calls Tick (every few seconds) to sample the L4 engine + the
// socket and recompute — so a worker wedge is caught between the slow passes.
// Tick must be called from a single goroutine (engineProbe is not goroutine-safe);
// SetApplyState and Phase are safe to call concurrently with it.
type PhaseTracker struct {
	conn Liveness
	eng  engineProbe // may be nil → no L4 wedge detection
	log  *slog.Logger

	mu            sync.Mutex
	everConnected bool
	pending       int
	applyErr      error
	wedged        int // workers wedged at the last Tick (L4); cached so SetApplyState recomputes without re-sampling the single-caller engine probe
	phase         model.DataPlanePhase
}

// recomputeLocked recomputes the phase from the current cached inputs. mu held.
func (pt *PhaseTracker) recomputeLocked() {
	up := pt.conn.Healthy()
	if up {
		pt.everConnected = true
	}
	next := ComputePhase(PhaseInputs{
		SocketUp:      up,
		EverConnected: pt.everConnected,
		Pending:       pt.pending,
		ApplyErr:      pt.applyErr,
		WedgedWorkers: pt.wedged,
	})
	if next != pt.phase {
		pt.log.Info("data-plane phase", "from", pt.phase, "to", next,
			"socket_up", up, "pending", pt.pending, "wedged_workers", pt.wedged, "apply_err", pt.applyErr)
	}
	pt.phase = next
}

// NewPhaseTracker builds a tracker over the VPP connection liveness and an optional
// L4 engine probe (nil to disable wedge detection). log (nil → discard) records
// every phase transition.
func NewPhaseTracker(conn Liveness, eng engineProbe, log *slog.Logger) *PhaseTracker {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &PhaseTracker{conn: conn, eng: eng, log: log, phase: model.PhasePending}
}

// SetApplyState records the latest reconcile pass outcome (pending = desired-actual
// deltas, applyErr = the pass error) and recomputes the phase immediately, so a
// report built right after a pass reflects this pass. Reuses the engine-wedge result
// cached from the last Tick (does not re-sample the probe).
func (pt *PhaseTracker) SetApplyState(pending int, applyErr error) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.pending = pending
	pt.applyErr = applyErr
	pt.recomputeLocked()
}

// Tick samples the L4 engine probe, refreshes the cached wedge count, and recomputes
// the phase, returning it. Call on a few-second ticker (faster than the reconcile
// interval) from a SINGLE goroutine — the engine probe is not goroutine-safe.
func (pt *PhaseTracker) Tick() model.DataPlanePhase {
	wedged := 0
	if pt.eng != nil {
		// A read error = "engine status unknown" — never synthesize a wedge.
		if stalled, err := pt.eng.Stalled(); err == nil {
			wedged = len(stalled)
		}
	}
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.wedged = wedged
	pt.recomputeLocked()
	return pt.phase
}

// Phase returns the most recently computed phase.
func (pt *PhaseTracker) Phase() model.DataPlanePhase {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	return pt.phase
}
