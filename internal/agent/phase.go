package agent

import (
	"log/slog"
	"sync"

	"github.com/fivetime/sbw-contract/model"
)

// PhaseInputs are the facts ComputePhase reduces to a phase (DESIGN-liveness §4.1).
// They come from the only data-plane layers a passive observer can know reliably:
// the socket (real death) and apply progress (busy/synced/error). NOT the L2
// ControlPing, and NOT the L4 engine — an adaptive VPP sleeps when idle so the
// per-worker loop counter freezes, indistinguishable from a wedge (verify proved
// the false positive). "Worker really forwarding" can't be told passively; that
// blind spot stays open (§4.1.6), and per-policer correctness goes through 对账.
type PhaseInputs struct {
	SocketUp      bool  // VPP socket connected + binding-compatible (vpp.Conn.Healthy)
	EverConnected bool  // have we ever been SocketUp (startup-Pending vs lost-Dead)
	Pending       int   // desired-actual deltas still to apply (>0 = busy applying)
	ApplyErr      error // last reconcile pass error (a real failure, not slowness)
}

// ComputePhase reduces the facts to one phase. Pure + total — the whole point is to
// NOT depend on a fixed timeout. Precedence: a gone socket dominates (real death); an
// erroring apply is Degraded; outstanding work is Reconciling (busy == alive, NOT
// dead); otherwise Ready.
func ComputePhase(in PhaseInputs) model.DataPlanePhase {
	switch {
	case !in.SocketUp && in.EverConnected:
		return model.PhaseDead // socket lost after being up — real death
	case !in.SocketUp:
		return model.PhasePending // startup / first connect not yet healthy
	case in.ApplyErr != nil:
		return model.PhaseDegraded // applies erroring (a real failure the agent observed)
	case in.Pending > 0:
		return model.PhaseReconciling // busy applying — a slow main thread is normal here
	default:
		return model.PhaseReady // synced
	}
}

// PhaseTracker maintains the agent's current data-plane phase. The reconcile loop
// feeds apply progress via SetApplyState (per pass), and a fast probe ticker calls
// Tick (every few seconds) to re-sample the socket and recompute — so a socket loss
// surfaces within seconds, not at the next slow pass. SetApplyState, Tick and Phase
// are safe to call concurrently.
type PhaseTracker struct {
	conn Liveness
	log  *slog.Logger

	mu            sync.Mutex
	everConnected bool
	pending       int
	applyErr      error
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
	})
	if next != pt.phase {
		pt.log.Info("data-plane phase", "from", pt.phase, "to", next,
			"socket_up", up, "pending", pt.pending, "apply_err", pt.applyErr)
	}
	pt.phase = next
}

// NewPhaseTracker builds a tracker over the VPP connection liveness. log (nil →
// discard) records every phase transition.
func NewPhaseTracker(conn Liveness, log *slog.Logger) *PhaseTracker {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &PhaseTracker{conn: conn, log: log, phase: model.PhasePending}
}

// SetApplyState records the latest reconcile pass outcome (pending = desired-actual
// deltas, applyErr = the pass error) and recomputes the phase immediately.
func (pt *PhaseTracker) SetApplyState(pending int, applyErr error) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.pending = pending
	pt.applyErr = applyErr
	pt.recomputeLocked()
}

// Tick re-samples the socket and recomputes the phase, returning it. Call on a
// few-second ticker so a socket loss surfaces promptly (faster than the reconcile pass).
func (pt *PhaseTracker) Tick() model.DataPlanePhase {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.recomputeLocked()
	return pt.phase
}

// Phase returns the most recently computed phase.
func (pt *PhaseTracker) Phase() model.DataPlanePhase {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	return pt.phase
}
