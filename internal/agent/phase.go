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
	// BirdBusy is true while the bird api feed is failing/reconnecting — bird is down
	// or re-dumping after a restart (§6.63 blind spot). The VPP socket + policer/
	// classify backlog above are BLIND to bird-vpp, the process that actually stalls/
	// crashes under a large anchor+flowspec push; without this a bird restart drains
	// the agent's own deltas to 0 → Ready while bird's ctrl-tap is still down, so the
	// server takes the FAST hard-death path and false-fails-over a live edge. Reporting
	// Reconciling here makes the server's §6.63 grace ride out the bird restart.
	BirdBusy bool
	// ApplyBusy is true while the reconcile goroutine has work in flight or queued
	// (a full pass or delta mid-apply, or deltaQ backlog — Reconciler.Busy, §6.67
	// wall-①). Pending above only updates at pass END (Observe), so a minutes-long
	// grind would otherwise read Ready the whole way through — exactly the window
	// where the VPP main thread starves the death sensors. Busy == alive, not dead.
	ApplyBusy bool
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
	case in.Pending > 0 || in.BirdBusy || in.ApplyBusy:
		return model.PhaseReconciling // busy applying (own deltas or bird still churning) — a slow main thread is normal here
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
	// birdBusy (nil-safe) reports whether the bird api feed is failing/reconnecting
	// (bird down or re-dumping) — folded into the phase so a bird restart reads as
	// Reconciling, not Ready (§6.63 blind spot). Sampled on every recompute so both
	// the reconcile Observe and the fast phase ticker pick it up.
	birdBusy func() bool
	// applyBusy (nil-safe) reports in-flight/queued materialization work
	// (Reconciler.Busy, §6.67 wall-①) — folded into the phase so a long full pass
	// or delta stream reads as Reconciling mid-grind, not only at pass boundaries.
	applyBusy func() bool
}

// recomputeLocked recomputes the phase from the current cached inputs. mu held.
func (pt *PhaseTracker) recomputeLocked() {
	up := pt.conn.Healthy()
	if up {
		pt.everConnected = true
	}
	birdBusy := false
	if pt.birdBusy != nil {
		birdBusy = pt.birdBusy()
	}
	applyBusy := false
	if pt.applyBusy != nil {
		applyBusy = pt.applyBusy()
	}
	next := ComputePhase(PhaseInputs{
		SocketUp:      up,
		EverConnected: pt.everConnected,
		Pending:       pt.pending,
		ApplyErr:      pt.applyErr,
		BirdBusy:      birdBusy,
		ApplyBusy:     applyBusy,
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

// SetBirdBusy wires a bird-materialization busy signal — true while the api feed is
// failing/reconnecting (bird down or re-dumping after a restart). While it returns
// true the phase is Reconciling, so the server's §6.63 hard-death grace rides out a
// bird restart instead of failing over a live edge. Call once at startup before the
// phase tickers run. nil clears it (legacy: phase blind to bird-vpp).
func (pt *PhaseTracker) SetBirdBusy(fn func() bool) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.birdBusy = fn
}

// SetApplyBusy wires the in-flight/queued materialization signal (Reconciler.Busy,
// §6.67 wall-①). Without it the phase only reflects apply progress at pass
// boundaries (Observe), so a minutes-long grind reads Ready throughout — the exact
// window the sensor busy-gates and the server's phase-aware grace need covered.
// Call once at startup before the phase tickers run. nil clears it.
func (pt *PhaseTracker) SetApplyBusy(fn func() bool) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.applyBusy = fn
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
