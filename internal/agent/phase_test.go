package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fivetime/sbw-contract/model"
)

func TestComputePhase(t *testing.T) {
	errApply := errors.New("ENOMEM")
	cases := []struct {
		name string
		in   PhaseInputs
		want model.DataPlanePhase
	}{
		{"startup → pending", PhaseInputs{SocketUp: false, EverConnected: false}, model.PhasePending},
		{"socket lost → dead", PhaseInputs{SocketUp: false, EverConnected: true}, model.PhaseDead},
		{"apply err → degraded", PhaseInputs{SocketUp: true, EverConnected: true, ApplyErr: errApply}, model.PhaseDegraded},
		{"busy → reconciling", PhaseInputs{SocketUp: true, EverConnected: true, Pending: 5}, model.PhaseReconciling},
		{"bird busy → reconciling", PhaseInputs{SocketUp: true, EverConnected: true, BirdBusy: true}, model.PhaseReconciling},
		{"apply busy → reconciling", PhaseInputs{SocketUp: true, EverConnected: true, ApplyBusy: true}, model.PhaseReconciling},
		{"synced → ready", PhaseInputs{SocketUp: true, EverConnected: true}, model.PhaseReady},
		// precedence
		{"dead dominates", PhaseInputs{SocketUp: false, EverConnected: true, Pending: 5}, model.PhaseDead},
		{"dead dominates bird-busy", PhaseInputs{SocketUp: false, EverConnected: true, BirdBusy: true}, model.PhaseDead},
		{"apply-err beats busy", PhaseInputs{SocketUp: true, EverConnected: true, Pending: 5, ApplyErr: errApply}, model.PhaseDegraded},
		{"apply-err beats bird-busy", PhaseInputs{SocketUp: true, EverConnected: true, BirdBusy: true, ApplyErr: errApply}, model.PhaseDegraded},
		{"apply-err beats apply-busy", PhaseInputs{SocketUp: true, EverConnected: true, ApplyBusy: true, ApplyErr: errApply}, model.PhaseDegraded},
	}
	for _, c := range cases {
		if got := ComputePhase(c.in); got != c.want {
			t.Errorf("%s: ComputePhase=%q want %q", c.name, got, c.want)
		}
	}
}

type phaseConn struct{ up bool }

func (p *phaseConn) Healthy() bool { return p.up }

func TestPhaseTracker(t *testing.T) {
	conn := &phaseConn{up: false}
	pt := NewPhaseTracker(conn, nil)

	if pt.Phase() != model.PhasePending {
		t.Fatalf("initial phase = %q, want Pending", pt.Phase())
	}
	// startup: never connected → Pending (NOT Dead).
	if p := pt.Tick(); p != model.PhasePending {
		t.Fatalf("startup = %q, want Pending", p)
	}
	// socket up + deltas pending → Reconciling (busy == alive, NOT dead).
	conn.up = true
	pt.SetApplyState(10, nil)
	if p := pt.Tick(); p != model.PhaseReconciling {
		t.Fatalf("busy = %q, want Reconciling", p)
	}
	// caught up → Ready.
	pt.SetApplyState(0, nil)
	if p := pt.Tick(); p != model.PhaseReady {
		t.Fatalf("synced = %q, want Ready", p)
	}
	// apply error → Degraded (a real failure the agent observed, NOT idle).
	pt.SetApplyState(0, errors.New("ENOMEM"))
	if p := pt.Tick(); p != model.PhaseDegraded {
		t.Fatalf("apply error = %q, want Degraded", p)
	}
	pt.SetApplyState(0, nil)
	// socket lost after having been up → Dead (real death, no timer).
	conn.up = false
	if p := pt.Tick(); p != model.PhaseDead {
		t.Fatalf("socket lost = %q, want Dead", p)
	}
}

// SetBirdBusy folds the bird-feed busy signal into the phase (§6.63): a synced
// edge (no own deltas) whose bird is down/re-dumping reports Reconciling, not
// Ready — so the server's hard-death grace rides out the bird restart. Sampled on
// every recompute (Tick + Observe).
func TestPhaseTrackerBirdBusy(t *testing.T) {
	conn := &phaseConn{up: true}
	pt := NewPhaseTracker(conn, nil)
	pt.SetApplyState(0, nil) // own deltas drained → would be Ready

	busy := true
	pt.SetBirdBusy(func() bool { return busy })
	if p := pt.Tick(); p != model.PhaseReconciling {
		t.Fatalf("bird busy: Tick = %q, want Reconciling", p)
	}
	busy = false // bird caught up
	if p := pt.Tick(); p != model.PhaseReady {
		t.Fatalf("bird idle: Tick = %q, want Ready", p)
	}
}

// SetApplyBusy folds in-flight/queued materialization (Reconciler.Busy) into the
// phase (§6.67 wall-①): the pass-boundary feed (SetApplyState) says pending=0 both
// before a long grind starts and after it ends, so mid-grind Reconciling must come
// from the live in-flight signal, sampled on every recompute.
func TestPhaseTrackerApplyBusy(t *testing.T) {
	conn := &phaseConn{up: true}
	pt := NewPhaseTracker(conn, nil)
	pt.SetApplyState(0, nil) // last pass fully drained → would be Ready

	busy := true
	pt.SetApplyBusy(func() bool { return busy })
	if p := pt.Tick(); p != model.PhaseReconciling {
		t.Fatalf("apply busy: Tick = %q, want Reconciling", p)
	}
	busy = false // grind finished
	if p := pt.Tick(); p != model.PhaseReady {
		t.Fatalf("apply idle: Tick = %q, want Ready", p)
	}
}

// Reconciler.Busy must be true while a delta is mid-apply on the reconcile
// goroutine AND while deltas sit queued — the §6.67 wall-① hot path that the
// pass-boundary phase feed is blind to.
func TestReconcilerBusyCoversDeltaHotPath(t *testing.T) {
	r := New(nil, nil)
	entered := make(chan struct{})
	release := make(chan struct{})
	r.SetDeltaApplier(func(model.EdgeDesiredDelta) {
		close(entered)
		<-release
	})

	if r.Busy() {
		t.Fatal("Busy() = true before any work")
	}
	r.SubmitDelta(model.EdgeDesiredDelta{Generation: 2, BaseGeneration: 1})
	if !r.Busy() {
		t.Fatal("Busy() = false with a delta queued")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Run(ctx, time.Hour, func() (model.EdgeDesiredState, bool) {
			return model.EdgeDesiredState{}, false // fail-static: full passes are no-ops
		})
	}()

	<-entered // delta apply is now in flight (queue already drained)
	if !r.Busy() {
		t.Fatal("Busy() = false while a delta apply is in flight")
	}
	close(release)
	cancel()
	<-done
	if r.Busy() {
		t.Fatal("Busy() = true after the loop stopped with no work queued")
	}
}
