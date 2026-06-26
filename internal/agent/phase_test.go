package agent

import (
	"errors"
	"testing"

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
		{"wedge → degraded", PhaseInputs{SocketUp: true, EverConnected: true, WedgedWorkers: 1}, model.PhaseDegraded},
		{"apply err → degraded", PhaseInputs{SocketUp: true, EverConnected: true, ApplyErr: errApply}, model.PhaseDegraded},
		{"busy → reconciling", PhaseInputs{SocketUp: true, EverConnected: true, Pending: 5}, model.PhaseReconciling},
		{"synced → ready", PhaseInputs{SocketUp: true, EverConnected: true}, model.PhaseReady},
		// precedence
		{"dead dominates", PhaseInputs{SocketUp: false, EverConnected: true, Pending: 5, WedgedWorkers: 2}, model.PhaseDead},
		{"wedge beats busy", PhaseInputs{SocketUp: true, EverConnected: true, Pending: 5, WedgedWorkers: 1}, model.PhaseDegraded},
		{"apply-err beats busy", PhaseInputs{SocketUp: true, EverConnected: true, Pending: 5, ApplyErr: errApply}, model.PhaseDegraded},
	}
	for _, c := range cases {
		if got := ComputePhase(c.in); got != c.want {
			t.Errorf("%s: ComputePhase=%q want %q", c.name, got, c.want)
		}
	}
}

type phaseConn struct{ up bool }

func (p *phaseConn) Healthy() bool { return p.up }

type phaseEng struct {
	wedged []int
	err    error
}

func (p *phaseEng) Stalled() ([]int, error) { return p.wedged, p.err }

func TestPhaseTracker(t *testing.T) {
	conn := &phaseConn{up: false}
	eng := &phaseEng{}
	pt := NewPhaseTracker(conn, eng)

	if pt.Phase() != model.PhasePending {
		t.Fatalf("initial phase = %q, want Pending", pt.Phase())
	}
	// startup: never connected → Pending (NOT Dead).
	if p := pt.Tick(); p != model.PhasePending {
		t.Fatalf("startup = %q, want Pending", p)
	}
	// socket up + deltas pending → Reconciling (busy == alive).
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
	// L4 worker wedge → Degraded (ControlPing would be blind to this).
	eng.wedged = []int{1}
	if p := pt.Tick(); p != model.PhaseDegraded {
		t.Fatalf("wedge = %q, want Degraded", p)
	}
	eng.wedged = nil
	// engine read error = unknown → must NOT synthesize a wedge; back to Ready.
	eng.err = errors.New("stats segment gone")
	if p := pt.Tick(); p != model.PhaseReady {
		t.Fatalf("engine read error = %q, want Ready (no synthesized wedge)", p)
	}
	eng.err = nil
	// socket lost after having been up → Dead (real death, no timer).
	conn.up = false
	if p := pt.Tick(); p != model.PhaseDead {
		t.Fatalf("socket lost = %q, want Dead", p)
	}
}

// nil engine probe must be safe (no L4 wedge detection) and never wedge.
func TestPhaseTrackerNilEngine(t *testing.T) {
	conn := &phaseConn{up: true}
	pt := NewPhaseTracker(conn, nil)
	pt.SetApplyState(0, nil)
	if p := pt.Tick(); p != model.PhaseReady {
		t.Fatalf("nil engine, synced = %q, want Ready", p)
	}
}
