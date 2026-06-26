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
		{"apply err → degraded", PhaseInputs{SocketUp: true, EverConnected: true, ApplyErr: errApply}, model.PhaseDegraded},
		{"busy → reconciling", PhaseInputs{SocketUp: true, EverConnected: true, Pending: 5}, model.PhaseReconciling},
		{"synced → ready", PhaseInputs{SocketUp: true, EverConnected: true}, model.PhaseReady},
		// precedence
		{"dead dominates", PhaseInputs{SocketUp: false, EverConnected: true, Pending: 5}, model.PhaseDead},
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
