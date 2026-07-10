package agent

import (
	"errors"
	"testing"

	"github.com/fivetime/sbw-contract/model"
)

type fakeLive struct{ healthy bool }

func (f fakeLive) Healthy() bool { return f.healthy }

func desiredN(policers, sessions int) model.EdgeDesiredState {
	d := model.EdgeDesiredState{Generation: 7}
	for i := 0; i < policers; i++ {
		d.Policers = append(d.Policers, model.PolicerSpec{})
	}
	for i := 0; i < sessions; i++ {
		d.ClassifySessions = append(d.ClassifySessions, model.ClassifySession{})
	}
	return d
}

func TestClassify(t *testing.T) {
	desired := desiredN(2, 3)
	clean := Result{}
	repaired := Result{PolicersAdded: 1, SessionsMoved: 1}

	cases := []struct {
		name       string
		vppHealthy bool
		res        Result
		err        error
		wantState  model.SoftDeathState
		wantSoft   bool
	}{
		{"healthy", true, clean, nil, model.HealthHealthy, false},
		{"drift repaired", true, repaired, nil, model.HealthDegraded, false},
		{"vpp down", false, clean, nil, model.HealthDataPlaneDown, true},
		// A reconcile error while the connection is ALIVE (vppHealthy) is "this pass could not
		// complete" (a slow/timed-out dump under load), NOT a dead data plane → self-healing
		// Degraded (retry), NOT SoftDead. Real death is caught by the connection-EOF case +
		// the active forwarding probe, latency-independent (§4.2.7).
		{"reconcile error, conn alive = degraded retry", true, clean, errors.New("boom"), model.HealthDegraded, false},
		{"vpp down dominates repair", false, repaired, nil, model.HealthDataPlaneDown, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rep := Classify("edge-2", desired, c.vppHealthy, c.res, c.err, 123)
			if rep.State != c.wantState {
				t.Errorf("state = %v, want %v", rep.State, c.wantState)
			}
			if rep.SoftDead() != c.wantSoft {
				t.Errorf("SoftDead() = %v, want %v", rep.SoftDead(), c.wantSoft)
			}
			if rep.EdgeID != "edge-2" || rep.GenerationApplied != 7 || rep.ObservedAtUnixMs != 123 {
				t.Errorf("metadata wrong: %+v", rep)
			}
			if rep.PolicersDesired != 2 || rep.SessionsDesired != 3 {
				t.Errorf("desired counts wrong: %+v", rep)
			}
			if rep.RepairActions != c.res.Total() {
				t.Errorf("RepairActions = %d, want %d", rep.RepairActions, c.res.Total())
			}
			if rep.VPPConnected != c.vppHealthy {
				t.Errorf("VPPConnected = %v, want %v", rep.VPPConnected, c.vppHealthy)
			}
		})
	}
}

func TestHealthCheckerObserveAndLast(t *testing.T) {
	live := &fakeLive{healthy: true}
	hc := NewHealthChecker("edge-2", live,
		WithClock(func() int64 { return 42 }))

	if _, seen := hc.Last(); seen {
		t.Fatal("expected no report before first Observe")
	}

	// Healthy pass.
	hc.Observe(desiredN(1, 1), Result{}, nil)
	rep, seen := hc.Last()
	if !seen || rep.State != model.HealthHealthy || rep.ObservedAtUnixMs != 42 {
		t.Fatalf("expected healthy report, got %+v seen=%v", rep, seen)
	}

	// Drift repaired → degraded.
	hc.Observe(desiredN(1, 1), Result{PolicersAdded: 1}, nil)
	if rep, _ := hc.Last(); rep.State != model.HealthDegraded || rep.RepairActions != 1 {
		t.Fatalf("expected degraded with 1 repair, got %+v", rep)
	}

	// VPP link drops → dataplane down.
	live.healthy = false
	hc.Observe(desiredN(1, 1), Result{}, nil)
	if rep, _ := hc.Last(); rep.State != model.HealthDataPlaneDown || !rep.SoftDead() {
		t.Fatalf("expected dataplane-down/softdead, got %+v", rep)
	}
}
