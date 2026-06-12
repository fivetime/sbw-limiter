//go:build integration

package agent

import (
	"testing"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/vpp"
)

// B-05 acceptance against real VPP (limiter §5.6): the soft-death health report
// tracks the data-plane ground truth across a destroyed-rule self-heal and a
// VPP link loss — failures BGP/BFD cannot see. Driven off the reconcile loop's
// observer hook. Run with BWPOOL_TEST_VPP_SOCKET set.
func TestRealSoftDeathDetectionAndSelfHeal(t *testing.T) {
	r, conn := realReconciler(t)

	hc := NewHealthChecker("edge-test", conn)
	r.AddObserver(hc.Observe)

	desired := desiredWith(
		spec(5200, model.DirectionIngress, 1_000_000),
		spec(5200, model.DirectionEgress, 1_000_000),
	)
	provider := func() (model.EdgeDesiredState, bool) { return desired, true }

	// 1. Converge from empty, then steady → Healthy.
	r.runOnce(provider)
	r.runOnce(provider)
	rep, seen := hc.Last()
	if !seen || rep.State != model.HealthHealthy {
		t.Fatalf("after converge: want healthy, got %+v (seen=%v)", rep, seen)
	}
	if rep.PolicersDesired != 2 {
		t.Errorf("PolicersDesired = %d, want 2", rep.PolicersDesired)
	}

	// 2. Soft death: a policer is destroyed out-of-band (device lost), control
	//    link still up. BGP cannot see this; the next reconcile must.
	deletePolicerOutOfBand(t, conn, model.PolicerName(5200, model.DirectionIngress))
	r.runOnce(provider) // detects missing → re-adds (local repair), notify → Degraded
	rep, _ = hc.Last()
	if rep.State != model.HealthDegraded {
		t.Fatalf("after destroy: want degraded, got %+v", rep)
	}
	if rep.RepairActions == 0 {
		t.Errorf("expected RepairActions > 0 (self-heal), got 0")
	}
	if !rep.VPPConnected {
		t.Errorf("VPP should still be connected during soft-death repair")
	}

	// 3. Steady again → Healthy (self-heal converged).
	r.runOnce(provider)
	if rep, _ := hc.Last(); rep.State != model.HealthHealthy {
		t.Fatalf("after heal: want healthy, got %+v", rep)
	}

	// Clean test policers while the link is still up.
	if _, err := r.Reconcile(desiredWith()); err != nil {
		t.Fatalf("cleanup reconcile: %v", err)
	}

	// 4. VPP control link down → DataPlaneDown / SoftDead (the unrecoverable
	//    case the controller must promote the backup for, §4.3/§4.7).
	conn.Close()
	r.runOnce(provider)
	rep, _ = hc.Last()
	if rep.State != model.HealthDataPlaneDown || !rep.SoftDead() {
		t.Fatalf("after link down: want dataplane-down/softdead, got %+v", rep)
	}
	if rep.VPPConnected {
		t.Errorf("VPPConnected should be false after Close")
	}
}

func deletePolicerOutOfBand(t *testing.T, conn *vpp.Conn, name string) {
	t.Helper()
	ch, err := conn.Channel()
	if err != nil {
		t.Fatalf("channel: %v", err)
	}
	defer ch.Close()
	if err := vpp.NewPolicers(ch).DeleteByName(name); err != nil {
		t.Fatalf("out-of-band delete %s: %v", name, err)
	}
}
