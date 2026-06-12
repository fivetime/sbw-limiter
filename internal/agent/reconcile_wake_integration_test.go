//go:build integration

package agent

import (
	"context"
	"testing"
	"time"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/vpp"
)

// TestRealWakeAppliesPushPromptly proves T-705 against real VPP: a desired-state
// push, signalled via Reconciler.Wake, converges the data plane in milliseconds
// — NOT on the reconcile timer. The loop runs with a 1-hour interval, so any
// convergence we observe within a short window must have come from the wake.
func TestRealWakeAppliesPushPromptly(t *testing.T) {
	r, conn := realReconciler(t)
	store := NewDesiredStore()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx, time.Hour, store.Desired) // huge interval: only the wake can drive a pass

	managed := []string{
		model.PolicerName(850, model.DirectionIngress),
		model.PolicerName(850, model.DirectionEgress),
	}
	// Ensure a clean slate afterwards. The Run loop is gone by cleanup time (ctx
	// cancelled), so prune synchronously with a direct one-shot reconcile to an
	// empty desired state — it deletes our managed policers as orphans.
	t.Cleanup(func() {
		if _, err := r.Reconcile(model.EdgeDesiredState{SchemaVersion: model.SchemaVersion, EdgeID: "test"}); err != nil {
			t.Errorf("cleanup reconcile: %v", err)
		}
		waitPolicers(t, conn, managed, false, 2*time.Second)
	})

	// Push a desired state with two policers and wake the loop.
	store.Accept(desiredWith(spec(850, model.DirectionIngress, 1_000_000), spec(850, model.DirectionEgress, 2_000_000)))
	r.Wake()

	// They must appear in real VPP well within the 1-hour interval — i.e. from
	// the wake, not the timer.
	waitPolicers(t, conn, managed, true, 2*time.Second)

	// A second push (rate change) must also converge promptly on wake.
	store.Accept(desiredWith(spec(850, model.DirectionIngress, 5_000_000), spec(850, model.DirectionEgress, 2_000_000)))
	r.Wake()
	deadline := time.Now().Add(2 * time.Second)
	for {
		live := livePolicerNames(t, conn)
		if p, ok := live[managed[0]]; ok && p.CIR == 5_000_000 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("rate change did not converge promptly on wake; live=%v", livePolicerNames(t, conn))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitPolicers polls live VPP until all names are present (want=true) or absent
// (want=false), or the timeout elapses.
func waitPolicers(t *testing.T, conn *vpp.Conn, names []string, want bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		live := livePolicerNames(t, conn)
		ok := true
		for _, n := range names {
			if _, present := live[n]; present != want {
				ok = false
				break
			}
		}
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("policers %v want present=%v not reached; live=%v", names, want, live)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
