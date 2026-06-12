//go:build integration

package agent

import (
	"context"
	"testing"
	"time"

	"github.com/fivetime/sbw-contract/model"
)

// T-505 acceptance against real VPP (DESIGN.md §6.4): when the controller is
// unreachable the agent freezes the last desired state — policers and rules
// persist, nothing is pruned or loosened.
//
// Two arms, both run the real reconcile loop against real VPP:
//  1. Cold start: an agent that boots while the controller is down has no
//     desired state. It must SKIP reconciliation, leaving a data plane that
//     outlived it untouched — NOT prune it to empty (the catastrophe a naive
//     "no state == empty desired" would cause).
//  2. Steady-state freeze: with a cached state and the controller down, the loop
//     keeps converging to the cached state, so the policers persist across ticks.

// runLoopFor runs the reconcile loop for d, then stops it (context timeout).
func runLoopFor(r *Reconciler, store *DesiredStore, d time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	r.Run(ctx, 200*time.Millisecond, store.Desired)
}

func TestRealFailStaticColdStartDoesNotPrune(t *testing.T) {
	r, conn := realReconciler(t)
	t.Cleanup(func() { _, _ = r.Reconcile(desiredWith()) }) // prune all on exit

	// A data plane installed before the agent (in)voluntarily restarted.
	seeded := desiredWith(
		spec(5400, model.DirectionIngress, 1_000_000),
		spec(5400, model.DirectionEgress, 1_000_000),
	)
	if _, err := r.Reconcile(seeded); err != nil {
		t.Fatalf("seed: %v", err)
	}
	for _, n := range []string{"pool5400_in", "pool5400_out"} {
		if _, ok := livePolicerNames(t, conn)[n]; !ok {
			t.Fatalf("seed policer %s missing", n)
		}
	}

	// Simulate an agent that just booted while the controller is unreachable:
	// a fresh reconciler (empty index cache, like a restart) and an empty store.
	r2 := New(conn, nil)
	store := NewDesiredStore()
	store.ControllerDown()

	// Run several passes. A correct agent skips every one (no authoritative
	// state); a buggy "empty desired" agent would prune the seeded policers on
	// the very first pass.
	runLoopFor(r2, store, 1500*time.Millisecond)

	live := livePolicerNames(t, conn)
	for _, n := range []string{"pool5400_in", "pool5400_out"} {
		if _, ok := live[n]; !ok {
			t.Errorf("fail-static violated: cold-start loop pruned %s (live=%v)", n, live)
		}
	}
}

func TestRealFailStaticFrozenServesLastState(t *testing.T) {
	r, conn := realReconciler(t)
	t.Cleanup(func() { _, _ = r.Reconcile(desiredWith()) })

	// The controller delivered a state; the agent installs it.
	store := NewDesiredStore()
	store.Accept(model.EdgeDesiredState{
		SchemaVersion: model.SchemaVersion, EdgeID: "test", Generation: 1,
		Policers: []model.PolicerSpec{
			spec(5410, model.DirectionIngress, 1_000_000),
			spec(5410, model.DirectionEgress, 1_000_000),
		},
	})
	runLoopFor(r, store, 600*time.Millisecond) // converge
	managed := []string{"pool5410_in", "pool5410_out"}
	for _, n := range managed {
		if _, ok := livePolicerNames(t, conn)[n]; !ok {
			t.Fatalf("policer %s not installed before freeze", n)
		}
	}

	// Controller drops. The loop keeps running and must keep converging to the
	// cached state — the policers persist, nothing is withdrawn.
	store.ControllerDown()
	if !store.Status().Frozen {
		t.Fatal("store should report Frozen")
	}
	runLoopFor(r, store, 1500*time.Millisecond)

	live := livePolicerNames(t, conn)
	for _, n := range managed {
		if _, ok := live[n]; !ok {
			t.Errorf("fail-static violated: froze but %s vanished (live=%v)", n, live)
		}
	}
}
