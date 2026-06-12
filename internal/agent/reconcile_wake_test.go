package agent

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fivetime/sbw-contract/model"
)

func TestWakeNonBlockingAndCoalescing(t *testing.T) {
	r := New(nil, nil) // wake channel initialized; conn nil is fine (not used here)
	// Two wakes in a row must not block — the second coalesces into the buffered slot.
	r.Wake()
	r.Wake()
	// Exactly one wake is pending.
	select {
	case <-r.wake:
	default:
		t.Fatal("expected one pending wake")
	}
	select {
	case <-r.wake:
		t.Fatal("wakes must coalesce to a single pending signal")
	default:
	}
}

// TestWakeTriggersImmediatePass proves a Wake forces a reconcile pass without
// waiting for the interval. The provider returns ok=false so the pass skips the
// VPP-touching Reconcile (fail-static), letting this run without a VPP conn.
func TestWakeTriggersImmediatePass(t *testing.T) {
	r := New(nil, nil)
	var passes int32
	provider := func() (model.EdgeDesiredState, bool) {
		atomic.AddInt32(&passes, 1)
		return model.EdgeDesiredState{}, false // skip Reconcile (no VPP in this test)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx, time.Hour, provider) // huge interval → only the initial pass + wakes drive it

	waitPasses(t, &passes, 1) // initial immediate pass
	r.Wake()
	waitPasses(t, &passes, 2) // wake → prompt pass
	r.Wake()
	waitPasses(t, &passes, 3)
}

func waitPasses(t *testing.T, n *int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(n) >= want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("reconcile passes = %d, want >= %d within timeout", atomic.LoadInt32(n), want)
}
