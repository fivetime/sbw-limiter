package agent

import (
	"testing"

	"github.com/fivetime/sbw-contract/model"
)

// TestSubmitDeltaCountsDrops proves SubmitDelta counts deltas it discards under deltaQ
// overflow (the local back-pressure the server turns into a delivery-degraded BSS event,
// DESIGN §9.1). While the 64-deep buffer has room nothing drops; each overflow bumps the
// cumulative counter. No VPP / Run loop needed — SubmitDelta only touches deltaQ.
func TestSubmitDeltaCountsDrops(t *testing.T) {
	r := New(nil, nil) // nil conn: SubmitDelta never dereferences it; nil log → discard

	// Fill the buffer exactly (cap 64) — no drops yet.
	for i := 0; i < 64; i++ {
		r.SubmitDelta(model.EdgeDesiredDelta{})
	}
	if got := r.DeltasDropped(); got != 0 {
		t.Fatalf("no drops expected while buffer has room, got %d", got)
	}

	// Overflow 5 → 5 drops (nothing draining deltaQ).
	for i := 0; i < 5; i++ {
		r.SubmitDelta(model.EdgeDesiredDelta{})
	}
	if got := r.DeltasDropped(); got != 5 {
		t.Fatalf("DeltasDropped after overflow = %d, want 5", got)
	}
}

// TestHealthReportCarriesDeltasDropped proves the WithDeltasDropped source is folded into
// the health report, so the server can compare successive reports and emit
// delivery-degraded on a rise (DESIGN §9.1). A pre-§9.1 build (no source) reports 0.
func TestHealthReportCarriesDeltasDropped(t *testing.T) {
	dropped := uint64(0)
	hc := NewHealthChecker("edge-x", fakeLive{healthy: true},
		WithClock(func() int64 { return 1 }),
		WithDeltasDropped(func() uint64 { return dropped }))

	hc.Observe(model.EdgeDesiredState{Generation: 1}, Result{}, nil)
	if rep, _ := hc.Last(); rep.DeltasDropped != 0 {
		t.Fatalf("clean report DeltasDropped = %d, want 0", rep.DeltasDropped)
	}

	dropped = 12
	hc.Observe(model.EdgeDesiredState{Generation: 2}, Result{}, nil)
	if rep, _ := hc.Last(); rep.DeltasDropped != 12 {
		t.Fatalf("report DeltasDropped = %d, want 12", rep.DeltasDropped)
	}
}

// TestHealthReportNoDeltasSourceReportsZero proves a build that never wires
// WithDeltasDropped reads back 0 (omitempty), so the server's rise-detector never
// false-fires for a pre-§9.1 agent.
func TestHealthReportNoDeltasSourceReportsZero(t *testing.T) {
	hc := NewHealthChecker("edge-y", fakeLive{healthy: true}, WithClock(func() int64 { return 1 }))
	hc.Observe(model.EdgeDesiredState{Generation: 1}, Result{}, nil)
	if rep, _ := hc.Last(); rep.DeltasDropped != 0 {
		t.Fatalf("no-source report DeltasDropped = %d, want 0", rep.DeltasDropped)
	}
}
