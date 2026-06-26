package vpp

import "testing"

// TestEngineLivenessStalled drives EngineLiveness through a fake loops-per-worker
// source: per-worker freeze must be caught (not masked by other workers advancing),
// only after `threshold` consecutive frozen samples, and cleared on recovery.
func TestEngineLivenessStalled(t *testing.T) {
	var seq [][]uint64
	idx := 0
	read := func() ([]uint64, error) {
		s := seq[idx]
		idx++
		return s, nil
	}
	e := newEngineLiveness(read, 2) // wedged after 2 consecutive frozen samples

	step := func(s []uint64) []int {
		seq = append(seq, s)
		w, err := e.Stalled()
		if err != nil {
			t.Fatalf("Stalled: %v", err)
		}
		return w
	}

	if w := step([]uint64{100, 200}); len(w) != 0 {
		t.Fatalf("seed: want no verdict, got %v", w)
	}
	if w := step([]uint64{110, 210}); len(w) != 0 {
		t.Fatalf("both advanced: want none, got %v", w)
	}
	// worker 1 freezes (210→210) while worker 0 keeps moving — 1st frozen sample,
	// below threshold → not yet wedged (and NOT masked by worker 0 advancing).
	if w := step([]uint64{120, 210}); len(w) != 0 {
		t.Fatalf("1st freeze below threshold: want none, got %v", w)
	}
	// worker 1 still frozen — 2nd consecutive == threshold → wedged [1].
	if w := step([]uint64{130, 210}); len(w) != 1 || w[0] != 1 {
		t.Fatalf("sustained freeze: want [1], got %v", w)
	}
	// worker 1 recovers → cleared.
	if w := step([]uint64{140, 220}); len(w) != 0 {
		t.Fatalf("recovered: want none, got %v", w)
	}
	// worker count changes (VPP restart) → reseed, no verdict.
	if w := step([]uint64{1, 2, 3}); len(w) != 0 {
		t.Fatalf("worker-count change: want reseed/none, got %v", w)
	}
}
