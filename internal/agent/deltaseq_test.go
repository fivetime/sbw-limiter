package agent

import (
	"log/slog"
	"testing"

	"github.com/fivetime/sbw-contract/model"
)

// seqHarness drives a DeltaSequencer with a fake apply that enforces contiguity
// (apply must only ever see a delta chaining onto the current last-applied) and
// records the order deltas were applied in.
type seqHarness struct {
	last    uint64
	applied []uint64
	failAt  uint64 // if non-zero, apply returns false (no advance) for this generation
	t       *testing.T
}

func (h *seqHarness) apply(d model.EdgeDesiredDelta) bool {
	if d.BaseGeneration != h.last {
		h.t.Fatalf("apply saw non-contiguous delta: base=%d last-applied=%d", d.BaseGeneration, h.last)
	}
	if h.failAt != 0 && d.Generation == h.failAt {
		return false // simulate a cold-start/apply error: last-applied does NOT advance
	}
	h.last = d.Generation
	h.applied = append(h.applied, d.Generation)
	return true
}

func newSeq(t *testing.T, start uint64) (*seqHarness, *DeltaSequencer) {
	h := &seqHarness{last: start, t: t}
	return h, NewDeltaSequencer(func() uint64 { return h.last }, h.apply, slog.New(slog.DiscardHandler))
}

func d(base, gen uint64) model.EdgeDesiredDelta {
	return model.EdgeDesiredDelta{SchemaVersion: model.SchemaVersion, BaseGeneration: base, Generation: gen}
}

// The core §6.28 property: deltas delivered OUT OF ORDER are applied IN chain order,
// with zero drops (no resync), the instant the chain becomes contiguous.
func TestDeltaSequencerReordersOutOfOrder(t *testing.T) {
	h, seq := newSeq(t, 10)
	// chain 10→11→12→13→14 delivered scrambled.
	for _, dl := range []model.EdgeDesiredDelta{d(12, 13), d(13, 14), d(11, 12), d(10, 11)} {
		seq.Submit(dl)
	}
	// 13,14,12 arrive ahead → buffered; 11 lands → drains 12,13,14.
	want := []uint64{11, 12, 13, 14}
	if len(h.applied) != len(want) {
		t.Fatalf("applied %v, want %v", h.applied, want)
	}
	for i := range want {
		if h.applied[i] != want[i] {
			t.Fatalf("applied order %v, want %v", h.applied, want)
		}
	}
	if seq.Buffered() != 0 {
		t.Errorf("buffer not drained: %d entries left", seq.Buffered())
	}
	if h.last != 14 {
		t.Errorf("last-applied = %d, want 14", h.last)
	}
}

// A delta whose base is BELOW the chain (already applied / superseded) is ignored,
// never re-applied.
func TestDeltaSequencerIgnoresBelowChain(t *testing.T) {
	h, seq := newSeq(t, 20)
	seq.Submit(d(10, 11)) // stale duplicate from before a resync
	if len(h.applied) != 0 {
		t.Fatalf("stale below-chain delta was applied: %v", h.applied)
	}
	if seq.Buffered() != 0 {
		t.Errorf("stale delta buffered: %d", seq.Buffered())
	}
}

// A genuinely lost predecessor leaves the successor buffered; a full resync jumping
// last-applied forward strands it, and it is evicted (not applied) on the next Submit.
func TestDeltaSequencerFullResyncEvictsStranded(t *testing.T) {
	h, seq := newSeq(t, 10)
	seq.Submit(d(11, 12)) // predecessor (base10→gen11) is LOST; buffer gen12
	if seq.Buffered() != 1 {
		t.Fatalf("ahead-of-chain delta not buffered: %d", seq.Buffered())
	}
	// Full resync applies out-of-band, jumping last-applied to 30.
	h.last = 30
	// A fresh delta chains onto the resync (base30→gen31); the stranded gen12 (base11
	// < 30) must be evicted, NOT applied.
	seq.Submit(d(30, 31))
	if h.last != 31 {
		t.Fatalf("post-resync delta not applied: last=%d", h.last)
	}
	if seq.Buffered() != 0 {
		t.Errorf("stranded delta not evicted: %d buffered", seq.Buffered())
	}
	for _, g := range h.applied {
		if g == 12 {
			t.Fatal("stranded delta gen12 was wrongly applied after resync")
		}
	}
}

// The buffer is bounded: a flood of ahead-of-chain deltas (lost predecessor) clears
// rather than growing unbounded, falling back to resync.
func TestDeltaSequencerBufferBounded(t *testing.T) {
	h, seq := newSeq(t, 0)
	seq.max = 4
	// All ahead of chain (base never equals last-applied 0), predecessor never comes.
	for i := uint64(0); i < 10; i++ {
		seq.Submit(d(100+i, 200+i))
	}
	if seq.Buffered() > seq.max {
		t.Errorf("buffer exceeded max: %d > %d", seq.Buffered(), seq.max)
	}
	if len(h.applied) != 0 {
		t.Errorf("nothing should apply with a permanently missing predecessor, applied %v", h.applied)
	}
}

// An apply that fails (cold start / partial VPP) does NOT advance the chain, and the
// would-be successor stays buffered until a real advance — no silent skip.
func TestDeltaSequencerApplyFailureHoldsChain(t *testing.T) {
	h, seq := newSeq(t, 10)
	h.failAt = 11         // applying gen11 fails
	seq.Submit(d(11, 12)) // buffered (ahead)
	seq.Submit(d(10, 11)) // chains, but apply fails → no advance, no drain
	if h.last != 10 {
		t.Fatalf("failed apply advanced the chain to %d", h.last)
	}
	if len(h.applied) != 0 {
		t.Fatalf("failed delta counted as applied: %v", h.applied)
	}
	// gen12 remains buffered (its predecessor never successfully applied).
	if seq.Buffered() != 1 {
		t.Errorf("successor should stay buffered after predecessor apply failure: %d", seq.Buffered())
	}
}

// TestApplyFailureAdvancesChainSoRemovalLands pins §6.40 layer 4: a delta whose
// VPP apply FAILS (after the desired-state Merge succeeded) must still ADVANCE the
// applied-generation chain. lastGen is the position on the DESIRED chain, not a VPP
// completion marker: a pool with VPP-rejected parameters retries (and fails)
// forever, so refusing to advance stranded every later delta in the reorder buffer
// behind an un-completable predecessor — even the bad pool's own REMOVAL delta
// could never land, and the ghost pool kept its home edges Degraded until a
// restart. Model the fixed handler contract at the sequencer boundary: apply
// returns TRUE (chain advanced) even when VPP errored, and the buffered removal
// (base = the failed delta's generation) drains immediately.
func TestApplyFailureAdvancesChainSoRemovalLands(t *testing.T) {
	h := &seqHarness{last: 10, t: t}
	// The fixed applyOneDelta contract: Merge adopts the delta (chain advances)
	// even when the VPP apply errors — so this apply NEVER returns false for a
	// merged delta, and the harness's contiguity check still holds.
	seq := NewDeltaSequencer(func() uint64 { return h.last }, h.apply, slog.New(slog.DiscardHandler))

	// Removal (base 11) arrives BEFORE its predecessor (the bad create, gen 11):
	// buffered.
	seq.Submit(d(11, 12))
	if seq.Buffered() != 1 {
		t.Fatalf("removal not buffered: %d", seq.Buffered())
	}
	// The bad create lands and its VPP apply FAILS — under the OLD contract apply
	// returned false, the chain stayed at 10, and gen 12 (the removal) stayed
	// buffered forever. Under the fixed contract the chain advances to 11 and the
	// removal drains at once.
	seq.Submit(d(10, 11))
	if h.last != 12 {
		t.Fatalf("chain = %d, want 12 (bad create advanced to 11, removal drained to 12)", h.last)
	}
	if seq.Buffered() != 0 {
		t.Fatalf("removal still stranded: %d buffered", seq.Buffered())
	}
}
