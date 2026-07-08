package agent

import (
	"log/slog"

	"github.com/fivetime/sbw-contract/model"
)

// defaultMaxPendingDeltas bounds the reorder buffer. It is a safety valve for a
// GENUINELY lost predecessor under heavy churn (which never arrives): rather than
// grow unbounded we clear and fall back to the controller's full resync. It is far
// above any real reorder window (a burst reorders a handful of deltas, not hundreds).
const defaultMaxPendingDeltas = 512

// DeltaSequencer reorders out-of-order incremental deltas back onto the server's
// linear base-generation chain before applying them (TEST-SCENARIOS §6.28).
//
// The controller mints each edge's generations under one lock, so the base-chain is
// strictly linear: every generation has exactly one successor (a delta's
// BaseGeneration equals its predecessor's Generation) and no two deltas share a base.
// But the controller ENQUEUES deltas from concurrent goroutines (create/destroy fan
// out per pool), so under a burst a successor can reach the agent before its
// predecessor. The old handler DROPPED such a delta and waited for a full resync;
// under sustained concurrent churn that degraded the delta hot path to periodic full
// resync — the delta optimization lost exactly when load is highest. The sequencer
// instead BUFFERS an ahead-of-chain delta, keyed by the generation it chains onto,
// and drains it the instant its predecessor lands, so ordinary reordering costs
// nothing.
//
// A genuinely LOST predecessor still self-heals: the held state (missing the buffered
// delta's change) hashes differently from the controller's expected pool set, so the
// DriftSweep pushes a full DESIRED_STATE resync. That resync jumps last-applied
// forward, stranding the buffered entries, which are evicted lazily on the next
// Submit (base below the new chain point).
//
// NOT safe for concurrent use: it is driven solely from the reconcile goroutine
// (SetDeltaApplier → Submit), mutually exclusive with the full Reconcile, so it needs
// no lock — the same discipline the previous inline gap check relied on.
type DeltaSequencer struct {
	pending     map[uint64]model.EdgeDesiredDelta // BaseGeneration → delta awaiting that predecessor
	lastApplied func() uint64                     // the reconciler's current applied generation
	apply       func(model.EdgeDesiredDelta) bool // apply one delta; true iff last-applied advanced
	log         *slog.Logger
	max         int
}

// NewDeltaSequencer wires the sequencer to the reconciler's applied-generation getter
// and a single-delta apply function (which must advance last-applied on success).
func NewDeltaSequencer(lastApplied func() uint64, apply func(model.EdgeDesiredDelta) bool, log *slog.Logger) *DeltaSequencer {
	return &DeltaSequencer{
		pending:     map[uint64]model.EdgeDesiredDelta{},
		lastApplied: lastApplied,
		apply:       apply,
		log:         log,
		max:         defaultMaxPendingDeltas,
	}
}

// Submit ingests one delta: applies it (and any now-contiguous buffered successors)
// if it chains onto the current last-applied generation, buffers it if it is ahead of
// the chain, or ignores it if the chain has already passed its base.
func (s *DeltaSequencer) Submit(delta model.EdgeDesiredDelta) {
	base := s.lastApplied()
	// Evict entries the chain has already passed — e.g. a full resync jumped
	// last-applied forward, so their predecessor can never arrive.
	for k := range s.pending {
		if k < base {
			delete(s.pending, k)
		}
	}
	switch {
	case delta.BaseGeneration == base:
		if !s.apply(delta) {
			return // cold start / apply error — leave the chain where it is
		}
		s.drain()
	case delta.BaseGeneration > base:
		if len(s.pending) >= s.max {
			s.log.Warn("delta reorder buffer full; clearing and awaiting full resync",
				"buffered", len(s.pending), "last_applied", base)
			s.pending = map[uint64]model.EdgeDesiredDelta{}
			return
		}
		s.pending[delta.BaseGeneration] = delta
		s.log.Info("delta ahead of chain; buffering until predecessor arrives",
			"base_generation", delta.BaseGeneration, "last_applied", base,
			"delta_generation", delta.Generation, "buffered", len(s.pending))
	default: // delta.BaseGeneration < base
		s.log.Info("delta below chain; ignoring (already applied or superseded)",
			"base_generation", delta.BaseGeneration, "last_applied", base,
			"delta_generation", delta.Generation)
	}
}

// drain applies buffered deltas as the advancing chain makes them contiguous.
func (s *DeltaSequencer) drain() {
	for {
		next, ok := s.pending[s.lastApplied()]
		if !ok {
			return
		}
		delete(s.pending, next.BaseGeneration)
		if !s.apply(next) {
			return
		}
	}
}

// Buffered reports how many ahead-of-chain deltas are held (tests / metrics).
func (s *DeltaSequencer) Buffered() int { return len(s.pending) }
