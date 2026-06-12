package agent

import (
	"sync"
	"time"

	"github.com/fivetime/sbw-contract/model"
)

// DesiredStore holds the last desired state the controller delivered and
// enforces fail-static discipline (DESIGN.md §6.4): when the controller is
// unreachable the agent FREEZES the last good state — it never withdraws
// announcements, deletes policers, or loosens rules. The blast radius of a
// controller outage is "changes don't take effect", never "rate-limiting opens
// up".
//
// The load-bearing rule: the agent must never reconcile to a state the
// controller did not send. "Controller down" is NOT "desired state is empty".
// An empty state is applied only when a HEALTHY controller actually sends one
// (all pools removed — a real change). So the store distinguishes:
//
//   - have a state  → serve it, regardless of controller health (the steady-
//     state freeze: keep converging to last-good while the controller is away).
//   - never had one → Desired() reports ok=false, and the reconcile loop SKIPS
//     the pass rather than pruning (the cold-start freeze: an agent that boots
//     while the controller is down must not wipe a data plane that survived).
//
// Safe for concurrent use: the controller-subscription goroutine writes via
// Accept/ControllerUp/ControllerDown while the reconcile loop reads via Desired.
type DesiredStore struct {
	mu        sync.RWMutex
	state     model.EdgeDesiredState
	haveState bool
	healthy   bool      // controller currently reachable
	lastTouch time.Time // last accepted update

	now func() time.Time
}

// NewDesiredStore returns an empty store. Until the first Accept, Desired
// reports ok=false (cold-start freeze).
func NewDesiredStore() *DesiredStore {
	return &DesiredStore{now: time.Now}
}

// Accept records a fresh desired state from the controller and marks the
// controller healthy (a delivered update is proof of contact). A stale or
// out-of-order generation is ignored. Returns whether the state was taken.
//
// An empty state IS accepted — from a reachable controller that is a deliberate
// "remove everything", not a loss of contact. Only the absence of contact
// (never any Accept) freezes via the cold-start path.
func (s *DesiredStore) Accept(state model.EdgeDesiredState) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.haveState && state.Generation < s.state.Generation {
		return false // older revision arrived late; keep the newer one
	}
	s.state = state
	s.haveState = true
	s.healthy = true
	s.lastTouch = s.now()
	return true
}

// ControllerDown records that the controller became unreachable. The held state
// is untouched — that is the whole point: the next reconcile still converges to
// it.
func (s *DesiredStore) ControllerDown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.healthy = false
}

// ControllerUp records that the controller is reachable again (e.g. the
// subscription re-established). The held state is unchanged until the next
// Accept, which the controller pushes as part of its post-reconnect full replay.
func (s *DesiredStore) ControllerUp() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.healthy = true
}

// Desired returns the state to reconcile to. ok=false means no state has ever
// been received (cold start) — the caller MUST NOT reconcile, so a data plane
// that outlived the agent is left frozen rather than pruned. When ok=true the
// state is returned regardless of controller health.
func (s *DesiredStore) Desired() (model.EdgeDesiredState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.haveState {
		return model.EdgeDesiredState{}, false
	}
	return s.state, true
}

// DesiredStatus is a snapshot of fail-static state for health export
// (DESIGN.md §6.5: the agent exposes its own local facts, not a verdict).
type DesiredStatus struct {
	HaveState         bool
	ControllerHealthy bool
	// Frozen is true when the controller is unreachable but a state is held —
	// the agent is serving stale-but-safe desired state.
	Frozen     bool
	Generation uint64
	// StaleFor is how long since the last accepted update; meaningful when Frozen.
	StaleFor time.Duration
}

// Status returns the current fail-static snapshot.
func (s *DesiredStore) Status() DesiredStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := DesiredStatus{
		HaveState:         s.haveState,
		ControllerHealthy: s.healthy,
		Frozen:            s.haveState && !s.healthy,
	}
	if s.haveState {
		st.Generation = s.state.Generation
		st.StaleFor = s.now().Sub(s.lastTouch)
	}
	return st
}
