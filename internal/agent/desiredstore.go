package agent

import (
	"net/netip"
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

	// contentAsOf is the CONTENT watermark (server clock, unix ms) of the held
	// state: the max GeneratedAtUnixMs across every Accept and Merge applied. The
	// controller's full renders read the pool store through FOLLOWER READS pinned
	// up to ~10s in the past, so a full snapshot can carry a NEWER Generation than
	// a per-pool delta while its content PREDATES that delta — ordering by
	// generation alone let such a snapshot clobber the delta's merge and the next
	// reconcile tore the fresh pool down as a VPP orphan (~60s rate-limit hole on
	// its home edge; TEST-SCENARIOS §6.26). Accept therefore also rejects a full
	// state whose watermark is strictly OLDER than this. 0 = producer sent no
	// watermark (legacy): generation ordering alone, as before.
	contentAsOf int64

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
	if s.haveState && state.GeneratedAtUnixMs > 0 && state.GeneratedAtUnixMs < s.contentAsOf {
		// Content-stale snapshot: rendered from a follower-read DB snapshot that
		// predates content we already applied (typically a delta's pool create),
		// even though its Generation is newer. Taking it would remove that content
		// and the next reconcile would orphan-delete its VPP programming. Reject;
		// the controller's level-triggered resync re-renders past the staleness
		// bound within seconds and THAT one is accepted.
		return false
	}
	s.state = state
	s.haveState = true
	s.healthy = true
	s.lastTouch = s.now()
	if state.GeneratedAtUnixMs > s.contentAsOf {
		s.contentAsOf = state.GeneratedAtUnixMs
	}
	return true
}

// Merge folds an incremental EdgeDesiredDelta into the held desired state so the
// full-reconcile backstop and the bird/flowspec appliers keep seeing a complete,
// current EdgeDesiredState (the delta hot path mutates VPP directly; this keeps the
// in-memory desired view in lockstep). For each pool it REPLACES that pool's
// contribution — its Policers, ClassifySessions, Anchors and FlowRedirects — then
// applies the delta's redirect next-hops, removes the Removed pools' contributions,
// and bumps Generation/DesiredVersion to the delta's. It returns the held state's
// ClassifySessions AS THEY WERE BEFORE the merge (the apply path needs them to know
// which members a replaced/removed pool must have torn down) and ok=false if there
// is no held state yet (a delta with no base is a gap — the caller resyncs).
//
// Safe for concurrent use; mutates under the write lock like Accept.
func (s *DesiredStore) Merge(delta model.EdgeDesiredDelta) (prevSessions []model.ClassifySession, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.haveState {
		return nil, false // no base to merge onto — the caller must resync
	}
	prev := append([]model.ClassifySession(nil), s.state.ClassifySessions...)

	// Pools touched by this delta (upserted or removed); their old contribution is
	// dropped wholesale, then upserts re-add theirs. A pool is identified in each
	// resource by its pool id (policer/session PoolID; anchors/flowredirects are
	// per-pool only on the home edge but carry no pool id — they are replaced as the
	// union of the touched pools' fragments, matching how the controller renders).
	touched := map[model.PoolID]struct{}{}
	for _, up := range delta.Upserts {
		touched[up.PoolID] = struct{}{}
	}
	for _, id := range delta.Removed {
		touched[id] = struct{}{}
	}

	// Member prefixes of the touched pools, identifying their Anchors/FlowRedirects
	// (which carry no pool id) so we REPLACE rather than accumulate duplicate /32-/128
	// advertisements (the bug: BIRD/FlowSpec duplicate steering). Two sources, UNIONED,
	// because either alone has a hole:
	//   (1) the CURRENT classify sessions of the touched pools — covers a member being
	//       REMOVED, whose old anchor must drop even though the upsert no longer lists it;
	//   (2) the upserts' OWN anchors/flow-redirects — covers the case where a touched
	//       pool's classify session is ABSENT from the held state at merge time (a
	//       full-state-resync vs in-flight-delta dual-path race), where (1) alone misses
	//       the prefix and the re-added anchor DUPLICATES the held one ("anchors:
	//       duplicate anchor prefix ..." — fails the whole BIRD configure).
	touchedPrefixes := map[netip.Prefix]struct{}{}
	for _, c := range s.state.ClassifySessions {
		if _, ok := touched[c.PoolID]; ok {
			touchedPrefixes[c.Prefix] = struct{}{}
		}
	}
	for _, up := range delta.Upserts {
		for _, a := range up.Anchors {
			touchedPrefixes[a.Prefix] = struct{}{}
		}
		for _, f := range up.FlowRedirects {
			touchedPrefixes[f.SrcPrefix] = struct{}{}
		}
	}

	// Drop touched pools' policers and sessions from the held state.
	s.state.Policers = filterOutPools(s.state.Policers, touched, func(p model.PolicerSpec) model.PoolID { return p.PoolID })
	s.state.ClassifySessions = filterOutPools(s.state.ClassifySessions, touched, func(c model.ClassifySession) model.PoolID { return c.PoolID })
	// Drop touched pools' anchors + flow-redirects (matched by member prefix) so the upserts
	// below REPLACE them rather than accumulate.
	s.state.Anchors = filterOutPrefixes(s.state.Anchors, touchedPrefixes, func(a model.Anchor) netip.Prefix { return a.Prefix })
	s.state.FlowRedirects = filterOutPrefixes(s.state.FlowRedirects, touchedPrefixes, func(f model.FlowRedirect) netip.Prefix { return f.SrcPrefix })

	// Re-add each upserted pool's contribution.
	for _, up := range delta.Upserts {
		s.state.Policers = append(s.state.Policers, up.Policers...)
		s.state.ClassifySessions = append(s.state.ClassifySessions, up.ClassifySessions...)
		s.state.Anchors = append(s.state.Anchors, up.Anchors...)
		s.state.FlowRedirects = append(s.state.FlowRedirects, up.FlowRedirects...)
		if up.RedirectNextHop.IsValid() {
			s.state.RedirectNextHop = up.RedirectNextHop
		}
		if up.RedirectNextHopV6.IsValid() {
			s.state.RedirectNextHopV6 = up.RedirectNextHopV6
		}
	}

	s.state.Generation = delta.Generation
	if delta.DesiredVersion != 0 {
		s.state.DesiredVersion = delta.DesiredVersion
	}
	// Adopt the delta's content watermark: deltas are rendered from the committed
	// pool passed in-memory (content-exact, stamped post-commit), so this is what
	// protects the merge from a follower-read-stale full snapshot arriving later
	// with a newer Generation (see Accept + the model field's doc).
	if delta.GeneratedAtUnixMs > s.contentAsOf {
		s.contentAsOf = delta.GeneratedAtUnixMs
	}
	s.healthy = true
	s.lastTouch = s.now()
	return prev, true
}

// filterOutPools returns xs with every element whose pool id is in drop removed.
func filterOutPools[T any](xs []T, drop map[model.PoolID]struct{}, poolOf func(T) model.PoolID) []T {
	out := xs[:0:0]
	for _, x := range xs {
		if _, gone := drop[poolOf(x)]; gone {
			continue
		}
		out = append(out, x)
	}
	return out
}

// filterOutPrefixes returns xs with every element whose prefix is in drop removed —
// the Anchor/FlowRedirect analogue of filterOutPools (those carry no pool id).
func filterOutPrefixes[T any](xs []T, drop map[netip.Prefix]struct{}, prefixOf func(T) netip.Prefix) []T {
	out := xs[:0:0]
	for _, x := range xs {
		if _, gone := drop[prefixOf(x)]; gone {
			continue
		}
		out = append(out, x)
	}
	return out
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
