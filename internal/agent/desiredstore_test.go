package agent

import (
	"testing"
	"time"

	"github.com/fivetime/sbw-contract/model"
)

func stateGen(gen uint64, pools ...model.PolicerSpec) model.EdgeDesiredState {
	return model.EdgeDesiredState{
		SchemaVersion: model.SchemaVersion, EdgeID: "test",
		Generation: gen, Policers: pools,
	}
}

func TestDesiredStoreColdStartSkips(t *testing.T) {
	s := NewDesiredStore()
	// Before any controller update, the reconcile loop must SKIP, not prune.
	if _, ok := s.Desired(); ok {
		t.Fatal("cold start must report ok=false so the loop skips")
	}
	st := s.Status()
	if st.HaveState || st.Frozen {
		t.Errorf("cold start status = %+v", st)
	}
}

func TestDesiredStoreColdStartFreezesEvenWhenControllerDown(t *testing.T) {
	s := NewDesiredStore()
	s.ControllerDown() // agent booted while controller unreachable
	if _, ok := s.Desired(); ok {
		t.Fatal("no state + controller down must still skip (freeze existing data plane)")
	}
}

func TestDesiredStoreServesLastStateWhileControllerDown(t *testing.T) {
	s := NewDesiredStore()
	want := stateGen(5, ingressSpec(200, 1_000_000))
	if !s.Accept(want) {
		t.Fatal("Accept should take the first state")
	}

	// Controller drops — the held state must still be served (the freeze).
	s.ControllerDown()
	got, ok := s.Desired()
	if !ok {
		t.Fatal("must keep serving the last state while the controller is down")
	}
	if got.Generation != 5 || len(got.Policers) != 1 {
		t.Fatalf("served state = gen %d, %d policers; want gen 5, 1", got.Generation, len(got.Policers))
	}
	st := s.Status()
	if !st.Frozen || st.ControllerHealthy {
		t.Errorf("status should report Frozen while down: %+v", st)
	}
}

func TestDesiredStoreEmptyUpdateFromHealthyControllerIsApplied(t *testing.T) {
	s := NewDesiredStore()
	s.Accept(stateGen(1, ingressSpec(200, 1_000_000)))
	// A reachable controller deliberately removing all pools is a real change,
	// distinct from a loss of contact: it IS applied (ok=true, empty policers).
	if !s.Accept(stateGen(2)) {
		t.Fatal("empty update from healthy controller should be accepted")
	}
	got, ok := s.Desired()
	if !ok || len(got.Policers) != 0 || got.Generation != 2 {
		t.Fatalf("empty update not applied: ok=%v gen=%d pools=%d", ok, got.Generation, len(got.Policers))
	}
}

func TestDesiredStoreRejectsStaleGeneration(t *testing.T) {
	s := NewDesiredStore()
	s.Accept(stateGen(10, ingressSpec(200, 1_000_000)))
	// An out-of-order older revision must not overwrite the newer state.
	if s.Accept(stateGen(9, ingressSpec(201, 2_000_000))) {
		t.Fatal("stale generation must be rejected")
	}
	got, _ := s.Desired()
	if got.Generation != 10 {
		t.Fatalf("held generation = %d, want 10 (stale ignored)", got.Generation)
	}
	// Same generation re-broadcast is idempotent-accepted (>=).
	if !s.Accept(stateGen(10, ingressSpec(200, 1_000_000))) {
		t.Error("same generation re-broadcast should be accepted")
	}
}

func TestDesiredStoreControllerUpClearsFrozen(t *testing.T) {
	s := NewDesiredStore()
	s.Accept(stateGen(1))
	s.ControllerDown()
	if !s.Status().Frozen {
		t.Fatal("should be frozen after down")
	}
	s.ControllerUp()
	if s.Status().Frozen || !s.Status().ControllerHealthy {
		t.Errorf("ControllerUp should clear frozen: %+v", s.Status())
	}
}

func TestDesiredStoreStaleForGrows(t *testing.T) {
	s := NewDesiredStore()
	clock := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return clock }
	s.Accept(stateGen(1))
	s.ControllerDown()
	clock = clock.Add(90 * time.Second)
	if d := s.Status().StaleFor; d != 90*time.Second {
		t.Fatalf("StaleFor = %s, want 90s", d)
	}
}

// The stale-render guard (content watermark): the controller's full renders read
// the pool store through follower reads pinned up to ~10s in the past, so a full
// snapshot can carry a NEWER generation than a per-pool delta while its CONTENT
// predates the delta's pool. Ordering by generation alone let such a snapshot
// clobber the delta's merge — the next reconcile then orphan-deleted the fresh
// pool's VPP policers for ~60s (TEST-SCENARIOS §6.26). Accept must reject a full
// state whose content watermark is strictly older than what was applied.
func TestDesiredStoreRejectsContentStaleSnapshot(t *testing.T) {
	s := NewDesiredStore()

	// Baseline full state at watermark T-10s (a normal follower-read render).
	base := stateGen(10, ingressSpec(200, 1_000_000))
	base.GeneratedAtUnixMs = 100_000
	if !s.Accept(base) {
		t.Fatal("baseline accept failed")
	}

	// A delta merges pool 964 with an EXACT content watermark (post-commit stamp).
	if _, ok := s.Merge(model.EdgeDesiredDelta{
		SchemaVersion: model.SchemaVersion, EdgeID: "test",
		Generation: 11, GeneratedAtUnixMs: 111_000,
		Upserts: []model.PoolDelta{{PoolID: 964, Policers: []model.PolicerSpec{ingressSpec(964, 500_000)}}},
	}); !ok {
		t.Fatal("delta merge failed")
	}

	// The racing stale full render: generation NEWER than the delta (minted after)
	// but content watermark OLDER (follower-read snapshot predates the commit) and
	// pool 964 missing. Must be rejected — accepting it would tear 964 down.
	stale := stateGen(12, ingressSpec(200, 1_000_000))
	stale.GeneratedAtUnixMs = 105_000 // < the delta's 111_000
	if s.Accept(stale) {
		t.Fatal("content-stale snapshot (newer generation, older watermark) must be rejected")
	}
	got, _ := s.Desired()
	if got.Generation != 11 || len(got.Policers) != 2 {
		t.Fatalf("held state clobbered: gen=%d policers=%d (want 11/2)", got.Generation, len(got.Policers))
	}

	// A later render past the staleness bound (watermark >= the delta's) with the
	// full converged content is accepted — the level-triggered heal.
	fresh := stateGen(13, ingressSpec(200, 1_000_000), ingressSpec(964, 500_000))
	fresh.GeneratedAtUnixMs = 112_000
	if !s.Accept(fresh) {
		t.Fatal("fresh snapshot must be accepted")
	}

	// Legacy producer (no watermark, 0): generation ordering alone, as before.
	legacy := stateGen(14, ingressSpec(200, 1_000_000))
	legacy.GeneratedAtUnixMs = 0
	if !s.Accept(legacy) {
		t.Fatal("watermark-less (legacy) state must fall back to generation ordering")
	}
}

// Equal watermarks must NOT be rejected: a commit at time T is visible to a
// snapshot pinned at T, so an equal-watermark snapshot already contains it.
func TestDesiredStoreAcceptsEqualWatermark(t *testing.T) {
	s := NewDesiredStore()
	a := stateGen(1, ingressSpec(200, 1_000_000))
	a.GeneratedAtUnixMs = 50_000
	if !s.Accept(a) {
		t.Fatal("accept a")
	}
	b := stateGen(2, ingressSpec(200, 1_000_000))
	b.GeneratedAtUnixMs = 50_000
	if !s.Accept(b) {
		t.Fatal("equal-watermark snapshot must be accepted")
	}
}
