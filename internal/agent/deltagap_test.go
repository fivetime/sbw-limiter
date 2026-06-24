package agent

import (
	"net/netip"
	"testing"

	"github.com/fivetime/sbw-contract/model"
)

// deltaHandler mirrors the edge-agent's main.go delta closure (the documented
// gap-detection seam) WITHOUT the VPP ApplyDelta call, so the decision can be
// unit-tested: gap-detect against the reconciler's last-applied generation, and on
// a clean base merge into the held desired state and signal "would apply". On a gap
// it drops the delta (relying on the controller's full DESIRED_STATE resync) and
// signals applied=false.
func deltaHandler(r *Reconciler, store *DesiredStore, delta model.EdgeDesiredDelta) (applied bool, prev []model.ClassifySession) {
	if delta.BaseGeneration != r.LastAppliedGeneration() {
		return false, nil // GAP → drop, await resync
	}
	p, ok := store.Merge(delta)
	if !ok {
		return false, nil // no base state yet
	}
	// (ApplyDelta(delta, p) would run here on the reconcile goroutine.)
	return true, p
}

func clsSession(pool model.PoolID, prefix string) model.ClassifySession {
	return model.ClassifySession{
		PoolID: pool, Prefix: netip.MustParsePrefix(prefix),
		Direction: model.DirectionIngress, Mask: model.MaskIP4Dst32,
		PolicerName: model.PolicerName(pool, model.DirectionIngress),
	}
}

// TestDeltaGapDroppedAwaitsResync: a delta whose BaseGeneration ≠ the agent's
// last-applied generation is DROPPED (not applied, held state untouched), so the
// agent never folds a delta onto a divergent base — the controller's full resync
// heals it instead.
func TestDeltaGapDroppedAwaitsResync(t *testing.T) {
	r := newReconciler()
	r.lastGen = 5 // agent last applied generation 5

	store := NewDesiredStore()
	store.Accept(model.EdgeDesiredState{
		SchemaVersion: model.SchemaVersion, EdgeID: "e", Generation: 5,
		Policers:         []model.PolicerSpec{ingressSpec(200, 1_000_000)},
		ClassifySessions: []model.ClassifySession{clsSession(200, "203.0.113.10/32")},
	})

	// Delta claims to build on generation 4 — a GAP (agent is at 5).
	gapped := model.EdgeDesiredDelta{
		SchemaVersion: model.SchemaVersion, EdgeID: "e",
		Generation: 6, BaseGeneration: 4,
		Removed: []model.PoolID{200},
	}
	applied, _ := deltaHandler(r, store, gapped)
	if applied {
		t.Fatal("gapped delta must NOT be applied")
	}
	// Held state untouched (still generation 5 with pool 200).
	st, _ := store.Desired()
	if st.Generation != 5 || len(st.Policers) != 1 {
		t.Errorf("held state mutated by a dropped delta: gen=%d policers=%d", st.Generation, len(st.Policers))
	}
}

// TestDeltaCleanBaseMergesAndApplies: a delta on the agent's current generation is
// accepted — merged into the held state (touched pools replaced/removed, generation
// bumped) and the pre-merge sessions returned for the scoped VPP teardown.
func TestDeltaCleanBaseMergesAndApplies(t *testing.T) {
	r := newReconciler()
	r.lastGen = 5

	store := NewDesiredStore()
	store.Accept(model.EdgeDesiredState{
		SchemaVersion: model.SchemaVersion, EdgeID: "e", Generation: 5,
		Policers: []model.PolicerSpec{ingressSpec(200, 1_000_000), ingressSpec(201, 2_000_000)},
		ClassifySessions: []model.ClassifySession{
			clsSession(200, "203.0.113.10/32"),
			clsSession(201, "203.0.113.20/32"),
		},
	})

	// Clean delta on base 5: remove pool 200, add pool 300.
	delta := model.EdgeDesiredDelta{
		SchemaVersion: model.SchemaVersion, EdgeID: "e",
		Generation: 6, BaseGeneration: 5,
		Removed: []model.PoolID{200},
		Upserts: []model.PoolDelta{{
			PoolID:           300,
			Policers:         []model.PolicerSpec{ingressSpec(300, 3_000_000)},
			ClassifySessions: []model.ClassifySession{clsSession(300, "203.0.113.30/32")},
		}},
	}
	applied, prev := deltaHandler(r, store, delta)
	if !applied {
		t.Fatal("clean-base delta must be applied")
	}
	// prev (pre-merge) must contain pool 200's + 201's sessions (the teardown record).
	if len(prev) != 2 {
		t.Errorf("prev sessions = %d, want 2 (pre-merge held set)", len(prev))
	}

	// Held state now reflects the merge: generation 6; pool 200 gone; 201 kept; 300 added.
	st, _ := store.Desired()
	if st.Generation != 6 {
		t.Errorf("merged generation = %d, want 6", st.Generation)
	}
	have := map[model.PoolID]bool{}
	for _, p := range st.Policers {
		have[p.PoolID] = true
	}
	if have[200] {
		t.Error("removed pool 200 still in merged held state")
	}
	if !have[201] || !have[300] {
		t.Errorf("merged held pools = %v, want {201,300}", have)
	}
	sessPools := map[model.PoolID]bool{}
	for _, s := range st.ClassifySessions {
		sessPools[s.PoolID] = true
	}
	if sessPools[200] || !sessPools[201] || !sessPools[300] {
		t.Errorf("merged held sessions pools = %v, want {201,300}", sessPools)
	}
}

// TestDeltaMergeReplacesPoolContribution: re-upserting an EXISTING pool replaces its
// contribution wholesale (old members dropped from the held set, new ones in), and
// returns the pool's pre-merge sessions so the apply path can delete the dropped ones.
func TestDeltaMergeReplacesPoolContribution(t *testing.T) {
	store := NewDesiredStore()
	store.Accept(model.EdgeDesiredState{
		SchemaVersion: model.SchemaVersion, EdgeID: "e", Generation: 5,
		Policers: []model.PolicerSpec{ingressSpec(200, 1_000_000)},
		ClassifySessions: []model.ClassifySession{
			clsSession(200, "203.0.113.10/32"),
			clsSession(200, "203.0.113.11/32"),
		},
	})
	delta := model.EdgeDesiredDelta{
		SchemaVersion: model.SchemaVersion, EdgeID: "e",
		Generation: 6, BaseGeneration: 5,
		Upserts: []model.PoolDelta{{
			PoolID:   200,
			Policers: []model.PolicerSpec{ingressSpec(200, 1_000_000)},
			// Member .11 dropped; only .10 remains.
			ClassifySessions: []model.ClassifySession{clsSession(200, "203.0.113.10/32")},
		}},
	}
	prev, ok := store.Merge(delta)
	if !ok {
		t.Fatal("merge onto held state must succeed")
	}
	if len(prev) != 2 {
		t.Errorf("prev sessions = %d, want 2", len(prev))
	}
	st, _ := store.Desired()
	if len(st.ClassifySessions) != 1 || st.ClassifySessions[0].Prefix.String() != "203.0.113.10/32" {
		t.Errorf("replaced pool 200 sessions = %+v, want only .10", st.ClassifySessions)
	}
}

// TestDeltaMergeColdStartRejected: a delta with no base held state is rejected
// (ok=false) — the agent must wait for a full DESIRED_STATE first (cold start).
func TestDeltaMergeColdStartRejected(t *testing.T) {
	store := NewDesiredStore()
	if _, ok := store.Merge(model.EdgeDesiredDelta{Generation: 1}); ok {
		t.Error("merge onto a cold-start store (no base) must report ok=false")
	}
}
