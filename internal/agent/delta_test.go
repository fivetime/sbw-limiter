package agent

import (
	"net/netip"
	"testing"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/vpp"
)

// dumpGuard wraps fakePolicers but FAILS the test if Dump is called — the delta
// hot path must touch ONLY the delta's pools (scoped add/update/delete by name via
// polIdx), never enumerate the whole edge. It proves the apply is O(delta), not O(N).
type dumpGuard struct {
	*fakePolicers
	t *testing.T
}

func (g *dumpGuard) Dump() ([]vpp.PolicerInfo, error) {
	g.t.Fatal("delta hot path must not Dump policers (full reconcile only)")
	return nil, nil
}

func guard(t *testing.T, fp *fakePolicers) policerReconciler { return &dumpGuard{fp, t} }

func egressSpec(pool model.PoolID, cir uint64) model.PolicerSpec {
	s := ingressSpec(pool, cir)
	s.Name = model.PolicerName(pool, model.DirectionEgress)
	s.Direction = model.DirectionEgress
	return s
}

// TestApplyDeltaAddsAndRemovesPoolsScoped applies a delta that ADDS pool 300 and
// REMOVES pool 200 (over a baseline of pools 200+201), asserting: only those pools'
// resources are touched; an untouched pool (201) keeps its policer index and
// session; the installed pool hash reflects the new {201,300} set; and Dump is
// NEVER called (the hot path is O(delta), not a full edge scan).
func TestApplyDeltaAddsAndRemovesPoolsScoped(t *testing.T) {
	r := newReconciler()

	// Baseline: a full reconcile installed pools 200 and 201.
	fp := newFakePolicers()
	fc := newFakeClassify()
	if _, err := r.reconcilePolicers(fp, []model.PolicerSpec{
		ingressSpec(200, 1_000_000), ingressSpec(201, 2_000_000),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.reconcileClassify(fc, []model.ClassifySession{
		member(200, "203.0.113.10/32"),
		member(201, "203.0.113.20/32"),
	}); err != nil {
		t.Fatal(err)
	}
	r.lastGen = 5
	r.recomputePoolHash()
	idx201 := r.polIdx["pool201_in"]

	// --- REMOVE pool 200 (sessions then policer), via the same scoped helpers
	//     ApplyDelta drives — but through the Dump-guarded policer fake. ---
	d, err := r.deletePoolSessions(fc, []model.ClassifySession{member(200, "203.0.113.10/32")})
	if err != nil || d != 1 {
		t.Fatalf("delete pool200 sessions: d=%d err=%v", d, err)
	}
	pd, err := r.deletePoolPolicers(guard(t, fp), 200)
	if err != nil || pd != 1 {
		t.Fatalf("delete pool200 policer: pd=%d err=%v", pd, err)
	}

	// --- UPSERT pool 300 (policer then session). ---
	up := model.PoolDelta{
		PoolID:           300,
		Policers:         []model.PolicerSpec{ingressSpec(300, 3_000_000)},
		ClassifySessions: []model.ClassifySession{member(300, "203.0.113.30/32")},
	}
	pa, pu, err := r.upsertPoolPolicers(guard(t, fp), up.Policers)
	if err != nil || pa != 1 || pu != 0 {
		t.Fatalf("upsert pool300 policer: pa=%d pu=%d err=%v", pa, pu, err)
	}
	a, dd, mv, err := r.upsertPoolSessions(fc, 300, nil, up.ClassifySessions)
	if err != nil || a != 1 || dd != 0 || mv != 0 {
		t.Fatalf("upsert pool300 sessions: a=%d dd=%d mv=%d err=%v", a, dd, mv, err)
	}

	// Pool 201 untouched: same index, session still present in VPP.
	if r.polIdx["pool201_in"] != idx201 {
		t.Errorf("untouched pool 201 policer index changed %d→%d", idx201, r.polIdx["pool201_in"])
	}
	if _, ok := r.polIdx["pool200_in"]; ok {
		t.Error("removed pool 200 still in polIdx")
	}
	if _, ok := r.polIdx["pool300_in"]; !ok {
		t.Error("added pool 300 missing from polIdx")
	}
	if _, gone := fp.live["pool200_in"]; gone {
		t.Error("pool 200 policer not deleted from VPP")
	}
	if _, ok := fp.live["pool201_in"]; !ok {
		t.Error("untouched pool 201 policer was deleted")
	}

	// Installed-pool hash now reflects {201, 300}.
	r.recomputePoolHash()
	if got, want := r.InstalledPoolHash(), model.PoolSetHash([]model.PoolID{201, 300}); got != want {
		t.Errorf("InstalledPoolHash = %d, want %d (set {201,300})", got, want)
	}
}

// TestApplyDeltaV6IngressEgressNoCollision locks the fix for the ip6-dst-128 vs
// ip6-src-128 map-key collision (now enforced by the SHARED buildSessionWants/
// sessionMapKey in classifydiff.go): one member's ingress (dst) and egress (src)
// v6 sessions share a BYTE-IDENTICAL VPP match key (vpp.SessionKey encodes only the
// masked address, not the mask), so an un-namespaced desired map dropped one. Both
// must materialize, in two SEPARATE mask tables.
func TestApplyDeltaV6IngressEgressNoCollision(t *testing.T) {
	r := newReconciler()
	fc := newFakeClassify()
	r.polIdx["pool500_in"] = 11
	r.polIdx["pool500_out"] = 12

	mbr := netip.MustParsePrefix("2001:db8::5/128")
	next := []model.ClassifySession{
		{PoolID: 500, Prefix: mbr, Direction: model.DirectionIngress, Mask: model.MaskIP6Dst128, PolicerName: model.PolicerName(500, model.DirectionIngress)},
		{PoolID: 500, Prefix: mbr, Direction: model.DirectionEgress, Mask: model.MaskIP6Src128, PolicerName: model.PolicerName(500, model.DirectionEgress)},
	}
	a, dd, mv, err := r.upsertPoolSessions(fc, 500, nil, next)
	if err != nil || a != 2 || dd != 0 || mv != 0 {
		t.Fatalf("v6 ingress+egress upsert: a=%d dd=%d mv=%d err=%v (both dst-128 and src-128 must be added)", a, dd, mv, err)
	}
	tables, _ := fc.FindTablesByMask()
	td, okd := tables[model.MaskIP6Dst128]
	ts, oks := tables[model.MaskIP6Src128]
	if !okd || !oks || td == ts {
		t.Fatalf("want two distinct v6 tables, got dst=%v(%d) src=%v(%d)", okd, td, oks, ts)
	}
	if n := len(fc.sessions[td]); n != 1 {
		t.Errorf("dst-128 table sessions = %d, want 1", n)
	}
	if n := len(fc.sessions[ts]); n != 1 {
		t.Errorf("src-128 table sessions = %d, want 1", n)
	}
}

// TestApplyDeltaMovesMember: re-upserting a pool whose member moved to a different
// policer index re-points (moves) the session — a single AddSession overwrite, no
// full table scan.
func TestApplyDeltaMovesMember(t *testing.T) {
	r := newReconciler()
	fc := newFakeClassify()
	r.polIdx["pool200_in"] = 7
	prev := []model.ClassifySession{member(200, "203.0.113.10/32")}
	if a, _, _, err := r.upsertPoolSessions(fc, 200, nil, prev); err != nil || a != 1 {
		t.Fatalf("seed: a=%d err=%v", a, err)
	}
	// Pool's policer index changed (e.g. re-created): same member, new hit target.
	r.polIdx["pool200_in"] = 9
	a, dd, mv, err := r.upsertPoolSessions(fc, 200, prev, []model.ClassifySession{member(200, "203.0.113.10/32")})
	if err != nil || a != 0 || dd != 0 || mv != 1 {
		t.Fatalf("move: a=%d dd=%d mv=%d err=%v", a, dd, mv, err)
	}
}

// TestInstalledPoolHashMatchesPoolSetHash: the reconciler's cached hash equals
// model.PoolSetHash over the DISTINCT installed pool ids (the SAME function the
// controller uses), de-duping by pool even when a pool has both directions.
func TestInstalledPoolHashMatchesPoolSetHash(t *testing.T) {
	r := newReconciler()
	fp := newFakePolicers()
	specs := []model.PolicerSpec{
		ingressSpec(200, 1_000_000),
		ingressSpec(201, 2_000_000),
		egressSpec(201, 2_000_000), // 3 policers, 2 distinct pools
	}
	if _, err := r.reconcilePolicers(fp, specs); err != nil {
		t.Fatal(err)
	}
	r.recomputePoolHash()
	if got, want := r.InstalledPoolHash(), model.PoolSetHash([]model.PoolID{200, 201}); got != want {
		t.Errorf("InstalledPoolHash = %d, want %d (distinct pools {200,201})", got, want)
	}
}

// TestActualCountsTrackDeltas pins the §6.52 #5 sequel fix: the incrementally
// maintained ACTUAL counters must follow the DELTA-path mutations (policer
// add/delete, session upsert/delete) so the reported counts stay fresh between
// full reconciles — the stale actuals made the B-02 audit see phantom
// "program-drift" on routine churn once the desired side was freshened.
func TestActualCountsTrackDeltas(t *testing.T) {
	r := newReconciler()
	fp := newFakePolicers()
	fc := newFakeClassify()

	// Before the first full-reconcile anchor: not ok (reporter leaves counts alone).
	if _, _, ok := r.ActualCounts(); ok {
		t.Fatal("ActualCounts must not be ok before the first anchor")
	}
	// Simulate the anchor a full reconcile performs after countProgrammed.
	r.actPol.Store(1)
	r.actSess.Store(1)
	r.actAnchored.Store(true)

	// Delta: add pool 300's policer + session.
	if _, _, err := r.upsertPoolPolicers(guard(t, fp), []model.PolicerSpec{ingressSpec(300, 3_000_000)}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := r.upsertPoolSessions(fc, 300, nil, []model.ClassifySession{member(300, "203.0.113.30/32")}); err != nil {
		t.Fatal(err)
	}
	pol, sess, ok := r.ActualCounts()
	if !ok || pol != 2 || sess != 2 {
		t.Fatalf("after delta add: pol=%d sess=%d ok=%v, want 2/2/true", pol, sess, ok)
	}

	// Delta: remove pool 300 again (sessions then policer).
	if _, err := r.deletePoolSessions(fc, []model.ClassifySession{member(300, "203.0.113.30/32")}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.deletePoolPolicers(guard(t, fp), 300); err != nil {
		t.Fatal(err)
	}
	pol, sess, _ = r.ActualCounts()
	if pol != 1 || sess != 1 {
		t.Fatalf("after delta remove: pol=%d sess=%d, want 1/1", pol, sess)
	}

	// Re-anchor overrides any drift (full reconcile wins).
	r.actPol.Store(7)
	r.actSess.Store(9)
	if pol, sess, _ := r.ActualCounts(); pol != 7 || sess != 9 {
		t.Fatalf("anchor must override: %d/%d", pol, sess)
	}
}
