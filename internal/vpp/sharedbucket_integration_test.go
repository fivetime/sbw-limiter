//go:build integration

package vpp

import (
	"net/netip"
	"testing"

	"github.com/fivetime/sbw-contract/model"
)

// T-404 acceptance: the pool semantics (DESIGN.md §5.2) — multiple classify
// sessions whose hit target is the SAME policer index share that policer's one
// token bucket. This verifies the WIRING our materializers produce (the runtime
// token-bucket sharing is VPP's own behavior; behavioral rate verification with
// real traffic is part of the §9 perf harness, T-1101).
//
// Wires a real pool: one ingress policer (T-402) + two member sessions on an
// ip4-dst-32 table (T-403) both pointing at that policer, and confirms via
// classify_session_dump that both sessions report the same hit_next = policer
// index.
func TestRealSharedBucketWiring(t *testing.T) {
	c := realConn(t)
	ch, err := c.Channel()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ch.Close)

	pol := NewPolicers(ch)
	cl := NewClassify(ch)

	// Pool 4244 ingress policer.
	spec := model.PolicerSpec{
		Name: model.PolicerName(4244, model.DirectionIngress), PoolID: 4244,
		Direction: model.DirectionIngress, Type: model.Policer1R2C, RateType: model.RateKbps,
		CIR: 1_000_000, CommittedBurstBytes: 12_500_000,
		ConformAction: model.PolicerTransmit, ExceedAction: model.PolicerDrop,
	}
	pi, err := pol.Add(spec)
	if err != nil {
		t.Fatalf("policer Add: %v", err)
	}
	t.Cleanup(func() { _ = pol.Delete(pi) })

	ti, err := cl.AddTable(TableSpec{Mask: model.MaskIP4Dst32})
	if err != nil {
		t.Fatalf("AddTable: %v", err)
	}
	t.Cleanup(func() { _ = cl.DeleteTable(ti) })

	members := []netip.Prefix{
		netip.MustParsePrefix("203.0.113.10/32"),
		netip.MustParsePrefix("203.0.113.11/32"),
	}
	for _, m := range members {
		if err := cl.AddSession(ti, model.MaskIP4Dst32, m, pi); err != nil {
			t.Fatalf("AddSession %s: %v", m, err)
		}
	}

	sessions, err := cl.DumpSessions(ti)
	if err != nil {
		t.Fatalf("DumpSessions: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("got %d sessions, want 2", len(sessions))
	}
	// The crux: BOTH members' sessions hit the SAME policer index = one bucket.
	for i, s := range sessions {
		if s.HitNextIndex != pi {
			t.Errorf("session[%d] hit_next = %d, want policer index %d (shared bucket broken)", i, s.HitNextIndex, pi)
		}
	}

	// Removing one member must not affect the other's wiring.
	if err := cl.DelSession(ti, model.MaskIP4Dst32, members[0]); err != nil {
		t.Fatalf("DelSession: %v", err)
	}
	sessions, err = cl.DumpSessions(ti)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].HitNextIndex != pi {
		t.Errorf("after del: sessions=%d, remaining hit_next=%v, want 1 session at policer %d", len(sessions), sessions, pi)
	}
}

// Re-pointing a member to a different pool policer (member migration, §5.3) is
// an atomic overwrite of the same key — no del+add window.
func TestRealMemberRepointIsAtomic(t *testing.T) {
	c := realConn(t)
	ch, err := c.Channel()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ch.Close)

	pol := NewPolicers(ch)
	cl := NewClassify(ch)

	mk := func(id model.PoolID) uint32 {
		s := model.PolicerSpec{
			Name: model.PolicerName(id, model.DirectionIngress), PoolID: id,
			Direction: model.DirectionIngress, Type: model.Policer1R2C, RateType: model.RateKbps,
			CIR: 500_000, CommittedBurstBytes: 6_250_000,
			ConformAction: model.PolicerTransmit, ExceedAction: model.PolicerDrop,
		}
		idx, err := pol.Add(s)
		if err != nil {
			t.Fatalf("policer Add %d: %v", id, err)
		}
		t.Cleanup(func() { _ = pol.Delete(idx) })
		return idx
	}
	poolA := mk(4245)
	poolB := mk(4246)

	ti, err := cl.AddTable(TableSpec{Mask: model.MaskIP4Dst32})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cl.DeleteTable(ti) })

	member := netip.MustParsePrefix("203.0.113.20/32")
	if err := cl.AddSession(ti, model.MaskIP4Dst32, member, poolA); err != nil {
		t.Fatal(err)
	}
	// Re-add same key with a different policer — overwrite, not duplicate.
	if err := cl.AddSession(ti, model.MaskIP4Dst32, member, poolB); err != nil {
		t.Fatal(err)
	}
	sessions, err := cl.DumpSessions(ti)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Fatalf("re-point should overwrite, got %d sessions", len(sessions))
	}
	if sessions[0].HitNextIndex != poolB {
		t.Errorf("after re-point hit_next = %d, want poolB %d", sessions[0].HitNextIndex, poolB)
	}
}
