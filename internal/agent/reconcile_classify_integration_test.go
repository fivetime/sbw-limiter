//go:build integration

package agent

import (
	"context"
	"net/netip"
	"testing"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/vpp"
)

// T-501 (classify) acceptance against real VPP: a full reconcile pass drives
// policers AND classify sessions to match desired — creating the mask table,
// wiring members to the pool policer (shared bucket), deleting orphans, and
// re-pointing a moved member — all confirmed via classify_session_dump.
func dsMember(pool model.PoolID, prefix string) model.ClassifySession {
	return model.ClassifySession{
		PoolID: pool, Prefix: netip.MustParsePrefix(prefix),
		Direction: model.DirectionIngress, Mask: model.MaskIP4Dst32,
		PolicerName: model.PolicerName(pool, model.DirectionIngress),
	}
}

func desiredFull(specs []model.PolicerSpec, sessions []model.ClassifySession) model.EdgeDesiredState {
	return model.EdgeDesiredState{
		SchemaVersion: model.SchemaVersion, EdgeID: "test",
		Policers: specs, ClassifySessions: sessions,
	}
}

func TestRealReconcileClassifyConverges(t *testing.T) {
	r, conn := realReconciler(t)
	t.Cleanup(func() { _, _ = r.Reconcile(desiredWith()) }) // clean policers (also drops their sessions' table refs)

	pool := model.PoolID(5200)
	polIn := spec(pool, model.DirectionIngress, 1_000_000)

	// 1. From empty: policer + two members on the ip4-dst-32 table.
	res, err := r.Reconcile(desiredFull(
		[]model.PolicerSpec{polIn},
		[]model.ClassifySession{dsMember(pool, "203.0.113.10/32"), dsMember(pool, "203.0.113.11/32")},
	))
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.PolicersAdded != 1 || res.SessionsAdded != 2 {
		t.Fatalf("res = %+v, want 1 policer + 2 sessions added", res)
	}

	// Verify both members hit the SAME policer index (shared bucket).
	pi := r.polIdx["pool5200_in"]
	tbl := classifyTable(t, conn, model.MaskIP4Dst32)
	sessions := dumpSessions(t, conn, tbl)
	if len(sessions) != 2 {
		t.Fatalf("got %d sessions, want 2", len(sessions))
	}
	t.Cleanup(func() { cleanTable(conn, tbl) })
	for _, s := range sessions {
		if s.HitNextIndex != pi {
			t.Errorf("session hit = %d, want policer %d", s.HitNextIndex, pi)
		}
	}

	// 2. Re-apply → no-op.
	res, err = r.Reconcile(desiredFull(
		[]model.PolicerSpec{polIn},
		[]model.ClassifySession{dsMember(pool, "203.0.113.10/32"), dsMember(pool, "203.0.113.11/32")},
	))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Empty() {
		t.Fatalf("re-apply should be a no-op, got %+v", res)
	}

	// 3. Drop one member → orphan session deleted.
	res, err = r.Reconcile(desiredFull(
		[]model.PolicerSpec{polIn},
		[]model.ClassifySession{dsMember(pool, "203.0.113.10/32")},
	))
	if err != nil {
		t.Fatal(err)
	}
	if res.SessionsDeleted != 1 {
		t.Fatalf("sessions deleted = %d, want 1", res.SessionsDeleted)
	}
	if len(dumpSessions(t, conn, tbl)) != 1 {
		t.Error("expected 1 session after orphan delete")
	}

	// 4. Move the member to a second pool → re-point to the new policer.
	pool2 := model.PoolID(5201)
	res, err = r.Reconcile(desiredFull(
		[]model.PolicerSpec{polIn, spec(pool2, model.DirectionIngress, 500_000)},
		[]model.ClassifySession{dsMember(pool2, "203.0.113.10/32")},
	))
	if err != nil {
		t.Fatal(err)
	}
	if res.SessionsMoved != 1 {
		t.Fatalf("sessions moved = %d, want 1", res.SessionsMoved)
	}
	pi2 := r.polIdx["pool5201_in"]
	for _, s := range dumpSessions(t, conn, tbl) {
		if s.HitNextIndex != pi2 {
			t.Errorf("after move, hit = %d, want policer %d", s.HitNextIndex, pi2)
		}
	}
}

func classifyTable(t *testing.T, conn *vpp.Conn, mask model.MaskKind) uint32 {
	t.Helper()
	ch, _ := conn.Channel()
	defer ch.Close()
	tables, err := vpp.NewClassify(ch).FindTablesByMask()
	if err != nil {
		t.Fatal(err)
	}
	idx, ok := tables[mask]
	if !ok {
		t.Fatalf("table for mask %v not found", mask)
	}
	return idx
}

func dumpSessions(t *testing.T, conn *vpp.Conn, table uint32) []vpp.SessionInfo {
	t.Helper()
	ch, _ := conn.Channel()
	defer ch.Close()
	s, err := vpp.NewClassify(ch).DumpSessions(table)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func cleanTable(conn *vpp.Conn, table uint32) {
	ch, err := conn.Channel()
	if err != nil {
		return
	}
	defer ch.Close()
	cl := vpp.NewClassify(ch)
	if s, err := cl.DumpSessions(table); err == nil {
		for _, ss := range s {
			_ = cl.DelSessionByKey(table, model.MaskIP4Dst32, ss.Match)
		}
	}
	_ = cl.DeleteTable(table)
	_ = context.Background()
}
