//go:build integration

package agent

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/vpp"
)

// T-501 acceptance against real VPP: a reconcile pass drives VPP's managed
// policers to match the desired state — adds missing, deletes orphans, leaves
// steady state untouched, updates drift — verified via policer dump. Run with
// BWPOOL_TEST_VPP_SOCKET set.
func realReconciler(t *testing.T) (*Reconciler, *vpp.Conn) {
	t.Helper()
	sock := os.Getenv("BWPOOL_TEST_VPP_SOCKET")
	if sock == "" {
		t.Skip("BWPOOL_TEST_VPP_SOCKET not set")
	}
	conn, err := vpp.Dial(context.Background(), sock, vpp.WithReadyTimeout(10*time.Second))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(conn.Close)
	return New(conn, nil), conn
}

func desiredWith(specs ...model.PolicerSpec) model.EdgeDesiredState {
	return model.EdgeDesiredState{SchemaVersion: model.SchemaVersion, EdgeID: "test", Policers: specs}
}

func spec(pool model.PoolID, dir model.Direction, cir uint64) model.PolicerSpec {
	return model.PolicerSpec{
		Name: model.PolicerName(pool, dir), PoolID: pool, Direction: dir,
		Type: model.Policer1R2C, RateType: model.RateKbps,
		CIR: cir, CommittedBurstBytes: 12_500_000,
		ConformAction: model.PolicerTransmit, ExceedAction: model.PolicerDrop,
	}
}

func livePolicerNames(t *testing.T, conn *vpp.Conn) map[string]vpp.PolicerInfo {
	t.Helper()
	ch, err := conn.Channel()
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()
	infos, err := vpp.NewPolicers(ch).Dump()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]vpp.PolicerInfo{}
	for _, i := range infos {
		out[i.Name] = i
	}
	return out
}

func TestRealReconcileConverges(t *testing.T) {
	r, conn := realReconciler(t)

	// Clean any leftover test policers from a prior run.
	t.Cleanup(func() {
		_, _ = r.Reconcile(desiredWith())
	})

	// 1. From empty → add two pools (ingress + egress each).
	desired := desiredWith(
		spec(5100, model.DirectionIngress, 1_000_000),
		spec(5100, model.DirectionEgress, 1_000_000),
		spec(5101, model.DirectionIngress, 500_000),
	)
	res, err := r.Reconcile(desired)
	if err != nil {
		t.Fatalf("Reconcile add: %v", err)
	}
	if res.PolicersAdded != 3 {
		t.Fatalf("added = %d, want 3", res.PolicersAdded)
	}
	live := livePolicerNames(t, conn)
	for _, n := range []string{"pool5100_in", "pool5100_out", "pool5101_in"} {
		if _, ok := live[n]; !ok {
			t.Errorf("policer %s not created", n)
		}
	}

	// 2. Re-apply same desired → steady state, no changes.
	res, err = r.Reconcile(desired)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Empty() {
		t.Fatalf("re-apply should be a no-op, got %+v", res)
	}

	// 3. Drop pool 5101 from desired → orphan deleted.
	res, err = r.Reconcile(desiredWith(
		spec(5100, model.DirectionIngress, 1_000_000),
		spec(5100, model.DirectionEgress, 1_000_000),
	))
	if err != nil {
		t.Fatal(err)
	}
	if res.PolicersDeleted != 1 {
		t.Fatalf("deleted = %d, want 1", res.PolicersDeleted)
	}
	if _, ok := livePolicerNames(t, conn)["pool5101_in"]; ok {
		t.Error("orphan pool5101_in not deleted")
	}

	// 4. Change pool 5100 ingress rate → drift update (index stays stable).
	idxBefore := r.polIdx["pool5100_in"]
	res, err = r.Reconcile(desiredWith(
		spec(5100, model.DirectionIngress, 2_000_000),
		spec(5100, model.DirectionEgress, 1_000_000),
	))
	if err != nil {
		t.Fatal(err)
	}
	if res.PolicersUpdated != 1 {
		t.Fatalf("updated = %d, want 1", res.PolicersUpdated)
	}
	if r.polIdx["pool5100_in"] != idxBefore {
		t.Errorf("in-place update changed index %d→%d", idxBefore, r.polIdx["pool5100_in"])
	}
	if live := livePolicerNames(t, conn); live["pool5100_in"].CIR != 2_000_000 {
		t.Errorf("drift not applied: CIR = %d, want 2000000", live["pool5100_in"].CIR)
	}
}
