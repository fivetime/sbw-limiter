package agent

import (
	"log/slog"
	"testing"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/vpp"
)

// fakePolicers implements policerReconciler over an in-memory name→spec store,
// recording calls so the reconcile diff logic can be tested without VPP.
type fakePolicers struct {
	live    map[string]vpp.PolicerInfo
	nextIdx uint32

	added, updated, deletedNames []string
}

func newFakePolicers(live ...vpp.PolicerInfo) *fakePolicers {
	m := make(map[string]vpp.PolicerInfo)
	for _, p := range live {
		m[p.Name] = p
	}
	return &fakePolicers{live: m, nextIdx: 100}
}

func (f *fakePolicers) Dump() ([]vpp.PolicerInfo, error) {
	out := make([]vpp.PolicerInfo, 0, len(f.live))
	for _, p := range f.live {
		out = append(out, p)
	}
	return out, nil
}

func (f *fakePolicers) Add(s model.PolicerSpec) (uint32, error) {
	idx := f.nextIdx
	f.nextIdx++
	f.live[s.Name] = vpp.PolicerInfo{Name: s.Name, CIR: uint32(s.CIR), CB: s.CommittedBurstBytes}
	f.added = append(f.added, s.Name)
	return idx, nil
}

func (f *fakePolicers) Update(_ uint32, s model.PolicerSpec) error {
	f.live[s.Name] = vpp.PolicerInfo{Name: s.Name, CIR: uint32(s.CIR), CB: s.CommittedBurstBytes}
	f.updated = append(f.updated, s.Name)
	return nil
}

func (f *fakePolicers) DeleteByName(name string) error {
	delete(f.live, name)
	f.deletedNames = append(f.deletedNames, name)
	return nil
}

func ingressSpec(pool model.PoolID, cir uint64) model.PolicerSpec {
	return model.PolicerSpec{
		Name: model.PolicerName(pool, model.DirectionIngress), PoolID: pool,
		Direction: model.DirectionIngress, Type: model.Policer1R2C, RateType: model.RateKbps,
		CIR: cir, CommittedBurstBytes: 12_500_000,
		ConformAction: model.PolicerTransmit, ExceedAction: model.PolicerDrop,
	}
}

func newReconciler() *Reconciler {
	return &Reconciler{log: slog.New(slog.DiscardHandler), polIdx: map[string]uint32{}}
}

func TestReconcileAddsMissing(t *testing.T) {
	f := newFakePolicers()
	r := newReconciler()
	c, err := r.reconcilePolicers(f, []model.PolicerSpec{ingressSpec(200, 1_000_000), ingressSpec(201, 500_000)})
	if err != nil {
		t.Fatal(err)
	}
	if c.added != 2 || c.updated != 0 || c.deleted != 0 {
		t.Fatalf("counts = %+v, want 2 added", c)
	}
	if _, ok := r.polIdx["pool200_in"]; !ok {
		t.Error("index not tracked after add")
	}
}

func TestReconcileDeletesOrphans(t *testing.T) {
	// VPP has two managed policers + one unmanaged ("vpp_default"); desired has
	// only one. The other managed one is an orphan; the unmanaged is untouched.
	f := newFakePolicers(
		vpp.PolicerInfo{Name: "pool200_in", CIR: 1_000_000, CB: 12_500_000},
		vpp.PolicerInfo{Name: "pool999_in", CIR: 1, CB: 1},
		vpp.PolicerInfo{Name: "vpp_default", CIR: 1, CB: 1},
	)
	r := newReconciler()
	r.polIdx["pool200_in"] = 5
	r.polIdx["pool999_in"] = 6

	c, err := r.reconcilePolicers(f, []model.PolicerSpec{ingressSpec(200, 1_000_000)})
	if err != nil {
		t.Fatal(err)
	}
	if c.deleted != 1 || len(f.deletedNames) != 1 || f.deletedNames[0] != "pool999_in" {
		t.Fatalf("deleted = %v, want [pool999_in]", f.deletedNames)
	}
	if _, ok := f.live["vpp_default"]; !ok {
		t.Error("unmanaged policer must not be deleted")
	}
	if _, ok := r.polIdx["pool999_in"]; ok {
		t.Error("orphan index not dropped from map")
	}
}

func TestReconcileUpdatesDrift(t *testing.T) {
	f := newFakePolicers(vpp.PolicerInfo{Name: "pool200_in", CIR: 1_000_000, CB: 12_500_000})
	r := newReconciler()
	r.polIdx["pool200_in"] = 9

	// Desired CIR changed → in-place update via tracked index (index stays 9).
	c, err := r.reconcilePolicers(f, []model.PolicerSpec{ingressSpec(200, 2_000_000)})
	if err != nil {
		t.Fatal(err)
	}
	if c.updated != 1 || len(f.updated) != 1 {
		t.Fatalf("updated = %v, want 1", f.updated)
	}
	if len(f.added) != 0 {
		t.Error("drift should update in place, not re-add")
	}
}

func TestReconcileDriftWithUnknownIndexRecreates(t *testing.T) {
	// Index not tracked (e.g. after agent restart) → re-create by name.
	f := newFakePolicers(vpp.PolicerInfo{Name: "pool200_in", CIR: 1_000_000, CB: 12_500_000})
	r := newReconciler() // empty polIdx

	c, err := r.reconcilePolicers(f, []model.PolicerSpec{ingressSpec(200, 2_000_000)})
	if err != nil {
		t.Fatal(err)
	}
	if c.updated != 1 {
		t.Fatalf("counts = %+v, want 1 updated", c)
	}
	if len(f.deletedNames) != 1 || len(f.added) != 1 {
		t.Errorf("unknown-index drift should delete+add: del=%v add=%v", f.deletedNames, f.added)
	}
	if _, ok := r.polIdx["pool200_in"]; !ok {
		t.Error("new index must be tracked")
	}
}

func TestReconcileSteadyStateNoOp(t *testing.T) {
	f := newFakePolicers(vpp.PolicerInfo{Name: "pool200_in", CIR: 1_000_000, CB: 12_500_000})
	r := newReconciler()
	r.polIdx["pool200_in"] = 3

	c, err := r.reconcilePolicers(f, []model.PolicerSpec{ingressSpec(200, 1_000_000)})
	if err != nil {
		t.Fatal(err)
	}
	if c.added+c.updated+c.deleted != 0 {
		t.Fatalf("steady state should be a no-op, got %+v", c)
	}
}
