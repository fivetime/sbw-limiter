package agent

import (
	"testing"

	"github.com/fivetime/sbw-contract/model"
)

// T-503: after a VPP restart the reconciler's cached policer name→index map is
// stale (VPP reassigns indexes from zero). Reset drops it so the next reconcile
// re-adds policers by name and relearns the indexes.
func TestResetClearsPolicerIndexCache(t *testing.T) {
	r := newReconciler()
	f := newFakePolicers()

	// First reconcile learns an index for the pool policer.
	if _, err := r.reconcilePolicers(f, []model.PolicerSpec{ingressSpec(200, 1_000_000)}); err != nil {
		t.Fatal(err)
	}
	name := f.added[0]
	if _, ok := r.polIdx[name]; !ok {
		t.Fatalf("expected %s in index cache after add", name)
	}

	// Simulate a VPP restart: the data plane is empty, and Reset clears the
	// now-invalid cache.
	r.Reset()
	if len(r.polIdx) != 0 {
		t.Fatalf("Reset should clear the index cache, got %v", r.polIdx)
	}

	// Reinstall against the fresh (empty) VPP → the policer is re-added and a new
	// index relearned, not assumed-present from the stale cache.
	fresh := newFakePolicers() // empty dump, as after a restart
	c, err := r.reconcilePolicers(fresh, []model.PolicerSpec{ingressSpec(200, 1_000_000)})
	if err != nil {
		t.Fatal(err)
	}
	if c.added != 1 {
		t.Fatalf("post-restart reconcile should re-add the policer, added=%d", c.added)
	}
	if _, ok := r.polIdx[name]; !ok {
		t.Errorf("index cache should be relearned after reinstall")
	}
}
