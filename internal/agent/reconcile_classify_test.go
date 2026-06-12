package agent

import (
	"encoding/hex"
	"net/netip"
	"testing"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/vpp"
)

// fakeClassify implements classifyReconciler over in-memory tables/sessions.
type fakeClassify struct {
	tables   map[model.MaskKind]uint32    // existing tables
	sessions map[uint32]map[string]uint32 // table → matchKey → hitNext
	nextTbl  uint32

	added, deleted int
}

func newFakeClassify() *fakeClassify {
	return &fakeClassify{
		tables:   map[model.MaskKind]uint32{},
		sessions: map[uint32]map[string]uint32{},
		nextTbl:  10,
	}
}

func (f *fakeClassify) FindTablesByMask() (map[model.MaskKind]uint32, error) {
	out := map[model.MaskKind]uint32{}
	for k, v := range f.tables {
		out[k] = v
	}
	return out, nil
}

func (f *fakeClassify) AddTable(spec vpp.TableSpec) (uint32, error) {
	idx := f.nextTbl
	f.nextTbl++
	f.tables[spec.Mask] = idx
	f.sessions[idx] = map[string]uint32{}
	return idx, nil
}

func (f *fakeClassify) DumpSessions(table uint32) ([]vpp.SessionInfo, error) {
	var out []vpp.SessionInfo
	for key, hit := range f.sessions[table] {
		m, _ := hex.DecodeString(key)
		out = append(out, vpp.SessionInfo{Match: m, HitNextIndex: hit})
	}
	return out, nil
}

func (f *fakeClassify) AddSession(table uint32, mask model.MaskKind, prefix netip.Prefix, hitNext uint32) error {
	m, err := vpp.SessionKey(mask, prefix)
	if err != nil {
		return err
	}
	if f.sessions[table] == nil {
		f.sessions[table] = map[string]uint32{}
	}
	f.sessions[table][hex.EncodeToString(m)] = hitNext
	f.added++
	return nil
}

func (f *fakeClassify) DelSessionByKey(table uint32, _ model.MaskKind, match []byte) error {
	delete(f.sessions[table], hex.EncodeToString(match))
	f.deleted++
	return nil
}

func member(pool model.PoolID, prefix string) model.ClassifySession {
	return model.ClassifySession{
		PoolID: pool, Prefix: netip.MustParsePrefix(prefix),
		Direction: model.DirectionIngress, Mask: model.MaskIP4Dst32,
		PolicerName: model.PolicerName(pool, model.DirectionIngress),
	}
}

func TestReconcileClassifyAddsAndCreatesTable(t *testing.T) {
	f := newFakeClassify()
	r := newReconciler()
	r.polIdx["pool200_in"] = 5

	c, err := r.reconcileClassify(f, []model.ClassifySession{
		member(200, "203.0.113.10/32"),
		member(200, "203.0.113.11/32"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.added != 2 || c.deleted != 0 || c.moved != 0 {
		t.Fatalf("counts = %+v, want 2 added", c)
	}
	// Table created for ip4-dst-32, both sessions hit policer 5 (shared bucket).
	tbl := f.tables[model.MaskIP4Dst32]
	for _, hit := range f.sessions[tbl] {
		if hit != 5 {
			t.Errorf("session hit = %d, want 5", hit)
		}
	}
}

func TestReconcileClassifyDeletesOrphan(t *testing.T) {
	f := newFakeClassify()
	r := newReconciler()
	r.polIdx["pool200_in"] = 5
	// Seed two members; desired keeps only one.
	_, _ = r.reconcileClassify(f, []model.ClassifySession{
		member(200, "203.0.113.10/32"), member(200, "203.0.113.11/32"),
	})

	c, err := r.reconcileClassify(f, []model.ClassifySession{member(200, "203.0.113.10/32")})
	if err != nil {
		t.Fatal(err)
	}
	if c.deleted != 1 {
		t.Fatalf("deleted = %d, want 1", c.deleted)
	}
	if len(f.sessions[f.tables[model.MaskIP4Dst32]]) != 1 {
		t.Errorf("expected 1 remaining session")
	}
}

func TestReconcileClassifyRepointsMovedMember(t *testing.T) {
	f := newFakeClassify()
	r := newReconciler()
	r.polIdx["pool200_in"] = 5
	r.polIdx["pool201_in"] = 6

	_, _ = r.reconcileClassify(f, []model.ClassifySession{member(200, "203.0.113.10/32")})

	// Same prefix now belongs to pool 201 → re-point to policer 6.
	c, err := r.reconcileClassify(f, []model.ClassifySession{member(201, "203.0.113.10/32")})
	if err != nil {
		t.Fatal(err)
	}
	if c.moved != 1 || c.added != 0 || c.deleted != 0 {
		t.Fatalf("counts = %+v, want 1 moved", c)
	}
	tbl := f.tables[model.MaskIP4Dst32]
	for _, hit := range f.sessions[tbl] {
		if hit != 6 {
			t.Errorf("re-pointed hit = %d, want 6", hit)
		}
	}
}

func TestReconcileClassifyUnknownPolicerErrors(t *testing.T) {
	f := newFakeClassify()
	r := newReconciler() // empty polIdx
	_, err := r.reconcileClassify(f, []model.ClassifySession{member(200, "203.0.113.10/32")})
	if err == nil {
		t.Fatal("expected error for session referencing unreconciled policer")
	}
}

func TestReconcileClassifySteadyStateNoOp(t *testing.T) {
	f := newFakeClassify()
	r := newReconciler()
	r.polIdx["pool200_in"] = 5
	sessions := []model.ClassifySession{member(200, "203.0.113.10/32")}
	_, _ = r.reconcileClassify(f, sessions)

	c, err := r.reconcileClassify(f, sessions)
	if err != nil {
		t.Fatal(err)
	}
	if c.added+c.deleted+c.moved != 0 {
		t.Fatalf("steady state should be a no-op, got %+v", c)
	}
}
