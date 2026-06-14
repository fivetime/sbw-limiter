package agent

import (
	"net/netip"
	"testing"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/vpp"
)

// TestCountProgrammed: the B-02 attestation counts only MANAGED policers (name
// encodes a pool id; an unmanaged "vpp_default" is excluded) and sums classify
// sessions across ALL mask tables (so an orphan on any table is counted).
func TestCountProgrammed(t *testing.T) {
	fp := newFakePolicers(
		vpp.PolicerInfo{Name: model.PolicerName(200, model.DirectionIngress)},
		vpp.PolicerInfo{Name: model.PolicerName(200, model.DirectionEgress)},
		vpp.PolicerInfo{Name: "vpp_default"}, // unmanaged — must not be counted
	)
	fc := newFakeClassify()
	t4, _ := fc.AddTable(vpp.TableSpec{Mask: model.MaskIP4Dst32})
	if err := fc.AddSession(t4, model.MaskIP4Dst32, netip.MustParsePrefix("203.0.113.7/32"), 100); err != nil {
		t.Fatal(err)
	}
	if err := fc.AddSession(t4, model.MaskIP4Dst32, netip.MustParsePrefix("203.0.113.8/32"), 100); err != nil {
		t.Fatal(err)
	}
	t6, _ := fc.AddTable(vpp.TableSpec{Mask: model.MaskIP6Dst128})
	if err := fc.AddSession(t6, model.MaskIP6Dst128, netip.MustParsePrefix("2001:db8::1/128"), 101); err != nil {
		t.Fatal(err)
	}

	pol, sess, err := countProgrammed(fp, fc)
	if err != nil {
		t.Fatal(err)
	}
	if pol != 2 {
		t.Errorf("policers = %d, want 2 (managed only, unmanaged excluded)", pol)
	}
	if sess != 3 {
		t.Errorf("sessions = %d, want 3 (summed across both tables)", sess)
	}
}
