//go:build integration

package vpp

import (
	"encoding/hex"
	"net/netip"
	"testing"

	"github.com/fivetime/sbw-contract/model"
)

// T-403 acceptance against real VPP: create each of the six mask tables via the
// Go API and confirm VPP's table_info reports byte-identical skip/match/mask
// (i.e. our hand-built layout matches what VPP computes for the same mask).
// Run with BWPOOL_TEST_VPP_SOCKET set.
func TestRealClassifyTableLayouts(t *testing.T) {
	c := realConn(t)
	ch, err := c.Channel()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ch.Close)
	cl := NewClassify(ch)

	cases := []struct {
		mask    model.MaskKind
		skip    uint32
		match   uint32
		maskHex string
	}{
		{model.MaskIP4Dst32, 1, 2, "0000000000000000000000000000ffffffff0000000000000000000000000000"},
		{model.MaskIP4Dst24, 1, 2, "0000000000000000000000000000ffffff000000000000000000000000000000"},
		{model.MaskIP4Src32, 1, 1, "00000000000000000000ffffffff0000"},
		{model.MaskIP4Src24, 1, 1, "00000000000000000000ffffff000000"},
		{model.MaskIP6Dst128, 2, 2, "000000000000ffffffffffffffffffffffffffffffff00000000000000000000"},
		{model.MaskIP6Src128, 1, 2, "000000000000ffffffffffffffffffffffffffffffff00000000000000000000"},
	}
	for _, tc := range cases {
		t.Run(tc.mask.String(), func(t *testing.T) {
			idx, err := cl.AddTable(TableSpec{Mask: tc.mask})
			if err != nil {
				t.Fatalf("AddTable: %v", err)
			}
			t.Cleanup(func() { _ = cl.DeleteTable(idx) })

			info, err := cl.TableInfo(idx)
			if err != nil {
				t.Fatalf("TableInfo: %v", err)
			}
			if info.SkipNVectors != tc.skip || info.MatchNVectors != tc.match {
				t.Errorf("VPP skip/match = %d/%d, want %d/%d",
					info.SkipNVectors, info.MatchNVectors, tc.skip, tc.match)
			}
			if got := hex.EncodeToString(info.Mask); got != tc.maskHex {
				t.Errorf("VPP mask:\n got %s\nwant %s", got, tc.maskHex)
			}
		})
	}
}

// Build a chain (ip4-dst-32 → ip4-dst-24 → ip6-dst-128) and verify VPP records
// the next_table_index links — the §5.3 multi-mask 串查 chain.
func TestRealClassifyTableChaining(t *testing.T) {
	c := realConn(t)
	ch, err := c.Channel()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ch.Close)
	cl := NewClassify(ch)

	t6, err := cl.AddTable(TableSpec{Mask: model.MaskIP6Dst128})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cl.DeleteTable(t6) })
	t24, err := cl.AddTable(TableSpec{Mask: model.MaskIP4Dst24})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cl.DeleteTable(t24) })
	t32, err := cl.AddTable(TableSpec{Mask: model.MaskIP4Dst32})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cl.DeleteTable(t32) })

	// Chain explicitly: t32 → t24 → t6.
	if err := cl.LinkTable(t32, t24); err != nil {
		t.Fatal(err)
	}
	if err := cl.LinkTable(t24, t6); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		idx, next uint32
		name      string
	}{
		{t32, t24, "ip4-dst-32 → ip4-dst-24"},
		{t24, t6, "ip4-dst-24 → ip6-dst-128"},
	} {
		info, err := cl.TableInfo(tc.idx)
		if err != nil {
			t.Fatal(err)
		}
		if info.NextTableIndex != tc.next {
			t.Errorf("%s: next = %d, want %d", tc.name, info.NextTableIndex, tc.next)
		}
	}
}

// Add and remove a member session on a real table; the session-match buffer
// must be accepted by VPP (validates the (skip+match)*16 length and layout).
func TestRealClassifySession(t *testing.T) {
	c := realConn(t)
	ch, err := c.Channel()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ch.Close)
	cl := NewClassify(ch)

	idx, err := cl.AddTable(TableSpec{Mask: model.MaskIP4Dst32})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cl.DeleteTable(idx) })

	p := netip.MustParsePrefix("203.0.113.10/32")
	// hit_next 0 is a valid node index for the bare classify accept; we only
	// need VPP to accept the match buffer here (policer link is T-404).
	if err := cl.AddSession(idx, model.MaskIP4Dst32, p, 0); err != nil {
		t.Fatalf("AddSession: %v", err)
	}
	info, err := cl.TableInfo(idx)
	if err != nil {
		t.Fatal(err)
	}
	if info.MatchNVectors != 2 {
		t.Errorf("table match vectors = %d", info.MatchNVectors)
	}
	if err := cl.DelSession(idx, model.MaskIP4Dst32, p); err != nil {
		t.Fatalf("DelSession: %v", err)
	}
}
