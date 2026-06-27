package vpp

import (
	"encoding/hex"
	"net/netip"
	"testing"

	"github.com/fivetime/sbw-contract/model"
)

// The expected skip/match/mask values are the L3 (IP-header) layout VPP's
// policer-classify input feature reads — `classify table mask l3 ip{4,6}
// {src,dst}` (no Ethernet/L2 offset). They must stay byte-identical so tables
// dedupe and dumps verify. (The earlier values added a 14-byte Ethernet header;
// that layout dumped fine but never matched real traffic — see classify.go.)
func TestTableMaskLayouts(t *testing.T) {
	cases := []struct {
		mask    model.MaskKind
		skip    uint32
		match   uint32
		maskHex string // match-only mask bytes (match*16)
	}{
		{model.MaskIP4Dst32, 1, 1, "ffffffff000000000000000000000000"},
		{model.MaskIP4Dst24, 1, 1, "ffffff00000000000000000000000000"},
		{model.MaskIP4Src32, 0, 1, "000000000000000000000000ffffffff"},
		{model.MaskIP4Src24, 0, 1, "000000000000000000000000ffffff00"},
		{model.MaskIP6Dst128, 1, 2, "0000000000000000ffffffffffffffffffffffffffffffff0000000000000000"},
		{model.MaskIP6Src128, 0, 2, "0000000000000000ffffffffffffffffffffffffffffffff0000000000000000"},
	}
	for _, c := range cases {
		t.Run(c.mask.String(), func(t *testing.T) {
			ms, err := specOf(c.mask)
			if err != nil {
				t.Fatal(err)
			}
			skip, match, mask := ms.tableMask()
			if skip != c.skip || match != c.match {
				t.Errorf("skip/match = %d/%d, want %d/%d", skip, match, c.skip, c.match)
			}
			if got := hex.EncodeToString(mask); got != c.maskHex {
				t.Errorf("mask:\n got %s\nwant %s", got, c.maskHex)
			}
			if len(mask) != int(match)*vec {
				t.Errorf("mask len %d != match*16 %d", len(mask), match*vec)
			}
		})
	}
}

func TestSessionMatchLayout(t *testing.T) {
	cases := []struct {
		mask     model.MaskKind
		prefix   string
		totalLen int    // (skip+match)*16
		valHex   string // address bytes
		valAt    int    // absolute packet offset
	}{
		// ip4 dst/32: L3 IP dst at byte 16; total (1+1)*16 = 32
		{model.MaskIP4Dst32, "203.0.113.10/32", 32, "cb00710a", 16},
		// ip4 src/32: L3 IP src at byte 12; total (0+1)*16 = 16
		{model.MaskIP4Src32, "203.0.113.10/32", 16, "cb00710a", 12},
		// ip4 dst/24 network 203.0.113.0
		{model.MaskIP4Dst24, "203.0.113.0/24", 32, "cb007100", 16},
		// ip6 dst/128: L3 IP dst at byte 24; total (1+2)*16 = 48
		{model.MaskIP6Dst128, "2001:db8::a/128", 48, "20010db800000000000000000000000a", 24},
		// ip6 src/128: L3 IP src at byte 8; total (0+2)*16 = 32
		{model.MaskIP6Src128, "2001:db8::a/128", 32, "20010db800000000000000000000000a", 8},
	}
	for _, c := range cases {
		t.Run(c.mask.String(), func(t *testing.T) {
			ms, _ := specOf(c.mask)
			buf, err := ms.sessionMatch(netip.MustParsePrefix(c.prefix))
			if err != nil {
				t.Fatal(err)
			}
			if len(buf) != c.totalLen {
				t.Fatalf("match len %d, want %d", len(buf), c.totalLen)
			}
			val, _ := hex.DecodeString(c.valHex)
			got := buf[c.valAt : c.valAt+len(val)]
			if hex.EncodeToString(got) != c.valHex {
				t.Errorf("addr at byte %d = %x, want %s", c.valAt, got, c.valHex)
			}
			// Everything outside the address must be zero (VPP masks anyway,
			// but a clean buffer makes dumps deterministic).
			for i, b := range buf {
				if i >= c.valAt && i < c.valAt+len(val) {
					continue
				}
				if b != 0 {
					t.Errorf("non-zero byte %d = %#x outside address", i, b)
				}
			}
		})
	}
}

func TestSessionMatchFamilyMismatch(t *testing.T) {
	ms, _ := specOf(model.MaskIP4Dst32)
	if _, err := ms.sessionMatch(netip.MustParsePrefix("2001:db8::a/128")); err == nil {
		t.Fatal("expected family mismatch error")
	}
}

func TestNetmask(t *testing.T) {
	cases := []struct {
		mask model.MaskKind
		want string
	}{
		{model.MaskIP4Dst32, "ffffffff"},
		{model.MaskIP4Dst24, "ffffff00"},
		{model.MaskIP6Dst128, "ffffffffffffffffffffffffffffffff"},
	}
	for _, c := range cases {
		ms, _ := specOf(c.mask)
		if got := hex.EncodeToString(ms.netmask()); got != c.want {
			t.Errorf("%v netmask = %s, want %s", c.mask, got, c.want)
		}
	}
}
