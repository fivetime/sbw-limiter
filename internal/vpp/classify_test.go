package vpp

import (
	"encoding/hex"
	"net/netip"
	"testing"

	"github.com/fivetime/sbw-contract/model"
)

// The expected skip/match/mask values were measured from real VPP 26.06
// (`show classify tables verbose`) and must stay byte-identical so tables
// dedupe and dumps verify.
func TestTableMaskLayouts(t *testing.T) {
	cases := []struct {
		mask    model.MaskKind
		skip    uint32
		match   uint32
		maskHex string // match-only mask bytes (match*16)
	}{
		{model.MaskIP4Dst32, 1, 2, "0000000000000000000000000000ffffffff0000000000000000000000000000"},
		{model.MaskIP4Dst24, 1, 2, "0000000000000000000000000000ffffff000000000000000000000000000000"},
		{model.MaskIP4Src32, 1, 1, "00000000000000000000ffffffff0000"},
		{model.MaskIP4Src24, 1, 1, "00000000000000000000ffffff000000"},
		{model.MaskIP6Dst128, 2, 2, "000000000000ffffffffffffffffffffffffffffffff00000000000000000000"},
		{model.MaskIP6Src128, 1, 2, "000000000000ffffffffffffffffffffffffffffffff00000000000000000000"},
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
		// ip4 dst/32: Ethernet14 + IP dst16 = byte 30; total (1+2)*16 = 48
		{model.MaskIP4Dst32, "203.0.113.10/32", 48, "cb00710a", 30},
		// ip4 src/32: byte 26; total (1+1)*16 = 32
		{model.MaskIP4Src32, "203.0.113.10/32", 32, "cb00710a", 26},
		// ip4 dst/24 network 203.0.113.0
		{model.MaskIP4Dst24, "203.0.113.0/24", 48, "cb007100", 30},
		// ip6 dst/128: byte 38; total (2+2)*16 = 64
		{model.MaskIP6Dst128, "2001:db8::a/128", 64, "20010db800000000000000000000000a", 38},
		// ip6 src/128: byte 22; total (1+2)*16 = 48
		{model.MaskIP6Src128, "2001:db8::a/128", 48, "20010db800000000000000000000000a", 22},
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
