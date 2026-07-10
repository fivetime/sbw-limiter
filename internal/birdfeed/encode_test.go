package birdfeed

import (
	"bytes"
	"net/netip"
	"testing"
)

// The redirect EC must be byte-identical to flowspec.redirectIP4ExtCommunity and
// to the live lab config `(generic, 0x010c0a46, 0x63150000)` (redirect → 10.70.99.21).
func TestRedirectIP4EC(t *testing.T) {
	ec := redirectIP4EC(netip.MustParseAddr("10.70.99.21"))
	want := [8]byte{0x01, 0x0c, 0x0a, 0x46, 0x63, 0x15, 0x00, 0x00}
	if ec != want {
		t.Fatalf("redirectIP4EC = % x, want % x", ec, want)
	}
}

func TestFrameAnchorAdd(t *testing.T) {
	got := frameAnchor(opAdd, netip.MustParsePrefix("11.0.0.5/32"), nil)
	// header(8): v=1 op=1 flags=0,0 len=0,0,0,16 ; body: net=1 px=32 key=11,0,0,5 attr=1,0
	want := []byte{1, 1, 0, 0, 0, 0, 0, 16, netIP4, 32, 11, 0, 0, 5, attrBlackhole, 0}
	if !bytes.Equal(got, want) {
		t.Fatalf("anchor ADD = % x\nwant            % x", got, want)
	}
}

func TestFrameAnchorDel(t *testing.T) {
	got := frameAnchor(opDel, netip.MustParsePrefix("11.0.0.5/32"), nil)
	want := []byte{1, opDel, 0, 0, 0, 0, 0, 14, netIP4, 32, 11, 0, 0, 5} // no attr on DEL
	if !bytes.Equal(got, want) {
		t.Fatalf("anchor DEL = % x\nwant            % x", got, want)
	}
}

func TestFrameAnchorV6(t *testing.T) {
	got := frameAnchor(opAdd, netip.MustParsePrefix("2001:db8::7/128"), nil)
	if got[1] != opAdd || got[hdrLen] != netIP6 || got[hdrLen+1] != 128 {
		t.Fatalf("v6 anchor header wrong: op=%d net=%d px=%d", got[1], got[hdrLen], got[hdrLen+1])
	}
	// 8 hdr + 1 net + 1 px + 16 key + 2 attr = 28
	if len(got) != 28 {
		t.Fatalf("v6 anchor len = %d, want 28", len(got))
	}
}

func TestFrameFlowAdd(t *testing.T) {
	ec := redirectIP4EC(netip.MustParseAddr("10.70.99.21"))
	got := frameFlow(opAdd, netip.MustParsePrefix("11.0.0.5/32"), ec[:])
	want := []byte{
		1, opAdd, 0, 0, 0, 0, 0, 24, // header, len = 8+1+1+4+2+8 = 24
		netFlow4, 32, 11, 0, 0, 5,
		attrExtComm, 8, 0x01, 0x0c, 0x0a, 0x46, 0x63, 0x15, 0x00, 0x00,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("flow ADD = % x\nwant          % x", got, want)
	}
}

// redirectI6EC must be the standard 20-byte i6ec wire layout:
// type/sub-type 0x000c, then the 16-byte IPv6 target, then a zero local-admin.
func TestRedirectI6EC(t *testing.T) {
	ec := redirectI6EC(netip.MustParseAddr("2001:db8::7"))
	want := [20]byte{
		0x00, 0x0c, // type 0x00 (IPv6-addr-specific) + sub-type 0x0c (redirect)
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x07, // 2001:db8::7
		0x00, 0x00, // local-admin 0 (C=0 = redirect)
	}
	if ec != want {
		t.Fatalf("redirectI6EC = % x\nwant           % x", ec, want)
	}
}

func TestFrameFlowV6(t *testing.T) {
	ec := redirectI6EC(netip.MustParseAddr("2001:db8::7"))
	got := frameFlow(opAdd, netip.MustParsePrefix("fc00:16::3/128"), ec[:])
	// header(8) + net(1) + px(1) + key(16) + attr-tlv-hdr(2) + ec(20) = 48
	want := []byte{
		1, opAdd, 0, 0, 0, 0, 0, 48,
		netFlow6, 128,
		0xfc, 0, 0, 0x16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, // fc00:16::3
		attrExtComm, 20,
		0x00, 0x0c, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x07, 0x00, 0x00,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("v6 flow ADD = % x\nwant             % x", got, want)
	}
}

func TestFrameHelloEOR(t *testing.T) {
	if h := frameHello(); len(h) != 8 || h[1] != opHello || h[7] != 8 {
		t.Fatalf("hello = % x", h)
	}
	if e := frameEOR(); len(e) != 8 || e[1] != opEOR || e[7] != 8 {
		t.Fatalf("eor = % x", e)
	}
}
