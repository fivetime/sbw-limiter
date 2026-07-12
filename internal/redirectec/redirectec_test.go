package redirectec

import (
	"net/netip"
	"testing"
)

// TestIP4Layout pins the exact redirect-to-IPv4 EC bytes — the cross-check the
// two consumers (flowspec text render + birdfeed api bytes) both rely on. If this
// layout ever changes, R/vppfdp parses the wrong redirect target.
func TestIP4Layout(t *testing.T) {
	got := IP4(netip.MustParseAddr("10.0.0.5"))
	want := [8]byte{0x01, 0x0c, 10, 0, 0, 5, 0x00, 0x00}
	if got != want {
		t.Fatalf("IP4 = % x, want % x", got, want)
	}
}

// TestI6Layout pins the redirect-to-IPv6 i6ec bytes (RFC 5701 20-byte form).
func TestI6Layout(t *testing.T) {
	got := I6(netip.MustParseAddr("fc00:4:2:3::72"))
	// 0x000c type/subtype, then the 16-byte address, then 2 zero local-admin bytes.
	want := [20]byte{
		0x00, 0x0c,
		0xfc, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x72,
		0x00, 0x00,
	}
	if got != want {
		t.Fatalf("I6 = % x, want % x", got, want)
	}
}
