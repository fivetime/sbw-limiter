// Package redirectec is the SINGLE SOURCE OF TRUTH for the redirect-to-IP BGP
// ext-community wire layout that steers a FlowSpec source-prefix to its home L.
//
// The bytes are consumed by two independent BIRD paths that must agree exactly or
// R/vppfdp parses the wrong redirect target (no compile error, no cross-test):
//   - the legacy `birdc configure` path (internal/flowspec) renders BIRD filter
//     text, deriving the two 32-bit halves of the v4 EC from IP4();
//   - the api-feed path (internal/birdfeed) ships the raw bytes over the api socket.
//
// Both used to hand-roll the layout; centralizing it here removes the silent-drift
// hazard (change one, forget the other). Format: draft-ietf-idr-flowspec-redirect-ip.
package redirectec

import (
	"encoding/binary"
	"net/netip"
)

// IP4 encodes the standard redirect-to-IPv4 transitive ext-community (type 0x01
// IPv4-Address-Specific, sub-type 0x0c) for nextHop: [0x01,0x0c,a,b,c,d,0x00,0x00]
// with a.b.c.d = nextHop (global-admin) and local-admin 0 (C=0 = redirect, not
// copy). NOT RFC 8955's rt-redirect (sub 0x08 = redirect-to-VRF). nextHop must be
// IPv4 (callers validate).
func IP4(nextHop netip.Addr) [8]byte {
	var ec [8]byte
	ec[0], ec[1] = 0x01, 0x0c
	b4 := nextHop.As4()
	copy(ec[2:6], b4[:])
	return ec
}

// I6 encodes the standard redirect-to-IPv6 transitive IPv6-Address-Specific
// ext-community (type/sub-type 0x000c, RFC 5701 20-byte form): [0x000c(2 BE),
// ipv6(16), local-admin(2 BE)] with local-admin 0 (C=0 = redirect). Byte-identical
// to BIRD's `i6ec(0x000c, nextHop6, 0)` filter helper, so vppfdp/R parse it
// unchanged. nextHop6 must be IPv6 (callers validate).
func I6(nextHop6 netip.Addr) [20]byte {
	var ec [20]byte
	binary.BigEndian.PutUint16(ec[0:2], 0x000c)
	ip := nextHop6.As16()
	copy(ec[2:18], ip[:])
	return ec
}
