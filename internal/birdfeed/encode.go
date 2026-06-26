// Package birdfeed is the agent-side client of the bird-vpp `api` source proto:
// it streams incremental route announce/withdraw over /run/bird/api.sock instead
// of rendering anchors.conf/flowspec.conf + `birdc configure` (which at scale
// took minutes per reconfigure, locked the whole table for ~24s and tripped a
// bird assertion — see sbw-contract DESIGN-bird-api.md). bird's `api` proto calls
// rte_update() per message (microsecond per-route lock, no config parse).
//
// encode.go is the wire codec (BF-01): a pure, model-independent encoder for the
// length-prefixed binary frames the proto parses. Byte layout MUST match
// proto/api/api.h:
//
//	frame  = version(u8) opcode(u8) flags(u16 BE) length(u32 BE, whole frame) body
//	ADD    = net_type(u8) pxlen(u8) key(addr bytes: v4=4 v6=16) attr-TLVs
//	DEL    = net_type(u8) pxlen(u8) key
//	HELLO/EOR = header only
//	attr   = type(u8) len(u8) val[len]   (BLACKHOLE: len 0; EXTCOMM: len 8)
package birdfeed

import (
	"encoding/binary"
	"net/netip"
)

// Wire constants — keep in lockstep with bird proto/api/api.h.
const (
	wireVersion = 1
	hdrLen      = 8

	opAdd   = 1
	opDel   = 2
	opEOR   = 3
	opHello = 4

	// net_type values are BIRD's own (lib/net.h): NET_IP4/IP6/FLOW4/FLOW6.
	netIP4   = 1
	netIP6   = 2
	netFlow4 = 7
	netFlow6 = 8

	attrBlackhole = 1 // len 0 — RTD_BLACKHOLE (anchor advertisement carrier)
	attrExtComm   = 2 // len 8 — 8-byte ext-community (v4 flowspec redirect)
)

// frame prepends the 8-byte header (big-endian / network order, matching bird's
// get_u32) to body and returns the complete frame.
func frame(op uint8, body []byte) []byte {
	b := make([]byte, hdrLen+len(body))
	b[0] = wireVersion
	b[1] = op
	// b[2:4] flags = 0
	binary.BigEndian.PutUint32(b[4:8], uint32(len(b)))
	copy(b[hdrLen:], body)
	return b
}

// addrBytes returns the network-order address bytes (4 for v4, 16 for v6); the
// proto reads them with get_ip4/get_ip6, which are also network-order.
func addrBytes(a netip.Addr) []byte {
	if a.Is4() {
		x := a.As4()
		return x[:]
	}
	x := a.As16()
	return x[:]
}

func frameHello() []byte { return frame(opHello, nil) }
func frameEOR() []byte   { return frame(opEOR, nil) }

// frameAnchor encodes an anchor ADD/DEL: a unicast /32 (v4) or /128 (v6) carried
// as a BLACKHOLE route (advertisement carrier only). op is opAdd or opDel.
func frameAnchor(op uint8, p netip.Prefix) []byte {
	a := p.Addr()
	nt := byte(netIP4)
	if a.Is6() {
		nt = netIP6
	}
	key := addrBytes(a)
	body := make([]byte, 0, 2+len(key)+2)
	body = append(body, nt, byte(p.Bits()))
	body = append(body, key...)
	if op == opAdd {
		body = append(body, attrBlackhole, 0) // TLV: type, len=0
	}
	return frame(op, body)
}

// frameFlow encodes a flowspec ADD/DEL: a source-prefix flow4/flow6 NLRI; on ADD
// it carries the 8-byte redirect ext-community ec.
func frameFlow(op uint8, src netip.Prefix, ec [8]byte) []byte {
	a := src.Addr()
	nt := byte(netFlow4)
	if a.Is6() {
		nt = netFlow6
	}
	key := addrBytes(a)
	body := make([]byte, 0, 2+len(key)+10)
	body = append(body, nt, byte(src.Bits()))
	body = append(body, key...)
	if op == opAdd {
		body = append(body, attrExtComm, 8)
		body = append(body, ec[:]...)
	}
	return frame(op, body)
}

// redirectIP4EC encodes the standard redirect-to-IPv4 transitive ext-community
// (draft-ietf-idr-flowspec-redirect-ip: type 0x01 IPv4-Address-Specific, sub-type
// 0x0c) for the redirect target nextHop. The 8 bytes are
// [0x01, 0x0c, a, b, c, d, 0x00, 0x00] with a.b.c.d = nextHop, C=0 (redirect).
// Byte-identical to flowspec.redirectIP4ExtCommunity so vppfdp/R parse unchanged.
// nextHop must be IPv4 (caller validates).
func redirectIP4EC(nextHop netip.Addr) [8]byte {
	var ec [8]byte
	ec[0], ec[1] = 0x01, 0x0c
	b4 := nextHop.As4()
	copy(ec[2:6], b4[:])
	// ec[6], ec[7] = 0 (local-admin, C=0 = redirect not copy)
	return ec
}
