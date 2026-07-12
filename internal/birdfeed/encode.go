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
	"log/slog"
	"net/netip"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/redirectec"
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
	attrExtComm   = 2 // len 8 (v4 redirect EC) or 20 (v6 redirect i6ec)
	// attrCommunity / attrLargeCommunity carry an anchor's RTBH (or other)
	// communities (§6.56 — the api feed used to drop them: upstream received the
	// blackhole /32 as plain unicast and never dropped). Wire format matches
	// bird-vpp proto/api api.h API_ATTR_COMMUNITY/LARGECOMM:
	//   community:       n×4 bytes, each big-endian (u16 asn, u16 value)
	//   large community: n×12 bytes, each 3×u32 big-endian (global, d1, d2)
	attrCommunity      = 4
	attrLargeCommunity = 5
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
// as a BLACKHOLE route (advertisement carrier only). op is opAdd or opDel. attrs
// is the pre-encoded community TLV bytes (anchorAttrBytes; nil for a plain
// anchor) appended verbatim on ADD — DEL is keyed by prefix alone.
func frameAnchor(op uint8, p netip.Prefix, attrs []byte) []byte {
	a := p.Addr()
	nt := byte(netIP4)
	if a.Is6() {
		nt = netIP6
	}
	key := addrBytes(a)
	body := make([]byte, 0, 2+len(key)+2+len(attrs))
	body = append(body, nt, byte(p.Bits()))
	body = append(body, key...)
	if op == opAdd {
		body = append(body, attrBlackhole, 0) // TLV: type, len=0
		body = append(body, attrs...)
	}
	return frame(op, body)
}

// anchorAttrBytes encodes an anchor's communities as api-proto TLVs (empty for a
// plain anchor). The byte string doubles as the feed's diff signature: a
// community change re-announces the anchor (idempotent upsert in bird). A TLV
// length is a u8, capping one TLV at 63 standard / 21 large communities —
// anchors carry ~1 (RTBH), so truncate defensively rather than fail the feed.
// Truncation is NOT silent: dropping a policy/RTBH community without a trace could
// leave a blackhole silently un-dropped upstream, so it is logged at WARN.
func anchorAttrBytes(a model.Anchor, log *slog.Logger) []byte {
	if len(a.Communities) == 0 && len(a.LargeCommunities) == 0 {
		return nil
	}
	var out []byte
	if n := len(a.Communities); n > 0 {
		if n > 63 {
			if log != nil {
				log.Warn("birdfeed: anchor communities truncated to TLV cap — some dropped",
					"prefix", a.Prefix, "have", n, "cap", 63)
			}
			n = 63
		}
		out = append(out, attrCommunity, byte(n*4))
		for _, c := range a.Communities[:n] {
			out = append(out, byte(c.ASN>>8), byte(c.ASN), byte(c.Value>>8), byte(c.Value))
		}
	}
	if n := len(a.LargeCommunities); n > 0 {
		if n > 21 {
			if log != nil {
				log.Warn("birdfeed: anchor large-communities truncated to TLV cap — some dropped",
					"prefix", a.Prefix, "have", n, "cap", 21)
			}
			n = 21
		}
		out = append(out, attrLargeCommunity, byte(n*12))
		for _, lc := range a.LargeCommunities[:n] {
			for _, w := range [3]uint32{lc.GlobalAdmin, lc.LocalData1, lc.LocalData2} {
				out = append(out, byte(w>>24), byte(w>>16), byte(w>>8), byte(w))
			}
		}
	}
	return out
}

// frameFlow encodes a flowspec ADD/DEL: a source-prefix flow4/flow6 NLRI; on ADD
// it carries the redirect ext-community ec — 8 bytes (v4 redirect-to-IPv4) or 20
// bytes (v6 redirect-to-IPv6 i6ec). On DEL ec is ignored (the key identifies the
// route). The EXTCOMM TLV's own length byte tells bird's api proto which one it is
// (8 → bgp_ext_community, 20 → bgp_ipv6_ext_community).
func frameFlow(op uint8, src netip.Prefix, ec []byte) []byte {
	a := src.Addr()
	nt := byte(netFlow4)
	if a.Is6() {
		nt = netFlow6
	}
	key := addrBytes(a)
	body := make([]byte, 0, 2+len(key)+2+len(ec))
	body = append(body, nt, byte(src.Bits()))
	body = append(body, key...)
	if op == opAdd {
		body = append(body, attrExtComm, byte(len(ec)))
		body = append(body, ec...)
	}
	return frame(op, body)
}

// redirectIP4EC encodes the standard redirect-to-IPv4 transitive ext-community
// (draft-ietf-idr-flowspec-redirect-ip: type 0x01 IPv4-Address-Specific, sub-type
// 0x0c) for the redirect target nextHop. The 8 bytes are
// [0x01, 0x0c, a, b, c, d, 0x00, 0x00] with a.b.c.d = nextHop, C=0 (redirect).
// Byte-identical to flowspec.redirectIP4ExtCommunity so vppfdp/R parse unchanged.
// nextHop must be IPv4 (caller validates).
func redirectIP4EC(nextHop netip.Addr) [8]byte { return redirectec.IP4(nextHop) }

// redirectI6EC encodes the standard redirect-to-IPv6 transitive IPv6-Address-
// Specific ext-community (draft-ietf-idr-flowspec-redirect-ip: type/sub-type
// 0x000c, RFC 5701 20-byte form) for the redirect target nextHop6. The wire
// layout is the standard i6ec byte order — [type_subtype(2 BE), ipv6(16),
// local-admin(2 BE)] — with local-admin 0 (C=0 = redirect). Byte-identical to
// what flowspec.Render's `i6ec(0x000c, nextHop6, 0)` produces, so vppfdp/R parse
// it unchanged. nextHop6 must be IPv6 (caller validates).
func redirectI6EC(nextHop6 netip.Addr) [20]byte { return redirectec.I6(nextHop6) }
