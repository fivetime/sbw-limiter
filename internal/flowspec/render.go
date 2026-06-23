// Package flowspec renders the agent-managed BIRD include that originates the
// home edge's egress-homing FlowSpec (B-01, limiter §3.2): for each home member
// source prefix, a flow4/flow6 route carrying a redirect-to-IP ext-community
// pointing at this edge. The include is exported (by the L→R BGP
// session, export filter) to every R, which materializes it as a VPP ABF
// redirect (project A). This replaces the old L-side ABF (S-02).
//
// Rendering is a pure, deterministic function of (redirects, nextHop): the
// source set is validated, deduped and sorted, so equal inputs produce byte-
// identical output. The reload flow skips no-op reconfigures on that basis and
// BIRD's static reconfigure diffs the sorted set efficiently.
//
// Both protocol blocks (flowspec4 / flowspec6) are always emitted — even empty —
// so the names referenced by the L→R export filter exist unconditionally (mirrors
// anchors §4.4).
//
// Both families use the redirect-to-IP action of draft-ietf-idr-flowspec-redirect-ip
// (IESG-approved / RFC Editor queue; IANA-allocated; the FlowSpec framework itself
// is RFC 8955/8956 but those do NOT define redirect-to-IP). A v4 source carries an
// IPv4-Address-Specific EC (type 0x01 sub 0x0c, target in the 8-byte EC); a v6 source
// carries an IPv6-Address-Specific EC (0x000c, 20-byte, target in the IPv6 global-
// admin field), since no 8-byte EC can hold a v6 address.
package flowspec

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/fivetime/sbw-contract/model"
)

// Protocol4 is the static protocol name owning the v4 FlowSpec include. The
// L→R export filter references it by name; do not change without changing
// bird.conf in lockstep.
const Protocol4 = "flowspec4"

// Table4 is the BIRD flow4 table the FlowSpec is injected into; the L→R BGP
// session's flow4 channel exports from it. Matches the bird-vpp deploy examples.
const Table4 = "flowtab4"

// Protocol6 / Table6 are the v6 analogs (flow6 table flowtab6), referenced by the
// L→R flow6 channel's export filter; keep in lockstep with bird.conf.
const Protocol6 = "flowspec6"
const Table6 = "flowtab6"

// redirectI6ECTypeSubtype is the standard redirect-to-IPv6 codepoint from
// draft-ietf-idr-flowspec-redirect-ip (IESG-approved, in the RFC Editor queue;
// IANA-allocated): transitive IPv6-address-specific EC type 0x00 (RFC 5701) +
// sub-type 0x0c → the 2-byte type/subtype 0x000c. The 16-byte global-admin is the
// redirect target IPv6; local-admin is 0 here (C=0 = redirect, not copy). The
// codepoint lives at the originator (here) and the consumer (vppfdp), NOT in BIRD
// core — BIRD's RFC 5701 EC support is generic and application-agnostic. (The
// FlowSpec framework itself is RFC 8955/8956; redirect-to-IP is the one action
// those RFCs do NOT define — only this draft does.)
const redirectI6ECTypeSubtype = 0x000c

const header = `# Managed by sbw-limiter edge-agent — DO NOT EDIT (rendered, B-01).
# Egress-homing FlowSpec (limiter §3.2): "source ∈ home member → redirect to
# this edge". Exported to all R (export filter), never to fabric (export none).
# Reloaded via: atomic rename + configure check + configure (§4.4).
`

// Render produces the FlowSpec include for the given home member source
// prefixes: v4 sources redirected to nextHop, v6 sources to nextHop6 (this edge's
// own v4 / v6 addresses). It rejects invalid / non-canonical sources, a missing-
// or-wrong-family next-hop when that family's sources are present, and duplicates
// — the desired state must already be clean, and a broken include would fail the
// whole configure (§4.4). Both protocol blocks are always emitted (even empty).
func Render(redirects []model.FlowRedirect, nextHop, nextHop6 netip.Addr) ([]byte, error) {
	v4, err := collectSrcs(redirects, false)
	if err != nil {
		return nil, err
	}
	v6, err := collectSrcs(redirects, true)
	if err != nil {
		return nil, err
	}
	if len(v4) > 0 && !nextHop.Is4() {
		return nil, fmt.Errorf("flowspec: v4 redirect next-hop %s must be a valid IPv4 address", nextHop)
	}
	if len(v6) > 0 && !nextHop6.Is6() {
		return nil, fmt.Errorf("flowspec: v6 redirect next-hop %s must be a valid IPv6 address", nextHop6)
	}

	var b strings.Builder
	b.WriteString(header)

	// flowspec4: redirect-to-IPv4 ext-community (draft-ietf-idr-flowspec-redirect-ip;
	// shared next-hop, computed once). Always emitted so the L→R export filter exists.
	var hi, lo uint32
	if len(v4) > 0 {
		hi, lo = redirectIP4ExtCommunity(nextHop)
	}
	fmt.Fprintf(&b, "protocol static %s {\n", Protocol4)
	fmt.Fprintf(&b, "  flow4 { table %s; };\n", Table4)
	for _, p := range v4 {
		fmt.Fprintf(&b, "  route flow4 { src %s; } {\n", p)
		fmt.Fprintf(&b, "    bgp_ext_community.add((generic, 0x%08x, 0x%08x));\n", hi, lo)
		b.WriteString("  };\n")
	}
	b.WriteString("}\n")

	// flowspec6: redirect-to-IPv6 EC (draft-ietf-idr-flowspec-redirect-ip, 0x000c;
	// the target IPv6 in the global-admin field). Always emitted.
	fmt.Fprintf(&b, "protocol static %s {\n", Protocol6)
	fmt.Fprintf(&b, "  flow6 { table %s; };\n", Table6)
	for _, p := range v6 {
		fmt.Fprintf(&b, "  route flow6 { src %s; } {\n", p)
		fmt.Fprintf(&b, "    bgp_ipv6_ext_community.add(i6ec(0x%04x, %s, 0));\n", redirectI6ECTypeSubtype, nextHop6)
		b.WriteString("  };\n")
	}
	b.WriteString("}\n")

	return []byte(b.String()), nil
}

// collectSrcs validates, dedups and sorts the source prefixes of one family
// (v6 if wantV6 else v4) from the redirect set.
func collectSrcs(redirects []model.FlowRedirect, wantV6 bool) ([]netip.Prefix, error) {
	srcs := make([]netip.Prefix, 0, len(redirects))
	seen := make(map[netip.Prefix]struct{}, len(redirects))
	for i, r := range redirects {
		if r.SrcPrefix.Addr().Is6() != wantV6 {
			continue
		}
		if err := r.Validate(); err != nil {
			return nil, fmt.Errorf("flowspec: redirect[%d]: %w", i, err)
		}
		p := r.SrcPrefix
		if _, dup := seen[p]; dup {
			return nil, fmt.Errorf("flowspec: duplicate source prefix %s", p)
		}
		seen[p] = struct{}{}
		srcs = append(srcs, p)
	}
	sort.Slice(srcs, func(i, j int) bool {
		if c := srcs[i].Addr().Compare(srcs[j].Addr()); c != 0 {
			return c < 0
		}
		return srcs[i].Bits() < srcs[j].Bits()
	})
	return srcs, nil
}

// redirectIP4ExtCommunity encodes the standard redirect-to-IPv4 transitive
// ext-community from draft-ietf-idr-flowspec-redirect-ip (type 0x01 IPv4-Address-
// Specific, sub-type 0x0c) for nextHop into its two 32-bit halves, as BIRD's
// `(generic, hi, lo)` form. The 8 bytes are [0x01, 0x0c, a, b, c, d, 0x00, 0x00]
// where a.b.c.d = nextHop (global-admin) and the trailing 0x0000 is the local-admin
// with C=0 (redirect, not copy). vppfdp consumes exactly this: e.g. 10.0.0.5 →
// 0x010c0a00, 0x00050000. NOT RFC 8955's rt-redirect (sub 0x08 → redirect-to-VRF),
// which is a different action. nextHop must be IPv4 (callers validate).
func redirectIP4ExtCommunity(nextHop netip.Addr) (hi, lo uint32) {
	b4 := nextHop.As4()
	ip := binary.BigEndian.Uint32(b4[:])
	hi = 0x010c0000 | (ip >> 16)
	lo = (ip & 0xffff) << 16
	return hi, lo
}
