// Package flowspec renders the agent-managed BIRD include that originates the
// home edge's egress-homing FlowSpec (B-01, limiter §3.2): for each home member
// source prefix, a flow4 route carrying an RFC 8955 redirect-to-IPv4 ext-
// community pointing at this edge. The include is exported (by the L→R BGP
// session, export filter) to every R, which materializes it as a VPP ABF
// redirect (project A). This replaces the old L-side ABF (S-02).
//
// Rendering is a pure, deterministic function of (redirects, nextHop): the
// source set is validated, deduped and sorted, so equal inputs produce byte-
// identical output. The reload flow skips no-op reconfigures on that basis and
// BIRD's static reconfigure diffs the sorted set efficiently.
//
// The protocol block is always emitted — even empty — so the name referenced by
// the L→R export filter exists unconditionally (mirrors anchors §4.4).
//
// V1 is IPv4 only (redirect-to-IPv4, ext-community type 0x81 sub 0x08). IPv6
// FlowSpec redirect is a follow-up shared with project A (no 8-byte ext-
// community can carry a v6 next-hop).
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

const header = `# Managed by sbw-limiter edge-agent — DO NOT EDIT (rendered, B-01).
# Egress-homing FlowSpec (limiter §3.2): "source ∈ home member → redirect to
# this edge". Exported to all R (export filter), never to fabric (export none).
# Reloaded via: atomic rename + configure check + configure (§4.4).
`

// Render produces the FlowSpec include for the given home member source
// prefixes, all redirected to nextHop (this edge's own IPv4 address). It rejects
// invalid / non-canonical / non-IPv4 sources and a missing-or-non-v4 nextHop
// when sources are present: the desired state must already be clean, and a
// broken include would fail the whole configure (§4.4).
func Render(redirects []model.FlowRedirect, nextHop netip.Addr) ([]byte, error) {
	if len(redirects) > 0 {
		if !nextHop.IsValid() {
			return nil, fmt.Errorf("flowspec: redirect next-hop must be set when redirects present")
		}
		if !nextHop.Is4() {
			return nil, fmt.Errorf("flowspec: redirect next-hop %s must be IPv4 (V1 redirect-to-IPv4)", nextHop)
		}
	}

	srcs := make([]netip.Prefix, 0, len(redirects))
	seen := make(map[netip.Prefix]struct{}, len(redirects))
	for i, r := range redirects {
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

	// All of this edge's redirects share one next-hop; compute the ext-community
	// once. Skipped when there are no routes (nextHop may be unset then).
	var hi, lo uint32
	if len(srcs) > 0 {
		hi, lo = redirectIP4ExtCommunity(nextHop)
	}

	var b strings.Builder
	b.WriteString(header)
	fmt.Fprintf(&b, "protocol static %s {\n", Protocol4)
	fmt.Fprintf(&b, "  flow4 { table %s; };\n", Table4)
	for _, p := range srcs {
		fmt.Fprintf(&b, "  route flow4 { src %s; } {\n", p)
		fmt.Fprintf(&b, "    bgp_ext_community.add((generic, 0x%08x, 0x%08x));\n", hi, lo)
		b.WriteString("  };\n")
	}
	b.WriteString("}\n")
	return []byte(b.String()), nil
}

// redirectIP4ExtCommunity encodes an RFC 8955 redirect-to-IPv4 transitive
// ext-community (type 0x81, sub-type 0x08) for nextHop into its two 32-bit
// halves, as BIRD's `(generic, hi, lo)` form. The 8 bytes are
// [0x81, 0x08, a, b, c, d, 0x00, 0x00] where a.b.c.d = nextHop. project A's
// vppfdp parser consumes exactly this (A-05b): e.g. 10.0.0.5 → 0x81080a00,
// 0x00050000. nextHop must be IPv4 (callers validate).
func redirectIP4ExtCommunity(nextHop netip.Addr) (hi, lo uint32) {
	b4 := nextHop.As4()
	ip := binary.BigEndian.Uint32(b4[:])
	hi = 0x81080000 | (ip >> 16)
	lo = (ip & 0xffff) << 16
	return hi, lo
}
