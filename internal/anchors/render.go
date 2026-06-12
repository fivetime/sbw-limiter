// Package anchors renders the agent-managed BIRD include file (T-302,
// DESIGN.md §4.4): static blackhole routes used purely as BGP advertisement
// carriers, with optional per-route community attribute blocks (RTBH, canary).
//
// Rendering is a pure, deterministic function of the anchor set: anchors and
// their communities are sorted, so equal sets produce byte-identical output.
// The reload flow (T-303) relies on this to skip no-op reconfigures, and
// BIRD's static reconfigure diffs the sorted set efficiently.
//
// Both protocol blocks (anchors4 / anchors6) are always emitted — even empty —
// so the protocol names referenced by the kernel export filter (§4.2/§4.3) and
// by the leak check (§4.2-3) exist unconditionally.
package anchors

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/fivetime/sbw-contract/model"
)

// Protocol names fixed by DESIGN.md §4.3/§4.4. The kernel export filter
// rejects routes from these protocols by name; do not change without changing
// bird.conf in lockstep.
const (
	Protocol4 = "anchors4"
	Protocol6 = "anchors6"
)

const header = `# Managed by bwpool edge-agent — DO NOT EDIT (rendered, T-302).
# Anchors are BGP advertisement carriers only (DESIGN.md §4.4): blackhole
# statics that MUST NOT reach the kernel/VPP FIB (excluded by krt_export,
# §4.2). Reloaded via: atomic rename + configure check + configure (§4.4).
`

// Render produces the anchors include file for the given anchor set. It
// rejects invalid, non-canonical (host bits set), IPv4-mapped-IPv6, and
// duplicate prefixes: the desired state must already be clean, and a broken
// include would fail the whole configure (§4.4).
func Render(list []model.Anchor) ([]byte, error) {
	var v4, v6 []model.Anchor
	seen := make(map[netip.Prefix]struct{}, len(list))
	for i, a := range list {
		p := a.Prefix
		if !p.IsValid() {
			return nil, fmt.Errorf("anchors: anchor[%d]: invalid prefix", i)
		}
		if p.Addr().Is4In6() {
			return nil, fmt.Errorf("anchors: anchor[%d] %s: IPv4-mapped IPv6 prefix not allowed", i, p)
		}
		if p.Addr() != p.Masked().Addr() {
			return nil, fmt.Errorf("anchors: anchor[%d] %s: host bits set (non-canonical)", i, p)
		}
		if _, dup := seen[p]; dup {
			return nil, fmt.Errorf("anchors: duplicate anchor prefix %s", p)
		}
		seen[p] = struct{}{}
		if p.Addr().Is4() {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}

	sortAnchors(v4)
	sortAnchors(v6)

	var b strings.Builder
	b.WriteString(header)
	writeProtocol(&b, Protocol4, "ipv4", "master4", v4)
	b.WriteString("\n")
	writeProtocol(&b, Protocol6, "ipv6", "master6", v6)
	return []byte(b.String()), nil
}

func sortAnchors(list []model.Anchor) {
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i].Prefix, list[j].Prefix
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c < 0
		}
		return a.Bits() < b.Bits()
	})
}

func writeProtocol(b *strings.Builder, name, channel, table string, list []model.Anchor) {
	fmt.Fprintf(b, "protocol static %s {\n", name)
	fmt.Fprintf(b, "  %s { table %s; };\n", channel, table)
	for _, a := range list {
		writeRoute(b, a)
	}
	b.WriteString("}\n")
}

func writeRoute(b *strings.Builder, a model.Anchor) {
	if len(a.Communities) == 0 && len(a.LargeCommunities) == 0 {
		fmt.Fprintf(b, "  route %s blackhole;\n", a.Prefix)
		return
	}

	comms := append([]model.Community(nil), a.Communities...)
	sort.Slice(comms, func(i, j int) bool {
		if comms[i].ASN != comms[j].ASN {
			return comms[i].ASN < comms[j].ASN
		}
		return comms[i].Value < comms[j].Value
	})
	lcs := append([]model.LargeCommunity(nil), a.LargeCommunities...)
	sort.Slice(lcs, func(i, j int) bool {
		a, b := lcs[i], lcs[j]
		if a.GlobalAdmin != b.GlobalAdmin {
			return a.GlobalAdmin < b.GlobalAdmin
		}
		if a.LocalData1 != b.LocalData1 {
			return a.LocalData1 < b.LocalData1
		}
		return a.LocalData2 < b.LocalData2
	})

	fmt.Fprintf(b, "  route %s blackhole {\n", a.Prefix)
	for _, c := range comms {
		fmt.Fprintf(b, "    bgp_community.add((%d, %d));\n", c.ASN, c.Value)
	}
	for _, lc := range lcs {
		fmt.Fprintf(b, "    bgp_large_community.add((%d, %d, %d));\n", lc.GlobalAdmin, lc.LocalData1, lc.LocalData2)
	}
	b.WriteString("  };\n")
}
