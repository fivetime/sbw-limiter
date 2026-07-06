package vpp

import (
	"fmt"
	"net/netip"

	govppapi "go.fd.io/govpp/api"

	"github.com/fivetime/sbw-limiter/internal/binapi/interface_types"
	ipn "github.com/fivetime/sbw-limiter/internal/binapi/ip_neighbor"
	"github.com/fivetime/sbw-limiter/internal/binapi/ip_types"
)

// Neighbors reads VPP's ARP/ND neighbor table — the L's PHYSICAL authority on
// which member hosts are actually present on its member interface (DESIGN-liveness
// §11 / REFACTOR-coverer-liveness-only.md). The agent turns the live neighbor set
// into EdgeReport.ObservedMembers (the physical-presence signal the server consumes
// for member-up/down + locality) and gates anchor advertisement locally on it
// ("防盲写黑洞": advertise only members the data plane can actually see).
//
// Co-located with VPP over the same binary-API channel the policer/classify
// materializers use — no BGP round-trip, no coverer tap: a directly-connected host
// that answers ARP/ND has a resolved neighbor entry; a dead/absent host does not.
type Neighbors struct {
	ch govppapi.Channel
}

// NewNeighbors wraps a channel for neighbor-table dumps.
func NewNeighbors(ch govppapi.Channel) *Neighbors { return &Neighbors{ch: ch} }

// DumpHosts returns the host prefixes (/32, /128) of every neighbor VPP currently
// has resolved on swIfIndex, across BOTH address families. A resolved neighbor =
// the host answered ARP/ND = physically present. VPP filters ip_neighbor_dump by
// address family, so both families are dumped and merged.
func (n *Neighbors) DumpHosts(swIfIndex uint32) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, af := range []ip_types.AddressFamily{ip_types.ADDRESS_IP4, ip_types.ADDRESS_IP6} {
		reqCtx := n.ch.SendMultiRequest(&ipn.IPNeighborDump{
			SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
			Af:        af,
		})
		for {
			d := &ipn.IPNeighborDetails{}
			stop, err := reqCtx.ReceiveReply(d)
			if err != nil {
				return nil, fmt.Errorf("vpp: ip_neighbor_dump(af=%d): %w", af, err)
			}
			if stop {
				break
			}
			addr, ok := netip.AddrFromSlice(d.Neighbor.IPAddress.ToIP())
			if !ok {
				continue
			}
			addr = addr.Unmap() // ToIP() already narrows v4 to 4 bytes; belt-and-suspenders
			// Skip link-local (fe80::/10, 169.254/16): a member advertises its ROUTABLE
			// address; its link-local is ND/RA noise that never matches a pool member's
			// anchor and would pollute EdgeReport.ObservedMembers.
			if addr.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	return out, nil
}
