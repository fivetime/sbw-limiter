package vpp

import (
	"fmt"
	"net/netip"

	govppapi "go.fd.io/govpp/api"

	"github.com/fivetime/sbw-limiter/internal/binapi/interface_types"
	ipn "github.com/fivetime/sbw-limiter/internal/binapi/ip_neighbor"
	"github.com/fivetime/sbw-limiter/internal/binapi/ip_types"
)

// Neighbors reads VPP's ARP/ND neighbor table on the member interface. The agent
// turns the live neighbor set into EdgeReport.ObservedMembers (the server's
// member-up/down signal). It does NOT gate anchor advertisement — that gate is gone.
//
// CAVEAT: a neighbor entry only exists for members L2-adjacent to this L, which is a
// lab-topology accident (in production members arrive via fabric→R→L over BGP and are
// never on L's neighbor segment). So this ObservedMembers basis is owed a rework onto
// forwarding/FIB reachability (DESIGN-liveness §10); see MemberObserver's doc.
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
		req := &ipn.IPNeighborDump{SwIfIndex: interface_types.InterfaceIndex(swIfIndex), Af: af}
		err := dumpAll(n.ch, fmt.Sprintf("ip_neighbor_dump(af=%d)", af), req, func(d *ipn.IPNeighborDetails) {
			addr, ok := netip.AddrFromSlice(d.Neighbor.IPAddress.ToIP())
			if !ok {
				return
			}
			addr = addr.Unmap() // ToIP() already narrows v4 to 4 bytes; belt-and-suspenders
			// Skip link-local (fe80::/10, 169.254/16): a member advertises its ROUTABLE
			// address; its link-local is ND/RA noise that never matches a pool member's
			// anchor and would pollute EdgeReport.ObservedMembers.
			if addr.IsLinkLocalUnicast() {
				return
			}
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
