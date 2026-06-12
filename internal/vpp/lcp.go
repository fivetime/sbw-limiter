package vpp

import (
	"fmt"

	govppapi "go.fd.io/govpp/api"

	"github.com/fivetime/sbw-limiter/internal/binapi/interface_types"
	"github.com/fivetime/sbw-limiter/internal/binapi/lcp"
)

// LcpPairs manages linux-cp interface pairs (T-410, DESIGN.md §5.1): a VPP
// interface is mirrored to a tap in a Linux netns. BIRD runs in that netns and
// writes the routing table to the Linux RIB; linux-cp's netlink listener
// mirrors it into the VPP FIB. The pair is the bridge that makes "BIRD 永不
// 编程数据平面" work — BIRD writes Linux, linux-cp programs VPP.
type LcpPairs struct {
	ch govppapi.Channel
}

// NewLcpPairs wraps a channel for lcp pair operations.
func NewLcpPairs(ch govppapi.Channel) *LcpPairs { return &LcpPairs{ch: ch} }

// Create pairs a VPP interface with a host tap named hostIfName in netns
// (empty netns = the linux-cp default namespace). The host side is a TAP so the
// full Ethernet/IP frame is mirrored.
func (l *LcpPairs) Create(swIfIndex uint32, hostIfName, netns string) error {
	if hostIfName == "" {
		return fmt.Errorf("vpp: lcp pair requires a host interface name")
	}
	req := &lcp.LcpItfPairAddDelV3{
		IsAdd:      true,
		SwIfIndex:  interface_types.InterfaceIndex(swIfIndex),
		HostIfName: hostIfName,
		HostIfType: lcp.LCP_API_ITF_HOST_TAP,
		Netns:      netns,
	}
	reply := &lcp.LcpItfPairAddDelV3Reply{}
	if err := l.ch.SendRequest(req).ReceiveReply(reply); err != nil {
		return fmt.Errorf("vpp: lcp_itf_pair_add_del_v3 add (if=%d host=%s): %w", swIfIndex, hostIfName, err)
	}
	if reply.Retval != 0 {
		return fmt.Errorf("vpp: lcp pair add (if=%d host=%s) failed: retval %d", swIfIndex, hostIfName, reply.Retval)
	}
	return nil
}

// Delete removes the lcp pair for a VPP interface.
func (l *LcpPairs) Delete(swIfIndex uint32) error {
	req := &lcp.LcpItfPairAddDelV3{IsAdd: false, SwIfIndex: interface_types.InterfaceIndex(swIfIndex)}
	reply := &lcp.LcpItfPairAddDelV3Reply{}
	if err := l.ch.SendRequest(req).ReceiveReply(reply); err != nil {
		return fmt.Errorf("vpp: lcp_itf_pair_add_del_v3 del (if=%d): %w", swIfIndex, err)
	}
	if reply.Retval != 0 {
		return fmt.Errorf("vpp: lcp pair del (if=%d) failed: retval %d", swIfIndex, reply.Retval)
	}
	return nil
}
