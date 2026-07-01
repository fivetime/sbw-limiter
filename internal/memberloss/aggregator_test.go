package memberloss

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/fivetime/sbw-contract/model"

	"github.com/fivetime/sbw-limiter/internal/ipfix"
)

const (
	data0 = uint32(1)
	macc  = uint32(2)
)

func u64b(v uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, v); return b }
func u32b(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
func v4b(s string) []byte  { a := netip.MustParseAddr(s).As4(); return a[:] }

// rec builds a flow record: dir (FlowRx/FlowTx), the observation interface, the address
// IE (IESrcIPv4 or IEDstIPv4) → addr, and a packet count.
func rec(dir uint64, obsIf uint32, addrIE uint16, addr string, pkts uint64) ipfix.Record {
	f := map[uint16][]byte{
		ipfix.IEFlowDirection:    {byte(dir)},
		ipfix.IEPacketDeltaCount: u64b(pkts),
		addrIE:                   v4b(addr),
	}
	if dir == ipfix.FlowRx {
		f[ipfix.IEIngressInterface] = u32b(obsIf)
	} else {
		f[ipfix.IEEgressInterface] = u32b(obsIf)
	}
	return ipfix.Record{Fields: f}
}

func find(v []model.MemberLoss, member string, dir model.Direction) (model.MemberLoss, bool) {
	p := netip.MustParsePrefix(member)
	for _, m := range v {
		if m.Prefix == p && m.Dir == dir {
			return m, true
		}
	}
	return model.MemberLoss{}, false
}

func TestDownstreamLoss(t *testing.T) {
	a := New()
	a.SetTopology(data0, macc, []netip.Prefix{netip.MustParsePrefix("172.16.0.5/32")})
	// toward member: offered = data0 RX (1000), delivered = macc TX (900) → 10% loss.
	a.Fold([]ipfix.Record{
		rec(ipfix.FlowRx, data0, ipfix.IEDstIPv4, "172.16.0.5", 1000),
		rec(ipfix.FlowTx, macc, ipfix.IEDstIPv4, "172.16.0.5", 900),
	})
	got := a.Snapshot(0)
	m, ok := find(got, "172.16.0.5/32", model.DirectionIngress)
	if !ok {
		t.Fatalf("no ingress loss for member; got %+v", got)
	}
	if m.LossBps != 1000 {
		t.Fatalf("loss = %d bps, want 1000 (10%%)", m.LossBps)
	}
}

func TestUpstreamNoLossOmittedByWatermark(t *testing.T) {
	a := New()
	a.SetTopology(data0, macc, []netip.Prefix{netip.MustParsePrefix("172.16.0.5/32")})
	// from member: offered = macc RX (500), delivered = data0 TX (500) → 0% loss.
	a.Fold([]ipfix.Record{
		rec(ipfix.FlowRx, macc, ipfix.IESrcIPv4, "172.16.0.5", 500),
		rec(ipfix.FlowTx, data0, ipfix.IESrcIPv4, "172.16.0.5", 500),
	})
	if got := a.Snapshot(100); len(got) != 0 {
		t.Fatalf("0%% loss under watermark must be omitted, got %+v", got)
	}
}

func TestSnapshotResetsWindow(t *testing.T) {
	a := New()
	a.SetTopology(data0, macc, []netip.Prefix{netip.MustParsePrefix("172.16.0.5/32")})
	a.Fold([]ipfix.Record{
		rec(ipfix.FlowRx, data0, ipfix.IEDstIPv4, "172.16.0.5", 1000),
		rec(ipfix.FlowTx, macc, ipfix.IEDstIPv4, "172.16.0.5", 500),
	})
	if got := a.Snapshot(0); len(got) != 1 || got[0].LossBps != 5000 {
		t.Fatalf("first window: %+v", got)
	}
	// A fresh window with no traffic → nothing (counts were reset).
	if got := a.Snapshot(0); len(got) != 0 {
		t.Fatalf("window must reset after snapshot, got %+v", got)
	}
}

func TestNonMemberAndNoTopoIgnored(t *testing.T) {
	a := New()
	// No topology yet → Fold is a no-op.
	a.Fold([]ipfix.Record{rec(ipfix.FlowRx, data0, ipfix.IEDstIPv4, "172.16.0.5", 1000)})
	if got := a.Snapshot(0); len(got) != 0 {
		t.Fatalf("fold before topology must be ignored, got %+v", got)
	}
	a.SetTopology(data0, macc, []netip.Prefix{netip.MustParsePrefix("172.16.0.5/32")})
	// A flow to a NON-member destination is ignored.
	a.Fold([]ipfix.Record{
		rec(ipfix.FlowRx, data0, ipfix.IEDstIPv4, "10.0.0.9", 1000),
		rec(ipfix.FlowTx, macc, ipfix.IEDstIPv4, "10.0.0.9", 100),
	})
	if got := a.Snapshot(0); len(got) != 0 {
		t.Fatalf("non-member traffic must be ignored, got %+v", got)
	}
}

func TestWrongInterfaceNotCounted(t *testing.T) {
	a := New()
	a.SetTopology(data0, macc, []netip.Prefix{netip.MustParsePrefix("172.16.0.5/32")})
	// Downstream offered must be data0 RX; a macc RX toward the member is the wrong
	// observation point and must not become "offered" (that's the upstream point).
	a.Fold([]ipfix.Record{
		rec(ipfix.FlowRx, macc, ipfix.IEDstIPv4, "172.16.0.5", 1000), // wrong iface for ingress-offered
		rec(ipfix.FlowTx, macc, ipfix.IEDstIPv4, "172.16.0.5", 100),  // delivered
	})
	// offered stayed 0 → loss undefined → omitted.
	if got := a.Snapshot(0); len(got) != 0 {
		t.Fatalf("mismatched observation interface must not count as offered, got %+v", got)
	}
}

func TestLossBasisPointsClamp(t *testing.T) {
	if got := lossBasisPoints(1000, 1200); got != 0 {
		t.Fatalf("delivered>offered must clamp to 0, got %d", got)
	}
	if got := lossBasisPoints(1000, 0); got != 10000 {
		t.Fatalf("total loss = %d, want 10000", got)
	}
	if got := lossBasisPoints(3, 1); got != 6666 {
		t.Fatalf("2/3 loss = %d, want 6666", got)
	}
}
