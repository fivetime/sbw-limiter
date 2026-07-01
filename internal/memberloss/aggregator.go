// Package memberloss is the agent side of §4.2.5 per-member forwarding loss: it folds
// flowprobe IPFIX flow records into per-member, per-direction offered/delivered packet
// counts and, on snapshot, emits the compact model.MemberLoss vector the EdgeReport
// carries up (only members over a watermark). The SERVER holds the alert/migrate
// thresholds; the agent is a pure sensor.
//
// Measurement (design §4.2.2), keyed off flowprobe's flowDirection (rx/tx) + the
// observation interface:
//
//	toward member  (dst=member, ingress): offered = data0 RX,  delivered = macc TX
//	from   member  (src=member, egress):  offered = macc  RX,  delivered = data0 TX
//
// loss = (offered − delivered) / offered per (member,direction). The policer's
// intentional rate-limit drops (violate) must NOT count as loss — that hinges on the
// offered measurement sitting downstream of the policer (a feature-arc property
// verified lab-side); see DESIGN-liveness §4.2.2.
package memberloss

import (
	"net/netip"
	"sync"

	"github.com/fivetime/sbw-contract/model"

	"github.com/fivetime/sbw-limiter/internal/ipfix"
)

type key struct {
	member netip.Prefix
	dir    model.Direction
}

type counts struct{ offered, delivered uint64 }

// Aggregator accumulates flowprobe records into per-(member,direction) offered/
// delivered packet counts. Fold is called from the ipfix.Collector sink; Snapshot
// drains a delta window into the loss vector. Safe for concurrent Fold/Snapshot.
type Aggregator struct {
	mu       sync.Mutex
	acc      map[key]*counts
	members  map[netip.Addr]netip.Prefix // member host addr → its /32 or /128 prefix
	data0    uint32                      // mesh/fabric-side sw_if_index
	macc     uint32                      // member-side sw_if_index
	haveTopo bool
}

// New returns an empty aggregator (no topology yet — Fold is a no-op until
// SetTopology is called).
func New() *Aggregator {
	return &Aggregator{acc: map[key]*counts{}, members: map[netip.Addr]netip.Prefix{}}
}

// SetTopology updates the interface roles and the member set (call on reconcile / when
// the desired member set or resolved interface indices change). members are the /32,
// /128 host prefixes the edge homes; non-host prefixes are ignored.
func (a *Aggregator) SetTopology(data0, macc uint32, members []netip.Prefix) {
	m := make(map[netip.Addr]netip.Prefix, len(members))
	for _, p := range members {
		if p.IsSingleIP() { // /32 or /128 — a member host route
			m[p.Addr()] = p
		}
	}
	a.mu.Lock()
	a.data0, a.macc, a.members, a.haveTopo = data0, macc, m, true
	a.mu.Unlock()
}

// Fold accumulates a batch of decoded flow records (the collector sink).
func (a *Aggregator) Fold(recs []ipfix.Record) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.haveTopo {
		return
	}
	for _, r := range recs {
		a.foldOne(r)
	}
}

func (a *Aggregator) foldOne(r ipfix.Record) {
	pkts, ok := r.Uint(ipfix.IEPacketDeltaCount)
	if !ok || pkts == 0 {
		return
	}
	fdir, ok := r.Uint(ipfix.IEFlowDirection)
	if !ok {
		return // without the observation direction the record can't be placed
	}
	obsIf, ok := obsInterface(r, fdir)
	if !ok {
		return
	}
	src := recAddr(r, ipfix.IESrcIPv4, ipfix.IESrcIPv6)
	dst := recAddr(r, ipfix.IEDstIPv4, ipfix.IEDstIPv6)

	// toward member (dst is a member): offered=data0 RX, delivered=macc TX.
	if mp, ok := a.members[dst]; ok {
		switch {
		case fdir == ipfix.FlowRx && obsIf == a.data0:
			a.at(mp, model.DirectionIngress).offered += pkts
		case fdir == ipfix.FlowTx && obsIf == a.macc:
			a.at(mp, model.DirectionIngress).delivered += pkts
		}
	}
	// from member (src is a member): offered=macc RX, delivered=data0 TX.
	if mp, ok := a.members[src]; ok {
		switch {
		case fdir == ipfix.FlowRx && obsIf == a.macc:
			a.at(mp, model.DirectionEgress).offered += pkts
		case fdir == ipfix.FlowTx && obsIf == a.data0:
			a.at(mp, model.DirectionEgress).delivered += pkts
		}
	}
}

func (a *Aggregator) at(member netip.Prefix, dir model.Direction) *counts {
	k := key{member, dir}
	c := a.acc[k]
	if c == nil {
		c = &counts{}
		a.acc[k] = c
	}
	return c
}

// Snapshot computes the loss vector for the accumulated window and RESETS it (delta
// windowing aligns with the report interval). Only members whose loss is at/above
// watermarkBps (basis points) are emitted; a member with no offered traffic is omitted
// (loss is undefined, not zero). TopDropReason is left empty here — the caller attaches
// the node-level dominant reason (GetErrorStats) since VPP drop causes are not
// per-member.
func (a *Aggregator) Snapshot(watermarkBps uint16) []model.MemberLoss {
	a.mu.Lock()
	acc := a.acc
	a.acc = map[key]*counts{}
	a.mu.Unlock()

	var out []model.MemberLoss
	for k, c := range acc {
		if c.offered == 0 {
			continue // no offered traffic → loss undefined; don't report
		}
		lossBps := lossBasisPoints(c.offered, c.delivered)
		if lossBps < watermarkBps {
			continue
		}
		out = append(out, model.MemberLoss{Prefix: k.member, Dir: k.dir, LossBps: lossBps})
	}
	return out
}

// lossBasisPoints = clamp((offered − delivered) / offered) in basis points (0..10000).
// delivered > offered (reordering across the window boundary) clamps to 0.
func lossBasisPoints(offered, delivered uint64) uint16 {
	if delivered >= offered {
		return 0
	}
	bps := (offered - delivered) * 10000 / offered
	if bps > 10000 {
		bps = 10000
	}
	return uint16(bps)
}

// obsInterface is the interface flowprobe observed the flow on: the ingress interface
// for an rx record, the egress interface for a tx record.
func obsInterface(r ipfix.Record, fdir uint64) (uint32, bool) {
	ie := ipfix.IEIngressInterface
	if fdir == ipfix.FlowTx {
		ie = ipfix.IEEgressInterface
	}
	v, ok := r.Uint(uint16(ie))
	return uint32(v), ok
}

// recAddr reads the v4 IE, else the v6 IE, as a netip.Addr.
func recAddr(r ipfix.Record, v4ie, v6ie uint16) netip.Addr {
	if a, ok := r.Addr(v4ie); ok {
		return a
	}
	if a, ok := r.Addr(v6ie); ok {
		return a
	}
	return netip.Addr{}
}
