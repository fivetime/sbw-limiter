package agent

import (
	"log/slog"
	"net/netip"
	"sort"

	"github.com/fivetime/sbw-limiter/internal/vpp"
)

// MemberObserver reads the L's PHYSICAL member presence from VPP's ARP/ND neighbor
// table on the member interface(s) — the L's physical authority (DESIGN-liveness §11 /
// REFACTOR-coverer-liveness-only.md). Its Observe() feeds EdgeReport.ObservedMembers
// (which the server consumes for member-up/down + locality) and, later, the agent's
// own local anti-blackhole anchor gate ("防盲写黑洞": advertise only members the data
// plane can actually see).
//
// Like FaultSensor, it opens a short-lived, reply-timeout-bounded channel per call so a
// wedged/slow VPP main thread never blocks the report path (VPP single-main-thread
// bottleneck). Best-effort: any VPP error yields an empty set — the report just omits
// the field this pass; the server's fail-static "advertise" default is unaffected.
type MemberObserver struct {
	conn   *vpp.Conn
	ifaces []string // member-facing interface names (e.g. host-macc)
	log    *slog.Logger
}

// NewMemberObserver builds an observer over a live VPP connection scoped to the
// member-access interfaces. memberIfaces empty → Observe returns nil (disabled).
func NewMemberObserver(conn *vpp.Conn, memberIfaces []string, log *slog.Logger) *MemberObserver {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &MemberObserver{conn: conn, ifaces: memberIfaces, log: log}
}

// Observe dumps the neighbor table on the member interface(s) and returns the sorted,
// deduplicated set of physically-present member host prefixes (/32, /128).
func (o *MemberObserver) Observe() []netip.Prefix {
	if o == nil || o.conn == nil || len(o.ifaces) == 0 || !o.conn.Healthy() {
		return nil
	}
	ch, err := o.conn.Channel()
	if err != nil {
		o.log.Warn("member observe: vpp channel", "err", err)
		return nil
	}
	defer ch.Close()
	ch.SetReplyTimeout(dumpTimeout) // never block the report path on a wedged main thread

	// Resolve names → sw_if_index. IndexMap returns whatever resolved plus an error
	// naming the missing ones; use the resolved subset (a member iface may be absent
	// mid-reconfigure — skip it rather than fail the whole observation).
	idx, err := vpp.NewInterfaces(ch).IndexMap(o.ifaces...)
	if err != nil {
		o.log.Warn("member observe: interface resolve (using resolved subset)", "err", err)
	}

	nb := vpp.NewNeighbors(ch)
	seen := make(map[netip.Prefix]struct{})
	var out []netip.Prefix
	for _, name := range o.ifaces {
		sw, ok := idx[name]
		if !ok {
			continue
		}
		hosts, err := nb.DumpHosts(sw)
		if err != nil {
			o.log.Warn("member observe: neighbor dump", "iface", name, "err", err)
			continue
		}
		for _, h := range hosts {
			if _, dup := seen[h]; dup {
				continue
			}
			seen[h] = struct{}{}
			out = append(out, h)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
