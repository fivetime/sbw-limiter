package agent

import (
	"log/slog"
	"net/netip"
	"sort"
	"sync"

	"github.com/fivetime/sbw-limiter/internal/vpp"
)

// MemberObserver reads member presence from VPP's ARP/ND neighbor table on the member
// interface(s) and caches it for the reporter: Observe() refreshes the cache, Latest()
// exposes it, and it is wired to EdgeReport.ObservedMembers (the server's member-up/down
// signal). It is NOT an anchor-advertisement gate — that gate ("physical gate") is gone;
// anchors now flow desired→bird unconditionally.
//
// PENDING (do not treat as settled): this reads member liveness off the SAME host-macc
// ARP/ND basis as the removed physical gate, which only reflects members that happen to be
// L2-adjacent to this L — a lab-topology accident, not the production path (members arrive
// via fabric→R→L over BGP and are never on L's neighbor segment). So this ObservedMembers
// source is itself owed a rework onto a forwarding/FIB-reachability basis (DESIGN-liveness
// §10); it is kept only because member-up/down has no replacement signal yet.
//
// Like FaultSensor, it opens a short-lived, reply-timeout-bounded channel per call so a
// wedged/slow VPP main thread never blocks the report path (VPP single-main-thread
// bottleneck). Best-effort: any VPP error yields nil ("no trustworthy read") — the report
// omits the field; the last GOOD read stays cached.
type MemberObserver struct {
	conn   *vpp.Conn
	ifaces []string // member-facing interface names (e.g. host-macc)
	log    *slog.Logger

	mu   sync.Mutex
	last []netip.Prefix // most recent TRUSTWORTHY observation (nil until first success)
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
//
// Return-value contract (the server relies on this to distinguish "nothing there" from
// "couldn't look"):
//   - nil        → NO trustworthy observation this pass (disabled / VPP unhealthy /
//     channel or dump error / an interface not resolvable). The server SKIPS — it must
//     never reap a member on an uncertain read (fail-safe).
//   - non-nil    → a CLEAN, complete observation: exactly the members physically present.
//     An empty (but non-nil) slice means "looked, found none" → the server reaps absent
//     members (member-down). This is why the EmptyIfClean init below is non-nil.
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

	// All member interfaces must resolve for a TRUSTWORTHY pass; a missing one (VPP
	// mid-reconfigure) makes the observation incomplete → skip rather than falsely report
	// a smaller set that would reap live members.
	idx, err := vpp.NewInterfaces(ch).IndexMap(o.ifaces...)
	if err != nil {
		o.log.Warn("member observe: interface resolve incomplete; skipping pass", "err", err)
		return nil
	}

	nb := vpp.NewNeighbors(ch)
	seen := make(map[netip.Prefix]struct{})
	out := make([]netip.Prefix, 0) // NON-nil: a clean dump with zero neighbors = "none present"
	for _, name := range o.ifaces {
		sw, ok := idx[name]
		if !ok {
			return nil // defensive (IndexMap already errored above) — incomplete, skip
		}
		hosts, err := nb.DumpHosts(sw)
		if err != nil {
			o.log.Warn("member observe: neighbor dump; skipping pass", "iface", name, "err", err)
			return nil // a dump error makes the pass incomplete → skip (never reap on error)
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
	// Cache this TRUSTWORTHY read (out is non-nil here) so the reporter can read it via
	// Latest() without a second VPP dump. Untrustworthy passes returned nil above and never
	// reach here, so the cache always holds the last GOOD physical set.
	f := make([]netip.Prefix, len(out))
	copy(f, out)
	o.mu.Lock()
	o.last = f
	o.mu.Unlock()
	return out
}

// Latest returns the most recent TRUSTWORTHY observation (a copy), or nil if none has
// succeeded yet. The reporter reads it to fill EdgeReport.ObservedMembers, sharing the
// periodic dump rather than issuing its own. (nil ⇒ the report omits the field.)
func (o *MemberObserver) Latest() []netip.Prefix {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.last == nil {
		return nil
	}
	f := make([]netip.Prefix, len(o.last))
	copy(f, o.last)
	return f
}
