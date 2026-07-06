package birdfeed

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/fivetime/sbw-contract/model"
)

// Provider yields the latest desired state; ok=false means nothing authoritative
// yet (cold start) and the pass is skipped (fail-static, mirrors BirdApplier).
type Provider func() (model.EdgeDesiredState, bool)

// sink is the transport the Feed writes frames to (Client in prod, fake in tests).
type sink interface {
	connected() bool
	connect() error
	write(frame []byte)
	flush() error
	close()
}

// Feed streams the control-plane half of the desired state (member anchors +
// egress-homing flowspec) to bird's `api` proto incrementally: a per-pass diff
// against the last-fed snapshot emits only ADD/DEL; a (re)connect (or a redirect
// next-hop change) does a full HELLO + all + EOR resync, and the proto's
// refresh-cycle reconciles + prunes any stale routes. Replaces BirdApplier's
// full-file render + `birdc configure` (DESIGN-bird-api.md).
type Feed struct {
	client sink
	path   string
	log    *slog.Logger
	wake   chan struct{}

	// observed, if set, is the local physical anti-blackhole gate (防盲写黑洞,
	// REFACTOR step 5): the agent's most recent TRUSTWORTHY VPP ARP/ND observation
	// (MemberObserver.Latest). A HOST member's /32//128 anchor is fed only if that
	// member is physically present in this set (intent ∧ physical, both local to the
	// agent). nil, or a nil return, ⇒ no gating (fail-static: advertise all — never
	// blackhole a live member because its physical set couldn't be read).
	observed func() []netip.Prefix

	// snapshot of what is currently fed, for diffing.
	anchors  map[netip.Prefix]struct{}
	flows    map[netip.Prefix]struct{} // both families; EC chosen per-prefix family
	nextHop  netip.Addr                // v4 redirect target (for the 8-byte EC)
	nextHop6 netip.Addr                // v6 redirect target (for the 20-byte i6ec)
	resync   bool
}

// WithObserved wires the local physical-presence gate (REFACTOR step 5): fn returns the
// agent's most recent trustworthy VPP ARP/ND member set (MemberObserver.Latest). Anchors
// for physically-absent HOST members are withheld. nil disables the gate (advertise all).
func (f *Feed) WithObserved(fn func() []netip.Prefix) *Feed { f.observed = fn; return f }

// NewFeed wires a Feed over a fresh Client for the api socket path.
func NewFeed(path string, log *slog.Logger) *Feed {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Feed{
		client:  NewClient(path),
		path:    path,
		log:     log,
		wake:    make(chan struct{}, 1),
		anchors: map[netip.Prefix]struct{}{},
		flows:   map[netip.Prefix]struct{}{},
		resync:  true,
	}
}

// Wake requests an immediate feed pass (coalescing, non-blocking).
func (f *Feed) Wake() {
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

// Run feeds on a timer and on Wake until ctx is cancelled, pulling state from
// provider (ok=false skips — fail-static). Blocks; run in a goroutine.
func (f *Feed) Run(ctx context.Context, interval time.Duration, provider Provider) {
	t := time.NewTicker(interval)
	defer t.Stop()
	f.pass(provider)
	for {
		select {
		case <-ctx.Done():
			f.client.close()
			f.log.Info("bird feed loop stopped")
			return
		case <-t.C:
			f.pass(provider)
		case <-f.wake:
			f.pass(provider)
		}
	}
}

func (f *Feed) pass(provider Provider) {
	st, ok := provider()
	if !ok {
		return
	}
	_ = f.apply(st)
}

func (f *Feed) apply(st model.EdgeDesiredState) error {
	if !f.client.connected() {
		if err := f.client.connect(); err != nil {
			f.log.Warn("bird feed: connect failed", "socket", f.path, "err", err)
			return err
		}
		f.log.Info("bird feed: connected", "socket", f.path)
		f.resync = true
	}

	// Desired sets. Anchors (v4+v6) and flowspec (v4+v6) are all fed; the redirect
	// EC is chosen per source-prefix family — 8-byte redirect-to-IPv4 for a v4
	// source, 20-byte redirect-to-IPv6 i6ec for a v6 source (DESIGN-bird-api §3.3).
	desA := make(map[netip.Prefix]struct{}, len(st.Anchors))
	for _, a := range st.Anchors {
		desA[a.Prefix] = struct{}{}
	}
	// Local physical anti-blackhole gate (REFACTOR step 5): withhold a HOST member's
	// anchor unless the agent physically observes that member (VPP ARP/ND). intent (the
	// desired anchor) ∧ physical (the observation) — both local to the agent, no coverer
	// tap round-trip. Fail-static: a nil observation (never read / VPP unhealthy) gates
	// nothing (advertise all). Non-host anchors (a /24 bare-metal block) are not a
	// physical-presence signal → never gated (mirrors the server's shouldWithdraw). The
	// existing diff turns a withheld member into a DEL (withdraw) and a re-appeared one
	// into an ADD, so the gate self-heals as the physical set changes.
	if f.observed != nil {
		if obs := f.observed(); obs != nil {
			present := make(map[netip.Prefix]struct{}, len(obs))
			for _, p := range obs {
				present[p] = struct{}{}
			}
			withheld := 0
			var sample netip.Prefix
			for p := range desA {
				if model.IsHost(p) {
					if _, ok := present[p]; !ok {
						delete(desA, p)
						if withheld == 0 {
							sample = p
						}
						withheld++
					}
				}
			}
			if withheld > 0 {
				// Scale-safe: log counts + one sample, not the full sets (a member-scale
				// edge could withhold thousands — never dump them all).
				f.log.Info("anchor gate: withholding physically-absent members",
					"withheld", withheld, "sample", sample, "observed_count", len(present))
			}
		}
	}
	desF := make(map[netip.Prefix]struct{}, len(st.FlowRedirects))
	haveV4, haveV6 := false, false
	for _, r := range st.FlowRedirects {
		desF[r.SrcPrefix] = struct{}{}
		if r.SrcPrefix.Addr().Is6() {
			haveV6 = true
		} else {
			haveV4 = true
		}
	}

	// Per-family redirect ECs, validated fail-static (mirrors flowspec.Render): a
	// flow of a family requires that family's redirect next-hop.
	var ec4 [8]byte
	var ec6 [20]byte
	if haveV4 {
		if !st.RedirectNextHop.Is4() {
			err := fmt.Errorf("bird feed: v4 flowspec present but RedirectNextHop %s not v4", st.RedirectNextHop)
			f.log.Error(err.Error())
			return err
		}
		ec4 = redirectIP4EC(st.RedirectNextHop)
	}
	if haveV6 {
		if !st.RedirectNextHopV6.Is6() {
			err := fmt.Errorf("bird feed: v6 flowspec present but RedirectNextHopV6 %s not v6", st.RedirectNextHopV6)
			f.log.Error(err.Error())
			return err
		}
		ec6 = redirectI6EC(st.RedirectNextHopV6)
	}
	ecFor := func(p netip.Prefix) []byte {
		if p.Addr().Is6() {
			return ec6[:]
		}
		return ec4[:]
	}

	// A change to EITHER redirect next-hop must re-announce every flow of that
	// family (the EC is an attribute, not part of the diff key), so resync on both.
	if f.resync || st.RedirectNextHop != f.nextHop || st.RedirectNextHopV6 != f.nextHop6 {
		f.fullResync(desA, desF, ecFor)
	} else {
		f.incremental(desA, desF, ecFor)
	}

	if err := f.client.flush(); err != nil {
		f.log.Warn("bird feed: flush failed, will reconnect + resync", "err", err)
		f.client.close()
		f.resync = true
		return err
	}
	// Commit the snapshot only after a clean flush.
	f.anchors, f.flows = desA, desF
	f.nextHop, f.nextHop6 = st.RedirectNextHop, st.RedirectNextHopV6
	return nil
}

// fullResync: HELLO + all current routes + EOR. The proto marks everything stale
// on HELLO, the re-announces clear it, EOR prunes whatever the agent dropped.
// ecFor picks the redirect EC for a flow by its source-prefix family.
func (f *Feed) fullResync(desA, desF map[netip.Prefix]struct{}, ecFor func(netip.Prefix) []byte) {
	f.client.write(frameHello())
	for p := range desA {
		f.client.write(frameAnchor(opAdd, p))
	}
	for p := range desF {
		f.client.write(frameFlow(opAdd, p, ecFor(p)))
	}
	f.client.write(frameEOR())
	f.resync = false
}

// incremental: only the diff vs the last-fed snapshot (O(delta) into bird).
func (f *Feed) incremental(desA, desF map[netip.Prefix]struct{}, ecFor func(netip.Prefix) []byte) {
	for p := range desA {
		if _, ok := f.anchors[p]; !ok {
			f.client.write(frameAnchor(opAdd, p))
		}
	}
	for p := range f.anchors {
		if _, ok := desA[p]; !ok {
			f.client.write(frameAnchor(opDel, p))
		}
	}
	for p := range desF {
		if _, ok := f.flows[p]; !ok {
			f.client.write(frameFlow(opAdd, p, ecFor(p)))
		}
	}
	for p := range f.flows {
		if _, ok := desF[p]; !ok {
			f.client.write(frameFlow(opDel, p, ecFor(p))) // ec ignored on DEL
		}
	}
}
