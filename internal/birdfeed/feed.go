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

	// snapshot of what is currently fed, for diffing.
	anchors map[netip.Prefix]struct{}
	flows   map[netip.Prefix]struct{}
	nextHop netip.Addr
	resync  bool

	observers []func(model.EdgeDesiredState, error)
}

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

// AddObserver registers a callback invoked after each pass with the state it fed
// and any error (metrics / health), mirroring BirdApplier.AddObserver.
func (f *Feed) AddObserver(fn func(model.EdgeDesiredState, error)) {
	f.observers = append(f.observers, fn)
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
	err := f.apply(st)
	for _, fn := range f.observers {
		fn(st, err)
	}
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

	// Desired sets. v6 flowspec is deferred (needs the 20-byte i6ec EC on both
	// bird + here, see DESIGN-bird-api.md §3.3); v6 anchors are handled.
	desA := make(map[netip.Prefix]struct{}, len(st.Anchors))
	for _, a := range st.Anchors {
		desA[a.Prefix] = struct{}{}
	}
	desF := make(map[netip.Prefix]struct{}, len(st.FlowRedirects))
	for _, r := range st.FlowRedirects {
		if r.SrcPrefix.Addr().Is6() {
			continue
		}
		desF[r.SrcPrefix] = struct{}{}
	}

	var ec [8]byte
	if len(desF) > 0 {
		if !st.RedirectNextHop.Is4() {
			err := fmt.Errorf("bird feed: v4 flowspec present but RedirectNextHop %s not v4", st.RedirectNextHop)
			f.log.Error(err.Error())
			return err // fail-static: skip the whole pass (mirrors flowspec.Render strictness)
		}
		ec = redirectIP4EC(st.RedirectNextHop)
	}

	if f.resync || st.RedirectNextHop != f.nextHop {
		f.fullResync(desA, desF, ec)
	} else {
		f.incremental(desA, desF, ec)
	}

	if err := f.client.flush(); err != nil {
		f.log.Warn("bird feed: flush failed, will reconnect + resync", "err", err)
		f.client.close()
		f.resync = true
		return err
	}
	// Commit the snapshot only after a clean flush.
	f.anchors, f.flows, f.nextHop = desA, desF, st.RedirectNextHop
	return nil
}

// fullResync: HELLO + all current routes + EOR. The proto marks everything stale
// on HELLO, the re-announces clear it, EOR prunes whatever the agent dropped.
func (f *Feed) fullResync(desA, desF map[netip.Prefix]struct{}, ec [8]byte) {
	f.client.write(frameHello())
	for p := range desA {
		f.client.write(frameAnchor(opAdd, p))
	}
	for p := range desF {
		f.client.write(frameFlow(opAdd, p, ec))
	}
	f.client.write(frameEOR())
	f.resync = false
}

// incremental: only the diff vs the last-fed snapshot (O(delta) into bird).
func (f *Feed) incremental(desA, desF map[netip.Prefix]struct{}, ec [8]byte) {
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
			f.client.write(frameFlow(opAdd, p, ec))
		}
	}
	for p := range f.flows {
		if _, ok := desF[p]; !ok {
			f.client.write(frameFlow(opDel, p, ec)) // ec ignored on DEL
		}
	}
}
