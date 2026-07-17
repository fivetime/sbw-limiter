package birdfeed

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync/atomic"
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

	// snapshot of what is currently fed, for diffing. anchors maps each fed
	// prefix to its community-TLV bytes (anchorAttrBytes) — value change (e.g.
	// RTBH community edit) re-announces, since bird's ADD is an idempotent upsert.
	anchors  map[netip.Prefix][]byte
	flows    map[netip.Prefix]struct{} // both families; EC chosen per-prefix family
	nextHop  netip.Addr                // v4 redirect target (for the 8-byte EC)
	nextHop6 netip.Addr                // v6 redirect target (for the 20-byte i6ec)
	resync   bool

	// Pacing (opt-in via WithPacing): flush + yield every maxOps frames so bird-vpp's
	// vppfib drains between chunks instead of taking a whole (re)dump as one in-flight
	// burst. maxOps<=0 = legacy (whole pass in one burst). lastConnect/connectStreak
	// back off successive resyncs when bird reconnects rapidly (crash-looping). All
	// feed-goroutine-only (apply runs on the single Run loop).
	maxOps        int
	pace          time.Duration
	lastConnect   time.Time
	connectStreak int

	// Feed health for the report/metrics (read via Status from other goroutines).
	// fails = CONSECUTIVE failed apply passes (connect/encode/flush); a sustained
	// non-zero means traction convergence is silently stale — log-only was invisible
	// to the server (billed-as-live ≠ enforced), so this feeds HealthReport +
	// Prometheus + the server's bird-feed-degraded BSS event.
	fails  atomic.Int64
	lastOK atomic.Int64 // unix ms of the last fully-applied (flushed+committed) pass; 0 = never
}

// reconnect-backoff bounds (WithPacing only): space out successive full resyncs
// when bird reconnects within the window, growing per clustered reconnect up to max.
const (
	reconnectBackoffWindow = 5 * time.Second
	reconnectBackoffStep   = 250 * time.Millisecond
	reconnectBackoffMax    = 2 * time.Second
)

// FeedOption configures a Feed.
type FeedOption func(*Feed)

// WithPacing bounds the api feed to maxOps frames per flush, yielding pace between
// chunks so a large (re)dump does not slam bird-vpp as one in-flight burst (the
// 60K-churn os_panic amplifier). maxOps<=0 disables pacing (legacy one-burst pass).
func WithPacing(maxOps int, pace time.Duration) FeedOption {
	return func(f *Feed) {
		f.maxOps = maxOps
		f.pace = pace
	}
}

// NewFeed wires a Feed over a fresh Client for the api socket path.
func NewFeed(path string, log *slog.Logger, opts ...FeedOption) *Feed {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	c := NewClient(path)
	f := &Feed{
		client:  c,
		path:    path,
		log:     log,
		wake:    make(chan struct{}, 1),
		anchors: map[netip.Prefix][]byte{},
		flows:   map[netip.Prefix]struct{}{},
		resync:  true,
	}
	for _, o := range opts {
		o(f)
	}
	// Bird-death wake (the bird-restart hole): the client's watcher detects the
	// peer closing the socket (bird restart/stop) and wakes the feed, so the next
	// pass reconnects + full-resyncs immediately — a stable desired state would
	// otherwise never exercise the dead socket (zero-diff passes write nothing)
	// and the steering bird lost would stay gone until an agent restart.
	c.onDown = f.Wake
	return f
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
		return // cold start / fail-static skip — not a feed failure
	}
	if err := f.apply(st); err != nil {
		f.fails.Add(1)
		// Retry on a short fuse instead of waiting out a full interval tick —
		// for EVERY failure path (2026-07-17 audit #5). The connect-failure case
		// always needed this (bird's socket isn't up yet); the flush-error cases
		// (bird died and the AGENT's own write detected it first) relied on the
		// reader-EOF watcher to wake the feed, but f.client.close() on those paths
		// tears the watcher down with the connection, so nothing re-armed and the
		// steering re-feed degraded to the next ~60s tick. Each failed pass
		// schedules exactly one wake (coalescing channel), so this self-arms every
		// ~2s while bird is down and stops on the first clean pass.
		time.AfterFunc(2*time.Second, f.Wake)
		return
	}
	f.fails.Store(0)
	f.lastOK.Store(time.Now().UnixMilli())
}

// Status returns the feed's health: consecutive failed apply passes and the unix-ms
// timestamp of the last fully-applied pass (0 = never). Safe from any goroutine;
// wired to HealthReport.BirdFeedFails/BirdFeedLastOKUnixMs + the agent metrics.
func (f *Feed) Status() (fails int64, lastOKUnixMs int64) {
	return f.fails.Load(), f.lastOK.Load()
}

func (f *Feed) apply(st model.EdgeDesiredState) error {
	if !f.client.connected() {
		if err := f.client.connect(); err != nil {
			f.log.Warn("bird feed: connect failed", "socket", f.path, "err", err)
			// bird is (re)starting — its socket isn't up yet. The caller (pass)
			// arms the short-fuse retry wake for every failed pass.
			return err
		}
		f.log.Info("bird feed: connected", "socket", f.path)
		f.resync = true
		f.backoffReconnect()
	}

	// Desired sets. Anchors (v4+v6) and flowspec (v4+v6) are all fed; the redirect
	// EC is chosen per source-prefix family — 8-byte redirect-to-IPv4 for a v4
	// source, 20-byte redirect-to-IPv6 i6ec for a v6 source (DESIGN-bird-api §3.3).
	desA := make(map[netip.Prefix][]byte, len(st.Anchors))
	for _, a := range st.Anchors {
		desA[a.Prefix] = anchorAttrBytes(a, f.log) // nil for a plain anchor; RTBH etc. ride as TLVs
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

	// Paced write: flush + yield every maxOps frames so bird-vpp's vppfib drains
	// between chunks. Feeding a whole (re)dump as one in-flight burst overran bird-
	// vpp's vapi accumulation → os_panic under 60K churn, and a bird restart re-
	// dumped the whole set into the just-restarted bird, re-crashing it (the self-
	// sustaining loop). write() flushes mid-pass, so a flush error there means bird
	// went away — reconnect + full resync next pass. maxOps<=0 = one-burst (legacy).
	n := 0
	write := func(frame []byte) error {
		f.client.write(frame)
		if f.maxOps <= 0 {
			return nil
		}
		if n++; n >= f.maxOps {
			if err := f.client.flush(); err != nil {
				return err
			}
			n = 0
			if f.pace > 0 {
				time.Sleep(f.pace)
			}
		}
		return nil
	}

	// A change to EITHER redirect next-hop must re-announce every flow of that
	// family (the EC is an attribute, not part of the diff key), so resync on both.
	var werr error
	if f.resync || st.RedirectNextHop != f.nextHop || st.RedirectNextHopV6 != f.nextHop6 {
		werr = f.fullResync(desA, desF, ecFor, write)
	} else {
		werr = f.incremental(desA, desF, ecFor, write)
	}
	if werr != nil {
		f.log.Warn("bird feed: paced flush failed mid-pass, will reconnect + resync", "err", werr)
		f.client.close()
		f.resync = true
		return werr
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
// ecFor picks the redirect EC for a flow by its source-prefix family. write paces
// the stream (flush + yield per chunk) and returns the first mid-pass flush error.
func (f *Feed) fullResync(desA map[netip.Prefix][]byte, desF map[netip.Prefix]struct{}, ecFor func(netip.Prefix) []byte, write func([]byte) error) error {
	if err := write(frameHello()); err != nil {
		return err
	}
	for p, attrs := range desA {
		if err := write(frameAnchor(opAdd, p, attrs)); err != nil {
			return err
		}
	}
	for p := range desF {
		if err := write(frameFlow(opAdd, p, ecFor(p))); err != nil {
			return err
		}
	}
	if err := write(frameEOR()); err != nil {
		return err
	}
	f.resync = false
	return nil
}

// incremental: only the diff vs the last-fed snapshot (O(delta) into bird). write
// paces the stream and returns the first mid-pass flush error.
func (f *Feed) incremental(desA map[netip.Prefix][]byte, desF map[netip.Prefix]struct{}, ecFor func(netip.Prefix) []byte, write func([]byte) error) error {
	for p, attrs := range desA {
		if prev, ok := f.anchors[p]; !ok || !bytes.Equal(prev, attrs) {
			if err := write(frameAnchor(opAdd, p, attrs)); err != nil { // new, or communities changed (upsert)
				return err
			}
		}
	}
	for p := range f.anchors {
		if _, ok := desA[p]; !ok {
			if err := write(frameAnchor(opDel, p, nil)); err != nil {
				return err
			}
		}
	}
	for p := range desF {
		if _, ok := f.flows[p]; !ok {
			if err := write(frameFlow(opAdd, p, ecFor(p))); err != nil {
				return err
			}
		}
	}
	for p := range f.flows {
		if _, ok := desF[p]; !ok {
			if err := write(frameFlow(opDel, p, ecFor(p))); err != nil { // ec ignored on DEL
				return err
			}
		}
	}
	return nil
}

// backoffReconnect spaces out successive full resyncs when bird reconnects rapidly
// (crash-looping): re-dumping the whole homed set the instant the socket returns can
// itself re-crash a just-restarted bird. Feed-goroutine-only state (apply runs on
// the single Run loop). No-op unless pacing is enabled.
func (f *Feed) backoffReconnect() {
	if f.maxOps <= 0 {
		return
	}
	now := time.Now()
	if !f.lastConnect.IsZero() && now.Sub(f.lastConnect) < reconnectBackoffWindow {
		f.connectStreak++
		d := time.Duration(f.connectStreak) * reconnectBackoffStep
		if d > reconnectBackoffMax {
			d = reconnectBackoffMax
		}
		f.log.Warn("bird feed: rapid reconnect, backing off before resync",
			"streak", f.connectStreak, "delay", d)
		time.Sleep(d)
	} else {
		f.connectStreak = 0
	}
	f.lastConnect = time.Now()
}
