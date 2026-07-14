package agent

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// ForwardingProbe is the §4.2.7/§4.2.8 device-level active forwarding check — the ③
// signal (VPP up, interfaces up, but not forwarding: a silent black-hole a passive
// check cannot see). Each round observes whether a stable target is forwarding-reachable
// (recv > 0); after K consecutive black-holed rounds it declares the path broken. It is
// source-agnostic: the round closure either reads the `probe` plugin's FIB-reachability
// gauge over the stats segment (§4.2.8, preferred — never touches VPP's main thread) or
// pings the target through the data plane (§4.2.7 legacy). It runs at the DEVICE level
// (one probe, not per-member) and is immune to the policer — a single low-rate echo is
// far below any pool rate, so failure means a real forwarding fault, not intentional
// drops. The FaultSensor reads Broken() and reports FaultForwardingBroken.
type ForwardingProbe struct {
	// ping runs one probe round, returning how many echoes came back and any transport
	// error (channel unavailable / main-thread timeout). recv > 0 = path healthy.
	ping     func() (recv int, err error)
	interval time.Duration
	k        int // consecutive zero-reply rounds before Broken flips true
	log      *slog.Logger

	fails       int         // loop-local consecutive failure count (only the Run goroutine touches it)
	everHealthy bool        // has the target been reachable at least once? (loop-local)
	broken      atomic.Bool // the verdict the FaultSensor reads

	// gen, when bound, is the data-plane (re)connect generation (vpp.Conn.Generation).
	// A change means VPP RESTARTED under a still-armed probe: the FIB is empty until
	// bird/vppfib re-feeds (tens of seconds), and an armed probe would misread that
	// rebuild window as a black-hole → forwarding-broken → spurious IMMEDIATE failover
	// (server routes ③ as trusted+immediate). The startup grace (everHealthy) only
	// covers AGENT restarts; this is its twin for VPP restarts: on a generation change
	// the probe DISARMS and re-arms on first reachability, exactly like boot.
	gen     func() uint64
	lastGen uint64 // loop-local (only the Run goroutine compares/updates after Bind)

	// busy, when bound, reports the edge is mid-materialization (phase Reconciling,
	// §6.67 wall-①): a saturated VPP main thread starves the probe plugin's process
	// node, so the reachability gauge goes stale/zero WITHOUT the path being broken
	// (observed at 120K: 54-72s false black-hole windows → determinate-fault fast
	// failover → churn storm). While busy a zero-reach round is INCONCLUSIVE — same
	// treatment as a transport error: logged, counter untouched. A REAL black-hole
	// that starts during materialization is declared once the edge leaves Reconciling
	// (drained → Ready, or a truly wedged VPP errors the reconcile → Degraded), so ③
	// is delayed by the busy window, never lost. nil → ungated (legacy).
	busy func() bool
}

// NewForwardingProbe builds a probe. ping is one round (e.g. conn.Ping wrapped to return
// recv+err); interval is how often to probe; k is the consecutive-failure threshold.
func NewForwardingProbe(ping func() (int, error), interval time.Duration, k int, log *slog.Logger) *ForwardingProbe {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if k < 1 {
		k = 1
	}
	return &ForwardingProbe{ping: ping, interval: interval, k: k, log: log}
}

// Broken reports whether the forwarding path has failed k consecutive rounds.
func (p *ForwardingProbe) Broken() bool { return p.broken.Load() }

// BindDataplaneGeneration wires the VPP (re)connect generation source
// (vpp.Conn.Generation) so a VPP restart disarms the probe (see the gen field
// doc). The current generation is snapshotted as the baseline. Call before Run.
func (p *ForwardingProbe) BindDataplaneGeneration(gen func() uint64) {
	p.gen = gen
	p.lastGen = gen()
}

// BindBusy wires the materialization-busy signal (phase Reconciling — see the busy
// field doc): while busy, zero-reach rounds are inconclusive and do not count toward
// the black-hole threshold. Call before Run.
func (p *ForwardingProbe) BindBusy(busy func() bool) { p.busy = busy }

// Run probes every interval until ctx is cancelled. A transport error (probe could not
// run — busy main thread, channel error) is NEITHER a healthy round NOR a forwarding
// failure: it is logged and leaves the counter untouched, so a wedged main thread (a
// phase-model concern, not ③) never false-positives a forwarding black-hole.
func (p *ForwardingProbe) Run(ctx context.Context) {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.round()
		}
	}
}

func (p *ForwardingProbe) round() {
	// VPP restarted since the last round → the data plane is REBUILDING (empty FIB
	// until bird re-feeds); disarm and re-arm on first reachability, like boot. This
	// must precede the ping so the rebuild window's legitimate zero-reach rounds
	// never count as regressions (live-hit: §6.44 — 3 fails during a 30s vppfib
	// re-feed spuriously killed the edge).
	if p.gen != nil {
		if g := p.gen(); g != p.lastGen {
			p.lastGen = g
			p.fails = 0
			p.everHealthy = false
			p.broken.Store(false)
			p.log.Info("forwarding probe disarmed: VPP restarted (data plane rebuilding); re-arms on first reachability",
				"generation", g)
		}
	}
	recv, err := p.ping()
	switch {
	case err != nil:
		p.log.Warn("forwarding probe could not run; leaving verdict unchanged", "err", err)
	case recv > 0:
		if p.fails > 0 || p.broken.Load() {
			p.log.Info("forwarding probe recovered", "after_fails", p.fails)
		}
		p.fails = 0
		p.everHealthy = true
		p.broken.Store(false)
	case !p.everHealthy:
		// recv == 0 but the target has never been reachable — this is initial
		// convergence (routes/BGP not up yet), not a regression. Declaring a
		// black-hole here would trip an immediate failover on every restart during
		// the convergence window. Only arm ③ after the path has been healthy once;
		// a genuinely dead-from-boot edge is caught by other signals (vpp-gone,
		// registration, link-down).
		return
	default: // recv == 0 after having been healthy → a regression THIS round…
		// …unless the edge is mid-materialization: a saturated main thread starves
		// the probe plugin, so the gauge lies (§6.67 wall-①). Inconclusive — same as
		// a transport error; the counter neither advances nor resets.
		if p.busy != nil && p.busy() {
			p.log.Info("forwarding probe: zero-reach while materializing — inconclusive, not counted",
				"fails_held_at", p.fails)
			return
		}
		p.fails++
		if p.fails >= p.k && !p.broken.Load() {
			p.log.Warn("forwarding probe: path black-holed", "consecutive_fails", p.fails, "threshold", p.k)
			p.broken.Store(true)
		}
	}
}
