package agent

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// ForwardingProbe is the §4.2.7 device-level active forwarding probe — the ③ signal
// (VPP up, interfaces up, but not forwarding: a silent black-hole a passive check
// cannot see). It periodically pings a stable, always-reachable next-hop through VPP's
// data plane; after K consecutive rounds with no reply it declares the forwarding path
// broken. It runs at the DEVICE level (one probe, not per-member) and is immune to the
// policer — a single low-rate echo is far below any pool rate, so it never triggers
// rate-limiting: probe failure means a real forwarding fault, not intentional drops
// (see DESIGN-liveness §4.2.5 SUPERSEDED / §4.2.7). The FaultSensor reads Broken() and
// reports FaultForwardingBroken.
type ForwardingProbe struct {
	// ping runs one probe round, returning how many echoes came back and any transport
	// error (channel unavailable / main-thread timeout). recv > 0 = path healthy.
	ping     func() (recv int, err error)
	interval time.Duration
	k        int // consecutive zero-reply rounds before Broken flips true
	log      *slog.Logger

	fails  int         // loop-local consecutive failure count (only the Run goroutine touches it)
	broken atomic.Bool // the verdict the FaultSensor reads
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
	recv, err := p.ping()
	switch {
	case err != nil:
		p.log.Warn("forwarding probe could not run; leaving verdict unchanged", "err", err)
	case recv > 0:
		if p.fails > 0 || p.broken.Load() {
			p.log.Info("forwarding probe recovered", "after_fails", p.fails)
		}
		p.fails = 0
		p.broken.Store(false)
	default: // recv == 0 → this path black-holed this round
		p.fails++
		if p.fails >= p.k && !p.broken.Load() {
			p.log.Warn("forwarding probe: path black-holed", "consecutive_fails", p.fails, "threshold", p.k)
			p.broken.Store(true)
		}
	}
}
