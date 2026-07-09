package agent

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// VppLiveness is stats-segment-based VPP process liveness (§6.44 follow-up:
// judge from stats, not the binary API). It reads the probe plugin's
// /probe/heartbeat counter — bumped once per timer-driven probe scan, so it
// advances even when VPP is idle — and derives the two death modes an agent
// cannot otherwise see off the main thread:
//
//   - PROCESS DEATH / RESTART: the read returns a disconnected error (the stats
//     socket was removed; govpp detects this via fsnotify — event-driven and
//     immediate, with none of the binary-API health-check's reply-timeout
//     ambiguity that put permanent-death failover at 30s in §6.44).
//   - MAIN-THREAD WEDGE: the segment is still mapped and readable but the
//     heartbeat stops advancing past wedgeGrace — the process is alive yet its
//     single main thread is stalled. This is the §4.1 blind spot the frozen
//     worker loop counters (adaptive sleep) cannot reveal, and which a socket
//     dial cannot catch (the kernel still accepts).
//
// It replaces the earlier SocketWatcher (which dialed the binary-API socket:
// caught process death but not wedge, on a slower K-dial debounce, and stood up
// a whole mechanism instead of reusing the stats channel the agent already
// holds for metering + the forwarding probe).
type VppLiveness struct {
	readBeat     func() (uint64, error) // reads /probe/heartbeat
	disconnected func(error) bool       // classifies a read error as process death
	interval     time.Duration          // poll cadence
	wedgeGrace   time.Duration          // heartbeat must advance within this, else wedge
	now          func() time.Time
	onTransition func(dead bool)
	log          *slog.Logger

	// loop-local (only Run's goroutine touches these)
	haveBeat    bool
	lastBeat    uint64
	lastAdvance time.Time

	dead atomic.Bool
}

// NewVppLiveness builds a liveness monitor. readBeat reads /probe/heartbeat
// (e.g. StatsReader.ReadGauge wrapped); disconnected classifies a read error as
// process death (vpp.IsStatsDisconnected); interval is the poll cadence;
// wedgeGrace is how long the heartbeat may stall before a wedge is declared
// (must exceed the probe scan cadence with margin).
func NewVppLiveness(readBeat func() (uint64, error), disconnected func(error) bool, interval, wedgeGrace time.Duration, log *slog.Logger) *VppLiveness {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &VppLiveness{
		readBeat: readBeat, disconnected: disconnected,
		interval: interval, wedgeGrace: wedgeGrace,
		now: time.Now, log: log,
	}
}

// OnTransition registers the dead↔alive hook (wire to the reporter wake so the
// typed vpp-gone / recovery reaches the server event-driven). Call before Run.
func (p *VppLiveness) OnTransition(fn func(dead bool)) { p.onTransition = fn }

// Dead reports whether VPP is judged gone (process death or main-thread wedge).
// The FaultSensor consults it to type vpp-gone even while govpp's binary-API
// connection still claims healthy.
func (p *VppLiveness) Dead() bool { return p.dead.Load() }

// Run polls the heartbeat every interval until ctx is cancelled.
func (p *VppLiveness) Run(ctx context.Context) {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.check()
		}
	}
}

func (p *VppLiveness) check() {
	beat, err := p.readBeat()
	switch {
	case err != nil && p.disconnected(err):
		// Stats socket removed = process gone/restarting.
		p.set(true, "stats disconnected (VPP process gone)")
	case err != nil:
		// Segment connected but heartbeat unreadable (gauge not yet registered on
		// a just-restarted VPP, or an image without the heartbeat). VPP is alive;
		// leave the verdict unchanged rather than false-positive a death.
		p.log.Debug("vpp liveness: heartbeat unreadable (verdict unchanged)", "err", err)
	case !p.haveBeat || beat > p.lastBeat:
		// Advanced (or first read) → alive.
		p.haveBeat = true
		p.lastBeat = beat
		p.lastAdvance = p.now()
		p.set(false, "")
	case beat < p.lastBeat:
		// Counter went backwards → VPP restarted (new process, beats from 0). Alive.
		p.lastBeat = beat
		p.lastAdvance = p.now()
		p.set(false, "")
	default:
		// beat == lastBeat: not advancing. Wedge once stalled past the grace.
		if p.now().Sub(p.lastAdvance) >= p.wedgeGrace {
			p.set(true, "heartbeat stalled past grace (main-thread wedge)")
		}
	}
}

func (p *VppLiveness) set(dead bool, reason string) {
	if p.dead.Swap(dead) == dead {
		return // no transition (also suppresses a spurious alive-transition at start)
	}
	if dead {
		p.log.Warn("vpp liveness: DEAD", "reason", reason)
	} else {
		p.log.Info("vpp liveness: alive")
	}
	if p.onTransition != nil {
		p.onTransition(dead)
	}
}
