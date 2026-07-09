package agent

import (
	"context"
	"log/slog"
	"net"
	"sync/atomic"
	"time"
)

// SocketWatcher is transport-level VPP PROCESS liveness, independent of govpp's
// health-check state machine (§6.44 drill finding). govpp's death detection is
// bimodal: a probe write that hits the dead socket fails with EPIPE immediately
// (~1s), but a write that lands in the kernel buffer just before the process
// dies STALLS the full HealthCheckReplyTimeout (30s, deliberately large per
// L-09 so a busy main thread is never misread as dead) with no further writes
// and therefore no EPIPE chance — leaving the agent VPP-blind for up to 30s
// while conn.Healthy() still reads true.
//
// Dialing the binary-API socket closes that blind spot with evidence a busy
// main thread cannot fake OR break: connect() on a unix socket is answered by
// the kernel listener backlog, so a slow VPP still accepts instantly, while a
// DEAD process's socket refuses (or the path is gone). K consecutive dial
// failures (default 2 × 1s) = the process is gone; a ~1s kubelet container
// self-heal produces at most one failure and never trips it, preserving the
// §6.43 flap-safety verdict. Detection only: it never touches the govpp
// connection state, so it cannot trigger reinstall churn.
type SocketWatcher struct {
	dial     func() error // one connect attempt (injectable for tests)
	interval time.Duration
	k        int // consecutive dial failures before Dead flips true

	// onTransition fires on dead↔alive flips (wire to the reporter wake so the
	// typed vpp-gone reaches the server event-driven, not on the 15s sampling).
	onTransition func(dead bool)

	fails int // loop-local (only the Run goroutine touches it)
	dead  atomic.Bool
	log   *slog.Logger
}

// NewSocketWatcher builds a watcher dialing the given unix socket path.
func NewSocketWatcher(path string, interval time.Duration, k int, log *slog.Logger) *SocketWatcher {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if k < 1 {
		k = 1
	}
	return &SocketWatcher{
		dial: func() error {
			c, err := net.DialTimeout("unix", path, time.Second)
			if err != nil {
				return err
			}
			return c.Close()
		},
		interval: interval,
		k:        k,
		log:      log,
	}
}

// OnTransition registers the dead↔alive hook. Call before Run.
func (w *SocketWatcher) OnTransition(fn func(dead bool)) { w.onTransition = fn }

// Dead reports whether the API socket has been un-dialable for k consecutive
// checks — hard evidence the VPP process is gone. The FaultSensor consults it.
func (w *SocketWatcher) Dead() bool { return w.dead.Load() }

// Run dials every interval until ctx is cancelled.
func (w *SocketWatcher) Run(ctx context.Context) {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.check()
		}
	}
}

func (w *SocketWatcher) check() {
	if err := w.dial(); err != nil {
		w.fails++
		if w.fails >= w.k && !w.dead.Load() {
			w.dead.Store(true)
			w.log.Warn("vpp api socket un-dialable: process gone (transport-level evidence)",
				"consecutive_fails", w.fails, "err", err)
			if w.onTransition != nil {
				w.onTransition(true)
			}
		}
		return
	}
	w.fails = 0
	if w.dead.Load() {
		w.dead.Store(false)
		w.log.Info("vpp api socket dialable again (process back)")
		if w.onTransition != nil {
			w.onTransition(false)
		}
	}
}
