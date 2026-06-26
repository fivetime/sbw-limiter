// Package vpp manages the govpp connection to VPP's binary API (T-401,
// DESIGN.md §5/§7): connect, auto-reconnect, and a binding-compatibility
// check on every (re)connect. It is the transport the data-plane materializers
// (T-402/403/406/407/408/410) use; they obtain a channel via Channel().
package vpp

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"go.fd.io/govpp/adapter"
	"go.fd.io/govpp/adapter/socketclient"
	govppapi "go.fd.io/govpp/api"
	"go.fd.io/govpp/core"
)

// Conn is a managed VPP binary-API connection. govpp reconnects automatically;
// Conn tracks health, re-verifies binding compatibility after each reconnect,
// and exposes readiness to the reconcile loop. Safe for concurrent use.
type Conn struct {
	conn *core.Connection
	log  *slog.Logger

	// checkCompat verifies the connected VPP speaks the messages our bindings
	// expect. Injectable for tests; defaults to the real channel check.
	checkCompat func() error

	healthy atomic.Bool
	done    chan struct{}
	stopOne sync.Once

	// gen counts healthy (re)connects: 1 on first connect, +1 each reconnect.
	// A reconnect means VPP may have restarted and lost all data-plane state
	// (policers/classify/ABF) — routes alone are re-dumped by linux-cp, but our
	// rules are not (T-503, §5/§7). reconnect notifies the reconcile loop so it
	// resets its caches and reinstalls everything.
	gen       atomic.Uint64
	reconnect chan struct{}

	readyMu   sync.Mutex
	readyChan chan struct{} // closed once on first healthy connect
	readyDone bool
}

// Option configures Connect.
type Option func(*config)

type config struct {
	attempts      int
	interval      time.Duration
	log           *slog.Logger
	compatMsgs    []govppapi.Message
	readyWait     time.Duration
	healthTimeout time.Duration
}

// WithReconnect sets the reconnect attempt count and interval.
func WithReconnect(attempts int, interval time.Duration) Option {
	return func(c *config) { c.attempts = attempts; c.interval = interval }
}

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) Option { return func(c *config) { c.log = l } }

// WithReadyTimeout bounds how long Connect waits for the first healthy connect.
func WithReadyTimeout(d time.Duration) Option { return func(c *config) { c.readyWait = d } }

// WithHealthCheck overrides govpp's health-probe reply timeout. govpp's default
// (250ms) is too tight at scale: a VPP busy installing classify sessions can take
// >250ms to answer a ControlPing, which govpp falsely reads as NotResponding →
// disconnect/reconnect → handleEvent signals a full data-plane reinstall (T-503)
// → VPP gets busier → more false timeouts: a self-reinforcing reinstall storm
// that also drops the controller gRPC subscription. A real VPP crash breaks the
// socket and is still detected immediately, independent of this timeout. 0 keeps
// govpp's default.
func WithHealthCheck(replyTimeout time.Duration) Option {
	return func(c *config) { c.healthTimeout = replyTimeout }
}

// Dial connects to VPP's binary-API socket (e.g. /run/vpp/api.sock).
func Dial(ctx context.Context, socketPath string, opts ...Option) (*Conn, error) {
	return Connect(ctx, socketclient.NewVppClient(socketPath), opts...)
}

// Connect establishes a managed connection over the given govpp adapter
// (socketclient in prod, mock in tests). It returns once the connection is up
// and binding-compatible, or on timeout/ctx cancellation.
func Connect(ctx context.Context, a adapter.VppAPI, opts ...Option) (*Conn, error) {
	cfg := config{
		attempts:   core.DefaultMaxReconnectAttempts,
		interval:   core.DefaultReconnectInterval,
		log:        slog.New(slog.DiscardHandler),
		compatMsgs: RequiredMessages(),
		readyWait:  15 * time.Second,
	}
	for _, o := range opts {
		o(&cfg)
	}

	// govpp's health-probe tunables are process-global; set before AsyncConnect
	// starts the health-check loop that reads them. The 250ms default reply
	// timeout is too tight at scale (see WithHealthCheck).
	if cfg.healthTimeout > 0 {
		core.HealthCheckReplyTimeout = cfg.healthTimeout
	}

	conn, events, err := core.AsyncConnect(a, cfg.attempts, cfg.interval)
	if err != nil {
		return nil, fmt.Errorf("vpp: async connect: %w", err)
	}

	c := &Conn{
		conn:      conn,
		log:       cfg.log,
		done:      make(chan struct{}),
		reconnect: make(chan struct{}, 1),
		readyChan: make(chan struct{}),
	}
	c.checkCompat = func() error {
		return c.verifyCompatibility(cfg.compatMsgs)
	}

	go c.watch(events)

	waitCtx := ctx
	if cfg.readyWait > 0 {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(ctx, cfg.readyWait)
		defer cancel()
	}
	if err := c.waitReady(waitCtx); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// watch processes connection events until Close. govpp emits Connected on each
// (re)establish and Disconnected/Failed on loss.
func (c *Conn) watch(events chan core.ConnectionEvent) {
	for {
		select {
		case <-c.done:
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			c.handleEvent(ev)
		}
	}
}

func (c *Conn) handleEvent(ev core.ConnectionEvent) {
	switch ev.State {
	case core.Connected:
		if err := c.checkCompat(); err != nil {
			c.healthy.Store(false)
			c.log.Error("VPP connected but binding-incompatible; not ready", "err", err)
			return
		}
		c.healthy.Store(true)
		gen := c.gen.Add(1)
		if c.signalReady() {
			c.log.Info("VPP connection established and compatible", "generation", gen)
		} else {
			// A reconnect after we were already up: VPP likely restarted and
			// dropped our data-plane state. Wake the reconcile loop.
			c.notifyReconnect()
			c.log.Warn("VPP reconnected (possible restart); signalling data-plane reinstall", "generation", gen)
		}
	case core.Disconnected:
		c.healthy.Store(false)
		c.log.Warn("VPP disconnected; govpp will reconnect")
	case core.Failed:
		c.healthy.Store(false)
		c.log.Error("VPP connection failed", "err", ev.Error)
	default:
		c.log.Debug("VPP connection event", "state", ev.State)
	}
}

// signalReady closes readyChan on the first healthy connect, returning true
// only that first time; subsequent (reconnect) calls return false.
func (c *Conn) signalReady() bool {
	c.readyMu.Lock()
	defer c.readyMu.Unlock()
	if !c.readyDone {
		c.readyDone = true
		close(c.readyChan)
		return true
	}
	return false
}

// notifyReconnect wakes the reconcile loop after a reconnect. The channel is
// buffered to one and sends are non-blocking, so repeated reconnects before the
// loop drains coalesce into a single reinstall.
func (c *Conn) notifyReconnect() {
	select {
	case c.reconnect <- struct{}{}:
	default:
	}
}

// Generation returns the count of healthy (re)connects: 1 after the first
// connect, incremented on each reconnect. A change since a prior read means VPP
// reconnected (and may have restarted).
func (c *Conn) Generation() uint64 { return c.gen.Load() }

// Reconnects delivers a signal each time VPP reconnects after the initial
// connect — the cue to reset caches and reinstall the data plane (T-503).
func (c *Conn) Reconnects() <-chan struct{} { return c.reconnect }

func (c *Conn) waitReady(ctx context.Context) error {
	select {
	case <-c.readyChan:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("vpp: not ready before deadline: %w", ctx.Err())
	}
}

func (c *Conn) verifyCompatibility(msgs []govppapi.Message) error {
	if len(msgs) == 0 {
		return nil
	}
	ch, err := c.conn.NewAPIChannel()
	if err != nil {
		return fmt.Errorf("vpp: open channel for compat check: %w", err)
	}
	defer ch.Close()
	if err := ch.CheckCompatiblity(msgs...); err != nil {
		return fmt.Errorf("vpp: binding/VPP message mismatch (regenerate binapi for the running VPP?): %w", err)
	}
	return nil
}

// Healthy reports whether the connection is currently up and compatible.
func (c *Conn) Healthy() bool { return c.healthy.Load() }

// Channel opens a new binary-API channel. Materializers open one per reconcile
// pass and Close it when done. Returns an error if the connection is down.
func (c *Conn) Channel() (govppapi.Channel, error) {
	if !c.healthy.Load() {
		return nil, fmt.Errorf("vpp: connection not healthy")
	}
	ch, err := c.conn.NewAPIChannel()
	if err != nil {
		return nil, fmt.Errorf("vpp: new api channel: %w", err)
	}
	return ch, nil
}

// Close stops watching and disconnects from VPP.
func (c *Conn) Close() {
	c.stopOne.Do(func() {
		close(c.done)
		if c.conn != nil {
			c.conn.Disconnect()
		}
		c.healthy.Store(false)
	})
}
