// Package homing is the agent side of controller sharding (DESIGN-liveness §10,
// TODO-liveness L-06): "who is my brain, and to whom do I report?".
//
// The agent NEVER reads etcd or computes the shard. It boots with a static set
// of controller endpoints, connects to any one, and Registers; the controller
// computes (membership + rendezvous hashing) this edge's coverers and returns
// them — primary + fallbacks. The director then homes onto the PRIMARY (reports
// + subscribes there) and keeps the fallbacks for when the primary is
// unreachable. When coverage moves the controller pushes a REHOME directive and
// the director switches primary. Across any reconnect gap the agent's
// DesiredStore holds the last desired state (fail-static), so the data plane
// never wobbles while the control link re-homes.
//
// The director implements agent.ReportSink (SendReport → the current primary),
// so the reporter just uses it; the downlink desired-state/directives flow
// through the same connection via the configured handlers.
package homing

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/grpcclient"
)

// ErrNotConnected is returned by SendReport when no controller link is up yet
// (the reporter logs and retries on its next tick — a missed report is benign).
var ErrNotConnected = errors.New("homing: not connected to any controller")

// Conn is the slice of grpcclient.Client the director drives — an interface so
// the loop is unit-tested with a fake (no real gRPC). *grpcclient.Client
// satisfies it.
type Conn interface {
	Register(ctx context.Context, capacityBps uint64) error
	SendReport(ctx context.Context, r model.EdgeReport) error
	SubscribePass(ctx context.Context) error
	Close() error
}

// DialFunc builds a connection to endpoint with the coverer callback wired (so
// Register/REHOME assignments reach the director). In production this is a thin
// wrapper over grpcclient.Dial; tests supply a fake.
type DialFunc func(endpoint string, onCoverers grpcclient.CovererFunc) (Conn, error)

// Director maintains the agent's connection to its primary coverer, re-homing on
// REHOME and falling back to other coverers/bootstrap endpoints on failure.
type Director struct {
	bootstrap   []string
	capacity    uint64
	dial        DialFunc
	backoff     time.Duration
	rehomeRetry time.Duration
	log         logger

	mu          sync.Mutex
	cur         Conn
	curEndpoint string
	assignment  model.CovererAssignment
	lastPrimary string             // last primary endpoint we acted on (de-thrash)
	rehomeTo    string             // pending directed switch target (primary changed)
	cancelPass  context.CancelFunc // cancels the active SubscribePass to force a re-home
}

// logger is the minimal logging surface (slog.Logger satisfies it).
type logger interface {
	Warn(msg string, args ...any)
	Info(msg string, args ...any)
}

type nopLogger struct{}

func (nopLogger) Warn(string, ...any) {}
func (nopLogger) Info(string, ...any) {}

// Option configures a Director.
type Option func(*Director)

// WithBackoff sets the reconnect backoff (default 1s).
func WithBackoff(d time.Duration) Option { return func(dir *Director) { dir.backoff = d } }

// WithRehomeRetry sets how often an agent parked on a FALLBACK retries its primary (default
// 30s). The retry covers the case where the primary was unreachable when we homed (e.g. a
// coverer restarting: its Watch reconnects to the server — which REHOMEs us toward it —
// before its agent-facing service is ready, so our switch fails and we fall back), and
// nothing else would retry it while the fallback subscription stays up. Rate-limited so a
// genuinely-down primary does not thrash.
func WithRehomeRetry(d time.Duration) Option { return func(dir *Director) { dir.rehomeRetry = d } }

// WithLogger sets the logger.
func WithLogger(l logger) Option { return func(dir *Director) { dir.log = l } }

// New builds a director over the bootstrap controller endpoints. dial builds a
// connection (wired with the director's coverer callback); capacity is announced
// at each Register.
func New(bootstrap []string, capacityBps uint64, dial DialFunc, opts ...Option) *Director {
	d := &Director{
		bootstrap:   bootstrap,
		capacity:    capacityBps,
		dial:        dial,
		backoff:     time.Second,
		rehomeRetry: 30 * time.Second,
		log:         nopLogger{},
	}
	for _, o := range opts {
		o(d)
	}
	return d
}

// SendReport delivers an EdgeReport to the current primary coverer (implements
// agent.ReportSink). ErrNotConnected before the first link comes up.
func (d *Director) SendReport(ctx context.Context, r model.EdgeReport) error {
	d.mu.Lock()
	c := d.cur
	d.mu.Unlock()
	if c == nil {
		return ErrNotConnected
	}
	return c.SendReport(ctx, r)
}

// CurrentEndpoint returns the controller the agent is currently homed on (tests/
// observability); "" before the first connection.
func (d *Director) CurrentEndpoint() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.curEndpoint
}

// handleCoverers receives an assignment (Register response or REHOME). It
// re-homes only when the primary endpoint actually CHANGES from the last one we
// acted on — not merely differs from where we sit. Otherwise an agent parked on a
// fallback (because its primary is down) would thrash: every Register re-reports
// the same dead primary, and re-homing to it on each cycle never settles. A
// genuine coverage change (new primary) does switch; a plain disconnect's
// candidate rotation still retries the primary later.
func (d *Director) handleCoverers(a model.CovererAssignment) {
	p, ok := a.Primary()
	d.mu.Lock()
	d.assignment = a
	if ok && p.GRPCEndpoint != "" && p.GRPCEndpoint != d.lastPrimary {
		d.lastPrimary = p.GRPCEndpoint
		if p.GRPCEndpoint != d.curEndpoint {
			d.rehomeTo = p.GRPCEndpoint
			if d.cancelPass != nil {
				d.cancelPass()
			}
		}
	}
	d.mu.Unlock()
}

// Run drives the homing loop until ctx is done: connect to the current target,
// Register (learn coverers), then subscribe; on a directed re-home switch to the
// new primary immediately, on a plain disconnect/failure rotate to the next
// candidate (primary → fallbacks → bootstrap) after a backoff. Blocks.
func (d *Director) Run(ctx context.Context) {
	if len(d.bootstrap) == 0 {
		d.log.Warn("homing: no bootstrap endpoints; nothing to connect to")
		return
	}
	target := d.bootstrap[0]
	for ctx.Err() == nil {
		c, err := d.dial(target, d.handleCoverers)
		if err != nil {
			d.log.Warn("homing: dial failed", "endpoint", target, "err", err)
			target = d.nextAfter(target)
			if !d.sleep(ctx) {
				return
			}
			continue
		}
		d.setCurrent(c, target)

		// Register fires handleCoverers, which may set a directed re-home.
		if err := c.Register(ctx, d.capacity); err != nil {
			d.log.Warn("homing: register failed", "endpoint", target, "err", err)
		} else {
			d.log.Info("homing: registered", "endpoint", target)
		}
		if rt := d.takeRehome(); rt != "" && rt != target {
			d.closeCurrent()
			target = rt
			continue // reconnect to the primary now (no backoff — directed)
		}

		// Subscribe pass, cancelable so a REHOME mid-stream (or the return-to-primary timer)
		// forces a re-home.
		passCtx, cancel := context.WithCancel(ctx)
		d.setCancel(cancel)
		stopRetry := d.scheduleReturnToPrimary(target)
		_ = c.SubscribePass(passCtx)
		stopRetry()
		d.setCancel(nil)
		cancel()
		d.closeCurrent()

		if ctx.Err() != nil {
			return
		}
		if rt := d.takeRehome(); rt != "" {
			target = rt // directed re-home: no backoff
			continue
		}
		// Plain disconnect: try the next candidate after a backoff.
		target = d.nextAfter(target)
		if !d.sleep(ctx) {
			return
		}
	}
}

func (d *Director) setCurrent(c Conn, endpoint string) {
	d.mu.Lock()
	d.cur, d.curEndpoint = c, endpoint
	d.mu.Unlock()
}

func (d *Director) closeCurrent() {
	d.mu.Lock()
	c := d.cur
	d.cur, d.curEndpoint = nil, ""
	d.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

func (d *Director) setCancel(fn context.CancelFunc) {
	d.mu.Lock()
	d.cancelPass = fn
	d.mu.Unlock()
}

// scheduleReturnToPrimary, while the agent is parked on a NON-primary endpoint (target !=
// primary — a fallback we rolled to because the primary was unreachable when we homed),
// arms a one-shot timer that forces a fresh attempt to return to the primary after
// rehomeRetry. Nothing else retries the primary while a fallback subscription stays up, so
// without this a transient primary outage (e.g. a coverer restart racing the REHOME) strands
// the agent on its fallback indefinitely. Returns a stop func to call when the pass ends.
// No-op when already on the primary or no primary is known. The fire re-checks under the
// lock that we are still off the primary, then sets the directed re-home + cancels the pass
// (reusing the REHOME mid-stream mechanism); the Run loop then reconnects to the primary.
func (d *Director) scheduleReturnToPrimary(target string) func() {
	d.mu.Lock()
	p, ok := d.assignment.Primary()
	d.mu.Unlock()
	if !ok || p.GRPCEndpoint == "" || p.GRPCEndpoint == target {
		return func() {}
	}
	t := time.AfterFunc(d.rehomeRetry, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		pp, ok := d.assignment.Primary()
		if ok && pp.GRPCEndpoint != "" && pp.GRPCEndpoint != d.curEndpoint {
			d.rehomeTo = pp.GRPCEndpoint
			if d.cancelPass != nil {
				d.cancelPass()
			}
		}
	})
	return func() { t.Stop() }
}

func (d *Director) takeRehome() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	rt := d.rehomeTo
	d.rehomeTo = ""
	return rt
}

// nextAfter returns the candidate to try after `cur`: round-robin over the
// ordered candidate list (current primary → fallbacks → bootstrap). This makes a
// dead primary roll to a fallback, and once reconnected Register re-learns the
// assignment and homes back onto the (possibly new) primary.
func (d *Director) nextAfter(cur string) string {
	d.mu.Lock()
	cands := orderedCandidates(d.assignment, d.bootstrap)
	d.mu.Unlock()
	return nextAfter(cands, cur)
}

func (d *Director) sleep(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d.backoff):
		return true
	}
}

// orderedCandidates builds the connect-preference list: the assignment's primary
// first, then its fallbacks, then any bootstrap endpoints not already listed.
// Empty endpoints are skipped; duplicates removed.
func orderedCandidates(a model.CovererAssignment, bootstrap []string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(e string) {
		if e == "" || seen[e] {
			return
		}
		seen[e] = true
		out = append(out, e)
	}
	if p, ok := a.Primary(); ok {
		add(p.GRPCEndpoint)
	}
	for _, f := range a.Fallbacks() {
		add(f.GRPCEndpoint)
	}
	for _, b := range bootstrap {
		add(b)
	}
	return out
}

// nextAfter returns the element following cur in list (wrapping). If cur is not
// in list (or list is short), it returns the first element — so a failed dial to
// an off-list endpoint still makes progress.
func nextAfter(list []string, cur string) string {
	if len(list) == 0 {
		return cur
	}
	for i, e := range list {
		if e == cur {
			return list[(i+1)%len(list)]
		}
	}
	return list[0]
}
