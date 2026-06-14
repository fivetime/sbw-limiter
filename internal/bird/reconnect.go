package bird

import (
	"errors"
	"log/slog"
	"sync"
)

// Reconnecting is a self-healing BIRD control client: it owns a socket path and
// transparently (re)dials on demand, so a BIRD restart — which kills the
// underlying unix socket and would otherwise wedge every later command on
// ErrClosed — is recovered automatically on the next command. It implements the
// command surface the anchors.Applier needs (anchors.BirdConfigurer), so it
// drops in wherever a *Client did, and a single instance is shared by the
// anchors and FlowSpec appliers (one BIRD connection, serialized).
//
// Why this lives here and not in the apply loop: client.go's contract is "I/O
// errors close the connection; the caller redials." This is that caller. It
// distinguishes a connection fault (redial + retry) from a BIRD CommandError
// (8xxx/9xxx — a valid reply that a config was rejected; never redial).
type Reconnecting struct {
	path string
	opts []Option
	log  *slog.Logger

	mu  sync.Mutex
	cur *Client // nil until first use / after a connection fault
}

// NewReconnecting returns a lazy self-reconnecting client for the BIRD control
// socket at path (e.g. /run/bird.ctl). It does not dial until the first command,
// so the agent can start before BIRD (or across a BIRD restart) without failing.
func NewReconnecting(path string, log *slog.Logger, opts ...Option) *Reconnecting {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Reconnecting{path: path, opts: opts, log: log}
}

// ensureLocked returns a live client, dialing if none is held. Caller holds mu.
func (r *Reconnecting) ensureLocked() (*Client, error) {
	if r.cur != nil {
		return r.cur, nil
	}
	c, err := Dial(r.path, r.opts...)
	if err != nil {
		return nil, err
	}
	r.cur = c
	r.log.Info("bird control connected", "socket", r.path, "version", c.Version())
	return c, nil
}

// dropLocked closes and forgets the current client so the next call redials.
func (r *Reconnecting) dropLocked() {
	if r.cur != nil {
		_ = r.cur.Close()
		r.cur = nil
	}
}

// call runs fn against a live client, redialing once on a connection fault. A
// BIRD CommandError is a valid reply (config rejected) and is returned as-is —
// only transport faults (ErrClosed / read/write errors, which Do() surfaces
// after closing the conn) trigger redial. At most one redial+retry per call, so
// a persistently-down BIRD fails this pass and is retried on the next tick.
func (r *Reconnecting) call(fn func(*Client) (ConfigureResult, error)) (ConfigureResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		c, err := r.ensureLocked()
		if err != nil {
			return ConfigureResult{}, err // dial failed: report; next pass retries
		}
		res, err := fn(c)
		if err != nil && isConnFault(err) {
			r.log.Warn("bird command hit a dead connection; will redial", "err", err)
			r.dropLocked()
			lastErr = err
			continue // redial and retry once
		}
		return res, err // success, or a BIRD CommandError (return as-is)
	}
	if lastErr == nil {
		lastErr = ErrClosed
	}
	return ConfigureResult{}, lastErr
}

// isConnFault reports whether err is a transport problem (redial-worthy) rather
// than a BIRD-reported config rejection. A *CommandError is a valid reply, never
// a fault; everything else from a command (ErrClosed, wrapped net I/O errors) is
// a dead/broken connection.
func isConnFault(err error) bool {
	var ce *CommandError
	return !errors.As(err, &ce)
}

// ConfigureCheck validates the on-disk config (anchors.BirdConfigurer).
func (r *Reconnecting) ConfigureCheck(path string) (ConfigureResult, error) {
	return r.call(func(c *Client) (ConfigureResult, error) { return c.ConfigureCheck(path) })
}

// Configure reloads the config (anchors.BirdConfigurer).
func (r *Reconnecting) Configure() (ConfigureResult, error) {
	return r.call(func(c *Client) (ConfigureResult, error) { return c.Configure() })
}

// ConfigureTimeout reloads with an undo window (anchors.BirdConfigurer).
func (r *Reconnecting) ConfigureTimeout(seconds int) (ConfigureResult, error) {
	return r.call(func(c *Client) (ConfigureResult, error) { return c.ConfigureTimeout(seconds) })
}

// ConfigureConfirm confirms a timed reconfigure (anchors.BirdConfigurer).
func (r *Reconnecting) ConfigureConfirm() (ConfigureResult, error) {
	return r.call(func(c *Client) (ConfigureResult, error) { return c.ConfigureConfirm() })
}

// Close drops the current connection. The wrapper stays usable: a later command
// simply redials.
func (r *Reconnecting) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dropLocked()
	return nil
}
