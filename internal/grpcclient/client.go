// Package grpcclient is the agent side of the controller↔agent gRPC transport
// (T-704/705, limiter §4.3). The agent is the client: it Registers, opens a
// Subscribe server-stream (receiving desired-state + failover/urgent directives
// pushed by the controller), and Reports up. It implements agent.ReportSink
// (B-03 uplink) and feeds the downlink to a handler (e.g. DesiredStore.Accept).
//
// Payloads are JSON of the frozen S-04 model (EdgeDesiredState down, EdgeReport
// up); this package transports, the agent reconciles.
package grpcclient

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-contract/rpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// DesiredFunc receives a desired-state push (wire it to DesiredStore.Accept).
type DesiredFunc func(model.EdgeDesiredState)

// DeltaFunc receives an incremental DESIRED_DELTA push (the hot path): the agent
// applies just the touched pools in O(delta). Gap detection (delta.BaseGeneration
// vs the agent's last-applied generation) lives in the handler, which drops a
// gapped delta and relies on the controller's full DESIRED_STATE resync.
type DeltaFunc func(model.EdgeDesiredDelta)

// Client is the agent's connection to the control plane (REFACTOR step 4: the server
// directly; formerly a coverer).
type Client struct {
	conn *grpc.ClientConn
	svc  rpc.AgentServiceClient
	edge model.EdgeID

	onDesired DesiredFunc
	onDelta   DeltaFunc
	backoff   time.Duration
	log       *slog.Logger

	// chunkAsm reassembles a chunked full DESIRED_STATE (DESIRED_STATE_CHUNK). It is
	// owned by the single dispatch goroutine (the Recv loop), so it needs no lock. A
	// chunk buffer is per-stream: a new subscribeOnce starts a fresh stream and a
	// reconnect/re-home means the controller re-sends the full snapshot anyway, so the
	// reassembler is reset on each subscribeOnce.
	chunkAsm chunkAssembler
}

// chunkAssembler buffers the fragments of ONE chunked full-state snapshot until its
// Last chunk arrives, then merges them into a single EdgeDesiredState applied through
// the SAME path as a plain DESIRED_STATE. It supersedes by Epoch: a chunk for a NEWER
// epoch discards the partially-buffered older one (latest-Epoch-wins); a chunk for an
// OLDER epoch is dropped. It NEVER applies a partial — if Last never arrives (stream
// break mid-snapshot) the buffer is simply discarded and the agent keeps its last good
// applied state; the controller's anti-drift backstop re-resyncs with a new Epoch.
type chunkAssembler struct {
	epoch  uint64 // epoch currently being assembled (0 = none)
	active bool   // a snapshot is in progress
	bySeq  map[uint32]model.EdgeDesiredStateChunk
}

// reset discards any partially-buffered snapshot (called per new stream, and after a
// completed snapshot is applied).
func (a *chunkAssembler) reset() {
	a.epoch = 0
	a.active = false
	a.bySeq = nil
}

// Option configures a Client.
type Option func(*Client)

// WithDesired wires the desired-state handler (DesiredStore.Accept).
func WithDesired(fn DesiredFunc) Option { return func(c *Client) { c.onDesired = fn } }

// WithDelta wires the incremental DESIRED_DELTA handler (the hot path).
func WithDelta(fn DeltaFunc) Option { return func(c *Client) { c.onDelta = fn } }

// WithBackoff sets the reconnect backoff (default 1s).
func WithBackoff(d time.Duration) Option { return func(c *Client) { c.backoff = d } }

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) Option { return func(c *Client) { c.log = l } }

// Dial connects to the controller at addr for the given edge id.
func Dial(addr string, edge model.EdgeID, opts ...Option) (*Client, error) {
	// The controller's full DESIRED_STATE resync (sent when the per-edge push buffer
	// overflows under a bulk create) is ONE message carrying every member homed to this
	// edge. At scale that exceeds gRPC's 4 MB default recv cap → the stream errors → the
	// agent re-homes in a loop and NEVER applies the members (the data plane stays empty,
	// the controller logs delivery-loss). Raise the per-message recv limit so large
	// resyncs get through (512 MB ≈ a few million members/edge).
	//
	// The full DESIRED_STATE resync is now CHUNKED (DESIRED_STATE_CHUNK): a snapshot
	// over the controller's chunk threshold is streamed as a sequence of small
	// fragments the agent reassembles (acceptChunk), so a 10M-member edge no longer
	// needs an ever-larger single message. This 512 MB cap is kept purely as a safety
	// net — individual chunks are far smaller (target ≤32 MB).
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(512<<20)),
	)
	if err != nil {
		return nil, fmt.Errorf("grpcclient: dial %s: %w", addr, err)
	}
	return newClient(conn, edge, opts...), nil
}

// NewWithConn builds a client over an existing connection (tests / shared conn).
func NewWithConn(conn *grpc.ClientConn, edge model.EdgeID, opts ...Option) *Client {
	return newClient(conn, edge, opts...)
}

func newClient(conn *grpc.ClientConn, edge model.EdgeID, opts ...Option) *Client {
	c := &Client{
		conn: conn, svc: rpc.NewAgentServiceClient(conn), edge: edge,
		backoff: time.Second, log: slog.New(slog.DiscardHandler),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Register announces this agent and its NIC capacity (idempotent server-side).
// It rejects a controller whose schema version differs.
func (c *Client) Register(ctx context.Context, capacityBps uint64) error {
	resp, err := c.svc.Register(ctx, &rpc.RegisterRequest{
		EdgeId: string(c.edge), CapacityBps: capacityBps, SchemaVersion: model.SchemaVersion,
	})
	if err != nil {
		return err
	}
	if !resp.Accepted {
		return fmt.Errorf("grpcclient: registration rejected (controller schema %d, agent %d)",
			resp.SchemaVersion, model.SchemaVersion)
	}
	// REFACTOR step 4: the agent connects DIRECTLY to the server, so it needs no coverer
	// assignment — resp.Coverers is empty (the server leaves it nil for a direct connect)
	// and the agent stays on the server it reached. The old coverer-homing parse is gone.
	return nil
}

// RunDirect is the direct-to-server control loop (REFACTOR step 4): (re)register, then
// hold a Subscribe stream open, reconnecting with backoff until ctx is cancelled. It
// re-registers on every reconnect so a freshly-(re)started server replica re-learns this
// agent (registry seed + mon.Alive); the durable registry makes a repeat register
// idempotent. Replaces the homing.Director's per-coverer register+subscribe+rehome loop —
// there is one server target and no coverer assignment, so the gRPC ClientConn's own
// transparent reconnect handles endpoint churn beneath a single Subscribe pass. Blocks;
// run in a goroutine.
func (c *Client) RunDirect(ctx context.Context, capacityBps uint64) {
	for ctx.Err() == nil {
		if err := c.Register(ctx, capacityBps); err != nil {
			if ctx.Err() != nil {
				return
			}
			c.log.Warn("register failed; retrying", "err", err, "backoff", c.backoff)
		} else {
			c.log.Info("registered with server (direct)")
			if err := c.subscribeOnce(ctx); err != nil && ctx.Err() == nil {
				c.log.Warn("subscribe stream ended; reconnecting", "err", err, "backoff", c.backoff)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(c.backoff):
		}
	}
}

// SendReport delivers an EdgeReport to the controller (implements agent.ReportSink).
func (c *Client) SendReport(ctx context.Context, r model.EdgeReport) error {
	payload, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = c.svc.Report(ctx, &rpc.ReportRequest{
		EdgeId: string(c.edge), Generation: r.Generation, Payload: payload,
	})
	return err
}

// Run keeps a Subscribe stream open, dispatching directives, reconnecting with
// backoff until ctx is cancelled. Blocks; run in a goroutine.
func (c *Client) Run(ctx context.Context) {
	for {
		if err := c.subscribeOnce(ctx); err != nil && ctx.Err() == nil {
			c.log.Warn("subscribe stream ended; reconnecting", "err", err, "backoff", c.backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(c.backoff):
		}
	}
}

func (c *Client) subscribeOnce(ctx context.Context) error {
	stream, err := c.svc.Subscribe(ctx, &rpc.SubscribeRequest{EdgeId: string(c.edge)})
	if err != nil {
		return err
	}
	// A fresh stream means the controller re-sends the full snapshot; abandon any
	// partial chunk buffer from a broken prior stream (no partial is ever applied).
	c.chunkAsm.reset()
	for {
		d, err := stream.Recv()
		if err != nil {
			return err
		}
		c.dispatch(d)
	}
}

func (c *Client) dispatch(d *rpc.Directive) {
	switch d.Kind {
	case rpc.Directive_DESIRED_STATE:
		var st model.EdgeDesiredState
		if err := json.Unmarshal(d.Payload, &st); err != nil {
			c.log.Error("bad desired-state payload", "err", err)
			return
		}
		if st.SchemaVersion != model.SchemaVersion {
			c.log.Error("desired-state schema mismatch", "got", st.SchemaVersion, "want", model.SchemaVersion)
			return
		}
		if c.onDesired != nil {
			c.onDesired(st)
		}
	case rpc.Directive_DESIRED_STATE_CHUNK:
		// One fragment of a chunked FULL snapshot. Buffer by Epoch; on Last, MERGE into
		// one EdgeDesiredState and apply it through the SAME path as a plain
		// DESIRED_STATE (onDesired), so VPP + bird get the identical assembled state and
		// the agent echoes the SAME Generation. Never apply a partial.
		var ch model.EdgeDesiredStateChunk
		if err := json.Unmarshal(d.Payload, &ch); err != nil {
			c.log.Error("bad desired-state-chunk payload", "err", err)
			return
		}
		c.acceptChunk(ch)
	case rpc.Directive_DESIRED_DELTA:
		// Hot path: an incremental per-pool change. Unmarshal and hand to the delta
		// handler, which does gap detection (BaseGeneration vs last-applied) and
		// applies just the touched pools in O(delta). A gapped/divergent delta is
		// dropped there; the controller resends a full DESIRED_STATE resync.
		var delta model.EdgeDesiredDelta
		if err := json.Unmarshal(d.Payload, &delta); err != nil {
			c.log.Error("bad desired-delta payload", "err", err)
			return
		}
		if delta.SchemaVersion != model.SchemaVersion {
			c.log.Error("desired-delta schema mismatch", "got", delta.SchemaVersion, "want", model.SchemaVersion)
			return
		}
		if c.onDelta != nil {
			c.onDelta(delta)
		}
	default:
		// No non-desired-state directive kinds are dispatched to the agent today
		// (failover etc. are server-side). Unknown kinds are ignored.
		c.log.Debug("ignoring unhandled directive kind", "kind", d.Kind)
	}
}

// acceptChunk buffers one DESIRED_STATE_CHUNK fragment and, on its Last chunk,
// assembles + applies the full snapshot. Runs on the single dispatch goroutine, so
// the assembler needs no lock.
//
// Epoch supersession (latest-wins):
//   - newer Epoch  → discard the partially-buffered older snapshot and start fresh
//     (a newer full resync supersedes an abandoned partial — the controller starts a
//     new Epoch when it abandons a sequence on buffer-full).
//   - older Epoch  → drop the chunk (a late straggler from a superseded snapshot).
//   - same Epoch   → accumulate by Seq (dedup; a re-sent Seq overwrites identically).
//
// On Last: reassemble in Seq order and hand the full state to onDesired — the EXACT
// SAME apply path as a plain DESIRED_STATE (DesiredStore.Accept → reconcile → echo
// Generation). If Last never arrives the buffer is just left until a newer Epoch or a
// new stream resets it; no partial is ever applied.
func (c *Client) acceptChunk(ch model.EdgeDesiredStateChunk) {
	a := &c.chunkAsm
	switch {
	case !a.active || ch.Epoch > a.epoch:
		// New (or first) snapshot — supersede any older partial.
		if a.active && ch.Epoch > a.epoch {
			c.log.Warn("superseding partial chunked snapshot",
				"old_epoch", a.epoch, "new_epoch", ch.Epoch, "buffered", len(a.bySeq))
		}
		a.epoch = ch.Epoch
		a.active = true
		a.bySeq = map[uint32]model.EdgeDesiredStateChunk{}
	case ch.Epoch < a.epoch:
		// Straggler from a superseded snapshot — drop it.
		c.log.Warn("dropping chunk for stale epoch", "epoch", ch.Epoch, "current", a.epoch)
		return
	}
	a.bySeq[ch.Seq] = ch

	if !ch.Last {
		return
	}
	// Last arrived: we expect Seq 0..lastSeq all present (the controller pushes them in
	// order on one stream). If any are missing the snapshot is incomplete — DO NOT apply
	// a partial; keep the last good state and await a fresh resync (new Epoch / new
	// stream). Missing seqs only happen if the wire reordered/lost a frame, which gRPC's
	// ordered stream does not do silently, but we guard anyway.
	lastSeq := ch.Seq
	ordered := make([]model.EdgeDesiredStateChunk, 0, lastSeq+1)
	for i := uint32(0); i <= lastSeq; i++ {
		frag, ok := a.bySeq[i]
		if !ok {
			c.log.Error("chunked snapshot missing fragment; not applying partial",
				"epoch", a.epoch, "missing_seq", i, "last_seq", lastSeq)
			a.reset()
			return
		}
		ordered = append(ordered, frag)
	}

	st := model.AssembleChunks(ordered)
	a.reset()

	if st.SchemaVersion != model.SchemaVersion {
		c.log.Error("assembled desired-state schema mismatch", "got", st.SchemaVersion, "want", model.SchemaVersion)
		return
	}
	if c.onDesired != nil {
		c.onDesired(st) // identical apply path + echoed Generation as a plain DESIRED_STATE
	}
}

// Close shuts the connection.
func (c *Client) Close() error { return c.conn.Close() }
