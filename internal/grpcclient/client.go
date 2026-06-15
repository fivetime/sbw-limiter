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

// DirectiveFunc receives a non-desired-state directive (failover/urgent); the
// raw JSON payload is passed through for the agent to interpret.
type DirectiveFunc func(kind rpc.Directive_Kind, generation uint64, payload []byte)

// CovererFunc receives this agent's coverer assignment (DESIGN-liveness §10,
// L-06): on the Register response (initial homing) and on every REHOME directive
// (coverage moved). The homing director uses it to (re)connect to the primary.
type CovererFunc func(model.CovererAssignment)

// Client is the agent's connection to the controller.
type Client struct {
	conn *grpc.ClientConn
	svc  rpc.AgentServiceClient
	edge model.EdgeID

	onDesired   DesiredFunc
	onDirective DirectiveFunc
	onCoverers  CovererFunc
	backoff     time.Duration
	log         *slog.Logger
}

// Option configures a Client.
type Option func(*Client)

// WithDesired wires the desired-state handler (DesiredStore.Accept).
func WithDesired(fn DesiredFunc) Option { return func(c *Client) { c.onDesired = fn } }

// WithDirective wires the failover/urgent directive handler.
func WithDirective(fn DirectiveFunc) Option { return func(c *Client) { c.onDirective = fn } }

// WithCoverers wires the coverer-assignment handler (homing, L-06): called on the
// Register response and on every REHOME directive.
func WithCoverers(fn CovererFunc) Option { return func(c *Client) { c.onCoverers = fn } }

// WithBackoff sets the reconnect backoff (default 1s).
func WithBackoff(d time.Duration) Option { return func(c *Client) { c.backoff = d } }

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) Option { return func(c *Client) { c.log = l } }

// Dial connects to the controller at addr for the given edge id.
func Dial(addr string, edge model.EdgeID, opts ...Option) (*Client, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
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
	// Surface the coverer assignment so the homing director can connect to the
	// primary (L-06). Empty when sharding is off — the agent stays where it is.
	if len(resp.Coverers) > 0 && c.onCoverers != nil {
		var a model.CovererAssignment
		if err := json.Unmarshal(resp.Coverers, &a); err != nil {
			c.log.Error("bad coverers in register response", "err", err)
		} else {
			c.onCoverers(a)
		}
	}
	return nil
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

// SubscribePass runs ONE subscribe stream to completion (stream end or ctx
// cancel). The homing director (L-06) drives passes itself so it can react to
// each disconnect — re-home to a new primary or fall back to another coverer —
// instead of Run's blind same-endpoint reconnect.
func (c *Client) SubscribePass(ctx context.Context) error { return c.subscribeOnce(ctx) }

func (c *Client) subscribeOnce(ctx context.Context) error {
	stream, err := c.svc.Subscribe(ctx, &rpc.SubscribeRequest{EdgeId: string(c.edge)})
	if err != nil {
		return err
	}
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
	case rpc.Directive_REHOME:
		// Coverage moved (L-06): re-home to the new primary, keep the fallbacks.
		var a model.CovererAssignment
		if err := json.Unmarshal(d.Payload, &a); err != nil {
			c.log.Error("bad REHOME payload", "err", err)
			return
		}
		if c.onCoverers != nil {
			c.onCoverers(a)
		}
	default:
		if c.onDirective != nil {
			c.onDirective(d.Kind, d.Generation, d.Payload)
		}
	}
}

// Close shuts the connection.
func (c *Client) Close() error { return c.conn.Close() }
