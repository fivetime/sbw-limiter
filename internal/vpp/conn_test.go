package vpp

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"go.fd.io/govpp/adapter/mock"
	"go.fd.io/govpp/core"
)

// --- connect + compatibility against the govpp mock adapter ------------------

func TestConnectAndCompatibilityWithMock(t *testing.T) {
	// The mock registers all globally-registered binapi messages (our imported
	// bindings), so the real CheckCompatibility path succeeds.
	a := mock.NewVppAdapter()
	c, err := Connect(context.Background(), a, WithReadyTimeout(5*time.Second))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer c.Close()

	if !c.Healthy() {
		t.Fatal("expected healthy after connect")
	}
	ch, err := c.Channel()
	if err != nil {
		t.Fatalf("Channel: %v", err)
	}
	ch.Close()
}

func TestChannelFailsWhenUnhealthy(t *testing.T) {
	c := &Conn{done: make(chan struct{}), readyChan: make(chan struct{})}
	if _, err := c.Channel(); err == nil {
		t.Fatal("Channel should fail when not healthy")
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	a := mock.NewVppAdapter()
	c, err := Connect(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	c.Close() // must not panic / double-close
	if c.Healthy() {
		t.Error("should be unhealthy after Close")
	}
}

func TestReadyTimeoutWhenNeverConnects(t *testing.T) {
	a := mock.NewVppAdapter()
	a.MockConnectError(errors.New("nope")) // adapter never connects
	_, err := Connect(context.Background(), a, WithReadyTimeout(300*time.Millisecond),
		WithReconnect(1, 50*time.Millisecond))
	if err == nil {
		t.Fatal("expected readiness timeout")
	}
}

// --- reconnect state machine (injected checkCompat, synthetic events) --------

// newTestConn builds a Conn with an injected compatibility check and no real
// govpp connection, so the event-handling logic can be driven directly.
func newTestConn(compat func() error) *Conn {
	return &Conn{
		log:          slog.New(slog.DiscardHandler),
		done:         make(chan struct{}),
		reconnect:    make(chan struct{}, 1),
		healthNotify: make(chan struct{}, 1),
		readyChan:    make(chan struct{}),
		checkCompat:  compat,
	}
}

func TestHandleEventTransitions(t *testing.T) {
	compatCalls := 0
	c := newTestConn(func() error { compatCalls++; return nil })

	// Initial connect → healthy, compat checked, ready signaled.
	c.handleEvent(core.ConnectionEvent{State: core.Connected})
	if !c.Healthy() {
		t.Fatal("should be healthy after Connected")
	}
	if compatCalls != 1 {
		t.Errorf("compat checked %d times, want 1", compatCalls)
	}
	if !isReady(c) {
		t.Error("ready should be signaled after first healthy connect")
	}

	// Disconnect → unhealthy.
	c.handleEvent(core.ConnectionEvent{State: core.Disconnected})
	if c.Healthy() {
		t.Fatal("should be unhealthy after Disconnected")
	}

	// Reconnect → healthy again, compat re-verified (the key reconnect guard).
	c.handleEvent(core.ConnectionEvent{State: core.Connected})
	if !c.Healthy() {
		t.Fatal("should recover health after reconnect")
	}
	if compatCalls != 2 {
		t.Errorf("compat should be re-checked on reconnect: got %d", compatCalls)
	}
}

func TestReconnectWithIncompatibleBindingStaysUnhealthy(t *testing.T) {
	c := newTestConn(func() error { return errors.New("crc mismatch") })
	c.handleEvent(core.ConnectionEvent{State: core.Connected})
	if c.Healthy() {
		t.Fatal("incompatible bindings must not be marked healthy")
	}
	// Ready must NOT be signaled on an incompatible connect.
	if isReady(c) {
		t.Error("ready should not be signaled when incompatible")
	}
}

func TestFailedEventLogsUnhealthy(t *testing.T) {
	c := newTestConn(func() error { return nil })
	c.handleEvent(core.ConnectionEvent{State: core.Failed, Error: errors.New("gave up")})
	if c.Healthy() {
		t.Fatal("should be unhealthy after Failed")
	}
}

// isReady reports whether the ready signal has fired, without racing a context.
func isReady(c *Conn) bool {
	select {
	case <-c.readyChan:
		return true
	default:
		return false
	}
}

func gotReconnect(c *Conn) bool {
	select {
	case <-c.reconnect:
		return true
	default:
		return false
	}
}

// T-503: generation tracks healthy (re)connects and only a RECONNECT (not the
// first connect) signals a data-plane reinstall.
func TestGenerationAndReconnectSignal(t *testing.T) {
	c := newTestConn(func() error { return nil })

	// First connect: generation 1, ready signaled, NO reconnect signal.
	c.handleEvent(core.ConnectionEvent{State: core.Connected})
	if c.Generation() != 1 {
		t.Fatalf("generation = %d, want 1 after first connect", c.Generation())
	}
	if gotReconnect(c) {
		t.Error("first connect must not raise a reconnect signal")
	}

	// Drop and come back: generation 2, reconnect signaled (VPP may have restarted).
	c.handleEvent(core.ConnectionEvent{State: core.Disconnected})
	c.handleEvent(core.ConnectionEvent{State: core.Connected})
	if c.Generation() != 2 {
		t.Fatalf("generation = %d, want 2 after reconnect", c.Generation())
	}
	if !gotReconnect(c) {
		t.Error("reconnect must raise a reinstall signal")
	}
}

func TestReconnectSignalCoalesces(t *testing.T) {
	c := newTestConn(func() error { return nil })
	c.handleEvent(core.ConnectionEvent{State: core.Connected}) // first

	// Two reconnects before the loop drains → a single pending signal (buffer 1).
	for i := 0; i < 2; i++ {
		c.handleEvent(core.ConnectionEvent{State: core.Disconnected})
		c.handleEvent(core.ConnectionEvent{State: core.Connected})
	}
	if c.Generation() != 3 {
		t.Fatalf("generation = %d, want 3", c.Generation())
	}
	if !gotReconnect(c) {
		t.Fatal("expected a pending reconnect signal")
	}
	if gotReconnect(c) {
		t.Error("reconnect signals must coalesce, not queue")
	}
}

// An incompatible reconnect must not bump the generation or signal a reinstall —
// reinstalling into a VPP we can't speak to would fail anyway.
func TestIncompatibleReconnectDoesNotSignal(t *testing.T) {
	calls := 0
	c := newTestConn(func() error {
		calls++
		if calls == 1 {
			return nil // first connect ok
		}
		return errors.New("crc mismatch")
	})
	c.handleEvent(core.ConnectionEvent{State: core.Connected})
	c.handleEvent(core.ConnectionEvent{State: core.Disconnected})
	c.handleEvent(core.ConnectionEvent{State: core.Connected}) // incompatible
	if c.Generation() != 1 {
		t.Fatalf("generation = %d, want 1 (incompatible reconnect not counted)", c.Generation())
	}
	if gotReconnect(c) {
		t.Error("incompatible reconnect must not signal a reinstall")
	}
}

// TestHealthTransitionsNotify pins the event-driven report trigger (§4.2.4
// ★实测更新): each healthy↔unhealthy TRANSITION signals HealthTransitions
// exactly once (coalesced, non-blocking); a same-state event (Failed after
// Disconnected) is silent — so a flapping govpp event stream cannot amplify
// into a wake storm at the source.
func TestHealthTransitionsNotify(t *testing.T) {
	c := newTestConn(func() error { return nil })
	drained := func() bool {
		select {
		case <-c.HealthTransitions():
			return true
		default:
			return false
		}
	}

	c.handleEvent(core.ConnectionEvent{State: core.Connected}) // false→true
	if !drained() {
		t.Fatal("Connected transition did not signal")
	}
	c.handleEvent(core.ConnectionEvent{State: core.Disconnected}) // true→false
	if !drained() {
		t.Fatal("Disconnected transition did not signal")
	}
	// Same-state: Failed while already unhealthy → NO signal.
	c.handleEvent(core.ConnectionEvent{State: core.Failed, Error: errors.New("x")})
	if drained() {
		t.Fatal("same-state Failed event signalled a transition")
	}
	// Recovery signals again.
	c.handleEvent(core.ConnectionEvent{State: core.Connected}) // false→true
	if !drained() {
		t.Fatal("recovery transition did not signal")
	}
}

// TestHealthTransitionsCoalesce: burst transitions while nobody is draining
// collapse into (at most) one pending signal — the consumer snapshots Healthy()
// on wake, so the collapsed signal loses no state.
func TestHealthTransitionsCoalesce(t *testing.T) {
	c := newTestConn(func() error { return nil })
	for i := 0; i < 5; i++ {
		c.handleEvent(core.ConnectionEvent{State: core.Connected})
		c.handleEvent(core.ConnectionEvent{State: core.Disconnected})
	}
	n := 0
	for {
		select {
		case <-c.HealthTransitions():
			n++
			continue
		default:
		}
		break
	}
	if n != 1 {
		t.Fatalf("pending signals = %d, want exactly 1 (coalesced)", n)
	}
	if c.Healthy() {
		t.Fatal("final state should be unhealthy")
	}
}
