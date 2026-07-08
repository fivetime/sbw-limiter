package birdfeed

import (
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// sockListener spins a Unix listener on a temp path and hands accepted conns out.
func sockListener(t *testing.T) (string, net.Listener, chan net.Conn) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "api.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()
	return path, l, accepted
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

// The bird-restart hole: the api proto is one-way, so with a stable desired
// state nothing ever exercises the socket and a dead peer must be detected by
// the watcher, not by a write error. Peer closes → connected() flips false and
// onDown fires (the Feed wires it to Wake for an immediate reconnect+resync).
func TestClientWatcherDetectsPeerClose(t *testing.T) {
	path, _, accepted := sockListener(t)
	c := NewClient(path)
	var downs atomic.Int32
	c.onDown = func() { downs.Add(1) }

	if err := c.connect(); err != nil {
		t.Fatal(err)
	}
	peer := <-accepted
	if !c.connected() {
		t.Fatal("connected() false after connect")
	}

	_ = peer.Close() // bird restarts: peer side closes
	waitFor(t, "connected()==false after peer close", func() bool { return !c.connected() })
	waitFor(t, "onDown fired", func() bool { return downs.Load() == 1 })
}

// Our own close() (flush-error path / shutdown) must NOT fire onDown — those
// paths handle their own resync; onDown is only for an asymmetric peer death.
func TestClientOwnCloseIsSilent(t *testing.T) {
	path, _, accepted := sockListener(t)
	c := NewClient(path)
	var downs atomic.Int32
	c.onDown = func() { downs.Add(1) }

	if err := c.connect(); err != nil {
		t.Fatal(err)
	}
	<-accepted
	c.close()
	if c.connected() {
		t.Fatal("connected() true after close")
	}
	time.Sleep(100 * time.Millisecond) // give the watcher time to (wrongly) fire
	if n := downs.Load(); n != 0 {
		t.Fatalf("onDown fired %d times on own close (want 0)", n)
	}
}

// Reconnect after a peer death arms a fresh watcher: a second peer death on the
// NEW connection is detected too (one watcher per connection, no stale carryover).
func TestClientWatcherRearmsOnReconnect(t *testing.T) {
	path, _, accepted := sockListener(t)
	c := NewClient(path)
	var downs atomic.Int32
	c.onDown = func() { downs.Add(1) }

	if err := c.connect(); err != nil {
		t.Fatal(err)
	}
	peer := <-accepted
	_ = peer.Close()
	waitFor(t, "first death detected", func() bool { return downs.Load() == 1 && !c.connected() })

	if err := c.connect(); err != nil {
		t.Fatal(err)
	}
	peer2 := <-accepted
	if !c.connected() {
		t.Fatal("connected() false after reconnect")
	}
	_ = peer2.Close()
	waitFor(t, "second death detected", func() bool { return downs.Load() == 2 && !c.connected() })
}

// Data from the peer (a future proto extension) must be discarded, not treated
// as death: the watcher only reacts to Read errors.
func TestClientWatcherIgnoresInboundData(t *testing.T) {
	path, _, accepted := sockListener(t)
	c := NewClient(path)
	var downs atomic.Int32
	c.onDown = func() { downs.Add(1) }

	if err := c.connect(); err != nil {
		t.Fatal(err)
	}
	peer := <-accepted
	if _, err := peer.Write([]byte("future-proto-bytes")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if !c.connected() || downs.Load() != 0 {
		t.Fatalf("inbound data must not kill the conn: connected=%v downs=%d", c.connected(), downs.Load())
	}
	_ = peer.Close()
	waitFor(t, "real death still detected", func() bool { return downs.Load() == 1 })
}
