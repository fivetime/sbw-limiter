package birdfeed

import (
	"bufio"
	"net"
	"sync"
	"time"
)

// Client is the /run/bird/api.sock stream client (BF-02): a buffered writer over
// a Unix socket with lazy (re)connect. Writes are best-effort and batched in the
// bufio; errors surface at flush(), and the Feed reacts to a flush error by
// reconnecting + a full resync (the proto's grace window covers the gap).
//
// LIVENESS (the bird-restart hole): the api proto is one-way — bird never sends
// bytes back — so on a STABLE desired state the incremental diff writes nothing
// and a dead peer is never exercised by the write path. A `conn != nil` flag
// alone therefore stays true forever after a bird restart, the Feed never
// reconnects/resyncs, and the steering (anchors + flowspec) — the one thing
// bird cannot recover by itself in api mode (no file, no peer to learn it
// from; the agent IS the source) — stays lost until the agent restarts.
// Fix: each connect spawns a watcher goroutine parked in conn.Read(); since the
// peer never sends, a Read return means EOF/reset = bird closed (restart/stop).
// The watcher tears the connection down and fires onDown (the Feed wires it to
// Wake), so the next pass reconnects + full-resyncs within seconds instead of
// never. Zero steady-state cost: a parked Read is free — no polling, no traffic,
// and the incremental feed path is untouched.
type Client struct {
	path   string
	onDown func() // fired from the watcher goroutine when the PEER kills the conn; nil ok

	mu   sync.Mutex // guards conn/w against the watcher goroutine
	conn net.Conn
	w    *bufio.Writer
}

// NewClient returns a client for the given socket path (not yet connected).
func NewClient(path string) *Client { return &Client{path: path} }

func (c *Client) connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}

func (c *Client) connect() error {
	conn, err := net.DialTimeout("unix", c.path, 3*time.Second)
	if err != nil {
		return err
	}
	c.mu.Lock()
	if c.conn != nil { // defensive: drop a stale conn instead of leaking it
		_ = c.conn.Close()
	}
	c.conn = conn
	c.w = bufio.NewWriterSize(conn, 1<<16) // 64 KiB: batch many small frames per syscall
	c.mu.Unlock()
	go c.watch(conn)
	return nil
}

// watch parks in Read until the connection dies. The api proto never sends data
// to the agent, so any received bytes are discarded (future-proof) and only an
// error (EOF on bird close/restart, reset, or our own close()) ends the loop.
// If the dying conn is still the CURRENT one, the peer killed it: tear it down
// and fire onDown so the Feed reconnects + resyncs now. If it is no longer
// current (we closed it ourselves — flush error path or a reconnect), stay
// silent: that path already handles its own resync.
func (c *Client) watch(conn net.Conn) {
	buf := make([]byte, 512)
	for {
		if _, err := conn.Read(buf); err != nil {
			break
		}
	}
	c.mu.Lock()
	peerDied := c.conn == conn
	if peerDied {
		_ = c.conn.Close()
		c.conn = nil
		c.w = nil
	}
	c.mu.Unlock()
	if peerDied && c.onDown != nil {
		c.onDown()
	}
}

// write buffers one frame; a write error tears the connection down so the next
// flush() reports it (best-effort, the resync heals any partial pass).
func (c *Client) write(frame []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.w == nil {
		return
	}
	if _, err := c.w.Write(frame); err != nil {
		c.closeLocked()
	}
}

func (c *Client) flush() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.w == nil {
		return net.ErrClosed
	}
	if err := c.w.Flush(); err != nil {
		c.closeLocked()
		return err
	}
	return nil
}

func (c *Client) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked()
}

// closeLocked tears the connection down; the watcher's pending Read returns,
// sees c.conn != its conn, and exits silently. Callers hold c.mu.
func (c *Client) closeLocked() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.conn = nil
	c.w = nil
}
