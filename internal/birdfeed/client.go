package birdfeed

import (
	"bufio"
	"net"
	"time"
)

// Client is the /run/bird/api.sock stream client (BF-02): a buffered writer over
// a Unix socket with lazy (re)connect. Writes are best-effort and batched in the
// bufio; errors surface at flush(), and the Feed reacts to a flush error by
// reconnecting + a full resync (the proto's grace window covers the gap).
type Client struct {
	path string
	conn net.Conn
	w    *bufio.Writer
}

// NewClient returns a client for the given socket path (not yet connected).
func NewClient(path string) *Client { return &Client{path: path} }

func (c *Client) connected() bool { return c.conn != nil }

func (c *Client) connect() error {
	conn, err := net.DialTimeout("unix", c.path, 3*time.Second)
	if err != nil {
		return err
	}
	c.conn = conn
	c.w = bufio.NewWriterSize(conn, 1<<16) // 64 KiB: batch many small frames per syscall
	return nil
}

// write buffers one frame; a write error tears the connection down so the next
// flush() reports it (best-effort, the resync heals any partial pass).
func (c *Client) write(frame []byte) {
	if c.w == nil {
		return
	}
	if _, err := c.w.Write(frame); err != nil {
		c.close()
	}
}

func (c *Client) flush() error {
	if c.w == nil {
		return net.ErrClosed
	}
	if err := c.w.Flush(); err != nil {
		c.close()
		return err
	}
	return nil
}

func (c *Client) close() {
	if c.conn != nil {
		c.conn.Close()
	}
	c.conn = nil
	c.w = nil
}
