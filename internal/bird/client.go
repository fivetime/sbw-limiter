// Package bird implements a client for the BIRD control socket (T-301,
// DESIGN.md §7). It speaks BIRD's line protocol directly — no birdc exec —
// and offers typed wrappers for the commands the edge-agent needs:
// configure (with check/timeout/confirm), show route count, show route
// exported, and show protocols.
//
// Wire protocol (verified against BIRD v3.3.1 nest/cli.c, client/client.c):
//
//	"XXXX msg\n"  — 4-digit code, space  = FINAL line of the reply
//	"XXXX-msg\n"  — 4-digit code, minus  = continuation line
//	" msg\n"      — single space         = continuation, code of previous line
//	"+msg\n"      — async message (CLI_ASYNC_CODE), not part of any reply
//
// Code classes: 0xxx success, 1xxx table entry, 2xxx table heading,
// 8xxx runtime error, 9xxx syntax error. On connect BIRD sends a banner
// reply: "0001 BIRD <version> ready."
package bird

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultTimeout bounds one command round-trip (write + full reply read).
// Configure on a full table can be slow; keep this generous.
const DefaultTimeout = 30 * time.Second

// ErrClosed is returned by calls on a client whose connection is gone. The
// caller owns reconnection (the agent reconciliation loop redials).
var ErrClosed = errors.New("bird: connection closed")

// CommandError is a BIRD-reported failure: a reply whose final code is in the
// runtime-error (8xxx) or syntax-error (9xxx) class. The previous
// configuration stays active when configure fails this way.
type CommandError struct {
	Code    int
	Message string
}

func (e *CommandError) Error() string {
	return fmt.Sprintf("bird: command failed (%04d): %s", e.Code, e.Message)
}

// Line is one numbered line of a reply.
type Line struct {
	Code int
	Text string
}

// Reply is a complete response to one command.
type Reply struct {
	Code  int      // code of the final line
	Lines []Line   // every numbered line, final included
	Async []string // async '+' messages received while reading
}

// Text joins all line texts with newlines.
func (r *Reply) Text() string {
	parts := make([]string, len(r.Lines))
	for i, l := range r.Lines {
		parts[i] = l.Text
	}
	return strings.Join(parts, "\n")
}

// Option configures a Client.
type Option func(*Client)

// WithTimeout sets the per-command deadline.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.timeout = d }
}

// Client is a BIRD control-socket client. Methods are safe for concurrent use;
// commands are serialized on the single connection.
type Client struct {
	mu      sync.Mutex
	conn    net.Conn
	br      *bufio.Reader
	timeout time.Duration
	banner  string
}

// Dial connects to the BIRD control socket at path (e.g. /run/bird.ctl) and
// consumes the banner reply.
func Dial(path string, opts ...Option) (*Client, error) {
	c := &Client{timeout: DefaultTimeout}
	for _, o := range opts {
		o(c)
	}

	conn, err := net.DialTimeout("unix", path, c.timeout)
	if err != nil {
		return nil, fmt.Errorf("bird: dial %s: %w", path, err)
	}
	c.conn = conn
	c.br = bufio.NewReader(conn)

	if err := conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("bird: set deadline: %w", err)
	}
	banner, err := c.readReply()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("bird: read banner: %w", err)
	}
	if banner.Code != 1 {
		_ = conn.Close()
		return nil, fmt.Errorf("bird: unexpected banner code %04d: %s", banner.Code, banner.Text())
	}
	c.banner = banner.Text()
	return c, nil
}

// Banner returns the raw connect banner, e.g. "BIRD 3.3.1 ready.".
func (c *Client) Banner() string { return c.banner }

var versionRe = regexp.MustCompile(`^BIRD (\S+) ready\.?`)

// Version returns the BIRD version parsed from the banner, or "" if unknown.
func (c *Client) Version() string {
	m := versionRe.FindStringSubmatch(c.banner)
	if m == nil {
		return ""
	}
	return m[1]
}

// Close closes the connection. Subsequent calls return ErrClosed.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeLocked()
}

func (c *Client) closeLocked() error {
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	c.br = nil
	return err
}

// Do sends one command and reads its complete reply. A final code >= 8000 is
// returned as *CommandError alongside the reply. I/O errors close the
// connection (the caller redials).
func (c *Client) Do(cmd string) (*Reply, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil, ErrClosed
	}
	deadline := time.Now().Add(c.timeout)
	if err := c.conn.SetDeadline(deadline); err != nil {
		_ = c.closeLocked()
		return nil, fmt.Errorf("bird: set deadline: %w", err)
	}
	if _, err := c.conn.Write([]byte(cmd + "\n")); err != nil {
		_ = c.closeLocked()
		return nil, fmt.Errorf("bird: write %q: %w", cmd, err)
	}
	reply, err := c.readReply()
	if err != nil {
		_ = c.closeLocked()
		return nil, fmt.Errorf("bird: read reply to %q: %w", cmd, err)
	}
	if reply.Code >= 8000 {
		return reply, &CommandError{Code: reply.Code, Message: reply.Text()}
	}
	return reply, nil
}

// readReply reads lines until the final line of one reply. Caller holds the
// lock and has set the deadline.
func (c *Client) readReply() (*Reply, error) {
	r := &Reply{}
	lastCode := -1
	for {
		raw, err := c.br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line := strings.TrimRight(raw, "\r\n")
		switch {
		case line == "":
			// Defensive: protocol never emits bare empty lines.
			continue
		case line[0] == '+':
			r.Async = append(r.Async, line[1:])
		case line[0] == ' ':
			if lastCode < 0 {
				return nil, fmt.Errorf("continuation line before any coded line: %q", line)
			}
			r.Lines = append(r.Lines, Line{Code: lastCode, Text: line[1:]})
		default:
			if len(line) < 5 {
				return nil, fmt.Errorf("malformed reply line: %q", line)
			}
			code, err := strconv.Atoi(line[:4])
			if err != nil {
				return nil, fmt.Errorf("malformed reply code in %q: %w", line, err)
			}
			sep, text := line[4], line[5:]
			r.Lines = append(r.Lines, Line{Code: code, Text: text})
			lastCode = code
			switch sep {
			case ' ':
				r.Code = code
				return r, nil
			case '-':
				// continuation; keep reading
			default:
				return nil, fmt.Errorf("malformed reply separator in %q", line)
			}
		}
	}
}
