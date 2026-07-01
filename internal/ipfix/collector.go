package ipfix

import (
	"context"
	"fmt"
	"log/slog"
	"net"
)

// maxDatagram bounds a single IPFIX UDP read. flowprobe exports fit comfortably; a
// jumbo export is truncated (the decoder then rejects the malformed tail) rather than
// growing the buffer unboundedly.
const maxDatagram = 65535

// Collector receives flowprobe IPFIX exports on a localhost UDP socket, decodes each
// datagram with one stateful Decoder (so templates carry across datagrams), and hands
// the decoded flow records to sink. The sink runs on the read goroutine and must not
// block; a records-less datagram (templates only) does not call it.
type Collector struct {
	conn *net.UDPConn
	dec  *Decoder
	sink func([]Record)
	log  *slog.Logger
}

// NewCollector binds a UDP socket at addr (e.g. "127.0.0.1:4739", or "127.0.0.1:0" to
// let the OS pick — read the chosen port back via LocalAddr for the exporter config).
func NewCollector(addr string, sink func([]Record), log *slog.Logger) (*Collector, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("ipfix: resolve %q: %w", addr, err)
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, fmt.Errorf("ipfix: listen %q: %w", addr, err)
	}
	return &Collector{conn: conn, dec: NewDecoder(), sink: sink, log: log}, nil
}

// LocalAddr is the bound socket address (its port is what the flowprobe IPFIX exporter
// must target).
func (c *Collector) LocalAddr() net.Addr { return c.conn.LocalAddr() }

// Run reads and decodes datagrams until ctx is cancelled. A decode error on one
// datagram is logged and skipped — a malformed export must not stop the collector.
func (c *Collector) Run(ctx context.Context) {
	go func() {
		<-ctx.Done()
		_ = c.conn.Close() // unblock the ReadFromUDP below
	}()
	buf := make([]byte, maxDatagram)
	for {
		n, _, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				c.log.Info("ipfix collector stopped")
				return
			}
			c.log.Warn("ipfix read failed", "err", err)
			continue
		}
		recs, err := c.dec.Decode(buf[:n])
		if err != nil {
			c.log.Warn("ipfix decode failed", "err", err, "bytes", n)
			continue
		}
		if len(recs) > 0 {
			c.sink(recs)
		}
	}
}

// Close releases the socket (Run also closes it on ctx cancel; Close is the explicit
// teardown for a collector that was never Run).
func (c *Collector) Close() error { return c.conn.Close() }
