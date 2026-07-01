package ipfix

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestCollectorReceivesAndDecodes(t *testing.T) {
	var mu sync.Mutex
	var got []Record
	done := make(chan struct{}, 1)
	sink := func(recs []Record) {
		mu.Lock()
		got = append(got, recs...)
		mu.Unlock()
		select {
		case done <- struct{}{}:
		default:
		}
	}

	c, err := NewCollector("127.0.0.1:0", sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	// Send a template then a data datagram to the collector's bound port.
	raddr := c.LocalAddr().(*net.UDPAddr)
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("172.16.0.5")
	if _, err := conn.Write(msg(1, templateSet(256, v4fields...))); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(msg(1, dataSet(256, v4record(src, dst, 999, 3)))); err != nil {
		t.Fatal(err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("collector did not deliver records in time")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("want 1 record, got %d", len(got))
	}
	if p, _ := got[0].Uint(IEPacketDeltaCount); p != 999 {
		t.Fatalf("pkts = %d, want 999", p)
	}
}

func TestCollectorStopsOnContextCancel(t *testing.T) {
	c, err := NewCollector("127.0.0.1:0", func([]Record) {}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { c.Run(ctx); close(stopped) }()
	cancel()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}
