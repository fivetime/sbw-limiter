package vpp

import (
	"testing"

	govppapi "go.fd.io/govpp/api"
)

func TestFoldInterfaceStats(t *testing.T) {
	in := govppapi.InterfaceStats{Interfaces: []govppapi.InterfaceCounters{
		{
			InterfaceIndex: 3, InterfaceName: "host-macc",
			Rx:    govppapi.InterfaceCounterCombined{Packets: 100, Bytes: 12000},
			Tx:    govppapi.InterfaceCounterCombined{Packets: 90, Bytes: 10800},
			Drops: 7, RxErrors: 2, RxMiss: 5, RxNoBuf: 1, Punts: 0,
		},
	}}
	got := foldInterfaceStats(in)
	if len(got) != 1 {
		t.Fatalf("want 1 iface, got %d", len(got))
	}
	c := got[0]
	if c.SwIfIndex != 3 || c.Name != "host-macc" || c.RxPackets != 100 || c.TxBytes != 10800 ||
		c.Drops != 7 || c.RxErrors != 2 || c.RxMiss != 5 || c.RxNoBuf != 1 {
		t.Fatalf("fold mismatch: %+v", c)
	}
}

func TestFoldErrorStatsSumsAndDropsIdle(t *testing.T) {
	in := govppapi.ErrorStats{Errors: []govppapi.ErrorCounter{
		{CounterName: "ip4-input/ip4 no route", Values: []uint64{4, 6, 0}}, // 10 across 3 threads
		{CounterName: "ip4-glean/idle", Values: []uint64{0, 0}},            // idle → dropped
		{CounterName: "ethernet-input/rx-miss", Values: []uint64{3}},       // single thread
	}}
	got := foldErrorStats(in)
	if len(got) != 2 {
		t.Fatalf("idle counters must be dropped; want 2, got %d (%+v)", len(got), got)
	}
	byName := map[string]uint64{}
	for _, e := range got {
		byName[e.Name] = e.Count
	}
	if byName["ip4-input/ip4 no route"] != 10 {
		t.Fatalf("per-thread values must sum to 10, got %d", byName["ip4-input/ip4 no route"])
	}
	if byName["ethernet-input/rx-miss"] != 3 {
		t.Fatalf("single-thread counter = %d, want 3", byName["ethernet-input/rx-miss"])
	}
	if _, present := byName["ip4-glean/idle"]; present {
		t.Fatal("zero-count counter must be excluded")
	}
}
