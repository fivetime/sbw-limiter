package vpp

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"go.fd.io/govpp/adapter"
	"go.fd.io/govpp/adapter/statsclient"
	govppapi "go.fd.io/govpp/api"
	govppcore "go.fd.io/govpp/core"
)

// IsStatsDisconnected reports whether a stats read failed because the VPP stats
// segment is gone — the socket was removed, which govpp detects via fsnotify
// (event-driven, immediate). This is the authoritative "VPP process died/
// restarted" signal off the stats channel (§6.44): distinct from a transient
// gauge-not-found (segment still mapped, VPP alive).
func IsStatsDisconnected(err error) bool {
	return errors.Is(err, adapter.ErrStatsDisconnected)
}

// PolicerCounters is one policer's cumulative conform/exceed/violate combined
// counters (packets + bytes), summed across VPP worker threads.
type PolicerCounters struct {
	ConformPackets, ConformBytes uint64
	ExceedPackets, ExceedBytes   uint64
	ViolatePackets, ViolateBytes uint64
}

// VPP exposes policer counters in the stats segment as three combined-counter
// vectors indexed by VPP policer index (T-1001). The agent reads them here and
// maps index→pool via the reconciler's policer name→index map.
const (
	statPolicerConform = "/net/policer/conform"
	statPolicerExceed  = "/net/policer/exceed"
	statPolicerViolate = "/net/policer/violate"
)

// StatsReader reads the VPP stats segment over its own socket connection
// (separate from the binary-API connection — the stats segment is shared memory,
// not the API). Read-only and non-destructive: reading never resets a counter.
//
// It exposes two layers: ReadPolicers uses the RAW adapter (index-keyed policer
// vectors the high-level API does not surface), while ReadInterfaceStats /
// ReadErrorStats use govpp's high-level StatsConnection (per-interface drop counters
// and per-node drop-reason counters, §4.2.2). Both share the one connected adapter, so
// all reads are serialized by mu (the metering loop and the loss loop may both read).
type StatsReader struct {
	mu     sync.Mutex
	client adapter.StatsAPI           // raw, for the index-keyed policer dump
	conn   *govppcore.StatsConnection // high-level, for interface / error stats
}

// NewStatsReader connects to the VPP stats segment at socketPath (e.g.
// /run/vpp/stats.sock).
func NewStatsReader(socketPath string) (*StatsReader, error) {
	c := statsclient.NewStatsClient(socketPath)
	conn, err := govppcore.ConnectStats(c) // connects the adapter (do not Connect() twice)
	if err != nil {
		return nil, fmt.Errorf("vpp: stats connect %s: %w", socketPath, err)
	}
	return &StatsReader{client: c, conn: conn}, nil
}

// Close disconnects from the stats segment.
func (s *StatsReader) Close() error {
	if s.conn != nil {
		s.conn.Disconnect() // disconnects the underlying stats socket
	}
	return nil
}

// InterfaceStats is one interface's cumulative rx/tx + error/drop counters from the
// stats segment — the §4.2.6 device-level drop backstop (a wedged worker → all
// interfaces' Drops/RxMiss spike) and corroboration for the §4.2 forwarding probe.
type InterfaceStats struct {
	SwIfIndex          uint32
	Name               string
	RxPackets, RxBytes uint64
	TxPackets, TxBytes uint64
	Drops              uint64
	RxErrors           uint64
	RxMiss             uint64
	RxNoBuf            uint64
	Punts              uint64
}

// ErrorStat is one VPP node/reason drop-cause counter, summed over worker threads.
// Name is "<node>/<reason>" (e.g. "ip4-input/ip4 no route"); Count is the cumulative
// hit count — the drop-CAUSE the §4.2 forwarding-health story reads (a rising
// "ip4 no route" is forwarding breakage, distinct from policer / congestion drops).
type ErrorStat struct {
	Name  string
	Count uint64
}

// ReadInterfaceStats returns per-interface counters (keyed nowhere; caller maps by
// SwIfIndex/Name). Summed across worker threads by govpp.
func (s *StatsReader) ReadInterfaceStats() ([]InterfaceStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var is govppapi.InterfaceStats
	if err := s.conn.GetInterfaceStats(&is); err != nil {
		return nil, fmt.Errorf("vpp: get interface stats: %w", err)
	}
	return foldInterfaceStats(is), nil
}

// ReadErrorStats returns every NON-ZERO node/reason drop counter (the full set is huge
// and mostly idle). Summed across worker threads.
func (s *StatsReader) ReadErrorStats() ([]ErrorStat, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var es govppapi.ErrorStats
	if err := s.conn.GetErrorStats(&es); err != nil {
		return nil, fmt.Errorf("vpp: get error stats: %w", err)
	}
	return foldErrorStats(es), nil
}

// foldInterfaceStats projects govpp's InterfaceStats onto the local struct (pure).
func foldInterfaceStats(is govppapi.InterfaceStats) []InterfaceStats {
	out := make([]InterfaceStats, 0, len(is.Interfaces))
	for _, c := range is.Interfaces {
		out = append(out, InterfaceStats{
			SwIfIndex: c.InterfaceIndex, Name: c.InterfaceName,
			RxPackets: c.Rx.Packets, RxBytes: c.Rx.Bytes,
			TxPackets: c.Tx.Packets, TxBytes: c.Tx.Bytes,
			Drops: c.Drops, RxErrors: c.RxErrors, RxMiss: c.RxMiss,
			RxNoBuf: c.RxNoBuf, Punts: c.Punts,
		})
	}
	return out
}

// foldErrorStats sums each error counter's per-thread values and drops the idle ones
// (Count==0), so the caller sees only reasons that actually fired (pure).
func foldErrorStats(es govppapi.ErrorStats) []ErrorStat {
	out := make([]ErrorStat, 0, len(es.Errors))
	for _, e := range es.Errors {
		var sum uint64
		for _, v := range e.Values {
			sum += v
		}
		if sum == 0 {
			continue
		}
		out = append(out, ErrorStat{Name: e.CounterName, Count: sum})
	}
	return out
}

// ReadGauge reads a single scalar gauge from the stats segment by exact name
// (e.g. "/probe/fib/fwd/reachable", published by the probe plugin's process
// node). The value is stored as an f64 but always holds an integer; it is
// returned as a uint64. Returns an error if the name is absent (e.g. the probe
// target has not been registered yet) or is not a scalar. Reading the stats
// segment is a shared-memory operation — it never touches VPP's main thread,
// which is the whole point of moving forwarding liveness off the cli_inband ping.
func (s *StatsReader) ReadGauge(name string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := s.client.DumpStats(name)
	if err != nil {
		return 0, fmt.Errorf("vpp: dump gauge %s: %w", name, err)
	}
	for _, e := range entries {
		if string(e.Name) != name {
			continue // DumpStats matches by prefix; take the exact leaf
		}
		v, ok := e.Data.(adapter.ScalarStat)
		if !ok {
			return 0, fmt.Errorf("vpp: gauge %s is not a scalar (%T)", name, e.Data)
		}
		return uint64(v), nil
	}
	return 0, fmt.Errorf("vpp: gauge %s not found", name)
}

// ReadPolicers returns the current cumulative counters per VPP policer index.
// Indexes with no policer report zero; the caller filters to managed policers via
// the name→index map. Counters are summed over all worker threads.
func (s *StatsReader) ReadPolicers() (map[uint32]PolicerCounters, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := s.client.DumpStats(statPolicerConform, statPolicerExceed, statPolicerViolate)
	if err != nil {
		return nil, fmt.Errorf("vpp: dump policer stats: %w", err)
	}
	out := map[uint32]PolicerCounters{}
	for _, e := range entries {
		ccs, ok := e.Data.(adapter.CombinedCounterStat)
		if !ok {
			continue // not a combined-counter vector (shouldn't happen for these names)
		}
		name := string(e.Name)
		// ccs is [thread][index]; widest thread gives the index count.
		n := 0
		for _, thread := range ccs {
			if len(thread) > n {
				n = len(thread)
			}
		}
		for i := 0; i < n; i++ {
			var pkts, bytes uint64
			for _, thread := range ccs {
				if i < len(thread) {
					pkts += thread[i].Packets()
					bytes += thread[i].Bytes()
				}
			}
			c := out[uint32(i)]
			switch {
			case strings.HasSuffix(name, "conform"):
				c.ConformPackets, c.ConformBytes = pkts, bytes
			case strings.HasSuffix(name, "exceed"):
				c.ExceedPackets, c.ExceedBytes = pkts, bytes
			case strings.HasSuffix(name, "violate"):
				c.ViolatePackets, c.ViolateBytes = pkts, bytes
			}
			out[uint32(i)] = c
		}
	}
	return out, nil
}
