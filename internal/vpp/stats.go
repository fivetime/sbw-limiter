package vpp

import (
	"fmt"
	"strings"

	"go.fd.io/govpp/adapter"
	"go.fd.io/govpp/adapter/statsclient"
)

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
type StatsReader struct {
	client adapter.StatsAPI
}

// NewStatsReader connects to the VPP stats segment at socketPath (e.g.
// /run/vpp/stats.sock).
func NewStatsReader(socketPath string) (*StatsReader, error) {
	c := statsclient.NewStatsClient(socketPath)
	if err := c.Connect(); err != nil {
		return nil, fmt.Errorf("vpp: stats connect %s: %w", socketPath, err)
	}
	return &StatsReader{client: c}, nil
}

// Close disconnects from the stats segment.
func (s *StatsReader) Close() error {
	if s.client == nil {
		return nil
	}
	return s.client.Disconnect()
}

// ReadPolicers returns the current cumulative counters per VPP policer index.
// Indexes with no policer report zero; the caller filters to managed policers via
// the name→index map. Counters are summed over all worker threads.
func (s *StatsReader) ReadPolicers() (map[uint32]PolicerCounters, error) {
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
