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

// statLoopsPerWorker is VPP's per-worker vlib main-loop iteration counter. It
// advances every loop a thread runs — the cheapest, **traffic-independent**
// "data-plane engine alive" signal (L4, DESIGN-liveness §4.1). The L2 ControlPing
// only attests the MAIN thread; a worker can wedge (packets black-holed, policers
// dead) while the main thread still answers ping — that blind spot is what this
// catches. Single-threaded VPP carries thread 0's loops here; with workers, one
// entry per worker. (`/sys/heartbeat` is a main-thread process tick — L2, not L4.)
const statLoopsPerWorker = "/sys/loops_per_worker"

// ReadLoopsPerWorker returns each worker thread's cumulative main-loop count. The
// engine is alive iff these advance between reads; a thread frozen while it has
// work is wedged (L4, blind to the ControlPing). Returns the per-worker slice.
func (s *StatsReader) ReadLoopsPerWorker() ([]uint64, error) {
	entries, err := s.client.DumpStats(statLoopsPerWorker)
	if err != nil {
		return nil, fmt.Errorf("vpp: dump %s: %w", statLoopsPerWorker, err)
	}
	for _, e := range entries {
		// loops_per_worker is a per-thread simple counter: [thread][0].
		scs, ok := e.Data.(adapter.SimpleCounterStat)
		if !ok {
			continue
		}
		out := make([]uint64, 0, len(scs))
		for _, thread := range scs {
			if len(thread) > 0 {
				out = append(out, uint64(thread[0]))
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("vpp: %s not a simple-counter stat (got none)", statLoopsPerWorker)
}

// EngineLiveness tracks loops_per_worker across reads to answer the L4 question
// the phase needs — "is each VPP data-plane worker advancing?" — the ground truth
// the ControlPing (L2, main thread) cannot see. **Per-worker on purpose**: a single
// hung worker is a *partial* outage (the flows RSS-hashed to it die while the others
// forward), which a coarse "any worker advanced" check would mask. In polling mode
// an idle worker still spins (loop advances), so a frozen loop is a genuine wedge,
// not idleness. Not goroutine-safe; call from one probe loop.
type EngineLiveness struct {
	read      func() ([]uint64, error)
	threshold int
	last      []uint64
	stalls    []int // per-worker consecutive-stall count
}

// NewEngineLiveness builds an L4 tracker over the stats reader. threshold is the
// number of consecutive frozen samples before a worker is called wedged (rides out
// a transient where a worker briefly didn't advance within one sampling window).
func NewEngineLiveness(r *StatsReader, threshold int) *EngineLiveness {
	return newEngineLiveness(r.ReadLoopsPerWorker, threshold)
}

func newEngineLiveness(read func() ([]uint64, error), threshold int) *EngineLiveness {
	if threshold < 1 {
		threshold = 1
	}
	return &EngineLiveness{read: read, threshold: threshold}
}

// Stalled samples loops_per_worker and returns the indices of workers whose loop
// counter has stayed frozen for `threshold` consecutive samples — wedged engines.
// Empty = every worker advancing (engine healthy). The first call, and any change
// in worker count (VPP restart), reseeds and returns no verdict. A read error
// surfaces; the caller treats "engine status unknown" as no-stall — never
// synthesize a wedge from a missing stat.
func (e *EngineLiveness) Stalled() ([]int, error) {
	cur, err := e.read()
	if err != nil {
		return nil, err
	}
	if len(e.last) != len(cur) {
		e.last = cur
		e.stalls = make([]int, len(cur))
		return nil, nil
	}
	var wedged []int
	for i := range cur {
		if cur[i] > e.last[i] {
			e.stalls[i] = 0
		} else {
			e.stalls[i]++
			if e.stalls[i] >= e.threshold {
				wedged = append(wedged, i)
			}
		}
	}
	e.last = cur
	return wedged, nil
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
