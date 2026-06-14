// Package agent's metering loop (T-1001, limiter §4.3/§8.1) reads the VPP policer
// counters every interval and ships RAW CUMULATIVE samples downstream (Kafka →
// ClickHouse → BSS). The system is a telemetry SOURCE only: it collects and
// pushes; BSS computes bandwidth/volume/95th/口径/漏网. One sample per pool per
// direction (the shared policer is pool-grained; members share the bucket, so
// there is no per-member metering).
package agent

import (
	"context"
	"log/slog"
	"time"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/vpp"
)

// MeteringSample is one (pool, direction) record: the raw cumulative VPP policer
// counters at a point in time. conform = delivered (billable); conform+exceed+
// violate = offered (what arrived); the gap = dropped (attack/SLA signal). BSS
// derives everything from these; the agent computes nothing.
type MeteringSample struct {
	TS           int64  `json:"ts"`
	Edge         string `json:"edge"`
	PoolID       uint64 `json:"pool_id"`
	Dir          string `json:"dir"`
	ConformPkts  uint64 `json:"conform_pkts"`
	ConformBytes uint64 `json:"conform_bytes"`
	ExceedPkts   uint64 `json:"exceed_pkts"`
	ExceedBytes  uint64 `json:"exceed_bytes"`
	ViolatePkts  uint64 `json:"violate_pkts"`
	ViolateBytes uint64 `json:"violate_bytes"`
}

// MeteringSink ships a batch of samples downstream (the Kafka producer). A
// transient error is non-fatal: the next tick re-sends fresh CUMULATIVE counters,
// so a dropped batch costs resolution for that interval, never the running total.
type MeteringSink interface {
	Emit(ctx context.Context, samples []MeteringSample) error
}

// policerStats is the subset of *vpp.StatsReader the loop needs (test seam).
type policerStats interface {
	ReadPolicers() (map[uint32]vpp.PolicerCounters, error)
}

// Metering periodically reads VPP policer counters, maps each managed policer to
// its pool via the reconciler's name→index snapshot, and pushes raw samples.
type Metering struct {
	edge    model.EdgeID
	stats   policerStats
	indexes func() map[string]uint32 // reconciler.PolicerIndexes (name → VPP index)
	sink    MeteringSink
	now     func() int64
	log     *slog.Logger
}

// MeteringOption configures a Metering.
type MeteringOption func(*Metering)

// WithMeteringClock overrides the timestamp source (tests).
func WithMeteringClock(now func() int64) MeteringOption { return func(m *Metering) { m.now = now } }

// WithMeteringLogger sets the logger (default: discard).
func WithMeteringLogger(l *slog.Logger) MeteringOption { return func(m *Metering) { m.log = l } }

// NewMetering builds the loop. `indexes` supplies the current policer name→index
// map (the reconciler's PolicerIndexes); `stats` reads the VPP stats segment.
func NewMetering(edge model.EdgeID, stats policerStats, indexes func() map[string]uint32, sink MeteringSink, opts ...MeteringOption) *Metering {
	m := &Metering{
		edge: edge, stats: stats, indexes: indexes, sink: sink,
		now: func() int64 { return time.Now().Unix() },
		log: slog.New(slog.DiscardHandler),
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Collect reads the current counters and builds one sample per managed policer
// (one per pool per direction). A policer in the index map but absent from the
// stats read reports zero — still emitted, so the time series stays continuous.
func (m *Metering) Collect() ([]MeteringSample, error) {
	counters, err := m.stats.ReadPolicers()
	if err != nil {
		return nil, err
	}
	idx := m.indexes()
	ts := m.now()
	out := make([]MeteringSample, 0, len(idx))
	for name, i := range idx {
		poolID, dir, err := model.ParsePolicerName(name)
		if err != nil {
			continue // not a managed pool policer
		}
		c := counters[i]
		out = append(out, MeteringSample{
			TS: ts, Edge: string(m.edge), PoolID: uint64(poolID), Dir: dir.String(),
			ConformPkts: c.ConformPackets, ConformBytes: c.ConformBytes,
			ExceedPkts: c.ExceedPackets, ExceedBytes: c.ExceedBytes,
			ViolatePkts: c.ViolatePackets, ViolateBytes: c.ViolateBytes,
		})
	}
	return out, nil
}

// Run collects and ships every interval until ctx is cancelled. Blocks; run in a
// goroutine. A collect or emit error is logged, not fatal (next tick retries).
func (m *Metering) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			m.log.Info("metering loop stopped")
			return
		case <-t.C:
			samples, err := m.Collect()
			if err != nil {
				m.log.Warn("metering collect failed", "err", err)
				continue
			}
			if len(samples) == 0 {
				continue
			}
			if err := m.sink.Emit(ctx, samples); err != nil {
				m.log.Warn("metering emit failed", "err", err, "samples", len(samples))
			}
		}
	}
}
