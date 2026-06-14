package agent

import (
	"testing"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/vpp"
)

type fakeStats struct{ m map[uint32]vpp.PolicerCounters }

func (f fakeStats) ReadPolicers() (map[uint32]vpp.PolicerCounters, error) { return f.m, nil }

// TestMeteringCollect: Collect maps each MANAGED policer (name parses to a pool)
// to one sample per direction via the index map, copies the raw counters, and
// skips unmanaged policers.
func TestMeteringCollect(t *testing.T) {
	stats := fakeStats{m: map[uint32]vpp.PolicerCounters{
		3: {ConformPackets: 8000, ConformBytes: 1024000, ExceedPackets: 500, ExceedBytes: 64000},
		5: {ConformPackets: 100, ConformBytes: 12800},
		7: {ConformPackets: 999, ConformBytes: 999}, // unmanaged index, must be skipped
	}}
	indexes := func() map[string]uint32 {
		return map[string]uint32{
			model.PolicerName(900, model.DirectionIngress): 3, // pool900_in
			model.PolicerName(900, model.DirectionEgress):  5, // pool900_out
			"vpp_default": 7, // unmanaged → ParsePolicerName fails → skipped
		}
	}
	m := NewMetering("l1", stats, indexes, nil, WithMeteringClock(func() int64 { return 1000 }))

	samples, err := m.Collect()
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 2 {
		t.Fatalf("want 2 samples (managed only), got %d: %+v", len(samples), samples)
	}
	byDir := map[string]MeteringSample{}
	for _, s := range samples {
		byDir[s.Dir] = s
	}
	in := byDir["ingress"]
	if in.PoolID != 900 || in.Edge != "l1" || in.TS != 1000 ||
		in.ConformBytes != 1024000 || in.ConformPkts != 8000 || in.ExceedBytes != 64000 || in.ExceedPkts != 500 {
		t.Errorf("ingress sample wrong: %+v", in)
	}
	eg := byDir["egress"]
	if eg.PoolID != 900 || eg.ConformBytes != 12800 || eg.ConformPkts != 100 {
		t.Errorf("egress sample wrong: %+v", eg)
	}
}

// TestMeteringCollectZeroPolicer: a managed policer with no stats entry reports
// zero (still emitted, so the time series stays continuous).
func TestMeteringCollectZeroPolicer(t *testing.T) {
	stats := fakeStats{m: map[uint32]vpp.PolicerCounters{}} // no counters read
	indexes := func() map[string]uint32 {
		return map[string]uint32{model.PolicerName(700, model.DirectionIngress): 1}
	}
	m := NewMetering("l2", stats, indexes, nil, WithMeteringClock(func() int64 { return 42 }))
	samples, err := m.Collect()
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 || samples[0].PoolID != 700 || samples[0].ConformBytes != 0 {
		t.Fatalf("want 1 zero sample for pool 700, got %+v", samples)
	}
}
