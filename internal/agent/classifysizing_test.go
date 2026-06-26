package agent

import "testing"

func TestClassifyTableSizing(t *testing.T) {
	const GiB = 1 << 30
	tests := []struct {
		name       string
		members    uint32
		memPct     float64
		budget     uint64
		wantNb     uint32 // 0 = don't assert
		minMem     uint32 // memorySize must be >= this
		maxMem     uint32 // memorySize must be <= this (0 = skip)
	}{
		{name: "explicit members wins over pct", members: 1_000_000, memPct: 50, budget: 4 * GiB,
			wantNb: 1 << 20 /*1,048,576 = nextPow2(1M), under 2M cap*/, minMem: 128 << 20},
		{name: "pct of small pod budget", members: 0, memPct: 2.0, budget: 4 * GiB,
			minMem: 16 << 20},
		{name: "default pct when unset", members: 0, memPct: 0, budget: 64 * GiB,
			minMem: 256 << 20},
		{name: "floor at legacy 3000 when budget tiny", members: 0, memPct: 2.0, budget: 1 << 20,
			wantNb: 4096, minMem: 16 << 20},
		{name: "explicit small clamps to floors", members: 100, memPct: 0, budget: 0,
			wantNb: 4096, minMem: 16 << 20},
		{name: "huge members caps buckets at 2M and mem at u32", members: 4_000_000_000, memPct: 0, budget: 0,
			wantNb: 2 << 20, minMem: 1 << 30, maxMem: 0xE0000000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nb, mem := classifyTableSizing(tc.members, tc.memPct, tc.budget)
			if tc.wantNb != 0 && nb != tc.wantNb {
				t.Errorf("nbuckets = %d, want %d", nb, tc.wantNb)
			}
			if nb < classifyMinBuckets || nb > classifyMaxBuckets {
				t.Errorf("nbuckets %d out of [%d,%d]", nb, classifyMinBuckets, classifyMaxBuckets)
			}
			if mem < tc.minMem {
				t.Errorf("memorySize = %d, want >= %d", mem, tc.minMem)
			}
			if tc.maxMem != 0 && mem > tc.maxMem {
				t.Errorf("memorySize = %d, want <= %d", mem, tc.maxMem)
			}
		})
	}
}

func TestNextPow2(t *testing.T) {
	cases := map[uint64]uint64{0: 1, 1: 1, 2: 2, 3: 4, 4096: 4096, 4097: 8192, 1_000_000: 1 << 20}
	for in, want := range cases {
		if got := nextPow2(in); got != want {
			t.Errorf("nextPow2(%d) = %d, want %d", in, got, want)
		}
	}
}
