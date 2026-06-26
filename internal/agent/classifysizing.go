package agent

import (
	"os"
	"strconv"
	"strings"
)

// classify table auto-sizing (per VPP classify mask table).
//
// VPP creates each classify table with a FIXED, non-growable heap of `memory_size`
// (clib_mem_create_heap + mspace_disable_expand), and each member is one session
// allocated from it; when it fills, vnet_classify_add_del_session -> os_panic crashes
// VPP (exit 139). The historical default (16 MiB / 4096 buckets, "ample for 3000
// sessions") was hard-coded and crashed at scale. We size the table from the node's
// memory budget so k8s nodes/pods of different sizes auto-tune without per-node config:
//
//	capacity := BWPOOL_CLASSIFY_MEMBERS                       (explicit, highest priority)
//	         := BWPOOL_CLASSIFY_MEM_PCT % of the memory budget (fallback / default)
//	nbuckets := ~capacity (pow2, clamped)                    load-factor ~1 → no chain churn
//	memory   := capacity * perEntry * headroom               committed-on-use, so generous is cheap
//
// The budget is the CGROUP limit (k8s pod memory limit) when set — NOT the physical
// node RAM — so a 4 GiB pod on a 256 GiB node sizes to 4 GiB and is never OOM-killed.
const (
	// classifyPerEntryBytes is the effective per-member cost: the /32 entry
	// (sizeof(vnet_classify_entry_t)=32B + match key 16B = 48B) plus page/bucket/
	// freelist/fragmentation overhead. Conservative so memory_size never under-shoots.
	classifyPerEntryBytes = 128
	// classifyHeadroomNum/Den = 1.5x headroom on memory_size for fragmentation.
	classifyHeadroomNum = 3
	classifyHeadroomDen = 2
	// defaultClassifyMemPct: when neither MEMBERS nor MEM_PCT is set, give the
	// classify tables this % of the memory budget. Modest: the tables are
	// committed-on-use, so this is a ceiling, and the per-table bucket array
	// (the only upfront cost) is bounded by classifyMaxBuckets.
	defaultClassifyMemPct = 2.0
	// floors/caps.
	classifyMinMembers = 3000      // never below the legacy capacity
	classifyMinBuckets = 4096      // VPP-friendly minimum
	classifyMaxBuckets = 2 << 20   // 2M: caps upfront bucket array (~16MB/table)
	classifyMinMem     = 16 << 20  // 16 MiB floor (legacy default)
	classifyMaxMem     = 0xE0000000 // ~3.5 GiB: memory_size is u32 in the VPP API
)

// classifyTableSizing computes (nbuckets, memorySize) for each classify mask table
// from the explicit member capacity (members>0) or memPct of the memory budget.
// Pure (budget injected) so it is unit-testable; classifyAutoSizing wires the live budget.
func classifyTableSizing(members uint32, memPct float64, budget uint64) (nbuckets, memorySize uint32) {
	capacity := uint64(members)
	if capacity == 0 {
		if memPct <= 0 {
			memPct = defaultClassifyMemPct
		}
		if budget > 0 {
			capacity = uint64(float64(budget)*memPct/100.0) / classifyPerEntryBytes
		}
	}
	if capacity < classifyMinMembers {
		capacity = classifyMinMembers
	}

	nb := nextPow2(capacity)
	if nb < classifyMinBuckets {
		nb = classifyMinBuckets
	}
	if nb > classifyMaxBuckets {
		nb = classifyMaxBuckets
	}
	nbuckets = uint32(nb)

	m := capacity * classifyPerEntryBytes * classifyHeadroomNum / classifyHeadroomDen
	if m < classifyMinMem {
		m = classifyMinMem
	}
	if m > classifyMaxMem {
		m = classifyMaxMem
	}
	memorySize = uint32(m)
	return
}

// classifyAutoSizing reads BWPOOL_CLASSIFY_MEMBERS / BWPOOL_CLASSIFY_MEM_PCT and the
// live memory budget, returning the per-table (nbuckets, memorySize).
func classifyAutoSizing() (nbuckets, memorySize uint32) {
	members := uint32(envUint("BWPOOL_CLASSIFY_MEMBERS", 0))
	pct := envFloat("BWPOOL_CLASSIFY_MEM_PCT", 0) // 0 → use default inside the sizing fn
	return classifyTableSizing(members, pct, memoryBudget())
}

// memoryBudget returns the memory budget in bytes: min(cgroup limit, physical RAM).
// In k8s the cgroup limit is the pod's memory limit; outside containers it's effectively
// the physical RAM. "max"/unbounded cgroup values fall back to the physical total.
func memoryBudget() uint64 {
	phys := procMemTotalBytes()
	budget := phys
	for _, p := range []string{
		"/sys/fs/cgroup/memory.max",                  // cgroup v2
		"/sys/fs/cgroup/memory/memory.limit_in_bytes", // cgroup v1
	} {
		if v, ok := readCgroupLimit(p); ok && v < budget {
			budget = v
		}
	}
	return budget
}

func readCgroupLimit(path string) (uint64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(b))
	if s == "" || s == "max" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	// cgroup v1 reports a huge sentinel (≈ 2^63) when unlimited.
	if v >= 1<<62 {
		return 0, false
	}
	return v, true
}

func procMemTotalBytes() uint64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			f := strings.Fields(line) // "MemTotal: 264 kB"
			if len(f) >= 2 {
				if kb, err := strconv.ParseUint(f[1], 10, 64); err == nil {
					return kb * 1024
				}
			}
		}
	}
	return 0
}

func nextPow2(n uint64) uint64 {
	if n == 0 {
		return 1
	}
	p := uint64(1)
	for p < n {
		p <<= 1
	}
	return p
}

func envUint(key string, def uint64) uint64 {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func envFloat(key string, def float64) float64 {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}
