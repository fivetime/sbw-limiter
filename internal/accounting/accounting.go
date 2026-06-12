// Package accounting implements the three-way route-count reconciliation of
// DESIGN.md §5.1: compare the BIRD RIB, the Linux RIB, and the VPP FIB every
// cycle and flag when they diverge.
//
// Why this exists: the path BIRD → kernel → VPP is mirrored over netlink by
// linux-cp's linux_nl listener. Netlink loss is SILENT — a dropped route-add
// leaves VPP's FIB short of the kernel with no error anywhere. Counting routes
// at each stage and comparing is the backstop that surfaces that drift, so the
// agent can trigger a full re-export (DESIGN.md §5.1: "偏差超阈值 → 告警 + 重 export").
//
// The three tables are NOT expected to be equal — they carry LARGE, directional
// systematic offsets, which a real VPP makes obvious:
//   - The VPP FIB also holds connected/local/receive routes (interface subnets,
//     per-address /32 receive entries, the default) that the kernel main table
//     and BIRD RIB don't, so the FIB count sits well ABOVE the kernel main
//     table even when the mirror is perfectly healthy.
//   - The kernel main table excludes the anchors BIRD holds in its RIB
//     (krt_export filters them, §4.2), so the BIRD RIB count runs higher still.
//
// Because the offset is large and directional, an absolute tolerance on the raw
// |Linux − VPP| gap is wrong: a lost route moves Linux TOWARD VPP and can shrink
// the raw gap. The signal is instead DRIFT from the healthy steady-state gap.
// The Checker compares the observed signed gap (Linux − VPP) against a
// calibrated BaselineGap and flags when it departs by more than the tolerance —
// that departure is the netlink-loss signature regardless of the constant
// structural offset.
//
// The actionable invariant is the kernel↔FIB mirror (Linux vs VPP) — the
// netlink path that loses updates. The BIRD leg is the upstream cross-check,
// reported for diagnostics; its offset to the kernel (the anchor count) is
// deployment-specific and not a fault, so it does not drive the trigger.
package accounting

import (
	"context"
	"fmt"
)

// Counter returns the route/FIB count from one leg of the accounting. Each leg
// (BIRD, Linux, VPP) is a Counter so the comparison logic is pure and testable
// with fakes; the real legs wrap the BIRD client / `ip route` / `vppctl`.
type Counter interface {
	Count(ctx context.Context) (uint64, error)
	Name() string
}

// Report is one accounting sample: the three counts, the signed mirror gap, its
// drift from the calibrated baseline, and whether that drift exceeded tolerance.
type Report struct {
	BIRD  uint64
	Linux uint64
	VPP   uint64

	// Gap is the signed kernel↔FIB difference (Linux − VPP). At a healthy
	// steady state it is a stable negative number (the FIB's structural
	// surplus). Drift is Gap − BaselineGap: how far the mirror has moved from
	// healthy. Netlink loss pushes Drift positive (kernel routes the FIB lacks);
	// a stale FIB surplus pushes it negative.
	Gap   int64
	Drift int64

	// ExportGap is BIRD − Linux, the upstream cross-check (carries the anchor
	// offset), reported but not used for the trigger.
	ExportGap int64

	// Deviated is true when |Drift| exceeds the checker's tolerance: the signal
	// to alert and re-export.
	Deviated bool
}

// String renders a one-line summary for logging.
func (r Report) String() string {
	return fmt.Sprintf("bird=%d linux=%d vpp=%d gap=%d drift=%d export-gap=%d deviated=%v",
		r.BIRD, r.Linux, r.VPP, r.Gap, r.Drift, r.ExportGap, r.Deviated)
}

// Checker compares the three legs. BaselineGap is the expected healthy signed
// gap (Linux − VPP), calibrated on a healthy edge or learned at startup;
// Tolerance is the maximum drift from it treated as healthy. A larger drift
// sets Report.Deviated.
type Checker struct {
	BIRD        Counter
	Linux       Counter
	VPP         Counter
	BaselineGap int64
	Tolerance   uint64
}

// Check samples all three legs and computes the report. A failure in any leg is
// returned as an error (a missing count can't be compared — better to surface
// the collection failure than to report a false deviation).
func (c Checker) Check(ctx context.Context) (Report, error) {
	bird, err := c.BIRD.Count(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("accounting: %s: %w", c.BIRD.Name(), err)
	}
	linux, err := c.Linux.Count(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("accounting: %s: %w", c.Linux.Name(), err)
	}
	vpp, err := c.VPP.Count(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("accounting: %s: %w", c.VPP.Name(), err)
	}

	r := Report{
		BIRD:      bird,
		Linux:     linux,
		VPP:       vpp,
		Gap:       int64(linux) - int64(vpp),
		ExportGap: int64(bird) - int64(linux),
	}
	r.Drift = r.Gap - c.BaselineGap
	r.Deviated = absInt(r.Drift) > int64(c.Tolerance)
	return r, nil
}

// CalibrateBaseline samples the current signed gap (Linux − VPP) for use as
// BaselineGap. Call it once when the data plane is known healthy — e.g. right
// after a clean reconcile at startup — so later drift is measured from a real
// steady state rather than from zero.
func (c Checker) CalibrateBaseline(ctx context.Context) (int64, error) {
	linux, err := c.Linux.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("accounting: calibrate %s: %w", c.Linux.Name(), err)
	}
	vpp, err := c.VPP.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("accounting: calibrate %s: %w", c.VPP.Name(), err)
	}
	return int64(linux) - int64(vpp), nil
}

func absInt(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
