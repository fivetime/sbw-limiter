// Package accounting implements the three-way route-count reconciliation of
// DESIGN.md §5.1: compare the BIRD RIB, the Linux RIB, and the VPP FIB every
// cycle and flag when they diverge.
//
// Why this exists: transit routes have to make it from BIRD all the way into
// the VPP FIB, and that last hop is SILENT on failure — a dropped route leaves
// the FIB short with no error anywhere. Counting routes at each stage and
// comparing is the backstop that surfaces that drift, so the agent can trigger a
// full re-export (DESIGN.md §5.1: "偏差超阈值 → 告警 + 重 export").
//
// The actionable mirror is BIRD↔VPP, and deliberately so — it is path-agnostic:
//   - route B (BIRD → kernel → linux_nl → VPP): a netlink-loss drops the route
//     before the FIB. BIRD has it, VPP lacks it.
//   - route A (BIRD → vppfib → VPP, kernel dropped, §1.2): a vppfib
//     materialization miss drops it before the FIB. BIRD has it, VPP lacks it.
// Either way the end-to-end failure shows up as BIRD running ahead of VPP, so
// comparing BIRD↔VPP catches both without caring which path is deployed.
//
// The Linux leg is NO LONGER the mirror. Under route A the transit /32//128 are
// programmed straight into the FIB and never enter the kernel main table, so
// Linux↔VPP is structurally broken (the kernel is short every transit route).
// Linux is kept only as a route-B-era diagnostic (ExportGap): under route B it
// is the netlink leg; under route A a large ExportGap simply confirms route A is
// active. It does not drive the trigger.
//
// The three tables are NOT expected to be equal — they carry LARGE, directional
// systematic offsets:
//   - The VPP FIB also holds connected/local/receive routes (interface subnets,
//     per-address /32 receive entries, the default) that BIRD's RIB doesn't.
//   - BIRD's RIB holds the anchors (krt_export filters them out of the kernel,
//     §4.2) that the FIB doesn't.
// So at a healthy steady state BIRD − VPP is a stable offset (anchors minus the
// FIB's connected/local surplus), not zero. An absolute tolerance on the raw gap
// is therefore wrong; the signal is DRIFT from that calibrated BaselineGap. A
// lost transit route pushes the gap positive (BIRD ahead of a FIB it should
// match); a stale FIB surplus pushes it negative.
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

	// Gap is the signed BIRD↔VPP difference (BIRD − VPP) — the path-agnostic
	// mirror (route A via vppfib or route B via netlink both end here). At a
	// healthy steady state it is a stable number (anchors minus the FIB's
	// connected/local surplus). Drift is Gap − BaselineGap: how far the mirror
	// has moved from healthy. A lost transit route pushes Drift positive (BIRD
	// ahead of a FIB it should match); a stale FIB surplus pushes it negative.
	Gap   int64
	Drift int64

	// ExportGap is BIRD − Linux, a route-B-era diagnostic (under B it carries the
	// anchor offset; under A — kernel dropped — it is ≈ the whole transit count,
	// confirming route A is active). Reported, never used for the trigger.
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
// gap (BIRD − VPP), calibrated on a healthy edge or learned at startup;
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
		Gap:       int64(bird) - int64(vpp),   // BIRD↔VPP mirror — path-agnostic (route A or B)
		ExportGap: int64(bird) - int64(linux), // Linux leg: route-B netlink diagnostic only
	}
	r.Drift = r.Gap - c.BaselineGap
	r.Deviated = absInt(r.Drift) > int64(c.Tolerance)
	return r, nil
}

// CalibrateBaseline samples the current signed gap (BIRD − VPP) for use as
// BaselineGap. Call it once when the data plane is known healthy — e.g. right
// after a clean reconcile at startup — so later drift is measured from a real
// steady state rather than from zero.
func (c Checker) CalibrateBaseline(ctx context.Context) (int64, error) {
	bird, err := c.BIRD.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("accounting: calibrate %s: %w", c.BIRD.Name(), err)
	}
	vpp, err := c.VPP.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("accounting: calibrate %s: %w", c.VPP.Name(), err)
	}
	return int64(bird) - int64(vpp), nil
}

func absInt(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
