// Package leakcheck verifies the anchor placement invariants (T-306,
// DESIGN.md §4.2-3): every anchor prefix MUST be in BIRD's exported-upstream
// set, MUST NOT be in the Linux kernel RIB, and MUST NOT be in the VPP FIB. A
// blackhole anchor that reaches the kernel becomes a DROP in the VPP FIB and
// silently discards the very traffic it pulled to this edge — so this check is
// a load-bearing safety net, run periodically by the reconcile loop (T-501).
//
// RIB/FIB sources are pluggable Listers so the kernel reader works today while
// the VPP FIB reader arrives with T-401; the checker logic is source-agnostic
// and unit-tested with fakes.
package leakcheck

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Lister returns the set of prefixes currently present in one RIB/FIB.
type Lister interface {
	ListPrefixes(ctx context.Context) (map[netip.Prefix]struct{}, error)
	Name() string
}

// Report is the outcome of one leak check.
type Report struct {
	Checked int // number of anchor prefixes evaluated

	// LeakedToKernel / LeakedToFIB are anchors found where they must be
	// absent — critical: traffic to them is being black-holed at this edge.
	LeakedToKernel []netip.Prefix
	LeakedToFIB    []netip.Prefix

	// MissingExport are anchors not in BIRD's exported set — they are not
	// being advertised upstream, so traffic is not pulled to this edge.
	MissingExport []netip.Prefix

	// FIBChecked records whether a VPP FIB source was available; false means
	// the FIB leg was skipped (alerting should know coverage is partial).
	FIBChecked bool
}

// OK reports whether all invariants held.
func (r Report) OK() bool {
	return len(r.LeakedToKernel) == 0 && len(r.LeakedToFIB) == 0 && len(r.MissingExport) == 0
}

// Err returns a violation summary, or nil if OK. It is a value error meant for
// alerting; infrastructure failures (a Lister erroring) are returned separately
// by Check.
func (r Report) Err() error {
	if r.OK() {
		return nil
	}
	var parts []string
	if len(r.LeakedToKernel) > 0 {
		parts = append(parts, fmt.Sprintf("LEAKED to kernel: %s", joinPrefixes(r.LeakedToKernel)))
	}
	if len(r.LeakedToFIB) > 0 {
		parts = append(parts, fmt.Sprintf("LEAKED to VPP FIB: %s", joinPrefixes(r.LeakedToFIB)))
	}
	if len(r.MissingExport) > 0 {
		parts = append(parts, fmt.Sprintf("not exported upstream: %s", joinPrefixes(r.MissingExport)))
	}
	return fmt.Errorf("anchor leak check failed: %s", strings.Join(parts, "; "))
}

// Checker holds the sources for one edge. Kernel and BirdExported are required;
// FIB is optional (nil until T-401 wires the VPP FIB reader).
type Checker struct {
	Kernel       Lister
	BirdExported Lister
	FIB          Lister
}

// Check evaluates the invariants for the given anchor prefixes. It returns an
// error only when a source cannot be listed (the check could not run); actual
// violations are reported in Report (use Report.Err for alerting).
func (c Checker) Check(ctx context.Context, anchors []netip.Prefix) (Report, error) {
	rep := Report{Checked: len(anchors)}
	if len(anchors) == 0 {
		rep.FIBChecked = c.FIB != nil
		return rep, nil
	}

	kernel, err := c.Kernel.ListPrefixes(ctx)
	if err != nil {
		return rep, fmt.Errorf("leakcheck: list %s: %w", c.Kernel.Name(), err)
	}
	exported, err := c.BirdExported.ListPrefixes(ctx)
	if err != nil {
		return rep, fmt.Errorf("leakcheck: list %s: %w", c.BirdExported.Name(), err)
	}
	var fib map[netip.Prefix]struct{}
	if c.FIB != nil {
		fib, err = c.FIB.ListPrefixes(ctx)
		if err != nil {
			return rep, fmt.Errorf("leakcheck: list %s: %w", c.FIB.Name(), err)
		}
		rep.FIBChecked = true
	}

	for _, a := range anchors {
		if _, in := kernel[a]; in {
			rep.LeakedToKernel = append(rep.LeakedToKernel, a)
		}
		if _, in := exported[a]; !in {
			rep.MissingExport = append(rep.MissingExport, a)
		}
		if fib != nil {
			if _, in := fib[a]; in {
				rep.LeakedToFIB = append(rep.LeakedToFIB, a)
			}
		}
	}
	sortPrefixes(rep.LeakedToKernel)
	sortPrefixes(rep.LeakedToFIB)
	sortPrefixes(rep.MissingExport)
	return rep, nil
}

func sortPrefixes(ps []netip.Prefix) {
	sort.Slice(ps, func(i, j int) bool {
		if c := ps[i].Addr().Compare(ps[j].Addr()); c != 0 {
			return c < 0
		}
		return ps[i].Bits() < ps[j].Bits()
	})
}

func joinPrefixes(ps []netip.Prefix) string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = p.String()
	}
	return strings.Join(parts, ", ")
}
