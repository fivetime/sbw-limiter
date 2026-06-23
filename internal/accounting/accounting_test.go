package accounting

import (
	"context"
	"errors"
	"testing"
)

type fakeCounter struct {
	name string
	n    uint64
	err  error
}

func (f fakeCounter) Name() string                          { return f.name }
func (f fakeCounter) Count(context.Context) (uint64, error) { return f.n, f.err }

func TestCheckerHealthyAtBaseline(t *testing.T) {
	// The mirror is BIRD↔VPP. At a healthy steady state BIRD − VPP is a stable
	// offset (anchors minus the FIB's connected/local surplus); here -3. At
	// baseline the drift is zero → healthy. The Linux leg only feeds ExportGap.
	c := Checker{
		BIRD:        fakeCounter{name: "bird", n: 215}, // transit + anchors
		Linux:       fakeCounter{name: "linux", n: 208},
		VPP:         fakeCounter{name: "vpp", n: 218}, // transit + connected/local surplus
		BaselineGap: -3,
		Tolerance:   3,
	}
	r, err := c.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.Gap != -3 || r.Drift != 0 {
		t.Fatalf("gap=%d drift=%d, want -3/0", r.Gap, r.Drift)
	}
	if r.Deviated {
		t.Errorf("at baseline should be healthy: %s", r)
	}
}

func TestCheckerRouteLostBeforeFIBDriftsPositive(t *testing.T) {
	// A transit route makes it into BIRD but not the FIB — a netlink loss
	// (route B) or a vppfib materialization miss (route A); BIRD↔VPP catches
	// both. VPP falls short, BIRD stays, the gap moves positive past tolerance.
	c := Checker{
		BIRD:        fakeCounter{name: "bird", n: 215},
		Linux:       fakeCounter{name: "linux", n: 208},
		VPP:         fakeCounter{name: "vpp", n: 206}, // 12 transit routes short of healthy 218
		BaselineGap: -3,
		Tolerance:   3,
	}
	r, err := c.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.Gap != 9 || r.Drift != 12 {
		t.Fatalf("gap=%d drift=%d, want 9/12", r.Gap, r.Drift)
	}
	if !r.Deviated {
		t.Errorf("a route lost before the FIB should deviate: %s", r)
	}
}

func TestCheckerStaleFIBDriftsNegative(t *testing.T) {
	// The opposite fault: the FIB keeps routes BIRD has already withdrawn → VPP
	// runs above BIRD, the gap moves further negative → still flagged.
	c := Checker{
		BIRD:        fakeCounter{name: "bird", n: 215},
		Linux:       fakeCounter{name: "linux", n: 208},
		VPP:         fakeCounter{name: "vpp", n: 238}, // 20 stale surplus over healthy 218
		BaselineGap: -3,
		Tolerance:   5,
	}
	r, err := c.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.Drift != -20 {
		t.Fatalf("drift=%d, want -20", r.Drift)
	}
	if !r.Deviated {
		t.Errorf("stale-FIB drift should deviate: %s", r)
	}
}

func TestCheckerExportGapDoesNotTrigger(t *testing.T) {
	// The anchor surplus (BIRD holds anchors the FIB doesn't) is part of the
	// BIRD↔VPP gap, but it is STABLE and so baked into BaselineGap — a steady
	// anchor count drifts by zero. ExportGap (BIRD − Linux) is reported, never
	// drives the trigger. Under route A a large ExportGap just confirms the
	// transit routes skipped the kernel.
	c := Checker{
		BIRD:        fakeCounter{name: "bird", n: 5000}, // many anchors
		Linux:       fakeCounter{name: "linux", n: 208},
		VPP:         fakeCounter{name: "vpp", n: 218},
		BaselineGap: 4782, // calibrated BIRD − VPP, anchors included
		Tolerance:   3,
	}
	r, err := c.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.ExportGap != 4792 {
		t.Errorf("export gap = %d, want 4792", r.ExportGap)
	}
	if r.Drift != 0 {
		t.Errorf("drift = %d, want 0 (stable anchors are in the baseline)", r.Drift)
	}
	if r.Deviated {
		t.Errorf("a stable anchor surplus must not deviate: %s", r)
	}
}

func TestCheckerDriftBoundary(t *testing.T) {
	base := func(bird uint64) Checker {
		return Checker{
			BIRD:        fakeCounter{name: "bird", n: bird},
			Linux:       fakeCounter{name: "linux", n: bird},
			VPP:         fakeCounter{name: "vpp", n: 100},
			BaselineGap: 0,
			Tolerance:   5,
		}
	}
	// Drift exactly == tolerance is healthy; one more deviates (both directions).
	if r, _ := base(105).Check(context.Background()); r.Deviated {
		t.Errorf("drift == tolerance should be healthy: %s", r)
	}
	if r, _ := base(106).Check(context.Background()); !r.Deviated {
		t.Errorf("drift > tolerance should deviate: %s", r)
	}
	if r, _ := base(95).Check(context.Background()); r.Deviated {
		t.Errorf("negative drift == tolerance should be healthy: %s", r)
	}
	if r, _ := base(94).Check(context.Background()); !r.Deviated {
		t.Errorf("negative drift > tolerance should deviate: %s", r)
	}
}

func TestCalibrateBaseline(t *testing.T) {
	// Baseline is the signed BIRD − VPP gap, sampled when healthy.
	c := Checker{
		BIRD: fakeCounter{name: "bird", n: 208},
		VPP:  fakeCounter{name: "vpp", n: 218},
	}
	gap, err := c.CalibrateBaseline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if gap != -10 {
		t.Fatalf("baseline = %d, want -10", gap)
	}
}

func TestCheckerLegErrorSurfaces(t *testing.T) {
	// A leg failure must surface as an error (not a false deviation). VPP is on
	// both the Check and the CalibrateBaseline paths.
	sentinel := errors.New("socket closed")
	c := Checker{
		BIRD:  fakeCounter{name: "bird", n: 1},
		Linux: fakeCounter{name: "linux", n: 1},
		VPP:   fakeCounter{name: "vpp", err: sentinel},
	}
	if _, err := c.Check(context.Background()); !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want wrapped sentinel", err)
	}
	if _, err := c.CalibrateBaseline(context.Background()); !errors.Is(err, sentinel) {
		t.Fatalf("calibrate err = %v, want wrapped sentinel", err)
	}
}
